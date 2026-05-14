/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_adaptive_bg_prio v4
 *
 * Core change from v1: FLUSH_DSQ and L0_DSQ are merged into one BG_PRIO_DSQ.
 *
 * v1 problem: vtime bonus only orders tasks within the same DSQ.
 * Since flush lived in FLUSH_DSQ and L0 in L0_DSQ, and dispatch always
 * consumed FLUSH_DSQ first, the per-DSQ vtime bonuses had no effect on
 * the flush-vs-L0 CPU allocation.
 *
 * v4 fix: put both flush and L0 compaction threads into a single
 * BG_PRIO_DSQ with vtime ordering.  Each thread's vtime is set to:
 *
 *   vtime = vtime_now - BG_BONUS_BASE × pressure_ratio / 100
 *
 * where pressure_ratio reflects how far the relevant metric exceeds its
 * threshold (capped at MAX_PRESSURE_PCT=300%).
 *
 * When flush pressure is higher than L0 pressure the flush thread gets a
 * lower vtime → dispatched more often.  When L0 pressure dominates the L0
 * compaction thread wins.  The CPU allocation automatically tracks which
 * bottleneck is more urgent.
 *
 * Dispatch order: BG_PRIO_DSQ (vtime) > COMP_DSQ (FIFO) > SHARED_DSQ (FIFO)
 *
 * Preemption: flush and L0 threads can preempt COMP/SHARED (CPU_PRIO_NONE)
 * but not each other (CPU_PRIO_BG_PRIO).
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;
const volatile u64 flush_slice_ns;
const volatile u64 l0_slice_ns;
const volatile u64 comp_slice_ns;
const volatile u64 shared_slice_ns;
const volatile u64 metrics_max_age_ns;
const volatile u64 wait_safety_ns;
const volatile u64 memtable_bytes_thr;
const volatile u64 imm_memtables_thr;
const volatile u64 l0_files_thr;

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ   0
#define COMP_DSQ     1
#define BG_PRIO_DSQ  2

#define BG_FLUSH_CLASS      1
#define BG_COMPACTION_CLASS 2
#define MAX_TRACK_CPUS  4096
#define WAIT_MAP_ENTRIES 16384

/* CPU prio state: BG_PRIO covers both flush and L0 compaction threads */
#define CPU_PRIO_NONE    0
#define CPU_PRIO_BG_PRIO 1

#define TASK_CLS_NONE  0
#define TASK_CLS_FLUSH 1
#define TASK_CLS_L0    2
#define TASK_CLS_COMP  4

/*
 * Common bonus base: both flush and L0 start from the same scale so that
 * pressure_ratio directly determines which thread wins CPU time.
 * 500 ms gives enough headroom above the typical vtime window.
 */
#define BG_BONUS_BASE_NS   500000000ULL  /* 500 ms */
#define MAX_PRESSURE_PCT   300ULL

struct scx_thread_class_value {
	u32 class_id;
	s32 start_level;
	s32 output_level;
	u32 pad;
};

struct scx_db_metrics_value {
	u64 l0_files;
	u64 debt_bytes;
	u32 stall_flag;
	u32 num_immutable_memtables;
	u64 cur_size_all_memtables;
	u64 timestamp_ns;
};

enum stat_idx {
	STAT_LOCAL = 0,
	STAT_GLOBAL,
	STAT_FLUSH_HIT,
	STAT_FLUSH_IDLE_DIRECT,
	STAT_FLUSH_PREEMPT,
	STAT_FLUSH_PREEMPT_FAIL,
	STAT_FLUSH_DSQ,
	STAT_L0_HIT,
	STAT_L0_IDLE_DIRECT,
	STAT_L0_PREEMPT,
	STAT_L0_PREEMPT_FAIL,
	STAT_L0_DSQ,
	STAT_THREAD_MISS,
	STAT_METRICS_MISS,
	STAT_METRICS_STALE,
	STAT_WAIT_OVERRIDE,
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_prio_state_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_preemptable_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct scx_thread_class_value);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rocksdb_scx_thread_class_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct scx_db_metrics_value);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rocksdb_scx_db_metrics_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, WAIT_MAP_ENTRIES);
} task_wait_map SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);

	if (cnt_p)
		(*cnt_p)++;
}

static __always_inline bool metrics_is_stale(const struct scx_db_metrics_value *dbm)
{
	u64 age_limit = metrics_max_age_ns ? : 3000000000ULL;
	u64 now = bpf_ktime_get_ns();

	if (!dbm)
		return true;
	if (now < dbm->timestamp_ns)
		return false;
	return now - dbm->timestamp_ns > age_limit;
}

static __always_inline u32 classify_task(struct task_struct *p)
{
	u32 tid = p->pid;
	u32 tgid = p->tgid;
	struct scx_thread_class_value *tcls;
	struct scx_db_metrics_value *dbm;
	u64 bytes_thr = memtable_bytes_thr ? : (64ULL << 20);
	u64 imm_thr   = imm_memtables_thr ? : 1;
	u64 l0_thr    = l0_files_thr ? : 4;

	tcls = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
	if (!tcls) {
		stat_inc(STAT_THREAD_MISS);
		return TASK_CLS_NONE;
	}

	if (tcls->class_id == BG_FLUSH_CLASS) {
		dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
		if (!dbm) {
			stat_inc(STAT_METRICS_MISS);
			return TASK_CLS_NONE;
		}
		if (metrics_is_stale(dbm)) {
			stat_inc(STAT_METRICS_STALE);
			return TASK_CLS_NONE;
		}
		if (dbm->stall_flag ||
		    dbm->num_immutable_memtables >= imm_thr ||
		    dbm->cur_size_all_memtables >= bytes_thr)
			return TASK_CLS_FLUSH;
		return TASK_CLS_NONE;
	}

	if (tcls->class_id == BG_COMPACTION_CLASS) {
		if (tcls->start_level == 0) {
			dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
			if (!dbm) {
				stat_inc(STAT_METRICS_MISS);
				return TASK_CLS_COMP;
			}
			if (metrics_is_stale(dbm)) {
				stat_inc(STAT_METRICS_STALE);
				return TASK_CLS_COMP;
			}
			if (dbm->l0_files >= l0_thr)
				return TASK_CLS_L0;
		}
		return TASK_CLS_COMP;
	}

	return TASK_CLS_NONE;
}

static __always_inline u32 classify_task_nostat(struct task_struct *p)
{
	u32 tid = p->pid;
	u32 tgid = p->tgid;
	struct scx_thread_class_value *tcls;
	struct scx_db_metrics_value *dbm;
	u64 bytes_thr = memtable_bytes_thr ? : (64ULL << 20);
	u64 imm_thr   = imm_memtables_thr ? : 1;
	u64 l0_thr    = l0_files_thr ? : 4;

	tcls = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
	if (!tcls)
		return TASK_CLS_NONE;

	if (tcls->class_id == BG_FLUSH_CLASS) {
		dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
		if (!dbm || metrics_is_stale(dbm))
			return TASK_CLS_NONE;
		if (dbm->stall_flag ||
		    dbm->num_immutable_memtables >= imm_thr ||
		    dbm->cur_size_all_memtables >= bytes_thr)
			return TASK_CLS_FLUSH;
		return TASK_CLS_NONE;
	}

	if (tcls->class_id == BG_COMPACTION_CLASS) {
		if (tcls->start_level == 0) {
			dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
			if (!dbm || metrics_is_stale(dbm))
				return TASK_CLS_COMP;
			if (dbm->l0_files >= l0_thr)
				return TASK_CLS_L0;
		}
		return TASK_CLS_COMP;
	}

	return TASK_CLS_NONE;
}

/*
 * Flush pressure bonus: BG_BONUS_BASE × max(imm_ratio, mem_ratio) / 100
 * At threshold (ratio=100%): 500 ms.  At 3× threshold: 1500 ms.
 */
static __always_inline u64 compute_flush_bonus(struct scx_db_metrics_value *dbm)
{
	u64 imm_thr_v   = imm_memtables_thr ? : 1;
	u64 bytes_thr_v = memtable_bytes_thr ? : (64ULL << 20);
	u64 imm_ratio, mem_ratio, ratio;

	if (!dbm)
		return BG_BONUS_BASE_NS;

	imm_ratio = imm_thr_v > 0 ?
		dbm->num_immutable_memtables * 100 / imm_thr_v : 100;
	if (imm_ratio > MAX_PRESSURE_PCT)
		imm_ratio = MAX_PRESSURE_PCT;

	mem_ratio = bytes_thr_v > 0 ?
		dbm->cur_size_all_memtables * 100 / bytes_thr_v : 0;
	if (mem_ratio > MAX_PRESSURE_PCT)
		mem_ratio = MAX_PRESSURE_PCT;

	ratio = imm_ratio > mem_ratio ? imm_ratio : mem_ratio;
	if (ratio < 100)
		ratio = 100;

	return BG_BONUS_BASE_NS * ratio / 100;
}

/*
 * L0 pressure bonus: BG_BONUS_BASE × l0_ratio / 100
 * At threshold (ratio=100%): 500 ms.  At 3× threshold: 1500 ms.
 */
static __always_inline u64 compute_l0_bonus(struct scx_db_metrics_value *dbm)
{
	u64 l0_thr_v = l0_files_thr ? : 4;
	u64 l0_ratio;

	if (!dbm)
		return BG_BONUS_BASE_NS;

	l0_ratio = l0_thr_v > 0 ? dbm->l0_files * 100 / l0_thr_v : 100;
	if (l0_ratio > MAX_PRESSURE_PCT)
		l0_ratio = MAX_PRESSURE_PCT;
	if (l0_ratio < 100)
		l0_ratio = 100;

	return BG_BONUS_BASE_NS * l0_ratio / 100;
}

static __always_inline u64 prio_vtime(u64 vtime, u64 bonus_ns)
{
	u64 min_vtime = vtime_now > bonus_ns ? vtime_now - bonus_ns : 0;

	if (time_before(vtime, min_vtime))
		return vtime;
	return min_vtime;
}

static __always_inline u32 get_cpu_prio_state(s32 cpu)
{
	u32 key = (u32)cpu;
	u32 *p;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return CPU_PRIO_NONE;
	p = bpf_map_lookup_elem(&cpu_prio_state_map, &key);
	return p ? *p : CPU_PRIO_NONE;
}

static __always_inline bool is_cpu_preemptable(s32 cpu)
{
	u32 key = (u32)cpu;
	u32 *p;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return false;
	p = bpf_map_lookup_elem(&cpu_preemptable_map, &key);
	return p && *p == 1;
}

enum prio_dispatch_res {
	PRIO_DISPATCH_FAIL    = 0,
	PRIO_DISPATCH_IDLE    = 1,
	PRIO_DISPATCH_PREEMPT = 2,
};

/*
 * BG_PRIO threads (flush or L0) preempt COMP/SHARED (CPU_PRIO_NONE) only.
 * They do not preempt each other — BG_PRIO_DSQ vtime handles that.
 */
static __always_inline s32 try_bg_prio_preempt_dispatch(struct task_struct *p,
							 u64 enq_flags,
							 u64 slice_ns)
{
	s32 target = scx_bpf_task_cpu(p);
	s32 victim = -1;
	s32 idle_cpu;
	u32 nr_cpus;
	s32 cpu;

	idle_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (idle_cpu >= 0) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | idle_cpu, slice_ns,
				   enq_flags | SCX_ENQ_PREEMPT);
		scx_bpf_kick_cpu(idle_cpu, SCX_KICK_IDLE);
		return PRIO_DISPATCH_IDLE;
	}

	if (target >= 0 && bpf_cpumask_test_cpu(target, p->cpus_ptr) &&
	    get_cpu_prio_state(target) == CPU_PRIO_NONE &&
	    is_cpu_preemptable(target))
		victim = target;

	if (victim < 0) {
		nr_cpus = scx_bpf_nr_cpu_ids();
		bpf_for(cpu, 0, nr_cpus) {
			if (cpu == target)
				continue;
			if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
				continue;
			if (get_cpu_prio_state(cpu) != CPU_PRIO_NONE)
				continue;
			if (!is_cpu_preemptable(cpu))
				continue;
			victim = cpu;
			break;
		}
	}

	if (victim >= 0) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | victim, slice_ns,
				   enq_flags | SCX_ENQ_PREEMPT);
		scx_bpf_kick_cpu(victim, SCX_KICK_PREEMPT);
		return PRIO_DISPATCH_PREEMPT;
	}

	return PRIO_DISPATCH_FAIL;
}

s32 BPF_STRUCT_OPS(adaptive_bg_prio_v4_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(STAT_LOCAL);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}
	return cpu;
}

void BPF_STRUCT_OPS(adaptive_bg_prio_v4_enqueue, struct task_struct *p, u64 enq_flags)
{
	u32 cls = classify_task(p);
	u64 f_slice = flush_slice_ns  ? : 120000000ULL;
	u64 l_slice = l0_slice_ns     ? : 250000000ULL;
	u64 c_slice = comp_slice_ns   ? : 20000000ULL;
	u64 s_slice = shared_slice_ns ? : SCX_SLICE_DFL;
	u64 now = bpf_ktime_get_ns();
	u32 pid = p->pid;
	u32 tgid = p->tgid;
	u64 *enq_ts = bpf_map_lookup_elem(&task_wait_map, &pid);

	stat_inc(STAT_GLOBAL);
	if (!enq_ts)
		bpf_map_update_elem(&task_wait_map, &pid, &now, BPF_ANY);

	if (cls == TASK_CLS_FLUSH) {
		s32 res;

		stat_inc(STAT_FLUSH_HIT);
		res = try_bg_prio_preempt_dispatch(p, enq_flags, f_slice);
		if (res == PRIO_DISPATCH_IDLE) {
			stat_inc(STAT_FLUSH_IDLE_DIRECT);
			return;
		}
		if (res == PRIO_DISPATCH_PREEMPT) {
			stat_inc(STAT_FLUSH_PREEMPT);
			return;
		}
		stat_inc(STAT_FLUSH_PREEMPT_FAIL);
		if (fifo_sched) {
			scx_bpf_dsq_insert(p, BG_PRIO_DSQ, f_slice, enq_flags);
		} else {
			struct scx_db_metrics_value *dbm =
				bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
			u64 bonus = compute_flush_bonus(dbm);
			u64 vtime = prio_vtime(p->scx.dsq_vtime, bonus);

			scx_bpf_dsq_insert_vtime(p, BG_PRIO_DSQ, f_slice, vtime, enq_flags);
		}
		stat_inc(STAT_FLUSH_DSQ);
		return;
	}

	if (cls == TASK_CLS_L0) {
		s32 res;

		stat_inc(STAT_L0_HIT);
		res = try_bg_prio_preempt_dispatch(p, enq_flags, l_slice);
		if (res == PRIO_DISPATCH_IDLE) {
			stat_inc(STAT_L0_IDLE_DIRECT);
			return;
		}
		if (res == PRIO_DISPATCH_PREEMPT) {
			stat_inc(STAT_L0_PREEMPT);
			return;
		}
		stat_inc(STAT_L0_PREEMPT_FAIL);
		if (fifo_sched) {
			scx_bpf_dsq_insert(p, BG_PRIO_DSQ, l_slice, enq_flags);
		} else {
			struct scx_db_metrics_value *dbm =
				bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
			u64 bonus = compute_l0_bonus(dbm);
			u64 vtime = prio_vtime(p->scx.dsq_vtime, bonus);

			scx_bpf_dsq_insert_vtime(p, BG_PRIO_DSQ, l_slice, vtime, enq_flags);
		}
		stat_inc(STAT_L0_DSQ);
		return;
	}

	if (cls == TASK_CLS_COMP) {
		scx_bpf_dsq_insert(p, COMP_DSQ, c_slice, enq_flags);
		return;
	}

	scx_bpf_dsq_insert(p, SHARED_DSQ, s_slice, enq_flags);
}

static __always_inline bool try_rescue_shared(s32 cpu)
{
	struct task_struct *p;
	u64 now = bpf_ktime_get_ns();

	bpf_for_each(scx_dsq, p, SHARED_DSQ, 0) {
		unsigned long runnable_at = p->scx.runnable_at;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		if (!runnable_at || now < runnable_at ||
		    now - runnable_at < 1000000000ULL)
			break;
		if (__COMPAT_scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SCX_DSQ_LOCAL, 0)) {
			stat_inc(STAT_WAIT_OVERRIDE);
			return true;
		}
	}
	return false;
}

void BPF_STRUCT_OPS(adaptive_bg_prio_v4_dispatch, s32 cpu, struct task_struct *prev)
{
	if (scx_bpf_dsq_move_to_local(BG_PRIO_DSQ))
		return;

	if (try_rescue_shared(cpu))
		return;

	if (scx_bpf_dsq_move_to_local(COMP_DSQ))
		return;

	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(adaptive_bg_prio_v4_running, struct task_struct *p)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 cls = classify_task_nostat(p);
	u32 prio_state = (cls == TASK_CLS_FLUSH || cls == TASK_CLS_L0) ?
			 CPU_PRIO_BG_PRIO : CPU_PRIO_NONE;
	u32 preemptable = p->mm ? 1 : 0;
	u32 pid = p->pid;

	if (cpu < MAX_TRACK_CPUS) {
		bpf_map_update_elem(&cpu_prio_state_map, &cpu, &prio_state, BPF_ANY);
		bpf_map_update_elem(&cpu_preemptable_map, &cpu, &preemptable, BPF_ANY);
	}
	bpf_map_delete_elem(&task_wait_map, &pid);

	if (fifo_sched)
		return;
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(adaptive_bg_prio_v4_stopping, struct task_struct *p, bool runnable)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 zero = 0;

	if (cpu < MAX_TRACK_CPUS) {
		bpf_map_update_elem(&cpu_prio_state_map, &cpu, &zero, BPF_ANY);
		bpf_map_update_elem(&cpu_preemptable_map, &cpu, &zero, BPF_ANY);
	}

	if (fifo_sched)
		return;
	if (p->scx.slice < SCX_SLICE_DFL)
		p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(adaptive_bg_prio_v4_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(adaptive_bg_prio_v4_init)
{
	s32 ret;

	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret)
		return ret;
	ret = scx_bpf_create_dsq(COMP_DSQ, -1);
	if (ret)
		return ret;
	return scx_bpf_create_dsq(BG_PRIO_DSQ, -1);
}

void BPF_STRUCT_OPS(adaptive_bg_prio_v4_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(adaptive_bg_prio_v4_ops,
	       .select_cpu = (void *)adaptive_bg_prio_v4_select_cpu,
	       .enqueue    = (void *)adaptive_bg_prio_v4_enqueue,
	       .dispatch   = (void *)adaptive_bg_prio_v4_dispatch,
	       .running    = (void *)adaptive_bg_prio_v4_running,
	       .stopping   = (void *)adaptive_bg_prio_v4_stopping,
	       .enable     = (void *)adaptive_bg_prio_v4_enable,
	       .init       = (void *)adaptive_bg_prio_v4_init,
	       .exit       = (void *)adaptive_bg_prio_v4_exit,
	       .name       = "adaptive_bg_prio_v4");
