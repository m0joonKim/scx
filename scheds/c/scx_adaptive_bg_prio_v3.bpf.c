/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Adaptive background priority sched_ext scheduler (v3).
 *
 * v3 change over v1: flush threads can NO LONGER preempt running L0
 * compaction threads.  In v1, a waking flush thread would kick an
 * in-progress L0→L1 compaction off its CPU, wasting the remaining slice
 * and delaying compaction.  v3 limits flush preemption to CPUs running
 * COMP/SHARED tasks (CPU_PRIO_NONE), forcing flush to wait for an idle
 * CPU or a lower-priority CPU instead.
 *
 * Expected effect: L0→L1 compaction runs to completion without
 * interruption → lower L0 stall.  Memtable stall may increase slightly
 * because flush must wait longer for a preemptable CPU.
 *
 * Dispatch order: FLUSH_DSQ > L0_DSQ > COMP_DSQ > SHARED_DSQ  (same as v1)
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
const volatile u64 flush_budget;
const volatile u64 l0_budget;
const volatile u64 memtable_bytes_thr;
const volatile u64 imm_memtables_thr;
const volatile u64 l0_files_thr;

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ 0
#define FLUSH_DSQ  1
#define L0_DSQ     2
#define COMP_DSQ   3

#define BG_FLUSH_CLASS      1
#define BG_COMPACTION_CLASS 2
#define MAX_TRACK_CPUS  4096
#define WAIT_MAP_ENTRIES 16384

/* CPU prio state values — must NOT overlap with BG_*_CLASS constants */
#define CPU_PRIO_NONE  0
#define CPU_PRIO_FLUSH 1
#define CPU_PRIO_L0    2

/*
 * classify_task() return values — use values distinct from CPU_PRIO_* and
 * BG_*_CLASS to avoid accidental aliasing.
 */
#define TASK_CLS_NONE      0   /* non-RocksDB or no map entry */
#define TASK_CLS_FLUSH     1   /* flush with memtable pressure (== CPU_PRIO_FLUSH) */
#define TASK_CLS_L0        2   /* L0 compaction with l0 pressure (== CPU_PRIO_L0) */
#define TASK_CLS_COMP      4   /* compaction, no pressure — distinct from all others */

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
	STAT_FLUSH_WAIT_OVERRIDE,
	STAT_L0_WAIT_OVERRIDE,
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

/* CPU -> priority level of currently running task: 0=none, 1=flush, 2=l0 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_prio_state_map SEC(".maps");

/* CPU -> can be preempted (p->mm != NULL) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_preemptable_map SEC(".maps");

/* CPU -> consecutive flush dispatch count */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_flush_cnt_map SEC(".maps");

/* CPU -> consecutive L0 dispatch count */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_l0_cnt_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32); /* tid */
	__type(value, struct scx_thread_class_value);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rocksdb_scx_thread_class_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32); /* tgid */
	__type(value, struct scx_db_metrics_value);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rocksdb_scx_db_metrics_map SEC(".maps");

/* task pid -> enqueue timestamp (ns) for wait-time safety */
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
	u64 age_limit = metrics_max_age_ns ? : 3000000000ULL; /* 3s */
	u64 now = bpf_ktime_get_ns();

	if (!dbm)
		return true;
	if (now < dbm->timestamp_ns)
		return false;
	return now - dbm->timestamp_ns > age_limit;
}


/*
 * Classify the task into one of TASK_CLS_* values.
 * Counts stats; use _nostat variant in running hook.
 */
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

/* running hook variant: no stat_inc calls */
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

static __always_inline u64 prio_vtime(u64 vtime, u64 bonus_ns)
{
	u64 min_vtime = vtime_now > bonus_ns ? vtime_now - bonus_ns : 0;

	if (time_before(vtime, min_vtime))
		return vtime;
	return min_vtime;
}

enum prio_dispatch_res {
	PRIO_DISPATCH_FAIL    = 0,
	PRIO_DISPATCH_IDLE    = 1,
	PRIO_DISPATCH_PREEMPT = 2,
};

/*
 * v3: flush can preempt COMP/SHARED tasks but NOT L0 compaction tasks.
 * Preempting an in-progress L0→L1 compaction wastes the remaining slice
 * and delays compaction completion, causing higher L0 stall.  Flush must
 * find an idle CPU or a non-priority CPU instead.
 */
static __always_inline s32 try_flush_preempt_dispatch(struct task_struct *p,
						       u64 enq_flags, u64 slice_ns)
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

	/* Skip CPUs running flush or L0 compaction tasks */
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

/*
 * L0 can preempt only non-prio tasks (prio_state == CPU_PRIO_NONE)
 * that have p->mm.  Flush-prio tasks are protected.
 */
static __always_inline s32 try_l0_preempt_dispatch(struct task_struct *p,
						    u64 enq_flags, u64 slice_ns)
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


static __always_inline bool should_force_shared(s32 cpu)
{
	u32 key = (u32)cpu;
	u32 *cnt_p;
	u64 budget = flush_budget ? : 3;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return false;
	cnt_p = bpf_map_lookup_elem(&cpu_flush_cnt_map, &key);
	return cnt_p && *cnt_p >= budget;
}

static __always_inline bool should_force_comp(s32 cpu)
{
	u32 key = (u32)cpu;
	u32 *cnt_p;
	u64 budget = l0_budget ? : 2;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return false;
	cnt_p = bpf_map_lookup_elem(&cpu_l0_cnt_map, &key);
	return cnt_p && *cnt_p >= budget;
}

static __always_inline void bump_flush_cnt(s32 cpu, bool ran_flush)
{
	u32 key = (u32)cpu;
	u32 cnt = 0;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return;
	if (ran_flush) {
		u32 *cnt_p = bpf_map_lookup_elem(&cpu_flush_cnt_map, &key);
		cnt = cnt_p ? *cnt_p : 0;
		if (cnt < 0xffffffff)
			cnt++;
	}
	bpf_map_update_elem(&cpu_flush_cnt_map, &key, &cnt, BPF_ANY);
}

static __always_inline void bump_l0_cnt(s32 cpu, bool ran_l0)
{
	u32 key = (u32)cpu;
	u32 cnt = 0;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return;
	if (ran_l0) {
		u32 *cnt_p = bpf_map_lookup_elem(&cpu_l0_cnt_map, &key);
		cnt = cnt_p ? *cnt_p : 0;
		if (cnt < 0xffffffff)
			cnt++;
	}
	bpf_map_update_elem(&cpu_l0_cnt_map, &key, &cnt, BPF_ANY);
}

s32 BPF_STRUCT_OPS(adaptive_bg_prio_v3_select_cpu, struct task_struct *p,
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

void BPF_STRUCT_OPS(adaptive_bg_prio_v3_enqueue, struct task_struct *p, u64 enq_flags)
{
	u32 cls = classify_task(p);
	u64 f_slice = flush_slice_ns  ? : 120000000ULL; /* 120ms */
	u64 l_slice = l0_slice_ns     ? : 250000000ULL; /* 250ms */
	u64 c_slice = comp_slice_ns   ? : 20000000ULL;  /* 20ms  */
	u64 s_slice = shared_slice_ns ? : SCX_SLICE_DFL;
	u64 now = bpf_ktime_get_ns();
	u32 pid = p->pid;
	u64 *enq_ts = bpf_map_lookup_elem(&task_wait_map, &pid);

	stat_inc(STAT_GLOBAL);
	if (!enq_ts)
		bpf_map_update_elem(&task_wait_map, &pid, &now, BPF_ANY);

	if (cls == TASK_CLS_FLUSH) {
		s32 res;

		stat_inc(STAT_FLUSH_HIT);
		res = try_flush_preempt_dispatch(p, enq_flags, f_slice);
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
			scx_bpf_dsq_insert(p, FLUSH_DSQ, f_slice, enq_flags);
		} else {
			u64 vtime = prio_vtime(p->scx.dsq_vtime, f_slice * 2);
			scx_bpf_dsq_insert_vtime(p, FLUSH_DSQ, f_slice, vtime, enq_flags);
		}
		stat_inc(STAT_FLUSH_DSQ);
		return;
	}

	if (cls == TASK_CLS_L0) {
		s32 res;

		stat_inc(STAT_L0_HIT);
		res = try_l0_preempt_dispatch(p, enq_flags, l_slice);
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
			scx_bpf_dsq_insert(p, L0_DSQ, l_slice, enq_flags);
		} else {
			u64 vtime = prio_vtime(p->scx.dsq_vtime, l_slice * 4);
			scx_bpf_dsq_insert_vtime(p, L0_DSQ, l_slice, vtime, enq_flags);
		}
		stat_inc(STAT_L0_DSQ);
		return;
	}

	if (cls == TASK_CLS_COMP) {
		/*
		 * Use FIFO for COMP_DSQ: tasks dispatch in insertion order so
		 * the longest-waiting task is always at the front.  vtime
		 * ordering causes permanent starvation when tasks carry over
		 * low vtimes from a previous L0/flush priority period.
		 */
		scx_bpf_dsq_insert(p, COMP_DSQ, c_slice, enq_flags);
		return;
	}

	/*
	 * SHARED_DSQ: always FIFO.  vtime ordering causes starvation when tasks
	 * carry over extreme vtimes (e.g. from stopping-hook underflow after
	 * being preempted mid long-slice).  Oldest-inserted task dispatched first.
	 */
	scx_bpf_dsq_insert(p, SHARED_DSQ, s_slice, enq_flags);
}

/*
 * Rescue a SHARED_DSQ task that has been starved by COMP.
 * COMP_DSQ has no explicit budget cap against SHARED_DSQ, so without this
 * a continuously-busy COMP_DSQ would starve SHARED_DSQ indefinitely.
 *
 * SHARED_DSQ is FIFO, so the front task is always the longest-waiting one.
 * We check only the front task (break on first non-matching): O(1).
 * Threshold is 1 s — high enough to never interfere with normal priority
 * dispatch, low enough to fire well before the 30 s SCX watchdog.
 */
static __always_inline bool try_rescue_shared(s32 cpu)
{
	struct task_struct *p;
	u64 now = bpf_ktime_get_ns();

	bpf_for_each(scx_dsq, p, SHARED_DSQ, 0) {
		unsigned long runnable_at = p->scx.runnable_at;

		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		/* FIFO: front task is oldest; if it hasn't waited 1 s, nobody has */
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

void BPF_STRUCT_OPS(adaptive_bg_prio_v3_dispatch, s32 cpu, struct task_struct *prev)
{
	/* flush_budget exhausted: let L0/COMP/SHARED run */
	if (should_force_shared(cpu)) {
		if (scx_bpf_dsq_move_to_local(L0_DSQ)) {
			bump_flush_cnt(cpu, false);
			bump_l0_cnt(cpu, true);
			return;
		}
		if (scx_bpf_dsq_move_to_local(COMP_DSQ)) {
			bump_flush_cnt(cpu, false);
			bump_l0_cnt(cpu, false);
			return;
		}
		if (scx_bpf_dsq_move_to_local(SHARED_DSQ)) {
			bump_flush_cnt(cpu, false);
			bump_l0_cnt(cpu, false);
			return;
		}
	}

	/* l0_budget exhausted: force COMP/SHARED */
	if (should_force_comp(cpu)) {
		if (scx_bpf_dsq_move_to_local(COMP_DSQ)) {
			bump_flush_cnt(cpu, false);
			bump_l0_cnt(cpu, false);
			return;
		}
		if (scx_bpf_dsq_move_to_local(SHARED_DSQ)) {
			bump_flush_cnt(cpu, false);
			bump_l0_cnt(cpu, false);
			return;
		}
	}

	/* Normal priority: FLUSH and L0 are strictly highest */
	if (scx_bpf_dsq_move_to_local(FLUSH_DSQ)) {
		bump_flush_cnt(cpu, true);
		bump_l0_cnt(cpu, false);
		return;
	}
	if (scx_bpf_dsq_move_to_local(L0_DSQ)) {
		bump_flush_cnt(cpu, false);
		bump_l0_cnt(cpu, true);
		return;
	}

	/*
	 * Rescue SHARED_DSQ tasks starved ≥1 s by a busy COMP_DSQ.
	 * Placed after FLUSH/L0 to preserve strict priority: a flush task
	 * in FLUSH_DSQ always wins over a starved SHARED task.  COMP_DSQ has
	 * no explicit budget cap against SHARED_DSQ, so without this a
	 * continuously-busy COMP_DSQ starves SHARED_DSQ indefinitely.
	 * SHARED_DSQ is FIFO, so checking the front task is O(1).
	 */
	if (try_rescue_shared(cpu))
		return;

	if (scx_bpf_dsq_move_to_local(COMP_DSQ)) {
		bump_flush_cnt(cpu, false);
		bump_l0_cnt(cpu, false);
		return;
	}
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(adaptive_bg_prio_v3_running, struct task_struct *p)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 prio_state = classify_task_nostat(p);
	u32 preemptable = p->mm ? 1 : 0;
	u32 pid = p->pid;

	/*
	 * TASK_CLS_COMP (4) is not a cpu_prio_state level — clamp to NONE so
	 * cpu_prio_state_map only holds CPU_PRIO_{NONE,FLUSH,L0}.
	 */
	if (prio_state == TASK_CLS_COMP)
		prio_state = CPU_PRIO_NONE;

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

void BPF_STRUCT_OPS(adaptive_bg_prio_v3_stopping, struct task_struct *p, bool runnable)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 zero = 0;

	if (cpu < MAX_TRACK_CPUS) {
		bpf_map_update_elem(&cpu_prio_state_map, &cpu, &zero, BPF_ANY);
		bpf_map_update_elem(&cpu_preemptable_map, &cpu, &zero, BPF_ANY);
	}

	if (fifo_sched)
		return;
	/*
	 * Guard against u64 underflow: flush/L0 tasks get slices larger than
	 * SCX_SLICE_DFL (120ms / 250ms).  If preempted early, p->scx.slice can
	 * exceed SCX_SLICE_DFL, making the subtraction wrap to ~2^64.
	 */
	if (p->scx.slice < SCX_SLICE_DFL)
		p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(adaptive_bg_prio_v3_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(adaptive_bg_prio_v3_init)
{
	s32 ret;

	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret)
		return ret;
	ret = scx_bpf_create_dsq(FLUSH_DSQ, -1);
	if (ret)
		return ret;
	ret = scx_bpf_create_dsq(L0_DSQ, -1);
	if (ret)
		return ret;
	return scx_bpf_create_dsq(COMP_DSQ, -1);
}

void BPF_STRUCT_OPS(adaptive_bg_prio_v3_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(adaptive_bg_prio_v3_ops,
	       .select_cpu	= (void *)adaptive_bg_prio_v3_select_cpu,
	       .enqueue		= (void *)adaptive_bg_prio_v3_enqueue,
	       .dispatch	= (void *)adaptive_bg_prio_v3_dispatch,
	       .running		= (void *)adaptive_bg_prio_v3_running,
	       .stopping	= (void *)adaptive_bg_prio_v3_stopping,
	       .enable		= (void *)adaptive_bg_prio_v3_enable,
	       .init		= (void *)adaptive_bg_prio_v3_init,
	       .exit		= (void *)adaptive_bg_prio_v3_exit,
	       .name		= "adaptive_bg_prio_v3");
