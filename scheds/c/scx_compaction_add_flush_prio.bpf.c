/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Compaction-priority scheduler with selective flush elevation.
 *
 * Base: scx_l0_compaction_prio (L0 compaction super-priority when l0_files >= thr).
 * Extension: flush threads promoted to FLUSH_DSQ when memtable pressure is detected.
 *
 * DSQ dispatch priority:
 *   1. SUPER_DSQ  — L0 compaction with l0_files >= l0_files_thr
 *   2. FLUSH_DSQ  — flush with imm_memtables >= imm_thr OR memtable_bytes >= mem_thr
 *   3. COMP_DSQ   — other compaction
 *   4. SHARED_DSQ — everything else (including non-pressure flush)
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;
const volatile u64 super_slice_ns;
const volatile u64 flush_slice_ns;
const volatile u64 comp_slice_ns;
const volatile u64 shared_slice_ns;
const volatile u64 l0_files_thr;
const volatile u64 imm_memtables_thr;
const volatile u64 memtable_bytes_thr;
const volatile u64 metrics_max_age_ns;
const volatile u64 wait_safety_ns;
const volatile u64 super_budget;
const volatile u64 l0_budget;
const volatile u64 flush_budget;

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ          0
#define SUPER_DSQ           1
#define FLUSH_DSQ           2
#define COMP_DSQ            3
#define BG_FLUSH_CLASS      1
#define BG_COMPACTION_CLASS 2
#define MAX_TRACK_CPUS      4096
#define WAIT_MAP_ENTRIES    16384

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
	STAT_SUPER_HIT,
	STAT_SUPER_IDLE_DIRECT,
	STAT_SUPER_PREEMPT,
	STAT_SUPER_PREEMPT_FAIL,
	STAT_SUPER_DSQ,
	STAT_FLUSH_HIT,
	STAT_FLUSH_IDLE_DIRECT,
	STAT_FLUSH_PREEMPT,
	STAT_FLUSH_PREEMPT_FAIL,
	STAT_FLUSH_DSQ,
	STAT_METRICS_MISS,
	STAT_THREAD_MISS,
	STAT_METRICS_STALE,
	STAT_WAIT_OVERRIDE,
	STAT_SUPER_WAIT_OVERRIDE,
	STAT_FLUSH_WAIT_OVERRIDE,
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
} cpu_super_state_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_flush_state_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_preemptable_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_super_cnt_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_l0_cnt_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_flush_cnt_map SEC(".maps");

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

static __always_inline bool task_wait_exceeds(struct task_struct *p, u64 now, u64 wait_ns)
{
	unsigned long runnable_at = p->scx.runnable_at;
	u32 pid;
	u64 *enq_ts;

	if (!wait_ns)
		return false;
	if (runnable_at) {
		if (now < runnable_at)
			return false;
		return now - runnable_at >= wait_ns;
	}

	pid = p->pid;
	enq_ts = bpf_map_lookup_elem(&task_wait_map, &pid);
	if (!enq_ts)
		return false;
	if (now < *enq_ts)
		return false;
	return now - *enq_ts >= wait_ns;
}

static __always_inline bool is_cpu_running_super(s32 cpu)
{
	u32 key = (u32)cpu;
	u32 *p;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return false;
	p = bpf_map_lookup_elem(&cpu_super_state_map, &key);
	return p && *p == 1;
}

static __always_inline bool is_cpu_running_flush(s32 cpu)
{
	u32 key = (u32)cpu;
	u32 *p;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return false;
	p = bpf_map_lookup_elem(&cpu_flush_state_map, &key);
	return p && *p == 1;
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

static __always_inline u64 super_vtime(u64 vtime, u64 bonus_ns)
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

/* Dispatch p to idle CPU or preempt any non-super CPU. */
static __always_inline s32 try_super_preempt_dispatch(struct task_struct *p, u64 enq_flags,
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
	    !is_cpu_running_super(target) && is_cpu_preemptable(target))
		victim = target;

	if (victim < 0) {
		nr_cpus = scx_bpf_nr_cpu_ids();
		bpf_for(cpu, 0, nr_cpus) {
			if (cpu == target)
				continue;
			if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
				continue;
			if (is_cpu_running_super(cpu))
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

/* Dispatch flush p to idle CPU or preempt a non-super, non-flush CPU. */
static __always_inline s32 try_flush_preempt_dispatch(struct task_struct *p, u64 enq_flags,
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
	    !is_cpu_running_super(target) && !is_cpu_running_flush(target) &&
	    is_cpu_preemptable(target))
		victim = target;

	if (victim < 0) {
		nr_cpus = scx_bpf_nr_cpu_ids();
		bpf_for(cpu, 0, nr_cpus) {
			if (cpu == target)
				continue;
			if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
				continue;
			if (is_cpu_running_super(cpu))
				continue;
			if (is_cpu_running_flush(cpu))
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

static __always_inline bool try_wait_safety_dispatch_dsq(s32 cpu, u64 dsq_id, u32 stat_idx_val)
{
	struct task_struct *p;
	u64 wait_ns = wait_safety_ns ? : 5000000ULL;
	u64 now;

	if (cpu < 0 || !wait_ns)
		return false;

	now = bpf_ktime_get_ns();

	bpf_for_each(scx_dsq, p, dsq_id, 0) {
		if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		if (!task_wait_exceeds(p, now, wait_ns))
			continue;
		if (__COMPAT_scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SCX_DSQ_LOCAL, 0)) {
			stat_inc(stat_idx_val);
			return true;
		}
	}

	return false;
}

static __always_inline bool should_force_shared(s32 cpu)
{
	u32 key = (u32)cpu;
	u32 *cnt_p;
	u64 budget = super_budget ? : 3;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return false;
	cnt_p = bpf_map_lookup_elem(&cpu_super_cnt_map, &key);
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

static __always_inline bool should_force_non_flush(s32 cpu)
{
	u32 key = (u32)cpu;
	u32 *cnt_p;
	u64 budget = flush_budget ? : 3;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return false;
	cnt_p = bpf_map_lookup_elem(&cpu_flush_cnt_map, &key);
	return cnt_p && *cnt_p >= budget;
}

static __always_inline void bump_super_cnt(s32 cpu, bool inc)
{
	u32 key = (u32)cpu;
	u32 cnt = 0;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return;
	if (inc) {
		u32 *cnt_p = bpf_map_lookup_elem(&cpu_super_cnt_map, &key);

		cnt = cnt_p ? *cnt_p : 0;
		if (cnt < 0xffffffff)
			cnt++;
	}
	bpf_map_update_elem(&cpu_super_cnt_map, &key, &cnt, BPF_ANY);
}

static __always_inline void bump_l0_cnt(s32 cpu, bool inc)
{
	u32 key = (u32)cpu;
	u32 cnt = 0;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return;
	if (inc) {
		u32 *cnt_p = bpf_map_lookup_elem(&cpu_l0_cnt_map, &key);

		cnt = cnt_p ? *cnt_p : 0;
		if (cnt < 0xffffffff)
			cnt++;
	}
	bpf_map_update_elem(&cpu_l0_cnt_map, &key, &cnt, BPF_ANY);
}

static __always_inline void bump_flush_cnt(s32 cpu, bool inc)
{
	u32 key = (u32)cpu;
	u32 cnt = 0;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return;
	if (inc) {
		u32 *cnt_p = bpf_map_lookup_elem(&cpu_flush_cnt_map, &key);

		cnt = cnt_p ? *cnt_p : 0;
		if (cnt < 0xffffffff)
			cnt++;
	}
	bpf_map_update_elem(&cpu_flush_cnt_map, &key, &cnt, BPF_ANY);
}

static __always_inline void reset_all_cnts(s32 cpu)
{
	bump_super_cnt(cpu, false);
	bump_l0_cnt(cpu, false);
	bump_flush_cnt(cpu, false);
}

/* running hook only: no stat increments. */
static __always_inline bool is_super_prio_task_nostat(struct task_struct *p)
{
	u32 tid = p->pid;
	u32 tgid = p->tgid;
	struct scx_thread_class_value *tcls;
	struct scx_db_metrics_value *dbm;
	u64 thr = l0_files_thr ? : 4;

	tcls = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
	if (!tcls || tcls->class_id != BG_COMPACTION_CLASS || tcls->start_level != 0)
		return false;

	dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
	if (!dbm || metrics_is_stale(dbm))
		return false;

	return dbm->l0_files >= thr;
}

/* running hook only: no stat increments. */
static __always_inline bool is_flush_prio_task_nostat(struct task_struct *p)
{
	u32 tid = p->pid;
	u32 tgid = p->tgid;
	struct scx_thread_class_value *tcls;
	struct scx_db_metrics_value *dbm;
	u64 imm_thr = imm_memtables_thr ? : 1;
	u64 mem_thr = memtable_bytes_thr ? : (64ULL << 20);

	tcls = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
	if (!tcls || tcls->class_id != BG_FLUSH_CLASS)
		return false;

	dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
	if (!dbm || metrics_is_stale(dbm))
		return false;

	return dbm->num_immutable_memtables >= imm_thr ||
	       dbm->cur_size_all_memtables >= mem_thr;
}

s32 BPF_STRUCT_OPS(compaction_add_flush_prio_select_cpu, struct task_struct *p,
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

void BPF_STRUCT_OPS(compaction_add_flush_prio_enqueue, struct task_struct *p, u64 enq_flags)
{
	u32 tid = p->pid;
	u32 tgid = p->tgid;
	struct scx_thread_class_value *tcls;
	struct scx_db_metrics_value *dbm;
	u64 super_slice  = super_slice_ns  ? : 250000000ULL;
	u64 flush_slice  = flush_slice_ns  ? : 120000000ULL;
	u64 comp_slice   = comp_slice_ns   ? : SCX_SLICE_DFL;
	u64 shared_slice = shared_slice_ns ? : SCX_SLICE_DFL;
	u64 l0_thr  = l0_files_thr      ? : 4;
	u64 imm_thr = imm_memtables_thr ? : 1;
	u64 mem_thr = memtable_bytes_thr ? : (64ULL << 20);
	bool is_super = false, is_flush_prio = false, is_comp = false;
	u64 now = bpf_ktime_get_ns();
	u64 *enq_ts;

	stat_inc(STAT_GLOBAL);

	enq_ts = bpf_map_lookup_elem(&task_wait_map, &tid);
	if (!enq_ts)
		bpf_map_update_elem(&task_wait_map, &tid, &now, BPF_ANY);

	tcls = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
	if (!tcls) {
		stat_inc(STAT_THREAD_MISS);
		goto insert_shared;
	}

	if (tcls->class_id == BG_COMPACTION_CLASS) {
		is_comp = true;
		if (tcls->start_level == 0) {
			dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
			if (!dbm)
				stat_inc(STAT_METRICS_MISS);
			else if (metrics_is_stale(dbm))
				stat_inc(STAT_METRICS_STALE);
			else if (dbm->l0_files >= l0_thr)
				is_super = true;
		}
	} else if (tcls->class_id == BG_FLUSH_CLASS) {
		dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
		if (!dbm)
			stat_inc(STAT_METRICS_MISS);
		else if (metrics_is_stale(dbm))
			stat_inc(STAT_METRICS_STALE);
		else if (dbm->num_immutable_memtables >= imm_thr ||
			 dbm->cur_size_all_memtables >= mem_thr)
			is_flush_prio = true;
	}

	if (is_super) {
		s32 res;

		stat_inc(STAT_SUPER_HIT);
		res = try_super_preempt_dispatch(p, enq_flags, super_slice);
		if (res == PRIO_DISPATCH_IDLE) {
			stat_inc(STAT_SUPER_IDLE_DIRECT);
			return;
		}
		if (res == PRIO_DISPATCH_PREEMPT) {
			stat_inc(STAT_SUPER_PREEMPT);
			return;
		}
		stat_inc(STAT_SUPER_PREEMPT_FAIL);
		if (fifo_sched) {
			scx_bpf_dsq_insert(p, SUPER_DSQ, super_slice, enq_flags);
		} else {
			u64 vtime = super_vtime(p->scx.dsq_vtime, super_slice * 4);

			scx_bpf_dsq_insert_vtime(p, SUPER_DSQ, super_slice, vtime, enq_flags);
		}
		stat_inc(STAT_SUPER_DSQ);
		return;
	}

	if (is_flush_prio) {
		s32 res;

		stat_inc(STAT_FLUSH_HIT);
		res = try_flush_preempt_dispatch(p, enq_flags, flush_slice);
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
			scx_bpf_dsq_insert(p, FLUSH_DSQ, flush_slice, enq_flags);
		} else {
			u64 vtime = p->scx.dsq_vtime;

			if (time_before(vtime, vtime_now - flush_slice))
				vtime = vtime_now - flush_slice;
			scx_bpf_dsq_insert_vtime(p, FLUSH_DSQ, flush_slice, vtime, enq_flags);
		}
		stat_inc(STAT_FLUSH_DSQ);
		return;
	}

	if (is_comp) {
		if (fifo_sched) {
			scx_bpf_dsq_insert(p, COMP_DSQ, comp_slice, enq_flags);
		} else {
			u64 vtime = p->scx.dsq_vtime;

			if (time_before(vtime, vtime_now - comp_slice))
				vtime = vtime_now - comp_slice;
			scx_bpf_dsq_insert_vtime(p, COMP_DSQ, comp_slice, vtime, enq_flags);
		}
		return;
	}

insert_shared:
	if (fifo_sched) {
		scx_bpf_dsq_insert(p, SHARED_DSQ, shared_slice, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		if (time_before(vtime, vtime_now - shared_slice))
			vtime = vtime_now - shared_slice;
		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, shared_slice, vtime, enq_flags);
	}
}

void BPF_STRUCT_OPS(compaction_add_flush_prio_dispatch, s32 cpu, struct task_struct *prev)
{
	/* starvation prevention: dispatch any task waiting > wait_safety_ns */
	if (try_wait_safety_dispatch_dsq(cpu, SHARED_DSQ, STAT_WAIT_OVERRIDE))
		return;
	if (try_wait_safety_dispatch_dsq(cpu, SUPER_DSQ, STAT_SUPER_WAIT_OVERRIDE))
		return;
	if (try_wait_safety_dispatch_dsq(cpu, FLUSH_DSQ, STAT_FLUSH_WAIT_OVERRIDE))
		return;
	if (try_wait_safety_dispatch_dsq(cpu, COMP_DSQ, STAT_WAIT_OVERRIDE))
		return;

	/* budget enforcement */
	if (should_force_shared(cpu)) {
		if (scx_bpf_dsq_move_to_local(SHARED_DSQ)) {
			reset_all_cnts(cpu);
			return;
		}
	}
	if (should_force_comp(cpu)) {
		if (scx_bpf_dsq_move_to_local(COMP_DSQ)) {
			reset_all_cnts(cpu);
			return;
		}
	}
	if (should_force_non_flush(cpu)) {
		if (scx_bpf_dsq_move_to_local(COMP_DSQ)) {
			reset_all_cnts(cpu);
			return;
		}
		if (scx_bpf_dsq_move_to_local(SHARED_DSQ)) {
			reset_all_cnts(cpu);
			return;
		}
	}

	/* normal priority order: SUPER > FLUSH > COMP > SHARED */
	if (scx_bpf_dsq_move_to_local(SUPER_DSQ)) {
		bump_super_cnt(cpu, true);
		bump_l0_cnt(cpu, true);
		bump_flush_cnt(cpu, false);
		return;
	}
	if (scx_bpf_dsq_move_to_local(FLUSH_DSQ)) {
		bump_super_cnt(cpu, false);
		bump_l0_cnt(cpu, false);
		bump_flush_cnt(cpu, true);
		return;
	}
	if (scx_bpf_dsq_move_to_local(COMP_DSQ)) {
		reset_all_cnts(cpu);
		return;
	}
	if (scx_bpf_dsq_move_to_local(SHARED_DSQ))
		reset_all_cnts(cpu);
}

void BPF_STRUCT_OPS(compaction_add_flush_prio_running, struct task_struct *p)
{
	u32 cpu = bpf_get_smp_processor_id();
	bool is_super = is_super_prio_task_nostat(p);
	u32 running_super = is_super ? 1 : 0;
	u32 running_flush = (!is_super && is_flush_prio_task_nostat(p)) ? 1 : 0;
	u32 preemptable = p->mm ? 1 : 0;
	u32 tid = p->pid;

	if (cpu < MAX_TRACK_CPUS) {
		bpf_map_update_elem(&cpu_super_state_map, &cpu, &running_super, BPF_ANY);
		bpf_map_update_elem(&cpu_flush_state_map, &cpu, &running_flush, BPF_ANY);
		bpf_map_update_elem(&cpu_preemptable_map, &cpu, &preemptable, BPF_ANY);
	}
	bpf_map_delete_elem(&task_wait_map, &tid);

	if (fifo_sched)
		return;

	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(compaction_add_flush_prio_stopping, struct task_struct *p, bool runnable)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 zero = 0;

	if (cpu < MAX_TRACK_CPUS) {
		bpf_map_update_elem(&cpu_super_state_map, &cpu, &zero, BPF_ANY);
		bpf_map_update_elem(&cpu_flush_state_map, &cpu, &zero, BPF_ANY);
		bpf_map_update_elem(&cpu_preemptable_map, &cpu, &zero, BPF_ANY);
	}

	if (fifo_sched)
		return;

	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(compaction_add_flush_prio_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(compaction_add_flush_prio_init)
{
	s32 ret;

	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret)
		return ret;
	ret = scx_bpf_create_dsq(SUPER_DSQ, -1);
	if (ret)
		return ret;
	ret = scx_bpf_create_dsq(FLUSH_DSQ, -1);
	if (ret)
		return ret;
	return scx_bpf_create_dsq(COMP_DSQ, -1);
}

void BPF_STRUCT_OPS(compaction_add_flush_prio_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(compaction_add_flush_prio_ops,
	       .select_cpu = (void *)compaction_add_flush_prio_select_cpu,
	       .enqueue    = (void *)compaction_add_flush_prio_enqueue,
	       .dispatch   = (void *)compaction_add_flush_prio_dispatch,
	       .running    = (void *)compaction_add_flush_prio_running,
	       .stopping   = (void *)compaction_add_flush_prio_stopping,
	       .enable     = (void *)compaction_add_flush_prio_enable,
	       .init       = (void *)compaction_add_flush_prio_init,
	       .exit       = (void *)compaction_add_flush_prio_exit,
	       .name       = "compaction_add_flush_prio");
