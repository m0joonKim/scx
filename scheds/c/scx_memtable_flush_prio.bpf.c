/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Memtable-pressure-aware flush priority sched_ext scheduler.
 *
 * Flush-priority target:
 * - RocksDB flush thread (class_id=1)
 * - DB metrics are fresh
 * - memtable pressure is present:
 *   - num_immutable_memtables >= imm_memtables_thr, or
 *   - cur_size_all_memtables >= memtable_bytes_thr, or
 *   - stall_flag is set
 *
 * Priority flush tasks get:
 * - direct idle dispatch when possible
 * - preemptive dispatch against non-flush victims
 * - long slice
 * - dedicated flush DSQ consumed before compaction/shared DSQs
 *
 * Compactions are isolated into their own DSQ so flush pressure does not turn
 * into arbitrary starvation of every other runnable task.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;
const volatile u64 flush_slice_ns;
const volatile u64 shared_slice_ns;
const volatile u64 comp_slice_ns;
const volatile u64 metrics_max_age_ns;
const volatile u64 wait_safety_ns;
const volatile u64 flush_budget;
const volatile u64 memtable_bytes_thr;
const volatile u64 imm_memtables_thr;

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ 0
#define FLUSH_DSQ 1
#define COMP_DSQ 2
#define BG_FLUSH_CLASS 1
#define BG_COMPACTION_CLASS 2
#define MAX_TRACK_CPUS 4096
#define WAIT_MAP_ENTRIES 16384

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
	STAT_METRICS_MISS,
	STAT_THREAD_MISS,
	STAT_METRICS_STALE,
	STAT_WAIT_OVERRIDE,
	STAT_FLUSH_WAIT_OVERRIDE,
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

/* CPU -> currently running flush-priority task (1) or not (0). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_flush_state_map SEC(".maps");

/* CPU -> current task can be preempted by flush-priority task (1). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_preemptable_map SEC(".maps");

/* CPU -> consecutive flush dispatch count. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_flush_cnt_map SEC(".maps");

/* Reuse externally pinned map by map name. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32); /* tid */
	__type(value, struct scx_thread_class_value);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rocksdb_scx_thread_class_map SEC(".maps");

/* Reuse externally pinned map by map name. */
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

static __always_inline bool is_compaction_task(struct task_struct *p)
{
	u32 tid = p->pid;
	struct scx_thread_class_value *tcls;

	tcls = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
	return tcls && tcls->class_id == BG_COMPACTION_CLASS;
}

static __always_inline bool is_flush_prio_task(struct task_struct *p)
{
	u32 tid = p->pid;
	u32 tgid = p->tgid;
	struct scx_thread_class_value *tcls;
	struct scx_db_metrics_value *dbm;
	u64 bytes_thr = memtable_bytes_thr ? : (64ULL << 20);
	u64 imm_thr = imm_memtables_thr ? : 1;

	tcls = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
	if (!tcls) {
		stat_inc(STAT_THREAD_MISS);
		return false;
	}

	if (tcls->class_id != BG_FLUSH_CLASS)
		return false;

	dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
	if (!dbm) {
		stat_inc(STAT_METRICS_MISS);
		return false;
	}
	if (metrics_is_stale(dbm)) {
		stat_inc(STAT_METRICS_STALE);
		return false;
	}

	if (dbm->stall_flag)
		return true;
	if (dbm->num_immutable_memtables >= imm_thr)
		return true;
	return dbm->cur_size_all_memtables >= bytes_thr;
}

/* running 훅 전용: stats 카운터를 건드리지 않는 버전 */
static __always_inline bool is_flush_prio_task_nostat(struct task_struct *p)
{
	u32 tid = p->pid;
	u32 tgid = p->tgid;
	struct scx_thread_class_value *tcls;
	struct scx_db_metrics_value *dbm;
	u64 bytes_thr = memtable_bytes_thr ? : (64ULL << 20);
	u64 imm_thr = imm_memtables_thr ? : 1;

	tcls = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
	if (!tcls)
		return false;

	if (tcls->class_id != BG_FLUSH_CLASS)
		return false;

	dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
	if (!dbm)
		return false;
	if (metrics_is_stale(dbm))
		return false;

	if (dbm->stall_flag)
		return true;
	if (dbm->num_immutable_memtables >= imm_thr)
		return true;
	return dbm->cur_size_all_memtables >= bytes_thr;
}

static __always_inline bool is_cpu_running_flush(s32 cpu)
{
	u32 key = (u32)cpu;
	u32 *running_p;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return false;

	running_p = bpf_map_lookup_elem(&cpu_flush_state_map, &key);
	return running_p && *running_p == 1;
}

static __always_inline bool is_cpu_preemptable(s32 cpu)
{
	u32 key = (u32)cpu;
	u32 *preemptable_p;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return false;

	preemptable_p = bpf_map_lookup_elem(&cpu_preemptable_map, &key);
	return preemptable_p && *preemptable_p == 1;
}

static __always_inline u64 flush_vtime(u64 vtime, u64 bonus_ns)
{
	u64 min_vtime = vtime_now > bonus_ns ? vtime_now - bonus_ns : 0;

	if (time_before(vtime, min_vtime))
		return vtime;
	return min_vtime;
}

enum flush_dispatch_res {
	FLUSH_DISPATCH_FAIL = 0,
	FLUSH_DISPATCH_IDLE = 1,
	FLUSH_DISPATCH_PREEMPT = 2,
};

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
		return FLUSH_DISPATCH_IDLE;
	}

	if (target >= 0 && bpf_cpumask_test_cpu(target, p->cpus_ptr) &&
	    !is_cpu_running_flush(target) && is_cpu_preemptable(target))
		victim = target;

	if (victim < 0) {
		nr_cpus = scx_bpf_nr_cpu_ids();
		bpf_for(cpu, 0, nr_cpus) {
			if (cpu == target)
				continue;
			if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
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
		return FLUSH_DISPATCH_PREEMPT;
	}

	return FLUSH_DISPATCH_FAIL;
}

static __always_inline bool try_wait_safety_dispatch_dsq(s32 cpu, u64 dsq_id, u32 stat_idx)
{
	struct task_struct *p;
	u64 wait_ns = wait_safety_ns ? : 5000000ULL; /* 5ms default */
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
			stat_inc(stat_idx);
			return true;
		}
	}

	return false;
}

static __always_inline bool should_force_shared(s32 cpu)
{
	u32 key = (u32)cpu;
	u32 *cnt_p;
	u64 budget = flush_budget ? : 3;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return false;
	cnt_p = bpf_map_lookup_elem(&cpu_flush_cnt_map, &key);
	if (!cnt_p)
		return false;
	return *cnt_p >= budget;
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

s32 BPF_STRUCT_OPS(memtable_flush_prio_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
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

void BPF_STRUCT_OPS(memtable_flush_prio_enqueue, struct task_struct *p, u64 enq_flags)
{
	bool flush = is_flush_prio_task(p);
	bool comp = is_compaction_task(p);
	u64 prio_slice = flush_slice_ns ? : 120000000ULL; /* 120ms default */
	u64 shared_slice = shared_slice_ns ? : SCX_SLICE_DFL;
	u64 comp_slice = comp_slice_ns ? : shared_slice;
	u64 now = bpf_ktime_get_ns();
	u32 pid = p->pid;
	u64 *enq_ts = bpf_map_lookup_elem(&task_wait_map, &pid);

	stat_inc(STAT_GLOBAL);

	if (!enq_ts)
		bpf_map_update_elem(&task_wait_map, &pid, &now, BPF_ANY);

	if (flush) {
		s32 dispatch_res;

		stat_inc(STAT_FLUSH_HIT);

		dispatch_res = try_flush_preempt_dispatch(p, enq_flags, prio_slice);
		if (dispatch_res == FLUSH_DISPATCH_IDLE) {
			stat_inc(STAT_FLUSH_IDLE_DIRECT);
			return;
		}
		if (dispatch_res == FLUSH_DISPATCH_PREEMPT) {
			stat_inc(STAT_FLUSH_PREEMPT);
			return;
		}
		stat_inc(STAT_FLUSH_PREEMPT_FAIL);

		if (fifo_sched) {
			scx_bpf_dsq_insert(p, FLUSH_DSQ, prio_slice, enq_flags);
		} else {
			u64 vtime = flush_vtime(p->scx.dsq_vtime, prio_slice * 2);

			scx_bpf_dsq_insert_vtime(p, FLUSH_DSQ, prio_slice, vtime,
						 enq_flags);
		}
		stat_inc(STAT_FLUSH_DSQ);
		return;
	}

	if (comp) {
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

	if (fifo_sched) {
		scx_bpf_dsq_insert(p, SHARED_DSQ, shared_slice, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		if (time_before(vtime, vtime_now - shared_slice))
			vtime = vtime_now - shared_slice;

		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, shared_slice, vtime, enq_flags);
	}
}

void BPF_STRUCT_OPS(memtable_flush_prio_dispatch, s32 cpu, struct task_struct *prev)
{
	if (try_wait_safety_dispatch_dsq(cpu, SHARED_DSQ, STAT_WAIT_OVERRIDE))
		return;
	if (try_wait_safety_dispatch_dsq(cpu, COMP_DSQ, STAT_WAIT_OVERRIDE))
		return;
	if (try_wait_safety_dispatch_dsq(cpu, FLUSH_DSQ, STAT_FLUSH_WAIT_OVERRIDE))
		return;
	if (should_force_shared(cpu)) {
		if (scx_bpf_dsq_move_to_local(SHARED_DSQ)) {
			bump_flush_cnt(cpu, false);
			return;
		}
		if (scx_bpf_dsq_move_to_local(COMP_DSQ)) {
			bump_flush_cnt(cpu, false);
			return;
		}
	}
	if (scx_bpf_dsq_move_to_local(FLUSH_DSQ)) {
		bump_flush_cnt(cpu, true);
		return;
	}
	if (scx_bpf_dsq_move_to_local(COMP_DSQ)) {
		bump_flush_cnt(cpu, false);
		return;
	}
	if (scx_bpf_dsq_move_to_local(SHARED_DSQ)) {
		bump_flush_cnt(cpu, false);
		return;
	}
}

void BPF_STRUCT_OPS(memtable_flush_prio_running, struct task_struct *p)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 running = is_flush_prio_task_nostat(p) ? 1 : 0;
	u32 preemptable = p->mm ? 1 : 0;
	u32 pid = p->pid;

	if (cpu < MAX_TRACK_CPUS)
		bpf_map_update_elem(&cpu_flush_state_map, &cpu, &running, BPF_ANY);
	if (cpu < MAX_TRACK_CPUS)
		bpf_map_update_elem(&cpu_preemptable_map, &cpu, &preemptable, BPF_ANY);
	bpf_map_delete_elem(&task_wait_map, &pid);

	if (fifo_sched)
		return;

	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(memtable_flush_prio_stopping, struct task_struct *p, bool runnable)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 zero = 0;

	if (cpu < MAX_TRACK_CPUS)
		bpf_map_update_elem(&cpu_flush_state_map, &cpu, &zero, BPF_ANY);
	if (cpu < MAX_TRACK_CPUS)
		bpf_map_update_elem(&cpu_preemptable_map, &cpu, &zero, BPF_ANY);

	if (fifo_sched)
		return;

	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(memtable_flush_prio_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(memtable_flush_prio_init)
{
	s32 ret;

	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret)
		return ret;
	ret = scx_bpf_create_dsq(FLUSH_DSQ, -1);
	if (ret)
		return ret;
	return scx_bpf_create_dsq(COMP_DSQ, -1);
}

void BPF_STRUCT_OPS(memtable_flush_prio_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(memtable_flush_prio_ops,
	       .select_cpu		= (void *)memtable_flush_prio_select_cpu,
	       .enqueue			= (void *)memtable_flush_prio_enqueue,
	       .dispatch		= (void *)memtable_flush_prio_dispatch,
	       .running			= (void *)memtable_flush_prio_running,
	       .stopping		= (void *)memtable_flush_prio_stopping,
	       .enable			= (void *)memtable_flush_prio_enable,
	       .init			= (void *)memtable_flush_prio_init,
	       .exit			= (void *)memtable_flush_prio_exit,
	       .name			= "memtable_flush_prio");
