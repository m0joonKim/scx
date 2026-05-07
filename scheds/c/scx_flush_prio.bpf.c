/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Flush-priority sched_ext scheduler.
 *
 * Tasks classified as BG_FLUSH_CLASS in the pinned thread-class map are given
 * strict preference:
 * - immediate preemptive dispatch when possible
 * - long scheduling slice
 * - dedicated flush DSQ consumed before the normal DSQ
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;
const volatile u64 flush_slice_ns;

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ 0
#define FLUSH_DSQ 1
#define BG_FLUSH_CLASS 1
#define MAX_TRACK_CPUS 4096

enum stat_idx {
	STAT_LOCAL = 0,
	STAT_GLOBAL,
	STAT_FLUSH_HIT,
	STAT_FLUSH_IDLE_DIRECT,
	STAT_FLUSH_PREEMPT,
	STAT_FLUSH_PREEMPT_FAIL,
	STAT_FLUSH_DSQ,
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

/* CPU -> currently running flush(1) or not(0). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_flush_state_map SEC(".maps");

/* Must match RocksDB-side exported layout (16 bytes). */
struct scx_thread_class_value {
	u32 class_id;
	s32 start_level;
	s32 output_level;
	u32 pad;
};

/* Reuse externally pinned map by map name. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct scx_thread_class_value);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rocksdb_scx_thread_class_map SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static __always_inline bool is_flush_task(struct task_struct *p)
{
	u32 tid = p->pid;
	struct scx_thread_class_value *tcls =
		bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);

	return tcls && tcls->class_id == BG_FLUSH_CLASS;
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

static __always_inline u64 flush_vtime(u64 vtime, u64 bonus_ns)
{
	u64 min_vtime = vtime_now > bonus_ns ? vtime_now - bonus_ns : 0;

	if (time_before(vtime, min_vtime))
		return vtime;
	return min_vtime;
}

/* 플러시 작업의 선점 디스패치를 시도하는 함수 */
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

	/* 유휴 CPU를 찾아 디스패치 시도 */
	idle_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (idle_cpu >= 0) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | idle_cpu, slice_ns,
				   enq_flags | SCX_ENQ_PREEMPT);
		scx_bpf_kick_cpu(idle_cpu, SCX_KICK_IDLE);
		return FLUSH_DISPATCH_IDLE;
	}

	/* 대상 CPU를 먼저 확인하고 flush victim이면 다른 허용 CPU를 탐색한다. */
	if (target >= 0 && bpf_cpumask_test_cpu(target, p->cpus_ptr) &&
	    !is_cpu_running_flush(target))
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

	/* 디스패치 실패 */
	return FLUSH_DISPATCH_FAIL;
}

s32 BPF_STRUCT_OPS(flush_prio_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
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

void BPF_STRUCT_OPS(flush_prio_enqueue, struct task_struct *p, u64 enq_flags)
{
	bool flush = is_flush_task(p);
	u64 slice = flush_slice_ns ? : 120000000ULL; /* 120ms default */

	stat_inc(STAT_GLOBAL);

	if (flush) {
		s32 dispatch_res;

		stat_inc(STAT_FLUSH_HIT);

		dispatch_res = try_flush_preempt_dispatch(p, enq_flags, slice);
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
			scx_bpf_dsq_insert(p, FLUSH_DSQ, slice, enq_flags);
		} else {
			u64 vtime = flush_vtime(p->scx.dsq_vtime, slice * 2);
			scx_bpf_dsq_insert_vtime(p, FLUSH_DSQ, slice, vtime,
						 enq_flags);
		}
		stat_inc(STAT_FLUSH_DSQ);
		return;
	}

	if (fifo_sched) {
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
					 enq_flags);
	}
}

void BPF_STRUCT_OPS(flush_prio_dispatch, s32 cpu, struct task_struct *prev)
{
	if (scx_bpf_dsq_move_to_local(FLUSH_DSQ))
		return;
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(flush_prio_running, struct task_struct *p)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 running = is_flush_task(p) ? 1 : 0;

	if (cpu < MAX_TRACK_CPUS)
		bpf_map_update_elem(&cpu_flush_state_map, &cpu, &running, BPF_ANY);

	if (fifo_sched)
		return;

	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(flush_prio_stopping, struct task_struct *p, bool runnable)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 zero = 0;

	if (cpu < MAX_TRACK_CPUS)
		bpf_map_update_elem(&cpu_flush_state_map, &cpu, &zero, BPF_ANY);

	if (fifo_sched)
		return;

	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(flush_prio_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(flush_prio_init)
{
	s32 ret;

	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret)
		return ret;
	return scx_bpf_create_dsq(FLUSH_DSQ, -1);
}

void BPF_STRUCT_OPS(flush_prio_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(flush_prio_ops,
	       .select_cpu		= (void *)flush_prio_select_cpu,
	       .enqueue			= (void *)flush_prio_enqueue,
	       .dispatch		= (void *)flush_prio_dispatch,
	       .running			= (void *)flush_prio_running,
	       .stopping		= (void *)flush_prio_stopping,
	       .enable			= (void *)flush_prio_enable,
	       .init			= (void *)flush_prio_init,
	       .exit			= (void *)flush_prio_exit,
	       .name			= "flush_prio");
