/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sched_ext scheduler to probe RocksDB SCX pinned maps.
 *
 * This scheduler keeps scheduling behavior close to scx_simple while
 * validating map lookups from BPF:
 * - /sys/fs/bpf/rocksdb_scx_thread_class_map (tid -> class)
 * - /sys/fs/bpf/rocksdb_scx_db_metrics_map   (tgid -> db metrics)
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

/* Shared DSQ used for global FIFO/vtime modes. */
#define SHARED_DSQ 0

/* BG class IDs exported by RocksDB. */
#define BG_FLUSH_CLASS 1
#define BG_COMPACTION_CLASS 2

enum decision_event_type {
	DECISION_EVENT_NONE = 0,
	DECISION_EVENT_ENQUEUE = 1,
	DECISION_EVENT_STOPPING = 2,
};

enum stat_idx {
	STAT_LOCAL = 0,
	STAT_GLOBAL,
	STAT_TID_HIT,
	STAT_PID_HIT,
	STAT_BOTH_HIT,
	STAT_CLASS_FLUSH,
	STAT_CLASS_COMPACTION,
	STAT_STALL,
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

/* Must match RocksDB-side exported value layout. */
struct rocksdb_scx_db_metrics {
	u64 l0_files;
	u64 debt_bytes;
	u32 stall_flag;
	u32 pad;
	u64 timestamp_ns;
};

struct last_decision {
	u64 ts_ns;
	u32 tid;
	u32 tgid;
	u32 class_id;
	u32 stall_flag;
	u32 event_type;
	u32 has_class;
	u32 has_db;
};

/* Latest decision among BG-classified tasks only. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct last_decision));
	__uint(max_entries, 1);
} last_bg_decision_map SEC(".maps");

/* Reuses externally pinned map path by map name. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);   /* tid */
	__type(value, u32); /* class id */
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rocksdb_scx_thread_class_map SEC(".maps");

/* Reuses externally pinned map path by map name. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32); /* tgid */
	__type(value, struct rocksdb_scx_db_metrics);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rocksdb_scx_db_metrics_map SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static void update_last_bg_decision(struct task_struct *p, u32 class_id,
				    bool has_db, u32 stall_flag,
				    enum decision_event_type event)
{
	u32 key = 0;
	struct last_decision *last;

	last = bpf_map_lookup_elem(&last_bg_decision_map, &key);
	if (!last)
		return;

	last->ts_ns = bpf_ktime_get_ns();
	last->tid = p->pid;
	last->tgid = p->tgid;
	last->class_id = class_id;
	last->stall_flag = stall_flag;
	last->event_type = (u32)event;
	last->has_class = 1;
	last->has_db = has_db ? 1 : 0;
}

s32 BPF_STRUCT_OPS(rdb_probe_select_cpu, struct task_struct *p, s32 prev_cpu,
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

void BPF_STRUCT_OPS(rdb_probe_enqueue, struct task_struct *p, u64 enq_flags)
{
	u32 tid = p->pid;
	u32 tgid = p->tgid;
	u32 *class_id;
	struct rocksdb_scx_db_metrics *dbm;
	u32 class_val = 0;
	u32 stall_val = 0;
	bool has_class = false;
	bool has_db = false;

	stat_inc(STAT_GLOBAL);

	class_id = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
	dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
	if (class_id) {
		has_class = true;
		class_val = *class_id;
	}
	if (dbm) {
		has_db = true;
		stall_val = dbm->stall_flag;
	}
	if (has_class)
		update_last_bg_decision(p, class_val, has_db, stall_val,
				      DECISION_EVENT_ENQUEUE);

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

void BPF_STRUCT_OPS(rdb_probe_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(rdb_probe_running, struct task_struct *p)
{
	if (fifo_sched)
		return;

	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(rdb_probe_stopping, struct task_struct *p, bool runnable)
{
	u32 tid = p->pid;
	u32 tgid = p->tgid;
	u32 *class_id;
	struct rocksdb_scx_db_metrics *dbm;
	u32 class_val = 0;
	u32 stall_val = 0;
	bool has_class = false;
	bool has_db = false;

	if (!fifo_sched)
		p->scx.dsq_vtime +=
			(SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;

	class_id = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
	dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);

	if (class_id) {
		has_class = true;
		class_val = *class_id;
		stat_inc(STAT_TID_HIT);
		if (class_val == BG_FLUSH_CLASS)
			stat_inc(STAT_CLASS_FLUSH);
		else if (class_val == BG_COMPACTION_CLASS)
			stat_inc(STAT_CLASS_COMPACTION);
	}

	if (dbm) {
		has_db = true;
		stall_val = dbm->stall_flag;
		stat_inc(STAT_PID_HIT);
		if (stall_val)
			stat_inc(STAT_STALL);
	}

	if (class_id && dbm)
		stat_inc(STAT_BOTH_HIT);

	if (has_class)
		update_last_bg_decision(p, class_val, has_db, stall_val,
				      DECISION_EVENT_STOPPING);
}

void BPF_STRUCT_OPS(rdb_probe_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rdb_probe_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(rdb_probe_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(rdb_probe_ops,
	       .select_cpu		= (void *)rdb_probe_select_cpu,
	       .enqueue		= (void *)rdb_probe_enqueue,
	       .dispatch		= (void *)rdb_probe_dispatch,
	       .running		= (void *)rdb_probe_running,
	       .stopping		= (void *)rdb_probe_stopping,
	       .enable			= (void *)rdb_probe_enable,
	       .init			= (void *)rdb_probe_init,
	       .exit			= (void *)rdb_probe_exit,
	       .name			= "rdb_probe");
