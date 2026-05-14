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
const volatile bool bg_boost_enabled;
const volatile u64 bg_boost_slice_ns;
const volatile u64 bg_super_boost_slice_ns;
const volatile u64 bg_l0_files_thr;
const volatile u64 bg_debt_thr;
const volatile u32 bg_boost_vtime_div;
const volatile u32 bg_super_vtime_div;

static u64 vtime_now;
UEI_DEFINE(uei);

/* Shared DSQ used for global FIFO/vtime modes. */
#define SHARED_DSQ 0
#define BOOST_DSQ 1
#define MAX_TRACK_CPUS 4096

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
	STAT_BG_BOOST_ENQ,
	STAT_BG_SUPER_BOOST_ENQ,
	STAT_BG_PREEMPT_DIRECT,
	STAT_BG_PREEMPT_FAIL,
	STAT_BG_BOOST_DSQ,
	STAT_BG_PREEMPT_BLOCKED,
	STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, STAT_MAX);
} stats SEC(".maps");

/*
 * CPU -> currently running RocksDB BG class.
 *
 * 0 means non-BG or unknown. For this draft policy, direct preemption is
 * blocked only for same-class BG preemption (flush -> flush,
 * compaction -> compaction).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_TRACK_CPUS);
} cpu_bg_class_map SEC(".maps");

/* Must match RocksDB-side exported value layout (40 bytes). */
struct rocksdb_scx_db_metrics {
	u64 l0_files;
	u64 debt_bytes;
	u32 stall_flag;
	u32 num_immutable_memtables;
	u64 cur_size_all_memtables;
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

/* Must match RocksDB-side exported value layout (16 bytes). */
struct scx_thread_class_value {
	u32 class_id;
	s32 start_level;
	s32 output_level;
	u32 pad;
};

/* Reuses externally pinned map path by map name. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32); /* tid */
	__type(value, struct scx_thread_class_value);
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

static __always_inline bool is_bg_class(u32 class_id)
{
	return class_id == BG_FLUSH_CLASS || class_id == BG_COMPACTION_CLASS;
}

static __always_inline bool is_same_bg_preempt_blocked(u32 enq_class, u32 victim_class)
{// flush -> flush or compaction -> compaction preemptive 막기위해서
	return is_bg_class(enq_class) && enq_class == victim_class;
}

static __always_inline u32 current_cpu_bg_class(s32 cpu)
{// 인자로 받은 cpu에 뭐 돌고있는지
	u32 key = (u32)cpu;
	u32 *class_p;

	if (cpu < 0 || cpu >= MAX_TRACK_CPUS)
		return 0;

	class_p = bpf_map_lookup_elem(&cpu_bg_class_map, &key);
	return class_p ? *class_p : 0;
}

static __always_inline u64 clamp_vtime_with_bonus(u64 vtime, u64 bonus_ns)
{//vtime 앞으로 당기기
	u64 min_vtime = vtime_now > bonus_ns ? vtime_now - bonus_ns : 0;

	if (time_before(vtime, min_vtime))
		return vtime;
	return min_vtime;
}

static __always_inline bool try_bg_preempt_dispatch(struct task_struct *p, u32 class_id,
						    u64 enq_flags, u64 slice_ns)
{
	// 선호하는 target CPU를 얻어오기
	s32 target = scx_bpf_task_cpu(p);
	s32 idle_cpu;
	idle_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (idle_cpu >= 0) {
		// 유휴 CPU의 로컬 DSQ에 태스크를 삽입하고 선점 플래그 설정
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | idle_cpu, slice_ns,
				   enq_flags | SCX_ENQ_PREEMPT);
		// 유휴 CPU를 IDLE 상태로 깨우기
		scx_bpf_kick_cpu(idle_cpu, SCX_KICK_IDLE);
		return true;
	}

	if (target >= 0 && bpf_cpumask_test_cpu(target, p->cpus_ptr)) {
		// target CPU에서 현재 실행 중인 RocksDB BG 클래스 확인
		u32 victim_class = current_cpu_bg_class(target);

		// 같은 클래스 BG 선점만 차단하고, 다른 클래스나 non-BG 태스크는 선점 허용
		if (!is_same_bg_preempt_blocked(class_id, victim_class)) {
			// target CPU의 로컬 DSQ에 태스크를 삽입하고 선점 플래그 설정
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | target, slice_ns,
					   enq_flags | SCX_ENQ_PREEMPT);
			// target CPU를 선점 요청과 함께 깨우기
			scx_bpf_kick_cpu(target, SCX_KICK_PREEMPT);
			return true;
		}
		// 같은 클래스 선점이 차단된 경우 통계 증가
		stat_inc(STAT_BG_PREEMPT_BLOCKED);
	}
	return false;
}
/* 최신 BG 작업 결정 정보를 업데이트하는 함수
 * @p: 작업 구조체
 * @class_id: RocksDB BG 클래스 ID (FLUSH 또는 COMPACTION)
 * @has_db: DB 메트릭 정보 존재 여부
 * @stall_flag: 스톨 플래그 상태
 * @event: 발생한 이벤트 타입 (ENQUEUE 또는 STOPPING)
 */
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
	struct scx_thread_class_value *tcls;
	struct rocksdb_scx_db_metrics *dbm;
	u32 class_val = 0;
	u32 stall_val = 0;
	bool has_class = false;
	bool has_db = false;
	bool is_bg = false;
	bool super_boost = false;

	stat_inc(STAT_GLOBAL);

	tcls = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
	dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
	if (tcls) {
		has_class = true;
		class_val = tcls->class_id;
	}
	if (dbm) {
		has_db = true;
		stall_val = dbm->stall_flag;
		if (stall_val)
			stat_inc(STAT_STALL);
	}
	if (has_class)
		update_last_bg_decision(p, class_val, has_db, stall_val,
				      DECISION_EVENT_ENQUEUE);

	if (has_class) {
		stat_inc(STAT_TID_HIT);
		if (class_val == BG_FLUSH_CLASS)
			stat_inc(STAT_CLASS_FLUSH);
		else if (class_val == BG_COMPACTION_CLASS)
			stat_inc(STAT_CLASS_COMPACTION);
	}
	if (has_db)
		stat_inc(STAT_PID_HIT);
	if (has_class && has_db)
		stat_inc(STAT_BOTH_HIT);

	is_bg = has_class && is_bg_class(class_val);
	if (is_bg && has_db &&
	    (stall_val ||
	     dbm->l0_files >= (bg_l0_files_thr ? : 16) ||
	     dbm->debt_bytes >= (bg_debt_thr ? : (512ULL << 20))))
		super_boost = true;

	if (bg_boost_enabled && is_bg) {
		u64 boost_slice = super_boost ? (bg_super_boost_slice_ns ? : 120000000ULL)
					      : (bg_boost_slice_ns ? : 40000000ULL);

		if (super_boost)
			stat_inc(STAT_BG_SUPER_BOOST_ENQ);
		else
			stat_inc(STAT_BG_BOOST_ENQ);

		if (try_bg_preempt_dispatch(p, class_val, enq_flags, boost_slice)) {
			stat_inc(STAT_BG_PREEMPT_DIRECT);
			return;
		}
		stat_inc(STAT_BG_PREEMPT_FAIL);

		if (fifo_sched) {
			scx_bpf_dsq_insert(p, BOOST_DSQ, boost_slice, enq_flags);
		} else {
			u64 vtime = clamp_vtime_with_bonus(p->scx.dsq_vtime,
							   super_boost ? boost_slice * 2 : boost_slice);

			scx_bpf_dsq_insert_vtime(p, BOOST_DSQ, boost_slice, vtime,
						 enq_flags);
		}
		stat_inc(STAT_BG_BOOST_DSQ);
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

void BPF_STRUCT_OPS(rdb_probe_dispatch, s32 cpu, struct task_struct *prev)
{
	if (scx_bpf_dsq_move_to_local(BOOST_DSQ))
		return;
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(rdb_probe_running, struct task_struct *p)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 tid = p->pid;
	struct scx_thread_class_value *tcls;
	u32 class_val = 0;

	tcls = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
	if (tcls && is_bg_class(tcls->class_id))
		class_val = tcls->class_id;
	if (cpu < MAX_TRACK_CPUS)
		bpf_map_update_elem(&cpu_bg_class_map, &cpu, &class_val, BPF_ANY);

	if (fifo_sched)
		return;

	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(rdb_probe_stopping, struct task_struct *p, bool runnable)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 zero = 0;
	u32 tid = p->pid;
	u32 tgid = p->tgid;
	struct scx_thread_class_value *tcls;
	struct rocksdb_scx_db_metrics *dbm;
	u32 class_val = 0;
	u32 stall_val = 0;
	bool has_class = false;
	bool has_db = false;

	if (cpu < MAX_TRACK_CPUS)
		bpf_map_update_elem(&cpu_bg_class_map, &cpu, &zero, BPF_ANY);

	tcls = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
	dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);

	if (tcls) {
		has_class = true;
		class_val = tcls->class_id;
	}

	if (dbm) {
		has_db = true;
		stall_val = dbm->stall_flag;
	}

	if (!fifo_sched) {
		u32 div = 1;
		u64 charge = (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;

		if (bg_boost_enabled && has_class && is_bg_class(class_val)) {
			bool super_boost = has_db &&
				(stall_val ||
				 dbm->l0_files >= (bg_l0_files_thr ? : 16) ||
				 dbm->debt_bytes >= (bg_debt_thr ? : (512ULL << 20)));
			div = super_boost ? (bg_super_vtime_div ? : 8) :
				(bg_boost_vtime_div ? : 4);
			if (!div)
				div = 1;
		}
		p->scx.dsq_vtime += charge / div;
	}

	if (has_class && has_db)
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
	s32 ret;

	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret)
		return ret;
	return scx_bpf_create_dsq(BOOST_DSQ, -1);
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
