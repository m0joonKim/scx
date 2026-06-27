/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_adaptive_bg_prio v6
 *
 * ─────────────────────────────────────────────────────────────────────
 * v5 → v6 변경점
 * ─────────────────────────────────────────────────────────────────────
 *
 * [배경]
 * v5 측정 결과:
 *   - stall 빈도 v4 대비 97% 감소 (24521 → 4847 events)
 *   - 그러나 개별 stall duration 5x 증가 (avg 7.7ms → 37ms)
 *   - **total stall time 거의 동일** (189s → 180s)
 *   → "frequent small stall" 을 "rare massive stall" 로 amortize한 것뿐.
 *      LSM compaction 빚은 미루기만 할 뿐 사라지지 않음.
 *
 * [v6 가설]
 *   deeper-level compaction을 항상 양보(v5)도, 항상 우선(v4)도 정답 아님.
 *   debt_bytes (pending compaction bytes, RocksDB 자체 metric) 따라
 *   동적 switching:
 *
 *     debt < soft_thr           → v5 동작 (SHARED_DSQ, fair with writer)
 *     soft_thr ≤ debt < hard_thr → v4 동작 (COMP_DSQ, writer보다 우선)
 *     debt ≥ hard_thr           → 긴급 (BG_PRIO_DSQ, vtime bonus)
 *
 *   이 자체조절 동작으로:
 *     - 평소: writer 보호 (v5 장점 유지)
 *     - 백로그 누적 시: 미리 catch-up 시작 (massive stall 방지)
 *     - 극단: 폭발 직전 긴급 drain
 *
 * [구현 위치]
 *   classify_task() 의 BG_COMPACTION_CLASS branch (start_level != 0) 만 변경.
 *   L0 compaction과 flush는 v5와 동일.
 *
 * [신규 파라미터]
 *   debt_soft_thr_bytes (-D, default 256 MB)
 *   debt_hard_thr_bytes (-H, default 1 GB)
 *
 * [위험 / 한계]
 *   - Hysteresis 없음 — debt 임계값 근처에서 모드 흔들림 가능
 *     완화: soft/hard 갭을 충분히 (256MB ↔ 1GB)
 *   - debt_bytes update 주기(3초)만큼 반응 지연
 *   - 임계값 튜닝 sensitivity 큼 — sweep 측정 필요
 *
 * ─────────────────────────────────────────────────────────────────────
 * (이하 v5 원문 — v5의 비대칭 제거 설계는 v6에서도 그대로 유지됨)
 * ─────────────────────────────────────────────────────────────────────
 *
 * ─────────────────────────────────────────────────────────────────────
 * v4 → v5 변경점
 * ─────────────────────────────────────────────────────────────────────
 *
 * [배경]
 * v4 multi-instance 측정 결과:
 *   - write p99 latency: 100배 개선 (1.1ms → 9µs)
 *   - throughput: +13~20%
 *   - 그러나 p99.9 / p99.99 latency가 base CFS 대비 2~5배 악화
 *
 * 가설 검증 (per-event stall duration + non-stall avg latency 분석):
 *   (A) 큰 backlog 가설 확인:
 *       v4는 stall 빈도를 82% 감소시키지만 개별 stall duration은
 *       3~5배 길어짐 (avg 2ms → 6ms, p99 5ms → 26ms).
 *   (B) Writer starvation 확인:
 *       정상(비-stall) 시기에도 writer의 non-stall avg latency가
 *       base 대비 1.5~2배 증가 (8µs → 14~17µs).
 *
 * [v4 코드 분석으로 드러난 비대칭]
 *   classify_task() 구조:
 *     - Flush:   pressure 없으면 TASK_CLS_NONE → SHARED_DSQ (writer와 동등) ✓
 *     - L0 comp: pressure 없으면 TASK_CLS_COMP → COMP_DSQ (writer보다 우선) ✗
 *     - L1+ comp: pressure 조건 자체 없음 → 항상 COMP_DSQ → 항상 writer보다 우선 ✗
 *
 *   Dispatch 순서가 BG_PRIO_DSQ > COMP_DSQ > SHARED_DSQ 이므로
 *   COMP_DSQ 안의 모든 compaction은 압력과 무관하게 writer를 밀어냄.
 *   이게 (B) writer starvation의 구조적 원인.
 *
 * [v5 변경]
 *   비대칭 제거 — L0 compaction도 flush와 같은 방식으로 분기,
 *   deeper-level compaction은 항상 writer와 동등:
 *
 *     - L0 compaction (start_level == 0):
 *         l0_files >= l0_thr  → TASK_CLS_L0   → BG_PRIO_DSQ  (기존과 동일)
 *         l0_files <  l0_thr  → TASK_CLS_NONE → SHARED_DSQ   (변경: COMP → NONE)
 *
 *     - Deeper compaction (start_level != 0):
 *         항상 TASK_CLS_NONE → SHARED_DSQ                    (변경: 항상 COMP → NONE)
 *
 *   결과적으로 TASK_CLS_COMP / COMP_DSQ 는 더 이상 enqueue되지 않지만
 *   metrics_miss / stale fallback 경로 호환을 위해 큐 정의와 dispatch
 *   로직은 그대로 유지함.
 *
 * [기대 효과]
 *   - 압력 없는 시기 writer가 deeper-level compaction과 fair share
 *     → non-stall latency 회복 (가설 B 완화)
 *   - 압력 발생 시 기존 vtime bonus 로직은 그대로 동작
 *     → stall 빈도 유지 (p99 효과 유지)
 *   - 예상 부작용: deeper-level compaction 진행 속도 다소 감소 →
 *     장기 write amplification 증가 가능. fillrandom 단기 벤치엔 영향 미미.
 *
 * ─────────────────────────────────────────────────────────────────────
 * (v4 원문 설명 — vtime 메커니즘은 그대로 유지)
 * ─────────────────────────────────────────────────────────────────────
 *
 * flush와 L0 compaction 두 BG thread를 BG_PRIO_DSQ에 함께 넣고
 * vtime ordering으로 dispatch. 각 thread의 vtime은:
 *
 *   vtime = vtime_now - BG_BONUS_BASE × pressure_ratio / 100
 *
 * pressure_ratio는 해당 metric이 threshold를 얼마나 초과했는지로 계산
 * (MAX_PRESSURE_PCT=300%로 cap). flush pressure > L0 pressure이면 flush가
 * 더 자주 dispatch, 반대면 L0가 우선.
 *
 * Dispatch order: BG_PRIO_DSQ (vtime) > COMP_DSQ (FIFO) > SHARED_DSQ (FIFO)
 *
 * Preemption: flush/L0 thread는 COMP/SHARED(CPU_PRIO_NONE)를 preempt할 수
 * 있으나, 서로(CPU_PRIO_BG_PRIO)는 preempt하지 않음.
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
/* v6: dynamic deeper-compaction switching thresholds (bytes) */
const volatile u64 debt_soft_thr_bytes;
const volatile u64 debt_hard_thr_bytes;

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
	u64 imm_thr   = imm_memtables_thr;  /* 0 = always activate flush */
	u64 l0_thr    = l0_files_thr ? : 4;
	u64 debt_soft = debt_soft_thr_bytes ? : (256ULL << 20);  /* 256 MB */
	u64 debt_hard = debt_hard_thr_bytes ? : (1024ULL << 20); /* 1 GB */

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
		if (!imm_thr ||  /* 0 = always */
		    dbm->stall_flag ||
		    dbm->num_immutable_memtables >= imm_thr ||
		    dbm->cur_size_all_memtables >= bytes_thr)
			return TASK_CLS_FLUSH;
		return TASK_CLS_NONE;
	}

	if (tcls->class_id == BG_COMPACTION_CLASS) {
		if (tcls->start_level == 0) {
			/* L0 compaction: v5 동일 — l0_files 기반 */
			dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
			if (!dbm) {
				stat_inc(STAT_METRICS_MISS);
				return TASK_CLS_NONE;
			}
			if (metrics_is_stale(dbm)) {
				stat_inc(STAT_METRICS_STALE);
				return TASK_CLS_NONE;
			}
			if (dbm->l0_files >= l0_thr)
				return TASK_CLS_L0;
			return TASK_CLS_NONE;
		}

		/*
		 * v6: deeper-level compaction (start_level != 0) — debt_bytes
		 * 기반 3단계 동적 분류.
		 *   debt < soft  → SHARED (v5 동작, writer fair)
		 *   soft ≤ debt < hard → COMP (v4 동작, writer 위)
		 *   debt ≥ hard  → BG_PRIO (긴급 drain, vtime bonus)
		 */
		dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
		if (!dbm) {
			stat_inc(STAT_METRICS_MISS);
			return TASK_CLS_NONE;
		}
		if (metrics_is_stale(dbm)) {
			stat_inc(STAT_METRICS_STALE);
			return TASK_CLS_NONE;
		}
		if (dbm->debt_bytes >= debt_hard)
			return TASK_CLS_L0;       /* BG_PRIO_DSQ + vtime bonus */
		if (dbm->debt_bytes >= debt_soft)
			return TASK_CLS_COMP;     /* COMP_DSQ (writer 위) */
		return TASK_CLS_NONE;         /* SHARED_DSQ (fair) */
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
	u64 imm_thr   = imm_memtables_thr;  /* 0 = always activate flush */
	u64 l0_thr    = l0_files_thr ? : 4;
	u64 debt_soft = debt_soft_thr_bytes ? : (256ULL << 20);
	u64 debt_hard = debt_hard_thr_bytes ? : (1024ULL << 20);

	tcls = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
	if (!tcls)
		return TASK_CLS_NONE;

	if (tcls->class_id == BG_FLUSH_CLASS) {
		dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
		if (!dbm || metrics_is_stale(dbm))
			return TASK_CLS_NONE;
		if (!imm_thr ||  /* 0 = always */
		    dbm->stall_flag ||
		    dbm->num_immutable_memtables >= imm_thr ||
		    dbm->cur_size_all_memtables >= bytes_thr)
			return TASK_CLS_FLUSH;
		return TASK_CLS_NONE;
	}

	if (tcls->class_id == BG_COMPACTION_CLASS) {
		if (tcls->start_level == 0) {
			dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
			if (!dbm || metrics_is_stale(dbm))
				return TASK_CLS_NONE;
			if (dbm->l0_files >= l0_thr)
				return TASK_CLS_L0;
			return TASK_CLS_NONE;
		}
		/* v6: deeper compaction debt-based 3-tier */
		dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
		if (!dbm || metrics_is_stale(dbm))
			return TASK_CLS_NONE;
		if (dbm->debt_bytes >= debt_hard)
			return TASK_CLS_L0;
		if (dbm->debt_bytes >= debt_soft)
			return TASK_CLS_COMP;
		return TASK_CLS_NONE;
	}

	return TASK_CLS_NONE;
}

/*
 * Flush pressure bonus: BG_BONUS_BASE × max(imm_ratio, mem_ratio) / 100
 * At threshold (ratio=100%): 500 ms.  At 3× threshold: 1500 ms.
 */
static __always_inline u64 compute_flush_bonus(struct scx_db_metrics_value *dbm)
{
	u64 imm_thr_v   = imm_memtables_thr;  /* 0 = always */
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

s32 BPF_STRUCT_OPS(adaptive_bg_prio_v6_select_cpu, struct task_struct *p,
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

void BPF_STRUCT_OPS(adaptive_bg_prio_v6_enqueue, struct task_struct *p, u64 enq_flags)
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

void BPF_STRUCT_OPS(adaptive_bg_prio_v6_dispatch, s32 cpu, struct task_struct *prev)
{
	if (scx_bpf_dsq_move_to_local(BG_PRIO_DSQ))
		return;

	if (try_rescue_shared(cpu))
		return;

	if (scx_bpf_dsq_move_to_local(COMP_DSQ))
		return;

	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(adaptive_bg_prio_v6_running, struct task_struct *p)
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

void BPF_STRUCT_OPS(adaptive_bg_prio_v6_stopping, struct task_struct *p, bool runnable)
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

void BPF_STRUCT_OPS(adaptive_bg_prio_v6_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(adaptive_bg_prio_v6_init)
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

void BPF_STRUCT_OPS(adaptive_bg_prio_v6_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(adaptive_bg_prio_v6_ops,
	       .select_cpu = (void *)adaptive_bg_prio_v6_select_cpu,
	       .enqueue    = (void *)adaptive_bg_prio_v6_enqueue,
	       .dispatch   = (void *)adaptive_bg_prio_v6_dispatch,
	       .running    = (void *)adaptive_bg_prio_v6_running,
	       .stopping   = (void *)adaptive_bg_prio_v6_stopping,
	       .enable     = (void *)adaptive_bg_prio_v6_enable,
	       .init       = (void *)adaptive_bg_prio_v6_init,
	       .exit       = (void *)adaptive_bg_prio_v6_exit,
	       .name       = "adaptive_bg_prio_v6");
