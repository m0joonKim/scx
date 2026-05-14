/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Userspace runner for scx_adaptive_bg_prio.
 */
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <libgen.h>
#include <scx/common.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "scx_adaptive_bg_prio.bpf.skel.h"

#define THREAD_CLASS_MAP_PATH_ENV "ROCKSDB_SCX_THREAD_CLASS_MAP_PATH"
#define THREAD_CLASS_MAP_PATH_DFL "/sys/fs/bpf/rocksdb_scx_thread_class_map"
#define DB_METRICS_MAP_PATH_ENV   "ROCKSDB_SCX_DB_METRICS_MAP_PATH"
#define DB_METRICS_MAP_PATH_DFL   "/sys/fs/bpf/rocksdb_scx_db_metrics_map"

#define FLUSH_SLICE_US_DFL      120000
#define L0_SLICE_US_DFL         250000
#define COMP_SLICE_US_DFL        20000
#define SHARED_SLICE_US_DFL      20000
#define METRICS_MAX_AGE_MS_DFL    3000
#define WAIT_SAFETY_MS_DFL           5
#define FLUSH_BUDGET_DFL             3
#define L0_BUDGET_DFL                2
#define MEMTABLE_BYTES_THR_DFL  (64ULL << 20)
#define IMM_MEMTABLES_THR_DFL        1
#define L0_FILES_THR_DFL             4

const char help_fmt[] =
"Adaptive flush/L0-compaction priority sched_ext scheduler.\n"
"\n"
"Usage: %s [-f] [-S FLUSH_US] [-L L0_US] [-c COMP_US] [-s SHARED_US]\n"
"          [-m MEM_BYTES] [-i IMM_CNT] [-k L0_FILES] [-A AGE_MS]\n"
"          [-W WAIT_MS] [-B FLUSH_BUDGET] [-l L0_BUDGET] [-v]\n"
"\n"
"  -f             FIFO scheduling (no vtime)\n"
"  -S FLUSH_US    Flush-priority slice in usec (default 120000)\n"
"  -L L0_US       L0-compaction-priority slice in usec (default 250000)\n"
"  -c COMP_US     Non-priority compaction slice in usec (default 20000)\n"
"  -s SHARED_US   Shared DSQ slice in usec (default 20000)\n"
"  -m MEM_BYTES   Flush priority if cur_size_all_memtables >= MEM_BYTES (default 67108864)\n"
"  -i IMM_CNT     Flush priority if num_immutable_memtables >= IMM_CNT (default 1)\n"
"  -k L0_FILES    L0-prio if l0_files >= L0_FILES (default 4, match level0_slowdown_writes_trigger)\n"
"  -A AGE_MS      Max DB metrics age in ms (default 3000)\n"
"  -W WAIT_MS     Starvation guard: dispatch any DSQ task waiting >= WAIT_MS (default 5)\n"
"  -B FLUSH_BUDGET Force non-flush after N flush dispatches (default 3)\n"
"  -l L0_BUDGET   Force comp/shared after N L0 dispatches (default 2)\n"
"  -v             Verbose libbpf output\n"
"  -h             Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

struct scx_db_metrics_value {
	__u64 l0_files;
	__u64 debt_bytes;
	__u32 stall_flag;
	__u32 num_immutable_memtables;
	__u64 cur_size_all_memtables;
	__u64 timestamp_ns;
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int sig)
{
	exit_req = 1;
}

static const char *map_path_or_default(const char *env_name, const char *dfl)
{
	const char *path = getenv(env_name);

	if (!path || !path[0])
		return dfl;
	return path;
}

static void reuse_pinned_map(struct bpf_map *map, const char *map_path, const char *map_desc)
{
	int fd = bpf_obj_get(map_path);

	SCX_BUG_ON(fd < 0, "Failed to open pinned map '%s' for %s", map_path, map_desc);
	SCX_BUG_ON(bpf_map__reuse_fd(map, fd),
		   "Failed to reuse pinned map '%s' for %s", map_path, map_desc);
}

static void read_stats(struct scx_adaptive_bg_prio *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[STAT_MAX][nr_cpus];
	__u32 idx;

	assert(nr_cpus > 0);
	memset(stats, 0, sizeof(stats[0]) * STAT_MAX);

	for (idx = 0; idx < STAT_MAX; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

static int read_latest_db_metrics(struct scx_adaptive_bg_prio *skel,
				   struct scx_db_metrics_value *out)
{
	int map_fd = bpf_map__fd(skel->maps.rocksdb_scx_db_metrics_map);
	__u32 key, next_key;
	bool has_prev = false;
	__u64 newest_ts = 0;
	bool found = false;

	memset(out, 0, sizeof(*out));
	while (bpf_map_get_next_key(map_fd, has_prev ? &key : NULL, &next_key) == 0) {
		struct scx_db_metrics_value m = {};

		if (bpf_map_lookup_elem(map_fd, &next_key, &m) == 0) {
			if (!found || m.timestamp_ns >= newest_ts) {
				newest_ts = m.timestamp_ns;
				*out = m;
				found = true;
			}
		}
		key = next_key;
		has_prev = true;
	}

	return found ? 0 : -ENOENT;
}

int main(int argc, char **argv)
{
	struct scx_adaptive_bg_prio *skel;
	struct bpf_link *link;
	const char *thread_class_map_path;
	const char *db_metrics_map_path;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(adaptive_bg_prio_ops, scx_adaptive_bg_prio);

	skel->rodata->flush_slice_ns     = FLUSH_SLICE_US_DFL  * 1000ULL;
	skel->rodata->l0_slice_ns        = L0_SLICE_US_DFL     * 1000ULL;
	skel->rodata->comp_slice_ns      = COMP_SLICE_US_DFL   * 1000ULL;
	skel->rodata->shared_slice_ns    = SHARED_SLICE_US_DFL * 1000ULL;
	skel->rodata->metrics_max_age_ns = METRICS_MAX_AGE_MS_DFL * 1000000ULL;
	skel->rodata->wait_safety_ns     = WAIT_SAFETY_MS_DFL  * 1000000ULL;
	skel->rodata->flush_budget       = FLUSH_BUDGET_DFL;
	skel->rodata->l0_budget          = L0_BUDGET_DFL;
	skel->rodata->memtable_bytes_thr = MEMTABLE_BYTES_THR_DFL;
	skel->rodata->imm_memtables_thr  = IMM_MEMTABLES_THR_DFL;
	skel->rodata->l0_files_thr       = L0_FILES_THR_DFL;

	while ((opt = getopt(argc, argv, "fS:L:c:s:m:i:k:A:W:B:l:vh")) != -1) {
		switch (opt) {
		case 'f':
			skel->rodata->fifo_sched = true;
			break;
		case 'S':
			skel->rodata->flush_slice_ns = strtoull(optarg, NULL, 0) * 1000ULL;
			break;
		case 'L':
			skel->rodata->l0_slice_ns = strtoull(optarg, NULL, 0) * 1000ULL;
			break;
		case 'c':
			skel->rodata->comp_slice_ns = strtoull(optarg, NULL, 0) * 1000ULL;
			break;
		case 's':
			skel->rodata->shared_slice_ns = strtoull(optarg, NULL, 0) * 1000ULL;
			break;
		case 'm':
			skel->rodata->memtable_bytes_thr = strtoull(optarg, NULL, 0);
			break;
		case 'i':
			skel->rodata->imm_memtables_thr = strtoull(optarg, NULL, 0);
			break;
		case 'k':
			skel->rodata->l0_files_thr = strtoull(optarg, NULL, 0);
			break;
		case 'A':
			skel->rodata->metrics_max_age_ns = strtoull(optarg, NULL, 0) * 1000000ULL;
			break;
		case 'W':
			skel->rodata->wait_safety_ns = strtoull(optarg, NULL, 0) * 1000000ULL;
			break;
		case 'B':
			skel->rodata->flush_budget = strtoull(optarg, NULL, 0);
			break;
		case 'l':
			skel->rodata->l0_budget = strtoull(optarg, NULL, 0);
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	thread_class_map_path = map_path_or_default(THREAD_CLASS_MAP_PATH_ENV,
						    THREAD_CLASS_MAP_PATH_DFL);
	db_metrics_map_path   = map_path_or_default(DB_METRICS_MAP_PATH_ENV,
						    DB_METRICS_MAP_PATH_DFL);

	reuse_pinned_map(skel->maps.rocksdb_scx_thread_class_map,
			 thread_class_map_path,
			 "rocksdb_scx_thread_class_map(tid->class/start/output)");
	reuse_pinned_map(skel->maps.rocksdb_scx_db_metrics_map,
			 db_metrics_map_path,
			 "rocksdb_scx_db_metrics_map(pid->db_metrics)");

	fprintf(stderr,
		"[scx_adaptive_bg_prio] thread_map=%s db_map=%s "
		"flush_slice_us=%llu l0_slice_us=%llu comp_slice_us=%llu shared_slice_us=%llu "
		"memtable_bytes_thr=%llu imm_thr=%llu l0_files_thr=%llu "
		"age_ms=%llu wait_ms=%llu flush_budget=%llu l0_budget=%llu fifo=%u\n",
		thread_class_map_path,
		db_metrics_map_path,
		(unsigned long long)(skel->rodata->flush_slice_ns  / 1000ULL),
		(unsigned long long)(skel->rodata->l0_slice_ns     / 1000ULL),
		(unsigned long long)(skel->rodata->comp_slice_ns   / 1000ULL),
		(unsigned long long)(skel->rodata->shared_slice_ns / 1000ULL),
		(unsigned long long)skel->rodata->memtable_bytes_thr,
		(unsigned long long)skel->rodata->imm_memtables_thr,
		(unsigned long long)skel->rodata->l0_files_thr,
		(unsigned long long)(skel->rodata->metrics_max_age_ns / 1000000ULL),
		(unsigned long long)(skel->rodata->wait_safety_ns     / 1000000ULL),
		(unsigned long long)skel->rodata->flush_budget,
		(unsigned long long)skel->rodata->l0_budget,
		skel->rodata->fifo_sched ? 1U : 0U);

	SCX_OPS_LOAD(skel, adaptive_bg_prio_ops, scx_adaptive_bg_prio, uei);
	link = SCX_OPS_ATTACH(skel, adaptive_bg_prio_ops, scx_adaptive_bg_prio);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[STAT_MAX];
		struct scx_db_metrics_value metrics = {};

		read_stats(skel, stats);
		read_latest_db_metrics(skel, &metrics);

		printf("local=%llu global=%llu "
		       "flush_hit=%llu flush_idle=%llu flush_preempt=%llu flush_pfail=%llu flush_dsq=%llu "
		       "l0_hit=%llu l0_idle=%llu l0_preempt=%llu l0_pfail=%llu l0_dsq=%llu "
		       "thread_miss=%llu metrics_miss=%llu metrics_stale=%llu "
		       "wait_override=%llu flush_wait=%llu l0_wait=%llu "
		       "stall=%u imm=%u memtable_bytes=%llu l0_files=%llu debt=%llu\n",
		       (unsigned long long)stats[STAT_LOCAL],
		       (unsigned long long)stats[STAT_GLOBAL],
		       (unsigned long long)stats[STAT_FLUSH_HIT],
		       (unsigned long long)stats[STAT_FLUSH_IDLE_DIRECT],
		       (unsigned long long)stats[STAT_FLUSH_PREEMPT],
		       (unsigned long long)stats[STAT_FLUSH_PREEMPT_FAIL],
		       (unsigned long long)stats[STAT_FLUSH_DSQ],
		       (unsigned long long)stats[STAT_L0_HIT],
		       (unsigned long long)stats[STAT_L0_IDLE_DIRECT],
		       (unsigned long long)stats[STAT_L0_PREEMPT],
		       (unsigned long long)stats[STAT_L0_PREEMPT_FAIL],
		       (unsigned long long)stats[STAT_L0_DSQ],
		       (unsigned long long)stats[STAT_THREAD_MISS],
		       (unsigned long long)stats[STAT_METRICS_MISS],
		       (unsigned long long)stats[STAT_METRICS_STALE],
		       (unsigned long long)stats[STAT_WAIT_OVERRIDE],
		       (unsigned long long)stats[STAT_FLUSH_WAIT_OVERRIDE],
		       (unsigned long long)stats[STAT_L0_WAIT_OVERRIDE],
		       metrics.stall_flag,
		       metrics.num_immutable_memtables,
		       (unsigned long long)metrics.cur_size_all_memtables,
		       (unsigned long long)metrics.l0_files,
		       (unsigned long long)metrics.debt_bytes);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_adaptive_bg_prio__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
