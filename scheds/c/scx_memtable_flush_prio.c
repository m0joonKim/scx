/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Userspace runner for scx_memtable_flush_prio.
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
#include "scx_memtable_flush_prio.bpf.skel.h"

#define THREAD_CLASS_MAP_PATH_ENV "ROCKSDB_SCX_THREAD_CLASS_MAP_PATH"
#define THREAD_CLASS_MAP_PATH_DFL "/sys/fs/bpf/rocksdb_scx_thread_class_map"
#define DB_METRICS_MAP_PATH_ENV "ROCKSDB_SCX_DB_METRICS_MAP_PATH"
#define DB_METRICS_MAP_PATH_DFL "/sys/fs/bpf/rocksdb_scx_db_metrics_map"

#define FLUSH_SLICE_US_DFL 120000
#define SHARED_SLICE_US_DFL 20000
#define COMP_SLICE_US_DFL 10000
#define METRICS_MAX_AGE_MS_DFL 3000
#define WAIT_SAFETY_MS_DFL 5
#define FLUSH_BUDGET_DFL 3
#define MEMTABLE_BYTES_THR_DFL (64ULL << 20)
#define IMM_MEMTABLES_THR_DFL 1

const char help_fmt[] =
"Memtable-pressure-aware flush priority sched_ext scheduler.\n"
"\n"
"Usage: %s [-f] [-S FLUSH_US] [-s SHARED_US] [-c COMP_US] [-m MEM_BYTES] [-i IMM_CNT] [-A AGE_MS] [-W WAIT_MS] [-B FLUSH_BUDGET] [-v]\n"
"\n"
"  -f             Use FIFO scheduling instead of weighted vtime scheduling\n"
"  -S FLUSH_US    Flush-priority slice in usec (default 120000)\n"
"  -s SHARED_US   Shared DSQ slice in usec (default 20000)\n"
"  -c COMP_US     Compaction DSQ slice in usec (default 10000)\n"
"  -m MEM_BYTES   Flush priority if cur_size_all_memtables >= MEM_BYTES (default 67108864)\n"
"  -i IMM_CNT     Flush priority if num_immutable_memtables >= IMM_CNT (default 1)\n"
"  -A AGE_MS      Max DB metrics age in ms (default 3000)\n"
"  -W WAIT_MS     Dispatch any waiting shared/comp task after WAIT_MS (default 5)\n"
"  -B FLUSH_BUDGET Force a non-flush dispatch after N flush dispatches (default 3)\n"
"  -v             Print libbpf debug messages\n"
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
	STAT_METRICS_MISS,
	STAT_THREAD_MISS,
	STAT_METRICS_STALE,
	STAT_WAIT_OVERRIDE,
	STAT_FLUSH_WAIT_OVERRIDE,
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

static void read_stats(struct scx_memtable_flush_prio *skel, __u64 *stats)
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

static int read_latest_db_metrics(struct scx_memtable_flush_prio *skel,
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
	struct scx_memtable_flush_prio *skel;
	struct bpf_link *link;
	const char *thread_class_map_path;
	const char *db_metrics_map_path;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(memtable_flush_prio_ops, scx_memtable_flush_prio);

	skel->rodata->flush_slice_ns = FLUSH_SLICE_US_DFL * 1000ULL;
	skel->rodata->shared_slice_ns = SHARED_SLICE_US_DFL * 1000ULL;
	skel->rodata->comp_slice_ns = COMP_SLICE_US_DFL * 1000ULL;
	skel->rodata->metrics_max_age_ns = METRICS_MAX_AGE_MS_DFL * 1000000ULL;
	skel->rodata->wait_safety_ns = WAIT_SAFETY_MS_DFL * 1000000ULL;
	skel->rodata->flush_budget = FLUSH_BUDGET_DFL;
	skel->rodata->memtable_bytes_thr = MEMTABLE_BYTES_THR_DFL;
	skel->rodata->imm_memtables_thr = IMM_MEMTABLES_THR_DFL;

	while ((opt = getopt(argc, argv, "fS:s:c:m:i:A:W:B:vh")) != -1) {
		switch (opt) {
		case 'f':
			skel->rodata->fifo_sched = true;
			break;
		case 'S':
			skel->rodata->flush_slice_ns = strtoull(optarg, NULL, 0) * 1000ULL;
			break;
		case 's':
			skel->rodata->shared_slice_ns = strtoull(optarg, NULL, 0) * 1000ULL;
			break;
		case 'c':
			skel->rodata->comp_slice_ns = strtoull(optarg, NULL, 0) * 1000ULL;
			break;
		case 'm':
			skel->rodata->memtable_bytes_thr = strtoull(optarg, NULL, 0);
			break;
		case 'i':
			skel->rodata->imm_memtables_thr = strtoull(optarg, NULL, 0);
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
	db_metrics_map_path = map_path_or_default(DB_METRICS_MAP_PATH_ENV,
						  DB_METRICS_MAP_PATH_DFL);

	reuse_pinned_map(skel->maps.rocksdb_scx_thread_class_map,
			 thread_class_map_path,
			 "rocksdb_scx_thread_class_map(tid->class/start/output)");
	reuse_pinned_map(skel->maps.rocksdb_scx_db_metrics_map,
			 db_metrics_map_path,
			 "rocksdb_scx_db_metrics_map(pid->db_metrics)");

	fprintf(stderr,
		"[scx_memtable_flush_prio] thread_map=%s db_map=%s memtable_bytes_thr=%llu imm_thr=%llu flush_slice_us=%llu shared_slice_us=%llu comp_slice_us=%llu age_ms=%llu wait_ms=%llu flush_budget=%llu fifo=%u\n",
		thread_class_map_path,
		db_metrics_map_path,
		(unsigned long long)skel->rodata->memtable_bytes_thr,
		(unsigned long long)skel->rodata->imm_memtables_thr,
		(unsigned long long)(skel->rodata->flush_slice_ns / 1000ULL),
		(unsigned long long)(skel->rodata->shared_slice_ns / 1000ULL),
		(unsigned long long)(skel->rodata->comp_slice_ns / 1000ULL),
		(unsigned long long)(skel->rodata->metrics_max_age_ns / 1000000ULL),
		(unsigned long long)(skel->rodata->wait_safety_ns / 1000000ULL),
		(unsigned long long)skel->rodata->flush_budget,
		skel->rodata->fifo_sched ? 1U : 0U);

	SCX_OPS_LOAD(skel, memtable_flush_prio_ops, scx_memtable_flush_prio, uei);
	link = SCX_OPS_ATTACH(skel, memtable_flush_prio_ops, scx_memtable_flush_prio);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[STAT_MAX];
		struct scx_db_metrics_value metrics = {};

		read_stats(skel, stats);
		read_latest_db_metrics(skel, &metrics);

		printf("local=%llu global=%llu flush_hit=%llu idle_direct=%llu preempt=%llu prefail=%llu flush_dsq=%llu thread_miss=%llu metrics_miss=%llu metrics_stale=%llu wait_override=%llu flush_wait_override=%llu stall=%u imm=%u memtable_bytes=%llu debt=%llu l0_files=%llu\n",
		       (unsigned long long)stats[STAT_LOCAL],
		       (unsigned long long)stats[STAT_GLOBAL],
		       (unsigned long long)stats[STAT_FLUSH_HIT],
		       (unsigned long long)stats[STAT_FLUSH_IDLE_DIRECT],
		       (unsigned long long)stats[STAT_FLUSH_PREEMPT],
		       (unsigned long long)stats[STAT_FLUSH_PREEMPT_FAIL],
		       (unsigned long long)stats[STAT_FLUSH_DSQ],
		       (unsigned long long)stats[STAT_THREAD_MISS],
		       (unsigned long long)stats[STAT_METRICS_MISS],
		       (unsigned long long)stats[STAT_METRICS_STALE],
		       (unsigned long long)stats[STAT_WAIT_OVERRIDE],
		       (unsigned long long)stats[STAT_FLUSH_WAIT_OVERRIDE],
		       metrics.stall_flag,
		       metrics.num_immutable_memtables,
		       (unsigned long long)metrics.cur_size_all_memtables,
		       (unsigned long long)metrics.debt_bytes,
		       (unsigned long long)metrics.l0_files);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_memtable_flush_prio__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
