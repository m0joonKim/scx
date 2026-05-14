/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Userspace runner for scx_flush_compaction_prio.
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
#include <strings.h>
#include <unistd.h>
#include "scx_flush_compaction_prio.bpf.skel.h"

#define THREAD_CLASS_MAP_PATH_ENV "ROCKSDB_SCX_THREAD_CLASS_MAP_PATH"
#define THREAD_CLASS_MAP_PATH_DFL "/sys/fs/bpf/rocksdb_scx_thread_class_map"
#define PRIO_SLICE_US_DFL 120000

#define BG_FLUSH_CLASS 1
#define BG_COMPACTION_CLASS 2

const char help_fmt[] =
"Flush/compaction-priority sched_ext scheduler.\n"
"\n"
"Usage: %s [-f] [-S PRIO_US] [-T TARGET] [-v]\n"
"\n"
"  -f             Use FIFO scheduling instead of weighted vtime scheduling\n"
"  -S PRIO_US     Priority task slice in usec (default 120000)\n"
"  -T TARGET      Priority target: flush|compaction|1|2 (default flush)\n"
"  -v             Print libbpf debug messages\n"
"  -h             Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

enum stat_idx {
	STAT_LOCAL = 0,
	STAT_GLOBAL,
	STAT_PRIO_HIT,
	STAT_PRIO_IDLE_DIRECT,
	STAT_PRIO_PREEMPT,
	STAT_PRIO_PREEMPT_FAIL,
	STAT_PRIO_DSQ,
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

static const char *prio_class_name(__u32 class_id)
{
	switch (class_id) {
	case BG_FLUSH_CLASS:
		return "flush";
	case BG_COMPACTION_CLASS:
		return "compaction";
	default:
		return "unknown";
	}
}

static int parse_prio_class(const char *arg, __u32 *class_id)
{
	if (!arg || !class_id)
		return -EINVAL;

	if (!strcasecmp(arg, "flush") || !strcmp(arg, "1")) {
		*class_id = BG_FLUSH_CLASS;
		return 0;
	}

	if (!strcasecmp(arg, "compaction") || !strcmp(arg, "2")) {
		*class_id = BG_COMPACTION_CLASS;
		return 0;
	}

	return -EINVAL;
}

static void reuse_pinned_map(struct bpf_map *map, const char *map_path, const char *map_desc)
{
	int fd = bpf_obj_get(map_path);

	SCX_BUG_ON(fd < 0, "Failed to open pinned map '%s' for %s", map_path, map_desc);
	SCX_BUG_ON(bpf_map__reuse_fd(map, fd),
		   "Failed to reuse pinned map '%s' for %s", map_path, map_desc);
}

static void read_stats(struct scx_flush_compaction_prio *skel, __u64 *stats)
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

int main(int argc, char **argv)
{
	struct scx_flush_compaction_prio *skel;
	struct bpf_link *link;
	const char *thread_class_map_path;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(flush_compaction_prio_ops, scx_flush_compaction_prio);

	skel->rodata->prio_slice_ns = PRIO_SLICE_US_DFL * 1000ULL;
	skel->rodata->prio_class = BG_FLUSH_CLASS;
	while ((opt = getopt(argc, argv, "fS:T:vh")) != -1) {
		switch (opt) {
		case 'f':
			skel->rodata->fifo_sched = true;
			break;
		case 'S':
			skel->rodata->prio_slice_ns = strtoull(optarg, NULL, 0) * 1000ULL;
			break;
		case 'T':
			if (parse_prio_class(optarg, &skel->rodata->prio_class)) {
				fprintf(stderr, "Invalid -T target '%s' (use flush|compaction|1|2)\n", optarg);
				fprintf(stderr, help_fmt, basename(argv[0]));
				return 1;
			}
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
	reuse_pinned_map(skel->maps.rocksdb_scx_thread_class_map,
			 thread_class_map_path,
			 "rocksdb_scx_thread_class_map(tid->class)");

	fprintf(stderr,
		"[scx_flush_compaction_prio] thread_map=%s target=%s prio_slice_us=%llu fifo=%u\n",
		thread_class_map_path,
		prio_class_name(skel->rodata->prio_class),
		(unsigned long long)(skel->rodata->prio_slice_ns / 1000ULL),
		skel->rodata->fifo_sched ? 1U : 0U);

	SCX_OPS_LOAD(skel, flush_compaction_prio_ops, scx_flush_compaction_prio, uei);
	link = SCX_OPS_ATTACH(skel, flush_compaction_prio_ops, scx_flush_compaction_prio);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[STAT_MAX];

		read_stats(skel, stats);
		printf("local=%llu global=%llu prio_hit=%llu idle_direct=%llu preempt=%llu prefail=%llu prio_dsq=%llu target=%s\n",
		       (unsigned long long)stats[STAT_LOCAL],
		       (unsigned long long)stats[STAT_GLOBAL],
		       (unsigned long long)stats[STAT_PRIO_HIT],
		       (unsigned long long)stats[STAT_PRIO_IDLE_DIRECT],
		       (unsigned long long)stats[STAT_PRIO_PREEMPT],
		       (unsigned long long)stats[STAT_PRIO_PREEMPT_FAIL],
		       (unsigned long long)stats[STAT_PRIO_DSQ],
		       prio_class_name(skel->rodata->prio_class));
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_flush_compaction_prio__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
