/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Userspace runner for scx_rdb_probe.
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <scx/common.h>
#include "scx_rdb_probe.bpf.skel.h"

#define THREAD_CLASS_MAP_PATH_ENV "ROCKSDB_SCX_THREAD_CLASS_MAP_PATH"
#define THREAD_CLASS_MAP_PATH_DFL "/sys/fs/bpf/rocksdb_scx_thread_class_map"
#define DB_METRICS_MAP_PATH_ENV "ROCKSDB_SCX_DB_METRICS_MAP_PATH"
#define DB_METRICS_MAP_PATH_DFL "/sys/fs/bpf/rocksdb_scx_db_metrics_map"

#define BG_FLUSH_CLASS 1
#define BG_COMPACTION_CLASS 2

enum decision_event_type {
	DECISION_EVENT_NONE = 0,
	DECISION_EVENT_ENQUEUE = 1,
	DECISION_EVENT_STOPPING = 2,
};

struct rocksdb_scx_db_metrics {
	__u64 l0_files;
	__u64 debt_bytes;
	__u32 stall_flag;
	__u32 pad;
	__u64 timestamp_ns;
};

struct thread_map_snapshot {
	__u64 total;
	__u64 flush;
	__u64 compaction;
	__u64 other;
};

struct db_map_snapshot {
	bool found;
	__u32 entries;
	__u32 pid;
	__u64 age_ms;
	struct rocksdb_scx_db_metrics metrics;
};

struct last_decision {
	__u64 ts_ns;
	__u32 tid;
	__u32 tgid;
	__u32 class_id;
	__u32 stall_flag;
	__u32 event_type;
	__u32 has_class;
	__u32 has_db;
};

const char help_fmt[] =
"Probe scheduler that validates RocksDB SCX map reads from BPF.\n"
"\n"
"Usage: %s [-f] [-v]\n"
"\n"
"  -f            Use FIFO scheduling instead of weighted vtime scheduling\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int sig)
{
	exit_req = 1;
}

static __u64 mono_now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static const char *map_path_or_default(const char *env_name, const char *dfl)
{
	const char *path = getenv(env_name);

	if (!path || !path[0])
		return dfl;
	return path;
}

static void reuse_pinned_map(struct bpf_map *map, const char *map_path,
			     const char *map_desc)
{
	int fd = bpf_obj_get(map_path);

	SCX_BUG_ON(fd < 0, "Failed to open pinned map '%s' for %s", map_path,
		   map_desc);
	SCX_BUG_ON(bpf_map__reuse_fd(map, fd),
		   "Failed to reuse pinned map '%s' for %s", map_path, map_desc);
	/* libbpf takes ownership of fd after successful bpf_map__reuse_fd(). */
}

static void read_thread_map_snapshot(int map_fd, struct thread_map_snapshot *out)
{
	__u32 key, next_key;
	bool has_prev = false;

	memset(out, 0, sizeof(*out));
	while (bpf_map_get_next_key(map_fd, has_prev ? &key : NULL, &next_key) == 0) {
		__u32 class_id = 0;

		if (bpf_map_lookup_elem(map_fd, &next_key, &class_id) == 0) {
			out->total++;
			if (class_id == BG_FLUSH_CLASS)
				out->flush++;
			else if (class_id == BG_COMPACTION_CLASS)
				out->compaction++;
			else
				out->other++;
		}
		key = next_key;
		has_prev = true;
	}
}

static void read_db_map_snapshot(int map_fd, struct db_map_snapshot *out)
{
	__u32 key, next_key;
	bool has_prev = false;
	__u64 newest_ts = 0;
	__u64 now_ns = mono_now_ns();

	memset(out, 0, sizeof(*out));
	while (bpf_map_get_next_key(map_fd, has_prev ? &key : NULL, &next_key) == 0) {
		struct rocksdb_scx_db_metrics metrics = {};

		if (bpf_map_lookup_elem(map_fd, &next_key, &metrics) == 0) {
			out->entries++;
			if (!out->found || metrics.timestamp_ns >= newest_ts) {
				out->found = true;
				out->pid = next_key;
				out->metrics = metrics;
				newest_ts = metrics.timestamp_ns;
			}
		}
		key = next_key;
		has_prev = true;
	}

	if (out->found && now_ns >= out->metrics.timestamp_ns)
		out->age_ms = (now_ns - out->metrics.timestamp_ns) / 1000000ULL;
}

static void read_last_bg_decision_snapshot(int map_fd, struct last_decision *out)
{
	int nr_cpus = libbpf_num_possible_cpus();
	struct last_decision vals[nr_cpus];
	__u32 key = 0;
	int cpu;

	memset(out, 0, sizeof(*out));
	if (nr_cpus <= 0)
		return;
	memset(vals, 0, sizeof(vals));

	if (bpf_map_lookup_elem(map_fd, &key, vals) != 0)
		return;

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		if (vals[cpu].ts_ns >= out->ts_ns)
			*out = vals[cpu];
	}
}

static const char *class_id_to_name(__u32 class_id)
{
	switch (class_id) {
	case BG_FLUSH_CLASS:
		return "BG_FLUSH";
	case BG_COMPACTION_CLASS:
		return "BG_COMPACTION";
	default:
		return "UNKNOWN";
	}
}

static const char *event_type_to_name(__u32 event_type)
{
	switch (event_type) {
	case DECISION_EVENT_ENQUEUE:
		return "enqueue";
	case DECISION_EVENT_STOPPING:
		return "stopping";
	default:
		return "none";
	}
}

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

static void read_stats(struct scx_rdb_probe *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[STAT_MAX][nr_cpus];
	__u32 idx;

	assert(nr_cpus > 0);
	memset(stats, 0, sizeof(stats[0]) * STAT_MAX);

	for (idx = 0; idx < STAT_MAX; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

int main(int argc, char **argv)
{
	struct scx_rdb_probe *skel;
	struct bpf_link *link;
	const char *thread_class_map_path;
	const char *db_metrics_map_path;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(rdb_probe_ops, scx_rdb_probe);

	while ((opt = getopt(argc, argv, "fvh")) != -1) {
		switch (opt) {
		case 'f':
			skel->rodata->fifo_sched = true;
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
			"rocksdb_scx_thread_class_map(tid->class)");
	reuse_pinned_map(skel->maps.rocksdb_scx_db_metrics_map,
			db_metrics_map_path,
			"rocksdb_scx_db_metrics_map(pid->db_metrics)");

	fprintf(stderr, "[scx_rdb_probe] using maps: thread=%s db=%s\n",
		thread_class_map_path, db_metrics_map_path);

	SCX_OPS_LOAD(skel, rdb_probe_ops, scx_rdb_probe, uei);
	link = SCX_OPS_ATTACH(skel, rdb_probe_ops, scx_rdb_probe);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[STAT_MAX];
		__u64 last_age_ms = 0;
		__u64 now_ns;
		struct thread_map_snapshot tmap;
		struct db_map_snapshot dbmap;
		struct last_decision last_bg;

		read_stats(skel, stats);
		read_thread_map_snapshot(bpf_map__fd(skel->maps.rocksdb_scx_thread_class_map),
					 &tmap);
		read_db_map_snapshot(bpf_map__fd(skel->maps.rocksdb_scx_db_metrics_map),
				     &dbmap);
		read_last_bg_decision_snapshot(bpf_map__fd(skel->maps.last_bg_decision_map),
					      &last_bg);
		now_ns = mono_now_ns();
		if (last_bg.ts_ns > 0 && now_ns >= last_bg.ts_ns)
			last_age_ms = (now_ns - last_bg.ts_ns) / 1000000ULL;

		if (dbmap.found) {
			printf("local=%llu global=%llu tid_hit=%llu pid_hit=%llu both=%llu "
			       "flush=%llu compaction=%llu stall=%llu | "
			       "thread_map(total=%llu f=%llu c=%llu o=%llu) | "
			       "db_map(entries=%u pid=%u l0=%llu debt=%llu stall=%u age_ms=%llu) | "
			       "last_bg(ev=%s tid=%u tgid=%u class=%s(%u) has_db=%u stall=%u age_ms=%llu)\n",
			       stats[STAT_LOCAL],
			       stats[STAT_GLOBAL],
			       stats[STAT_TID_HIT],
			       stats[STAT_PID_HIT],
			       stats[STAT_BOTH_HIT],
			       stats[STAT_CLASS_FLUSH],
			       stats[STAT_CLASS_COMPACTION],
			       stats[STAT_STALL],
			       tmap.total,
			       tmap.flush,
			       tmap.compaction,
			       tmap.other,
			       dbmap.entries,
			       dbmap.pid,
			       dbmap.metrics.l0_files,
			       dbmap.metrics.debt_bytes,
			       dbmap.metrics.stall_flag,
			       dbmap.age_ms,
			       event_type_to_name(last_bg.event_type),
			       last_bg.tid,
			       last_bg.tgid,
			       class_id_to_name(last_bg.class_id),
			       last_bg.class_id,
			       last_bg.has_db,
			       last_bg.stall_flag,
			       last_age_ms);
		} else {
			printf("local=%llu global=%llu tid_hit=%llu pid_hit=%llu both=%llu "
			       "flush=%llu compaction=%llu stall=%llu | "
			       "thread_map(total=%llu f=%llu c=%llu o=%llu) | "
			       "db_map(entries=0) | "
			       "last_bg(ev=%s tid=%u tgid=%u class=%s(%u) has_db=%u stall=%u age_ms=%llu)\n",
			       stats[STAT_LOCAL],
			       stats[STAT_GLOBAL],
			       stats[STAT_TID_HIT],
			       stats[STAT_PID_HIT],
			       stats[STAT_BOTH_HIT],
			       stats[STAT_CLASS_FLUSH],
			       stats[STAT_CLASS_COMPACTION],
			       stats[STAT_STALL],
			       tmap.total,
			       tmap.flush,
			       tmap.compaction,
			       tmap.other,
			       event_type_to_name(last_bg.event_type),
			       last_bg.tid,
			       last_bg.tgid,
			       class_id_to_name(last_bg.class_id),
			       last_bg.class_id,
			       last_bg.has_db,
			       last_bg.stall_flag,
			       last_age_ms);
		}
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_rdb_probe__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
