# SCX BPF Map Contract for RocksDB Background Work

This document describes the contract exported by RocksDB into SCX-facing BPF
maps. It is intended for implementing an SCX scheduler on the BPF side.

Scope:

- Source of truth is the current working tree, including the current unstaged
  changes in `db/db_impl/db_impl.h` and `db/db_impl/db_impl_compaction_flush.cc`.
- This document describes what RocksDB writes, when it writes it, and how the
  scheduler should interpret the data.

## 1. Map Names and Paths

Pinned map paths:

- Thread class map:
  `ROCKSDB_SCX_THREAD_CLASS_MAP_PATH` or
  `/sys/fs/bpf/rocksdb_scx_thread_class_map`
- DB metrics map:
  `ROCKSDB_SCX_DB_METRICS_MAP_PATH` or
  `/sys/fs/bpf/rocksdb_scx_db_metrics_map`

Both maps are updated from RocksDB user space through `BPF_MAP_UPDATE_ELEM`.

## 2. Scheduler-Side Lookup Keys

For a current task in BPF:

- Thread class map key: Linux `tid`
- DB metrics map key: Linux process `pid` / thread-group ID (`tgid`)

Practical lookup rule from `bpf_get_current_pid_tgid()`:

- Low 32 bits: use as the thread-class-map key
- High 32 bits: use as the db-metrics-map key

Reason:

- RocksDB writes the thread class map keyed by tid
- RocksDB writes the DB metrics map keyed by `getpid()`

On Linux, those correspond to:

- background thread task ID for per-thread classification
- process ID / thread-group ID for per-DB process metrics

## 3. Thread Class Map

Purpose:

- Classify RocksDB background worker threads for SCX scheduling
- Export compaction level metadata when available

Map schema:

- Type: hash
- Key: `u32 tid`
- Value size required by current code: `16` bytes

Value layout:

```c
struct scx_thread_class_value {
    __u32 class_id;
    __s32 start_level;
    __s32 output_level;
    __u32 pad;
};
```

Field semantics:

- `class_id`
  - `1`: background flush worker
  - `2`: background compaction worker
- `start_level`
  - Compaction input start level
  - `-1` means unknown or not applicable
- `output_level`
  - Compaction output level
  - `-1` means unknown or not applicable
- `pad`
  - Reserved for alignment, always `0`

Scheduler interpretation:

- For flush threads, expect:
  - `class_id = 1`
  - `start_level = -1`
  - `output_level = -1`
- For compaction threads:
  - initially the worker may publish only class information with
    `start_level = -1`, `output_level = -1`
  - later, after a compaction is picked, the same `tid` is updated with the
    actual `start_level` and `output_level`

Important:

- Do not infer class from Linux thread name (`comm`) such as `rocksdb:low` /
  `rocksdb:high`.
- The authoritative signal is the map value keyed by `tid`.
- In real runs, `rocksdb:low` may publish `class_id=1` or `class_id=2`
  depending on the BG job currently executed by that worker.

Update points:

- Flush worker entry:
  - `BGWorkFlush()` writes `class_id=1`
- Compaction worker entry:
  - `BGWorkCompaction()` and `BGWorkBottomCompaction()` write `class_id=2`
    first, with unknown levels
- After compaction pick:
  - `BackgroundCompaction()` writes `class_id=2` again with concrete
    `start_level` and `output_level` if a `Compaction*` exists

Important behavior:

- There is no delete operation for thread-map entries
- The last published value for a `tid` remains in the map until it is
  overwritten or the map is recreated/cleared
- RocksDB avoids redundant writes with a thread-local cache, so identical
  consecutive values may not trigger another map update
- If a worker exits, its old `tid` entry can remain as stale data
- Linux can eventually reuse a numeric `tid`; scheduler logic should combine map
  hint + current task identity/state (comm/cgroup/runtime context), not map-only

Implication for the scheduler:

- Treat the thread class map as a hint, not a strict liveness signal
- A mapped `tid` means "this thread has previously run RocksDB BG work and
  last published this role"
- Use task identity plus task state, not the map alone, to infer whether BG
  work is currently active
- A miss for current `/proc/<pid>/task/<tid>` does not necessarily mean map
  update failure; it can also be a stale key mismatch

## 4. DB Metrics Map

Purpose:

- Export coarse DB pressure indicators that an SCX scheduler can use to bias
  RocksDB BG scheduling

Map schema:

- Type: hash
- Key: `u32 pid` (`tgid` on the BPF side)
- Value size required by current code: `40` bytes

Value layout:

```c
struct scx_db_metrics_value {
    __u64 l0_files;                  // offset 0
    __u64 debt_bytes;                // offset 8
    __u32 stall_flag;                // offset 16
    __u32 num_immutable_memtables;   // offset 20
    __u64 cur_size_all_memtables;    // offset 24
    __u64 timestamp_ns;              // offset 32
};
```

Field semantics:

- `l0_files`
  - From `DB::Properties::kNumFilesAtLevelPrefix + "0"`
- `debt_bytes`
  - From `DB::Properties::kEstimatePendingCompactionBytes`
- `stall_flag`
  - `1` if RocksDB judges the DB to be in write-pressure state
  - `0` otherwise
- `num_immutable_memtables`
  - From `DB::Properties::kNumImmutableMemTable`
- `cur_size_all_memtables`
  - From `DB::Properties::kCurSizeAllMemTables`
- `timestamp_ns`
  - Monotonic timestamp from `clock_gettime(CLOCK_MONOTONIC)`
  - Timestamp of the export event, not of the underlying DB properties

### 4.1 `stall_flag` Definition

RocksDB exports `stall_flag = 1` when either condition holds:

1. slowdown condition
2. stop-write condition

Slowdown condition:

- `l0_files >= level0_slowdown_writes_trigger(default_cf)`
- or `actual_delayed_write_rate > 0`

Stop-write condition:

- `is_write_stopped > 0`

Notes:

- The slowdown trigger is taken from the default column family
- The map only exports the final boolean `stall_flag`, not the reason

## 5. Export Timing

The DB metrics map is not continuously streamed.

Current export timing:

- At the end of each flush background job
- At the end of each compaction background job

Current call sites:

- `BGWorkFlush()`
- `BGWorkCompaction()`
- `BGWorkBottomCompaction()`

Implications:

- `timestamp_ns` can become stale if no BG jobs finish for a while
- The scheduler should age out or discount DB metrics entries that are too old
- The exported numbers are snapshots at job completion boundaries

## 6. Memory Layout and Endianness

Layout assumptions:

- Native C layout, naturally aligned
- No packed attribute is used
- Intended deployment is Linux on little-endian machines

For BPF code running on the same host:

- Define the structs exactly as above
- Do not assume the old 4-byte or 32-byte layouts

For user-space tools parsing raw `bpftool` hex dumps:

- Interpret fields as little-endian

## 7. Compatibility and Migration Notes

This interface has changed relative to commit `ae67d5e8d`.

Commit `ae67d5e8d` exported:

- thread class map value: `4` bytes
  - only `class_id`
- DB metrics map value: `32` bytes
  - `l0_files`
  - `debt_bytes`
  - `stall_flag`
  - padding
  - `timestamp_ns`

Current working tree exports:

- thread class map value: `16` bytes
- DB metrics map value: `40` bytes

New fields added after that commit:

- thread map:
  - `start_level`
  - `output_level`
- DB metrics map:
  - `num_immutable_memtables`
  - `cur_size_all_memtables`

Helper script expectation:

- `init_scx_maps.sh` should create:
  - thread map value size `16`
  - DB metrics map value size `40`
- `check_scx_maps.sh` should decode the current layout and may also decode the
  older layout for compatibility during migration

To switch an existing deployment to the new fields, recreate the pinned maps
with the new schema:

- thread map value size `16`
- DB metrics map value size `40`

## 8. Recommended Scheduler Use

A practical policy split is:

- Use thread class map to classify per-thread service class
- Use DB metrics map to bias urgency at the process level

Examples:

- If `stall_flag == 1`, favor RocksDB flush and compaction threads for that
  process
- If `class_id == 1`, treat the thread as flush-critical
- If `class_id == 2`, use `start_level` and `output_level` to distinguish:
  - upper-level compactions
  - lower-level or bottom-level compactions
- If `timestamp_ns` is old, fall back to weaker heuristics

## 9. BPF-Side Reference Structs

```c
struct scx_thread_class_value {
    __u32 class_id;
    __s32 start_level;
    __s32 output_level;
    __u32 pad;
};

struct scx_db_metrics_value {
    __u64 l0_files;
    __u64 debt_bytes;
    __u32 stall_flag;
    __u32 num_immutable_memtables;
    __u64 cur_size_all_memtables;
    __u64 timestamp_ns;
};
```

Recommended lookup convention:

```c
u64 pid_tgid = bpf_get_current_pid_tgid();
u32 tid = (u32)pid_tgid;
u32 tgid = pid_tgid >> 32;

struct scx_thread_class_value *tcls;
struct scx_db_metrics_value *dbm;

tcls = bpf_map_lookup_elem(&rocksdb_scx_thread_class_map, &tid);
dbm = bpf_map_lookup_elem(&rocksdb_scx_db_metrics_map, &tgid);
```

## 10. Source Locations

Primary implementation:

- `db/db_impl/db_impl_compaction_flush.cc`
- `db/db_impl/db_impl.h`

Helper scripts that must be kept in sync with the schema:

- `init_scx_maps.sh`
- `check_scx_maps.sh`

Runtime validation note:

- `check_scx_maps.sh` reports `thread_map_entries`.
- When current `/proc` tids do not match, it also prints decoded raw map entries
  (`map_tid/class/start/output`) to distinguish:
  - stale key mismatch
  - decode/parser issue
  - map update failure

## 11. `scx_l0_compaction_prio` Operational Notes

### 11.1 CLI Options

```
sudo scx_l0_compaction_prio [-f] [-S SUPER_US] [-s SHARED_US] [-c COMP_US]
                             [-k L0_FILES] [-A AGE_MS] [-W WAIT_MS]
                             [-B SUPER_BUDGET] [-L L0_BUDGET] [-v]
```

Key options:

| Flag | Default | Description |
|------|---------|-------------|
| `-k L0_FILES` | 4 | `l0_files >= k` threshold to activate super-priority. **Must match `level0_slowdown_writes_trigger` in db_bench/RocksDB config.** |
| `-A AGE_MS` | 3000 | Max age of DB metrics before treating as stale (ms). Increase to 10000 if `metrics_stale` counter grows rapidly. |
| `-W WAIT_MS` | 5 | Dispatch any task that has waited longer than this from any DSQ (starvation guard). |
| `-B SUPER_BUDGET` | 3 | Force a shared-DSQ task after N consecutive super dispatches (prevents starvation). |
| `-L L0_BUDGET` | 2 | Force a non-L0 compaction task after N consecutive L0 dispatches. |
| `-S SUPER_US` | 250000 | Slice for super-priority (L0 compaction) tasks (µs). |
| `-s SHARED_US` | 20000 | Slice for normal tasks (µs). |
| `-c COMP_US` | 20000 | Slice for non-L0 compaction tasks (µs). |

Recommended invocation matching the standard db_bench experiment config
(`-level0_slowdown_writes_trigger=4`):

```bash
sudo ./scx_l0_compaction_prio -k 4 -A 10000
```

### 11.2 Diagnostic Stats

The scheduler prints one line per second:

```
local=N global=N super_hit=N idle_direct=N preempt=N prefail=N super_dsq=N
thread_miss=N metrics_miss=N metrics_stale=N
wait_override=N super_wait_override=N
l0_files=N compaction_start_levels=[...]
```

| Counter | Healthy state | Problem if... |
|---------|--------------|---------------|
| `super_hit` | Growing during L0 pressure | Stays 0: check `compaction_start_levels` for `0` entries and verify `-k` threshold |
| `thread_miss ≈ global` | ~1× ratio | Was >2× before `running`-hook fix; now normal that non-RocksDB tasks miss |
| `metrics_stale` | Near zero | Growing fast: metrics export lagging; increase `-A` or check export call sites |
| `metrics_miss` | 0 | >0: DB metrics map not populated; re-run `init_scx_maps.sh` |
| `wait_override` | Low-moderate | Very large: shared tasks starved; decrease `-W` or `-B` |
| `compaction_start_levels` | Contains `0` during L0 burst | Never `0`: L0 compactions not being registered; check `BackgroundCompaction()` level export |

### 11.3 Known Bugs Fixed (commit `7a71e65db` + subsequent)

#### Bug 1: BPF map value_size mismatch (root cause of all early experiment failures)

- `scx_flush_prio.bpf.c` and `scx_flush_compaction_prio.bpf.c` declared
  `rocksdb_scx_thread_class_map` value as `u32` (4 B).
- `scx_rdb_probe.bpf.c` declared `rocksdb_scx_db_metrics` as 32 B.
- Pinned maps were created at 16 B / 40 B respectively.
- Result: every `bpf_map_lookup_elem` returned `ENOENT`; `super_hit` was
  permanently 0 and `thread_miss ≈ 2.2× global` for the entire experiment history.
- Fix: all BPF structs updated to match current schema (16 B / 40 B).

#### Bug 2: Linux TID mismatch

- `RegisterScxBgThreadClass` was keying the map by `env_->GetThreadID()`
  (RocksDB internal ID) instead of the Linux kernel TID (`p->pid` in BPF).
- Fix: `ScxGetCurrentLinuxTid()` using `syscall(__NR_gettid)`.

#### Bug 3: `l0_files_thr` default too high

- Default was 8; db_bench uses `level0_slowdown_writes_trigger=4`.
- At `l0_files=5` the DB is fully write-stalled, but the scheduler would not
  activate super-priority until `l0_files >= 8`.
- Fix: default lowered to 4 in both `.bpf.c` and `.c`.

#### Bug 4: `STAT_THREAD_MISS` inflated by `running` hook

- `is_super_prio_task(p)` was called from both `enqueue` and `running` hooks,
  both incrementing `STAT_THREAD_MISS`.
- `running` fires far more often than `enqueue`, making `thread_miss > global`.
- Fix: `running` hook uses `is_super_prio_task_nostat()` which performs the
  same lookup without touching any stat counters.

### 11.4 `metrics_stale` Behavior

`ExportScxDbMetrics` is called only at job-completion boundaries
(`BGWorkFlush`, `BGWorkCompaction`, `BGWorkBottomCompaction`).

When a single CPU handles both flush and compaction threads, the winning thread
monopolizes the CPU and the other thread's job may not complete for an extended
period, causing the metrics timestamp to age out.

Workaround: pass `-A <large_ms>` (e.g., `-A 30000`) to extend the staleness
window, or switch the super-priority condition from `l0_files >= k` to
`stall_flag == 1` (which does not require a fresh timestamp, though staleness
should still be checked for correctness).
