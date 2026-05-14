# RocksDB SCX Schedulers — 빌드 및 실행 가이드

RocksDB가 BPF map으로 내보내는 메트릭을 읽어 백그라운드 스레드를
우선순위 제어하는 `sched_ext` 기반 SCX 스케줄러 모음.

---

## 목차

1. [요구사항](#1-요구사항)
2. [빌드](#2-빌드)
3. [BPF 맵 초기화](#3-bpf-맵-초기화)
4. [스케줄러 실행](#4-스케줄러-실행)
5. [스케줄러 설명 및 추천 파라미터](#5-스케줄러-설명-및-추천-파라미터)
6. [동작 확인](#6-동작-확인)
7. [RocksDB 연동 요구사항](#7-rocksdb-연동-요구사항)
8. [트러블슈팅](#8-트러블슈팅)

---

## 1. 요구사항

### 커널
- Linux **6.12** 이상 (sched_ext 포함)
- `sched_ext` CONFIG 활성화 확인:
  ```bash
  zcat /proc/config.gz | grep CONFIG_SCHED_CLASS_EXT
  # CONFIG_SCHED_CLASS_EXT=y
  ```

### 패키지 (Ubuntu 25.04/25.10 기준)
```bash
sudo apt install -y \
  clang llvm \
  libelf-dev zlib1g-dev libzstd-dev \
  meson ninja-build pkg-config \
  bpftool \
  python3 python3-pip
```

### Python (그래프 생성용, 선택)
```bash
pip3 install matplotlib
```

---

## 2. 빌드

```bash
git clone <repo_url>
cd scx_ksc

# 최초 1회: build 디렉토리 설정
meson setup build -Dbuildtype=release

# 전체 빌드 (시간 걸림)
meson compile -C build

# 특정 스케줄러만 빌드 (빠름)
meson compile -C build scheds/c/scx_l0_compaction_prio
meson compile -C build scheds/c/scx_compaction_add_flush_prio
```

빌드 결과 바이너리 위치:
```
build/scheds/c/scx_l0_compaction_prio
build/scheds/c/scx_compaction_add_flush_prio
build/scheds/c/scx_memtable_flush_prio
build/scheds/c/scx_adaptive_bg_prio_v4
...
```

build 디렉토리가 이미 있고 설정을 바꾸고 싶으면:
```bash
meson setup build --reconfigure -Dbuildtype=release
```

---

## 3. BPF 맵 초기화

스케줄러는 RocksDB가 쓰는 pinned BPF 맵 2개를 **재사용**한다.
RocksDB 실행 전에 반드시 맵을 먼저 생성해야 한다.

### 초기화 스크립트 실행

```bash
# rocksdb 저장소에 있음
cd <rocksdb_repo>
sudo bash init_scx_maps.sh
```

생성되는 맵:
| 맵 | 경로 | key | value |
|----|------|-----|-------|
| thread class | `/sys/fs/bpf/rocksdb_scx_thread_class_map` | u32 tid | 16B |
| db metrics   | `/sys/fs/bpf/rocksdb_scx_db_metrics_map`   | u32 tgid | 40B |

### 맵 경로 변경 (선택)
```bash
export ROCKSDB_SCX_THREAD_CLASS_MAP_PATH=/sys/fs/bpf/my_thread_map
export ROCKSDB_SCX_DB_METRICS_MAP_PATH=/sys/fs/bpf/my_db_map
```
RocksDB와 스케줄러 양쪽에 같은 환경변수를 설정해야 한다.

---

## 4. 스케줄러 실행

### 기본 패턴

```bash
# 터미널 1: 스케줄러 실행 (foreground, Ctrl-C로 종료)
sudo ./build/scheds/c/<scheduler_name> [옵션]

# 터미널 2: RocksDB 실행
./db_bench ...
```

스케줄러가 먼저 떠 있어야 RocksDB가 BPF 맵을 통해 연동된다.

### 종료

`Ctrl-C` 또는 `SIGTERM` 으로 종료하면 커널이 기본 CFS로 자동 복귀한다.

---

## 5. 스케줄러 설명 및 추천 파라미터

### `scx_l0_compaction_prio` — L0 컴팩션 우선

L0 파일 수가 임계값 이상일 때 L0 컴팩션 스레드에 super-priority 부여.
**베스트 단일 스케줄러** (실험 결과 기준).

```bash
sudo ./build/scheds/c/scx_l0_compaction_prio \
  -k 4 \        # l0_files >= 4 이면 super-priority 발동 (level0_slowdown_writes_trigger와 맞출 것)
  -A 10000      # DB 메트릭 최대 허용 staleness: 10초

# headroom 설정 (slowdown=8) 사용 시
sudo ./build/scheds/c/scx_l0_compaction_prio -k 8 -A 10000
```

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `-k` | 4 | l0_files 임계값 (`level0_slowdown_writes_trigger`와 맞출 것) |
| `-S` | 250000 | super-priority 슬라이스 (µs) |
| `-s` | 20000 | shared DSQ 슬라이스 (µs) |
| `-c` | 20000 | 일반 compaction 슬라이스 (µs) |
| `-A` | 3000 | DB 메트릭 최대 age (ms). 메트릭 업데이트가 느리면 늘릴 것 |
| `-W` | 5 | starvation 방지: N ms 이상 기다린 태스크 강제 dispatch |
| `-B` | 3 | N번 super dispatch 후 shared 강제 |
| `-L` | 2 | N번 L0 dispatch 후 compaction 강제 |

---

### `scx_compaction_add_flush_prio` — L0 컴팩션 + 선택적 flush elevation

`scx_l0_compaction_prio` 기반에 memtable 압력 감지 시 flush elevation 추가.

```bash
sudo ./build/scheds/c/scx_compaction_add_flush_prio \
  -k 4 \   # L0 super-priority 임계값
  -i 7 \   # imm_memtables >= 7 이면 flush elevation (max_write_buffer_number 기준으로 설정)
  -A 10000
```

**`-i` 값 선택 기준:**

`max_write_buffer_number=10` 이면 최대 immutable 9개.
- `-i 1`: 항상 elevation (flushprio와 거의 동일, 비권장)
- `-i 5`: 절반 찼을 때
- `-i 7`: stall 직전 (~권장)
- `-i 999`: flush elevation 비활성화 (l0_compaction_prio와 동일)

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `-k` | 4 | L0 super-priority 임계값 |
| `-i` | 1 | flush elevation: imm_memtables >= i |
| `-m` | 67108864 | flush elevation: cur_size_all_memtables >= m bytes |
| `-F` | 120000 | flush 슬라이스 (µs) |
| `-b` | 3 | N번 flush dispatch 후 comp/shared 강제 |

---

### `scx_memtable_flush_prio` — flush 우선

memtable 압력 감지 시 flush 스레드에 super-priority.

```bash
sudo ./build/scheds/c/scx_memtable_flush_prio \
  -i 1 \           # imm_memtables >= 1
  -m 67108864 \    # 또는 memtable_bytes >= 64MB
  -A 10000
```

---

### `scx_adaptive_bg_prio_v4` — FLUSH+L0 통합 vtime 경쟁

FLUSH_DSQ와 L0_DSQ를 하나의 BG_PRIO_DSQ로 통합, vtime으로 직접 경쟁.

```bash
sudo ./build/scheds/c/scx_adaptive_bg_prio_v4 \
  -k 8 \
  -A 10000
```

---

## 6. 동작 확인

### 출력 형식 (scx_l0_compaction_prio)

```
local=N global=N super_hit=N idle_direct=N preempt=N prefail=N super_dsq=N
thread_miss=N metrics_miss=N metrics_stale=N
wait_override=N super_wait_override=N
l0_files=N compaction_start_levels=[0,1,...]
```

| 카운터 | 정상 상태 | 문제 징후 |
|--------|-----------|-----------|
| `super_hit` | L0 압력 시 증가 | 0이면 `-k` 임계값 확인 |
| `compaction_start_levels` | `[0,...]` 포함 | 0 없으면 L0 컴팩션 미등록 |
| `metrics_stale` | 0에 가까움 | 급증 시 `-A` 값 늘릴 것 |
| `metrics_miss` | 0 | > 0 이면 `init_scx_maps.sh` 재실행 |
| `thread_miss` | global의 ~1배 | 대폭 초과 시 TID 매핑 문제 |

### 출력 형식 (scx_compaction_add_flush_prio)

추가 카운터:
```
flush_hit=N flush_idle=N flush_preempt=N flush_pfail=N flush_dsq=N
flush_wait=N
stall=N imm=N memtable_bytes=N l0_files=N
```

| 카운터 | 의미 |
|--------|------|
| `flush_hit` | flush elevation 발동 횟수 |
| `flush_preempt` | preemption 성공 |
| `flush_pfail` | preemption 실패 (idle CPU 없음) |
| `flush_wait` | wait_safety로 dispatch된 flush 수 |

`flush_wait ≈ flush_dsq` 이면 flush가 wait_safety(5ms)로만 나오는 것 → L0와 동시 압력 상황.

---

## 7. RocksDB 연동 요구사항

RocksDB 빌드에 SCX 연동 코드가 포함되어 있어야 한다.
연동 코드는 다음을 수행한다:

- `BGWorkFlush()` 진입 시 thread class map에 `class_id=1` 기록
- `BGWorkCompaction()` 진입 시 `class_id=2` 기록, 컴팩션 pick 후 `start_level`/`output_level` 업데이트
- 각 BG job 완료 시 db metrics map에 `l0_files`, `imm`, `memtable_bytes` 등 기록

BPF 맵 스키마 상세: `SCX_BPF_MAP_CONTRACT.md` 참고.

### RocksDB 빌드 확인

```bash
# db_bench 실행 후 맵에 데이터가 채워지는지 확인
sudo bpftool map dump pinned /sys/fs/bpf/rocksdb_scx_thread_class_map | head -20
sudo bpftool map dump pinned /sys/fs/bpf/rocksdb_scx_db_metrics_map   | head -20
```

---

## 8. 트러블슈팅

### `super_hit` 가 0

1. `compaction_start_levels`에 `0`이 있는지 확인
2. `-k` 값이 실제 `l0_files` 보다 높지 않은지 확인
3. `metrics_miss > 0` 이면 `init_scx_maps.sh` 재실행
4. RocksDB 버전에 SCX 연동 코드가 있는지 확인

### `metrics_stale` 급증

BG job이 완료되지 않아 메트릭이 오래됨.
```bash
sudo ./build/scheds/c/scx_l0_compaction_prio -k 4 -A 30000  # staleness 30초로 늘림
```

### 맵 permission 오류

```bash
sudo bash init_scx_maps.sh  # chown/chmod 재적용
```

### 스케줄러 로드 실패 (BPF verifier error)

커널 버전 확인: `uname -r` → 6.12 이상 필요.
`CONFIG_SCHED_CLASS_EXT=y` 확인.

### 스케줄러 종료 후 CFS 복귀 안 됨

정상적으로 SIGTERM/Ctrl-C로 종료하면 자동 복귀.
비정상 종료 시:
```bash
# 현재 스케줄러 확인
cat /sys/kernel/sched_ext/state
# 강제 종료
sudo pkill scx_
```
