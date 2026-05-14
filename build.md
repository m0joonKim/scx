아래 순서로 하면 됩니다 (/home/dccmars/mjkim/scx_ksc 기준).

cd /home/dccmars/mjkim/scx_ksc
# 1) 최초 1회 설정
meson setup build -Dbuildtype=release
# 2) 빌드
meson compile -C build
scx_l0_compaction_prio만 빠르게 빌드하려면:

meson compile -C build scx_l0_compaction_prio
빌드 결과 바이너리:

build/scheds/c/scx_l0_compaction_prio
실행 예시 (k=12):

sudo ./build/scheds/c/scx_l0_compaction_prio -k 12
이미 build 디렉토리가 있는데 설정을 바꾸고 싶으면:

meson setup build --reconfigure -Dbuildtype=release