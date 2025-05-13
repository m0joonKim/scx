/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dsq_insert_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scs_cf_simple only supported global FIFO scheduling, then we could just
 * use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0
// compaction vs flush start
// #define COMPACTION 1
// #define FLUSH 5
// compaction vs flush end
#define CSTART 4
#define SLOWDOWN 20
#define STALL 36

#define T50

#ifdef CF
#define THRESHOLD 36
#define SCALE 2
#define T_WEIGHT 8
#endif
#ifdef FF
#define THRESHOLD 36
#define SCALE 8
#define T_WEIGHT 2
#endif
#ifdef T90
#define THRESHOLD 18
#define SCALE 8
#define T_WEIGHT 2
#endif
#ifdef T75
#define THRESHOLD 15
#define SCALE 8
#define T_WEIGHT 2
#endif
#ifdef T50
#define THRESHOLD 10
#define SCALE 8
#define T_WEIGHT 2
#endif
#ifdef BASE
#define THRESHOLD 36
#define SCALE 2
#define T_WEIGHT 2
#endif

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 2); /* [local, global] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
    u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
    if (cnt_p)
        (*cnt_p)++;
}

s32 BPF_STRUCT_OPS(cf_simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    bool is_idle = false;
    s32 cpu;

    cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
    if (is_idle)
    {
        stat_inc(0); /* count local queueing */
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    }

    return cpu;
}

void BPF_STRUCT_OPS(cf_simple_enqueue, struct task_struct *p, u64 enq_flags)
{
    stat_inc(1); /* count queueing */

    if (fifo_sched)
    {
        scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
    }
    else
    {
        u64 vtime = p->scx.dsq_vtime;

        /*
         * Limit the amount of budget that an idling task can accumulate
         * to one slice.
         */
        if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
            vtime = vtime_now - SCX_SLICE_DFL;

        scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
                                 enq_flags);
    }
}

void BPF_STRUCT_OPS(cf_simple_dispatch, s32 cpu, struct task_struct *prev)
{
    scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(cf_simple_running, struct task_struct *p)
{
    if (fifo_sched)
        return;

    /*
     * Global vtime always progresses forward as tasks start executing. The
     * test and update can be performed concurrently from multiple CPUs and
     * thus racy. Any error should be contained and temporary. Let's just
     * live with it.
     */
    if (time_before(vtime_now, p->scx.dsq_vtime))
        vtime_now = p->scx.dsq_vtime;
}

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // bpffs에 고정된 맵을 사용
} L0num SEC(".maps");

void BPF_STRUCT_OPS(cf_simple_stopping, struct task_struct *p, bool runnable)
{
    if (fifo_sched)
        return;

    // compaction vs flush start
    bool is_compaction = __builtin_memcmp(p->comm, "rocksdb:low", 12) == 0;
    bool is_flush = __builtin_memcmp(p->comm, "rocksdb:high", 11) == 0;

    int key = 0;
    int *val;
    // default weight : 100
    // high weight == high priority
    // u32 weight_modi = p->scx.weight;
    if (is_compaction)
    {
        val = bpf_map_lookup_elem(&L0num, &key);
        int compaction_w;
        if (*val > THRESHOLD)
            compaction_w = SCALE;
        else
            compaction_w = T_WEIGHT;

        p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / (compaction_w * p->scx.weight);
        // bpf_printk("%d\n", *val);
        // bpf_printk("%s %u\n", p->comm, (SCX_SLICE_DFL - p->scx.slice) * 100 / (COMPACTION * p->scx.weight));
    }
    else if (is_flush)
    {
        val = bpf_map_lookup_elem(&L0num, &key);
        int flush_w;
        if (*val > THRESHOLD)
            flush_w = T_WEIGHT;
        else
            flush_w = SCALE;

        p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / (flush_w * p->scx.weight);
        // bpf_printk("%s %u\n", p->comm, (SCX_SLICE_DFL - p->scx.slice) * 100 / (FLUSH * p->scx.weight));
    }
    else // default
    {
        p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
        // bpf_printk("%s %u\n", p->comm, (SCX_SLICE_DFL - p->scx.slice) * 100 / (p->scx.weight));
    }
    // compaction vs flush end
}

void BPF_STRUCT_OPS(cf_simple_enable, struct task_struct *p)
{
    p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cf_simple_init)
{
    return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(cf_simple_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cf_simple_ops,
               .select_cpu = (void *)cf_simple_select_cpu,
               .enqueue = (void *)cf_simple_enqueue,
               .dispatch = (void *)cf_simple_dispatch,
               .running = (void *)cf_simple_running,
               .stopping = (void *)cf_simple_stopping,
               .enable = (void *)cf_simple_enable,
               .init = (void *)cf_simple_init,
               .exit = (void *)cf_simple_exit,
               .name = "simple");
