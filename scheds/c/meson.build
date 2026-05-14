c_scheds = ['scx_simple', 'scx_qmap', 'scx_central', 'scx_userland', 'scx_nest',
            'scx_flatcg', 'scx_pair', 'scx_prev', 'scx_cf_simple', 'scx_rdb_probe',
            'scx_flush_prio', 'scx_flush_compaction_prio', 'scx_l0_compaction_prio',
            'scx_memtable_flush_prio', 'scx_adaptive_bg_prio', 'scx_adaptive_bg_prio_v2',
            'scx_adaptive_bg_prio_v3', 'scx_adaptive_bg_prio_v4',
            'scx_compaction_add_flush_prio']

c_scheds_lib = ['scx_sdt']

thread_dep = dependency('threads')

foreach sched: c_scheds
  bpf_o = gen_bpf_o.process(sched + '.bpf.c')
  bpf_skel = gen_bpf_skel.process(bpf_o)
  executable(sched, [bpf_skel, sched + '.c'],
             include_directories: [user_c_includes],
             dependencies: [kernel_dep, libbpf_dep, thread_dep],
             install: true)
endforeach

foreach sched: c_scheds_lib
  bpf_o = gen_bpf_o.process(sched + '.bpf.c')
  bpf_skel = gen_bpf_skel_lib.process(bpf_o)
  executable(sched, [bpf_skel, sched + '.c'],
             include_directories: [user_c_includes],
             dependencies: [kernel_dep, libbpf_dep, thread_dep],
             install: true)
endforeach
