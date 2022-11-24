#include "common.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") uprobe_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4,
};

struct stack
{
    u64 lo;
    u64 hi;
};

struct gobuf
{
    u64 sp;
    u64 pc;
    u64 g;
    u64 ctxt;
    u64 ret;
    u64 lr;
    u64 bp;
};

struct g
{
    struct stack stack;
    u64 stackguard0;
    u64 stackguard1;

    u64 _panic;
    u64 _defer;
    u64 m;
    struct gobuf sched;
    u64 syscallsp;
    u64 syscallpc;
    u64 stktopsp;
    u64 param;
    u32 atomicstatus;
    u32 stackLock;
    s64 goid; // Here it is!
};

// struct pt_regs
// {

//     unsigned long sp;
//     unsigned long bx;
//     unsigned long cx;
//     unsigned long dx;
//     unsigned long si;
//     unsigned long di;
//     unsigned long bp;
//     unsigned long ax;

//     // more fields ...
// };

struct funcval
{
    u64 fn;
};

SEC("uprobe/runtime.newproc1")
int uprobe_main_hello(struct pt_regs *ctx)
{
    __u32 key = (__u32)2;
    __u64 initval = 1, *valp;

    valp = bpf_map_lookup_elem(&uprobe_map, &key);
    if (!valp)
    {
        bpf_map_update_elem(&uprobe_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp, 1);

    void *stackAddr = (void *)ctx->rsp;
    struct funcval fn;
    bpf_probe_read(&fn, sizeof(fn), stackAddr + 8);

    bpf_printk("fn: %x", fn.fn);

    struct g gs;
    bpf_probe_read(&gs, sizeof(gs), (void *)PT_REGS_PARM1(ctx));
    bpf_printk("uprobe_runtime_newproc1 bpf_printk bpf_probe_read goroutine_struct.goid: %lld", gs.goid);
    // retrieve output parameter

    return 0;
}