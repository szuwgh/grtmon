#include "common.h"
#include "bpf_tracing.h"

//var gorEvent = map[uint32] string { 1 : "create", 2 : "put global g", 3 : "get global g", 4 : "steal", 5 : "exit" }

// const u32 create = 1;
// const u32 put_global = 2;
// const u32 get_global = 3;
// const u32 steal = 4;
// const u32 exit1 = 5;

struct
{ //高阶用法，改为Map堆中创建数据结构
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct gorevent);
} heap SEC(".maps");

static struct gorevent *get_event()
{
    static const int zero = 0;
    struct gorevent *event;

    event = bpf_map_lookup_elem(&heap, &zero);
    if (!event)
        return NULL;
    return event;
}

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") uprobe_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4,
};

struct gorevent
{
    u64 fn;
    u64 mid;
    u64 time;
    u32 event;
    u32 pid;
    u32 pid2;
    s64 goid;
};

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
};

const struct gorevent *unused __attribute__((unused));

struct bpf_map_def SEC("maps") time_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(s64),
    .value_size = sizeof(__u64),
    .max_entries = 512,
};

struct bpf_map_def SEC("maps") mem_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 512,
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

struct slice
{
    u64 addr;
    u64 len;
    u64 cap;
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
    s64 goid;
};

struct p
{

    u32 id;
    u32 status;
};

// const s32 tlsSlots = 6;

struct m
{
    u64 g0;
    struct gobuf morebuf;
    u64 tls[6];
    u64 mstartfn;
    u64 curg;
    u64 caughtsig;
    u64 p;
    u64 nextp;
    u64 oldp;
    s64 id;
};

struct funcval
{
    u64 fn; //函数地址
};

// 我们通过 go func() 来创建一个 goroutine；
// 有两个存储 G 的队列，一个是局部调度器P的本地队列、一个是全局G队列。新创建的G会先保存在
// P 的本地队列中，如果 P 的本地队列已经满了就会保存在全局的队列中；
// G 只能运行在 M 中，一个 M 必须持有一个 P，M 与 P 是 1：1 的关系。M 会从 P 的本地队列弹出一个可执行状态的 G 来执行，
// 如果 P 的本地队列为空，就会想其他的 MP 组合偷取一个可执行的 G 来执行；
// 一个 M 调度 G 执行的过程是一个循环机制；
// 当 M 执行某一个 G 时候如果发生了 syscall 或则其余阻塞操作，M 会阻塞，如果当前有一些 G 在执行，
// runtime 会把这个线程 M 从 P 中摘除(detach)，然后再创建一个新的操作系统的线程(如果有空闲的线程可用就复用空闲线程)来服务于这个 P；
// 当 M 系统调用结束时候，这个 G 会尝试获取一个空闲的 P 执行，并放入到这个 P 的本地队列。如果获取不到
// P，那么这个线程 M 变成休眠状态， 加入到空闲线程中，然后这个 G 会被放入全局队列中。

SEC("uprobe/runtime.newproc1")
int uprobe_runtime_newproc1(struct pt_regs *ctx)
{
    // __u32 key = 2;
    // __u64 initval = 1, *valp;

    // valp = bpf_map_lookup_elem(&uprobe_map, &key);
    // if (!valp)
    // {
    //     bpf_map_update_elem(&uprobe_map, &key, &initval, BPF_ANY);
    //     return 0;
    // }
    // __sync_fetch_and_add(valp, 1);
    //  struct gorevent event;
    struct funcval fn;
    bpf_probe_read(&fn, sizeof(fn), (void *)PT_REGS_RC(ctx));
    struct gorevent *event;
    event = get_event();
    if (!event)
        return 0;
    event->fn = fn.fn;
    event->event = 1;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

//放入全局队列
//func runqputslow(_p_ *p, gp *g, h, t uint32) bool
SEC("uprobe/runtime.runqputslow")
int uprobe_runtime_runqputslow(struct pt_regs *ctx)
{

    struct p ps;
    bpf_probe_read(&ps, sizeof(ps), (void *)(ctx->rax));

    struct g gs;
    bpf_probe_read(&gs, sizeof(gs), (void *)(ctx->rbx));
    // bpf_printk("runqput: %lld", gs.goid);
    //   struct gorevent event;
    // event.fn = fn.fn;
    //   event.goid = gs.goid;
    //   event.pid = ps.id;
    //   event.event = 2;
    //  bpf_perf_event_output(ctx, &gorevents, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

//从全局队列取
//func globrunqget(_p_ *p, max int32) *g
// SEC("uprobe/runtime.globrunqget")
// int uprobe_runtime_globrunqget(struct pt_regs *ctx)
// {

//     // struct p ps;
//     //  bpf_probe_read(&ps, sizeof(ps), (void *)(ctx->rax));
//     struct gorevent event;
//     // event.fn = fn.fn;
//     //event.pid = ps.id;
//     // event.event = get_global;
//     bpf_perf_event_output(ctx, &gorevents, BPF_F_CURRENT_CPU, &event, sizeof(event));

//     return 0;
// }

// Steal half of elements from local runnable queue of p2
//从其他队列偷
//func runqsteal(_p_, p2 *p, stealRunNextG bool) *g
SEC("uprobe/runtime.runqsteal")
int uprobe_runtime_runqsteal(struct pt_regs *ctx)
{

    struct p ps1;
    bpf_probe_read(&ps1, sizeof(ps1), (void *)(ctx->rax));

    struct p ps2;
    bpf_probe_read(&ps2, sizeof(ps2), (void *)(ctx->rbx));
    // bpf_printk("runqput: %lld", gs.goid);
    //    struct gorevent event;
    //    event.pid = ps1.id;
    //    event.pid2 = ps2.id;
    //    event.event = 3;
    //  bpf_perf_event_output(ctx, &gorevents, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

SEC("uprobe/runtime.execute")
int uprobe_runtime_execute(struct pt_regs *ctx)
{

    struct g gs;
    bpf_probe_read(&gs, sizeof(gs), (void *)(ctx->rax));
    // bpf_printk("execute: %lld", gs.goid);

    __u64 *valp = bpf_map_lookup_elem(&time_map, &gs.goid);
    if (!valp)
    {
        __u64 time1 = bpf_ktime_get_ns();
        //  bpf_printk("time %lld", time1);
        bpf_map_update_elem(&time_map, &gs.goid, &time1, BPF_ANY);
        return 0;
    }

    return 0;
}

SEC("uprobe/runtime.goexit0")
int uprobe_runtime_goexit0(struct pt_regs *ctx)
{

    struct g gs;
    bpf_probe_read(&gs, sizeof(gs), (void *)(ctx->rax));

    __u64 *time1 = bpf_map_lookup_elem(&time_map, &gs.goid);
    __u64 t1 = 0;
    bpf_probe_read(&t1, sizeof(t1), (void *)time1);
    //   __u64 time2 = bpf_ktime_get_ns();
    // bpf_printk("goexit0: %lld,%lld ns", gs.goid, time2 - t1);
    bpf_map_delete_elem(&time_map, &gs.goid);
    // struct gorevent *event;
    // event = get_event();
    //  event.goid = gs.goid;
    // event.pid = ps.id;
    //   event.event = 4;
    //   event.time = time2 - t1;
    // bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(*event));
    return 0;
}

// 第一个阶段 gc开始 （stw）

// stop the world 暂停程序执行
// 启动标记工作携程（ mark worker goroutine ），用于第二阶段
// 启动写屏障
// 将root 跟对象放入标记队列（放入标记队列里的就是灰色）
// start the world 取消程序暂停，进入第二阶段

// 第二阶段 marking（这个阶段，用户程序跟标记携程是并行的）开启写屏障
// 从标记队列里取出对象，标记为黑色
// 然后检测是否指向了另一个对象，如果有，将另一个对象放入标记队列
// 在扫描过程中，用户程序如果新创建了对象 或者修改了对象，就会触发写屏障，将对象放入单独的 marking队列，也就是标记为灰色
// 扫描完标记队列里的对象，就会进入第三阶段

// 第三阶段 处理marking过程中修改的指针 （stw）
// stop the world 暂停程序
// 将marking阶段 修改的对象 触发写屏障产生的队列里的对象取出，标记为黑色
// 然后检测是否指向了另一个对象，如果有，将另一个对象放入标记队列
// 扫描完marking队列里的对象，start the world 取消暂停程序

// 进入第四阶段
// 到这一阶段，所有内存要么是黑色的要么是白色的，清楚所有白色的即可
// golang的内存管理结构中有一个bitmap区域，其中可以标记是否“黑色”

//**********************************************************************************************************//

// 1、GC 清理终止 (GC performs sweep termination）
// a. Stop the world, 每个P 进入GC safepoint（安全点），从此刻开始，万物静止。
// b. 清理未被清理的span，如果GC被强制执行时才会出现这些未清理的span

// 2、GC 标记阶段（GC performs the mark phase）
// a. 将gc标记从 _GCoff 修改为 _GCmark，开启写屏障（write barries）和 协助助手（mutator assists），将根对象放入队列。 在STW期间，在所有P都启用写屏障之前不会有什么对象被扫描。
// b. Start the world（恢复STW）。标记工作线程和协助助手并发的执行。对于任何指针的写操作和指针值，都会被写屏障覆盖，使新分配的对象标记为黑色。
// c. GC 执行根标记工作。包括扫描所有的栈，全局对象和不在堆数据结构中的堆指针。每扫描一个栈就会导致goroutine停止，把在栈上找到的所有指针置灰色，然后再恢复goroutine运行。
// d. GC 遍历队列中的每个灰色对象，扫描完以后将灰色对象标记为黑色，并将其指向的对象标记为灰色。
// e. 由于GC工作在分布本地缓存中，采用了一种 “分布式终止算法（distributed termination algorithm）” 来检测什么时候没有根对象或灰色对象。在这个时机GC会转为标记中止（mark termination）。

// 3、标记终止（GC performs mark termination）
// a. Stop the world，从此刻开始，万物静止
// b. 设置阶段为 _GCmarktermination，并禁用 工作线程worker和协助助手
// c. 执行清理，flush cache

// 4、清理阶段（GC performs the sweep phase）
// a. 设置清理阶段标记为 _GCoff，设置清理状态禁用写屏障
// b. Start the world（恢复STW），从现在开始，新分配的对象是白色的。如有必要，请在请在使用前扫描清理
// c. GC在后台执行并发扫描，并响应分配

// 第二阶段 扫描标记
SEC("uprobe/runtime.gcBgMarkWorker")
int uprobe_runtime_gcDrain(struct pt_regs *ctx)
{
    bpf_printk("gcBgMarkWorker");
    return 0;
}

// //第三阶段 标记终止
// SEC("uprobe/runtime.gcMarkDone")
// int uprobe_runtime_gcMarkDone(struct pt_regs *ctx)
// {
//     bpf_printk("gcMarkDone");
//     return 0;
// }

// 第四阶段 清理
SEC("uprobe/runtime.gcSweep")
int uprobe_runtime_gcsweep(struct pt_regs *ctx)
{
    bpf_printk("gcSweep");
    return 0;
}

// 停止世界
SEC("uprobe/runtime.stopTheWorldWithSema")
int uprobe_runtime_stopTheWorldWithSema(struct pt_regs *ctx)
{
    bpf_printk("stopTheWorldWithSema");
    return 0;
}

// 开始世界
SEC("uprobe/runtime.startTheWorldWithSema")
int uprobe_runtime_startTheWorldWithSema(struct pt_regs *ctx)
{
    bpf_printk("startTheWorldWithSema");
    return 0;
}

struct gotype
{
    u64 size;
    u64 ptrdata;
};

// 小于 16B 的用 mcache 中的 tiny 分配器分配；
// 大于 32KB 的对象直接使用堆区分配；
// 16B 和 32KB 之间的对象用 mspan 分配。

// Allocate an object of size bytes.
// Small objects are allocated from the per-P cache's free lists.
// Large objects (> 32 kB) are allocated straight from the heap.
SEC("uprobe/runtime.mallocgc")
int uprobe_runtime_mallocgc(struct pt_regs *ctx)
{
    //struct g gs;
    __u64 siz = ctx->rax;
    //bpf_probe_read(&siz, sizeof(siz), (void *)(ctx->rax));

    // struct gotype gt;
    // bpf_probe_read(&gt, -sizeof(gt), (void *)(ctx->rbx));

    bpf_printk("siz: %lld", siz);
    return 0;
}

//内存分配
