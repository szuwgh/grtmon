#include "common.h"
#include "bpf_tracing.h"

static const u32 gor_create = 1;
static const u32 gor_put_global = 2;
static const u32 gor_get_global = 3;
static const u32 gor_steal = 4;
static const u32 gor_exit = 5;

static const u32 gc_mark = 1;
static const u32 gc_sweep = 2;
static const u32 gc_stw = 3;

struct gorevent
{
    u64 fn;
    u64 time;
    u32 event;
    u32 pid;
    s64 goid;
};

struct gcevent
{
    u64 time;
    u32 event;
};

const struct gorevent *unused __attribute__((unused));
const struct gcevent *unused1 __attribute__((unused));

//高阶用法，改为Map堆中创建数据结构
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct gorevent);
} heap SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct gcevent);
} heap1 SEC(".maps");

static struct gorevent *get_gorevent()
{
    static const int zero = 0;
    struct gorevent *event;
    event = bpf_map_lookup_elem(&heap, &zero);
    if (!event)
        return NULL;
    event->fn = 0;
    event->time = 0;
    event->event = 0;
    event->pid = 0;
    event->goid = 0;
    return event;
}

static struct gcevent *get_gcevent()
{
    static const int zero = 0;
    struct gcevent *event;
    event = bpf_map_lookup_elem(&heap1, &zero);
    if (!event)
        return NULL;
    event->time = 0;
    event->event = 0;
    return event;
}

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") uprobe_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4,
};

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 1024,
};

struct bpf_map_def SEC("maps") gr_time_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(s64),
    .value_size = sizeof(__u64),
    .max_entries = 128,
};

struct bpf_map_def SEC("maps") gc_time_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(__u64),
    .max_entries = 128,
};

struct bpf_map_def SEC("maps") mem_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 512,
};

struct bpf_map_def SEC("maps") gm_hist_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 128,
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

    u64 schedlink;
    s64 waitsince;
    u8 waitreason;

    u8 preempt;       // preemption signal, duplicates stackguard0 = stackpreempt
    u8 preemptStop;   // transition to _Gpreempted on preemption; otherwise, just deschedule
    u8 preemptShrink; // shrink stack at synchronous safe point

    // asyncSafePoint is set if g is stopped at an asynchronous
    // safe point. This means there are frames on the stack
    // without precise pointer information.
    u8 asyncSafePoint;

    u8 paniconfault; // panic (instead of crash) on unexpected fault address
    u8 gcscandone;   // g has scanned stack; protected by _Gscan bit in status
    u8 throwsplit;   // must not split stack
                     // activeStackChans indicates that there are unlocked channels
                     // pointing into this goroutine's stack. If true, stack
                     // copying needs to acquire channel locks to protect these
                     // areas of the stack.
    u8 activeStackChans;
    // parkingOnChan indicates that the goroutine is about to
    // park on a chansend or chanrecv. Used to signal an unsafe point
    // for stack shrinking. It's a boolean value, but is updated atomically.
    u8 parkingOnChan;

    u8 raceignore;     // ignore race detection events
    u8 sysblocktraced; // StartTrace has emitted EvGoInSyscall about this goroutine
    u8 tracking;       // whether we're tracking this G for sched latency statistics
    u8 trackingSeq;    // used to decide whether to track this G
    s64 runnableStamp; // timestamp of when the G last became runnable, only used when tracking
    s64 runnableTime;  // the amount of time spent runnable, cleared when running, only used when tracking
    s64 sysexitticks;  // cputicks when syscall has returned (for tracing)
    u64 traceseq;      // trace event sequencer
    u64 tracelastp;    // last P emitted an event for this goroutine
    u64 lockedm;
    u32 sig;
    struct slice writebuf;
    u64 sigcode0;
    u64 sigcode1;
    u64 sigpc;
    u64 gopc;      // pc of go statement that created this goroutine
    u64 ancestors; // ancestor information goroutine(s) that created this goroutine (only used if debug.tracebackancestors)
    u64 startpc;   // pc of goroutine function
};

struct p
{

    u32 id;
    u32 status;
};

struct gsignalStack
{
};

struct sigset
{
};

struct m
{
    u64 g0;
    struct gobuf morebuf;
    u32 divmod;
    u32 _;
    u64 procid;
    u64 gsignal;

    struct gsignalStack goSigStack;
    u64 sigmask;

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
    struct funcval fn;
    bpf_probe_read(&fn, sizeof(fn), (void *)PT_REGS_RC(ctx));
    struct gorevent *event;
    event = get_gorevent();
    if (!event)
        return 0;
    event->fn = fn.fn;
    event->event = gor_create;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

//放入全局队列
// func runqputslow(_p_ *p, gp *g, h, t uint32) bool
SEC("uprobe/runtime.runqputslow")
int uprobe_runtime_runqputslow(struct pt_regs *ctx)
{

    struct p ps;
    bpf_probe_read(&ps, sizeof(ps), (void *)(ctx->rax));

    struct g gs;
    bpf_probe_read(&gs, sizeof(gs), (void *)(ctx->rbx));
    // bpf_printk("runqput: %lld", gs.goid);
    struct gorevent *event;
    event = get_gorevent();
    if (!event)
        return 0;
    event->goid = gs.goid;
    event->pid = ps.id;
    event->event = gor_put_global;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

//从全局队列取
// func globrunqget(_p_ *p, max int32) * g
SEC("uprobe/runtime.globrunqget")
int uprobe_runtime_globrunqget(struct pt_regs *ctx)
{

    struct p ps;
    bpf_probe_read(&ps, sizeof(ps), (void *)(ctx->rax));
    struct gorevent *event;
    event = get_gorevent();
    if (!event)
        return 0;
    // event.fn = fn.fn;
    event->pid = ps.id;
    event->event = gor_get_global;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// Steal half of elements from local runnable queue of p2
//从其他队列偷
// func runqsteal(_p_, p2 *p, stealRunNextG bool) *g
SEC("uprobe/runtime.runqsteal")
int uprobe_runtime_runqsteal(struct pt_regs *ctx)
{

    struct p ps1;
    bpf_probe_read(&ps1, sizeof(ps1), (void *)(ctx->rax));

    struct p ps2;
    bpf_probe_read(&ps2, sizeof(ps2), (void *)(ctx->rbx));
    struct gorevent *event;
    event = get_gorevent();
    if (!event)
        return 0;
    event->pid = ps1.id;
    event->event = gor_steal;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

SEC("uprobe/runtime.execute")
int uprobe_runtime_execute(struct pt_regs *ctx)
{

    struct g gs;
    bpf_probe_read(&gs, sizeof(gs), (void *)(ctx->rax));
    u64 *valp = bpf_map_lookup_elem(&gr_time_map, &gs.goid);
    if (!valp)
    {
        u64 time1 = bpf_ktime_get_ns();
        bpf_map_update_elem(&gr_time_map, &gs.goid, &time1, BPF_ANY);
        return 0;
    }
    return 0;
}

SEC("uprobe/runtime.goexit0")
int uprobe_runtime_goexit0(struct pt_regs *ctx)
{

    struct g gs;
    bpf_probe_read(&gs, sizeof(gs), (void *)(ctx->rax));
    u64 *time1 = bpf_map_lookup_elem(&gr_time_map, &gs.goid);
    u64 t1 = 0;
    bpf_probe_read(&t1, sizeof(t1), (void *)time1);
    bpf_map_delete_elem(&gr_time_map, &gs.goid);
    struct gorevent *event;
    event = get_gorevent();
    if (!event)
        return 0;
    u64 time2 = bpf_ktime_get_ns();
    event->fn = gs.startpc;
    event->goid = gs.goid;
    event->event = gor_exit;
    event->time = time2 - t1;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

SEC("uprobe/runtime.goexit0")
int uprobe_runtime_goexit1(struct pt_regs *ctx)
{

    struct g gs;
    bpf_probe_read(&gs, sizeof(gs), (void *)(ctx->rax));
    u64 *time1 = bpf_map_lookup_elem(&gr_time_map, &gs.goid);
    u64 t1 = 0;
    bpf_probe_read(&t1, sizeof(t1), (void *)time1);
    bpf_map_delete_elem(&gr_time_map, &gs.goid);
    struct gorevent *event;
    event = get_gorevent();
    if (!event)
        return 0;
    u64 time2 = bpf_ktime_get_ns();
    event->fn = gs.startpc;
    event->goid = gs.goid;
    event->event = gor_exit;
    event->time = time2 - t1;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
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
SEC("uprobe/runtime.gcStart")
int uprobe_runtime_gcStart(struct pt_regs *ctx)
{

    u32 key = 1;
    u64 *valp = bpf_map_lookup_elem(&gc_time_map, &key);
    if (!valp)
    {
        u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&gc_time_map, &key, &ts, BPF_ANY);
        return 0;
    }
    return 0;
}

//第三阶段 标记终止
SEC("uprobe/runtime.gcMarkDone")
int uprobe_runtime_gcMarkDone(struct pt_regs *ctx)
{
    u32 key = 1;
    u64 *ts1 = bpf_map_lookup_elem(&gc_time_map, &key);
    if (!ts1)
    {
        return 0;
    }
    struct gcevent *event;
    event = get_gcevent();
    if (!event)
        return 0;
    u64 t1 = 0;
    u64 t2 = bpf_ktime_get_ns();
    bpf_probe_read(&t1, sizeof(t1), (void *)ts1);
    event->event = gc_mark;
    event->time = t2 - t1;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    bpf_map_delete_elem(&gc_time_map, &key);
    return 0;
}

// 第四阶段 清理
SEC("uprobe/runtime.gcSweep")
int uprobe_runtime_gcsweep(struct pt_regs *ctx)
{
    u32 key = 2;
    u64 *valp = bpf_map_lookup_elem(&gc_time_map, &key);
    if (!valp)
    {
        u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&gc_time_map, &key, &ts, BPF_ANY);
        return 0;
    }
    return 0;
}

// 停止世界
SEC("uprobe/runtime.stopTheWorldWithSema")
int uprobe_runtime_stopTheWorldWithSema(struct pt_regs *ctx)
{
    u32 key = 3;
    u64 *valp = bpf_map_lookup_elem(&gc_time_map, &key);
    if (!valp)
    {
        u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&gc_time_map, &key, &ts, BPF_ANY);
        return 0;
    }
    return 0;
}

// 开始世界
SEC("uprobe/runtime.startTheWorldWithSema")
int uprobe_runtime_startTheWorldWithSema(struct pt_regs *ctx)
{
    u32 key1 = 2;
    u64 *ts1 = bpf_map_lookup_elem(&gc_time_map, &key1);
    if (ts1)
    {
        struct gcevent *event;
        event = get_gcevent();
        if (event)
        {
            u64 t1 = 0;
            u64 t2 = bpf_ktime_get_ns();
            bpf_probe_read(&t1, sizeof(t1), (void *)ts1);
            event->event = gc_sweep;
            event->time = t2 - t1;
            bpf_map_delete_elem(&gc_time_map, &key1);
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
        }
    }

    u32 key2 = 3;
    u64 *ts2 = bpf_map_lookup_elem(&gc_time_map, &key2);

    if (ts2)
    {
        struct gcevent *event;
        event = get_gcevent();
        if (event)
        {
            u64 t1 = 0;
            u64 t2 = bpf_ktime_get_ns();
            bpf_probe_read(&t1, sizeof(t1), (void *)ts2);
            event->event = gc_stw;
            event->time = t2 - t1;
            bpf_map_delete_elem(&gc_time_map, &key2);
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
        }
    }

    return 0;
}

struct gotype
{
    u64 size;
    u64 ptrdata;
};

// 小于 16B 的用 mcache 中的 tiny 分配器分配；
// 16B 和 32KB 之间的对象用 mspan 分配。
// 大于 32KB 的对象直接使用堆区分配；

// Allocate an object of size bytes.
// Small objects are allocated from the per-P cache's free lists.
// Large objects (> 32 kB) are allocated straight from the heap.
SEC("uprobe/runtime.mallocgc")
int uprobe_runtime_mallocgc(struct pt_regs *ctx)
{

    __u64 siz = ctx->rax;
    u64 initval = 1;
    if (siz < 16)
    {
        u32 key = 0;
        u64 *valp = bpf_map_lookup_elem(&gm_hist_map, &key);
        if (!valp)
        {
            bpf_map_update_elem(&gm_hist_map, &key, &initval, BPF_ANY);
            return 0;
        }
        __sync_fetch_and_add(valp, 1);
    }
    else if (siz >= 16 && siz < 32758)
    {
        u32 key = 1;
        u64 *valp = bpf_map_lookup_elem(&gm_hist_map, &key);
        if (!valp)
        {
            bpf_map_update_elem(&gm_hist_map, &key, &initval, BPF_ANY);
            return 0;
        }
        __sync_fetch_and_add(valp, 1);
    }
    else
    {
        u32 key = 2;
        u64 *valp = bpf_map_lookup_elem(&gm_hist_map, &key);
        if (!valp)
        {
            bpf_map_update_elem(&gm_hist_map, &key, &initval, BPF_ANY);
            return 0;
        }
        __sync_fetch_and_add(valp, 1);
    }
    return 0;
}

//内存分配
