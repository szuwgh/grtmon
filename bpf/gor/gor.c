#include "common.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// type g struct {
// 	// Stack parameters.
// 	// stack describes the actual stack memory: [stack.lo, stack.hi).
// 	// stackguard0 is the stack pointer compared in the Go stack growth prologue.
// 	// It is stack.lo+StackGuard normally, but can be StackPreempt to trigger a preemption.
// 	// stackguard1 is the stack pointer compared in the C stack growth prologue.
// 	// It is stack.lo+StackGuard on g0 and gsignal stacks.
// 	// It is ~0 on other goroutine stacks, to trigger a call to morestackc (and crash).
// 	stack       stack   // offset known to runtime/cgo
// 	stackguard0 uintptr // offset known to liblink
// 	stackguard1 uintptr // offset known to liblink

// 	_panic    *_panic // innermost panic - offset known to liblink
// 	_defer    *_defer // innermost defer
// 	m         *m      // current m; offset known to arm liblink
// 	sched     gobuf
// 	syscallsp uintptr // if status==Gsyscall, syscallsp = sched.sp to use during gc
// 	syscallpc uintptr // if status==Gsyscall, syscallpc = sched.pc to use during gc
// 	stktopsp  uintptr // expected sp at top of stack, to check in traceback
// 	// param is a generic pointer parameter field used to pass
// 	// values in particular contexts where other storage for the
// 	// parameter would be difficult to find. It is currently used
// 	// in three ways:
// 	// 1. When a channel operation wakes up a blocked goroutine, it sets param to
// 	//    point to the sudog of the completed blocking operation.
// 	// 2. By gcAssistAlloc1 to signal back to its caller that the goroutine completed
// 	//    the GC cycle. It is unsafe to do so in any other way, because the goroutine's
// 	//    stack may have moved in the meantime.
// 	// 3. By debugCallWrap to pass parameters to a new goroutine because allocating a
// 	//    closure in the runtime is forbidden.
// 	param        unsafe.Pointer
// 	atomicstatus uint32
// 	stackLock    uint32 // sigprof/scang lock; TODO: fold in to atomicstatus
// 	goid         int64
// 	schedlink    guintptr
// 	waitsince    int64      // approx time when the g become blocked
// 	waitreason   waitReason // if status==Gwaiting

// 	preempt       bool // preemption signal, duplicates stackguard0 = stackpreempt
// 	preemptStop   bool // transition to _Gpreempted on preemption; otherwise, just deschedule
// 	preemptShrink bool // shrink stack at synchronous safe point

// 	// asyncSafePoint is set if g is stopped at an asynchronous
// 	// safe point. This means there are frames on the stack
// 	// without precise pointer information.
// 	asyncSafePoint bool

// 	paniconfault bool // panic (instead of crash) on unexpected fault address
// 	gcscandone   bool // g has scanned stack; protected by _Gscan bit in status
// 	throwsplit   bool // must not split stack
// 	// activeStackChans indicates that there are unlocked channels
// 	// pointing into this goroutine's stack. If true, stack
// 	// copying needs to acquire channel locks to protect these
// 	// areas of the stack.
// 	activeStackChans bool
// 	// parkingOnChan indicates that the goroutine is about to
// 	// park on a chansend or chanrecv. Used to signal an unsafe point
// 	// for stack shrinking. It's a boolean value, but is updated atomically.
// 	parkingOnChan uint8

// 	raceignore     int8     // ignore race detection events
// 	sysblocktraced bool     // StartTrace has emitted EvGoInSyscall about this goroutine
// 	tracking       bool     // whether we're tracking this G for sched latency statistics
// 	trackingSeq    uint8    // used to decide whether to track this G
// 	runnableStamp  int64    // timestamp of when the G last became runnable, only used when tracking
// 	runnableTime   int64    // the amount of time spent runnable, cleared when running, only used when tracking
// 	sysexitticks   int64    // cputicks when syscall has returned (for tracing)
// 	traceseq       uint64   // trace event sequencer
// 	tracelastp     puintptr // last P emitted an event for this goroutine
// 	lockedm        muintptr
// 	sig            uint32
// 	writebuf       []byte
// 	sigcode0       uintptr
// 	sigcode1       uintptr
// 	sigpc          uintptr
// 	gopc           uintptr         // pc of go statement that created this goroutine
// 	ancestors      *[]ancestorInfo // ancestor information goroutine(s) that created this goroutine (only used if debug.tracebackancestors)
// 	startpc        uintptr         // pc of goroutine function
// 	racectx        uintptr
// 	waiting        *sudog         // sudog structures this g is waiting on (that have a valid elem ptr); in lock order
// 	cgoCtxt        []uintptr      // cgo traceback context
// 	labels         unsafe.Pointer // profiler labels
// 	timer          *timer         // cached timer for time.Sleep
// 	selectDone     uint32         // are we participating in a select and did someone win the race?

// 	// Per-G GC state

// 	// gcAssistBytes is this G's GC assist credit in terms of
// 	// bytes allocated. If this is positive, then the G has credit
// 	// to allocate gcAssistBytes bytes without assisting. If this
// 	// is negative, then the G must correct this by performing
// 	// scan work. We track this in bytes to make it fast to update
// 	// and check for debt in the malloc hot path. The assist ratio
// 	// determines how this corresponds to scan work debt.
// 	gcAssistBytes int64
// }

struct bpf_map_def SEC("maps") uprobe_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4,
};

struct bpf_map_def SEC("maps") time_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(s64),
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
    s64 goid; // Here it is!

    // u64 schedlink;
    // s64 waitsince;
    // u8 waitreason;

    // u8 preempt;       // preemption signal, duplicates stackguard0 = stackpreempt
    // u8 preemptStop;   // transition to _Gpreempted on preemption; otherwise, just deschedule
    // u8 preemptShrink; // shrink stack at synchronous safe point

    // // asyncSafePoint is set if g is stopped at an asynchronous
    // // safe point. This means there are frames on the stack
    // // without precise pointer information.
    // u8 asyncSafePoint;

    // u8 paniconfault; // panic (instead of crash) on unexpected fault address
    // u8 gcscandone;   // g has scanned stack; protected by _Gscan bit in status
    // u8 throwsplit;   // must not split stack
    //                  // activeStackChans indicates that there are unlocked channels
    //                  // pointing into this goroutine's stack. If true, stack
    //                  // copying needs to acquire channel locks to protect these
    //                  // areas of the stack.
    // u8 activeStackChans;
    // // parkingOnChan indicates that the goroutine is about to
    // // park on a chansend or chanrecv. Used to signal an unsafe point
    // // for stack shrinking. It's a boolean value, but is updated atomically.
    // u8 parkingOnChan;

    // u8 raceignore;     // ignore race detection events
    // u8 sysblocktraced; // StartTrace has emitted EvGoInSyscall about this goroutine
    // u8 tracking;       // whether we're tracking this G for sched latency statistics
    // u8 trackingSeq;    // used to decide whether to track this G
    // s64 runnableStamp; // timestamp of when the G last became runnable, only used when tracking
    // s64 runnableTime;  // the amount of time spent runnable, cleared when running, only used when tracking
    // s64 sysexitticks;  // cputicks when syscall has returned (for tracing)
    // u64 traceseq;      // trace event sequencer
    // u64 tracelastp;    // last P emitted an event for this goroutine
    // u64 lockedm;
    // u32 sig;
    // struct slice writebuf;
    // u64 sigcode0;
    // u64 sigcode1;
    // u64 sigpc;
    // u64 gopc;      // pc of go statement that created this goroutine
    // u64 ancestors; // ancestor information goroutine(s) that created this goroutine (only used if debug.tracebackancestors)
    // u64 startpc;   // pc of goroutine function
};

struct funcval
{
    u64 fn; //函数地址
};

SEC("uprobe/runtime.newproc1")
int uprobe_runtime_newproc1(struct pt_regs *ctx)
{
    __u32 key = 2;
    __u64 initval = 1, *valp;

    valp = bpf_map_lookup_elem(&uprobe_map, &key);
    if (!valp)
    {
        bpf_map_update_elem(&uprobe_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp, 1);

    struct funcval fn;
    bpf_probe_read(&fn, sizeof(fn), (void *)PT_REGS_RC(ctx));
    bpf_printk("fn %x", fn.fn);

    return 0;
}

SEC("uprobe/runtime.runqput")
int uprobe_runtime_runqput(struct pt_regs *ctx)
{

    struct g gs;
    bpf_probe_read(&gs, sizeof(gs), (void *)(ctx->rbx));
    bpf_printk("runqput: %lld", gs.goid);

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
    __u64 time2 = bpf_ktime_get_ns();
    bpf_printk("goexit0: %lld,%lld ns", gs.goid, time2 - t1);
    bpf_map_delete_elem(&time_map, &gs.goid);

    return 0;
}

SEC("uprobe/runtime.gcStart")
int uprobe_runtime_gcstart(struct pt_regs *ctx)
{
    bpf_printk("GC");
    return 0;
}

SEC("uprobe/runtime.gcSweep")
int uprobe_runtime_gcsweep(struct pt_regs *ctx)
{
    bpf_printk("GC");
    return 0;
}

SEC("uprobe/runtime.gcSweep")
int uprobe_runtime_gcsweep(struct pt_regs *ctx)
{
    bpf_printk("GC");
    return 0;
}

// SEC("uprobe/runtime.GC")
// int uprobe_runtime_gc(struct pt_regs *ctx)
// {
//     return 0;
// }
