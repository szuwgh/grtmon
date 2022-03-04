
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
const volatile __u64 min_us = 0;
const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
extern int LINUX_KERNEL_VERSION __kconfig;

struct bpf_map_def SEC("maps") tcp_map =
    {
        .type = BPF_MAP_TYPE_LRU_HASH,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(struct sock *),
        .max_entries = 1024};

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect)
{
    struct sock *sk = ctx->di;
    u32 pid = bpf_get_current_pid_tgid();

    // bpf_map_update_elem(&connection_map, &nconnkey, &port, BPF_ANY);
    // stash the sock ptr for lookup on return
    bpf_map_update_elem(&tcp_map, &pid, &sk, BPF_ANY);

    return 0;
};

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(ret_tcp_v4_connect)
{

    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = bpf_map_lookup_elem(&tcp_map, &pid);
    if (skpp == 0)
    {
        return 0; // missed entry
    }

    if (ret != 0)
    {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        bpf_map_delete_elem(&tcp_map, &pid);
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u32 saddr = (
        {
            typeof(__be32) _val;
            __builtin_memset(&_val, 0, sizeof(_val));
            bpf_probe_read(&_val, sizeof(_val), (u64)&skp->__sk_common.skc_rcv_saddr);
            _val;
        });
    u32 daddr = (
        {
            typeof(__be32) _val;
            __builtin_memset(&_val, 0, sizeof(_val));
            bpf_probe_read(&_val, sizeof(_val), (u64)&skp->__sk_common.skc_daddr);
            _val;
        });
    u16 dport = (
        {
            typeof(__be16) _val;
            __builtin_memset(&_val, 0, sizeof(_val));
            bpf_probe_read(&_val, sizeof(_val), (u64)&skp->__sk_common.skc_dport);
            _val;
        });

    // output
    (
        {
            bpf_printk("trace_tcp4connect %x %x \n", saddr, daddr);
        });

    bpf_map_delete_elem(&tcp_map, &pid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";