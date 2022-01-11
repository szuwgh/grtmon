#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include "xdppass.h"
#include <linux/tcp.h>
struct forward_info
{
	uint32_t dest_ip;
	uint16_t dest_port;
};

static __always_inline int forward_packet_l4(struct forward_info *info, struct xdp_md *ctx)
{
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	// h_proto 网络层所使用的协议类型
	if (eth->h_proto != htons(ETH_P_IP))
	{
		return XDP_PASS;
	}
	//获取ip头
	struct iphdr *iph = data + sizeof(struct ethhdr);

	if (unlikely(iph + 1 > (struct iphdr *)data_end))
	{
		return XDP_DROP;
	}
	// 只支持 TCP UDP ICMP
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_ICMP)
	{
		return XDP_PASS;
	}

	if (iph->protocol == IPPROTO_TCP)
	{
		struct tcphdr *tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
		if (tcph->source != 8000)
		{
			return XDP_PASS;
		}
	}
}

char __license[] SEC("license") = "GPL";
