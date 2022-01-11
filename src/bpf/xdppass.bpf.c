#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include "xdppass.h"

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
}

char __license[] SEC("license") = "GPL";
