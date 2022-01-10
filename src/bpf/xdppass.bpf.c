#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <arpa/inet.h>
SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	// // h_proto 网络层所使用的协议类型
	if (eth->h_proto != htons(ETH_P_IP))
	{
		return XDP_PASS;
	}
	// if (unlikely(eth + 1 > (struct ethhdr *)data_end))
	// {
	// 	return XDP_DROP;
	// }
	// int pkt_sz = data_end - data;

	// bpf_printk("packet size: %d", pkt_sz);
	// return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
