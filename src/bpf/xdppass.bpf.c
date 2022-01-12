#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include "xdppass.h"
#include <linux/tcp.h>
#include "csum.h"

#define MAXRULES 256
#define MAXCONNECTIONS 1000000

#define MINPORT 500
#define MAXPORT 520

struct conn_key
{
	uint32_t clientaddr;
	uint16_t clientport;
	uint32_t bindaddr;
	uint16_t bindport;
	uint8_t protocol;
};

struct port_key
{
	uint32_t bindaddr;
	uint32_t destaddr;
	uint16_t port;
};

struct forward_info
{
	uint32_t destaddr;
	uint16_t destport;
};

//链接跟踪
struct connection
{
	uint32_t clientaddr;
	uint16_t clientport;
	uint16_t bindport;
	uint16_t port;
	uint64_t firstseen;
	uint64_t lastseen;
	uint64_t count;
};

struct bpf_map_def SEC("maps") tcp_map =
	{
		.type = BPF_MAP_TYPE_LRU_HASH,
		.key_size = sizeof(struct port_key),
		.value_size = sizeof(struct connection),
		.max_entries = (MAXRULES * (MAXPORT - (MINPORT - 1)))};

struct bpf_map_def SEC("maps") connection_map =
	{
		.type = BPF_MAP_TYPE_LRU_HASH,
		.key_size = sizeof(struct conn_key),
		.value_size = sizeof(uint16_t),
		.max_entries = MAXCONNECTIONS};

static __always_inline void swapeth(struct ethhdr *eth)
{
	uint8_t tmp[ETH_ALEN];

	memcpy(&tmp, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, &tmp, ETH_ALEN);
}

static __always_inline int forwardpacket4(struct forward_info *info, struct connection *conn, struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;

	if (eth + 1 > (struct ethhdr *)data_end)
	{
		return XDP_DROP;
	}

	swapeth(eth);

	struct iphdr *iph = data + sizeof(struct ethhdr);

	if (iph + 1 > (struct iphdr *)data_end)
	{
		return XDP_DROP;
	}

	struct tcphdr *tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);
	if (tcph + 1 > (struct tcphdr *)data_end)
	{
		return XDP_DROP;
	}

	uint16_t oldsrcport = tcph->source;
	uint16_t olddestport = tcph->dest;

	uint32_t olddestaddr = iph->daddr;
	uint32_t oldsrcaddr = iph->saddr;

	//iph->daddr = info->destaddr;
	//638390956; // inet_aton("172.18.13.38"); //in_aton("172.18.13.38"); //2886864166; //172.18.13.38

	if (info)
	{
		iph->saddr = iph->daddr;
		tcph->source = conn->port;
		tcph->dest = info->destport;
		iph->daddr = info->destaddr;
	}
	else
	{
		tcph->source = conn->bindport;
		tcph->dest = conn->clientport;
	}

	//tcph->source = htons(8009);
	//tcph->dest = info->destport; //htons(8001);

	tcph->check = csum_diff4(olddestaddr, iph->daddr, tcph->check);
	tcph->check = csum_diff4(oldsrcaddr, iph->saddr, tcph->check);

	tcph->check = csum_diff4(oldsrcport, tcph->source, tcph->check);
	tcph->check = csum_diff4(olddestport, tcph->dest, tcph->check);

	update_iph_checksum(iph);
	return XDP_TX;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	int pkt_sz = data_end - data;
	if (eth + 1 > (struct ethhdr *)data_end)
	{
		return XDP_DROP;
	}

	// h_proto 网络层所使用的协议类型
	if (eth->h_proto != htons(ETH_P_IP))
	{
		return XDP_PASS;
	}
	//获取ip头
	struct iphdr *iph = data + sizeof(struct ethhdr);

	if (iph + 1 > (struct iphdr *)data_end)
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
		if (tcph + 1 > (struct tcphdr *)data_end)
		{
			return XDP_DROP;
		}
		if (tcph->dest != htons(22) && tcph->dest != htons(47152))
		{
			bpf_printk("packet saddr: %u, daddr:%u, port:  %u", iph->saddr, iph->daddr, htons(tcph->dest));
		}

		//bpf_printk("packet port: %d", tcph->dest);
		if (tcph->dest != htons(8000))
		{
			//reply:
			struct port_key pkey = {0};
			pkey.bindaddr = iph->daddr;
			pkey.destaddr = iph->saddr;
			pkey.port = tcph->dest;

			// Find out what the client IP is.
			struct connection *conn = bpf_map_lookup_elem(&tcp_map, &pkey);
			if (conn)
			{
				return forwardpacket4(NULL, conn, ctx);
			}
			return XDP_PASS;
		}
		struct forward_info fwdinfo = {0};
		fwdinfo.destaddr = 2185472192; //638390956;
		fwdinfo.destport = htons(8001);

		struct conn_key connkey = {0};

		connkey.clientaddr = iph->saddr;   //客户端ip地址
		connkey.clientport = tcph->source; //客户端端口
		connkey.bindaddr = iph->daddr;	   // 192.168.255.130
		connkey.bindport = tcph->dest;	   //8000
		connkey.protocol = iph->protocol;

		uint16_t *connport = bpf_map_lookup_elem(&connection_map, &connkey);
		//已存在连接
		if (connport)
		{

			struct port_key pkey = {0};
			pkey.bindaddr = iph->daddr;		  // 192.168.255.130
			pkey.destaddr = fwdinfo.destaddr; // 172.18.13.38
			pkey.port = *connport;

			struct connection *conn = bpf_map_lookup_elem(&tcp_map, &pkey);
			if (conn)
			{
				conn->count++;

				if (conn->clientport == connkey.clientport)
				{
					return forwardpacket4(&fwdinfo, conn, ctx);
				}
				else
				{
					bpf_map_delete_elem(&tcp_map, &pkey);
				}
			}
		}
		else
		{
			struct conn_key nconnkey = {0};
			nconnkey.clientaddr = iph->saddr;
			nconnkey.clientport = connkey.clientport;
			nconnkey.bindaddr = iph->daddr;
			nconnkey.bindport = tcph->dest;
			nconnkey.protocol = iph->protocol;

			uint16_t port = htons(8009);

			bpf_map_update_elem(&connection_map, &nconnkey, &port, BPF_ANY);

			struct port_key npkey = {0};
			npkey.bindaddr = iph->daddr;	   // 192.168.255.130
			npkey.destaddr = fwdinfo.destaddr; // 172.18.13.38
			npkey.port = port;

			struct connection newconn = {0};
			newconn.clientaddr = iph->saddr;
			newconn.clientport = connkey.clientport;
			//newconn.firstseen = now;
			//newconn.lastseen = now;
			newconn.count = 1;
			newconn.bindport = tcph->dest;
			newconn.port = port;

			bpf_map_update_elem(&tcp_map, &npkey, &newconn, BPF_ANY);

			return forwardpacket4(&fwdinfo, &newconn, ctx);
		}
	}
	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
