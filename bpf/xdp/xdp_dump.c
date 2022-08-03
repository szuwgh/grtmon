#include "common.h"

SEC("xdp")
int xdp_dump(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 packet_size = data_end - data;

    // L2
    struct ethhdr *ether = data;
    if (data + sizeof(*ether) > data_end)
    {
        return XDP_ABORTED;
    }
    return 0;
}