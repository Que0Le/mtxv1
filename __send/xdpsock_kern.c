/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include "xdpsock.h"
// struct bpf_map_def SEC("maps") xsks_map = {
// 	.type = BPF_MAP_TYPE_XSKMAP,
// 	.key_size = sizeof(int),
// 	.value_size = sizeof(int),
// 	.max_entries = 64,  /* Assume netdev has no more than 64 queues */
// };

// struct bpf_map_def SEC("maps") xdp_stats_map = {
// 	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
// 	.key_size    = sizeof(int),
// 	.value_size  = sizeof(__u32),
// 	.max_entries = 64,
// };

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 4);
} xdp_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 4);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
    __u32 *pkt_count;

    pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
    if (pkt_count) {
		bpf_printk("!! pkt_count: %d, index: %d\n", pkt_count, index);
        /* We pass every other packet */
        if ((*pkt_count)++ & 1)
            return XDP_PASS;
    }

    /* A set entry here means that the correspnding queue_id
     * has an active AF_XDP socket bound to it. */
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


// SPDX-License-Identifier: GPL-2.0
// #include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>
// #include "xdpsock.h"

/* This XDP program is only needed for the XDP_SHARED_UMEM mode.
 * If you do not use this mode, libbpf can supply an XDP program for you.
 */
/* 
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_SOCKS);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

static unsigned int rr;

SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{
	rr = (rr + 1) & (MAX_SOCKS - 1);

	return bpf_redirect_map(&xsks_map, rr, XDP_DROP);
}
*/