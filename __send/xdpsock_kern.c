// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "xdpsock.h"

/* This XDP program is only needed for the XDP_SHARED_UMEM mode.
 * If you do not use this mode, libbpf can supply an XDP program for you.
 */

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 3 /* MAX_SOCKS */);		// TODO: investigate this value
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

// static unsigned int rr;

SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{
	// rr = (rr + 1) & (MAX_SOCKS - 1);
	// bpf_printk("index: %d queue: %d rr: %d", ctx->ingress_ifindex, ctx->rx_queue_index, rr);
	int key = 0;
	if (ctx->ingress_ifindex == 3) {		// enp2s0
		key = 0;
	} else if (ctx->ingress_ifindex == 4) {	// enp5s0
		key = 1;
	} else if (ctx->ingress_ifindex == 5) {	// enp7s0
		key = 2;
	}
	return bpf_redirect_map(&xsks_map, key, XDP_PASS);
}


char _license[] SEC("license") = "GPL";


