// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

struct headers {
	void *data;
	void *data_end;
	struct ethhdr *eth;
	struct iphdr *ipv4;
	struct ipv6hdr *ipv6;
	struct tcphdr *tcp;
};

static __always_inline int is_valid_tcp(struct xdp_md *ctx, struct headers *hdr)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = (void *)(long)ctx->data;
	struct tcphdr *tcp;

	if (eth + 1 > data_end)
		return 0;

	switch (bpf_ntohs(eth->h_proto)) {
	case ETH_P_IP: {
		struct iphdr *ip = (void *)(eth + 1);

		if (ip + 1 > data_end)
			return 0;

		if (ip->ihl * 4 < sizeof(*ip))
			return 0;

		if (ip->version != 4)
			return 0;

		if (ip->protocol != IPPROTO_TCP)
			return 0;

		tcp = (void *)ip + ip->ihl * 4;
		break;
	}
	case ETH_P_IPV6:
/*		hdr->ipv4 = NULL;

		hdr->ipv6 = (void *)hdr->eth + sizeof(*hdr->eth);
		if (hdr->ipv6 + 1 > data_end)
			return XDP_DROP;
		if (hdr->ipv6->version != 6)
			return XDP_DROP;

		if (hdr->ipv6->nexthdr != NEXTHDR_TCP)
			return XDP_PASS;

		hdr->tcp = (void *)hdr->ipv6 + sizeof(*hdr->ipv6);
		break;
*/	default:
		return XDP_PASS;
	}

	if (tcp + 1 > data_end)
		return 0;

	if (tcp->doff * 4 < sizeof(*tcp))
		return 0;

	if ((void *)tcp + tcp->doff * 4 > data_end)
		return 0;

	if (bpf_xdp_adjust_tail(ctx, 60 - tcp->doff * 4))
		return 0;

	return 1;
}

SEC("xdp")
int gen_syncookie(struct xdp_md *ctx)
{
	struct headers hdr;

	if (!is_valid_tcp(ctx, &hdr))
		return XDP_DROP;

	return XDP_PASS;
}

SEC("sockops")
int check_syncookie(struct bpf_sock_ops *skops)
{
	int ret = 1;

	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_LISTEN_CB:
		bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_CHECK_SYNCOOKIE_CB_FLAG);
		break;
	case BPF_SOCK_OPS_CHECK_SYNCOOKIE_CB:
		break;
	}

	return ret;
}

char _license[] SEC("license") = "GPL";
