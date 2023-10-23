// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_kfuncs.h"

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define TCPOPT_NOP 1
#define TCPOPT_EOL 0
#define TCPOPT_MSS 2
#define TCPOPT_WINDOW 3
#define TCPOPT_SACK_PERM 4
#define TCPOPT_TIMESTAMP 8

struct header {
	struct ethhdr *eth;
	struct iphdr *ipv4;
	struct tcphdr *tcp;
};

static __always_inline int is_tcp(struct __sk_buff * skb, struct header *hdr)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	hdr->eth = data;
	if (hdr->eth + 1 > data_end)
		return 0;

	switch (bpf_ntohs(hdr->eth->h_proto)) {
	case ETH_P_IP: {
		hdr->ipv4 = (struct iphdr *)(hdr->eth + 1);
		if (hdr->ipv4 + 1 > data_end)
			return 0;

		if (hdr->ipv4->ihl != sizeof(*hdr->ipv4) / 4)
			return 0;

		if (hdr->ipv4->version != 4)
			return 0;

		if (hdr->ipv4->protocol != IPPROTO_TCP)
			return 0;

		hdr->tcp = (void *)hdr->ipv4 + hdr->ipv4->ihl * 4;
		break;
	}
	default:
		return 0;
	}

	if (hdr->tcp + 1 > data_end)
		return 0;

	return 1;
}

static __always_inline __u16 csum_fold(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);

	return (__u16)~csum;
}

static __always_inline u16 csum_tcp(struct header *hdr, __u64 csum)
{
	__u32 len = hdr->tcp->doff * 4;
	__u8 proto = IPPROTO_TCP;

	csum += (__u32)hdr->ipv4->saddr;
	csum += (__u32)hdr->ipv4->daddr;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	csum += proto + len;
#else
	csum += (proto + len) << 8;
#endif
	csum = (csum >> 32) + (csum & 0xffffffff);
	csum = (csum >> 32) + (csum & 0xffffffff);

	return csum_fold(csum);
}

static __always_inline int is_valid_syn(struct __sk_buff *skb, struct header *hdr)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	volatile u64 data_len;
	s64 csum;

	data_len = data_end - data;
	if (bpf_skb_change_tail(skb, data_len + 60 - hdr->tcp->doff * 4, 0))
		return 0;

	data_end = (void *)(long)skb->data_end;
	data = (void *)(long)skb->data;
	hdr->eth = data;
	hdr->ipv4 = (void *)(hdr->eth + 1);

	if ((void *)hdr->ipv4 + 60 > data_end)
		return 0;

	csum = bpf_csum_diff(0, 0, (void *)hdr->ipv4, hdr->ipv4->ihl * 4, 0);
	if (csum < 0)
		return 0;

	if (csum_fold(csum) != 0)
		return 0;

	hdr->tcp = (void*)hdr->ipv4 + hdr->ipv4->ihl * 4;
	if (hdr->tcp + 1 > data_end)
		return 0;

	if (hdr->tcp->doff < sizeof(*hdr->tcp) / 4)
		return 0;

	if ((void *)hdr->tcp + 60 > data_end)
		return 0;

	csum = bpf_csum_diff(0, 0, (void *)hdr->tcp, hdr->tcp->doff * 4, 0);
	if (csum < 0)
		return 0;

	/* checksum is on lo */
	bpf_printk("%d csum: %u", csum_tcp(hdr, csum));

	return 1;
}

#define swap(a, b)				\
	do {					\
		typeof(a) __tmp = (a);		\
		(a) = (b);			\
		(b) = __tmp;			\
	} while (0)

static __always_inline int gen_syncookie(struct __sk_buff *skb, struct header *hdr)
{
	u8 eth_tmp[ETH_ALEN];
	s64 csum;

	if (!is_valid_syn(skb, hdr))
		return TC_ACT_SHOT;

	__builtin_memcpy(eth_tmp, hdr->eth->h_source, ETH_ALEN);
	__builtin_memcpy(hdr->eth->h_source, hdr->eth->h_dest, ETH_ALEN);
	__builtin_memcpy(hdr->eth->h_dest, eth_tmp, ETH_ALEN);

	swap(hdr->ipv4->saddr, hdr->ipv4->daddr);
	swap(hdr->tcp->source, hdr->tcp->dest);

	hdr->ipv4->check = 0;
	hdr->ipv4->tos = 0;
	hdr->ipv4->id = 0;
	hdr->ipv4->ttl = 64;

	hdr->tcp->check = 0;
	hdr->tcp->ack_seq = bpf_htonl(bpf_ntohl(hdr->tcp->seq) + 1);
	hdr->tcp->seq = bpf_htonl(92);
	hdr->tcp->ack = 1;
	hdr->tcp->ece = 1;
	hdr->tcp->cwr = 0;

	csum = bpf_csum_diff(0, 0, (void *)hdr->tcp, hdr->tcp->doff * 4, 0);
	if (csum < 0)
		return TC_ACT_SHOT;

	hdr->tcp->check = csum_tcp(hdr, csum);

	csum = bpf_csum_diff(0, 0, (void *)hdr->ipv4, sizeof(*hdr->ipv4), 0);
	if (csum < 0)
		return TC_ACT_SHOT;

	hdr->ipv4->check = csum_fold(csum);

	return bpf_redirect(skb->ifindex, 0);
}

static __always_inline int check_syncookie(struct __sk_buff *skb, struct header *hdr)
{
	struct tcp_options_received tcp_opt = {
		.saw_tstamp = 1,
		.rcv_tsval = 10,
		.snd_wscale = 8,
		.sack_ok = 1,
		.wscale_ok = 1,
		.rcv_tsecr = 1
	};
	struct bpf_sock_tuple tuple = {
		.ipv4.saddr = hdr->ipv4->saddr,
		.ipv4.daddr = hdr->ipv4->daddr,
		.ipv4.sport = hdr->tcp->source,
		.ipv4.dport = hdr->tcp->dest,
	};
	struct bpf_sock *skc;
	struct tcp_sock *tp;
	int ret;

	skc = bpf_skc_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
	if (!skc)
		return TC_ACT_OK;

	if (skc->state != TCP_LISTEN)
		goto release;

	tp = bpf_skc_to_tcp_sock(skc);
	if (!tp)
		goto release;

	ret = bpf_sk_assign_tcp_reqsk(skb, (struct sock *)tp,
				      &tcp_opt, sizeof(tcp_opt), 1450);
	if (ret < 0)
		goto release;
	/* Call kfunc. */

release:
	bpf_sk_release(skc);

	return TC_ACT_OK;
}

SEC("tc")
int syncookie(struct __sk_buff *skb)
{
	struct header hdr;

	if (!is_tcp(skb, &hdr))
		return TC_ACT_OK;

	if (hdr.tcp->syn) {
		if (hdr.tcp->ack)
			return TC_ACT_OK;

		return gen_syncookie(skb, &hdr);
	}

	return check_syncookie(skb, &hdr);
}

char _license[] SEC("license") = "GPL";
