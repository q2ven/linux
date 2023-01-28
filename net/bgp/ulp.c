// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */

#include <linux/module.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/transp_v6.h>

#include "bgp.h"

enum {
	BGPV4,
	BGPV6,
	BGP_NUM_PROTS,
};

static struct proto bgp_prots[BGP_NUM_PROTS];

static void bgp_close(struct sock *sk, long timeout)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct bgp_context *ctx = bgp_get_ctx(sk);

	lock_sock(sk);

	rcu_assign_pointer(icsk->icsk_ulp_data, NULL);
	WRITE_ONCE(sk->sk_prot, ctx->sk_proto);

	release_sock(sk);

	sk->sk_prot->close(sk, timeout);

	kfree(ctx);
}

struct bgp_context *bgp_ctx_create(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct bgp_context *ctx;

	ctx = kmalloc(sizeof(*ctx), GFP_ATOMIC);
	if (!ctx)
		return NULL;

	ctx->sk = sk;
	ctx->sk_proto = sk->sk_prot;
	ctx->state = BGP_CONNECT;

	switch (sk->sk_family) {
	case AF_INET:
		WRITE_ONCE(sk->sk_prot, &bgp_prots[BGPV4]);
		break;
	case AF_INET6:
		WRITE_ONCE(sk->sk_prot, &bgp_prots[BGPV6]);
		break;
	default:
		BUG();
	}

	rcu_assign_pointer(icsk->icsk_ulp_data, ctx);

	return ctx;
}

static int bgp_ulp_init(struct sock *sk)
{
	struct bgp_context *ctx;

	sock_owned_by_me(sk);

	if (sk->sk_state != TCP_ESTABLISHED)
		return -ENOTCONN;

	ctx = bgp_ctx_create(sk);
	if (!ctx)
		return -ENOMEM;

	return 0;
}

static struct tcp_ulp_ops bgp_ulp_ops __read_mostly = {
	.name		= "bgp",
	.owner		= THIS_MODULE,
	.init		= bgp_ulp_init,
};

static void __init bgp_build_prot(struct proto *prot)
{
	prot->close = bgp_close;
}

static void __init bgp_build_prots(void)
{
	bgp_prots[BGPV4] = tcp_prot;
	bgp_prots[BGPV6] = tcpv6_prot;

	bgp_build_prot(&bgp_prots[BGPV4]);
	bgp_build_prot(&bgp_prots[BGPV6]);
}

static int __init bgp_init(void)
{
	bgp_build_prots();

	tcp_register_ulp(&bgp_ulp_ops);

	return 0;
}

static void __exit bgp_exit(void)
{
	tcp_unregister_ulp(&bgp_ulp_ops);
}

module_init(bgp_init);
module_exit(bgp_exit);

MODULE_AUTHOR("Kuniyuki Iwashima");
MODULE_DESCRIPTION("Border Gateway Protocol");
MODULE_LICENSE("GPL");
MODULE_ALIAS_TCP_ULP("bgp");
