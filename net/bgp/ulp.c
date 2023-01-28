// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */

#include <linux/module.h>
#include <linux/bgp.h>
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

static int bgp_validate_open(struct bgp_msg_open *bgpmsg)
{
	if (bgpmsg->version != BGP_VERSION_4)
		return -EOPNOTSUPP;

	if (bgpmsg->as == BGP_AS_TRANS)
		return -EOPNOTSUPP;

	if (bgpmsg->hold_time && bgpmsg->hold_time < 3)
		return -EINVAL;

	if (bgpmsg->opt_len)
		return -EOPNOTSUPP;

	return 0;
}

static int bgp_send_open(struct sock *sk, struct cmsghdr *cmsg, int *copied)
{
	struct bgp_context *ctx = bgp_get_ctx(sk);
	struct bgp_msg_open *bgpmsg;
	int err;

	if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct bgp_msg_open)))
		return -EINVAL;

	bgpmsg = CMSG_DATA(cmsg);
	err = bgp_validate_open(bgpmsg);
	if (err)
		return err;

	lock_sock(sk);

	if (ctx->state != BGP_CONNECT) {
		release_sock(sk);
		return -EINVAL;
	}

	release_sock(sk);

	return 0;
}

static int bgp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	int copied = 0, rc = -EINVAL;
	struct cmsghdr *cmsg;

	if (unlikely(!msg->msg_controllen))
		goto out;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			goto out;

		if (cmsg->cmsg_level != SOL_BGP)
			continue;

		switch (cmsg->cmsg_type) {
		case BGP_OPEN:
			rc = bgp_send_open(sk, cmsg, &copied);
			break;
		default:
			goto out;
		}
	}

out:
	return copied > 0 ? copied : rc;
}

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
	prot->sendmsg = bgp_sendmsg;
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
