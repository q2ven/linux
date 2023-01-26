// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */

#include <linux/module.h>
#include <net/sock.h>
#include <net/tcp.h>

static int bgp_ulp_init(struct sock *sk)
{
	sock_owned_by_me(sk);

	if (sk->sk_state != TCP_ESTABLISHED)
		return -ENOTCONN;

	return 0;
}

static struct tcp_ulp_ops bgp_ulp_ops __read_mostly = {
	.name		= "bgp",
	.owner		= THIS_MODULE,
	.init		= bgp_ulp_init,
};

static int __init bgp_init(void)
{
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
