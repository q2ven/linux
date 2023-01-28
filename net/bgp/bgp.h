/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright Amazon.com Inc. or its affiliates. */

#include <net/sock.h>
#include <net/inet_connection_sock.h>

enum bgp_state {
	BGP_IDLE,
	BGP_CONNECT,
	BGP_ACTIVE,
	BGP_OPEN_SENT,
	BGP_OPEN_CONFIRM,
	BGP_ESTABLISHED,
};

struct bgp_context {
	struct sock *sk;
	struct proto *sk_proto;
	unsigned char state;
};

struct bgp_context *bgp_get_ctx(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	return (__force struct bgp_context *)icsk->icsk_ulp_data;
}
