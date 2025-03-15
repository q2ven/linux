// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  net/dccp/minisocks.c
 *
 *  An implementation of the DCCP protocol
 *  Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 */

#include <linux/dccp.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/timer.h>

#include <net/sock.h>
#include <net/xfrm.h>
#include <net/inet_timewait_sock.h>
#include <net/rstreason.h>

#include "dccp.h"

struct inet_timewait_death_row dccp_death_row = {
	.tw_refcount = REFCOUNT_INIT(1),
	.sysctl_max_tw_buckets = NR_FILE * 2,
	.hashinfo	= &dccp_hashinfo,
};

EXPORT_SYMBOL_GPL(dccp_death_row);

void dccp_time_wait(struct sock *sk, int state, int timeo)
{
	struct inet_timewait_sock *tw;

	tw = inet_twsk_alloc(sk, &dccp_death_row, state);

	if (tw != NULL) {
		const struct inet_connection_sock *icsk = inet_csk(sk);
		const int rto = (icsk->icsk_rto << 2) - (icsk->icsk_rto >> 1);
#if IS_ENABLED(CONFIG_IPV6)
		if (tw->tw_family == PF_INET6) {
			tw->tw_v6_daddr = sk->sk_v6_daddr;
			tw->tw_v6_rcv_saddr = sk->sk_v6_rcv_saddr;
			tw->tw_ipv6only = sk->sk_ipv6only;
		}
#endif

		/* Get the TIME_WAIT timeout firing. */
		if (timeo < rto)
			timeo = rto;

		if (state == DCCP_TIME_WAIT)
			timeo = DCCP_TIMEWAIT_LEN;

		/* Linkage updates.
		 * Note that access to tw after this point is illegal.
		 */
		inet_twsk_hashdance_schedule(tw, sk, &dccp_hashinfo, timeo);
	} else {
		/* Sorry, if we're out of memory, just CLOSE this
		 * socket up.  We've got bigger problems than
		 * non-graceful socket closings.
		 */
		DCCP_WARN("time wait bucket table overflow\n");
	}

	dccp_done(sk);
}

struct sock *dccp_create_openreq_child(const struct sock *sk,
				       const struct request_sock *req,
				       const struct sk_buff *skb)
{
	return NULL;
}

EXPORT_SYMBOL_GPL(dccp_create_openreq_child);

/*
 * Process an incoming packet for RESPOND sockets represented
 * as an request_sock.
 */
struct sock *dccp_check_req(struct sock *sk, struct sk_buff *skb,
			    struct request_sock *req)
{
	struct sock *child = NULL;
	struct dccp_request_sock *dreq = dccp_rsk(req);
	bool own_req;

	/* TCP/DCCP listeners became lockless.
	 * DCCP stores complex state in its request_sock, so we need
	 * a protection for them, now this code runs without being protected
	 * by the parent (listener) lock.
	 */
	spin_lock_bh(&dreq->dreq_lock);

	/* Check for retransmitted REQUEST */
	if (dccp_hdr(skb)->dccph_type == DCCP_PKT_REQUEST) {

		if (after48(DCCP_SKB_CB(skb)->dccpd_seq, dreq->dreq_gsr)) {
			dccp_pr_debug("Retransmitted REQUEST\n");
			dreq->dreq_gsr = DCCP_SKB_CB(skb)->dccpd_seq;
			/*
			 * Send another RESPONSE packet
			 * To protect against Request floods, increment retrans
			 * counter (backoff, monitored by dccp_response_timer).
			 */
			inet_rtx_syn_ack(sk, req);
		}
		/* Network Duplicate, discard packet */
		goto out;
	}

	DCCP_SKB_CB(skb)->dccpd_reset_code = DCCP_RESET_CODE_PACKET_ERROR;

	if (dccp_hdr(skb)->dccph_type != DCCP_PKT_ACK &&
	    dccp_hdr(skb)->dccph_type != DCCP_PKT_DATAACK)
		goto drop;

	/* Invalid ACK */
	if (!between48(DCCP_SKB_CB(skb)->dccpd_ack_seq,
				dreq->dreq_iss, dreq->dreq_gss)) {
		dccp_pr_debug("Invalid ACK number: ack_seq=%llu, "
			      "dreq_iss=%llu, dreq_gss=%llu\n",
			      (unsigned long long)
			      DCCP_SKB_CB(skb)->dccpd_ack_seq,
			      (unsigned long long) dreq->dreq_iss,
			      (unsigned long long) dreq->dreq_gss);
		goto drop;
	}

	if (dccp_parse_options(sk, dreq, skb))
		 goto drop;

	child = inet_csk(sk)->icsk_af_ops->syn_recv_sock(sk, skb, req, NULL,
							 req, &own_req);
	if (child) {
		child = inet_csk_complete_hashdance(sk, child, req, own_req);
		goto out;
	}

	DCCP_SKB_CB(skb)->dccpd_reset_code = DCCP_RESET_CODE_TOO_BUSY;
drop:
	if (dccp_hdr(skb)->dccph_type != DCCP_PKT_RESET)
		req->rsk_ops->send_reset(sk, skb, SK_RST_REASON_NOT_SPECIFIED);

	inet_csk_reqsk_queue_drop(sk, req);
out:
	spin_unlock_bh(&dreq->dreq_lock);
	return child;
}

EXPORT_SYMBOL_GPL(dccp_check_req);

/*
 *  Queue segment on the new socket if the new socket is active,
 *  otherwise we just shortcircuit this and continue with
 *  the new socket.
 */
int dccp_child_process(struct sock *parent, struct sock *child,
		       struct sk_buff *skb)
	__releases(child)
{
	int ret = 0;
	const int state = child->sk_state;

	if (!sock_owned_by_user(child)) {
		ret = dccp_rcv_state_process(child, skb, dccp_hdr(skb),
					     skb->len);

		/* Wakeup parent, send SIGIO */
		if (state == DCCP_RESPOND && child->sk_state != state)
			parent->sk_data_ready(parent);
	} else {
		/* Alas, it is possible again, because we do lookup
		 * in main socket hash table and lock on listening
		 * socket does not protect us more.
		 */
		__sk_add_backlog(child, skb);
	}

	bh_unlock_sock(child);
	sock_put(child);
	return ret;
}

EXPORT_SYMBOL_GPL(dccp_child_process);

void dccp_reqsk_send_ack(const struct sock *sk, struct sk_buff *skb,
			 struct request_sock *rsk)
{
	DCCP_BUG("DCCP-ACK packets are never sent in LISTEN/RESPOND state");
}

EXPORT_SYMBOL_GPL(dccp_reqsk_send_ack);

int dccp_reqsk_init(struct request_sock *req,
		    struct dccp_sock const *dp, struct sk_buff const *skb)
{
	return -ENOMEM;
}

EXPORT_SYMBOL_GPL(dccp_reqsk_init);
