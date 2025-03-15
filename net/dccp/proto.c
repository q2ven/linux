// SPDX-License-Identifier: GPL-2.0-only
/*
 *  net/dccp/proto.c
 *
 *  An implementation of the DCCP protocol
 *  Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 */

#include <linux/dccp.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <net/checksum.h>

#include <net/inet_sock.h>
#include <net/inet_common.h>
#include <net/sock.h>
#include <net/xfrm.h>

#include <asm/ioctls.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/poll.h>

#include "dccp.h"

#define CREATE_TRACE_POINTS
#include "trace.h"

DEFINE_SNMP_STAT(struct dccp_mib, dccp_statistics) __read_mostly;

EXPORT_SYMBOL_GPL(dccp_statistics);

DEFINE_PER_CPU(unsigned int, dccp_orphan_count);
EXPORT_PER_CPU_SYMBOL_GPL(dccp_orphan_count);

struct inet_hashinfo dccp_hashinfo;
EXPORT_SYMBOL_GPL(dccp_hashinfo);

/* the maximum queue length for tx in packets. 0 is no limit */
int sysctl_dccp_tx_qlen __read_mostly = 5;

#ifdef CONFIG_IP_DCCP_DEBUG
static const char *dccp_state_name(const int state)
{
	static const char *const dccp_state_names[] = {
	[DCCP_OPEN]		= "OPEN",
	[DCCP_REQUESTING]	= "REQUESTING",
	[DCCP_PARTOPEN]		= "PARTOPEN",
	[DCCP_LISTEN]		= "LISTEN",
	[DCCP_RESPOND]		= "RESPOND",
	[DCCP_CLOSING]		= "CLOSING",
	[DCCP_ACTIVE_CLOSEREQ]	= "CLOSEREQ",
	[DCCP_PASSIVE_CLOSE]	= "PASSIVE_CLOSE",
	[DCCP_PASSIVE_CLOSEREQ]	= "PASSIVE_CLOSEREQ",
	[DCCP_TIME_WAIT]	= "TIME_WAIT",
	[DCCP_CLOSED]		= "CLOSED",
	};

	if (state >= DCCP_MAX_STATES)
		return "INVALID STATE!";
	else
		return dccp_state_names[state];
}
#endif

void dccp_set_state(struct sock *sk, const int state)
{
	const int oldstate = sk->sk_state;

	dccp_pr_debug("%s(%p)  %s  -->  %s\n", dccp_role(sk), sk,
		      dccp_state_name(oldstate), dccp_state_name(state));
	WARN_ON(state == oldstate);

	switch (state) {
	case DCCP_OPEN:
		if (oldstate != DCCP_OPEN)
			DCCP_INC_STATS(DCCP_MIB_CURRESTAB);
		break;

	case DCCP_CLOSED:
		if (oldstate == DCCP_OPEN || oldstate == DCCP_ACTIVE_CLOSEREQ ||
		    oldstate == DCCP_CLOSING)
			DCCP_INC_STATS(DCCP_MIB_ESTABRESETS);

		sk->sk_prot->unhash(sk);
		if (inet_csk(sk)->icsk_bind_hash != NULL &&
		    !(sk->sk_userlocks & SOCK_BINDPORT_LOCK))
			inet_put_port(sk);
		fallthrough;
	default:
		if (oldstate == DCCP_OPEN)
			DCCP_DEC_STATS(DCCP_MIB_CURRESTAB);
	}

	/* Change state AFTER socket is unhashed to avoid closed
	 * socket sitting in hash tables.
	 */
	inet_sk_set_state(sk, state);
}

EXPORT_SYMBOL_GPL(dccp_set_state);

static void dccp_finish_passive_close(struct sock *sk)
{
	switch (sk->sk_state) {
	case DCCP_PASSIVE_CLOSE:
		/* Node (client or server) has received Close packet. */
		dccp_send_reset(sk, DCCP_RESET_CODE_CLOSED);
		dccp_set_state(sk, DCCP_CLOSED);
		break;
	case DCCP_PASSIVE_CLOSEREQ:
		/*
		 * Client received CloseReq. We set the `active' flag so that
		 * dccp_send_close() retransmits the Close as per RFC 4340, 8.3.
		 */
		dccp_send_close(sk, 1);
		dccp_set_state(sk, DCCP_CLOSING);
	}
}

void dccp_done(struct sock *sk)
{
	dccp_set_state(sk, DCCP_CLOSED);
	dccp_clear_xmit_timers(sk);

	sk->sk_shutdown = SHUTDOWN_MASK;

	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk);
	else
		inet_csk_destroy_sock(sk);
}

EXPORT_SYMBOL_GPL(dccp_done);

const char *dccp_packet_name(const int type)
{
	static const char *const dccp_packet_names[] = {
		[DCCP_PKT_REQUEST]  = "REQUEST",
		[DCCP_PKT_RESPONSE] = "RESPONSE",
		[DCCP_PKT_DATA]	    = "DATA",
		[DCCP_PKT_ACK]	    = "ACK",
		[DCCP_PKT_DATAACK]  = "DATAACK",
		[DCCP_PKT_CLOSEREQ] = "CLOSEREQ",
		[DCCP_PKT_CLOSE]    = "CLOSE",
		[DCCP_PKT_RESET]    = "RESET",
		[DCCP_PKT_SYNC]	    = "SYNC",
		[DCCP_PKT_SYNCACK]  = "SYNCACK",
	};

	if (type >= DCCP_NR_PKT_TYPES)
		return "INVALID";
	else
		return dccp_packet_names[type];
}

EXPORT_SYMBOL_GPL(dccp_packet_name);

static int dccp_msghdr_parse(struct msghdr *msg, struct sk_buff *skb)
{
	struct cmsghdr *cmsg;

	/*
	 * Assign an (opaque) qpolicy priority value to skb->priority.
	 *
	 * We are overloading this skb field for use with the qpolicy subystem.
	 * The skb->priority is normally used for the SO_PRIORITY option, which
	 * is initialised from sk_priority. Since the assignment of sk_priority
	 * to skb->priority happens later (on layer 3), we overload this field
	 * for use with queueing priorities as long as the skb is on layer 4.
	 * The default priority value (if nothing is set) is 0.
	 */
	skb->priority = 0;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level != SOL_DCCP)
			continue;

		return -EINVAL;
	}
	return 0;
}

int dccp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	const struct dccp_sock *dp = dccp_sk(sk);
	const int flags = msg->msg_flags;
	const int noblock = flags & MSG_DONTWAIT;
	struct sk_buff *skb;
	int rc, size;
	long timeo;

	trace_dccp_probe(sk, len);

	if (len > READ_ONCE(dp->dccps_mss_cache))
		return -EMSGSIZE;

	lock_sock(sk);

	timeo = sock_sndtimeo(sk, noblock);

	/*
	 * We have to use sk_stream_wait_connect here to set sk_write_pending,
	 * so that the trick in dccp_rcv_request_sent_state_process.
	 */
	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(DCCPF_OPEN | DCCPF_PARTOPEN))
		if ((rc = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_release;

	size = sk->sk_prot->max_header + len;
	release_sock(sk);
	skb = sock_alloc_send_skb(sk, size, noblock, &rc);
	lock_sock(sk);
	if (skb == NULL)
		goto out_release;

	if (sk->sk_state == DCCP_CLOSED) {
		rc = -ENOTCONN;
		goto out_discard;
	}

	/* We need to check dccps_mss_cache after socket is locked. */
	if (len > dp->dccps_mss_cache) {
		rc = -EMSGSIZE;
		goto out_discard;
	}

	skb_reserve(skb, sk->sk_prot->max_header);
	rc = memcpy_from_msg(skb_put(skb, len), msg, len);
	if (rc != 0)
		goto out_discard;

	rc = dccp_msghdr_parse(msg, skb);
	if (rc != 0)
		goto out_discard;

	skb_queue_tail(&sk->sk_write_queue, skb);

	/*
	 * The xmit_timer is set if the TX CCID is rate-based and will expire
	 * when congestion control permits to release further packets into the
	 * network. Window-based CCIDs do not use this timer.
	 */
	if (!timer_pending(&dp->dccps_xmit_timer))
		dccp_write_xmit(sk);
out_release:
	release_sock(sk);
	return rc ? : len;
out_discard:
	kfree_skb(skb);
	goto out_release;
}

EXPORT_SYMBOL_GPL(dccp_sendmsg);

int dccp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags,
		 int *addr_len)
{
	const struct dccp_hdr *dh;
	long timeo;

	lock_sock(sk);

	if (sk->sk_state == DCCP_LISTEN) {
		len = -ENOTCONN;
		goto out;
	}

	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

	do {
		struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);

		if (skb == NULL)
			goto verify_sock_status;

		dh = dccp_hdr(skb);

		switch (dh->dccph_type) {
		case DCCP_PKT_DATA:
		case DCCP_PKT_DATAACK:
			goto found_ok_skb;

		case DCCP_PKT_CLOSE:
		case DCCP_PKT_CLOSEREQ:
			if (!(flags & MSG_PEEK))
				dccp_finish_passive_close(sk);
			fallthrough;
		case DCCP_PKT_RESET:
			dccp_pr_debug("found fin (%s) ok!\n",
				      dccp_packet_name(dh->dccph_type));
			len = 0;
			goto found_fin_ok;
		default:
			dccp_pr_debug("packet_type=%s\n",
				      dccp_packet_name(dh->dccph_type));
			sk_eat_skb(sk, skb);
		}
verify_sock_status:
		if (sock_flag(sk, SOCK_DONE)) {
			len = 0;
			break;
		}

		if (sk->sk_err) {
			len = sock_error(sk);
			break;
		}

		if (sk->sk_shutdown & RCV_SHUTDOWN) {
			len = 0;
			break;
		}

		if (sk->sk_state == DCCP_CLOSED) {
			if (!sock_flag(sk, SOCK_DONE)) {
				/* This occurs when user tries to read
				 * from never connected socket.
				 */
				len = -ENOTCONN;
				break;
			}
			len = 0;
			break;
		}

		if (!timeo) {
			len = -EAGAIN;
			break;
		}

		if (signal_pending(current)) {
			len = sock_intr_errno(timeo);
			break;
		}

		sk_wait_data(sk, &timeo, NULL);
		continue;
	found_ok_skb:
		if (len > skb->len)
			len = skb->len;
		else if (len < skb->len)
			msg->msg_flags |= MSG_TRUNC;

		if (skb_copy_datagram_msg(skb, 0, msg, len)) {
			/* Exception. Bailout! */
			len = -EFAULT;
			break;
		}
		if (flags & MSG_TRUNC)
			len = skb->len;
	found_fin_ok:
		if (!(flags & MSG_PEEK))
			sk_eat_skb(sk, skb);
		break;
	} while (1);
out:
	release_sock(sk);
	return len;
}

EXPORT_SYMBOL_GPL(dccp_recvmsg);

static void dccp_terminate_connection(struct sock *sk)
{
	u8 next_state = DCCP_CLOSED;

	switch (sk->sk_state) {
	case DCCP_PASSIVE_CLOSE:
	case DCCP_PASSIVE_CLOSEREQ:
		dccp_finish_passive_close(sk);
		break;
	case DCCP_PARTOPEN:
		dccp_pr_debug("Stop PARTOPEN timer (%p)\n", sk);
		inet_csk_clear_xmit_timer(sk, ICSK_TIME_DACK);
		fallthrough;
	case DCCP_OPEN:
		dccp_send_close(sk, 1);

		if (dccp_sk(sk)->dccps_role == DCCP_ROLE_SERVER &&
		    !dccp_sk(sk)->dccps_server_timewait)
			next_state = DCCP_ACTIVE_CLOSEREQ;
		else
			next_state = DCCP_CLOSING;
		fallthrough;
	default:
		dccp_set_state(sk, next_state);
	}
}

void dccp_close(struct sock *sk, long timeout)
{
	struct dccp_sock *dp = dccp_sk(sk);
	struct sk_buff *skb;
	u32 data_was_unread = 0;
	int state;

	lock_sock(sk);

	sk->sk_shutdown = SHUTDOWN_MASK;

	if (sk->sk_state == DCCP_LISTEN) {
		dccp_set_state(sk, DCCP_CLOSED);

		/* Special case. */
		inet_csk_listen_stop(sk);

		goto adjudge_to_death;
	}

	sk_stop_timer(sk, &dp->dccps_xmit_timer);

	/*
	 * We need to flush the recv. buffs.  We do this only on the
	 * descriptor close, not protocol-sourced closes, because the
	  *reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		data_was_unread += skb->len;
		__kfree_skb(skb);
	}

	/* If socket has been already reset kill it. */
	if (sk->sk_state == DCCP_CLOSED)
		goto adjudge_to_death;

	if (data_was_unread) {
		/* Unread data was tossed, send an appropriate Reset Code */
		DCCP_WARN("ABORT with %u bytes unread\n", data_was_unread);
		dccp_send_reset(sk, DCCP_RESET_CODE_ABORTED);
		dccp_set_state(sk, DCCP_CLOSED);
	} else if (sock_flag(sk, SOCK_LINGER) && !sk->sk_lingertime) {
		/* Check zero linger _after_ checking for unread data. */
		sk->sk_prot->disconnect(sk, 0);
	} else if (sk->sk_state != DCCP_CLOSED) {
		/*
		 * Normal connection termination. May need to wait if there are
		 * still packets in the TX queue that are delayed by the CCID.
		 */
		dccp_flush_write_queue(sk, &timeout);
		dccp_terminate_connection(sk);
	}

	/*
	 * Flush write queue. This may be necessary in several cases:
	 * - we have been closed by the peer but still have application data;
	 * - abortive termination (unread data or zero linger time),
	 * - normal termination but queue could not be flushed within time limit
	 */
	__skb_queue_purge(&sk->sk_write_queue);

	sk_stream_wait_close(sk, timeout);

adjudge_to_death:
	state = sk->sk_state;
	sock_hold(sk);
	sock_orphan(sk);

	/*
	 * It is the last release_sock in its life. It will remove backlog.
	 */
	release_sock(sk);
	/*
	 * Now socket is owned by kernel and we acquire BH lock
	 * to finish close. No need to check for user refs.
	 */
	local_bh_disable();
	bh_lock_sock(sk);
	WARN_ON(sock_owned_by_user(sk));

	this_cpu_inc(dccp_orphan_count);

	/* Have we already been destroyed by a softirq or backlog? */
	if (state != DCCP_CLOSED && sk->sk_state == DCCP_CLOSED)
		goto out;

	if (sk->sk_state == DCCP_CLOSED)
		inet_csk_destroy_sock(sk);

	/* Otherwise, socket is reprieved until protocol close. */

out:
	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
}

EXPORT_SYMBOL_GPL(dccp_close);

void dccp_shutdown(struct sock *sk, int how)
{
	dccp_pr_debug("called shutdown(%x)\n", how);
}

EXPORT_SYMBOL_GPL(dccp_shutdown);

static inline int __init dccp_mib_init(void)
{
	dccp_statistics = alloc_percpu(struct dccp_mib);
	if (!dccp_statistics)
		return -ENOMEM;
	return 0;
}

static inline void dccp_mib_exit(void)
{
	free_percpu(dccp_statistics);
}

static int thash_entries;
module_param(thash_entries, int, 0444);
MODULE_PARM_DESC(thash_entries, "Number of ehash buckets");

#ifdef CONFIG_IP_DCCP_DEBUG
bool dccp_debug;
module_param(dccp_debug, bool, 0644);
MODULE_PARM_DESC(dccp_debug, "Enable debug messages");

EXPORT_SYMBOL_GPL(dccp_debug);
#endif

static int __init dccp_init(void)
{
	unsigned long goal;
	unsigned long nr_pages = totalram_pages();
	int ehash_order, bhash_order, i;
	int rc;

	BUILD_BUG_ON(sizeof(struct dccp_skb_cb) >
		     sizeof_field(struct sk_buff, cb));
	rc = inet_hashinfo2_init_mod(&dccp_hashinfo);
	if (rc)
		goto out_fail;
	rc = -ENOBUFS;
	dccp_hashinfo.bind_bucket_cachep =
		kmem_cache_create("dccp_bind_bucket",
				  sizeof(struct inet_bind_bucket), 0,
				  SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT, NULL);
	if (!dccp_hashinfo.bind_bucket_cachep)
		goto out_free_hashinfo2;
	dccp_hashinfo.bind2_bucket_cachep =
		kmem_cache_create("dccp_bind2_bucket",
				  sizeof(struct inet_bind2_bucket), 0,
				  SLAB_HWCACHE_ALIGN | SLAB_ACCOUNT, NULL);
	if (!dccp_hashinfo.bind2_bucket_cachep)
		goto out_free_bind_bucket_cachep;

	/*
	 * Size and allocate the main established and bind bucket
	 * hash tables.
	 *
	 * The methodology is similar to that of the buffer cache.
	 */
	if (nr_pages >= (128 * 1024))
		goal = nr_pages >> (21 - PAGE_SHIFT);
	else
		goal = nr_pages >> (23 - PAGE_SHIFT);

	if (thash_entries)
		goal = (thash_entries *
			sizeof(struct inet_ehash_bucket)) >> PAGE_SHIFT;
	for (ehash_order = 0; (1UL << ehash_order) < goal; ehash_order++)
		;
	do {
		unsigned long hash_size = (1UL << ehash_order) * PAGE_SIZE /
					sizeof(struct inet_ehash_bucket);

		while (hash_size & (hash_size - 1))
			hash_size--;
		dccp_hashinfo.ehash_mask = hash_size - 1;
		dccp_hashinfo.ehash = (struct inet_ehash_bucket *)
			__get_free_pages(GFP_ATOMIC|__GFP_NOWARN, ehash_order);
	} while (!dccp_hashinfo.ehash && --ehash_order > 0);

	if (!dccp_hashinfo.ehash) {
		DCCP_CRIT("Failed to allocate DCCP established hash table");
		goto out_free_bind2_bucket_cachep;
	}

	for (i = 0; i <= dccp_hashinfo.ehash_mask; i++)
		INIT_HLIST_NULLS_HEAD(&dccp_hashinfo.ehash[i].chain, i);

	if (inet_ehash_locks_alloc(&dccp_hashinfo))
			goto out_free_dccp_ehash;

	bhash_order = ehash_order;

	do {
		dccp_hashinfo.bhash_size = (1UL << bhash_order) * PAGE_SIZE /
					sizeof(struct inet_bind_hashbucket);
		if ((dccp_hashinfo.bhash_size > (64 * 1024)) &&
		    bhash_order > 0)
			continue;
		dccp_hashinfo.bhash = (struct inet_bind_hashbucket *)
			__get_free_pages(GFP_ATOMIC|__GFP_NOWARN, bhash_order);
	} while (!dccp_hashinfo.bhash && --bhash_order >= 0);

	if (!dccp_hashinfo.bhash) {
		DCCP_CRIT("Failed to allocate DCCP bind hash table");
		goto out_free_dccp_locks;
	}

	dccp_hashinfo.bhash2 = (struct inet_bind_hashbucket *)
		__get_free_pages(GFP_ATOMIC | __GFP_NOWARN, bhash_order);

	if (!dccp_hashinfo.bhash2) {
		DCCP_CRIT("Failed to allocate DCCP bind2 hash table");
		goto out_free_dccp_bhash;
	}

	for (i = 0; i < dccp_hashinfo.bhash_size; i++) {
		spin_lock_init(&dccp_hashinfo.bhash[i].lock);
		INIT_HLIST_HEAD(&dccp_hashinfo.bhash[i].chain);
		spin_lock_init(&dccp_hashinfo.bhash2[i].lock);
		INIT_HLIST_HEAD(&dccp_hashinfo.bhash2[i].chain);
	}

	dccp_hashinfo.pernet = false;

	rc = dccp_mib_init();
	if (rc)
		goto out_free_dccp_bhash2;

	dccp_timestamping_init();

	return 0;

out_free_dccp_bhash2:
	free_pages((unsigned long)dccp_hashinfo.bhash2, bhash_order);
out_free_dccp_bhash:
	free_pages((unsigned long)dccp_hashinfo.bhash, bhash_order);
out_free_dccp_locks:
	inet_ehash_locks_free(&dccp_hashinfo);
out_free_dccp_ehash:
	free_pages((unsigned long)dccp_hashinfo.ehash, ehash_order);
out_free_bind2_bucket_cachep:
	kmem_cache_destroy(dccp_hashinfo.bind2_bucket_cachep);
out_free_bind_bucket_cachep:
	kmem_cache_destroy(dccp_hashinfo.bind_bucket_cachep);
out_free_hashinfo2:
	inet_hashinfo2_free_mod(&dccp_hashinfo);
out_fail:
	dccp_hashinfo.bhash = NULL;
	dccp_hashinfo.bhash2 = NULL;
	dccp_hashinfo.ehash = NULL;
	dccp_hashinfo.bind_bucket_cachep = NULL;
	dccp_hashinfo.bind2_bucket_cachep = NULL;
	return rc;
}

static void __exit dccp_fini(void)
{
	int bhash_order = get_order(dccp_hashinfo.bhash_size *
				    sizeof(struct inet_bind_hashbucket));

	dccp_mib_exit();
	free_pages((unsigned long)dccp_hashinfo.bhash, bhash_order);
	free_pages((unsigned long)dccp_hashinfo.bhash2, bhash_order);
	free_pages((unsigned long)dccp_hashinfo.ehash,
		   get_order((dccp_hashinfo.ehash_mask + 1) *
			     sizeof(struct inet_ehash_bucket)));
	inet_ehash_locks_free(&dccp_hashinfo);
	kmem_cache_destroy(dccp_hashinfo.bind_bucket_cachep);
	inet_hashinfo2_free_mod(&dccp_hashinfo);
}

module_init(dccp_init);
module_exit(dccp_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arnaldo Carvalho de Melo <acme@conectiva.com.br>");
MODULE_DESCRIPTION("DCCP - Datagram Congestion Controlled Protocol");
