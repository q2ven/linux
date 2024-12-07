/* SPDX-License-Identifier: GPL-2.0 */
/*
 *	Definitions for the UDP-Lite (RFC 3828) code.
 */
#ifndef _UDPLITE_H
#define _UDPLITE_H

#include <net/ip6_checksum.h>
#include <net/udp.h>

/*
 *	Checksum computation is all in software, hence simpler getfrag.
 */
static __inline__ int udplite_getfrag(void *from, char *to, int  offset,
				      int len, int odd, struct sk_buff *skb)
{
	struct msghdr *msg = from;
	return copy_from_iter_full(to, len, &msg->msg_iter) ? 0 : -EFAULT;
}

#endif	/* _UDPLITE_H */
