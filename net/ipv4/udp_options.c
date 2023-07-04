// SPDX-License-Identifier: GPL-2.0-or-later

#include <net/udp.h>

int udp_parse_options(struct sk_buff *skb)
{
	const unsigned char *ptr;
	struct udphdr *uh;
	int left;

	if (!pskb_may_pull(skb, skb->len))
		return -ENOMEM;

	uh = udp_hdr(skb);
	ptr = skb->data + ntohs(uh->len);
	left = skb->len - ntohs(uh->len);

	if ((unsigned long)ptr & 1) {
		/* Must be zero.  Section 6. */
		if (*ptr != 0)
			goto skip;

		ptr++;
		left--;
	}

skip:
	return 0;
}
