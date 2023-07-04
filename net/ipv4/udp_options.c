// SPDX-License-Identifier: GPL-2.0-or-later

#include <net/udp.h>

int udp_parse_ocs(const unsigned char *ptr, int left, struct udphdr *uh)
{
	u16 ocs;

	if (left < 2)
		return -EINVAL;

	if (uh->check) {
		ocs = *(u16 *)ptr;
	}

	return 2;
}

int udp_parse_options(struct sk_buff *skb)
{
	const unsigned char *ptr;
	struct udphdr *uh;
	int left, parsed;

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

	parsed = udp_parse_ocs(ptr, left, uh);
	if (parsed < 0)
		goto skip;

	ptr += parsed;
	left -= parsed;

skip:
	return 0;
}
