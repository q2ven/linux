// SPDX-License-Identifier: GPL-2.0-or-later

#include <net/udp.h>

int udp_parse_options(struct sk_buff *skb)
{
	if (!pskb_may_pull(skb, skb->len))
		return -ENOMEM;

	return 0;
}
