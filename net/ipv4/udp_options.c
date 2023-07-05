// SPDX-License-Identifier: GPL-2.0-or-later

#include <net/udp.h>

enum {
	UDPOPT_EOL,			/* End of options */
	UDPOPT_NOP,			/* Padding */
};

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

int udp_parse_nops(const unsigned char *ptr, int left)
{
	int parsed = 0;

	while (left) {
		if (*ptr != UDPOPT_NOP) {
			/* NOPs SHOULD NOT be used as padding before
			 * the EOL option.  See Section 9.1.
			 */
			if (unlikely(*ptr == UDPOPT_EOL))
				return -EINVAL;
			break;
		}

		parsed++;

		/* More than seven consecutive NOPs might be DoS.
		 * See Section 9.2.
		 */
		if (unlikely(parsed >= 7))
			return -EINVAL;

		/* NOPs SHOULD NOT be used as a substitute for EOL.
		 * See Section 9.2.
		 */
		if (left == 1)
			return -EINVAL;

		ptr++;
		left--;
	}

	return parsed;
}

int udp_parse_opsize(const unsigned char *ptr, int left, u16 *opleft)
{
	u16 opsize;
	int parsed;

	if (left < 1)
		return -EINVAL;

	opsize = *ptr++;
	left--;
	parsed = 1;

	if (opsize == 255) {
		if (left < 2)
			return -EINVAL;

		opsize = *(u16 *)ptr;
		len -= 2;
		parsed += 2;

		if (opsize < 4)
			return -EINVAL;

		if (opsize < 254)
			return -EINVAL;
	}

	*opleft = opsize - parsed;
	if (len < *opleft)
		return -EINVAL;

	return parsed;
}

int udp_parse_options(struct sk_buff *skb)
{
	const unsigned char *ptr;
	struct udphdr *uh;
	int left, parsed;
	u16 opleft;
	u8 opcode;

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

	while (len) {
		opcode = *ptr++;
		left--;

		switch (opcode) {
		case UDPOPT_EOL:
			goto success;
		case UDPOPT_NOP:
			parsed = udp_parse_nops(ptr, left);
			if (parsed < 0)
				goto skip;

			ptr += parsed;
			left -= parsed;
			continue;
		}

		parsed = udp_parse_opsize(ptr, left, &opleft);
		if (parsed < 0)
			goto skip;

		ptr += parsed;
		left -= parsed;

		switch (opcode) {
		default:
			goto skip;
		}
	}

success:
skip:
	return 0;
}
