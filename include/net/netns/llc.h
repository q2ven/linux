/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __NETNS_LLC_H__
#define __NETNS_LLC_H__

struct netns_llc {
#ifdef CONFIG_SYSCTL
	struct ctl_table_header	*header;
#endif
	int sysctl_llc2_ack_timeout;
	int sysctl_llc2_busy_timeout;
	int sysctl_llc2_p_timeout;
	int sysctl_llc2_rej_timeout;
};

#endif /* __NETNS_LLC_H__ */
