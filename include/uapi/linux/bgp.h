// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */

#ifndef _UAPI_LINUX_BGP_H
#define _UAPI_LINUX_BGP_H

#include <linux/types.h>

enum {
	BGP_OPEN = 1,
};

#define BGP_VERSION_4	4

#define BGP_AS_TRANS 	23456

struct bgp_msg_open {
	__u8 version;
	__u16 as;
	__u16 hold_time;
	__u32 id;
	__u8 opt_len;
} __attribute__((packed));

#endif /* _UAPI_LINUX_BGP_H */
