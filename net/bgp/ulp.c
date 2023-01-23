// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */

#include <linux/module.h>

static int __init bgp_init(void)
{
	return 0;
}

static void __exit bgp_exit(void)
{
}

module_init(bgp_init);
module_exit(bgp_exit);

MODULE_AUTHOR("Kuniyuki Iwashima");
MODULE_DESCRIPTION("Border Gateway Protocol");
MODULE_LICENSE("GPL");
