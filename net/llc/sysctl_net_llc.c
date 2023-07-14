// SPDX-License-Identifier: GPL-2.0
/*
 * sysctl_net_llc.c: sysctl interface to LLC net subsystem.
 *
 * Arnaldo Carvalho de Melo <acme@conectiva.com.br>
 */

#include <linux/mm.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <net/net_namespace.h>
#include <net/llc.h>

#ifndef CONFIG_SYSCTL
#error This file should not be compiled without CONFIG_SYSCTL defined
#endif

static struct ctl_table llc2_timeout_table[] = {
	{
		.procname	= "ack",
		.data		= &init_net.llc.sysctl_llc2_ack_timeout,
		.maxlen		= sizeof(init_net.llc.sysctl_llc2_ack_timeout),
		.mode		= 0644,
		.proc_handler   = proc_dointvec_jiffies,
	},
	{
		.procname	= "busy",
		.data		= &init_net.llc.sysctl_llc2_busy_timeout,
		.maxlen		= sizeof(init_net.llc.sysctl_llc2_busy_timeout),
		.mode		= 0644,
		.proc_handler   = proc_dointvec_jiffies,
	},
	{
		.procname	= "p",
		.data		= &init_net.llc.sysctl_llc2_p_timeout,
		.maxlen		= sizeof(init_net.llc.sysctl_llc2_p_timeout),
		.mode		= 0644,
		.proc_handler   = proc_dointvec_jiffies,
	},
	{
		.procname	= "rej",
		.data		= &init_net.llc.sysctl_llc2_rej_timeout,
		.maxlen		= sizeof(init_net.llc.sysctl_llc2_rej_timeout),
		.mode		= 0644,
		.proc_handler   = proc_dointvec_jiffies,
	},
};

int __net_init llc_sysctl_init(struct net *net)
{
	struct ctl_table *table;

	if (net_eq(net, &init_net)) {
		table = llc2_timeout_table;
	} else {
		int i;

		table = kmemdup(llc2_timeout_table, sizeof(llc2_timeout_table), GFP_KERNEL);
		if (!table)
			goto err;

		for (i = 0; i < ARRAY_SIZE(llc2_timeout_table); i++)
			table[i].data += (void *)net - (void *)&init_net;
	}

	net->llc.header = register_net_sysctl(net, "net/llc/llc2/timeout", table);
	if (!net->llc.header)
		goto err_register;

	return 0;

err_register:
	if (!net_eq(net, &init_net))
		kfree(table);
err:
	return -ENOMEM;
}

void __net_exit llc_sysctl_exit(struct net *net)
{
	struct ctl_table *table;

	table = net->llc.header->ctl_table_arg;
	unregister_net_sysctl_table(net->llc.header);

	if (!net_eq(net, &init_net))
		kfree(table);
}
