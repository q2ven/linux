// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */

#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <net/if.h>

#include "test_progs.h"
#include "cgroup_helpers.h"
#include "network_helpers.h"
#include "test_tcp_syncookie.skel.h"

static int setup_netns(void)
{
//	if (!ASSERT_OK(unshare(CLONE_NEWNET), "create netns"))
//		return -1;

	if (!ASSERT_OK(system("ip link set dev lo up"), "ip"))
		return -1;

//	if (!ASSERT_OK(system("ethtool -K lo tx off"), "ethtool"))
//		return -1;

	if (!ASSERT_OK(write_sysctl("/proc/sys/net/ipv4/tcp_syncookies", "2"),
		       "write_sysctl(tcp_syncookies)"))
		return -1;

	if (!ASSERT_OK(write_sysctl("/proc/sys/net/ipv4/tcp_ecn", "1"),
		       "write_sysctl(tcp_ecn)"))
		return -1;

	return 0;
}

static void create_connection(void)
{
	int server, client, child;

	server = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", 0, 0);
	if (!ASSERT_NEQ(server, -1, "start_server"))
		return;

	client = connect_to_fd(server, 0);
	if (!ASSERT_NEQ(client, -1, "connect_to_fd"))
		goto close_server;

	child = accept(server, NULL, 0);
	if (!ASSERT_NEQ(child, -1, "accept"))
		goto close_client;

	close(child);
close_client:
	close(client);
close_server:
	close(server);
}

void test_tcp_syncookie(void)
{
	struct test_tcp_syncookie *skel;

	if (setup_netns())
		return;

	skel = test_tcp_syncookie__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	LIBBPF_OPTS(bpf_tc_hook, qdisc_lo, .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc_attach,
		    .prog_fd = bpf_program__fd(skel->progs.syncookie));

	qdisc_lo.ifindex = if_nametoindex("lo");
	if (!ASSERT_OK(bpf_tc_hook_create(&qdisc_lo), "qdisc add dev lo clsact"))
		goto destroy_skel;

	if (!ASSERT_OK(bpf_tc_attach(&qdisc_lo, &tc_attach),
		       "filter add dev lo ingress"))
		goto destroy_skel;

	create_connection();

destroy_skel:
	system("tc qdisc del dev lo clsact");

	test_tcp_syncookie__destroy(skel);
}
