// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */

#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>

#include "test_progs.h"
#include "cgroup_helpers.h"
#include "network_helpers.h"
#include "test_tcp_syncookie.skel.h"

#define IFINDEX_LO 1

static int setup_netns(void)
{
	if (!ASSERT_OK(unshare(CLONE_NEWNET), "unshare"))
		return -1;

	if (!ASSERT_OK(system("ip link set dev lo up"), "ip link"))
		return -1;

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
	struct bpf_link *link_cg, *link_xdp;
	struct test_tcp_syncookie *skel;
	int fd_cg;

	if (setup_netns())
		return;

	skel = test_tcp_syncookie__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	fd_cg = test__join_cgroup("/tcp_syncookie");
	if (!ASSERT_GE(fd_cg, 0, "join_cgroup"))
		goto destroy_skel;

	link_cg = bpf_program__attach_cgroup(skel->progs.check_syncookie, fd_cg);
	if (!ASSERT_OK_PTR(link_cg, "attach_cgroup"))
		goto close_cgroup;

	link_xdp = bpf_program__attach_xdp(skel->progs.gen_syncookie, IFINDEX_LO);
	if (!ASSERT_OK_PTR(link_xdp, "attach_xdp"))
		goto destroy_link;

	create_connection();

	bpf_link__destroy(link_xdp);
destroy_link:
	bpf_link__destroy(link_cg);
close_cgroup:
	close(fd_cg);
destroy_skel:
	test_tcp_syncookie__destroy(skel);
}
