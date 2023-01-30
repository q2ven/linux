// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/bgp.h>

#define SOL_BGP 287

#include "../../kselftest_harness.h"

FIXTURE(bgp)
{
	struct sockaddr_in addr;
	socklen_t addrlen;
	int server, client;
};

static void setup_connection(struct __test_metadata *_metadata,
			     FIXTURE_DATA(bgp) *self)
{
	int ret;

	self->server = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT_GT(self->server, 0);

	ret = bind(self->server, (struct sockaddr *)&self->addr, self->addrlen);
	ASSERT_EQ(ret, 0);

	ret = listen(self->server, 1);
	ASSERT_EQ(ret, 0);

	ret = getsockname(self->server, (struct sockaddr *)&self->addr, &self->addrlen);
	ASSERT_EQ(ret, 0);

	self->client = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT_GT(self->client, 0);

	ret = connect(self->client, (struct sockaddr *)&self->addr, self->addrlen);
	ASSERT_EQ(ret, 0);
}

FIXTURE_SETUP(bgp)
{
	self->addr.sin_family = AF_INET;
	self->addr.sin_port = 0;
	self->addr.sin_addr.s_addr = htonl(INADDR_ANY);
	self->addrlen = sizeof(self->addr);

	setup_connection(_metadata, self);
}

FIXTURE_TEARDOWN(bgp)
{
	close(self->server);
	close(self->client);
}

static int send_open(struct __test_metadata *_metadata,
		     FIXTURE_DATA(bgp) *self)
{
	char buf[CMSG_SPACE(sizeof(struct bgp_msg_open))];
	struct bgp_msg_open *bgpmsg;
	struct msghdr msg = {0};
	struct cmsghdr *cmsg;

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(*bgpmsg));
	cmsg->cmsg_level = SOL_BGP;
	cmsg->cmsg_type = BGP_OPEN;

	bgpmsg = (struct bgp_msg_open *)CMSG_DATA(cmsg);
	bgpmsg->version = BGP_VERSION_4;
	bgpmsg->as = htons(65535);
	bgpmsg->hold_time = htons(180);
	bgpmsg->id = htonl(1);
	bgpmsg->opt_len = 0;

	msg.msg_controllen = cmsg->cmsg_len;

	return sendmsg(self->client, &msg, 0);
}

TEST_F(bgp, ulp)
{
	int ret;

	ret = setsockopt(self->client, SOL_TCP, TCP_ULP, "bgp", 3);
	ASSERT_EQ(ret, 0);

	ret = send_open(_metadata, self);
	ASSERT_NE(ret, sizeof(struct bgp_msg_open));
}

TEST_HARNESS_MAIN
