// SPDX-License-Identifier: GPL-2.0
/* Copyright Amazon.com Inc. or its affiliates. */

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

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

TEST_F(bgp, ulp)
{
	int ret;

	ret = setsockopt(self->client, SOL_TCP, TCP_ULP, "bgp", 3);
	ASSERT_EQ(ret, 0);
}

TEST_HARNESS_MAIN
