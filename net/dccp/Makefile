# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_IP_DCCP) += dccp.o dccp_ipv4.o

dccp-y := ccid.o feat.o input.o minisocks.o options.o output.o proto.o timer.o \
	  qpolicy.o
#
# CCID algorithms to be used by dccp.ko
#
# CCID-2 is default (RFC 4340, p. 77) and has Ack Vectors as dependency
dccp-y += ccids/ccid2.o ackvec.o

dccp_ipv4-y := ipv4.o

# build dccp_ipv6 as module whenever either IPv6 or DCCP is a module
obj-$(subst y,$(CONFIG_IP_DCCP),$(CONFIG_IPV6)) += dccp_ipv6.o
dccp_ipv6-y := ipv6.o
