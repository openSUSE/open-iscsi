/*
 * Copyright (c) 2011, Broadcom Corporation
 *
 * Written by:  Eddie Wai  (eddie.wai@broadcom.com)
 *              Based on Kevin Tran's iSCSI boot code
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Adam Dunkels.
 * 4. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ipv6.c - This file contains simplifed IPv6 processing code.
 *
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "logger.h"
#include "uip.h"
#include "ipv6.h"
#include "ipv6_pkt.h"
#include "icmpv6.h"
#include "uipopt.h"
#include "dhcpv6.h"

inline int best_match_bufcmp(u8_t * a, u8_t * b, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (a[i] != b[i])
			break;
	}
	return i;
}

/* Local function prototypes */
STATIC int ipv6_is_it_our_address(pIPV6_CONTEXT ipv6_context,
				  IPV6_ADDR __FAR__ * ipv6_addr);
STATIC void ipv6_insert_protocol_chksum(pIPV6_HDR ipv6);
STATIC void ipv6_update_arp_table(pIPV6_CONTEXT ipv6_context,
				  IPV6_ADDR __FAR__ * ip_addr,
				  MAC_ADDR __FAR__ * mac_addr);
STATIC void ipv6_icmp_init_link_option(pIPV6_CONTEXT ipv6_context,
				       pICMPV6_OPT_LINK_ADDR link_opt,
				       u8_t type);
STATIC void ipv6_icmp_rx(pIPV6_CONTEXT ipv6_context);
STATIC void ipv6_icmp_handle_nd_adv(pIPV6_CONTEXT ipv6_context);
STATIC void ipv6_icmp_handle_nd_sol(pIPV6_CONTEXT ipv6_context);
STATIC void ipv6_icmp_handle_echo_request(pIPV6_CONTEXT ipv6_context);
STATIC void ipv6_icmp_handle_router_adv(pIPV6_CONTEXT ipv6_context);
STATIC void ipv6_icmp_process_prefix(pIPV6_CONTEXT ipv6_context,
				     pICMPV6_OPT_PREFIX icmp_prefix);
STATIC void ipv6_udp_rx(pIPV6_CONTEXT ipv6_context);

int iscsiL2Send(pIPV6_CONTEXT ipv6_context, int pkt_len)
{
	LOG_DEBUG("IPV6: iscsiL2Send");
	uip_send(ipv6_context->ustack,
		 (void *)ipv6_context->ustack->data_link_layer, pkt_len);

	return pkt_len;
}

int iscsiL2AddMcAddr(pIPV6_CONTEXT ipv6_context, MAC_ADDR * new_mc_addr)
{
	int i;
	MAC_ADDR *mc_addr;
	const MAC_ADDR all_zeroes_mc = { 0, 0, 0, 0, 0, 0 };

	mc_addr = ipv6_context->mc_addr;
	for (i = 0; i < MAX_MCADDR_TABLE; i++, mc_addr++)
		if (!memcmp((char __FAR__ *)mc_addr,
			    (char __FAR__ *)new_mc_addr, sizeof(MAC_ADDR)))
			return TRUE;	/* Already in the mc table */

	mc_addr = ipv6_context->mc_addr;
	for (i = 0; i < MAX_MCADDR_TABLE; i++, mc_addr++)
		if (!memcmp((char __FAR__ *)mc_addr,
			    (char __FAR__ *)&all_zeroes_mc, sizeof(MAC_ADDR))) {
			memcpy((char __FAR__ *)mc_addr,
			       (char __FAR__ *)new_mc_addr, sizeof(MAC_ADDR));
			LOG_DEBUG("IPV6: mc_addr added %x:%x:%x:%x:%x:%x",
				  *(u8_t *) new_mc_addr,
				  *((u8_t *) new_mc_addr + 1),
				  *((u8_t *) new_mc_addr + 2),
				  *((u8_t *) new_mc_addr + 3),
				  *((u8_t *) new_mc_addr + 4),
				  *((u8_t *) new_mc_addr + 5));
			return TRUE;
		}
	return FALSE;
}

int iscsiL2IsOurMcAddr(pIPV6_CONTEXT ipv6_context, pMAC_ADDRESS dest_mac)
{
	int i;
	MAC_ADDR *mc_addr;

	mc_addr = ipv6_context->mc_addr;
	for (i = 0; i < MAX_MCADDR_TABLE; i++, mc_addr++)
		if (!memcmp((char __FAR__ *)mc_addr,
			    (char __FAR__ *)dest_mac->addr, sizeof(MAC_ADDR)))
			return TRUE;
	return FALSE;
}

void ipv6_init(struct ndpc_state *ndp, int cfg)
{
	int i;
	pIPV6_CONTEXT ipv6_context = (pIPV6_CONTEXT) ndp->ipv6_context;
	u8_t *mac_addr = (u8_t *) ndp->mac_addr;
	pIPV6_ARP_ENTRY ipv6_arp_table;
	pIPV6_PREFIX_ENTRY ipv6_prefix_table;
	MAC_ADDR mc_addr;

	if (ipv6_context == NULL) {
		LOG_ERR("IPV6: INIT ipv6_context is NULL");
		return;
	}

	memset((char __FAR__ *)ipv6_context, 0, sizeof(IPV6_CONTEXT));

	/* Associate the nic_iface's ustack to this ipv6_context */
	ipv6_context->ustack = ndp->ustack;

	ipv6_arp_table = &ipv6_context->ipv6_arp_table[0];
	ipv6_prefix_table = &ipv6_context->ipv6_prefix_table[0];

	memset((char __FAR__*)ipv6_arp_table, 0, sizeof(*ipv6_arp_table));
	memset((char __FAR__*)ipv6_prefix_table, 0,
	       sizeof(*ipv6_prefix_table));
	memcpy((char __FAR__*)&ipv6_context->mac_addr,
	       (char __FAR__*)mac_addr, sizeof(MAC_ADDR));
	/* 
	 * Per RFC 2373.  
	 * There are two types of local-use unicast addresses defined.  These
	 * are Link-Local and Site-Local.  The Link-Local is for use on a single
	 * link and the Site-Local is for use in a single site.  Link-Local
	 * addresses have the following format:
	 *
	 * |   10     |
	 * |  bits    |        54 bits          |          64 bits           |
	 * +----------+-------------------------+----------------------------+
	 * |1111111010|           0             |       interface ID         |
	 * +----------+-------------------------+----------------------------+
	 */
	ipv6_context->link_local_addr.addr8[0] = 0xfe;
	ipv6_context->link_local_addr.addr8[1] = 0x80;
	/* Bit 1 is 1 to indicate universal scope. */
	ipv6_context->link_local_addr.addr8[8] = mac_addr[0] | 0x2;
	ipv6_context->link_local_addr.addr8[9] = mac_addr[1];
	ipv6_context->link_local_addr.addr8[10] = mac_addr[2];
	ipv6_context->link_local_addr.addr8[11] = 0xff;
	ipv6_context->link_local_addr.addr8[12] = 0xfe;
	ipv6_context->link_local_addr.addr8[13] = mac_addr[3];
	ipv6_context->link_local_addr.addr8[14] = mac_addr[4];
	ipv6_context->link_local_addr.addr8[15] = mac_addr[5];

	ipv6_context->link_local_multi.addr8[0] = 0xff;
	ipv6_context->link_local_multi.addr8[1] = 0x02;
	ipv6_context->link_local_multi.addr8[11] = 0x01;
	ipv6_context->link_local_multi.addr8[12] = 0xff;
	ipv6_context->link_local_multi.addr8[13] |=
	    ipv6_context->link_local_addr.addr8[13];
	ipv6_context->link_local_multi.addr16[7] =
	    ipv6_context->link_local_addr.addr16[7];

	/* Default Prefix length is 64 */
	/* Add Link local address to the head of the ipv6 address
	   list */
	if (ipv6_context->ustack->linklocal_autocfg != IPV6_LL_AUTOCFG_OFF)
		ipv6_add_prefix_entry(ipv6_context,
				      &ipv6_context->link_local_addr, 64);

	/*
	 * Convert Multicast IP address to Multicast MAC adress per 
	 * RFC 2464: Transmission of IPv6 Packets over Ethernet Networks
	 * 
	 * An IPv6 packet with a multicast destination address DST, consisting
	 * of the sixteen octets DST[1] through DST[16], is transmitted to the
	 * Ethernet multicast address whose first two octets are the value 3333
	 * hexadecimal and whose last four octets are the last four octets of
	 * DST.
	 *
	 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *          |0 0 1 1 0 0 1 1|0 0 1 1 0 0 1 1|
	 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *          |   DST[13]     |   DST[14]     |
	 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *          |   DST[15]     |   DST[16]     |
	 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 * IPv6 requires the following Multicast IP addresses setup per node. 
	 */
	for (i = 0; i < 3; i++) {
		mc_addr[0] = 0x33;
		mc_addr[1] = 0x33;
		mc_addr[2] = 0x0;
		mc_addr[3] = 0x0;
		mc_addr[4] = 0x0;

		switch (i) {
		case 0:
			/* All Nodes Multicast IPv6 address : ff02::1 */
			mc_addr[5] = 0x1;
			break;

		case 1:
			/* All Host Multicast IPv6 address : ff02::3 */
			mc_addr[5] = 0x3;
			break;

		case 2:
			/* Solicited Node Multicast Address: ff02::01:ffxx:yyzz
			 */
			mc_addr[2] = 0xff;
			mc_addr[3] = mac_addr[3];
			mc_addr[4] = mac_addr[4];
			mc_addr[5] = mac_addr[5];
			break;

		default:
			break;
		}
		iscsiL2AddMcAddr(ipv6_context, &mc_addr);
	}

	/* Default HOP number */
	ipv6_context->hop_limit = IPV6_HOP_LIMIT;
}

int ipv6_add_prefix_entry(pIPV6_CONTEXT ipv6_context,
			  IPV6_ADDR * ipv6_addr, u8_t prefix_len)
{
	int i;
	pIPV6_PREFIX_ENTRY prefix_entry;
	pIPV6_PREFIX_ENTRY ipv6_prefix_table = ipv6_context->ipv6_prefix_table;

	/* Check if there is an valid entry already. */
	for (i = 0; i < IPV6_NUM_OF_ADDRESS_ENTRY; i++) {
		prefix_entry = &ipv6_prefix_table[i];

		if (prefix_entry->prefix_len != 0) {
			if (memcmp((char __FAR__ *)&prefix_entry->address,
				   (char __FAR__ *)ipv6_addr,
				   sizeof(IPV6_ADDR)) == 0) {
				/* We already initialize on this interface.
				   There is nothing to do */
				return 0;
			}
		}
	}

	/* Find an unused entry */
	for (i = 0; i < IPV6_NUM_OF_ADDRESS_ENTRY; i++) {
		prefix_entry = &ipv6_prefix_table[i];

		if (prefix_entry->prefix_len == 0) {
			break;
		}
	}

	if (prefix_entry->prefix_len != 0)
		return -1;

	prefix_entry->prefix_len = prefix_len / 8;

	memcpy((char __FAR__ *)&prefix_entry->address,
	       (char __FAR__ *)ipv6_addr, sizeof(IPV6_ADDR));


	LOG_DEBUG("IPV6: add prefix ip addr "
		  "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x "
		  "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
	prefix_entry->address.addr8[0], prefix_entry->address.addr8[1],
	prefix_entry->address.addr8[2], prefix_entry->address.addr8[3],
	prefix_entry->address.addr8[4], prefix_entry->address.addr8[5],
	prefix_entry->address.addr8[6], prefix_entry->address.addr8[7],
	prefix_entry->address.addr8[8], prefix_entry->address.addr8[9],
	prefix_entry->address.addr8[10], prefix_entry->address.addr8[11],
	prefix_entry->address.addr8[12], prefix_entry->address.addr8[13],
	prefix_entry->address.addr8[14], prefix_entry->address.addr8[15]);
 
	/* Put it on the list on head of the list. */
	if (ipv6_context->addr_list != NULL) {
		prefix_entry->next = ipv6_context->addr_list;
	} else {
		prefix_entry->next = NULL;
	}

	ipv6_context->addr_list = prefix_entry;

	return 0;
}

void ipv6_rx_packet(pIPV6_CONTEXT ipv6_context, u16_t len)
{
	pIPV6_HDR ipv6;
	u16_t protocol;

	if (!ipv6_context->ustack) {
		LOG_WARN("ipv6 rx pkt ipv6_context=%p ustack=%p", ipv6_context,
			 ipv6_context->ustack);
		return;
	}
	ipv6 = (pIPV6_HDR) ipv6_context->ustack->network_layer;
	/* Make sure it's an IPv6 packet */
	if ((ipv6->ipv6_version_fc & 0xf0) != IPV6_VERSION) {
		/* It's not an IPv6 packet. Drop it. */
		LOG_WARN("IPv6 version 0x%x not IPv6", ipv6->ipv6_version_fc);
		return;
	}
	protocol = ipv6_process_rx(ipv6);

	switch (protocol) {
	case IPPROTO_ICMPV6:
		ipv6_icmp_rx(ipv6_context);
		break;

	case IPPROTO_UDP:
		/* Indicate to UDP processing code */
		ipv6_udp_rx(ipv6_context);
		break;

	default:
		break;
	}
}

void ipv6_mc_init_dest_mac(pETH_HDR eth, pIPV6_HDR ipv6)
{
	int i;
	/*
	 * Initialize address mapping of IPV6 Multicast to multicast MAC 
	 * address per RFC 2464.
	 * 
	 * An IPv6 packet with a multicast destination address DST, consisting
	 * of the sixteen octets DST[1] through DST[16], is transmitted to the
	 * Ethernet multicast address whose first two octets are the value 3333
	 * hexadecimal and whose last four octets are the last four octets of
	 * DST.
	 * 
	 *              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *              |0 0 1 1 0 0 1 1|0 0 1 1 0 0 1 1|
	 *              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *              |   DST[13]     |   DST[14]     |
	 *              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *              |   DST[15]     |   DST[16]     |
	 *              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	eth->dest_mac[0] = 0x33;
	eth->dest_mac[1] = 0x33;
	for (i = 0; i < 4; i++)
		eth->dest_mac[2 + i] = ipv6->ipv6_dst.addr8[12 + i];
}

int ipv6_autoconfig(pIPV6_CONTEXT ipv6_context)
{
	return ipv6_discover_address(ipv6_context);
}

int ipv6_discover_address(pIPV6_CONTEXT ipv6_context)
{
	pETH_HDR eth = (pETH_HDR) ipv6_context->ustack->data_link_layer;
	pIPV6_HDR ipv6 = (pIPV6_HDR) ipv6_context->ustack->network_layer;
	pICMPV6_HDR icmp = (pICMPV6_HDR) ((u8_t *) ipv6 + sizeof(IPV6_HDR));
	int rc = 0;

	/* Retrieve tx buffer */
	if (eth == NULL || ipv6 == NULL) {
		return -EAGAIN;
	}

	/* Setup IPv6 All Routers Multicast address : ff02::2 */
	memset((char __FAR__ *)&ipv6->ipv6_dst, 0, sizeof(IPV6_ADDR));
	ipv6->ipv6_dst.addr8[0] = 0xff;
	ipv6->ipv6_dst.addr8[1] = 0x02;
	ipv6->ipv6_dst.addr8[15] = 0x02;
	ipv6->ipv6_hop_limit = 255;

	/* Initialize MAC header based on destination MAC address */
	ipv6_mc_init_dest_mac(eth, ipv6);
	ipv6->ipv6_nxt_hdr = IPPROTO_ICMPV6;

	icmp->icmpv6_type = ICMPV6_RTR_SOL;
	icmp->icmpv6_code = 0;
	icmp->icmpv6_data = 0;
	icmp->icmpv6_cksum = 0;
	ipv6_icmp_init_link_option(ipv6_context,
				   (pICMPV6_OPT_LINK_ADDR) ((u8_t *) icmp +
							    sizeof(ICMPV6_HDR)),
				   IPV6_ICMP_OPTION_SRC_ADDR);
	ipv6->ipv6_plen =
	    HOST_TO_NET16((sizeof(ICMPV6_HDR) + sizeof(ICMPV6_OPT_LINK_ADDR)));
	memcpy((char __FAR__ *)&ipv6->ipv6_src,
	       (char __FAR__ *)&ipv6_context->link_local_addr,
	       sizeof(IPV6_ADDR));

	icmp->icmpv6_cksum = 0;
	LOG_DEBUG("IPV6: Send rtr sol");
	ipv6_send(ipv6_context, (u8_t *) icmp - (u8_t *) eth +
		  sizeof(ICMPV6_HDR) + sizeof(ICMPV6_OPT_LINK_ADDR));
	return rc;
}

u16_t ipv6_process_rx(pIPV6_HDR ipv6)
{
	return ipv6->ipv6_nxt_hdr;
}

int ipv6_send(pIPV6_CONTEXT ipv6_context, u16_t packet_len)
{
	pETH_HDR eth = (pETH_HDR) ipv6_context->ustack->data_link_layer;
	pIPV6_HDR ipv6 = (pIPV6_HDR) ipv6_context->ustack->network_layer;

	ipv6_setup_hdrs(ipv6_context, eth, ipv6, packet_len);

	return iscsiL2Send(ipv6_context, packet_len);
}

void ipv6_send_udp_packet(pIPV6_CONTEXT ipv6_context, u16_t packet_len)
{
	pETH_HDR eth = (pETH_HDR) ipv6_context->ustack->data_link_layer;
	pIPV6_HDR ipv6 = (pIPV6_HDR) ipv6_context->ustack->network_layer;
	pUDP_HDR udp = (pUDP_HDR) ((u8_t *) ipv6 + sizeof(IPV6_HDR));

	ipv6->ipv6_nxt_hdr = IPPROTO_UDP;
	ipv6->ipv6_plen =
	    HOST_TO_NET16(packet_len - ((u8_t *) udp - (u8_t *) eth));

	udp->chksum = 0;

	/* 
	 * We only use UDP packet for DHCPv6.  The source address is always 
	 * link-local address.
	 */
	ipv6->ipv6_src.addr[0] = 0;

	/* Hop limit is always 1 for DHCPv6 packet. */
	ipv6->ipv6_hop_limit = 1;

	ipv6_send(ipv6_context, packet_len);
}

void ipv6_setup_hdrs(pIPV6_CONTEXT ipv6_context, pETH_HDR eth, pIPV6_HDR ipv6,
		     u16_t packet_len)
{
	pIPV6_ADDR our_address;

	/* VLAN will be taken cared of in the nic layer */
	eth->len_type = HOST_TO_NET16(LAYER2_TYPE_IPV6);
	memcpy((char __FAR__ *)&eth->src_mac,
	       (char __FAR__ *)&ipv6_context->mac_addr, sizeof(MAC_ADDR));

	/* Put the traffic class into the packet. */
	memset(&ipv6->ipv6_version_fc, 0, sizeof(u32_t));
	ipv6->ipv6_version_fc = IPV6_VERSION;
	if (ipv6->ipv6_hop_limit == 0)
		ipv6->ipv6_hop_limit = ipv6_context->hop_limit;

	if (ipv6->ipv6_src.addr[0] == 0) {
		/* Need to initialize source IP address. */
		if ((our_address = ipv6_our_address(ipv6_context)) != NULL) {
			/* Assume that caller has filled in the destination
			   IP address */
			memcpy((char __FAR__ *)&ipv6->ipv6_src,
			       (char __FAR__ *)our_address, sizeof(IPV6_ADDR));
		}
	}

	ipv6_insert_protocol_chksum(ipv6);
}

STATIC void ipv6_insert_protocol_chksum(pIPV6_HDR ipv6)
{
	u32_t sum;
	u16_t *ptr;
	u16_t *protocol_data_ptr;
	int i;
	u16_t protocol_data_len;
	u16_t checksum;

	/* 
	 * This routine assumes that there is no extension header. This driver
	 * doesn't user extension header to keep driver small and simple.
	 * 
	 * Pseudo check consists of the following:
	 * SRC IP, DST IP, Protocol Data Length, and Next Header.
	 */
	sum = 0;
	ptr = (u16_t *) & ipv6->ipv6_src;

	for (i = 0; i < sizeof(IPV6_ADDR); i++) {
		sum += HOST_TO_NET16(*ptr);
		ptr++;
	}

	/* Keep track where the layer header is */
	protocol_data_ptr = ptr;

	protocol_data_len = HOST_TO_NET16(ipv6->ipv6_plen);
	sum += protocol_data_len;
	sum += ipv6->ipv6_nxt_hdr;
	/* Sum now contains sum of IPv6 pseudo header.  Let's add the data
	   streams. */
	if (protocol_data_len & 1) {
		/* Length of data is odd */
		*((u8_t *) ptr + protocol_data_len) = 0;
		protocol_data_len++;
	}

	for (i = 0; i < protocol_data_len / 2; i++) {
		sum += HOST_TO_NET16(*ptr);
		ptr++;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	sum &= 0xffff;
	checksum = (u16_t) (~sum);
	checksum = HOST_TO_NET16(checksum);

	switch (ipv6->ipv6_nxt_hdr) {
	case IPPROTO_ICMPV6:
		/* Insert correct ICMPv6 checksum */
		((pICMPV6_HDR) (protocol_data_ptr))->icmpv6_cksum = checksum;
		break;
	case IPPROTO_UDP:
		/* Insert correct UDP checksum */
		((pUDP_HDR) protocol_data_ptr)->chksum = checksum;
		break;
	default:
		break;
	}
}

int ipv6_is_it_our_link_local_address(pIPV6_CONTEXT ipv6_context,
				      IPV6_ADDR __FAR__ * ipv6_addr)
{
	u8_t *test_adddr = (u8_t *) ipv6_addr->addr8;
	u8_t test_remainder;

	if (test_adddr[0] != ipv6_context->link_local_addr.addr8[0])
		return FALSE;

	test_remainder = (test_adddr[1] & 0xC0) >> 6;
	if (test_remainder != 2)
		return FALSE;

	return TRUE;
}

STATIC int ipv6_is_it_our_address(pIPV6_CONTEXT ipv6_context,
				  IPV6_ADDR __FAR__ * ipv6_addr)
{
	pIPV6_PREFIX_ENTRY ipv6_prefix;

	for (ipv6_prefix = ipv6_context->addr_list; ipv6_prefix != NULL;
	     ipv6_prefix = ipv6_prefix->next) {
		if (IPV6_ARE_ADDR_EQUAL(&ipv6_prefix->address, ipv6_addr))
			return TRUE;
	}

	return FALSE;
}

pIPV6_ADDR ipv6_our_address(pIPV6_CONTEXT ipv6_context)
{
	return &ipv6_context->link_local_addr;
}

int ipv6_ip_in_arp_table(pIPV6_CONTEXT ipv6_context, pIPV6_ADDR ipv6_addr,
			 MAC_ADDR * mac_addr)
{
	pIPV6_ARP_ENTRY arp_entry;
	int i;

	for (i = 0; i < UIP_ARPTAB_SIZE; i++) {
		arp_entry = &ipv6_context->ipv6_arp_table[i];

		if (IPV6_ARE_ADDR_EQUAL(&arp_entry->ip_addr, ipv6_addr)) {
			memcpy((char *)mac_addr, &arp_entry->mac_addr,
			       sizeof(MAC_ADDR));
			return 1;
		}
	}
	return 0;
}

pIPV6_ADDR ipv6_find_longest_match(pIPV6_CONTEXT ipv6_context,
				   pIPV6_ADDR ip_addr)
{
	pIPV6_PREFIX_ENTRY ipv6_prefix;
	pIPV6_PREFIX_ENTRY best_match = NULL;
	int longest_len = -1;
	int len;

	for (ipv6_prefix = ipv6_context->addr_list; ipv6_prefix != NULL;
	     ipv6_prefix = ipv6_prefix->next) {
		if (!IPV6_IS_ADDR_LINKLOCAL(&ipv6_prefix->address)) {
			len = best_match_bufcmp((u8_t *) & ipv6_prefix->address,
						(u8_t *) ip_addr,
						sizeof(IPV6_ADDR));
			if (len > longest_len) {
				best_match = ipv6_prefix;
				longest_len = len;
			}
		}
	}

	if (best_match)
		return &best_match->address;

	return NULL;
}

void ipv6_arp_out(pIPV6_CONTEXT ipv6_context, int *uip_len)
{
	/* Empty routine */
}


STATIC void ipv6_update_arp_table(pIPV6_CONTEXT ipv6_context,
				  IPV6_ADDR __FAR__ * ip_addr,
				  MAC_ADDR __FAR__ * mac_addr)
{
	pIPV6_ARP_ENTRY arp_entry;
	int i;
	pIPV6_ARP_ENTRY ipv6_arp_table = ipv6_context->ipv6_arp_table;

	LOG_DEBUG("IPV6: ARP update");
	/* 
	 * Walk through the ARP mapping table and try to find an entry to
	 * update. If none is found, the IP -> MAC address mapping is
	 * inserted in the ARP table. 
	 */
	for (i = 0; i < UIP_ARPTAB_SIZE; i++) {
		arp_entry = &ipv6_arp_table[i];

		/* Only check those entries that are actually in use. */
		if (arp_entry->ip_addr.addr[0] != 0) {
			/*
			 * Check if the source IP address of the incoming
			 * packet matches the IP address in this ARP table
			 * entry.
			 */
			if (IPV6_ARE_ADDR_EQUAL(&arp_entry->ip_addr, ip_addr)) {
				/* An old entry found, update this and return */
				memcpy((char __FAR__ *)&arp_entry->mac_addr,
				       (char __FAR__ *)mac_addr,
				       sizeof(MAC_ADDR));
				arp_entry->time = ipv6_context->arptime;
				return;
			}
		}
	}

	/*
	 * If we get here, no existing ARP table entry was found, so we
	 * create one.
	 *
	 * First, we try to find an unused entry in the ARP table. 
	 */
	for (i = 0; i < UIP_ARPTAB_SIZE; i++) {
		arp_entry = &ipv6_arp_table[i];

		if (arp_entry->ip_addr.addr[0] == 0)
			break;
	}

	if (i == UIP_ARPTAB_SIZE)
		return;

	/* Index j is the entry that is least used */
	arp_entry = &ipv6_arp_table[i];
	memcpy((char __FAR__ *)&arp_entry->ip_addr, (char __FAR__ *)ip_addr,
	       sizeof(IPV6_ADDR));
	memcpy((char __FAR__ *)&arp_entry->mac_addr,
	       (char __FAR__ *)mac_addr, sizeof(MAC_ADDR));

	arp_entry->time = ipv6_context->arptime;
}

/* DestIP is intact */
int ipv6_send_nd_solicited_packet(pIPV6_CONTEXT ipv6_context, pETH_HDR eth,
				  pIPV6_HDR ipv6)
{
	pICMPV6_HDR icmp;
	int pkt_len = 0;
	pIPV6_ADDR longest_match_addr;

	ipv6->ipv6_nxt_hdr = IPPROTO_ICMPV6;

	/* Depending on the IPv6 address of the target, we'll need to determine
	   whether we use the assigned IPv6 address/RA or the link local address
	*/
	/* Use Link-local as source address */
	if (ipv6_is_it_our_link_local_address(ipv6_context, &ipv6->ipv6_dst) ==
	    TRUE) {
		LOG_DEBUG("IPV6: NS using link local");
		memcpy((char __FAR__ *)&ipv6->ipv6_src,
		       (char __FAR__ *)&ipv6_context->link_local_addr,
		       sizeof(IPV6_ADDR));
	} else {
		longest_match_addr =
		    ipv6_find_longest_match(ipv6_context, &ipv6->ipv6_dst);
		if (longest_match_addr) {
			LOG_DEBUG("IPV6: NS using longest match addr");
			memcpy((char __FAR__ *)&ipv6->ipv6_src,  
			       (char __FAR__ *)longest_match_addr,
			       sizeof(IPV6_ADDR));
		} else {
			LOG_DEBUG("IPV6: NS using link local instead");
			memcpy((char __FAR__ *)&ipv6->ipv6_src,  
			       (char __FAR__ *)&ipv6_context->link_local_addr,
			       sizeof(IPV6_ADDR));
		}
	}
	icmp = (pICMPV6_HDR) ((u8_t *) ipv6 + sizeof(IPV6_HDR));

	LOG_DEBUG
	    ("IPV6: NS host ip addr %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"
	     " %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
	     ipv6->ipv6_src.addr8[0], ipv6->ipv6_src.addr8[1],
	     ipv6->ipv6_src.addr8[2], ipv6->ipv6_src.addr8[3],
	     ipv6->ipv6_src.addr8[4], ipv6->ipv6_src.addr8[5],
	     ipv6->ipv6_src.addr8[6], ipv6->ipv6_src.addr8[7],
	     ipv6->ipv6_src.addr8[8], ipv6->ipv6_src.addr8[9],
	     ipv6->ipv6_src.addr8[10], ipv6->ipv6_src.addr8[11],
	     ipv6->ipv6_src.addr8[12], ipv6->ipv6_src.addr8[13],
	     ipv6->ipv6_src.addr8[14], ipv6->ipv6_src.addr8[15]);
	/* 
	 * Destination IP address to be resolved is after the ICMPv6 
	 * header.
	 */
	memcpy((char __FAR__ *)((u8_t *) icmp + sizeof(ICMPV6_HDR)),
	       (char __FAR__ *)&ipv6->ipv6_dst, sizeof(IPV6_ADDR));

	/* 
	 * Destination IP in the IPv6 header contains solicited-node multicast 
	 * address corresponding to the target address.
	 *
	 * ff02::01:ffxx:yyzz. Where xyz are least
	 * significant of 24-bit MAC address.
	 */
	memset((char __FAR__ *)&ipv6->ipv6_dst, 0, sizeof(IPV6_ADDR) - 3);
	ipv6->ipv6_dst.addr8[0] = 0xff;
	ipv6->ipv6_dst.addr8[1] = 0x02;
	ipv6->ipv6_dst.addr8[11] = 0x01;
	ipv6->ipv6_dst.addr8[12] = 0xff;
	ipv6_mc_init_dest_mac(eth, ipv6);
	ipv6->ipv6_hop_limit = 255;

	icmp->icmpv6_type = ICMPV6_NEIGH_SOL;
	icmp->icmpv6_code = 0;
	icmp->icmpv6_data = 0;
	icmp->icmpv6_cksum = 0;
	ipv6_icmp_init_link_option(ipv6_context,
				   (pICMPV6_OPT_LINK_ADDR) ((u8_t *) icmp +
							    sizeof(ICMPV6_HDR) +
							    sizeof(IPV6_ADDR)),
				   IPV6_ICMP_OPTION_SRC_ADDR);
	ipv6->ipv6_plen =
	    HOST_TO_NET16((sizeof(ICMPV6_HDR) + sizeof(ICMPV6_OPT_LINK_ADDR) +
			   sizeof(IPV6_ADDR)));
	/* Total packet size */
	pkt_len = (u8_t *) icmp - (u8_t *) eth +
	    sizeof(ICMPV6_HDR) +
	    sizeof(ICMPV6_OPT_LINK_ADDR) + sizeof(IPV6_ADDR);
	ipv6_setup_hdrs(ipv6_context, eth, ipv6, pkt_len);
	return pkt_len;
}

STATIC void ipv6_icmp_init_link_option(pIPV6_CONTEXT ipv6_context,
				       pICMPV6_OPT_LINK_ADDR link_opt,
				       u8_t type)
{
	link_opt->hdr.type = type;
	link_opt->hdr.len = sizeof(ICMPV6_OPT_LINK_ADDR) / 8;
	memcpy((char __FAR__ *)&link_opt->link_addr,
	       (char __FAR__ *)&ipv6_context->mac_addr, sizeof(MAC_ADDRESS));
}

STATIC void ipv6_icmp_rx(pIPV6_CONTEXT ipv6_context)
{
	pIPV6_HDR ipv6 = (pIPV6_HDR) ipv6_context->ustack->network_layer;
	pICMPV6_HDR icmp = (pICMPV6_HDR) ((u8_t *) ipv6 + sizeof(IPV6_HDR));

	switch (icmp->icmpv6_type) {
	case ICMPV6_RTR_ADV:
		ipv6_icmp_handle_router_adv(ipv6_context);
		break;

	case ICMPV6_NEIGH_SOL:
		ipv6_icmp_handle_nd_sol(ipv6_context);
		break;

	case ICMPV6_NEIGH_ADV:
		ipv6_icmp_handle_nd_adv(ipv6_context);
		break;

	case ICMPV6_ECHO_REQUEST:
		/* Response with ICMP reply */
		ipv6_icmp_handle_echo_request(ipv6_context);
		break;

	default:
		break;
	}
}

STATIC void ipv6_icmp_handle_router_adv(pIPV6_CONTEXT ipv6_context)
{
	pIPV6_HDR ipv6 = (pIPV6_HDR) ipv6_context->ustack->network_layer;
	pICMPV6_ROUTER_ADVERT icmp =
	    (pICMPV6_ROUTER_ADVERT) ((u8_t *) ipv6 + sizeof(IPV6_HDR));
	pICMPV6_OPT_HDR icmp_opt;
	u16_t opt_len;
	u16_t len;
	char buf[INET6_ADDRSTRLEN];

	if (ipv6_context->flags & IPV6_FLAGS_ROUTER_ADV_RECEIVED)
		return;

	opt_len = HOST_TO_NET16(ipv6->ipv6_plen) - sizeof(ICMPV6_ROUTER_ADVERT);

	icmp_opt = (pICMPV6_OPT_HDR) ((u8_t __FAR__ *) icmp +
				      sizeof(ICMPV6_ROUTER_ADVERT));
	len = 0;
	while (len < opt_len) {
		icmp_opt = (pICMPV6_OPT_HDR) ((u8_t __FAR__ *) icmp +
					      sizeof(ICMPV6_ROUTER_ADVERT) +
					      len);

		switch (icmp_opt->type) {
		case IPV6_ICMP_OPTION_PREFIX:
			ipv6_icmp_process_prefix(ipv6_context,
						 (pICMPV6_OPT_PREFIX) icmp_opt);
			ipv6_context->flags |= IPV6_FLAGS_ROUTER_ADV_RECEIVED;
			break;

		default:
			break;
		}

		len += icmp_opt->len * 8;
	}

	if (ipv6_context->flags & IPV6_FLAGS_ROUTER_ADV_RECEIVED) {
		LOG_DEBUG("IPV6: RTR ADV nd_ra_flags=0x%x",
			  icmp->nd_ra_flags_reserved);
		if (icmp->nd_ra_curhoplimit > 0)
			ipv6_context->hop_limit = icmp->nd_ra_curhoplimit;

		if (icmp->nd_ra_flags_reserved & IPV6_RA_MANAGED_FLAG)
			ipv6_context->flags |= IPV6_FLAGS_MANAGED_ADDR_CONFIG;

		if (icmp->nd_ra_flags_reserved & IPV6_RA_CONFIG_FLAG)
			ipv6_context->flags |= IPV6_FLAGS_OTHER_STATEFUL_CONFIG;

		if (icmp->nd_ra_router_lifetime != 0) {
			/* There is a default router. */
			if (ipv6_context->ustack->router_autocfg !=
			    IPV6_RTR_AUTOCFG_OFF)
				memcpy(
				   (char __FAR__*)&ipv6_context->default_router,
				       (char __FAR__*)&ipv6->ipv6_src,
				       sizeof(IPV6_ADDR));
			inet_ntop(AF_INET6, &ipv6_context->default_router,
				  buf, sizeof(buf));
			LOG_DEBUG("IPV6: Got default router IP: %s", buf)
		}
	}
}

STATIC void ipv6_icmp_process_prefix(pIPV6_CONTEXT ipv6_context,
				     pICMPV6_OPT_PREFIX icmp_prefix)
{
	IPV6_ADDR addr;

	/* we only process on-link address info */
	if (!(icmp_prefix->flags & ICMPV6_OPT_PREFIX_FLAG_ON_LINK))
		return;

	/* 
	 * We only process prefix length of 64 since our Identifier is 64-bit
	 */
	if (icmp_prefix->prefix_len == 64) {
		/* Copy 64-bit from the local-link address to create IPv6 address */
		memcpy((char __FAR__ *)&addr,
		       (char __FAR__ *)&icmp_prefix->prefix, 8);
		memcpy((char __FAR__ *)&addr.addr8[8],
		       &ipv6_context->link_local_addr.addr8[8], 8);
		ipv6_add_prefix_entry(ipv6_context, &addr, 64);
	}
}

STATIC void ipv6_icmp_handle_nd_adv(pIPV6_CONTEXT ipv6_context)
{
	pETH_HDR eth = (pETH_HDR) ipv6_context->ustack->data_link_layer;
	pIPV6_HDR ipv6 = (pIPV6_HDR) ipv6_context->ustack->network_layer;
	pICMPV6_HDR icmp = (pICMPV6_HDR) ((u8_t *) ipv6 + sizeof(IPV6_HDR));
	pICMPV6_OPT_LINK_ADDR link_opt = (pICMPV6_OPT_LINK_ADDR)((u8_t *)icmp +
					sizeof(ICMPV6_HDR) + sizeof(IPV6_ADDR));
	pIPV6_ADDR tar_addr6;

	/* Added the multicast check for ARP table update */
	/* Should we qualify for only our host's multicast and our
	   link_local_multicast?? */
	LOG_DEBUG("IPV6: Handle nd adv");
	if ((ipv6_is_it_our_address(ipv6_context, &ipv6->ipv6_dst) == TRUE) ||
	    (memcmp((char __FAR__ *)&ipv6_context->link_local_multi,
		    (char __FAR__ *)&ipv6->ipv6_dst, sizeof(IPV6_ADDR)) == 0) ||
	    (memcmp((char __FAR__ *)&ipv6_context->multi,
		    (char __FAR__ *)&ipv6->ipv6_dst, sizeof(IPV6_ADDR)) == 0)) {
		/*
		 * This is an ARP reply for our addresses. Let's update the
		 * ARP table.
		 */
		ipv6_update_arp_table(ipv6_context, &ipv6->ipv6_src,
				      &eth->src_mac);

		/* Now check for the target address option and update that as
		   well */
		if (link_opt->hdr.type == IPV6_ICMP_OPTION_TAR_ADDR) {
			tar_addr6 = (pIPV6_ADDR)((u8_t *)icmp +
				    sizeof(ICMPV6_HDR));
			LOG_DEBUG("IPV6: tar mac %x:%x:%x:%x:%x:%x",
				link_opt->link_addr[0], link_opt->link_addr[1],
				link_opt->link_addr[2], link_opt->link_addr[3],
				link_opt->link_addr[4], link_opt->link_addr[5]);
			LOG_DEBUG("IPV6: tar addr "
				  "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x "
				  "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
				  tar_addr6->addr8[0], tar_addr6->addr8[1],
				  tar_addr6->addr8[2], tar_addr6->addr8[3],
				  tar_addr6->addr8[4], tar_addr6->addr8[5],
				  tar_addr6->addr8[6], tar_addr6->addr8[7],
				  tar_addr6->addr8[8], tar_addr6->addr8[9],
				  tar_addr6->addr8[10], tar_addr6->addr8[11],
				  tar_addr6->addr8[12], tar_addr6->addr8[13],
				  tar_addr6->addr8[14], tar_addr6->addr8[15]);
			ipv6_update_arp_table(ipv6_context, tar_addr6,
					      (MAC_ADDR *)link_opt->link_addr);
		}

	}
}

STATIC void ipv6_icmp_handle_nd_sol(pIPV6_CONTEXT ipv6_context)
{
	pETH_HDR eth = (pETH_HDR) ipv6_context->ustack->data_link_layer;
	pIPV6_HDR ipv6 = (pIPV6_HDR) ipv6_context->ustack->network_layer;
	pICMPV6_HDR icmp = (pICMPV6_HDR) ((u8_t *) ipv6 + sizeof(IPV6_HDR));
	pICMPV6_OPT_LINK_ADDR link_opt = (pICMPV6_OPT_LINK_ADDR)((u8_t *)icmp +
					sizeof(ICMPV6_HDR) + sizeof(IPV6_ADDR));
	int icmpv6_opt_len = 0;
	IPV6_ADDR tmp;
	pIPV6_ADDR longest_match_addr;
	pIPV6_ADDR tar_addr6;

	LOG_DEBUG("IPV6: Handle nd sol");

	if ((memcmp((char __FAR__ *)&ipv6_context->mac_addr,
		    (char __FAR__ *)eth->dest_mac, sizeof(MAC_ADDR)) != 0) &&
	    (iscsiL2IsOurMcAddr(ipv6_context, (pMAC_ADDRESS) & eth->dest_mac) ==
	     FALSE)) {
		/* This packet is not for us to handle */
		LOG_DEBUG("IPV6: MAC not addressed to us %x:%x:%x:%x:%x:%x",
			  eth->dest_mac[0], eth->dest_mac[1],
			  eth->dest_mac[2], eth->dest_mac[3],
			  eth->dest_mac[4], eth->dest_mac[5]);
		return;
	}

	/* Also check for the icmpv6_data before generating the reply */
	if (ipv6_is_it_our_address(ipv6_context,
				   (IPV6_ADDR *) ((u8_t *) icmp +
						  sizeof(ICMPV6_HDR)))
	    == FALSE) {
		/* This packet is not for us to handle */
		LOG_DEBUG("IPV6: IP not addressed to us");
		return;
	}

	/* Copy source MAC to Destination MAC */
	memcpy((char __FAR__ *)&eth->dest_mac,
	       (char __FAR__ *)&eth->src_mac, sizeof(MAC_ADDR));

	/* Dest IP contains source IP */
	memcpy((char __FAR__ *)&tmp,
	       (char __FAR__ *)&ipv6->ipv6_dst, sizeof(IPV6_ADDR));
	memcpy((char __FAR__ *)&ipv6->ipv6_dst,
	       (char __FAR__ *)&ipv6->ipv6_src, sizeof(IPV6_ADDR));

	/* Examine the Neighbor Solicitation ICMPv6 target address field.
	   If target address exist, use that to find best match src address
	   for the reply */
	if (link_opt->hdr.type == IPV6_ICMP_OPTION_SRC_ADDR) {
		tar_addr6 = (pIPV6_ADDR)((u8_t *)icmp + sizeof(ICMPV6_HDR));
		if (ipv6_is_it_our_link_local_address(ipv6_context, tar_addr6)
		    == TRUE) {
			LOG_DEBUG("IPV6: NA using link local");
			memcpy((char __FAR__ *)&ipv6->ipv6_src,  
			       (char __FAR__ *)&ipv6_context->link_local_addr,
			       sizeof(IPV6_ADDR));
		} else {
			longest_match_addr =
			      ipv6_find_longest_match(ipv6_context, tar_addr6);
			if (longest_match_addr) {
				LOG_DEBUG("IPV6: NA using longest match addr");
				memcpy((char __FAR__ *)&ipv6->ipv6_src,  
				       (char __FAR__ *)longest_match_addr,
				       sizeof(IPV6_ADDR));
			} else {
				LOG_DEBUG("IPV6: NA using link local instead");
				memcpy((char __FAR__ *)&ipv6->ipv6_src,  
				(char __FAR__ *)&ipv6_context->link_local_addr,
				       sizeof(IPV6_ADDR));
			}
		}
	} else {
		/* No target link address, just use whatever it sent to us */
		LOG_DEBUG("IPV6: NA use dst addr");
		memcpy((char __FAR__ *)&ipv6->ipv6_src,
		       (char __FAR__ *)&tmp,
		       sizeof(IPV6_ADDR));
	}
	ipv6->ipv6_hop_limit = 255;
	icmp->icmpv6_type = ICMPV6_NEIGH_ADV;
	icmp->icmpv6_code = 0;
	icmp->icmpv6_data = 0;
	icmp->icmpv6_cksum = 0;
	icmp->data.icmpv6_un_data8[0] =
	    IPV6_NA_FLAG_SOLICITED | IPV6_NA_FLAG_OVERRIDE;
	memcpy((char __FAR__ *)((u8_t *) icmp + sizeof(ICMPV6_HDR)),
	       (char __FAR__ *)&ipv6->ipv6_src,
	       sizeof(IPV6_ADDR));

	/* Add the target link address option only for all solicitation */
/*
	if ((memcmp((char __FAR__ *)&ipv6_context->multi_dest,
		    (char __FAR__ *)&tmp, sizeof(IPV6_ADDR)) == 0) ||
	    (memcmp((char __FAR__ *)&ipv6_context->link_local_multi,
		    (char __FAR__ *)&tmp, sizeof(IPV6_ADDR)) == 0)) {
*/
		ipv6_icmp_init_link_option(ipv6_context,
					   (pICMPV6_OPT_LINK_ADDR) ((u8_t *)
								    icmp +
								    sizeof
								    (ICMPV6_HDR)
								    +
								    sizeof
								    (IPV6_ADDR)),
					   IPV6_ICMP_OPTION_TAR_ADDR);
		icmpv6_opt_len = sizeof(ICMPV6_OPT_LINK_ADDR);
/*
	}
*/
	ipv6->ipv6_plen = HOST_TO_NET16((sizeof(ICMPV6_HDR) +
					 icmpv6_opt_len + sizeof(IPV6_ADDR)));
	LOG_DEBUG("IPV6: Send nd adv");
	ipv6_send(ipv6_context,
		  (u8_t *) icmp - (u8_t *) eth +
		  sizeof(ICMPV6_HDR) +
		  sizeof(ICMPV6_OPT_LINK_ADDR) + sizeof(IPV6_ADDR));
	return;
}

STATIC void ipv6_icmp_handle_echo_request(pIPV6_CONTEXT ipv6_context)
{
	pETH_HDR eth = (pETH_HDR) ipv6_context->ustack->data_link_layer;
	pIPV6_HDR ipv6 = (pIPV6_HDR) ipv6_context->ustack->network_layer;
	pICMPV6_HDR icmp = (pICMPV6_HDR) ((u8_t *) ipv6 + sizeof(IPV6_HDR));
	IPV6_ADDR temp;

	/* Copy source MAC to Destination MAC */
	memcpy((char __FAR__ *)&eth->dest_mac,
	       (char __FAR__ *)&eth->src_mac, sizeof(MAC_ADDR));

	memcpy((char __FAR__ *)&temp,
	       (char __FAR__ *)&ipv6->ipv6_dst, sizeof(IPV6_ADDR));

	/* Dest IP contains source IP */
	memcpy((char __FAR__ *)&ipv6->ipv6_dst,
	       (char __FAR__ *)&ipv6->ipv6_src, sizeof(IPV6_ADDR));
	/* Use Link-local as source address */
	memcpy((char __FAR__ *)&ipv6->ipv6_src,
	       (char __FAR__ *)&temp, sizeof(IPV6_ADDR));

	ipv6->ipv6_hop_limit = ipv6_context->hop_limit;
	icmp->icmpv6_type = ICMPV6_ECHO_REPLY;
	icmp->icmpv6_code = 0;
	icmp->icmpv6_cksum = 0;
	LOG_DEBUG("IPV6: Send echo reply");
	ipv6_send(ipv6_context, (u8_t *) icmp - (u8_t *) eth +
		  sizeof(IPV6_HDR) + HOST_TO_NET16(ipv6->ipv6_plen));
	return;
}

void ipv6_set_ip_params(pIPV6_CONTEXT ipv6_context,
			pIPV6_ADDR src_ip, u8_t prefix_len,
			pIPV6_ADDR default_gateway,
			pIPV6_ADDR linklocal)
{
	if (!(IPV6_IS_ADDR_UNSPECIFIED(src_ip))) {
		ipv6_add_prefix_entry(ipv6_context, src_ip, prefix_len);
		/* Create the multi_dest address */
		memset(&ipv6_context->multi_dest, 0, sizeof(IPV6_ADDR));
		ipv6_context->multi_dest.addr8[0] = 0xff;
		ipv6_context->multi_dest.addr8[1] = 0x02;
		ipv6_context->multi_dest.addr8[11] = 0x01;
		ipv6_context->multi_dest.addr8[12] = 0xff;
		ipv6_context->multi_dest.addr8[13] = src_ip->addr8[13];
		ipv6_context->multi_dest.addr16[7] = src_ip->addr16[7];
		/* Create the multi address */
		memset(&ipv6_context->multi, 0, sizeof(IPV6_ADDR));
		ipv6_context->multi.addr8[0] = 0xfc;
		ipv6_context->multi.addr8[2] = 0x02;
		ipv6_context->multi.addr16[7] = src_ip->addr16[7];
	}

	if (!(IPV6_IS_ADDR_UNSPECIFIED(default_gateway))) {
		/* Override the default gateway addr */
		memcpy((char __FAR__*)&ipv6_context->default_router,
		       (char __FAR__*)default_gateway, sizeof(IPV6_ADDR));
		ipv6_add_prefix_entry(ipv6_context, default_gateway,
				      prefix_len);
	}
	if (!(IPV6_IS_ADDR_UNSPECIFIED(linklocal))) {
		/* Override the linklocal addr */
		memcpy((char __FAR__*)&ipv6_context->link_local_addr,
		       (char __FAR__*)linklocal, sizeof(IPV6_ADDR));
	}
}

int ipv6_get_source_ip_addrs(pIPV6_CONTEXT ipv6_context,
			     pIPV6_ADDR_ENTRY addr_list)
{
	pIPV6_PREFIX_ENTRY ipv6_prefix;
	int i;

	for (i = 0, ipv6_prefix = ipv6_context->addr_list; ipv6_prefix != NULL;
	     ipv6_prefix = ipv6_prefix->next) {
		memcpy((char __FAR__ *)&addr_list->address,
		       (char __FAR__ *)&ipv6_prefix->address,
		       sizeof(IPV6_ADDR));
		addr_list->prefix_len = ipv6_prefix->prefix_len * 8;

		i++;
		addr_list++;
	}

	return i;
}

int ipv6_get_default_router_ip_addrs(pIPV6_CONTEXT ipv6_context,
				     pIPV6_ADDR ip_addr)
{
	/* This is a default router. */
	memcpy((char __FAR__ *)ip_addr,
	       (char __FAR__ *)&ipv6_context->default_router,
	       sizeof(IPV6_ADDR));

	return 1;
}

STATIC void ipv6_udp_rx(pIPV6_CONTEXT ipv6_context)
{
	pETH_HDR eth = (pETH_HDR) ipv6_context->ustack->data_link_layer;
	pIPV6_HDR ipv6 = (pIPV6_HDR) ipv6_context->ustack->network_layer;
	UDP_HDR __FAR__ *udp = (pUDP_HDR) ((u8_t *) ipv6 + sizeof(IPV6_HDR));
	pDHCPV6_CONTEXT dhcpv6c;

	/* 
	 * We only care about DHCPv6 packets from the DHCPv6 server.  We drop 
	 * all others.
	 */
	if (!(ipv6_context->flags & IPV6_FLAGS_DISABLE_DHCPV6)) {
		if ((udp->src_port == HOST_TO_NET16(DHCPV6_SERVER_PORT)) &&
		    (udp->dest_port == HOST_TO_NET16(DHCPV6_CLIENT_PORT))) {
			dhcpv6c = ipv6_context->dhcpv6_context;
			dhcpv6c->eth = eth;
			dhcpv6c->ipv6 = ipv6;
			dhcpv6c->udp = udp;
			ipv6_udp_handle_dhcp(dhcpv6c);
		}
	}
}

MAC_ADDRESS *ipv6_get_link_addr(pIPV6_CONTEXT ipv6_context)
{
	return &ipv6_context->mac_addr;
}

u16_t ipv6_do_stateful_dhcpv6(pIPV6_CONTEXT ipv6_context, u32_t flags)
{
	u16_t task = 0;
	u16_t ra_flags;

	ra_flags = ipv6_context->flags &
	    (IPV6_FLAGS_MANAGED_ADDR_CONFIG | IPV6_FLAGS_OTHER_STATEFUL_CONFIG);

	if (!(ipv6_context->flags & IPV6_FLAGS_ROUTER_ADV_RECEIVED)) {
		LOG_DEBUG("IPV6: There is no IPv6 router on the network");
		ra_flags |=
		    (IPV6_FLAGS_MANAGED_ADDR_CONFIG |
		     IPV6_FLAGS_OTHER_STATEFUL_CONFIG);
	}

	if ((flags & ISCSI_FLAGS_DHCP_TCPIP_CONFIG) &&
	    (ra_flags & IPV6_FLAGS_MANAGED_ADDR_CONFIG))
		task |= DHCPV6_TASK_GET_IP_ADDRESS;

	if ((flags & ISCSI_FLAGS_DHCP_ISCSI_CONFIG) &&
	    (ra_flags & IPV6_FLAGS_OTHER_STATEFUL_CONFIG))
		task |= DHCPV6_TASK_GET_OTHER_PARAMS;

	LOG_DEBUG("IPV6: Stateful flags=0x%x, ra_flags=0x%x, task=0x%x", flags,
		  ra_flags, task);

	return task;
}

void ipv6_add_solit_node_address(pIPV6_CONTEXT ipv6_context, pIPV6_ADDR ip_addr)
{
	MAC_ADDRESS mac_addr;

	/* 
	 * Add Solicited Node Multicast Address for statically configured IPv6 
	 * address.
	 */
	mac_addr.addr[0] = 0x33;
	mac_addr.addr[1] = 0x33;
	mac_addr.addr[2] = 0xff;
	mac_addr.addr[3] = ip_addr->addr8[13];
	mac_addr.addr[4] = ip_addr->addr8[14];
	mac_addr.addr[5] = ip_addr->addr8[15];
	iscsiL2AddMcAddr(ipv6_context, (MAC_ADDR *) & mac_addr);
}

void ipv6_cfg_link_local_addr(pIPV6_CONTEXT ipv6_context, pIPV6_ADDR ip_addr)
{
	memcpy((char __FAR__ *)&ipv6_context->link_local_addr,
	       (char __FAR__ *)ip_addr, sizeof(IPV6_ADDR));
}

void ipv6_disable_dhcpv6(pIPV6_CONTEXT ipv6_context)
{
	ipv6_context->flags |= IPV6_FLAGS_DISABLE_DHCPV6;
}
