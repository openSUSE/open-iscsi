/*
 * Copyright (c) 2011, Broadcom Corporation
 *
 * Written by:  Eddie Wai <eddie.wai@broadcom.com>
 *              Based on code from Kevin Tran's iSCSI boot code
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
 * dhcpv6.c - DHCPv6 engine
 *
 */
#include <stdio.h>
#include <string.h>

#include "ipv6.h"
#include "ipv6_pkt.h"
#include "dhcpv6.h"
#include "logger.h"

/* Local function prototypes */
STATIC int dhcpv6_send_solicit_packet(pDHCPV6_CONTEXT dhcpv6_context);
STATIC int dhcpv6_send_request_packet(pDHCPV6_CONTEXT dhcpv6_context);
STATIC u16_t dhcpv6_init_packet(pDHCPV6_CONTEXT dhcpv6_context, u8_t type);
STATIC void dhcpv6_init_dhcpv6_server_addr(pIPV6_ADDR addr);
//STATIC int dhcpv6_wait_for_dhcp_done(pPACKET_IPV6 pkt,int timeout);
STATIC void dhcpv6_handle_advertise(pDHCPV6_CONTEXT dhcpv6_context,
				    u16_t dhcpv6_len);
STATIC void dhcpv6_handle_reply(pDHCPV6_CONTEXT dhcpv6_context,
				u16_t dhcpv6_len);
STATIC int dhcpv6_process_opt_ia_na(pDHCPV6_CONTEXT dhcpv6_context,
				    pDHCPV6_OPT_HDR opt_hdr);
STATIC void dhcpv6_process_opt_dns_servers(pDHCPV6_CONTEXT dhcpv6_context,
					   pDHCPV6_OPT_HDR opt_hdr);
STATIC void dhcpv6_parse_vendor_option(pDHCPV6_CONTEXT dhcpv6_context,
				       u8_t * option, int len);

void dhcpv6_init(pDHCPV6_CONTEXT dhcpv6_context)
{
	dhcpv6_context->seconds = 0;
	dhcpv6_context->our_mac_addr =
	    ipv6_get_link_addr(dhcpv6_context->ipv6_context);

	/* Use the last four bytes of MAC address as base of the transaction
	   ID */
	dhcpv6_context->dhcpv6_transaction_id =
	    *((u32_t *) & dhcpv6_context->our_mac_addr->addr[2]) & 0xffffffL;

	dhcpv6_context->dhcpv6_done = FALSE;
	strcpy(dhcpv6_context->dhcp_vendor_id, "BRCM ISAN");
}

int dhcpv6_do_discovery(pDHCPV6_CONTEXT dhcpv6_context)
{
	int retc = ISCSI_FAILURE;

	dhcpv6_context->eth =
	    (pETH_HDR) dhcpv6_context->ipv6_context->ustack->data_link_layer;
	dhcpv6_context->ipv6 =
	    (pIPV6_HDR) dhcpv6_context->ipv6_context->ustack->network_layer;
	dhcpv6_context->udp =
	    (pUDP_HDR) ((u8_t *) dhcpv6_context->ipv6 + sizeof(IPV6_HDR));

	/* Send out DHCPv6 Solicit packet. */
	dhcpv6_send_solicit_packet(dhcpv6_context);

	return retc;
}

STATIC int dhcpv6_send_solicit_packet(pDHCPV6_CONTEXT dhcpv6_context)
{
	u16_t packet_len;

	LOG_DEBUG("DHCPV6: Send solicit");
	packet_len = dhcpv6_init_packet(dhcpv6_context, DHCPV6_SOLICIT);
	dhcpv6_context->dhcpv6_state = DHCPV6_STATE_SOLICIT_SENT;
	ipv6_send_udp_packet(dhcpv6_context->ipv6_context, packet_len);

	return 0;
}

STATIC int dhcpv6_send_request_packet(pDHCPV6_CONTEXT dhcpv6_context)
{
	u16_t packet_len;

	LOG_DEBUG("DHCPV6: Send request");
	packet_len = dhcpv6_init_packet(dhcpv6_context, DHCPV6_REQUEST);

	dhcpv6_context->dhcpv6_state = DHCPV6_STATE_REQ_SENT;
	ipv6_send_udp_packet(dhcpv6_context->ipv6_context, packet_len);

	return 0;
}

STATIC u16_t dhcpv6_init_packet(pDHCPV6_CONTEXT dhcpv6_context, u8_t type)
{
	u16_t pkt_len;
	UDP_HDR *udp = dhcpv6_context->udp;
	pDHCPV6_HDR dhcpv6;
	pDHCPV6_OPTION opt;
	u16_t len;

	/* Initialize dest IP with well-known DHCP server address */
	dhcpv6_init_dhcpv6_server_addr(&dhcpv6_context->ipv6->ipv6_dst);
	/* Initialize dest MAC based on MC dest IP */
	ipv6_mc_init_dest_mac(dhcpv6_context->eth, dhcpv6_context->ipv6);

	/* Initialize UDP header */
	udp->src_port = HOST_TO_NET16(DHCPV6_CLIENT_PORT);
	udp->dest_port = HOST_TO_NET16(DHCPV6_SERVER_PORT);

	/* 
	 * DHCPv6 section has the following format per RFC 3315
	 *
	 *  0                   1                   2                   3
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |    msg-type   |               transaction-id                  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                                                               |
	 * .                            options                            .
	 * .                           (variable)                          .
	 * |                                                               |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	dhcpv6 = (pDHCPV6_HDR) ((u8_t *) udp + sizeof(UDP_HDR));

	if (dhcpv6->dhcpv6_type != type) {
		dhcpv6_context->dhcpv6_transaction_id++;
	}

	dhcpv6->dhcpv6_trans_id = dhcpv6_context->dhcpv6_transaction_id;
	dhcpv6->dhcpv6_type = type;

	/* Keep track of length of all DHCP options. */
	pkt_len = sizeof(DHCPV6_HDR);

	if (dhcpv6->dhcpv6_type == DHCPV6_REQUEST) {
		/* We will send back whatever DHCPv6 sent us */
		return ((u8_t *) udp - (u8_t *) dhcpv6_context->eth +
			NET_TO_HOST16(udp->length));
	}

	opt = (pDHCPV6_OPTION) ((u8_t *) dhcpv6 + sizeof(DHCPV6_HDR));
	/* Add client ID option */
	opt->hdr.type = HOST_TO_NET16(DHCPV6_OPT_CLIENTID);
	opt->hdr.length = HOST_TO_NET16(sizeof(DHCPV6_OPT_CLIENT_ID));
	opt->type.client_id.duid_type =
	    HOST_TO_NET16(DHCPV6_DUID_TYPE_LINK_LAYER_AND_TIME);
	opt->type.client_id.hw_type = HOST_TO_NET16(DHCPV6_HW_TYPE_ETHERNET);
	opt->type.client_id.time = HOST_TO_NET32(clock_time()/1000 -
						 0x3A4FC880);
	memcpy((char __FAR__ *)&opt->type.client_id.link_layer_addr,
	       (char __FAR__ *)dhcpv6_context->our_mac_addr, sizeof(MAC_ADDR));
	pkt_len += sizeof(DHCPV6_OPT_CLIENT_ID) + sizeof(DHCPV6_OPT_HDR);
	opt = (pDHCPV6_OPTION) ((u8_t *) opt + sizeof(DHCPV6_OPT_CLIENT_ID) +
				sizeof(DHCPV6_OPT_HDR));

	/* Add Vendor Class option if it's configured */
	if ((len = strlen(dhcpv6_context->dhcp_vendor_id)) > 0) {
		opt->hdr.type = HOST_TO_NET16(DHCPV6_OPT_VENDOR_CLASS);
		opt->hdr.length = HOST_TO_NET16(sizeof(DHCPV6_VENDOR_CLASS) +
						len - 1);
		opt->type.vendor_class.enterprise_number =
		    HOST_TO_NET32(IANA_ENTERPRISE_NUM_BROADCOM);
		opt->type.vendor_class.vendor_class_length = HOST_TO_NET16(len);
		memcpy((char __FAR__ *)&opt->type.vendor_class.
		       vendor_class_data[0],
		       (char __FAR__ *)dhcpv6_context->dhcp_vendor_id, len);
		pkt_len +=
		    sizeof(DHCPV6_VENDOR_CLASS) - 1 + len +
		    sizeof(DHCPV6_OPT_HDR);
		opt =
		    (pDHCPV6_OPTION) ((u8_t *) opt +
				      sizeof(DHCPV6_VENDOR_CLASS) - 1 + len +
				      sizeof(DHCPV6_OPT_HDR));
	}

	/* Add IA_NA option */
	opt->hdr.type = HOST_TO_NET16(DHCPV6_OPT_IA_NA);
	opt->hdr.length = HOST_TO_NET16(sizeof(DHCPV6_OPT_ID_ASSOC_NA));
	opt->type.ida_na.iaid =
	    htonl(*((u32_t *) & dhcpv6_context->our_mac_addr->addr[2]));
	opt->type.ida_na.t1 = 0;
	opt->type.ida_na.t2 = 0;
	pkt_len += sizeof(DHCPV6_OPT_ID_ASSOC_NA) + sizeof(DHCPV6_OPT_HDR);
	opt = (pDHCPV6_OPTION) ((u8_t *) opt + sizeof(DHCPV6_OPT_ID_ASSOC_NA) +
				sizeof(DHCPV6_OPT_HDR));
	/* Add Elapsed Time option */
	opt->hdr.type = HOST_TO_NET16(DHCPV6_OPT_ELAPSED_TIME);
	opt->hdr.length = HOST_TO_NET16(sizeof(DHCPV6_OPT_ELAPSE_TIME));
	opt->type.elapsed_time.time = HOST_TO_NET16(dhcpv6_context->seconds);
	pkt_len += sizeof(DHCPV6_OPT_ELAPSE_TIME) + sizeof(DHCPV6_OPT_HDR);

	/* Add Option Request List */
	opt = (pDHCPV6_OPTION) ((u8_t *) opt + sizeof(DHCPV6_OPT_ELAPSE_TIME) +
				sizeof(DHCPV6_OPT_HDR));
	opt->hdr.type = HOST_TO_NET16(DHCPV6_OPT_ORO);
	opt->hdr.length = HOST_TO_NET16(3 * sizeof(DHCPV6_OPT_REQUEST_LIST));
	opt->type.list.request_code[0] = HOST_TO_NET16(DHCPV6_OPT_VENDOR_CLASS);
	opt->type.list.request_code[1] = HOST_TO_NET16(DHCPV6_OPT_VENDOR_OPTS);
	opt->type.list.request_code[2] = HOST_TO_NET16(DHCPV6_OPT_DNS_SERVERS);
	pkt_len += 3 * sizeof(DHCPV6_OPT_REQUEST_LIST) + sizeof(DHCPV6_OPT_HDR);

	udp->length = HOST_TO_NET16(sizeof(UDP_HDR) + pkt_len);

	pkt_len +=
	    ((u8_t *) udp - (u8_t *) dhcpv6_context->eth) + sizeof(UDP_HDR);

	return pkt_len;
}

STATIC void dhcpv6_init_dhcpv6_server_addr(pIPV6_ADDR addr)
{
	/* Well-known DHCPv6 server address is ff02::1:2 */
	memset((char __FAR__ *)addr, 0, sizeof(IPV6_ADDR));
	addr->addr8[0] = 0xff;
	addr->addr8[1] = 0x02;
	addr->addr8[13] = 0x01;
	addr->addr8[15] = 0x02;
}

void ipv6_udp_handle_dhcp(pDHCPV6_CONTEXT dhcpv6_context)
{
	pDHCPV6_HDR dhcpv6;
	u16_t dhcpv6_len;

	if (dhcpv6_context->dhcpv6_done == TRUE)
		return;

	dhcpv6 = (pDHCPV6_HDR) ((u8_t *) dhcpv6_context->udp + sizeof(UDP_HDR));

	if (dhcpv6->dhcpv6_trans_id != dhcpv6_context->dhcpv6_transaction_id)
		return;

	dhcpv6_len =
	    NET_TO_HOST16(dhcpv6_context->udp->length) - sizeof(UDP_HDR);

	switch (dhcpv6->dhcpv6_type) {
	case DHCPV6_ADVERTISE:
		dhcpv6_handle_advertise(dhcpv6_context, dhcpv6_len);
		break;

	case DHCPV6_REPLY:
		dhcpv6_handle_reply(dhcpv6_context, dhcpv6_len);
		break;

	default:
		break;
	}
}

STATIC void dhcpv6_handle_advertise(pDHCPV6_CONTEXT dhcpv6_context,
				    u16_t dhcpv6_len)
{
	pDHCPV6_HDR dhcpv6 =
	    (pDHCPV6_HDR) ((u8_t *) dhcpv6_context->udp + sizeof(UDP_HDR));
	pDHCPV6_OPT_HDR opt;
	u16_t type;
	int i;
	int opt_len;
	u8_t *vendor_id = NULL;
	u16_t vendor_id_len = 0;
	u8_t *vendor_opt_data = NULL;
	int vendor_opt_len = 0;
	int addr_cnt = 0;

	/* We only handle DHCPv6 advertise if we recently sent DHCPv6 solicit */
	if (dhcpv6_context->dhcpv6_state != DHCPV6_STATE_SOLICIT_SENT)
		return;

	LOG_DEBUG("DHCPV6: handle advertise");
	dhcpv6_context->dhcpv6_state = DHCPV6_STATE_ADV_RCVD;

	i = 0;
	while (i < (dhcpv6_len - sizeof(DHCPV6_HDR))) {
		opt =
		    (pDHCPV6_OPT_HDR) ((u8_t *) dhcpv6 + sizeof(DHCPV6_HDR) +
				       i);
		opt_len = NET_TO_HOST16(opt->length);

		type = NET_TO_HOST16(opt->type);

		/* We only care about some of the options */
		switch (type) {
		case DHCPV6_OPT_IA_NA:
			if (dhcpv6_context->
			    dhcpv6_task & DHCPV6_TASK_GET_IP_ADDRESS) {
				addr_cnt +=
				    dhcpv6_process_opt_ia_na(dhcpv6_context,
							     opt);
			}
			break;

		case DHCPV6_OPT_VENDOR_CLASS:
			vendor_id_len =
			    NET_TO_HOST16(((pDHCPV6_OPTION) opt)->type.
					  vendor_class.vendor_class_length);
			vendor_id =
			    &((pDHCPV6_OPTION) opt)->type.vendor_class.
			    vendor_class_data[0];
			break;

		case DHCPV6_OPT_VENDOR_OPTS:
			vendor_opt_len = opt_len - 4;
			vendor_opt_data =
			    &((pDHCPV6_OPTION) opt)->type.vendor_opts.
			    vendor_opt_data[0];
			break;

		case DHCPV6_OPT_DNS_SERVERS:
			if (dhcpv6_context->
			    dhcpv6_task & DHCPV6_TASK_GET_OTHER_PARAMS)
				dhcpv6_process_opt_dns_servers(dhcpv6_context,
							       opt);
			break;

		default:
			break;
		}

		i += NET_TO_HOST16(opt->length) + sizeof(DHCPV6_OPT_HDR);
	}

	if (dhcpv6_context->dhcpv6_task & DHCPV6_TASK_GET_OTHER_PARAMS) {
		if ((vendor_id_len > 0) &&
		    (strncmp((char __FAR__ *)vendor_id,
			     (char __FAR__ *)dhcpv6_context->dhcp_vendor_id,
			     vendor_id_len) == 0)) {
			dhcpv6_parse_vendor_option(dhcpv6_context,
						   vendor_opt_data,
						   vendor_opt_len);
			dhcpv6_context->dhcpv6_done = TRUE;
		}
	}

	if (dhcpv6_context->dhcpv6_task & DHCPV6_TASK_GET_IP_ADDRESS) {
		if (addr_cnt > 0) {
			/* 
			 * If we need to acquire IP address from the server,
			 * we need to send Request to server to confirm.
			 */
			dhcpv6_send_request_packet(dhcpv6_context);
			dhcpv6_context->dhcpv6_done = TRUE;
		}
	}

	if (dhcpv6_context->dhcpv6_done) {
		/* Keep track of IPv6 address of DHCHv6 server */
		memcpy((char __FAR__ *)&dhcpv6_context->dhcp_server,
		       (char __FAR__ *)&dhcpv6_context->ipv6->ipv6_src,
		       sizeof(IPV6_ADDR));
	}
}

STATIC int dhcpv6_process_opt_ia_na(pDHCPV6_CONTEXT dhcpv6_context,
				    pDHCPV6_OPT_HDR opt_hdr)
{
	int i;
	int opt_len;
	pDHCPV6_OPTION opt;
	int len;
	int addr_cnt;
	opt_len =
	    NET_TO_HOST16(opt_hdr->length) - sizeof(DHCPV6_OPT_ID_ASSOC_NA);

	i = 0;
	addr_cnt = 0;
	while (i < opt_len) {
		opt =
		    (pDHCPV6_OPTION) ((u8_t *) opt_hdr +
				      sizeof(DHCPV6_OPT_HDR) +
				      sizeof(DHCPV6_OPT_ID_ASSOC_NA) + i);

		len = NET_TO_HOST16(opt->hdr.length);
		switch (NET_TO_HOST16(opt->hdr.type)) {
		case DHCPV6_OPT_IAADDR:
			if (len >
			    (sizeof(DHCPV6_OPT_HDR) +
			     sizeof(DHCPV6_OPT_IAA_ADDR))) {
				pDHCPV6_OPTION in_opt;

				in_opt =
				    (pDHCPV6_OPTION) ((u8_t *) opt +
						      sizeof(DHCPV6_OPT_HDR) +
						      sizeof
						      (DHCPV6_OPT_IAA_ADDR));
				if (in_opt->hdr.type ==
				    HOST_TO_NET16(DHCPV6_OPT_STATUS_CODE)) {
					/* This entry has error! */
					if (in_opt->type.sts.status != 0)
						break;
				}
			}
			LOG_INFO("DHCPv6: Got IP Addr");
			/* Status is OK, let's add this addr to our address
			   list */
			ipv6_add_prefix_entry(dhcpv6_context->ipv6_context,
					      &opt->type.iaa_addr.addr, 64);

			/* Add multicast address for this address */
			ipv6_add_solit_node_address(dhcpv6_context->
						    ipv6_context,
						    &opt->type.iaa_addr.addr);
			addr_cnt++;
			break;

		default:
			break;
		}

		i += len + sizeof(DHCPV6_OPT_HDR);
	}

	return addr_cnt;
}

STATIC void dhcpv6_process_opt_dns_servers(pDHCPV6_CONTEXT dhcpv6_context,
					   pDHCPV6_OPT_HDR opt_hdr)
{
	int opt_len;

	opt_len = NET_TO_HOST16(opt_hdr->length);

	if (opt_len >= sizeof(IPV6_ADDR)) {
		memcpy((char __FAR__ *)&dhcpv6_context->primary_dns_server,
		       (char __FAR__ *)&((pDHCPV6_OPTION) opt_hdr)->type.dns.
		       primary_addr, sizeof(IPV6_ADDR));
	}

	if (opt_len >= 2 * sizeof(IPV6_ADDR)) {
		memcpy((char __FAR__ *)&dhcpv6_context->secondary_dns_server,
		       (char __FAR__ *)&((pDHCPV6_OPTION) opt_hdr)->type.dns.
		       secondary_addr, sizeof(IPV6_ADDR));
	}
}

STATIC void dhcpv6_handle_reply(pDHCPV6_CONTEXT dhcpv6_context,
				u16_t dhcpv6_len)
{
	if (dhcpv6_context->dhcpv6_state != DHCPV6_STATE_REQ_SENT)
		return;

	dhcpv6_context->dhcpv6_done = TRUE;
}

STATIC void dhcpv6_parse_vendor_option(pDHCPV6_CONTEXT dhcpv6_context,
				       u8_t * option, int len)
{
	pDHCPV6_OPTION opt;
	u16_t type;
	int opt_len;
	int data_len;
	int i;
	u8_t *data;

	for (i = 0; i < len; i += opt_len + sizeof(DHCPV6_OPT_HDR)) {
		opt = (pDHCPV6_OPTION) ((u8_t *) option + i);
		type = HOST_TO_NET16(opt->hdr.type);
		opt_len = HOST_TO_NET16(opt->hdr.length);
		data = &opt->type.data[0];
		data_len = strlen((char *)data);

		switch (type) {
		case 201:
			/* iSCSI target 1 */
//          iscsiAddiScsiTargetInfo(data,0);
			break;

		case 202:
			/* iSCSI target 2 */
//          iscsiAddiScsiTargetInfo(data,1);
			break;

		case 203:
			if (data_len > ISCSI_MAX_ISCSI_NAME_LENGTH)
				data_len = ISCSI_MAX_ISCSI_NAME_LENGTH;
			data[data_len] = '\0';
			strcpy(dhcpv6_context->initiatorName, (char *)data);
//          itolowerstr(dhcpv6_context->initiatorName);
			break;

		default:
			break;
		}
	}
}
