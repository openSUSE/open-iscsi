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
 * dhcpv6.h - DHCPv6 engine header
 *
 */
#ifndef __IDHCPV6_H__
#define __IDHCPV6_H__

#include "ipv6_ndpc.h"
#include "ipv6.h"

#ifdef PACK_DATA_STRUCTURE
#pragma pack(push,1)
#endif

#define ISCSI_MAX_ISCSI_NAME_LENGTH 128
/* DHCPv6 Message types. */
#define DHCPV6_SOLICIT               1
#define DHCPV6_ADVERTISE             2
#define DHCPV6_REQUEST               3
#define DHCPV6_CONFIRM               4
#define DHCPV6_RENEW                 5
#define DHCPV6_REBIND                6
#define DHCPV6_REPLY                 7
#define DHCPV6_RELEASE               8
#define DHCPV6_DECLINE               9
#define DHCPV6_RECONFIGURE           10
#define DHCPV6_INFO_REQUEST          11
#define DHCPV6_RELAY_FORW            12
#define DHCPV6_RELAY_REPL            13

/* Option codes. */
#define DHCPV6_OPT_CLIENTID       1	/* Client ID option - built by stack */
#define DHCPV6_OPT_SERVERID       2	/* Server ID option - built by stack */
#define DHCPV6_OPT_IA_NA          3	/* IA_NA option - built by user */
#define DHCPV6_OPT_IA_TA          4	/* IA_TA option - not supported */
#define DHCPV6_OPT_IAADDR         5	/* IA_ADDR option - built by user */
#define DHCPV6_OPT_ORO            6	/* Option Request Option - built by
					   stack */
#define DHCPV6_OPT_PREFERENCE     7	/* Preference option - built by server
					   */
#define DHCPV6_OPT_ELAPSED_TIME   8	/* Elapsed Time option - built by stack
					   */
#define DHCPV6_OPT_RELAY_MSG      9	/* Relay Message option - not supported
					   */
#define DHCPV6_OPT_AUTH           11	/* Authentication option - built by
					   stack */
#define DHCPV6_OPT_UNICAST        12	/* Server Unicast option - built by
					   server */
#define DHCPV6_OPT_STATUS_CODE    13	/* Status Code option - built by stack
					   */
#define DHCPV6_OPT_RAPID_COMMIT   14	/* Rapid Commit option - built by user
					   */
#define DHCPV6_OPT_USER_CLASS     15	/* User Class option - built by user */
#define DHCPV6_OPT_VENDOR_CLASS   16	/* Vendor Class option - built by user
					   */
#define DHCPV6_OPT_VENDOR_OPTS    17	/* Vendor-Specific Information option -
					   build by user */
#define DHCPV6_OPT_INTERFACE_ID   18	/* Interface ID option - not supported
					   */
#define DHCPV6_OPT_RECONF_MSG     19	/* Reconfigure Message option - built
					   by server */
#define DHCPV6_OPT_RECONF_ACCEPT  20	/* Reconfigure Accept option - built by
					   user */
#define DHCPV6_OPT_SIP_SERVER_D   21	/* NOT SUPPORTED - included for
					   completeness only */
#define DHCPV6_OPT_SIP_SERVER_A   22	/* NOT SUPPORTED - included for
					   completeness only */
#define DHCPV6_OPT_DNS_SERVERS    23	/* DNS Recursive Name Server option -
					   built by server */
#define DHCPV6_OPT_DOMAIN_LIST    24	/* Domain Search List option - not
					   supported */
#define DHCPV6_MAX_OPT_CODES      25	/* This will be the count + 1 since
					   the parsing array starts 
					   at [1] instead of [0] */

/* Authentication protocol types. */
#define DHCPV6_DELAYED_AUTH_PROT     2	/* Delayed Authentication protocol. */
#define DHCPV6_RECON_KEY_AUTH_PROT   3	/* Reconfigure Key Authentication
					   protocol. */

typedef struct DHCPV6_CONTEXT {
#define DHCP_VENDOR_ID_LEN 128
	char dhcp_vendor_id[DHCP_VENDOR_ID_LEN];
	MAC_ADDRESS *our_mac_addr;
	u32_t dhcpv6_transaction_id;
	u16_t seconds;
	int timeout;
	int dhcpv6_done;

#define DHCPV6_STATE_UNKNOWN       0
#define DHCPV6_STATE_SOLICIT_SENT  1
#define DHCPV6_STATE_ADV_RCVD      2
#define DHCPV6_STATE_REQ_SENT      3
#define DHCPV6_STATE_CONFIRM_SENT  4
	int dhcpv6_state;
	u16_t dhcpv6_task;
	pIPV6_CONTEXT ipv6_context;
	pETH_HDR eth;
	pIPV6_HDR ipv6;
	pUDP_HDR udp;

	char initiatorName[ISCSI_MAX_ISCSI_NAME_LENGTH];
	IPV6_ADDR dhcp_server;
	IPV6_ADDR primary_dns_server;
	IPV6_ADDR secondary_dns_server;

} DHCPV6_CONTEXT, *pDHCPV6_CONTEXT;

typedef union DHCPV6_HDR {
	struct {
		u32_t type:8;
		u32_t trans_id:24;
	} field;

	u32_t type_transaction;
} DHCPV6_HDR, *pDHCPV6_HDR;

#define dhcpv6_type      field.type
#define dhcpv6_trans_id  field.trans_id

typedef struct DHCPV6_OPT_HDR {
	u16_t type;
	u16_t length;
} DHCPV6_OPT_HDR, *pDHCPV6_OPT_HDR;

typedef struct DHCPV6_OPT_CLIENT_ID {
	u16_t duid_type;
#define DHCPV6_DUID_TYPE_LINK_LAYER_AND_TIME 1
#define DHCPV6_DUID_TYPE_VENDOR_BASED        2
#define DHCPV6_DUID_TYPE_LINK_LAYER          3
	u16_t hw_type;
#define DHCPV6_HW_TYPE_ETHERNET              1
	u32_t time;
	MAC_ADDR link_layer_addr;
} DHCPV6_OPT_CLIENT_ID, *pDHCPV6_OPT_CLIENT_ID;

typedef struct DHCPV6_OPT_ID_ASSOC_NA {
	u32_t iaid;
#define DHCPV6_OPT_IA_NA_IAID  0x306373L
	u32_t t1;
	u32_t t2;
} DHCPV6_OPT_ID_ASSOC_NA, *pDHCPV6_OPT_ID_ASSOC_NA;

typedef struct DHCPV6_OPT_ELAPSE_TIME {
	u16_t time;
} DHCPV6_OPT_ELAPSE_TIME, *pDHCPV6_OPT_ELAPSE_TIME;

typedef struct DHCPV6_OPT_IAA_ADDR {
	IPV6_ADDR addr;
	u32_t preferred_lifetime;
	u32_t valid_lifetime;
} DHCPV6_OPT_IAA_ADDR, *pDHCPV6_OPT_IAA_ADDR;

typedef struct DHCPV6_OPT_STATUS {
	u16_t status;
} DHCPV6_OPT_STATUS, *pDHCPV6_OPT_STATUS;

typedef struct DHCPV6_OPT_REQUEST_LIST {
	u16_t request_code[1];
} DHCPV6_OPT_REQUEST_LIST, *pDHCPV6_OPT_REQUEST_LIST;

typedef struct DHCPV6_OPT_DNS {
	IPV6_ADDR primary_addr;
	IPV6_ADDR secondary_addr;
} DHCPV6_OPT_DNS, *pDHCPV6_OPT_DNS;

typedef struct DHCPV6_VENDOR_CLASS {
	u32_t enterprise_number;
	u16_t vendor_class_length;
	u8_t vendor_class_data[1];
} DHCPV6_VENDOR_CLASS, *pDHCPV6_VENDOR_CLASS;

typedef struct DHCPV6_VENDOR_OPTS {
	u32_t enterprise_number;
	u8_t vendor_opt_data[1];
} DHCPV6_VENDOR_OPTS, *pDHCPV6_VENDOR_OPTS;

typedef struct DHCPV6_OPTION {
	DHCPV6_OPT_HDR hdr;
	union {
		DHCPV6_VENDOR_OPTS vendor_opts;
		DHCPV6_VENDOR_CLASS vendor_class;
		DHCPV6_OPT_CLIENT_ID client_id;
		DHCPV6_OPT_ID_ASSOC_NA ida_na;
		DHCPV6_OPT_ELAPSE_TIME elapsed_time;
		DHCPV6_OPT_IAA_ADDR iaa_addr;
		DHCPV6_OPT_STATUS sts;
		DHCPV6_OPT_REQUEST_LIST list;
		DHCPV6_OPT_DNS dns;
		u8_t data[1];
	} type;

} DHCPV6_OPTION, *pDHCPV6_OPTION;

#ifdef PACK_DATA_STRUCTURE
#pragma pack(pop)
#endif

#define DHCPV6_NUM_OF_RETRY      4

#define DHCPV6_ACK_TIMEOUT       2

#define IANA_ENTERPRISE_NUM_BROADCOM   0x113d

/* Broadcom Extended DHCP options used in iSCSI boot */
#define DHCPV6_TAG_FIRST_ISCSI_TARGET_NAME              201
#define DHCPV6_TAG_SECOND_ISCSI_TARGET_NAME             202
#define DHCPV6_TAG_ISCSI_INITIATOR_NAME                 203

#define MAX_DHCP_RX_OFFERS   4
#define MAX_DHCP_OPTION43_LENGTH  1024

#define DHCPV6_TASK_GET_IP_ADDRESS   0x1
#define DHCPV6_TASK_GET_OTHER_PARAMS 0x2

enum {
	ISCSI_FAILURE,
	ISCSI_USER_ABORT,
	ISCSI_SUCCESS
};

//const int dhcpv6_retry_timeout[DHCPV6_NUM_OF_RETRY] = {1,2,4,8};

/* Function prototypes */
int dhcpv6_do_discovery(pDHCPV6_CONTEXT dhcpv6_context);
void ipv6_udp_handle_dhcp(pDHCPV6_CONTEXT dhcpv6_context);
void dhcpv6_init(pDHCPV6_CONTEXT dhcpv6_context);

#endif /* __IDHCPV6_H__ */
