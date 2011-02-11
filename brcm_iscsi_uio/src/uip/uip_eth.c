/* uip_eth.c: CNIC UIO uIP user space stack
 *
 * Copyright (c) 2004-2010 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */

#include "uip.h"
#include "uip_eth.h"

int is_vlan_packet(struct uip_vlan_eth_hdr *hdr)
{
	/*  The TPID field in a 802.1Q Header must be 0x8100 */
	if(hdr->tpid == const_htons(UIP_ETHTYPE_8021Q))
	{
		return 1;
	}

	return 0;
}
