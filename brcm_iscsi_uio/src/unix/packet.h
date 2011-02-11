/* packet.h: packet definitions
 *
 * Copyright (c) 2004-2010 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */

#include <errno.h>

#ifndef __PACKET_H__
#define __PACKET_H__

#include "nic.h"

struct nic;
struct nic_interface;

typedef struct packet {
	struct packet *next;

	uint32_t flags;
#define VLAN_TAGGED	0x0001
	uint16_t vlan_tag;

	size_t  max_buf_size;
	size_t  buf_size;

	uint8_t *data_link_layer;
	uint8_t *network_layer;

	struct nic *nic;
	struct nic_interface *nic_iface;

	void   *priv;
	uint8_t	buf[];
} packet_t;

/******************************************************************************
 *  Packet Function Declarations
 *****************************************************************************/
int alloc_free_queue(struct nic *, size_t num_of_packets);
void reset_packet(packet_t *pkt);

#endif /*  __PACKET_H__ */
