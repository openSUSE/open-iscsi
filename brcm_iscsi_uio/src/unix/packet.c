/* packet.c: packet management
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
#include <stdio.h>

#include "logger.h"
#include "packet.h"
#include "nic.h"

/**
 * alloc_packet() - Function used to allocate memory for a packet
 * @param max_buf_size - max packet size
 * @param priv_size    - size of the assoicated private data
 * @return NULL if failed, on success return a pointer to the packet
 */
struct packet * alloc_packet(size_t max_buf_size,
			     size_t priv_size)
{
	struct packet *pkt;
	void *priv;

	pkt = malloc(max_buf_size + sizeof(struct packet));
	if(pkt == NULL) {
		LOG_ERR("Could not allocate any memory for packet");
		return NULL;
	}

	priv = malloc(priv_size);
	if(priv == NULL) {
		LOG_ERR("Could not allocate any memory for private structure");
		goto free_pkt;
	}
	
	pkt->max_buf_size = max_buf_size;
	pkt->priv = priv;

	return pkt;

free_pkt:
	free(pkt);

	return NULL;
}

void free_packet(struct packet *pkt)
{
	if(pkt->priv != NULL)
		free(pkt->priv);

	free(pkt);
}

/**
 *  reset_packet() - This will reset the packet fields to default values
 *  @param pkt - the packet to reset
 */
void reset_packet(packet_t *pkt)
{
	pkt->next = NULL;

	pkt->flags = 0;
	pkt->vlan_tag = 0;

	pkt->buf_size = 0;

	pkt->data_link_layer = NULL;
	pkt->network_layer   = NULL;
}

int alloc_free_queue(nic_t *nic,
		     size_t num_of_packets)
{
	int rc, i;

	pthread_mutex_lock(&nic->free_packet_queue_mutex);
	for(i=0; i<num_of_packets; i++) {
		packet_t *pkt;

		pkt = alloc_packet(1500, 1500);
		if(pkt == NULL) {
			rc = i;
			goto done;
		}

		reset_packet(pkt);

		pkt->next = nic->free_packet_queue;
		nic->free_packet_queue = pkt;
	}

	rc = num_of_packets;

done:	
	pthread_mutex_unlock(&nic->free_packet_queue_mutex);

	return i;
}
