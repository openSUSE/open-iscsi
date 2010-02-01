/* nic_util.h: NIC utility functions
 *
 * Copyright (c) 2004-2008 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */
#ifndef __NIC_UTILS_H__
#define __NIC_UTILS_H__

#include "nic.h"

/******************************************************************************
 * Function Prototype
 ******************************************************************************/
int nic_discover_iscsi_hosts();

int enable_mutlicast(nic_t *nic);
int disable_mutlicast(nic_t *nic);

int from_netdev_name_find_nic(char *interface_name,
			      nic_t **nic);

int from_host_no_find_associated_eth_device(int host_no,
					    nic_t **nic);

int from_phys_name_find_assoicated_uio_device(nic_t *nic);

int from_uio_find_associated_eth_device(int uio_minor, char *name,
					size_t name_size);

int nic_queue_tx_packet(nic_t *nic,
			nic_interface_t *nic_iface,
			packet_t *pkt);

packet_t * nic_dequeue_tx_packet(nic_t *nic);
nic_interface_t * nic_find_nic_iface(nic_t *nic,
				     uint16_t vlan_id);
int add_vlan_interfaces(nic_t *nic);

int nic_verify_uio_sysfs_name(nic_t *nic);
void nic_close_all();

uint32_t calculate_default_netmask(uint32_t ip_addr);

void prepare_nic(nic_t *nic);

int nic_enable(nic_t *nic);
int nic_disable(nic_t *nic);

int determine_file_size_read(const char *filepath);
int capture_file(char **raw, uint32_t *raw_size, const char *path);


#endif /* __NIC_UTILS_H__ */
