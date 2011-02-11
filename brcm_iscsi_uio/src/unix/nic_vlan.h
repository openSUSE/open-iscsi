/* nic_vlan.h: uIP user space stack VLAN utilities
 *
 * Copyright (c) 2004-2010 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */

#ifndef __NIC_VLAN_H__
#define __NIC_VLAN_H__

#include <sys/types.h>


/*  Used to hold entries in the vlan table */
struct vlan_entry {
	char vlan_iface_name[16];
	char phy_iface_name[16];
	uint16_t vlan_id; 
};

struct vlan_handle
{
	struct vlan_entry *entries;
	uint32_t          num_of_entries;

	uint32_t outstanding_found_handles;
};

struct vlan_found_entry
{
#define VLAN_ENTRY_FOUND	1
#define VLAN_ENTRY_NOT_FOUND	0
	uint8_t found;
};

struct vlan_found_handle
{
	struct vlan_handle *handle;
	uint32_t          num_of_entries;
	struct vlan_found_entry *entries;
};

/*******************************************************************************
 * Function Prototypes
 ******************************************************************************/
void init_vlan_table(struct vlan_handle *handle);
int capture_vlan_table(struct vlan_handle *handle);
void release_vlan_table(struct vlan_handle *handle);

int find_phy_using_vlan_interface(struct vlan_handle *handle,
				  char *vlan_iface_name,
				  char **phy_iface_name, uint16_t *vlan_id);
int find_vlans_using_phy_interface(struct vlan_handle *handle,
				   struct vlan_found_handle *found_handle,
				   char *phy_iface_name);

int init_vlan_found_handle(struct vlan_found_handle *found_handle,
                           struct vlan_handle *handle);
void release_vlan_found_handle(struct vlan_found_handle *found_handle);

int valid_vlan(short int vlan);
#endif /* __NIC_VLAN_H__ */
