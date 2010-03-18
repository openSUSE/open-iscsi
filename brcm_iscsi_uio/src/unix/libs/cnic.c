/* cnic_nl.c: CNIC UIO uIP user space stack
 *
 * Copyright (c) 2004-2008 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/socket.h>

#include "uip_arp.h"
#include "nic.h"
#include "nic_nl.h"
#include "logger.h"
#include "options.h"
#include "uevent.h"

#include "cnic.h"
#include "iscsi_if.h"

/*******************************************************************************
 * Constants
 ******************************************************************************/
#define PFX "CNIC "

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP			0x0800		/* IP */
#endif /* ETHERTYPE_IP */

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP			0x0806		/* Address resolution */
#endif /* ETHERTYPE_ARP */

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN			0x8100		/* IEEE 802.1Q VLAN tagging */
#endif /* ETHERTYPE_VLAN */

/*******************************************************************************
 * Constants shared between the bnx2 and bnx2x modules
 ******************************************************************************/
const char bnx2i_library_transport_name[] = "bnx2i";
const size_t bnx2i_library_transport_name_size = 
	sizeof(bnx2i_library_transport_name);

/******************************************************************************
 * Netlink Functions
 ******************************************************************************/

static int cnic_arp_send(nic_t *nic, nic_interface_t *nic_iface, int fd,
			 __u8 * mac_addr, __u32 ip_addr, __u16 op)
{
	struct ether_header *eth;
	uint16_t *vlan_hdr;
	struct ether_arp *arp;
	__u32 dst_ip = ip_addr;
	int pkt_size = sizeof(*eth) + sizeof(*arp);
	int rc;

	rc = pthread_mutex_trylock(&nic->xmit_mutex);
	if(rc != 0) {
		LOG_DEBUG(PFX "%s: could not get xmit_mutex", nic->log_name);
		return -EAGAIN;
	}

	eth = (*nic->ops->get_tx_pkt)(nic);
	memcpy(eth->ether_shost, nic->mac_addr, ETH_ALEN);

	vlan_hdr = (uint16_t *)(eth + 1);
        /*  Determine if we need to insert the VLAN tag */
        if(nic_iface->vlan_id != 0)
        {
		uint16_t insert_tpid = const_htons(ETHERTYPE_ARP);
		uint16_t insert_vlan_id = htons((0x0FFF & nic_iface->vlan_id) +
			  ((0x000F & nic_iface->vlan_priority) << 12));

                memcpy(vlan_hdr, &insert_vlan_id, 2);
		vlan_hdr++;
                memcpy(vlan_hdr, &insert_tpid, 2);
		vlan_hdr++;

                pkt_size = pkt_size + 4;
		eth->ether_type = htons(ETHERTYPE_VLAN);

                LOG_DEBUG(PFX "%s: Inserted vlan tag id: 0x%x",
                          nic->log_name,
                          ntohs(insert_vlan_id));
        } else {
		eth->ether_type = const_htons(ETHERTYPE_ARP);
	}

	arp = (struct ether_arp *)(vlan_hdr);

	if (op == ARPOP_REQUEST) {
		int i;

		for (i = 0; i < 6; i++)
			eth->ether_dhost[i] = 0xff;
	} else
		memcpy(eth->ether_dhost, mac_addr, 6);

	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETHERTYPE_IP);
	arp->arp_hln = ETH_ALEN;
	arp->arp_pln = 4;
	arp->arp_op = htons(op);
	memcpy(arp->arp_sha, nic->mac_addr, ETH_ALEN);

	/*  Copy the IP address's into the ARP response */
	memcpy(arp->arp_spa, nic_iface->ustack.hostaddr, 4);
	memcpy(arp->arp_tpa, &dst_ip, 4);

	(*nic->nic_library->ops->start_xmit)(nic, pkt_size);

	LOG_DEBUG(PFX "%s: Sent cnic arp request", nic->log_name);

	return 0;
}

static int cnic_nl_neigh_rsp(nic_t *nic, int fd,
			     struct iscsi_uevent *ev,
			     struct iscsi_path *path_req,
			     __u8 *mac_addr,
			     nic_interface_t *nic_iface,
			     int status)

{
	int rc;
	uint8_t *ret_buf;
	struct iscsi_uevent *ret_ev;
	struct iscsi_path *path_rsp;
	struct sockaddr_nl dest_addr;

        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0;
        dest_addr.nl_groups = 0; /* unicast */

	ret_buf = calloc(1, NLMSG_SPACE(sizeof(struct iscsi_uevent) + 256));

        memset(ret_buf, 0, NLMSG_SPACE(sizeof(struct iscsi_uevent) + 256));

	/*  prepare the iscsi_uevent buffer */
	ret_ev = (struct iscsi_uevent *)ret_buf;
	ret_ev->type = ISCSI_UEVENT_PATH_UPDATE;
	ret_ev->transport_handle = ev->transport_handle;
	ret_ev->u.set_path.host_no = ev->r.req_path.host_no;

	/*  Prepare the iscsi_path buffer */
	path_rsp = ret_buf + sizeof(*ret_ev);
	path_rsp->handle = path_req->handle;
	path_rsp->ip_addr_len = 4;
	memcpy(&path_rsp->src.v4_addr, &nic_iface->ustack.hostaddr,
	       sizeof(nic_iface->ustack.hostaddr));
	memcpy(path_rsp->mac_addr, mac_addr, 6);
	path_rsp->vlan_id = path_req->vlan_id;
	path_rsp->pmtu    = path_req->pmtu;

        rc = __kipc_call(fd, ret_ev, sizeof(*ret_ev) + sizeof(*path_rsp));
        if (rc > 0) {
                LOG_ERR(PFX "neighbor reply sent back to kernel");
	} else {
                LOG_ERR(PFX "send neighbor reply failed: %d", rc);
	}

	free(ret_buf);

	return rc;
}

/**
 * cnic_handle_iscsi_path_req() - This function will handle the path req calls 
 *                                the bnx2i kernel module
 * @param nic - The nic the message is directed towards
 * @param fd  - The file descriptor to be used to extract the private data
 * @param ev  - The iscsi_uevent
 * @param buf - The private message buffer
 * @param buf_len - The private message buffer length
 */
int cnic_handle_iscsi_path_req(nic_t *nic, int fd, struct iscsi_uevent *ev,
			       struct iscsi_path *path, size_t buf_len) 
{
	nic_interface_t *nic_iface;
	struct in_addr addr;
	__u8 mac_addr[6];
	int rc;
	uint16_t arp_retry;
	int status = 0;

	LOG_DEBUG(PFX "%s: Netlink message with VLAN ID: %d, path MTU: %d "
		      "minor: %d",
		   nic->log_name, path->vlan_id, path->pmtu, 0/* TODO FIX */);

	pthread_mutex_lock(&nic_list_mutex);

	/*  Find the proper interface via VLAN id */
	nic_iface = nic_find_nic_iface(nic, path->vlan_id);
	if (nic_iface == NULL) {
		nic_iface = nic_find_nic_iface(nic, 0);
		if (nic_iface == NULL) {
			pthread_mutex_unlock(&nic_list_mutex);
			LOG_ERR(PFX "%s: Couldn't find net_iface vlan_id: %d",
				nic->log_name, path->vlan_id);
			return -EINVAL;
		}

		nic_iface->vlan_id = path->vlan_id;
	}

	memcpy(&addr, &path->dst.v4_addr, sizeof(addr));

#define MAX_ARP_RETRY 4
	arp_retry = 0;

	rc = uip_lookup_arp_entry(addr.s_addr, mac_addr);
	if (rc != 0) {
		while ((arp_retry < MAX_ARP_RETRY) && (event_loop_stop == 0)) {
			char *addr_str;
			int count;

			addr_str = inet_ntoa(addr);
			LOG_INFO(PFX "%s: Didn't find ip: %s\n",
				 nic->log_name, addr_str);
			rc = cnic_arp_send(nic, nic_iface, fd,
					   mac_addr, addr.s_addr,
					   ARPOP_REQUEST);
			if(rc != 0) {
				status = -EIO;
				goto done;
			}

			for(count=0; count<8; count++) {
				usleep(250000);

				rc = uip_lookup_arp_entry(addr.s_addr,
							  mac_addr);
				if (rc == 0)
					goto done;
			}

			arp_retry++;
		}
	}

done:
	pthread_mutex_unlock(&nic_list_mutex);

	if(arp_retry >= MAX_ARP_RETRY) {
		status = -EIO;
		rc = -EIO;
	}

	if(status != 0 || rc != 0)
		pthread_mutex_unlock(&nic->xmit_mutex);

	cnic_nl_neigh_rsp(nic, fd, ev, path, mac_addr,
			  nic_iface, status);


	return rc;
}
