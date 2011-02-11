/* cnic_nl.c: CNIC UIO uIP user space stack
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
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/netlink.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/socket.h>

#include "uip_arp.h"
#include "nic.h"
#include "nic_utils.h"
#include "logger.h"
#include "options.h"
#include "uevent.h"

#include "cnic.h"
#include "iscsi_if.h"

/*******************************************************************************
 * Constants
 ******************************************************************************/
#define PFX "CNIC "
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
			 __u8 * mac_addr, __u32 ip_addr)
{
	struct ether_header *eth;
	struct ether_arp *arp;
	__u32 dst_ip = ip_addr;
	int pkt_size = sizeof(*eth) + sizeof(*arp);
	int rc;
	struct in_addr addr;
	static const uint8_t multicast_mac[] =
		{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	rc = pthread_mutex_trylock(&nic->xmit_mutex);
	if(rc != 0) {
		LOG_DEBUG(PFX "%s: could not get xmit_mutex", nic->log_name);
		return -EAGAIN;
	}

	eth = (*nic->ops->get_tx_pkt)(nic);
	if (eth == NULL) {
		LOG_WARN(PFX "%s: couldn't get tx packet", nic->log_name);
		return -EAGAIN;
	}

	nic_fill_ethernet_header(nic_iface, eth,
				 nic->mac_addr, multicast_mac,
				 &pkt_size, &arp, ETHERTYPE_ARP);

	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETHERTYPE_IP);
	arp->arp_hln = ETH_ALEN;
	arp->arp_pln = 4;
	arp->arp_op = htons(ARPOP_REQUEST);
	memcpy(arp->arp_sha, nic->mac_addr, ETH_ALEN);

	/*  Copy the IP address's into the ARP response */
	memcpy(arp->arp_spa, nic_iface->ustack.hostaddr, 4);
	memcpy(arp->arp_tpa, &dst_ip, 4);

	(*nic->nic_library->ops->start_xmit)(nic, pkt_size);

	memcpy(&addr.s_addr, &dst_ip, sizeof(addr.s_addr));
	LOG_DEBUG(PFX "%s: Sent cnic arp request for IP: %s",
		       nic->log_name, inet_ntoa(addr));

	return 0;
}

static int cnic_neigh_soliciation_send(nic_t *nic,
				       nic_interface_t *nic_iface, int fd,
				       __u8 * mac_addr,
				       struct in6_addr *addr6_dst)
{
	struct ether_header *eth;
	struct ip6_hdr *ipv6_hdr;
	struct nd_neighbor_solicit *sol;
	struct nd_opt_hdr *opt_hdr;
	char *data;
	int pkt_size = sizeof(*eth) + sizeof(*ipv6_hdr) + sizeof(*sol) +
		       sizeof(*opt_hdr) + 6;
	int rc;
	struct in6_addr multi;
	static const u_int8_t ipv6_neigh_dhost[ETH_ALEN] =
		{ 0x33, 0x33, 0xff, 0x00, 0x01, 0x01 };

	inet_pton(AF_INET6, "ff02::1:ff00:0", &multi);

	rc = pthread_mutex_trylock(&nic->xmit_mutex);
	if (rc != 0) {
		LOG_WARN(PFX "%s: could not get xmit_mutex", nic->log_name);
		return -EAGAIN;
	}

	/*  Build the ethernet header */
	eth = (*nic->ops->get_tx_pkt)(nic);
	if (eth == NULL) {
		LOG_WARN(PFX "%s: couldn't get tx packet", nic->log_name);
		return -EAGAIN;
	}

	 nic_fill_ethernet_header(nic_iface, eth,
				  nic->mac_addr, ipv6_neigh_dhost,
				  &pkt_size, &ipv6_hdr, ETHERTYPE_IPV6);

	/*  Prepare the IPv6 header */
	ipv6_hdr->ip6_vfc  = 0x6 << 4;
	ipv6_hdr->ip6_plen = htons((sizeof(*sol) + sizeof(*opt_hdr) + 6)); /*  Add optionial header */
	ipv6_hdr->ip6_hlim = 255;
	ipv6_hdr->ip6_nxt  = IPPROTO_ICMPV6;
	multi.s6_addr16[7] = 0;
	multi.s6_addr16[7] |= addr6_dst->s6_addr16[7];
	memcpy(ipv6_hdr->ip6_dst.s6_addr, multi.s6_addr,
	       sizeof(sol->nd_ns_target.s6_addr));
	memcpy(ipv6_hdr->ip6_src.s6_addr, nic_iface->ustack.hostaddr6,
	       sizeof(ipv6_hdr->ip6_src));

	/*  Prepare the ICMPv6 header */
	sol = (struct nd_neighbor_solicit *)(ipv6_hdr + 1);
	sol->nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
	sol->nd_ns_hdr.icmp6_code = 0;
	sol->nd_ns_hdr.icmp6_cksum = 0;
	memcpy(sol->nd_ns_target.s6_addr, addr6_dst->s6_addr,
	       sizeof(sol->nd_ns_target.s6_addr));

	/*  Prepare the ICMPv6 Option header */
	opt_hdr = (struct nd_opt_hdr *) (sol + 1);
	opt_hdr->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	opt_hdr->nd_opt_len = 8 >> 3;
	opt_hdr++;

	/*  Copy the Link Layer address */
	data = (char *) opt_hdr;
	memcpy(data, nic->mac_addr, sizeof(nic->mac_addr));

	sol->nd_ns_hdr.icmp6_cksum = ~icmpv6_checksum((uint8_t *) ipv6_hdr);

	(*nic->nic_library->ops->start_xmit)(nic, pkt_size);

	LOG_DEBUG(PFX "%s: Sent cnic ICMPv6 neighbor request", nic->log_name);

	return 0;
}


static int cnic_nl_neigh_rsp(nic_t *nic, int fd,
			     struct iscsi_uevent *ev,
			     struct iscsi_path *path_req,
			     __u8 *mac_addr,
			     nic_interface_t *nic_iface,
			     int status, int type)

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
	if (type == AF_INET) {
		path_rsp->ip_addr_len = 4;
		memcpy(&path_rsp->src.v4_addr, &nic_iface->ustack.hostaddr,
		       sizeof(nic_iface->ustack.hostaddr));
	} else {
		path_rsp->ip_addr_len = 16;
		memcpy(&path_rsp->src.v6_addr, &nic_iface->ustack.hostaddr6,
		       sizeof(nic_iface->ustack.hostaddr6));
	}
	memcpy(path_rsp->mac_addr, mac_addr, 6);
	path_rsp->vlan_id = path_req->vlan_id;
	path_rsp->pmtu    = path_req->pmtu;

        rc = __kipc_call(fd, ret_ev, sizeof(*ret_ev) + sizeof(*path_rsp));
        if (rc > 0) {
                LOG_DEBUG(PFX "neighbor reply sent back to kernel "
			      "at %02x:%02x:%02x:%02x:%02x:%02x",
			      mac_addr[0], mac_addr[1],
			      mac_addr[2], mac_addr[3],
			      mac_addr[4], mac_addr[5]);

	} else {
                LOG_ERR(PFX "send neighbor reply failed: %d", rc);
	}

	free(ret_buf);

	return rc;
}

/**
 * cnic_handle_ipv4_iscsi_path_req() - This function will handle the IPv4
 * 				       path req calls the bnx2i kernel module
 * @param nic - The nic the message is directed towards
 * @param fd  - The file descriptor to be used to extract the private data
 * @param ev  - The iscsi_uevent
 * @param buf - The private message buffer
 * @param buf_len - The private message buffer length
 */
int cnic_handle_ipv4_iscsi_path_req(nic_t *nic, int fd, struct iscsi_uevent *ev,
				    struct iscsi_path *path, size_t buf_len) 
{
	nic_interface_t *nic_iface;
	struct in_addr addr;
	__u8 mac_addr[6];
	int rc;
	uint16_t arp_retry;
	int status = 0;
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
			LOG_INFO(PFX "%s: Didn't find ip: %s in ARP table\n",
				 nic->log_name, addr_str);
			rc = cnic_arp_send(nic, nic_iface, fd,
					   mac_addr, addr.s_addr);
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
			  nic_iface, status, AF_INET);


	return rc;
}

/**
 * cnic_handle_ipv6_iscsi_path_req() - This function will handle the IPv4
 * 				       path req calls the bnx2i kernel module
 * @param nic - The nic the message is directed towards
 * @param fd  - The file descriptor to be used to extract the private data
 * @param ev  - The iscsi_uevent
 * @param buf - The private message buffer
 * @param buf_len - The private message buffer length
 */
int cnic_handle_ipv6_iscsi_path_req(nic_t *nic, int fd, struct iscsi_uevent *ev,
				    struct iscsi_path *path, size_t buf_len) 
{
	nic_interface_t *nic_iface;
	__u8 mac_addr[6];
	int rc;
	uint16_t neighbor_retry;
	int status = 0;
	char addr_dst_str[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &path->dst.v6_addr,
		  addr_dst_str, sizeof(path->dst.v6_addr));

	LOG_DEBUG(PFX "%s: Preparing to send IPv6 neighbor solicitation "
		      "to dst: %s",
		  nic->log_name, addr_dst_str);

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

#define MAX_ARP_RETRY 4
	neighbor_retry = 0;

	rc = uip_neighbor_lookup(&nic_iface->ustack, &path->dst.v6_addr, mac_addr);
	if (rc != 0) { 
		while ((neighbor_retry < MAX_ARP_RETRY) &&
		       (event_loop_stop == 0)) {
			int count;

			LOG_INFO(PFX "%s: Didn't find ip: %s\n",
				 nic->log_name, addr_dst_str);

			rc = cnic_neigh_soliciation_send(nic, nic_iface, fd,
							 mac_addr,
							 &path->dst.v6_addr);
			if(rc != 0) {
				status = -EIO;
				goto done;
			}

			for(count=0; count<8; count++) {
				usleep(250000);

				rc = uip_neighbor_lookup(&nic_iface->ustack,
							 &path->dst.v6_addr,
							 mac_addr);
				if (rc == 0)
					goto done;
			}

			neighbor_retry++;
		}
	}

done:
	pthread_mutex_unlock(&nic_list_mutex);

	if(neighbor_retry >= MAX_ARP_RETRY) {
		status = -EIO;
		rc = -EIO;
	}

	if(status != 0 || rc != 0)
		pthread_mutex_unlock(&nic->xmit_mutex);

	cnic_nl_neigh_rsp(nic, fd, ev, path, mac_addr,
			  nic_iface, status, AF_INET6);


	return rc;

	return 0;
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

	LOG_DEBUG(PFX "%s: Netlink message with VLAN ID: %d, path MTU: %d "
		      "minor: %d ip_addr_len: %d",
		   nic->log_name, path->vlan_id, path->pmtu, 0/* TODO FIX */,
		   path->ip_addr_len);

	if (path->ip_addr_len == 4)
		return cnic_handle_ipv4_iscsi_path_req(nic, fd, ev,
						       path, buf_len);
	else if (path->ip_addr_len == 16)
		return cnic_handle_ipv6_iscsi_path_req(nic, fd, ev,
						       path, buf_len);
	else {
		LOG_DEBUG(PFX "%s: unknown ip_addr_len: %d size dropping ",
			  nic->log_name, path->ip_addr_len);
		return -EIO;
	}
}
