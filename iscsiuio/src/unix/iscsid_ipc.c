/*
 * Copyright (c) 2009-2011, Broadcom Corporation
 *
 * Written by:  Benjamin Li  (benli@broadcom.com)
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
 * iscsi_ipc.c - Generic NIC management/utility functions
 *
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#define PFX "iscsi_ipc "

/* TODO fix me */
#define IFNAMSIZ 15

#include "nic.h"
#include "nic_utils.h"
#include "nic_vlan.h"
#include "options.h"
#include "mgmt_ipc.h"
#include "iscsid_ipc.h"
#include "uip.h"
#include "uip_mgmt_ipc.h"

#include "logger.h"
#include "uip.h"

/*  private iscsid options stucture */
struct iscsid_options {
	int fd;
	pthread_t thread;
};

struct ip_addr_mask {
	int ip_type;
	union {
		struct in_addr addr4;
		struct in6_addr addr6;
	} addr;
	union {
		struct in_addr nm4;
		struct in6_addr nm6;
	} netmask;
#define addr4		addr.addr4
#define addr6		addr.addr6
#define nm4		netmask.nm4
#define nm6		netmask.nm6
};

/******************************************************************************
 *  iscsid_ipc Constants
 *****************************************************************************/
static const char uio_udev_path_template[] = "/dev/uio%d";

/******************************************************************************
 *  Globals
 *****************************************************************************/
static struct iscsid_options iscsid_opts = {
	.fd = INVALID_FD,
	.thread = INVALID_THREAD,
};

/******************************************************************************
 *  iscsid Functions
 *****************************************************************************/

static void *enable_nic_thread(void *data)
{
	nic_t *nic = (nic_t *) data;

	prepare_nic_thread(nic);
	LOG_INFO(PFX "%s: started NIC enable thread state: 0x%x",
		 nic->log_name, nic->state)

	/*  Enable the NIC */
	nic_enable(nic);

	pthread_exit(NULL);
}

static int decode_cidr(char *in_ipaddr_str, struct ip_addr_mask *ipam,
		       int *prefix_len)
{
	int rc = 0, i;
	char *tmp, *tok;
	char ipaddr_str[NI_MAXHOST];
	char str[INET6_ADDRSTRLEN];
	int keepbits = 0;
	struct in_addr ia;
	struct in6_addr ia6;

	memset(ipam, 0, sizeof(struct ip_addr_mask));
	if (strlen(in_ipaddr_str) > NI_MAXHOST)
		strncpy(ipaddr_str, in_ipaddr_str, NI_MAXHOST);
	else
		strcpy(ipaddr_str, in_ipaddr_str);

	/* Find the CIDR if any */
	tmp = strchr(ipaddr_str, '/');
	if (tmp) {
		/* CIDR found, now decode, tmpbuf = ip, tmp = netmask */
		tmp = ipaddr_str;
		tok = strsep(&tmp, "/");
		LOG_INFO(PFX "in cidr: bitmask '%s' ip '%s'", tmp, tok);
		keepbits = atoi(tmp);
		strcpy(ipaddr_str, tok);
	}

	/*  Determine if the IP address passed from the iface file is
	 *  an IPv4 or IPv6 address */
	rc = inet_pton(AF_INET, ipaddr_str, &ipam->addr6);
	if (rc == 0) {
		/* Test to determine if the addres is an IPv6 address */
		rc = inet_pton(AF_INET6, ipaddr_str, &ipam->addr6);
		if (rc == 0) {
			LOG_ERR(PFX "Could not parse IP address: '%s'",
				ipaddr_str);
			goto out;
		}
		ipam->ip_type = AF_INET6;
		if (keepbits > 128) {
			LOG_ERR(PFX "CIDR netmask > 128 for IPv6: %d(%s)",
				keepbits, tmp);
			goto out;
		}
		if (!keepbits) {
			/* Default prefix mask to 64 */
			memcpy(&ipam->nm6.s6_addr, all_zeroes_addr6,
			       sizeof(struct in6_addr));
			for (i = 0; i < 2; i++)
				ipam->nm6.s6_addr32[i] = 0xffffffff;
			goto out;
		}
		*prefix_len = keepbits;
		memcpy(&ia6.s6_addr, all_zeroes_addr6,
		       sizeof(struct in6_addr));
		for (i = 0; i < 4; i++) {
			if (keepbits < 32) {
				ia6.s6_addr32[i] = keepbits > 0 ?
				    0x00 - (1 << (32 - keepbits)) : 0;
				break;
			} else
				ia6.s6_addr32[i] = 0xFFFFFFFF;
			keepbits -= 32;
		}
		ipam->nm6 = ia6;
		if (inet_ntop(AF_INET6, &ia6, str, sizeof(str)))
			LOG_INFO(PFX "Using netmask: %s", str);
	} else {
		ipam->ip_type = AF_INET;
		rc = inet_pton(AF_INET, ipaddr_str, &ipam->addr4);

		if (keepbits > 32) {
			LOG_ERR(PFX "CIDR netmask > 32 for IPv4: %d(%s)",
				keepbits, tmp);
			goto out;
		}
		ia.s_addr = keepbits > 0 ? 0x00 - (1 << (32 - keepbits)) : 0;
		ipam->nm4.s_addr = htonl(ia.s_addr);
		LOG_INFO(PFX "Using netmask: %s", inet_ntoa(ipam->nm4));
	}
out:
	return rc;
}

#if (ISCSID_VERSION == 872)
static void copy_iface_rec(struct iface_rec *rec, iscsid_uip_broadcast_t *data)
{
	struct iface_rec_872 *rec_872;
	struct iface_rec_872_22 *rec_872_22;

	memset(rec, 0, sizeof(struct iface_rec));
	/* Check for data->header.version for iface_rec decode */
	if (data->header.payload_len == sizeof(struct iface_rec_872_22)) {
		rec_872_22 = (struct iface_rec_872_22 *)
						&data->u.iface_rec.rec;
		rec->list = rec_872_22->list;
		memcpy(&rec->name, &rec_872_22->name, ISCSI_MAX_IFACE_LEN);
		rec->iface_num = rec_872_22->iface_num;
		memcpy(&rec->netdev, &rec_872_22->netdev, IFNAMSIZ);
		memcpy(&rec->ipaddress, &rec_872_22->ipaddress, NI_MAXHOST);
		memcpy(&rec->subnet_mask, &rec_872_22->subnet_mask, NI_MAXHOST);
		memcpy(&rec->gateway, &rec_872_22->gateway, NI_MAXHOST);
		memcpy(&rec->bootproto, &rec_872_22->bootproto, NI_MAXHOST);
		memcpy(&rec->ipv6_linklocal, &rec_872_22->ipv6_linklocal,
		       NI_MAXHOST);
		memcpy(&rec->ipv6_router, &rec_872_22->ipv6_router, NI_MAXHOST);
		memcpy(&rec->ipv6_autocfg, &rec_872_22->ipv6_autocfg,
		       NI_MAXHOST);
		memcpy(&rec->linklocal_autocfg, &rec_872_22->linklocal_autocfg,
		       NI_MAXHOST);
		memcpy(&rec->router_autocfg, &rec_872_22->router_autocfg,
		       NI_MAXHOST);
		rec->vlan_id = rec_872_22->vlan_id;
		rec->vlan_priority = rec_872_22->vlan_priority;
		memcpy(&rec->vlan_state, &rec_872_22->vlan_state,
		       ISCSI_MAX_STR_LEN);
		memcpy(&rec->state, &rec_872_22->state, ISCSI_MAX_STR_LEN);
		rec->mtu = rec_872_22->mtu;
		rec->port = rec_872_22->port;
		memcpy(&rec->hwaddress, &rec_872_22->hwaddress,
		       ISCSI_HWADDRESS_BUF_SIZE);
		memcpy(&rec->transport_name, &rec_872_22->transport_name,
		       ISCSI_TRANSPORT_NAME_MAXLEN);
		memcpy(&rec->alias, &rec_872_22->alias, TARGET_NAME_MAXLEN + 1);
		memcpy(&rec->iname, &rec_872_22->iname, TARGET_NAME_MAXLEN + 1);
	} else {
		rec_872 = (struct iface_rec_872 *)&data->u.iface_rec.rec;
		rec->list = rec_872->list;
		memcpy(rec->name, rec_872->name, ISCSI_MAX_IFACE_LEN);
		memcpy(rec->netdev, rec_872->netdev, IFNAMSIZ);
		memcpy(rec->ipaddress, rec_872->ipaddress, NI_MAXHOST);
		memcpy(rec->hwaddress, rec_872->hwaddress,
		       ISCSI_HWADDRESS_BUF_SIZE);
		memcpy(rec->transport_name, rec_872->transport_name,
		       ISCSI_TRANSPORT_NAME_MAXLEN);
		memcpy(rec->alias, rec_872->alias, TARGET_NAME_MAXLEN + 1);
		memcpy(rec->iname, rec_872->iname, TARGET_NAME_MAXLEN + 1);
	}
}
#endif

static int parse_iface(void *arg)
{
	int rc;
	nic_t *nic = NULL;
	nic_interface_t *nic_iface, *vlan_iface, *base_nic_iface;
	char *transport_name;
	size_t transport_name_size;
	nic_lib_handle_t *handle;
	iscsid_uip_broadcast_t *data;
	short int vlan;
	char ipv6_buf_str[INET6_ADDRSTRLEN];
	int request_type = 0;
	struct in_addr netmask;
	int i, prefix_len = 64;
	struct ip_addr_mask ipam;
	struct iface_rec *rec;
#if (ISCSID_VERSION == 872)
	struct iface_rec localrec;
#endif

	data = (iscsid_uip_broadcast_t *) arg;
#if (ISCSID_VERSION == 872)
	copy_iface_rec(&localrec, data);
	rec = &localrec;
#else
	rec = &data->u.iface_rec.rec;
#endif
	LOG_INFO(PFX "Received request for '%s' to set IP address: '%s' "
		 "VLAN: %d",
		 rec->netdev,
		 rec->ipaddress,
		 rec->vlan_id);

	vlan = rec->vlan_id;
	if (vlan && valid_vlan(vlan) == 0) { 
		LOG_ERR(PFX "Invalid VLAN tag: %d",
			rec->vlan_id)
		    rc = -EIO;
		goto early_exit;
	}

	/*  Detect for CIDR notation and strip off the netmask if present */
	rc = decode_cidr(rec->ipaddress, &ipam, &prefix_len);
	if (rc && !ipam.ip_type) {
		LOG_ERR(PFX "decode_cidr: rc=%d, ipam.ip_type=%d",
			rc, ipam.ip_type)
		    goto early_exit;
	}
	if (ipam.ip_type == AF_INET6)
		inet_ntop(AF_INET6, &ipam.addr6, ipv6_buf_str,
			  sizeof(ipv6_buf_str));

	for (i = 0; i < 10; i++) {
		struct timespec sleep_req, sleep_rem;

		if (pthread_mutex_trylock(&nic_list_mutex) == 0)
			break;

		sleep_req.tv_sec = 0;
		sleep_req.tv_nsec = 100000;
		nanosleep(&sleep_req, &sleep_rem);
	}

	if (i >= 10) {
		LOG_WARN(PFX "Could not aquire nic_list_mutex lock");

		rc = -EIO;
		goto early_exit;
	}

	/*  Check if we can find the NIC device using the netdev
	 *  name */
	rc = from_netdev_name_find_nic(rec->netdev, &nic);

	if (rc != 0) {
		LOG_WARN(PFX "Couldn't find NIC: %s, creating an instance",
			 rec->netdev);

		nic = nic_init();
		if (nic == NULL) {
			LOG_ERR(PFX "Couldn't allocate space for NIC %s",
				rec->netdev);

			rc = -ENOMEM;
			goto done;
		}

		strncpy(nic->eth_device_name,
			rec->netdev,
			sizeof(nic->eth_device_name));
		nic->config_device_name = nic->eth_device_name;
		nic->log_name = nic->eth_device_name;

		if (nic_fill_name(nic) != 0) {
			free(nic);
			rc = -EIO;
			goto done;
		}

		nic_add(nic);
	} else {
		LOG_INFO(PFX " %s, using existing NIC", rec->netdev);
	}

	if (nic->flags & NIC_GOING_DOWN) {
		rc = -EIO;
		LOG_INFO(PFX "nic->flags GOING DOWN");
		goto done;
	}

	/*  If we retry too many times allow iscsid to to timeout */
	if (nic->pending_count > 1000) {
		LOG_WARN(PFX "%s: pending count excceded 1000", nic->log_name);

		pthread_mutex_lock(&nic->nic_mutex);
		nic->pending_count = 0;
		nic->flags &= ~NIC_ENABLED_PENDING;
		pthread_mutex_unlock(&nic->nic_mutex);

		rc = 0;
		goto done;
	}

	if (nic->flags & NIC_ENABLED_PENDING) {
		struct timespec sleep_req, sleep_rem;

		sleep_req.tv_sec = 0;
		sleep_req.tv_nsec = 100000;
		nanosleep(&sleep_req, &sleep_rem);

		pthread_mutex_lock(&nic->nic_mutex);
		nic->pending_count++;
		pthread_mutex_unlock(&nic->nic_mutex);

		LOG_INFO(PFX "%s: enabled pending", nic->log_name);
		rc = -EAGAIN;
		goto done;
	}

	prepare_library(nic);

	/*  Sanity Check to ensure the transport names are the same */
	handle = nic->nic_library;
	if (handle != NULL) {
		(*handle->ops->lib_ops.get_transport_name) (&transport_name,
							  &transport_name_size);

		if (strncmp(transport_name,
			    rec->transport_name,
			    transport_name_size) != 0) {
			LOG_ERR(PFX "%s Transport name is not equal "
				"expected: %s got: %s",
				nic->log_name, rec->transport_name,
				transport_name);
		}
	} else {
		LOG_ERR(PFX "%s Couldn't find nic library ", nic->log_name);
		rc = -EIO;
		goto done;
	}

	LOG_INFO(PFX "%s library set using transport_name %s",
		 nic->log_name, transport_name);

	/*  Create the base network interface if it doesn't exist */
	nic_iface = nic_find_nic_iface_protocol(nic, 0, ipam.ip_type);
	if (nic_iface == NULL) {
		LOG_INFO(PFX "%s couldn't find interface with "
			 "ip_type: 0x%x creating it",
			 nic->log_name, ipam.ip_type);

		/*  Create the nic interface */
		nic_iface = nic_iface_init();

		if (nic_iface == NULL) {
			LOG_ERR(PFX "Couldn't allocate nic_iface", nic_iface);
			goto done;
		}

		nic_iface->protocol = ipam.ip_type;
		nic_add_nic_iface(nic, nic_iface);

		persist_all_nic_iface(nic);

		LOG_INFO(PFX "%s: created network interface", nic->log_name);
	} else {
		LOG_INFO(PFX "%s: using existing network interface",
			 nic->log_name);
	}

	set_nic_iface(nic, nic_iface);

	/* Find the vlan nic_interface */
	if (vlan) {
		vlan_iface = nic_find_vlan_iface_protocol(nic, nic_iface, vlan,
							  ipam.ip_type);
		if (vlan_iface == NULL) {
			LOG_INFO(PFX "%s couldn't find interface with VLAN = %d"
				 "ip_type: 0x%x creating it",
				 nic->log_name, vlan, ipam.ip_type);

			/*  Create the nic interface */
			vlan_iface = nic_iface_init();

			if (vlan_iface == NULL) {
				LOG_ERR(PFX "Couldn't allocate nic_iface for VLAN: %d",
					vlan_iface, vlan);
				goto done;
			}

			vlan_iface->protocol = ipam.ip_type;
			vlan_iface->vlan_id = vlan;
			nic_add_vlan_iface(nic, nic_iface, vlan_iface);
		} else {
			LOG_INFO(PFX "%s: using existing vlan interface",
				 nic->log_name);
		}
		base_nic_iface = nic_iface;
		nic_iface = vlan_iface;
	}

	/*  Determine how to configure the IP address */
	if (ipam.ip_type == AF_INET) {
		if (memcmp(&ipam.addr4,
			   all_zeroes_addr4, sizeof(uip_ip4addr_t)) == 0) {
			LOG_INFO(PFX "%s: requesting configuration using DHCP",
				 nic->log_name);
			request_type = IPV4_CONFIG_DHCP;
		} else {
			LOG_INFO(PFX "%s: requesting configuration using "
				 "static IP address", nic->log_name);
			request_type = IPV4_CONFIG_STATIC;
		}
	} else if (ipam.ip_type == AF_INET6) {
		if (memcmp(&ipam.addr6,
			   all_zeroes_addr6, sizeof(uip_ip6addr_t)) == 0) {
			LOG_INFO(PFX
				 "%s: requesting configuration using DHCPv6",
				 nic->log_name);
			request_type = IPV6_CONFIG_DHCP;
		} else {
			LOG_INFO(PFX "%s: request configuration using static "
				 "IPv6 address: '%s'",
				 nic->log_name, ipv6_buf_str);
			request_type = IPV6_CONFIG_STATIC;
		}
	} else {
		LOG_ERR(PFX "%s: unknown ip_type to configure: 0x%x",
			nic->log_name, ipam.ip_type);

		rc = -EIO;
		goto done;
	}

	if (nic_iface->ustack.ip_config == request_type) {
		if (request_type == IPV4_CONFIG_STATIC) {
			if (memcmp(nic_iface->ustack.hostaddr, &ipam.addr4,
				   sizeof(struct in_addr)))
				goto diff;
		} else if (request_type == IPV6_CONFIG_STATIC) {
			if (memcmp(nic_iface->ustack.hostaddr6, &ipam.addr6,
				   sizeof(struct in6_addr)))
				goto diff;
		}
		LOG_INFO(PFX "%s: IP configuration didn't change using 0x%x",
			 nic->log_name, nic_iface->ustack.ip_config);
		goto enable_nic;
diff:
		/* Disable the NIC */
		nic_disable(nic, 0);
	} else {
		if (request_type == IPV4_CONFIG_DHCP
		    || request_type == IPV6_CONFIG_DHCP)
			nic->flags |= NIC_RESET_UIP;

		/* Disable the NIC */
		nic_disable(nic, 0);
	}

	/*  Check to see if this is using DHCP or if this is
	 *  a static IPv4 address.  This is done by checking
	 *  if the IP address is equal to 0.0.0.0.  If it is
	 *  then the user has specified to use DHCP.  If not
	 *  then the user has spcicied to use a static IP address
	 *  an the default netmask will be used */
	switch (request_type) {
	case IPV4_CONFIG_DHCP:
		memset(nic_iface->ustack.hostaddr, 0, sizeof(struct in_addr));
		LOG_INFO(PFX "%s: configuring using DHCP", nic->log_name);
		nic_iface->ustack.ip_config = IPV4_CONFIG_DHCP;

		break;
	case IPV4_CONFIG_STATIC:
		memcpy(nic_iface->ustack.hostaddr, &ipam.addr4,
		       sizeof(struct in_addr));
		LOG_INFO(PFX "%s: configuring using static IP "
			 "IPv4 address :%s ",
			 nic->log_name, inet_ntoa(ipam.addr4));
		netmask.s_addr = ipam.nm4.s_addr;
		if (!netmask.s_addr)
			netmask.s_addr =
			    calculate_default_netmask(ipam.addr4.s_addr);
		memcpy(nic_iface->ustack.netmask,
		       &netmask, sizeof(netmask.s_addr));
		LOG_INFO(PFX "  netmask :%s", inet_ntoa(netmask));

		nic_iface->ustack.ip_config = IPV4_CONFIG_STATIC;
		break;
	case IPV6_CONFIG_DHCP:
		memset(nic_iface->ustack.hostaddr6, 0,
		       sizeof(struct in6_addr));
		nic_iface->ustack.prefix_len = prefix_len;
		if (ipam.nm6.s6_addr[0] | ipam.nm6.s6_addr[1] |
		    ipam.nm6.s6_addr[2] | ipam.nm6.s6_addr[3] |
		    ipam.nm6.s6_addr[4] | ipam.nm6.s6_addr[5] |
		    ipam.nm6.s6_addr[6] | ipam.nm6.s6_addr[7])
			memcpy(nic_iface->ustack.netmask6,
			       &ipam.nm6, sizeof(struct in6_addr));
		LOG_INFO(PFX "%s: configuring using DHCPv6",
			 nic->log_name);
		nic_iface->ustack.ip_config = IPV6_CONFIG_DHCP;
		break;
	case IPV6_CONFIG_STATIC:
		memcpy(nic_iface->ustack.hostaddr6, &ipam.addr6,
		       sizeof(struct in6_addr));

		nic_iface->ustack.prefix_len = prefix_len;
		if (ipam.nm6.s6_addr[0] | ipam.nm6.s6_addr[1] |
		    ipam.nm6.s6_addr[2] | ipam.nm6.s6_addr[3] |
		    ipam.nm6.s6_addr[4] | ipam.nm6.s6_addr[5] |
		    ipam.nm6.s6_addr[6] | ipam.nm6.s6_addr[7])
			memcpy(nic_iface->ustack.netmask6,
			       &ipam.nm6, sizeof(struct in6_addr));

		LOG_INFO(PFX "%s: configuring using static IP "
			 "IPv6 address: '%s'", nic->log_name, ipv6_buf_str);

		nic_iface->ustack.ip_config = IPV6_CONFIG_STATIC;
		break;
	default:
		LOG_INFO(PFX "%s: Unknown request type: 0x%x",
			 nic->log_name, request_type);

	}

	/* Configuration changed, do VLAN WA */
	vlan_iface = nic_iface->vlan_next;
	while (vlan_iface) {
		/* TODO: When VLAN support is placed in the iface file
		* revisit this code */
		if (vlan_iface->ustack.ip_config) {
			vlan_iface->ustack.ip_config =
				nic_iface->ustack.ip_config;
			memcpy(vlan_iface->ustack.hostaddr,
			       nic_iface->ustack.hostaddr,
			       sizeof(nic_iface->ustack.hostaddr));
			memcpy(vlan_iface->ustack.netmask,
			       nic_iface->ustack.netmask,
			       sizeof(nic_iface->ustack.netmask));
			memcpy(vlan_iface->ustack.hostaddr6,
			       nic_iface->ustack.hostaddr6,
			       sizeof(nic_iface->ustack.hostaddr6));
			memcpy(vlan_iface->ustack.netmask6,
			       nic_iface->ustack.netmask6,
			       sizeof(nic_iface->ustack.netmask6));
		}
		vlan_iface = vlan_iface->vlan_next;
	}

enable_nic:
	if (nic->state & NIC_STOPPED) {
		pthread_mutex_lock(&nic->nic_mutex);
		nic->flags |= NIC_ENABLED_PENDING;
		pthread_mutex_unlock(&nic->nic_mutex);

		/* This thread will be thrown away when completed */
		rc = pthread_create(&nic->enable_thread, NULL,
				    enable_nic_thread, (void *)nic);
		if (rc != 0)
			LOG_WARN(PFX "%s: failed starting enable NIC thread\n",
				 nic->log_name);

		rc = -EAGAIN;
	} else {
		LOG_INFO(PFX "%s: NIC already enabled "
			 "flags: 0x%x state: 0x%x\n",
			 nic->log_name, nic->flags, nic->state);
		rc = 0;
	}

	LOG_INFO(PFX "ISCSID_UIP_IPC_GET_IFACE: command: %x "
		 "name: %s, netdev: %s ipaddr: %s vlan: %d transport_name:%s",
		 data->header.command, rec->name, rec->netdev,
		 (ipam.ip_type == AF_INET) ? inet_ntoa(ipam.addr4) :
					     ipv6_buf_str,
		 vlan, rec->transport_name);

done:
	pthread_mutex_unlock(&nic_list_mutex);

early_exit:
	return rc;
}

/**
 *  process_iscsid_broadcast() - This function is used to process the
 *                               broadcast messages from iscsid
 */
int process_iscsid_broadcast(int s2)
{
	int rc = 0;
	iscsid_uip_broadcast_t *data;
	iscsid_uip_rsp_t rsp;
	FILE *fd;
	size_t size;
	iscsid_uip_cmd_e cmd;
	uint32_t payload_len;

	fd = fdopen(s2, "r+");
	if (fd == NULL) {
		LOG_ERR(PFX "Couldn't open file descriptor: %d(%s)",
			errno, strerror(errno));
		return -EIO;
	}

	/*  This will be freed by parse_iface_thread() */
	data = (iscsid_uip_broadcast_t *) malloc(sizeof(*data));
	if (data == NULL) {
		LOG_ERR(PFX "Couldn't allocate memory for iface data");
		return -ENOMEM;
	}
	memset(data, 0, sizeof(*data));

	size = fread(data, sizeof(iscsid_uip_broadcast_header_t), 1, fd);
	if (size == -1) {
		LOG_ERR(PFX "Could not read request: %d(%s)",
			errno, strerror(errno));
		rc = ferror(fd);
		goto error;
	}

	cmd = data->header.command;
	payload_len = data->header.payload_len;

	LOG_DEBUG(PFX "recv iscsid request: cmd: %d, payload_len: %d",
		  cmd, payload_len);

	size = fread(&data->u.iface_rec, payload_len, 1, fd);
	if (size == -1) {
		LOG_ERR(PFX "Could not read data: %d(%s)",
			errno, strerror(errno));
		goto error;
	}

	switch (cmd) {
	case ISCSID_UIP_IPC_GET_IFACE:
		rc = parse_iface(data);
		switch (rc) {
		case 0:
			rsp.command = cmd;
			rsp.err = ISCSID_UIP_MGMT_IPC_DEVICE_UP;
			break;
		case -EAGAIN:
			rsp.command = cmd;
			rsp.err = ISCSID_UIP_MGMT_IPC_DEVICE_INITIALIZING;
			break;
		default:
			rsp.command = cmd;
			rsp.err = ISCSID_UIP_MGMT_IPC_ERR;
		}

		break;
	default:
		LOG_WARN(PFX "Unknown iscsid broadcast command: %x",
			 data->header.command);

		/*  Send a response back to iscsid to tell it the
		   operation succeeded */
		rsp.command = cmd;
		rsp.err = ISCSID_UIP_MGMT_IPC_OK;
		break;
	}

	size = fwrite(&rsp, sizeof(rsp), 1, fd);
	if (size == -1) {
		LOG_ERR(PFX "Could not send response: %d(%s)",
			errno, strerror(errno));
		rc = ferror(fd);
	}

error:
	free(data);
	fclose(fd);

	return rc;
}

static void iscsid_loop_close(void *arg)
{
	close(iscsid_opts.fd);

	LOG_INFO(PFX "iSCSI daemon socket closed");
}

/**
 *  iscsid_loop() - This is the function which will process the broadcast
 *                  messages from iscsid
 *
 */
static void *iscsid_loop(void *arg)
{
	int rc;
	sigset_t set;

	pthread_cleanup_push(iscsid_loop_close, arg);

	sigfillset(&set);
	rc = pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (rc != 0) {
		LOG_ERR(PFX
			"Couldn't set signal mask for the iscisd listening "
			"thread");
	}

	LOG_DEBUG(PFX "Started iscsid listening thread");

	while (1) {
		struct sockaddr_un remote;
		socklen_t sock_len;
		int s2;

		LOG_DEBUG(PFX "Waiting for iscsid command");

		sock_len = sizeof(remote);
		s2 = accept(iscsid_opts.fd,
			    (struct sockaddr *)&remote, &sock_len);
		if (s2 == -1) {
			if (errno == EAGAIN) {
				LOG_DEBUG("Got EAGAIN from accept");
				sleep(1);
				continue;
			} else if (errno == EINTR) {
				LOG_DEBUG("Got EINTR from accept");
				/*  The program is terminating, time to exit */
				break;
			}

			LOG_ERR(PFX "Could not accept: %d(%s)",
				s2, strerror(errno));
			continue;
		}

		process_iscsid_broadcast(s2);
		close(s2);
	}

	pthread_cleanup_pop(0);

	LOG_ERR(PFX "exit iscsid listening thread");

	pthread_exit(NULL);
}

/******************************************************************************
 *  Initialize/Cleanup routines
 ******************************************************************************/
/**
 *  iscsid_init() - This function will setup the thread used to listen for
 *                  the iscsid broadcast messages
 *  @return 0 on success, <0 on failure
 */
int iscsid_init()
{
	int rc;
	struct sockaddr_un addr;

	iscsid_opts.fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (iscsid_opts.fd < 0) {
		LOG_ERR(PFX "Can not create IPC socket");
		return iscsid_opts.fd;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *)&addr.sun_path + 1, ISCSID_UIP_NAMESPACE,
	       strlen(ISCSID_UIP_NAMESPACE));

	rc = bind(iscsid_opts.fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc < 0) {
		LOG_ERR(PFX "Can not bind IPC socket: %s", strerror(errno));
		goto error;
	}

	rc = listen(iscsid_opts.fd, 32);
	if (rc < 0) {
		LOG_ERR(PFX "Can not listen IPC socket: %s", strerror(errno));
		goto error;
	}

	return 0;
error:
	close(iscsid_opts.fd);
	iscsid_opts.fd = INVALID_FD;

	return rc;
}

/**
 *  iscsid_start() - This function will start the thread used to listen for
 *                  the iscsid broadcast messages
 *  @return 0 on success, <0 on failure
 */
int iscsid_start()
{
	int rc;

	rc = pthread_create(&iscsid_opts.thread, NULL, iscsid_loop, NULL);
	if (rc != 0) {
		LOG_ERR(PFX "Could not start iscsid listening thread rc=%d",
			rc);
		goto error;
	}

	return 0;

error:
	close(iscsid_opts.fd);
	iscsid_opts.fd = INVALID_FD;

	return rc;
}

/**
 *  iscsid_cleanup() - This is called when stoping the thread listening
 *                     for the iscsid broadcast messages
 */
void iscsid_cleanup()
{
	int rc;
	void *res;

	if (iscsid_opts.fd != INVALID_FD) {
		rc = pthread_cancel(iscsid_opts.thread);
		if (rc != 0) {
			LOG_ERR("Could not cancel iscsid listening thread: %s",
				strerror(rc));
		}

		rc = pthread_join(iscsid_opts.thread, &res);
		if (rc != 0) {
			LOG_ERR("Could not wait for the iscsid listening "
				"thread: %s", strerror(rc));
		}
	}

	LOG_INFO(PFX "iscsid listening thread has shutdown");
}
