/* nic.c: Generic NIC management/utility functions
 *
 * Copyright (c) 2004-2010 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */


#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dhcpc.h"

#include "logger.h"
#include "nic.h"
#include "nic_utils.h"
#include "options.h"

#include "uip.h"
#include "uip_arp.h"
#include "uip_eth.h"
#include "uip-neighbor.h"

#include "bnx2.h"
#include "bnx2x.h"

/******************************************************************************
 *  Constants
 *****************************************************************************/
#define PFX "nic "

/******************************************************************************
 *  Global variables
 *****************************************************************************/
/*  Used to store a list of NIC libraries */
pthread_mutex_t nic_lib_list_mutex = PTHREAD_MUTEX_INITIALIZER;
nic_lib_handle_t *nic_lib_list;

/*  Used to store a list of active cnic devices */
pthread_mutex_t nic_list_mutex = PTHREAD_MUTEX_INITIALIZER;
nic_t *nic_list = NULL;

/******************************************************************************
 *  Functions to handle NIC libraries
 *****************************************************************************/
/**
 *  alloc_nic_library_handle() - Used to allocate a NIC library handle
 *  @return NULL if memory couldn't be allocated, pointer to the handle
 *    to the NIC library handle 
 */
static nic_lib_handle_t * alloc_nic_library_handle()
{
	nic_lib_handle_t *handle;

	handle = malloc(sizeof(*handle));
	if(handle == NULL)
		return NULL;

	memset(handle, 0, sizeof(*handle));
	handle->ops	  = NULL;

	pthread_mutex_init(&handle->mutex, NULL);

	return handle;
}

static void free_nic_library_handle(nic_lib_handle_t *handle)
{
	free(handle);
}

/**
 *  load_nic_library() - This function is used to load a NIC library
 *  @param handle - This is the library handle to load
 *  @return 0 = Success; <0 = failure
 */
static int load_nic_library(nic_lib_handle_t *handle)
{
	int rc;
	char *library_name;
	size_t library_name_size;
	char *library_version;
	size_t library_version_size;
	char *build_date_str;
	size_t build_date_str_size;

	pthread_mutex_lock(&handle->mutex);

	/* Validate the NIC ops table ensure that all the fields are not NULL */
	if ((handle->ops->open)  == NULL ||
	    (handle->ops->close) == NULL ||
	    (handle->ops->read)  == NULL ||
	    (handle->ops->write) == NULL ||
	    (handle->ops->clear_tx_intr == NULL)) {
		LOG_ERR("Invalid NIC ops table: open: 0x%x, close: 0x%x,"
			"read: 0x%x, write: 0x%x clear_tx_intr: 0x%x "
			"lib_ops: 0x%x",
			handle->ops->open, handle->ops->close,
			handle->ops->read, handle->ops->write,
			handle->ops->clear_tx_intr,
			handle->ops->lib_ops);
		rc = -EINVAL;
		handle->ops = NULL;
		goto error;
	}

	/*  Validate the NIC library ops table to ensure that all the proper
	 *  fields are filled */
	if ((handle->ops->lib_ops.get_library_name == NULL) ||
            (handle->ops->lib_ops.get_pci_table == NULL)    || 
            (handle->ops->lib_ops.get_library_version == NULL) ||
            (handle->ops->lib_ops.get_build_date == NULL)   ||
            (handle->ops->lib_ops.get_transport_name == NULL)) {
		rc = -EINVAL;
		goto error;
	}

	(*handle->ops->lib_ops.get_library_name)(&library_name,
				  		 &library_name_size);
	(*handle->ops->lib_ops.get_library_version)(&library_version,
						    &library_version_size);
	(*handle->ops->lib_ops.get_build_date)(&build_date_str,
					       &build_date_str_size);

	LOG_DEBUG("Loaded nic library '%s' Version: '%s' build on %s'",
		  library_name, library_version, build_date_str);
	
	pthread_mutex_unlock(&handle->mutex);

	return 0;

error:
	pthread_mutex_unlock(&handle->mutex);

	return rc;
}

static struct nic_ops * (*nic_get_ops[])() = {
	bnx2_get_ops,
	bnx2x_get_ops,
};

int load_all_nic_libraries()
{
	int rc, i = 0;
	nic_lib_handle_t *handle;

	for(i=0; i < sizeof(nic_get_ops) / sizeof(nic_get_ops[0]); i++) {
		/*  Add the CNIC library */
		handle = alloc_nic_library_handle();
		if(handle == NULL) {
			LOG_ERR("Could not allocate memory for CNIC nic lib");
			return -ENOMEM;
		}

		handle->ops = (*nic_get_ops[i])();

		rc = load_nic_library(handle);
		if(rc != 0)
			return rc;

		/*  Add the CNIC library to the list of library handles */
		pthread_mutex_lock(&nic_lib_list_mutex);
	
		/*  Add this library to the list of nic libraries we
		 *  know about */
		if(nic_lib_list == NULL) {
			nic_lib_list = handle;
		} else {
			nic_lib_handle_t *current = nic_lib_list;

			while(current->next != NULL) {
				current = current->next;
			}

			current->next = handle;
		}
		pthread_mutex_unlock(&nic_lib_list_mutex);

		LOG_DEBUG("Added '%s' nic library", handle->ops->description);
	}

	return rc;
}

int unload_all_nic_libraries() {
	nic_lib_handle_t *current, *next;

	pthread_mutex_lock(&nic_lib_list_mutex);
	current = nic_lib_list;
	
	while(current != NULL) {
		next = current->next;
		free_nic_library_handle(current);

		current = next;
	}

	pthread_mutex_unlock(&nic_lib_list_mutex);

	nic_lib_list = NULL;

	return 0;
}

NIC_LIBRARY_EXIST_T does_nic_uio_name_exist(char *name)
{
	NIC_LIBRARY_EXIST_T rc;
	nic_lib_handle_t *current;

	pthread_mutex_lock(&nic_lib_list_mutex);
	current = nic_lib_list;
	
	while(current != NULL) {
		char *uio_name;
		size_t uio_name_size;

		(*current->ops->lib_ops.get_uio_name)(&uio_name,
						      &uio_name_size);

		if(strncmp(name, uio_name, uio_name_size) == 0) {
			rc = NIC_LIBRARY_EXSITS;
			goto done;
		}

		current = current->next;
	}

	rc = NIC_LIBRARY_DOESNT_EXIST;

done:
	pthread_mutex_unlock(&nic_lib_list_mutex);
	return rc;
}

NIC_LIBRARY_EXIST_T does_nic_library_exist(char *name)
{
	NIC_LIBRARY_EXIST_T rc;
	nic_lib_handle_t *current;

	pthread_mutex_lock(&nic_lib_list_mutex);
	current = nic_lib_list;
	
	while(current != NULL) {
		char *library_name;
		size_t library_name_size;

		(*current->ops->lib_ops.get_library_name)(&library_name,
						 	  &library_name_size);

		if(strncmp(name, library_name, library_name_size) == 0) {
			rc = NIC_LIBRARY_EXSITS;
			goto done;
		}

		current = current->next;
	}

	rc = NIC_LIBRARY_DOESNT_EXIST;

done:
	pthread_mutex_unlock(&nic_lib_list_mutex);
	return rc;
}

/**
 *  find_nic_lib_using_pci_id() - Find the proper NIC library using the 
 *     PCI ID's
 *  @param vendor - PCI vendor ID to search on
 *  @param device - PCI device ID to search on
 *  @param subvendor - PCI subvendor ID to search on
 *  @param subdevice - PCI subdevice ID to search on
 *  @param handle - This function will return the nic lib handle if found
 *  @return 0 if found, <0 not found
 */
int find_nic_lib_using_pci_id(uint32_t vendor, uint32_t device,
			      uint32_t subvendor, uint32_t subdevice,
	 		      nic_lib_handle_t **handle,
			      struct pci_device_id **pci_entry)
{
	int rc;
	nic_lib_handle_t *current;

	pthread_mutex_lock(&nic_lib_list_mutex);
	current = nic_lib_list;
	
	while(current != NULL) {
		struct pci_device_id *pci_table;
		uint32_t entries;
		int i;

		current->ops->lib_ops.get_pci_table(&pci_table, &entries);

		/*  Sanity check the the pci table coming from the 
		 *  hardware library */
		if(entries > MAX_PCI_DEVICE_ENTRIES) {
			LOG_WARN(PFX "Too many pci_table entries(%d) skipping",
				 entries);
			continue;
		}

		for(i=0; i<entries; i++) {
			LOG_DEBUG(PFX "Checking against: "
				      "vendor: 0x%x device:0x%x "
				      "subvendor:0x%x subdevice:0x%x",
				      pci_table[i].vendor, pci_table[i].device,
				      pci_table[i].subvendor,
				      pci_table[i].subdevice);

			if(((vendor & pci_table[i].vendor) == vendor) &&
			   ((device & pci_table[i].device) == device) &&
			   ((subvendor & pci_table[i].subvendor) == subvendor) &&
			   ((subdevice & pci_table[i].subdevice) == subdevice)) {
				*handle = current;
				*pci_entry = &pci_table[i];
				rc = 0;
				goto done;
			}
		}

		current = current->next;
	}
	rc = -EINVAL;

done:
	pthread_mutex_unlock(&nic_lib_list_mutex);
	
	return rc;
}

/**
 * nic_init() - This will properly initialize a struct cnic_uio device
 * @return NULL is there is a failure and pointer to an allocated/initialized
 *         struct cnic_uio on success
 */
nic_t *nic_init()
{
	nic_t *nic;

	nic = malloc(sizeof(*nic));
	if (nic == NULL) {
		LOG_ERR("Coudln't malloc space for nic");
		return NULL;
	}

	memset(nic, 0, sizeof(*nic));
	nic->uio_minor = -1;
	nic->fd   = INVALID_FD;
	nic->next = NULL;
	nic->thread = INVALID_THREAD;
	nic->flags |= NIC_UNITIALIZED | NIC_DISABLED;
	nic->state |= NIC_STOPPED;
	nic->free_packet_queue = NULL;
	nic->tx_packet_queue = NULL;
	nic->nic_library = NULL;
	nic->pci_id	 = NULL;

	pthread_mutex_init(&nic->nic_mutex, NULL);
	pthread_mutex_init(&nic->xmit_mutex, NULL);
	pthread_mutex_init(&nic->uio_wait_mutex, NULL);
	pthread_mutex_init(&nic->free_packet_queue_mutex, NULL);

	pthread_cond_init(&nic->uio_wait_cond, NULL);
	pthread_cond_init(&nic->enable_wait_cond, NULL);
	pthread_cond_init(&nic->enable_done_cond, NULL);
	pthread_cond_init(&nic->nic_loop_started_cond, NULL);
	pthread_cond_init(&nic->disable_wait_cond, NULL);

	nic->rx_poll_usec = DEFAULT_RX_POLL_USEC;

	/*  Add this device to our list of nics */
	pthread_mutex_lock(&nic_list_mutex);
	if(nic_list == NULL) {
		nic_list = nic;
	} else {
		nic_t *current = nic_list;

		while (current->next != NULL) {
			current = current->next;
		}

		current->next = nic;
	}

	pthread_mutex_unlock(&nic_list_mutex);

	return nic;
}

int nic_remove(nic_t *nic, int locked)
{
	int rc;
	nic_t *prev, *current;

	pthread_mutex_lock(&nic->nic_mutex);
	if(nic->ops)
		nic->ops->close(nic, 0);
	pthread_mutex_unlock(&nic->nic_mutex);

	nic->state = NIC_EXIT;
	rc = pthread_cancel(nic->thread);
	if(rc != 0)
		LOG_ERR(PFX "%s: Coudln't send cancel to nic", nic->log_name);

	rc = pthread_join(nic->thread, NULL);
	if(rc != 0)
		LOG_ERR(PFX "%s: Coudln't join to canceled nic thread",
			nic->log_name);

	nic->thread = INVALID_THREAD;

	if(!locked)
		pthread_mutex_lock(&nic_list_mutex);

	current = prev = nic_list;
	while(current != NULL) {
		if(current == nic)
			break;

		prev = current;
		current = current->next;
	}

	if (current != NULL) {
		if (current == nic_list)
			nic_list = current->next;
		else
			prev->next = current->next;

		free(nic);
	} else {
		LOG_ERR(PFX "%s: Coudln't find nic", nic->log_name);
	}

	if(!locked)
		pthread_mutex_unlock(&nic_list_mutex);

	return 0;
}

/** 
 *  nic_close() - Used to indicate to a NIC that it should close
 *                Must be called with nic->nic_mutex
 *  @param nic - the nic to close
 *  @param graceful -  ALLOW_GRACEFUL_SHUTDOWN will check the nic state
 *                     before proceeding to close()
 *                     FORCE_SHUTDOWN will force the nic to close()
 *                     reguardless of the state
 */
void nic_close(nic_t *nic, NIC_SHUTDOWN_T graceful)
{
	int rc;
	nic_interface_t *nic_iface;

	if((nic->flags & NIC_DISABLED) &&
	   (graceful == ALLOW_GRACEFUL_SHUTDOWN))
		return;

	/*  The NIC could be configured by the uIP config file
	 *  but not assoicated with a hardware library just yet
	 *  we will need to check for this */
	if(nic->ops == NULL) {
		LOG_WARN(PFX "%s: when closing nic->ops == NULL",
			 nic->log_name);
		goto error;
	}

	rc = (*nic->ops->close)(nic, graceful);
	if(rc != 0) {
		LOG_ERR(PFX "%s: Could not close nic", nic->log_name);
	} else  {
		nic->state = NIC_STOPPED;
		nic->flags &= ~NIC_ENABLED;
		nic->flags |= NIC_DISABLED;
	}

	nic_iface = nic->nic_iface;
	while(nic_iface != NULL)
	{
		nic_iface->state = NIC_IFACE_STOPPED;
		uip_reset(&nic_iface->ustack);
		nic_iface = nic_iface->next;
	}

error:
	return;
}


/**
 *  net_iface_init() - This function is used to add an interface to the 
 *                     structure cnic_uio
 *  @return 0 on success, <0 on failure
 */
nic_interface_t * nic_iface_init()
{
	nic_interface_t *nic_iface = malloc(sizeof(*nic_iface));
	if(nic_iface == NULL)
	{
		LOG_ERR("Could not allocate space for nic iface");
		return NULL;
	}

	memset(nic_iface, 0, sizeof(*nic_iface));
	nic_iface->next = NULL;

	return nic_iface;
}

/**
 *  nic_add_net_iface() - This function is used to add an interface to the 
 *                        nic structure
 *  @param nic - struct nic device to add the interface to
 *  @param nic_iface - network interface used to add to the nic
 *  @return 0 on success, <0 on failure
 */
int nic_add_nic_iface(nic_t *nic, 
		      nic_interface_t *nic_iface)
{

	pthread_mutex_lock(&nic->nic_mutex);

	/*  Add the nic_interface */
	if(nic->nic_iface == NULL) {
		nic->nic_iface = nic_iface;
	} else {
		nic_interface_t *current = nic->nic_iface;

		while(current->next != NULL)
		{
			current = current->next;
		}

		current->next = nic_iface;
	}

	/* Set nic_interface common fields */
	nic_iface->parent = nic;
	nic->num_of_nic_iface++;

	pthread_mutex_unlock(&nic->nic_mutex);

	return 0;
}

/******************************************************************************
 * Routine to process interrupts from the NIC device
 ******************************************************************************/
/**
 *  nic_process_intr() - Routine used to process interrupts from the hardware
 *  @param nic - NIC hardware to process the interrupt on
 *  @return 0 on success, <0 on failure
 */
int nic_process_intr(nic_t *nic, int discard_check)
{
	fd_set fdset;
	int ret;
	int count;
	struct timeval tv;

	/*  Simple sanity checks */
	if ((discard_check != 1) &&
	    (nic->state & NIC_RUNNING) != NIC_RUNNING) {
		LOG_ERR(PFX "%s: Couldn't process interupt NIC not running",
			nic->log_name);
		return -EBUSY;
	}

	if((discard_check != 1) &&
	   (nic->fd == INVALID_FD)) {
		LOG_ERR(PFX "%s: NIC fd not valid", nic->log_name);
		return -EIO;
	}

	FD_ZERO(&fdset);
	FD_SET(nic->fd, &fdset);

	tv.tv_sec = 0;
	if(nic->state & NIC_LONG_SLEEP) {
		tv.tv_usec = 1000;
	} else {
		tv.tv_usec = nic->rx_poll_usec;
	}

	/*  Wait for an interrupt to come in or timeout */
	ret = select(nic->fd + 1, &fdset, NULL, NULL, &tv);
	switch(ret)
	{
	case 1:
		/* Usually there should only be one file descriptor ready
		 * to read */
		break;
	case 0:
		return ret;
	case -1:
		LOG_ERR(PFX "%s: error waiting for interrupt: %s",
			nic->log_name, strerror(errno));
		return 0;
	default:
		LOG_ERR(PFX "%s: unknown number of FD's, ignoring: %d ret",
			nic->log_name, ret);
		return 0;
	}

	pthread_mutex_lock(&nic->nic_mutex);
	ret = read(nic->fd, &count, sizeof(count));
	if (ret > 0) {
		nic->stats.interrupts++;
		LOG_DEBUG(PFX "%s: interrupt count: %d prev: %d", 
			  nic->log_name, count, nic->intr_count);

		if(count == nic->intr_count) {
			LOG_ERR(PFX "%s: got interrupt but count still the "
				    "same", 
				     nic->log_name, count);
			pthread_mutex_unlock(&nic->nic_mutex);
			return 0;
		}

		/*  Check if we missed an interrupt.  With UIO, 
		 *  the count should be incremental */
		if(count != nic->intr_count + 1) {
			nic->stats.missed_interrupts++;
			LOG_ERR(PFX "%s: Missed interrupt! on %d not %d", 
				nic->log_name, count, nic->intr_count);
		}

		nic->intr_count = count;

		(*nic->ops->clear_tx_intr)(nic);
		ret = 1;
	}
	pthread_mutex_unlock(&nic->nic_mutex);

	return ret;
}

static void prepare_ipv4_packet(nic_t *nic,
				nic_interface_t *nic_iface,
				struct uip_stack *ustack,
				packet_t *pkt)
{
	u16_t ipaddr[2];
	arp_table_query_t arp_query;
	dest_ipv4_addr_t  dest_ipv4_addr;
	struct arp_entry *tabptr;
	int queue_rc;

	dest_ipv4_addr = uip_determine_dest_ipv4_addr(ustack, ipaddr);
	if(dest_ipv4_addr == LOCAL_BROADCAST)
	{
		uip_build_eth_header(ustack, ipaddr, NULL, pkt,
				     nic_iface->vlan_id);
		return;
	}

	arp_query = is_in_arp_table(ipaddr, &tabptr);

	switch(arp_query) {
		case IS_IN_ARP_TABLE:
			uip_build_eth_header(ustack,
					     ipaddr,
					     tabptr,
					     pkt,
					     nic_iface->vlan_id);
			break;
		case NOT_IN_ARP_TABLE:
			queue_rc = nic_queue_tx_packet(nic,
						       nic_iface,
						       pkt);
			uip_build_arp_request(ustack, ipaddr);
			break;
		default:
			LOG_ERR("Unknown arp state");
			break;
	}
}

static void prepare_ustack(nic_t *nic,
		    nic_interface_t *nic_iface,
		    struct uip_stack *ustack,
		    struct packet * pkt)
{
	ustack->uip_buf = pkt->buf;
	ustack->uip_len = pkt->buf_size;

	pkt->nic = nic;
	pkt->nic_iface = nic_iface;

	ustack->data_link_layer = pkt->buf;
	/*  Adjust the network layer pointer depending if
	 *  there is a VLAN tag or not, or if the hardware 
	 *  has stripped out the
	 *  VLAN tag */
	if((nic_iface->vlan_id == 0) ||
	   (NIC_VLAN_STRIP_ENABLED & nic->flags)) {
		ustack->network_layer = ustack->data_link_layer +
				    sizeof(struct uip_eth_hdr);
	} else {
		ustack->network_layer = ustack->data_link_layer +
				    sizeof(struct uip_vlan_eth_hdr);
	}
}

static int check_timers(nic_t *nic,
			struct timer *periodic_timer,
			struct timer *arp_timer,
			uint8_t take_iface_mutex)
{
	if (timer_expired(periodic_timer)) {
		int i;
		nic_interface_t *current;

		timer_reset(periodic_timer);

		if(take_iface_mutex)
			pthread_mutex_lock(&nic->nic_mutex);

		current = nic->nic_iface;
		while(current != NULL)
		{
			packet_t *pkt;
			struct uip_stack *ustack = &current->ustack;

			pkt = get_next_free_packet(nic);
			if(pkt == NULL)
			{
				continue;
			}


			for (i = 0; i < UIP_CONNS; i++) {
				prepare_ustack(nic,
					       current,
					       ustack,
					       pkt);

				uip_periodic(ustack, i);
				/* If the above function invocation resulted
				 * in data that should be sent out on the 
				 * network, the global variable uip_len 
				 * is set to a value > 0. */
				if (ustack->uip_len > 0) {
					pkt->buf_size = ustack->uip_len;

					prepare_ipv4_packet(nic,
							    current,
							    ustack,
							    pkt);

					(*nic->ops->write)(nic, current, pkt);
				}
			}

			for (i = 0; i < UIP_UDP_CONNS; i++) {
				prepare_ustack(nic,
					       current,
					       ustack,
					       pkt);

				uip_udp_periodic(ustack, i);
				/* If the above function invocation resulted
				 * in data that should be sent out on the 
				 * network, the global variable uip_len is 
				 * set to a value > 0. */
				if (ustack->uip_len > 0) {
					pkt->buf_size = ustack->uip_len;

					prepare_ipv4_packet(nic,
							    current,
							    ustack,
							    pkt);

					(*nic->ops->write)(nic, current, pkt);
				}
			}

			/* Call the ARP timer function every 10 seconds. */
			if (timer_expired(arp_timer)) {
				timer_reset(arp_timer);
				uip_arp_timer();
			}

			put_packet_in_free_queue(pkt, nic);

 	               current = current->next;
	        }

		if(take_iface_mutex)
	        	pthread_mutex_unlock(&nic->nic_mutex);
	}

	return 0;
}

int process_packets(nic_t *nic,
		    struct timer *periodic_timer, 
		    struct timer *arp_timer,
		    nic_interface_t *nic_iface)
{
	int rc;
	packet_t *pkt;

	pkt = get_next_free_packet(nic);
	if(pkt == NULL)
		return -ENOMEM;

	pthread_mutex_lock(&nic->nic_mutex);
	rc = (*nic->ops->read)(nic, pkt);
	pthread_mutex_unlock(&nic->nic_mutex);

	if (rc != 0) {
		uint16_t type;
		struct uip_stack *ustack;

		/*  check if we have the given VLAN interface */
		if(nic_iface == NULL) {
			nic_iface = nic_find_nic_iface(nic, pkt->vlan_tag);
			if(nic_iface == NULL)
			{
				LOG_ERR(PFX "%s: Couldn't find interface for "
					    "VLAN: %d trying default stack",
					nic->log_name, pkt->vlan_tag);

				nic_iface = nic_find_nic_iface(nic, 0);
				if(nic_iface == NULL)
				{
					LOG_ERR(PFX "%s: Couldn't find interface for "
						    "VLAN: %d",
						nic->log_name, pkt->vlan_tag);
					rc = 0;
					goto done;
				}
			}
		}

		pkt->nic_iface = nic_iface;

		ustack = &nic_iface->ustack;

		ustack->uip_buf = pkt->buf;
		ustack->uip_len = pkt->buf_size;
		ustack->data_link_layer = pkt->buf;

		pkt->data_link_layer = pkt->buf;

		/*  Adjust the network layer pointer depending if there is a
		 *  VLAN tag or not, or if the hardware has stripped out the
		 *  VLAN tag */
		if((pkt->vlan_tag == 0) || 
		   (NIC_VLAN_STRIP_ENABLED & nic->flags)) {
			ustack->network_layer = ustack->data_link_layer +
					    sizeof(struct uip_eth_hdr);
			pkt->network_layer = pkt->data_link_layer +
					     sizeof(struct uip_eth_hdr);
			type = ntohs(ETH_BUF(pkt->buf)->type);
		} else {
			ustack->network_layer = ustack->data_link_layer +
					    sizeof(struct uip_vlan_eth_hdr);
			pkt->network_layer = pkt->data_link_layer +
					     sizeof(struct uip_vlan_eth_hdr);
			type = ntohs(VLAN_ETH_BUF(pkt->buf)->type);
		}
		
		/*  determine how we should process this packet based on the
		 *  ethernet type */
		switch(type) {
		case UIP_ETHTYPE_IPv6:
			uip_input(ustack);
			if (ustack->uip_len > 0) {
				pthread_mutex_lock(&nic->nic_mutex);
				uip_neighbor_out(ustack);

				(*nic->ops->write)(nic, nic_iface, pkt);
				pthread_mutex_unlock(&nic->nic_mutex);
			}
			break;
		case UIP_ETHTYPE_IPv4:
			uip_arp_ipin(ustack, pkt);
			uip_input(ustack);
			/* If the above function invocation resulted 
			 * in data that should be sent out on the 
			 * network, the global variable uip_len is 
			 * set to a value > 0. */
			if (ustack->uip_len > 0) {
				pthread_mutex_lock(&nic->nic_mutex);
				prepare_ipv4_packet(nic, nic_iface,
						    ustack, pkt);

				(*nic->ops->write)(nic, nic_iface, pkt);
				pthread_mutex_unlock(&nic->nic_mutex);
			}
			break;
		case UIP_ETHTYPE_ARP:
			uip_arp_arpin(ustack, pkt);

			/* If the above function invocation resulted 
			 * in data that should be sent out on the 
			 * network, the global variable uip_len 
			 * is set to a value > 0. */
			if (pkt->buf_size > 0) {
				pthread_mutex_lock(&nic->nic_mutex);
				(*nic->ops->write)(nic, nic_iface, pkt);
				pthread_mutex_unlock(&nic->nic_mutex);
			}
			break;
		}
	}

done:
	put_packet_in_free_queue(pkt, nic);

	return rc;
}

static int process_dhcp_loop(nic_t *nic,
			     nic_interface_t *nic_iface,
			     struct timer *periodic_timer,
			     struct timer *arp_timer)
{
	struct dhcpc_state *s;
	int rc;
	struct timeval start_time;
	struct timeval current_time;
	struct timeval wait_time;
	struct timeval total_time;
	struct timespec sleep_req, sleep_rem;

	sleep_req.tv_sec  = 0;
	sleep_req.tv_nsec = 250000000;

	wait_time.tv_sec  = 10;
	wait_time.tv_usec = 0;

	s = nic_iface->ustack.dhcpc;

	if (gettimeofday(&start_time, NULL)) {
		LOG_ERR(PFX "%s: Couldn't get time of day to start DHCP timer",
			nic->log_name);
                return -EIO;
        }

	timeradd(&start_time, &wait_time, &total_time);

	while ((event_loop_stop == 0) &&
	       (s->state != STATE_CONFIG_RECEIVED) &&
	       (nic->flags & NIC_ENABLED)) {
		/*  Check the periodic and ARP timer */
		check_timers(nic, periodic_timer, arp_timer, 0);

		rc = nic_process_intr(nic, 1);

		while(rc > 0) {
			rc = process_packets(nic,
					     periodic_timer,
					     arp_timer,
					     nic_iface);
		}

		if (gettimeofday(&current_time, NULL)) {
			LOG_ERR(PFX "%s: Couldn't get current time for "
					"DHCP start", nic->log_name);
	                return -EIO;
        	}

		if (timercmp(&total_time, &current_time, <)) {
			LOG_ERR(PFX "%s: timeout waiting for DHCP",
				nic->log_name);
			return -EIO;
		}

		nanosleep(&sleep_req, &sleep_rem);
	}

	return 0;
}


static void nic_loop_close(void *arg)
{
	nic_t *nic = (nic_t *) arg;

	pthread_mutex_lock(&nic->nic_mutex);
	(*nic->ops->close)(nic, 0);
	pthread_mutex_unlock(&nic->nic_mutex);
}

void *nic_loop(void *arg)
{
	nic_t *nic = (nic_t *) arg;
	int rc = -1;
	struct timer periodic_timer, arp_timer;
	sigset_t set;

	sigfillset(&set);
	rc = pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (rc != 0 )
	{
		/* TODO: determine if we need to exit this thread if we fail
		 * to set the signal mask */
		LOG_ERR(PFX "%s: Couldn't set signal mask", nic->log_name);
	}

	pthread_cleanup_push(nic_loop_close, arg);

	/*  Signal the device to enable itself */
	pthread_mutex_lock(&nic->nic_mutex);
	pthread_cond_signal(&nic->nic_loop_started_cond);
	pthread_mutex_unlock(&nic->nic_mutex);

	while(event_loop_stop == 0) {
		nic_interface_t *nic_iface;

		if(nic->flags & NIC_DISABLED)
		{
			LOG_DEBUG(PFX "%s: Waiting to be enabled",
				  nic->log_name);

			/*  Wait for the device to be enabled */
			pthread_mutex_lock(&nic->nic_mutex);
			pthread_cond_wait(&nic->enable_wait_cond,
					  &nic->nic_mutex);
			pthread_mutex_unlock(&nic->nic_mutex);

			if (nic->state == NIC_EXIT)
				pthread_exit(NULL);	

			LOG_DEBUG(PFX "%s: is now enabled", nic->log_name);
		}

		/*  initialize the device to send/rec data */
		rc = (*nic->ops->open)(nic);
		if(rc != 0)
		{
			LOG_ERR(PFX "%s: Could not initialize CNIC UIO device",
				nic->log_name);
			goto dev_close;
		}

		nic_set_all_nic_iface_mac_to_parent(nic);

		rc = alloc_free_queue(nic, 5);
		if(rc != 5)
		{
			if (rc != 0) {
				LOG_WARN(PFX "%s: Allocated %d packets "
					     "instead of %d",
					 nic->log_name, rc, 5);
			} else {
				LOG_ERR(PFX "%s: No packets allocated "
					    "instead of %d",
					 nic->log_name, 5);

				goto dev_close;
			}
		}

		/*  Initialize the system clocks */
		timer_set(&periodic_timer, CLOCK_SECOND / 2);
		timer_set(&arp_timer, CLOCK_SECOND * 10);

		/*  Prepare the stack for each of the VLAN interfaces */
		pthread_mutex_lock(&nic->nic_mutex);

		nic_iface = nic->nic_iface;
		while(nic_iface != NULL)
		{
			uip_init(&nic_iface->ustack,
				 nic->flags & NIC_IPv6_ENABLED);

			LOG_INFO(PFX "%s: Initialized ip stack: VLAN: %d",
				 nic->log_name, nic_iface->vlan_id);

			LOG_INFO(PFX "%s: mac: %02x:%02x:%02x:%02x:%02x:%02x",
				 nic->log_name,
				 nic_iface->mac_addr[0],
				 nic_iface->mac_addr[1],
				 nic_iface->mac_addr[2],
				 nic_iface->mac_addr[3],
				 nic_iface->mac_addr[4],
				 nic_iface->mac_addr[5]);

			if (nic_iface->ustack.ip_config ==
			    IPV4_CONFIG_STATIC) {
				struct in_addr addr;
				uip_ip4addr_t tmp = { 0, 0};

				memcpy(&addr.s_addr, nic_iface->ustack.hostaddr,
				       sizeof(addr.s_addr));

				LOG_INFO(PFX "%s: Using IP address: %s",
					 nic->log_name,
					 inet_ntoa(addr));

				memcpy(&addr.s_addr, nic_iface->ustack.netmask,
				       sizeof(addr.s_addr));

				LOG_INFO(PFX "%s: Using netmask: %s",
					 nic->log_name,
					 inet_ntoa(addr));

				set_uip_stack(&nic_iface->ustack, 
					      &nic_iface->ustack.hostaddr,
					      &nic_iface->ustack.netmask,
					      &tmp,
					      nic_iface->mac_addr);

			} else if (nic_iface->ustack.ip_config ==
			           IPV4_CONFIG_DHCP) {
				struct uip_stack *ustack = &nic_iface->ustack;
				uip_ip4addr_t tmp = { 0, 0};
				
				set_uip_stack(&nic_iface->ustack, 
					      &nic_iface->ustack.hostaddr,
					      &nic_iface->ustack.netmask,
					      &tmp,
					      nic_iface->mac_addr);

				dhcpc_init(nic, ustack,
					   nic_iface->mac_addr, ETH_ALEN);
				pthread_mutex_unlock(&nic->nic_mutex);
				rc = process_dhcp_loop(nic, nic_iface,
						       &periodic_timer,
						       &arp_timer);
				pthread_mutex_lock(&nic->nic_mutex);

				if (rc) {
					pthread_mutex_unlock(&nic->nic_mutex);
					goto dev_close;
				}

				if(nic->flags & NIC_DISABLED) {
					pthread_mutex_unlock(&nic->nic_mutex);
					break;
				}

				LOG_INFO(PFX "%s: Initialized dhcp client",
					 nic->log_name);
			}
			nic_iface->state = NIC_IFACE_RUNNING;

			nic_iface = nic_iface->next;
		}

		pthread_mutex_unlock(&nic->nic_mutex);

                if(nic->flags & NIC_DISABLED) {
			LOG_WARN(PFX "%s: nic was disabled during nic loop, "
				     "closing flag 0x%x",
				 nic->log_name, nic->flags);
                        goto dev_close;
		}

		/*  This is when we start the processing of packets */
		nic->start_time = time(NULL);
		nic->flags &= ~NIC_UNITIALIZED;
		nic->flags |= NIC_INITIALIZED;
		nic->state |= NIC_RUNNING;

                /*  Signal that the device enable is done */
		pthread_mutex_lock(&nic->nic_mutex);
		pthread_cond_broadcast(&nic->enable_done_cond);
		pthread_mutex_unlock(&nic->nic_mutex);

		LOG_INFO(PFX "%s: is now enabled done", nic->log_name);

		while ((nic->state & NIC_RUNNING) && (event_loop_stop == 0)) {
			/*  Check the periodic and ARP timer */
			check_timers(nic,
				     &periodic_timer,
				     &arp_timer,
				     1);

			rc = nic_process_intr(nic, 0);
			while((rc > 0) && (nic->state & NIC_RUNNING)) {
				rc = process_packets(nic,
						     &periodic_timer,
						     &arp_timer,
						     NULL);
			}
		}

dev_close:
		pthread_mutex_lock(&nic->nic_mutex);

		/*  Ensure that the IP configuration is cleared */
		nic_iface = nic->nic_iface;
		while(nic_iface != NULL)
		{
			nic_iface->ustack.ip_config =
				(IPV4_CONFIG_OFF | IPV6_CONFIG_OFF);
			nic_iface = nic_iface->next;
		}

		nic->state = NIC_STOPPED;
		nic_close(nic, 1);

		/*  Signal we are done closing CNIC/UIO device */
		pthread_cond_broadcast(&nic->disable_wait_cond);
		pthread_mutex_unlock(&nic->nic_mutex);
	}

	pthread_cleanup_pop(0);

	pthread_exit(NULL);
}
