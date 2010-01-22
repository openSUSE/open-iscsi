/* iscsi_ipc.c: Generic NIC management/utility functions
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
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

#define PFX "iscsi_ipc "

/* TODO fix me */
#define IFNAMSIZ 15

#include "nic.h"
#include "nic_utils.h"
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

/******************************************************************************
 *  Globals
 ******************************************************************************/
static struct iscsid_options iscsid_opts = {
	.fd = INVALID_FD,
        .thread = INVALID_THREAD,
};

/******************************************************************************
 *  iscsid Functions
 ******************************************************************************/
static void * parse_iface_thread(void * arg) 
{
	int rc;
	nic_t *nic;
	nic_interface_t *nic_iface;
        char *transport_name;
        size_t transport_name_size;
	nic_lib_handle_t *handle;
	struct in_addr addr;
	iscsid_uip_broadcast_t *data;

	data = (iscsid_uip_broadcast_t *) arg;

	/*  Check if we can find the NIC device using the netdev
	 *  name */
	rc = from_netdev_name_find_nic(data->u.iface_rec.rec.netdev, &nic);

	if(rc != 0) {
		LOG_INFO(PFX "Couldn't find interface: %s, creating NIC",
			 data->u.iface_rec.rec.netdev);

		nic = nic_init();
		if(nic == NULL) {
			LOG_ERR(PFX "Could not allocate space for NIC '%s'",
				data->u.iface_rec.rec.netdev);
			goto done;
		}

		nic->config_device_name = strdup(data->u.iface_rec.rec.netdev);
		if(nic->config_device_name == NULL) {
			LOG_ERR(PFX "Could not allocate config device name "
				"for NIC '%s'",
				data->u.iface_rec.rec.netdev);
			goto done;
		}
		nic->flags |= NIC_CONFIG_NAME_MALLOC;
		nic->log_name = nic->config_device_name;

	} else {
		LOG_INFO(PFX "Found interface: %s, using existing NIC",
			 data->u.iface_rec.rec.netdev);
	}

	prepare_nic(nic);

	/*  Sanity Check to ensure the transport names are the same */
	handle = nic->nic_library;
	if(handle != NULL) {
		(*handle->ops->lib_ops.get_transport_name)(&transport_name,
						 &transport_name_size);

		if(strncmp(transport_name,
			   data->u.iface_rec.rec.transport_name,
		           transport_name_size) != 0) {
			LOG_ERR(PFX "%s Transport name is not equal "
				    "expected: %s got: %s",
				    nic->log_name, 
				    data->u.iface_rec.rec.transport_name,
				    transport_name);

		}
	}

	/*  Create the network interface if it doesn't exist */
	nic_iface = nic_find_nic_iface(nic, 0);
	if(nic_iface == NULL) {
		/*  Create the vlan interface */
		nic_iface = nic_iface_init();

		if(nic_iface == NULL) {
			LOG_ERR(PFX "Could not allocate nic_iface",
				nic_iface);
			goto done;
		}

		nic_add_nic_iface(nic, nic_iface);
	}

	/*  Check to see if this is using DHCP or if this is
	 *  a static IPv4 address.  This is done by checking
	 *  if the IP address is equal to 0.0.0.0.  If it is
	 *  then the user has specified to use DHCP.  If not
	 *  then the user has spcicied to use a static IP address
	 *  an the default netmask will be used */
	inet_aton(data->u.iface_rec.rec.ipaddress,
		  (struct in_addr *) &addr);

	if(memcmp(&addr,
		  all_zeroes_addr4, sizeof(all_zeroes_addr4)) == 0) {
		LOG_INFO(PFX "%s: configuring using DHCP",
			 nic->log_name);
		nic_iface->ustack.ip_config = IP_CONFIG_DHCP;
	} else {
		struct in_addr netmask;
		memcpy(&nic_iface->ustack.hostaddr, &addr, sizeof(addr));

		LOG_INFO(PFX "%s: configuring using static IP\n"
		             "  IPv4 address :%s",
			 nic->log_name, inet_ntoa(addr))
		netmask.s_addr = calculate_default_netmask(addr.s_addr);
		LOG_INFO(PFX "  netmask :%s", inet_ntoa(netmask));

		 memcpy(&nic_iface->ustack.netmask,
		 	&netmask,
		 	sizeof(netmask.s_addr));
		nic_iface->ustack.ip_config = IP_CONFIG_STATIC;
	}

	/*  Enable the NIC */
	rc = nic_enable(nic);
	if(rc != 0)
		goto done;

	LOG_INFO(PFX "ISCSID_UIP_IPC_GET_IFACE: command: %x " 
		 "name: %s, netdev: %s ipaddr: %s transport_name:%s",
		 data->header.command, data->u.iface_rec.rec.name,
		 data->u.iface_rec.rec.netdev,
		 inet_ntoa(addr),
		 data->u.iface_rec.rec.transport_name);

done:
	free(data);

	pthread_exit(NULL);
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
	pthread_t tmp_thread;

	fd = fdopen(s2, "r+");
	if (fd == NULL) {
		LOG_ERR(PFX "Couldn't open file descriptor: %d(%s)",
			errno, strerror(errno));
		return -EIO;
	}

	/*  This will be freed by parse_iface_thread() */
	data = (iscsid_uip_broadcast_t *) malloc(sizeof(*data));
	if(data == NULL) {
		LOG_ERR(PFX "Couldn't allocate memory for iface data");
		return -ENOMEM;
	}

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
		/* This thread will be thrown away when completed */
		rc = pthread_create(&tmp_thread, NULL,
				    parse_iface_thread, data);
		if (rc != 0) {
			LOG_ERR(PFX "Couldn't start parse_iface thread rc=%d",
				rc);
			goto error;
		}
		
		break;
	default:
		LOG_WARN(PFX "Unknown iscsid broadcast command: %x",
			 data->header.command);
		free(data);
		break;
	}

	/*  Send a response back to iscsid to tell it the operation succeeded */
	rsp.command = cmd;
	rsp.err =  ISCSID_UIP_MGMT_IPC_OK;

	size = fwrite(&rsp, sizeof(rsp), 1, fd);
	if (size == -1) {
		LOG_ERR(PFX "Could not send response: %d(%s)",
			errno, strerror(errno));
		rc = ferror(fd);
	}

error:
	fclose(fd);

	return rc;
}

static void iscsid_loop_close(void *arg)
{
	close(iscsid_opts.fd);

	LOG_INFO(PFX "Admin socket closed");
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
		LOG_ERR(PFX "Couldn't set signal mask for the iscisd listening thread");
	}

	LOG_DEBUG(PFX "Started iscsid listening thread");

	while (1) {
		struct sockaddr_un remote;
		socklen_t sock_len;
		int s2;

		sock_len = sizeof(remote);
		s2 = accept(iscsid_opts.fd,
			    (struct sockaddr *)&remote, &sock_len);
		if (s2 == -1) {
			if (errno == EAGAIN) {
				LOG_DEBUG("Got EAGAIN from accept");
				sleep(1);
				continue;
			} else if (errno == EINTR) {
				/*  The program is terminating, time to exit */
				break;
			}

			LOG_ERR(PFX "Could not accept: %d(%s)",
				s2, strerror(errno));
			continue;
		}

		process_iscsid_broadcast(s2);
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
	memcpy((char *) &addr.sun_path + 1, ISCSID_UIP_NAMESPACE,
		strlen(ISCSID_UIP_NAMESPACE));

	rc = bind(iscsid_opts.fd,
		  (struct sockaddr *) &addr, sizeof(addr));
	if ( rc < 0) {
		LOG_ERR(PFX "Can not bind IPC socket: %s", strerror(errno));
		goto error;
	}

	rc = listen(iscsid_opts.fd, 32);
	if ( rc < 0) {
		LOG_ERR(PFX "Can not listen IPC socket: %s", strerror(errno));
		goto error;
	}

	rc = pthread_create(&iscsid_opts.thread, NULL, iscsid_loop, NULL);
	if (rc != 0) {
		LOG_ERR(PFX "Could not start iscsid listening thread rc=%d", rc);
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

	if (iscsid_opts.fd != INVALID_FD) {
		rc = pthread_cancel(iscsid_opts.thread);
		if (rc != 0) {
			LOG_ERR("Could not cancel iscsid listening thread: %s",
				strerror(rc));
		}

		rc = pthread_join(iscsid_opts.thread, NULL);
		if (rc != 0) {
			LOG_ERR("Could not wait for the iscsid listenging thread: %s",
				strerror(rc));
		}
	}

	LOG_INFO(PFX "iscsid listening thread has shutdown");
}

