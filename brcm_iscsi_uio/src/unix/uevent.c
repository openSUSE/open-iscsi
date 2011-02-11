/* uevent.c: CNIC UIO uIP user space stack
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
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/limits.h>
#include <linux/netlink.h>

#include "nic.h"
#include "nic_vlan.h"
#include "nic_utils.h"
#include "logger.h"
#include "options.h"
#include "uevent.h"

/******************************************************************************
 *  Listening for uevents for cnic and bnx2i 
 ******************************************************************************/
static int uevent_netlink_sock = -1;
static pthread_t uevent_watch_thread = INVALID_THREAD;

/*  Used to notify when the cnic module is loaded */
pthread_mutex_t cnic_module_loaded_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cnic_module_loaded_cond = PTHREAD_COND_INITIALIZER;
int cnic_loaded = 0;

/*  Used to notify when the bnx2i module is loaded */
pthread_mutex_t bnx2i_module_loaded_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t bnx2i_module_loaded_cond = PTHREAD_COND_INITIALIZER;
int bnx2i_loaded = 0;

/******************************************************************************
 *  uevent Contants
 ******************************************************************************/
#define PFX "uevent "

static const char add_cnic_module_str[] = "add@/module/cnic";
static const char remove_cnic_module_str[] = "remove@/module/cnic";
static const char add_uio_module_str[] = "add@/class/uio/uio";
static const char sscanf_uio_module_str[] = "add@/class/uio/uio%d";

static const char uevent_action_key[] = "ACTION=";
static const char uevent_devpath_key[] = "DEVPATH=";
static const char uevent_subsystem_key[] = "SUBSYSTEM=";
static const char uevent_driver_key[] = "DRIVER=";
static const char uevent_seqnum_key[] = "SEQNUM=";
static const char uevent_devpath_old_key[] = "DEVPATH_OLD=";
static const char uevent_physdevpath_key[] = "PHYSDEVPATH=";
static const char uevent_physdevbus_key[] = "PHYSDEVBUS=";
static const char uevent_physdevdriver_key[] = "PHYSDEVDRIVER=";
static const char uevent_major_key[] = "MAJOR=";
static const char uevent_minor_key[] = "MINOR=";
static const char uevent_timeout_key[] = "TIMEOUT=";
static const char uevent_interface_key[] = "INTERFACE=";
static const char uevent_ifindex_key[] = "IFINDEX=";

static const char uevent_add[] = "add";
static const char uevent_remove[] = "remove";
static const char uevent_uio[] = "uio";
static const char uevent_bnx2i[] = "bnx2i";

static const char uevent_cnic_devpath[] = "/module/cnic";
static const char uevent_cnic_subsystem[] = "module";

static const char uevent_bnx2i_devpath[]   = "/module/bnx2i";
static const char uevent_bnx2i_subsystem[] = "module";

static const char uevent_net_devpath[]		= "/class/net";
static const char uevent_net_subsystem[]	= "net";

static const char uio_udev_path_template[] = "/dev/uio%d";

/******************************************************************************
 *  uevent Functions
 ******************************************************************************/
static void parse_uevent(char *buf, int buf_len, struct parsed_uevent *event)
{
	int i;
	int bufpos;

	bufpos = 0;

	event->init = buf;

	for (i = 0; (bufpos < buf_len); i++) {
		char *key = &buf[bufpos];

		if (memcmp(key,
			   uevent_action_key,
			   sizeof(uevent_action_key) - 1) == 0) {
			event->action = &key[sizeof(uevent_action_key) - 1];
			LOG_UEVENT("%s%s", uevent_action_key, event->action);
		} else if (memcmp(key,
				  uevent_devpath_key,
				  sizeof(uevent_devpath_key) - 1) == 0) {
			event->devpath = &key[sizeof(uevent_devpath_key) - 1];
			LOG_UEVENT("%s%s", uevent_devpath_key, event->devpath);

		} else if (memcmp(key,
				  uevent_subsystem_key,
				  sizeof(uevent_subsystem_key) - 1) == 0) {
			event->subsystem =
			    &key[sizeof(uevent_subsystem_key) - 1];
			LOG_UEVENT("%s%s", uevent_subsystem_key,
				   event->subsystem);
		} else
		    if (memcmp
			(key, uevent_driver_key,
			 sizeof(uevent_driver_key) - 1) == 0) {
			event->driver = &key[sizeof(uevent_driver_key) - 1];
			LOG_UEVENT("%s%s", uevent_driver_key, event->driver);
		} else if (memcmp(key,
				  uevent_seqnum_key,
				  sizeof(uevent_seqnum_key) - 1) == 0) {
			event->seqnum = &key[sizeof(uevent_seqnum_key) - 1];
			LOG_UEVENT("%s%s", uevent_seqnum_key, event->seqnum);
		} else if (memcmp(key,
				  uevent_devpath_old_key,
				  sizeof(uevent_devpath_old_key) - 1) == 0) {
			event->devpath_old =
			    &key[sizeof(uevent_devpath_old_key)] - 1;
			LOG_UEVENT("%s%s", uevent_devpath_old_key,
				  event->devpath_old);
		} else
		    if (memcmp
			(key, uevent_physdevpath_key,
			 sizeof(uevent_physdevpath_key) - 1) == 0) {
			event->physdevpath =
			    &key[sizeof(uevent_physdevpath_key) - 1];
			LOG_UEVENT("%s%s", uevent_physdevpath_key,
				  event->physdevpath);
		} else
		    if (memcmp
			(key, uevent_physdevbus_key,
			 sizeof(uevent_physdevbus_key) - 1) == 0) {
			event->physdevbus =
			    &key[sizeof(uevent_physdevbus_key) - 1];
			LOG_UEVENT("%s%s", uevent_physdevbus_key,
				  event->physdevbus);
		} else
		    if (memcmp
			(key, uevent_physdevdriver_key,
			 sizeof(uevent_physdevdriver_key) - 1) == 0) {
			event->physdevdriver =
			    &key[sizeof(uevent_physdevdriver_key) - 1];
			LOG_UEVENT("%s%s", uevent_physdevdriver_key,
				  event->physdevdriver);
		} else
		    if (memcmp
			(key, uevent_major_key,
			 sizeof(uevent_major_key) - 1) == 0) {
			event->major = &key[sizeof(uevent_major_key) - 1];
			LOG_UEVENT("%s%s", uevent_major_key, event->major);
		} else if (memcmp(key,
				  uevent_minor_key,
				  sizeof(uevent_minor_key) - 1) == 0) {
			event->minor = &key[sizeof(uevent_minor_key) - 1];
			LOG_UEVENT("%s%s", uevent_minor_key, event->minor);
		} else if (memcmp(key,
				  uevent_timeout_key,
				  sizeof(uevent_timeout_key) - 1) == 0) {
			event->timeout = &key[sizeof(uevent_timeout_key) - 1];
			LOG_UEVENT("%s%s", uevent_timeout_key, event->timeout);
		} else if (memcmp(key,
				  uevent_interface_key,
				  sizeof(uevent_interface_key) - 1) == 0) {
			event->interface = &key[sizeof(uevent_interface_key) - 1];
			LOG_UEVENT("%s%s", uevent_interface_key,
					  event->interface);
		} else if (memcmp(key,
				  uevent_ifindex_key,
				  sizeof(uevent_ifindex_key) - 1) == 0) {
			event->ifindex = &key[sizeof(uevent_ifindex_key) - 1];
			LOG_UEVENT("%s%s", uevent_ifindex_key, event->ifindex);
		} else {
			LOG_INFO(PFX "Unknown: %s", key);
		}

		bufpos += strlen(key) + 1;
	}
}

/******************************************************************************
 *  wakeup_cnic_dev() - This function will notify all those waiting on the 
 *                      uio_wait_event conditionial.  This should trigger
 *                      all threads waiting on this event.
 *  @param event  - The uevent which comes from the kernel
 *  @param return - 0 on success, <0 on failure
 *****************************************************************************/
static int wakeup_cnic_dev(struct parsed_uevent *event)
{
	int minor;
	nic_t *nic;
	int rc;

	rc = sscanf(event->minor, "%d", &minor);
	if(rc == 1) {
		LOG_INFO(PFX "New uio device registered: minor: %d", minor);
	} else {
		LOG_INFO(PFX "Couldn't parse minor number: %s", event->minor);
		return -EIO;
	}

	pthread_mutex_lock(&nic_list_mutex);
	nic = nic_list;
	while (nic != NULL) {
		if (nic->uio_minor == minor) {
			/* TODO:  we need to wait for all the UIO entries to
			 * appear in sysfs.  Need to determine a discrete way
			 * to determine if this entry extsts */
			struct timespec sleep_req, sleep_rem;

			sleep_req.tv_sec  = 1;
			sleep_req.tv_nsec = 5000000;

			nanosleep(&sleep_req, &sleep_rem);

			/*  Ensure that this is still a bnx2_cnic device */
			rc = nic_verify_uio_sysfs_name(nic);
			if (rc != 0) {
				LOG_WARN(PFX "%s: Could not verify device",
					 nic->log_name);
			}

			nic->log_name = nic->eth_device_name;

			/*  Ensure all the NIC fields are initialized */
			prepare_nic(nic);

			if (nic->flags & NIC_UNITIALIZED) {
				LOG_INFO(PFX "toggling cnic: %s to start",
					 nic->log_name);
				pthread_mutex_lock(&nic->uio_wait_mutex);
				pthread_cond_broadcast(&nic->uio_wait_cond);
				pthread_mutex_unlock(&nic->uio_wait_mutex);
			}

			break;
		}

		nic = nic->next;
	}
	pthread_mutex_unlock(&nic_list_mutex);

	if (nic == NULL) {
                int uio_minor;

		/*  time to alloc a new cnic/uio device */
		LOG_INFO(PFX "Couldn't find dev instance");

		nic = nic_init();
		if(nic == NULL)
		{
			LOG_ERR(PFX "Could not allocate memory for device");

			rc =-ENOMEM;
			goto error;
		}

		nic->uio_minor = minor;

		/*  Malloc space for the uio name */
		nic->uio_device_name = malloc(sizeof(uio_udev_path_template) + 8);
		if(nic->uio_device_name == NULL)
		{
			LOG_ERR(PFX "Could not allocate space for device name");

			rc = -ENOMEM;
			goto error;
		}

		snprintf(nic->uio_device_name,
			 sizeof(uio_udev_path_template) + 8,
			 uio_udev_path_template, minor);

		nic->flags |= NIC_UIO_NAME_MALLOC;

                rc = from_uio_find_associated_eth_device(uio_minor,
						nic->eth_device_name,
						sizeof(nic->eth_device_name));

		nic->config_device_name = nic->eth_device_name;
		nic->log_name = nic->eth_device_name;

		/*  Ensure all the NIC fields are initialized */
		prepare_nic(nic);
	}

	rc = 0;

error:
	return rc;
}

/******************************************************************************
 *  close_cnic_dev() - This function will notify all those waiting on the 
 *                     uio_wait_event conditionial.  This should trigger
 *                     all threads waiting on this event.
 *  @param event  - The uevent which comes from the kernel
 *  @param return - 0 on success, <0 on failure
 *****************************************************************************/
static int close_cnic_dev(struct parsed_uevent *event)
{
	int minor;
	nic_t *nic;
	int rc;

	rc = sscanf(event->minor, "%d", &minor);
	if(rc == 1) {
		LOG_INFO(PFX "Removing uio device: minor: %d", minor);
	} else {
		LOG_INFO(PFX "Couldn't parse minor number: %s", event->minor);
		return -EIO;
	}

	pthread_mutex_lock(&nic_list_mutex);
	nic = nic_list;
	while (nic != NULL) {
		if (nic->uio_minor == minor) {
			nic_remove(nic, 1);

			rc = 0;
			break;
		}

		nic = nic->next;
	}
	pthread_mutex_unlock(&nic_list_mutex);

	if(nic == NULL)
	{
		LOG_INFO(PFX "Couldn't find nic to close");
		return -EINVAL;
	}

	return rc;
}

/**
 *  uevent_close() -  This function is called when exiting the uevent watch
 *  		      loop.   This function will clean up the Netlink socket
 *  		      watching for uevents from the kernel.
 */
static void uevent_close(void *arg)
{
	if (uevent_netlink_sock != -1)
		close(uevent_netlink_sock);
}

/**
 *  uevent_watch_loop() - This function will use Netlink to watch for uevents
 *                        coming from the kernel.  This operates much like
 *                        udev.
 */
static void *uevent_watch_loop(void *arg)
{
	int rc;
	sigset_t set;

	pthread_cleanup_push(uevent_close, NULL);

	sigfillset(&set);
	rc = pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (rc != 0) {
		LOG_ERR(PFX "Couldn't set signal mask for the uevent thread");
	}

	while (1) {
		ssize_t size;
		char buffer[1024];
		struct parsed_uevent event;

		size = recv(uevent_netlink_sock, &buffer, sizeof(buffer), 0);

		if ((size_t) size > sizeof(buffer) - 1)
			size = sizeof(buffer) - 1;
		buffer[size] = '\0';

		memset(&event, 0, sizeof(event));
		parse_uevent(buffer, size, &event);

		/* check if a uio device has been added */
		if ((memcmp(event.action,
			    uevent_add, sizeof(uevent_add)) == 0) &&
		    (memcmp(event.subsystem,
			    uevent_uio, sizeof(uevent_uio)) == 0)) {
			/*  Found a cnic device */
			wakeup_cnic_dev(&event);

		/* check if a uio device has been removed */
		} else if ((memcmp(event.action,
				   uevent_remove, sizeof(uevent_remove)) == 0)&&
			   (memcmp(event.subsystem,
			   	   uevent_uio, sizeof(uevent_uio)) == 0)) {
			/*  Found a cnic device */
			close_cnic_dev(&event);

		/* check if a bnx2i device has been added */
		} else if ((memcmp(event.action,
			    uevent_add, sizeof(uevent_add)) == 0) &&
		    (memcmp(event.subsystem,
			    uevent_bnx2i, sizeof(uevent_bnx2i)) == 0)) {
			/*  Found a bnx2i device */
			pthread_mutex_lock(&bnx2i_module_loaded_mutex);
			bnx2i_loaded = 1;

			pthread_cond_broadcast(&bnx2i_module_loaded_cond);
			pthread_mutex_unlock(&bnx2i_module_loaded_mutex);

		/* check if a bnx2i device has been removed */
		} else if ((memcmp(event.action,
				   uevent_remove, sizeof(uevent_remove)) == 0)&&
			   (memcmp(event.subsystem,
			   	   uevent_uio, sizeof(uevent_bnx2i)) == 0)) {
			/*  Found a cnic device */
			pthread_mutex_lock(&bnx2i_module_loaded_mutex);
			bnx2i_loaded = 0;

			pthread_cond_broadcast(&bnx2i_module_loaded_cond);
			pthread_mutex_unlock(&bnx2i_module_loaded_mutex);

		} else if ((memcmp(event.action,
				   uevent_add, sizeof(uevent_add)) == 0) &&
			   (memcmp(event.devpath,
				   uevent_cnic_devpath,
				   sizeof(uevent_cnic_devpath)) == 0) &&
			   (memcmp(event.subsystem,
				   uevent_cnic_subsystem,
				   sizeof(uevent_cnic_subsystem)) == 0)) {

			LOG_INFO("CNIC module has been loaded");
			pthread_mutex_lock(&cnic_module_loaded_mutex);
			pthread_cond_broadcast(&cnic_module_loaded_cond);
			cnic_loaded = 1;
			pthread_mutex_unlock(&cnic_module_loaded_mutex);
		} else if ((memcmp(event.action,
				   uevent_add, sizeof(uevent_add)) == 0) &&
			   (memcmp(event.devpath,
				   uevent_net_devpath,
				   sizeof(uevent_net_devpath) -1 ) == 0) &&
			   (memcmp(event.subsystem,
				   uevent_net_subsystem,
				   sizeof(uevent_net_subsystem)) == 0)) {
			uint16_t vlan_id;
			int rc;
			char *vlan_iface_name;
			struct vlan_handle handle;

			LOG_DEBUG("New NIC interface %s has been discovered",
				  event.interface);

			init_vlan_table(&handle);
			rc = capture_vlan_table(&handle);
			if(rc != 0) {
				LOG_ERR(PFX "Failed to capture VLAN table");
			}

			rc = find_phy_using_vlan_interface(&handle,
							   event.interface,
							   &vlan_iface_name,
							   &vlan_id);
			if(rc == 1)
			{
				LOG_DEBUG("Interface %s is a vlan",
					  event.interface);
			}

			release_vlan_table(&handle);
		}
	}

	pthread_cleanup_pop(0);

	pthread_exit(NULL);
}

/*******************************************************************************
 *  Public Functions
 ******************************************************************************/
/**
 *  init_uevent_netlink_sock() - This is used to initialize the NetLink
 *  				 connection to the kernel to listen for uevents
 *  @return 0 on success, <0 on failure
 */
int init_uevent_netlink_sock()
{
	struct sockaddr_nl snl;
	const int buffersize = 16 * 1024 * 1024;
	int rc;

	memset(&snl, 0x00, sizeof(struct sockaddr_nl));
	snl.nl_family = AF_NETLINK;
	snl.nl_pid = getpid();
	snl.nl_groups = 1;

	uevent_netlink_sock = socket(PF_NETLINK,
				     SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
	if (uevent_netlink_sock == -1) {
		LOG_ERR(PFX "error getting socket: %s", strerror(errno));
		return -EIO;
	}

	/* set receive buffersize */
	setsockopt(uevent_netlink_sock,
		   SOL_SOCKET, SO_RCVBUFFORCE, &buffersize, sizeof(buffersize));

	rc = bind(uevent_netlink_sock,
		  (struct sockaddr *)&snl, sizeof(struct sockaddr_nl));
	if (rc < 0) {
		LOG_ERR(PFX "bind failed: %s", strerror(errno));
		goto error;
	}

	/*  Spin up the thread used to watch */
	rc = pthread_create(&uevent_watch_thread, NULL,
			    uevent_watch_loop, NULL);
	if (rc != 0) {
		LOG_ERR(PFX "Could not create thread for watching uevents");
		goto error;
	}

	LOG_INFO(PFX "Listening for uevents");

	return 0;

      error:
	close(uevent_netlink_sock);
	uevent_netlink_sock = -1;
	return rc;
}

/**
 *  cleanup_uevent_netlink_sock() - This is used to close the NetLink
 *  				    connection to the kernel listening for 
 *  				    uevents
 *  @return 0 on success, <0 on failure
 */
int cleanup_uevent_netlink_sock()
{
	if (uevent_watch_thread != INVALID_THREAD) {
		int rc;

		/*  Notify that the uevent thread needs to stop */
		rc = pthread_cancel(uevent_watch_thread);
		if (rc != 0) {
			LOG_ERR(PFX "Could not cancel uevent thread: %s",
				strerror(rc));
		}

		/*  Wait for the uevent thread to stop */
		rc = pthread_join(uevent_watch_thread, NULL);
		if (rc != 0) {
			LOG_ERR(PFX "Could not kill uevent thread");
		}

		uevent_watch_thread = INVALID_THREAD;
	}

	LOG_INFO(PFX "uevent thread closed");

	return 0;
}
