/* uevent.h: CNIC UIO uIP user space stack
 *
 * Copyright (c) 2004-2010 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */

#ifndef __UEVENT_H__
#define __UEVENT_H__

#include <pthread.h>

#ifdef ENABLE_LOG_UEVENT
#define LOG_UEVENT	LOG_DEBUG
#else
#define LOG_UEVENT(fmt, args...)
#endif

extern pthread_mutex_t cnic_module_loaded_mutex;
extern pthread_cond_t  cnic_module_loaded_cond;
extern int cnic_loaded;

extern pthread_mutex_t bnx2i_module_loaded_mutex;
extern pthread_cond_t bnx2i_module_loaded_cond;
extern int bnx2i_loaded;

struct parsed_uevent {
	char *init;
	char *action;
	char *devpath;
	char *subsystem;
	char *driver;
	char *seqnum;
	char *devpath_old;
	char *physdevpath;
	char *physdevbus;
	char *physdevdriver;
	char *major;
	char *minor;
	char *timeout;

	/*  Seen when network interfaces appear */
	char *interface;
	char *ifindex;
};

int init_uevent_netlink_sock();
int cleanup_uevent_netlink_sock();

#endif /* __UEVENT_H__ */
