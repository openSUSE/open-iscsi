/* uip_ipc.h: Generic NIC management/utility functions
 *
 * Copyright (c) 2004-2010 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */

#ifndef __ISCSID_IPC_H__
#define __ISCSID_IPC_H__

#include "uip.h"
#include "mgmt_ipc.h"

mgmt_ipc_err_e iscsid_connect(int *fd);
int iscsid_get_ipaddr(int fd, uip_ip4addr_t *ipaddr);

int iscsid_init();
void iscsid_cleanup();

#endif /* __ISCSID_IPC_H__ */
