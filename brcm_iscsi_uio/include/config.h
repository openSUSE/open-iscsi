/*
 * iSCSI Configuration
 *
 * Copyright (C) 2002 Cisco Systems, Inc.
 * maintained by linux-iscsi-devel@lists.sourceforge.net
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <netdb.h>
#include "list.h"

/* ISIDs now have a typed naming authority in them.  We use an OUI */
#define DRIVER_ISID_0  0x00
#define DRIVER_ISID_1  0x02
#define DRIVER_ISID_2  0x3D

/* max len of interface */
#define ISCSI_MAX_IFACE_LEN	65

#if (ISCSID_VERSION == 872) /* 2.0-872 (RHEL 6.0) */

#define ISCSI_HWADDRESS_BUF_SIZE 18
#define ISCSI_TRANSPORT_NAME_MAXLEN 16

typedef struct iface_rec {
	struct list_head	list;
	/* iscsi iface record name */
	char			name[ISCSI_MAX_IFACE_LEN];
	/* network layer iface name (eth0) */
	char			netdev[IFNAMSIZ];
	char			ipaddress[NI_MAXHOST];
	/*
	 * TODO: we may have to make this bigger and interconnect
	 * specific for infinniband 
	 */
	char			hwaddress[ISCSI_HWADDRESS_BUF_SIZE];
	char			transport_name[ISCSI_TRANSPORT_NAME_MAXLEN];
	/*
	 * This is only used for boot now, but the iser guys
	 * can use this for their virtualization idea.
	 */
	char			alias[TARGET_NAME_MAXLEN + 1];
	char			iname[TARGET_NAME_MAXLEN + 1];

	char			vlan[ISCSI_MAX_IFACE_LEN];
} iface_rec_t;

#else /* 2.0-871 (RHEL 5.5)  */
/* number of possible connections per session */
#define ISCSI_CONN_MAX		1

#define ISCSI_TRANSPORT_NAME_MAXLEN 16

typedef struct iface_rec {
	struct list_head	list;
	/* iscsi iface record name */
	char			name[ISCSI_MAX_IFACE_LEN];
	/* network layer iface name (eth0) */
	char			netdev[IFNAMSIZ];
	char			ipaddress[NI_MAXHOST];

	/*
	 * TODO: we may have to make this bigger and interconnect
	 * specific for infinniband 
	 */
	char			hwaddress[ISCSI_MAX_IFACE_LEN];
	char			transport_name[ISCSI_TRANSPORT_NAME_MAXLEN];
	/*
	 * This is only used for boot now, but the iser guys
	 * can use this for their virtualization idea.
	 */
	char			alias[TARGET_NAME_MAXLEN + 1];
	char			iname[TARGET_NAME_MAXLEN + 1];

	char			vlan[ISCSI_MAX_IFACE_LEN];
} iface_rec_t;

#endif /* ISCSID_VERSION */

#endif /* CONFIG_H */
