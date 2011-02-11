/* cnic.h: CNIC UIO uIP user space stack
 *
 * Copyright (c) 2004-2010 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */

#ifndef __CNIC_NL_H__
#define __CNIC_NL_H__

/*******************************************************************************
 * Constants shared between the bnx2 and bnx2x modules
 ******************************************************************************/
extern const char bnx2i_library_transport_name[];
extern const size_t bnx2i_library_transport_name_size;

int cnic_nl_open();
void cnic_nl_close();

int cnic_handle_iscsi_path_req(nic_t *nic, int, struct iscsi_uevent *,
			       struct iscsi_path *path, size_t len);

#endif /* __CNIC_NL_H__ */
