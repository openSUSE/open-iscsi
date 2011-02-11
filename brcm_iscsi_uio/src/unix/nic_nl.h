/* nic_nl.h: NIC uIP NetLink user space stack
 *
 * Copyright (c) 2004-2010 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */

#ifndef __NIC_NL_H__
#define __NIC_NL_H__

int nic_nl_open();
void nic_nl_close();

int __kipc_call(int fd, void *iov_base, int iov_len);

#endif /* __NIC_NL_H__ */
