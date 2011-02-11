/* nic_id.h: NIC uIP NetLink user space stack
 *
 * Copyright (c) 2004-2010 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */

#ifndef __NIC_ID_H__
#define __NIC_ID_H__

int find_set_nic_lib(nic_t *nic);

int get_bus_slot_func_num(nic_t *nic,
                          uint32_t *bus,
                          uint32_t *slot,
                          uint32_t *func);

#endif /* __NIC_ID_H__ */
