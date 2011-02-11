/* options.c: CNIC UIO uIP user space stack
 *
 * Copyright (c) 2004-2010 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */
#ifndef __OPTIONS_H__
#define __OPTIONS_H__

#include <byteswap.h>
#include <time.h>
#include <sys/types.h>

/******************************************************************************
 * Constants which are tuned at compile time by the user
 *****************************************************************************/

/**
 * MAX_COUNT_NIC_NL_RESP - This is the maximum number of polls uIP will
 *                         try for a kernel response after a PATH_REQ
 */
#define MAX_COUNT_NIC_NL_RESP 5

/**
 * ENABLE_LOG_UEVENT - By defining ENABLE_LOG_UEVENT this will log all the
 *                     uevents from the kernel that the uIP application 
 *                     sees.  This is useful for debugging purposes
 */
#undef ENABLE_LOG_UEVENT

/**
 * NLM_BUF_DEFAULT_MAX - This is the buffer size allocated for the send/receive
 *                       buffers used by the uIP Netlink subsystem.  This
 *                       value is in bytes.
 */
#define NLM_BUF_DEFAULT_MAX	8192	/* bytes */

/**
 *  NL_POLL_RESOLUTION - This defines the number of milliseconds between
 *                       each polling of the Netlink socket.
 */
#define NL_POLL_RESOLUTION	250	/* milliseconds */

/******************************************************************************
 * Non adjustable constants
 *****************************************************************************/
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP                    0x0800  /* IP */
#endif /* ETHERTYPE_IP */

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6                  0x86dd   /* IP protocol version 6 */
#endif /* ETHERTYPE_IPV6 */

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP                   0x0806  /* Address resolution */
#endif /* ETHERTYPE_ARP */

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN                  0x8100  /* IEEE 802.1Q VLAN tagging */
#endif /* ETHERTYPE_VLAN */

#define APP_NAME "uIP"
/* BUILD_DATE is automatically generated from the Makefile */


#define DEBUG_OFF	0x1
#define DEBUG_ON	0x2

#define INVALID_FD	-1
#define INVALID_THREAD	-1

struct options {
	char debug;

	/*  Time the userspace daemon was started */
	time_t	start_time;
};

extern int event_loop_stop;
extern struct options opt;

#ifdef WORDS_BIGENDIAN
#define ntohll(x)  (x)
#define htonll(x)  (x)
#else
#define ntohll(x)  bswap_64(x)
#define htonll(x)  bswap_64(x)
#endif

# define likely(x)      __builtin_expect(!!(x), 1)
# define unlikely(x)    __builtin_expect(!!(x), 0)

/*  taken from Linux kernel, include/linux/compiler-gcc.h */
/* Optimization barrier */
/* The "volatile" is due to gcc bugs */
#define barrier() __asm__ __volatile__("": : :"memory")

#endif
