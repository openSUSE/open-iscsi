/* logger.h: Logging Utilities
 *
 * Copyright (c) 2004-2010 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 */

#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>

/*******************************************************************************
 * Logger Levels
 ******************************************************************************/
#define LOG_LEVEL_PACKET	5
#define LOG_LEVEL_DEBUG		4
#define LOG_LEVEL_INFO		3
#define LOG_LEVEL_WARN		2
#define LOG_LEVEL_ERR		1
#define LOG_LEVEL_UNKNOWN	0

#define LOG_LEVEL_PACKET_STR	"PKT  "
#define LOG_LEVEL_DEBUG_STR	"DBG  "
#define LOG_LEVEL_INFO_STR	"INFO "
#define LOG_LEVEL_WARN_STR	"WARN "
#define LOG_LEVEL_ERR_STR	"ERR  "
#define LOG_LEVEL_UNKNOWN_STR	"?    "

/*******************************************************************************
 * Logging Macro's
 ******************************************************************************/
#define LOG_PACKET(fmt, args...) { if (LOG_LEVEL_PACKET <= \
					      main_log.level) { \
					log_uip(LOG_LEVEL_PACKET_STR, fmt, ##args);\
				} }
#define LOG_DEBUG(fmt, args...) { if (LOG_LEVEL_DEBUG <= main_log.level) { \
					log_uip(LOG_LEVEL_DEBUG_STR, fmt, ##args);\
				} }

#define LOG_INFO(fmt, args...)  { if (LOG_LEVEL_INFO <= main_log.level) { \
					log_uip(LOG_LEVEL_INFO_STR, fmt, ##args); \
				} }
#define LOG_WARN(fmt, args...)  { if (LOG_LEVEL_WARN <= main_log.level) { \
					log_uip(LOG_LEVEL_WARN_STR, fmt, ##args); \
				} }
#define LOG_ERR(fmt, args...)   { if (LOG_LEVEL_ERR <= main_log.level) { \
					log_uip(LOG_LEVEL_ERR_STR, fmt, ##args); \
				} }

/*******************************************************************************
 * Logging Statistics
 ******************************************************************************/
struct logger_stats {
	uint64_t debug;
	uint64_t info;
	uint64_t warn;
	uint64_t error;

	time_t   last_log_time;
};

/*******************************************************************************
 * Logger Structure
 ******************************************************************************/
struct logger {
	FILE *fp;
	char *log_file;
	int8_t   level;

#define LOGGER_ENABLED	0x01
#define LOGGER_DISABLED	0x02
	int8_t   enabled;

	pthread_mutex_t lock;

	struct logger_stats stats;
};

extern struct logger main_log;

int init_logger(char *);
void log_uip(char *level_str, char *fmt, ...);
void fini_logger();

int backup_logger_settings(struct logger *src, struct logger *dest);
int restore_backup(struct logger *src, struct logger *dest);

#define CLOSE_LOGGER    0x01
#define SHUTDOWN_LOGGER 0x02

#endif
