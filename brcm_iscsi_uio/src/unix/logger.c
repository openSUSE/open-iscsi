/* logger.c: Logging Utilities
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
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>

#include "options.h"
#include "logger.h"

/******************************************************************************
 * Default logger values
 ******************************************************************************/
static const char default_logger_filename[] = "/var/log/brcm-iscsi.log";

struct logger main_log = {
	.enabled	= LOGGER_ENABLED,
	.fp		= NULL,
	.log_file	= (char *) default_logger_filename,
	.level		= LOG_LEVEL_INFO,
	.lock		= PTHREAD_MUTEX_INITIALIZER,

	.stats		= {
		.debug	= 0,
		.info	= 0,
		.warn	= 0,
		.error	= 0,

		.last_log_time = 0,
	},
};

/******************************************************************************
 * Logger Functions
 ******************************************************************************/
/**
 *  log_stream() - Main logging function
 *  @param fp  - FILE stream to write the log to
 *  @param level_str - log level string
 *  @param fmt - log format
 *  @param ap  - variable argument lists
 */
void log_stream(FILE *fp, char *level_str, char *fmt, va_list ap) 
{
	char time_buf[32];
	va_list va_cp;

	va_copy(va_cp, ap);

	pthread_mutex_lock(&main_log.lock);
	main_log.stats.last_log_time = time(NULL);
	strftime(time_buf, 26, "%a %b %d %T %Y",	
		 localtime(&main_log.stats.last_log_time));
	fprintf(fp, "%s [%s]", level_str, time_buf);
	vfprintf(fp, fmt, va_cp);
	fprintf(fp, "\n");
	pthread_mutex_unlock(&main_log.lock);
}


void log_uip(char *level_str, char *fmt, ...)
{
	va_list ap, va_cp;

	va_start(ap, fmt);
	va_copy(va_cp, ap);

	if(main_log.fp == NULL)
		return;

	if(main_log.enabled == LOGGER_ENABLED)
		log_stream(main_log.fp, level_str, fmt, va_cp);

	if(opt.debug == DEBUG_ON) {
		log_stream(stdout, level_str, fmt, va_cp);

		/* Force the printing of the log file */
		fflush(main_log.fp);

		/* Force the printing of the log out to standard output */
		fflush(stdout);
	}
	va_end(ap);
}

int backup_logger_settings(struct logger *src, struct logger *dest)
{
	dest->level = src->level;

	dest->log_file = malloc(strlen(src->log_file) + 1);
	if(dest->log_file == NULL) {
		LOG_ERR("Could not allocate memory for log file path for backup");
		return -ENOMEM;
	}

	return 0;
}

int restore_backup(struct logger *src, struct logger *dest)
{
	if(dest->log_file != NULL)
	{
		free(dest->log_file);
	}
	dest->log_file = src->log_file;

	return 0;
}



/******************************************************************************
 *  Initialize/Clean up routines
 ******************************************************************************/
/**
 *  init_logger() - Prepare the logger
 *  @param filename - path to where the log will be written to
 *  @return 0 on success, <0 on failure
 */
int init_logger(char *filename)
{
	int rc = 0;

	pthread_mutex_lock(&main_log.lock);

	main_log.fp = fopen( filename, "a");
	if( main_log.fp == NULL) {
		printf("Could not create log file: %s <%s>\n",
		       filename, strerror(errno));
		rc = -EIO;
	}

	pthread_mutex_unlock(&main_log.lock);

	LOG_INFO("Initialize logger using log file: %s", filename);

	return rc;
}

void fini_logger(int type)
{
	pthread_mutex_lock(&main_log.lock);

	if ( main_log.fp != NULL ) {
		fclose(main_log.fp);
		main_log.fp = NULL;

		if(opt.debug == DEBUG_ON) {
			printf("Closed logger\n");
			fflush(stdout);
		}
	}

	if(type == SHUTDOWN_LOGGER) {
		if ( (main_log.log_file != NULL) && 
		     (main_log.log_file != default_logger_filename)) {	   
			free (main_log.log_file );
			main_log.log_file = NULL;
		}
	}

	main_log.enabled = LOGGER_DISABLED;

	pthread_mutex_unlock(&main_log.lock);
}
