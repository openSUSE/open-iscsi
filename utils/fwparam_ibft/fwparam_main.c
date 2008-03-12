/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Authors:	Patrick Mansfield <patmans@us.ibm.com>
 *		Mike Anderson	<andmike@us.ibm.com>
 *		Hannes Reinecke <hare@suse.de>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>

#include "fwparam_ibft.h"
#include "fw_context.h"

extern int debug;

int get_ifnum_from_mac(char *mac)
{
	int ifnum = -1, fd;
	DIR *d;
	struct dirent *dent;
	char buf[20], attr[64];

	d = opendir("/sys/class/net");
	while ((dent = readdir(d))) {
		if (dent->d_name[0] == '.')
			continue;

		sprintf(attr,"/sys/class/net/%s/address", dent->d_name);
		fd = open(attr,O_RDONLY);
		if (!fd)
			continue;

		read(fd, buf, 18);
		close(fd);

		if (strncmp(mac, buf, strlen(mac)))
			continue;

		if (sscanf(dent->d_name,"eth%d", &ifnum) == 1)
			break;
	}
	closedir(d);

	return ifnum;
}

int
main (int argc, char **argv)
{
	int option, ret, do_ipconfig = 0;
	char *progname, *filebuf = NULL;
	struct boot_context ctxt;

	progname = argv[0];

	while (1) {
		option = getopt(argc, argv, "f:ivhb");
		if (option == -1)
			break;
		switch (option) {
		case 'b':
			/* Ignored for compability */
			break;
		case 'f':
			filebuf = optarg;
			break;
		case 'i':
			do_ipconfig = 1;
			break;
		case 'v':
			debug++;
			break;
		default:
			fprintf(stderr, "Unknown or bad option '%c'\n", option);
		case 'h':
			printf("Usage: %s OPTIONS\n"
			       "-b print only fw boot selected sections\n"
			       "-f file_to_search (default /dev/mem)\n"
			       "-v verbose\n",
			       progname);
			exit(1);
		}
	}

	if (!do_ipconfig)
		ret = fwparam_ibft(NULL, filebuf);
	else {
		ret = fwparam_ibft(&ctxt, filebuf);
		if (!ret)
			/*
			 * Format is:
			 * ipaddr:peeraddr:gwaddr:mask:hostname:iface:none
			 */
			printf("%s::%s:%s::eth%d:ibft\n",
			       ctxt.ipaddr, ctxt.gwaddr,
			       ctxt.mask, get_ifnum_from_mac(ctxt.mac));
	}
	exit(ret);
}
