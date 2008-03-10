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

#include "fwparam_ibft.h"
#include "fw_context.h"

extern int debug;

int
main (int argc, char **argv)
{
	int option, ret;
	char *progname, *filebuf = NULL;

	progname = argv[0];

	while (1) {
		option = getopt(argc, argv, "f:vhb");
		if (option == -1)
			break;
		switch (option) {
		case 'b':
			/* Ignored for compability */
			break;
		case 'f':
			filebuf = optarg;
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

	ret = fwparam_ibft(NULL, filebuf);

	exit(ret);
}
