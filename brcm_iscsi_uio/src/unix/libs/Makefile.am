# src/unix/libs/Makefile.am:  CNIC UIO libs Makefile.am
#
# Copyright (c) 2004-2010 Broadcom Corporation
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation.
#
# Written by: Benjamin Li  (benli@broadcom.com)
#

INCLUDES = -I${top_srcdir}/src/uip		\
	   -I${top_srcdir}/src/unix		\
	   -I${top_srcdir}/src/unix/libs	\
           -I${top_srcdir}/src/apps/dhcpc	\
           -I${top_srcdir}/include

noinst_LIBRARIES = libbrcm_iscsiuio_hw_cnic.a

libbrcm_iscsiuio_hw_cnic_a_SOURCES =	../build_date.c \
					cnic.c 		\
					bnx2.c		\
					bnx2x.c
