SUBDIRS= libs

INCLUDES = -I${top_srcdir}/src/uip		\
	   -I${top_srcdir}/src/apps/brcm-iscsi	\
	   -I${top_srcdir}/src/apps/dhcpc	\
	   -I${top_srcdir}/include		\
	   -I${top_srcdir}/src/unix/libs/

sbin_PROGRAMS = brcm_iscsiuio

brcm_iscsiuio_SOURCES =	build_date.c		\
			main.c			\
			clock-arch.c		\
			logger.c		\
			uevent.c		\
			nic.c			\
			nic_id.c		\
			nic_vlan.c		\
			nic_nl.c		\
			nic_utils.c		\
			packet.c		\
			iscsid_ipc.c

brcm_iscsiuio_CFLAGS = $(AM_CFLAGS)		\
		       $(LIBNL_CFLAGS)		\
		       -DBYTE_ORDER=@ENDIAN@

brcm_iscsiuio_LDFLAGS= $(AM_LDADD)		\
		       -ldl			\
		       -rdynamic		\
		       $(LIBNL_LIBS)		\
		       -lpthread

brcm_iscsiuio_LDADD  = ${top_srcdir}/src/uip/libbrcm_iscsi_uip.a	\
		       ${top_srcdir}/src/apps/dhcpc/libbrcm_apps_dhcpc.a\
		       ${top_srcdir}/src/apps/brcm-iscsi/libbrcm_apps_brcm_iscsi.a \
		       ${top_srcdir}/src/unix/libs/libbrcm_iscsiuio_hw_cnic.a

brcm_iscsiuio_YFLAGS = -d
