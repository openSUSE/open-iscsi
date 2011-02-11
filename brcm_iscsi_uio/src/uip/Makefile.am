INCLUDES =	-I${top_srcdir}/src/unix	\
		-I${top_srcdir}/src/apps/dhcpc	\
		-I${top_srcdir}/src/apps/brcm-iscsi \
		-I${top_srcdir}/include

noinst_LIBRARIES = libbrcm_iscsi_uip.a

libbrcm_iscsi_uip_a_SOURCES = 	uip.c		\
				uip_arp.c	\
				psock.c		\
				timer.c		\
				uip-neighbor.c	\
				uip_eth.c

libbrcm_iscsi_uip_a_CFLAGS = 	-DBYTE_ORDER=@ENDIAN@
