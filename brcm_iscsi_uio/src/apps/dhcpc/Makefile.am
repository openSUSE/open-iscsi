INCLUDES =	-I${top_srcdir}/src/unix	\
		-I${top_srcdir}/src/uip		\
		-I${top_srcdir}/src/apps/dhcpc	\
		-I${top_srcdir}/src/apps/brcm-iscsi \
		-I${top_srcdir}/include

noinst_LIBRARIES = libbrcm_apps_dhcpc.a

libbrcm_apps_dhcpc_a_SOURCES = 	dhcpc.c

libbrcm_apps_dhcpc_a_CFLAGS =	$(AM_CFLAGS)             \
				-DBYTE_ORDER=@ENDIAN@


