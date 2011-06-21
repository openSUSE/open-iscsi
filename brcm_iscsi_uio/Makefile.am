SUBDIRS= src

EXTRA_DIST = build_date

build_date:
	echo 'char *build_date ="'`date`'";' > build_date.c
	echo 'char *build_date; '> build_date.h

dist_man_MANS = docs/brcm_iscsiuio.8

manprefix = /usr/share
mandir = ${manprefix}/man
logdir = $(DESTDIR)/etc/logrotate.d

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am install-log

install-log:
	$(INSTALL_DATA) -D brcm_iscsiuiolog $(logdir)/brcm_iscsiuiolog
