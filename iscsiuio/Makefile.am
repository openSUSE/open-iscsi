SUBDIRS= src

EXTRA_DIST = build_date

build_date:
	echo 'char *build_date ="'`date`'";' > build_date.c
	echo 'char *build_date; '> build_date.h

dist_man_MANS = docs/iscsiuio.8

manprefix = /usr/share
mandir = ${manprefix}/man
logdir = $(DESTDIR)/etc/logrotate.d

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am install-log install-brcm

install-log:
	$(INSTALL_PROGRAM) iscsiuiolog $(logdir)

install-brcm:
	-rm -f $(sbindir)/brcm_iscsiuio
	-ln -s $(sbindir)/iscsiuio $(sbindir)/brcm_iscsiuio
