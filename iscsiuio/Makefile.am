SUBDIRS= src

EXTRA_DIST = build_date

build_date:
	echo 'char *build_date = "'`date`'";' > build_date.c
	echo 'char *build_date;'> build_date.h

manprefix = /usr/share
mandir = ${manprefix}/man
logdir = /etc/logrotate.d

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am install-man install-log install-brcm

install-man:
	cat docs/iscsiuio.8 | GZIP=$(GZIP_ENV) gzip -c > iscsiuio.8.gz
	$(INSTALL) -d $(DESTDIR)$(mandir)/man8/
	$(INSTALL_DATA) iscsiuio.8.gz $(DESTDIR)$(mandir)/man8/

install-log:
	$(INSTALL) -d $(DESTDIR)$(logdir)/
	$(INSTALL_DATA) iscsiuiolog $(DESTDIR)$(logdir)/

install-brcm:
	$(RM) $(DESTDIR)$(sbindir)/brcm_iscsiuio
	(cd $(DESTDIR)/$(sbindir); \
	 $(RM) brcm_iscsiuio; \
	 $(LN_S) iscsiuio brcm_iscsiuio)
