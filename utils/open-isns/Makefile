prefix	= /usr/local
exec_prefix = ${prefix}
sbindir	= ${exec_prefix}/sbin
mandir	= ${prefix}/share/man
etcdir	= /etc
vardir	= /var/lib/isns

SBINDIR	= $(INSTALL_ROOT)$(sbindir)
ETCDIR	= $(INSTALL_ROOT)$(etcdir)
CFGDIR	= $(ETCDIR)/isns
MANDIR	= $(INSTALL_ROOT)$(mandir)
VARDIR	= $(INSTALL_ROOT)$(vardir)

CC	= gcc
CPPFLAGS=  -D_GNU_SOURCE
CFLAGS	= -Wall -fno-strict-aliasing -fno-strict-aliasing -DOFFLOAD_BOOT_SUPPORTED -DLOCK_DIR="/etc/iscsi" -I.
LDFLAGS	= 

LIB	= libisns.a
LIBOBJS	= server.o \
	  client.o \
	  objects.o \
	  callback.o \
	  timer.o \
	  vendor.o \
	  db.o \
	  db-file.o \
	  db-policy.o \
	  relation.o \
	  scope.o \
	  message.o \
	  security.o \
	  authblock.o \
	  policy.o \
	  register.o \
	  query.o \
	  getnext.o \
	  deregister.o \
	  esi.o \
	  scn.o \
	  dd.o \
	  entity.o \
	  portal-group.o \
	  storage-node.o \
	  domain.o \
	  simple.o \
	  tags.o \
	  attrs.o \
	  export.o \
	  socket.o \
	  slp.o \
	  error.o \
	  logging.o \
	  config.o \
	  parser.o \
	  buffer.o \
	  pidfile.o \
	  sysdep-unix.o \
	  util.o \
	  bitvector.o \
	  mdebug.o
SECLINK	= 
SLPLINK	= 
SLPLIN	= 

all: $(LIB)

clean distclean::
	rm -f *.o $(LIB) *~

distclean::
	rm -f config.h Makefile config.status config.log
	rm -rf autom4te.cache

$(LIB): $(LIBOBJS)
	ar cr $@ $(LIBOBJS)

depend:
	gcc $(CFLAGS) -M `ls *.c` > .depend

-include .depend
