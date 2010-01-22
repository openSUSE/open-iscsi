SUBDIRS= src

EXTRA_DIST = build_date

build_date:
	echo 'char *build_date ="'`date`'";' > build_date.c
	echo 'char *build_date; '> build_date.h
