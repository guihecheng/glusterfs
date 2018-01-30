xlator_LTLIBRARIES = dir-worm.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/features

noinst_HEADERS = dir-worm.h dir-worm-mem-types.h dir-worm-helper.h

dir_worm_la_LDFLAGS = -module $(GF_XLATOR_DEFAULT_LDFLAGS)

dir_worm_la_SOURCES = dir-worm.c dir-worm-helper.c
dir_worm_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la

AM_CPPFLAGS = $(GF_CPPFLAGS) -I$(top_srcdir)/libglusterfs/src \
	-I$(top_srcdir)/rpc/xdr/src -I$(top_builddir)/rpc/xdr/src

AM_CFLAGS = -Wall $(GF_CFLAGS)

CLEANFILES =
