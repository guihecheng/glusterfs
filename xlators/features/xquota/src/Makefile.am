xlator_LTLIBRARIES = xquota.la xquotad.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/features

xquota_la_LDFLAGS = -module $(GF_XLATOR_DEFAULT_LDFLAGS)
xquotad_la_LDFLAGS = -module -avoid-version -export-symbols $(top_srcdir)/xlators/features/xquota/src/xquotad.sym

xquota_la_SOURCES = xquota.c xquota-enforcer-client.c
xquota_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la \
                   $(top_builddir)/rpc/xdr/src/libgfxdr.la

xquotad_la_SOURCES = xquotad.c xquotad-helpers.c xquotad-aggregator.c
xquotad_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la \
					$(top_builddir)/rpc/xdr/src/libgfxdr.la

noinst_HEADERS = xquota.h xquotad-helpers.h xquotad-aggregator.h \
				 xquota-mem-types.h xquota-messages.h

AM_CPPFLAGS = $(GF_CPPFLAGS) -I$(top_srcdir)/libglusterfs/src \
			  -I$(top_srcdir)/rpc/xdr/src -I$(top_builddir)/rpc/xdr/src \
			  -I$(top_srcdir)/rpc/rpc-lib/src

AM_CFLAGS = -Wall -fno-strict-aliasing $(GF_CFLAGS)

CLEANFILES =

EXTRA_DIST = xquotad.sym
