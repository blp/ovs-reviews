# ovn-nb IDL for ovn-northd
OVSIDL_BUILT += \
	ovn/northd/northd-nb-idl.c \
	ovn/northd/northd-nb-idl.h \
	ovn/northd/northd-nb-idl.ovsidl
EXTRA_DIST += ovn/northd/northd-nb-idl.ann
NORTHD_NB_IDL_FILES = \
	$(srcdir)/ovn/ovn-nb.ovsschema \
	$(srcdir)/ovn/northd/northd-nb-idl.ann
ovn/northd/northd-nb-idl.ovsidl: $(NORTHD_NB_IDL_FILES)
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(NORTHD_NB_IDL_FILES) > $@.tmp && \
	mv $@.tmp $@

# ovn-northd
bin_PROGRAMS += ovn/northd/ovn-northd
ovn_northd_ovn_northd_SOURCES = \
	ovn/northd/flow-template.c \
	ovn/northd/flow-template.h \
	ovn/northd/northd-nb-idl.c \
	ovn/northd/northd-nb-idl.h \
	ovn/northd/ovn-northd.c \
	ovn/northd/ovn-northd.h \
	ovn/northd/stages.c \
	ovn/northd/stages.h
ovn_northd_ovn_northd_LDADD = \
	ovn/lib/libovn.la \
	ovsdb/libovsdb.la \
	lib/libopenvswitch.la
man_MANS += ovn/northd/ovn-northd.8
EXTRA_DIST += ovn/northd/ovn-northd.8.xml
DISTCLEANFILES += ovn/northd/ovn-northd.8

ftldir = $(pkgdatadir)/ovn/northd
dist_ftl_DATA = 				\
	ovn/northd/lrouter.ftl			\
	ovn/northd/lswitch-acls.ftl		\
	ovn/northd/lswitch-lb.ftl		\
	ovn/northd/lswitch-pre-acls.ftl		\
	ovn/northd/lswitch-pre-lb.ftl		\
	ovn/northd/lswitch-pre-stateful.ftl	\
	ovn/northd/lswitch-stateful.ftl		\
	ovn/northd/lswitch.ftl			\
	ovn/northd/ovn.ftl

# The .ftl flow template files are interpreted at runtime, which means
# that if you screw them up then you don't find out until you start
# testing.  It's better to make mistakes break the build instead, so
# we can move up from #5 to #9 on The Hard To Misuse Positive Score
# List (see http://ozlabs.org/~rusty/index.cgi/tech/2008-03-30.html).
#
# We can't do this if we're cross-compiling, since we can't run the
# ovn-northd binary that we built.  Oh well.
if !CROSS_COMPILING
ALL_LOCAL += ovn/northd/ftl-check
ovn/northd/ftl-check: $(dist_ftl_DATA) ovn/northd/ovn-northd
	$(AM_V_GEN)ovn/northd/ovn-northd --check-syntax --clear-includes \
		-I$(srcdir)/ovn/northd
	$(AM_V_at)touch $@
endif
