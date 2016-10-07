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
	ovn/northd/northd-nb-idl.c \
	ovn/northd/northd-nb-idl.h \
	ovn/northd/ovn-northd.c \
	ovn/northd/ovn-northd.h
ovn_northd_ovn_northd_LDADD = \
	ovn/lib/libovn.la \
	ovsdb/libovsdb.la \
	lib/libopenvswitch.la
man_MANS += ovn/northd/ovn-northd.8
EXTRA_DIST += ovn/northd/ovn-northd.8.xml
DISTCLEANFILES += ovn/northd/ovn-northd.8
