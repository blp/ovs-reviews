# ovn-northd
bin_PROGRAMS += northd/ovn-northd
northd_ovn_northd_SOURCES = northd/ovn-northd.c
northd_ovn_northd_LDADD = \
	lib/libovn.la \
	$(OVSDB_LIBDIR)/libovsdb.la \
	$(OVS_LIBDIR)/libopenvswitch.la
man_MANS += northd/ovn-northd.8
EXTRA_DIST += northd/ovn-northd.8.xml
CLEANFILES += northd/ovn-northd.8

EXTRA_DIST += \
	northd/ovn-northd northd/ovn-northd.8.xml \
	northd/ovn_northd.dl northd/ovn.dl northd/ovn.rs \
	northd/ovn.toml northd/lswitch.dl northd/lrouter.dl \
	northd/helpers.dl northd/ipam.dl northd/multicast.dl \
	northd/docs/design.md  northd/docs/debugging.md \
	northd/docs/new-feature-tutorial.md \
	northd/nb2ddlog northd/sb2ddlog

if DDLOG
BUILT_SOURCES += northd/ovn_northd_ddlog/ddlog.h

bin_PROGRAMS += northd/ovn-northd-ddlog
northd_ovn_northd_ddlog_SOURCES = \
	northd/ovn-northd-ddlog.c \
	northd/ovn_northd_ddlog/ddlog.h
northd_ovn_northd_ddlog_LDADD = \
	lib/libovn.la \
	$(OVSDB_LIBDIR)/libovsdb.la \
	$(OVS_LIBDIR)/libopenvswitch.la \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.la

northd/OVN_Northbound.dl: ovn-nb.ovsschema northd/nb2ddlog
	$(AM_V_GEN)$(srcdir)/northd/nb2ddlog $(srcdir)/ovn-nb.ovsschema > $@.tmp
	$(AM_V_at)mv $@.tmp $@

northd/OVN_Southbound.dl: ovn-sb.ovsschema northd/sb2ddlog
	$(AM_V_GEN)$(srcdir)/northd/sb2ddlog $(srcdir)/ovn-sb.ovsschema > $@.tmp
	$(AM_V_at)mv $@.tmp $@

CLEANFILES += northd/OVN_Northbound.dl northd/OVN_Southbound.dl

northd/ovn_northd_ddlog/ddlog.h: \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a

northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.la: \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a

CARGO_VERBOSE = $(cargo_verbose_$(V))
cargo_verbose_ = $(cargo_verbose_$(AM_DEFAULT_VERBOSITY))
cargo_verbose_0 =
cargo_verbose_1 = --verbose

northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a: \
	northd/ovn_northd.dl	 \
	northd/lswitch.dl	 	 \
	northd/lrouter.dl	 	 \
	northd/ipam.dl			 \
	northd/multicast.dl		 \
	northd/ovn.dl			 \
	northd/ovn.rs			 \
	northd/helpers.dl		 \
	northd/OVN_Northbound.dl \
	northd/OVN_Southbound.dl \
	lib/libovn.la            \
	$(OVS_LIBDIR)/libopenvswitch.la
	$(AM_V_GEN)ddlog -i $< -L $(DDLOGLIBDIR) -L $(builddir)/northd
	$(eval LIBOPENVSWITCH_DEPS=$(shell sh -c "grep -oP \"dependency_libs=\'\K[^\']*\" lib/libovn.la"))
	$(eval LIBOVN_DEPS=$(shell sh -c "grep -oP \"dependency_libs=\'\K[^\']*\" $(OVS_LIBDIR)/libopenvswitch.la"))
	$(AM_V_at)cd northd/ovn_northd_ddlog && \
		RUSTFLAGS="-L ../../lib/.libs -L $(OVS_LIBDIR)/.libs $(LIBOPENVSWITCH_DEPS) $(LIBOVN_DEPS) \
		-Awarnings $(DDLOG_EXTRA_RUSTFLAGS)" cargo build --release \
		$(DDLOG_NORTHD_LIB_ONLY) $(CARGO_VERBOSE)

CLEAN_LOCAL += clean-ddlog
clean-ddlog:
	rm -rf northd/ovn_northd_ddlog

CLEANFILES += \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.la \
	northd/ovn_northd_ddlog/ddlog.h \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a \
	northd/ovn_northd_ddlog/target/release/ovn_northd_cli
endif
