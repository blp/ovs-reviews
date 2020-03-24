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

DDLOGFLAGS = -L $(DDLOGLIBDIR) -L $(builddir)/northd $(DDLOG_EXTRA_FLAGS)

#DDLOG_EXTRA_FLAGS = --output-internal-relations

RUSTFLAGS = \
	-L ../../lib/.libs \
	-L $(OVS_LIBDIR)/.libs \
	$(LIBOPENVSWITCH_DEPS) \
	$(LIBOVN_DEPS) \
	-Awarnings $(DDLOG_EXTRA_RUSTFLAGS)

ddlog_deps = \
	northd/ovn_northd.dl \
	northd/lswitch.dl \
	northd/lrouter.dl \
	northd/ipam.dl \
	northd/multicast.dl \
	northd/ovn.dl \
	northd/ovn.rs \
	northd/helpers.dl \
	northd/OVN_Northbound.dl \
	northd/OVN_Southbound.dl \
	lib/libovn.la \
	$(OVS_LIBDIR)/libopenvswitch.la
build_ddlog = \
	$(AM_V_GEN)$(DDLOG) -i $< -o $(builddir)/northd $(DDLOGFLAGS) && \
	LIBOVN_DEPS=`. lib/libovn.la && echo "$$dependency_libs"` && \
	LIBOPENVSWITCH_DEPS=`. $(OVS_LIBDIR)/libopenvswitch.la && echo "$$dependency_libs"` && \
	cd northd/ovn_northd_ddlog && \
	RUSTC='$(RUSTC)' RUSTFLAGS='$(RUSTFLAGS)' \
	    cargo build --release $(CARGO_VERBOSE)

northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a: $(ddlog_deps)
	$(build_ddlog) --lib

# ovn_northd_cli is useful for debugging, but it doubles build time so
# it is not compiled by default, so "make" the following target
# manually when you need it.  See docs/debuggging.md for more
# information.
northd/ovn_northd_ddlog/target/release/ovn_northd_cli: $(ddlog_deps)
	$(build_ddlog) --bin ovn_northd_cli

CLEAN_LOCAL += clean-ddlog
clean-ddlog:
	rm -rf northd/ovn_northd_ddlog

CLEANFILES += \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.la \
	northd/ovn_northd_ddlog/ddlog.h \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a \
	northd/ovn_northd_ddlog/target/release/ovn_northd_cli
endif
