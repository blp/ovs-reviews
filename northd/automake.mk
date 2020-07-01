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
	northd/ovn-nb.dlopts northd/ovn-sb.dlopts \
	northd/ovsdb2ddlog2c

if DDLOG
bin_PROGRAMS += northd/ovn-northd-ddlog
northd_ovn_northd_ddlog_SOURCES = \
	northd/ovn-northd-ddlog.c \
	northd/ovn-northd-ddlog-sb.inc \
	northd/ovn-northd-ddlog-nb.inc \
	northd/ovn_northd_ddlog/ddlog.h
northd_ovn_northd_ddlog_LDADD = \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.la \
	lib/libovn.la \
	$(OVSDB_LIBDIR)/libovsdb.la \
	$(OVS_LIBDIR)/libopenvswitch.la

nb_opts = $$(cat $(srcdir)/northd/ovn-nb.dlopts)
northd/OVN_Northbound.dl: ovn-nb.ovsschema northd/ovn-nb.dlopts
	$(AM_V_GEN)ovsdb2ddlog -f $< --output-file $@ $(nb_opts)
northd/ovn-northd-ddlog-nb.inc: ovn-nb.ovsschema northd/ovn-nb.dlopts northd/ovsdb2ddlog2c
	$(AM_V_GEN)$(run_python) $(srcdir)/northd/ovsdb2ddlog2c -p nb_ -f $< --output-file $@ $(nb_opts)

sb_opts = $$(cat $(srcdir)/northd/ovn-sb.dlopts)
northd/OVN_Southbound.dl: ovn-sb.ovsschema northd/ovn-sb.dlopts
	$(AM_V_GEN)ovsdb2ddlog -f $< --output-file $@ $(sb_opts)
northd/ovn-northd-ddlog-sb.inc: ovn-sb.ovsschema northd/ovn-sb.dlopts northd/ovsdb2ddlog2c
	$(AM_V_GEN)$(run_python) $(srcdir)/northd/ovsdb2ddlog2c -p sb_ -f $< --output-file $@ $(sb_opts)

BUILT_SOURCES += \
	northd/ovn-northd-ddlog-sb.inc \
	northd/ovn-northd-ddlog-nb.inc

northd/ovn_northd_ddlog/ddlog.h: northd/ddlog.stamp

CARGO_VERBOSE = $(cargo_verbose_$(V))
cargo_verbose_ = $(cargo_verbose_$(AM_DEFAULT_VERBOSITY))
cargo_verbose_0 =
cargo_verbose_1 = --verbose

DDLOGFLAGS = -L $(DDLOGLIBDIR) -L $(builddir)/northd $(DDLOG_EXTRA_FLAGS)

DDLOG_EXTRA_FLAGS = --output-internal-relations --output-input-relations=In_

RUSTFLAGS = \
	-L ../../lib/.libs \
	-L $(OVS_LIBDIR)/.libs \
	$$LIBOPENVSWITCH_DEPS \
	$$LIBOVN_DEPS \
	-Awarnings $(DDLOG_EXTRA_RUSTFLAGS)

ddlog_sources = \
	northd/ovn_northd.dl \
	northd/lswitch.dl \
	northd/lrouter.dl \
	northd/ipam.dl \
	northd/multicast.dl \
	northd/ovn.dl \
	northd/ovn.rs \
	northd/helpers.dl \
	northd/OVN_Northbound.dl \
	northd/OVN_Southbound.dl
northd/ddlog.stamp: $(ddlog_sources)
	$(AM_V_GEN)$(DDLOG) -i $< -o $(builddir)/northd $(DDLOGFLAGS)
	$(AM_V_at)touch $@

NORTHD_LIB = 1
NORTHD_CLI = 0

ddlog_targets = $(northd_lib_$(NORTHD_LIB)) $(northd_cli_$(NORTHD_CLI))
northd_lib_1 = northd/ovn_northd_ddlog/target/release/libovn_%_ddlog.la
northd_cli_1 = northd/ovn_northd_ddlog/target/release/ovn_%_cli
EXTRA_northd_ovn_northd_DEPENDENCIES = $(northd_cli_$(NORTHD_CLI))

cargo_build = $(cargo_build_$(NORTHD_LIB)$(NORTHD_CLI))
cargo_build_01 = --bin ovn_northd_cli
cargo_build_10 = --lib
cargo_build_11 =

$(ddlog_targets): northd/ddlog.stamp lib/libovn.la $(OVS_LIBDIR)/libopenvswitch.la
	$(AM_V_GEN)LIBOVN_DEPS=`. lib/libovn.la && echo "$$dependency_libs"` && \
	LIBOPENVSWITCH_DEPS=`. $(OVS_LIBDIR)/libopenvswitch.la && echo "$$dependency_libs"` && \
	cd northd/ovn_northd_ddlog && \
	RUSTC='$(RUSTC)' RUSTFLAGS="$(RUSTFLAGS)" \
	    cargo build --release $(CARGO_VERBOSE) $(cargo_build)
endif

CLEAN_LOCAL += clean-ddlog
clean-ddlog:
	rm -rf northd/ovn_northd_ddlog

CLEANFILES += \
	northd/ddlog.stamp \
	northd/ovn_northd_ddlog/ddlog.h \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.a \
	northd/ovn_northd_ddlog/target/release/libovn_northd_ddlog.la \
	northd/ovn_northd_ddlog/target/release/ovn_northd_cli
CLEANFILES += \
	northd/OVN_Northbound.dl \
	northd/OVN_Southbound.dl \
	northd/ovn-northd-ddlog-nb.inc \
	northd/ovn-northd-ddlog-sb.inc
