bin_PROGRAMS += controller/ovn-controller
controller_ovn_controller_SOURCES = \
	controller/bfd.c \
	controller/bfd.h \
	controller/binding.c \
	controller/binding.h \
	controller/chassis.c \
	controller/chassis.h \
	controller/ddlog.c \
	controller/ddlog.h \
	controller/encaps.c \
	controller/encaps.h \
	controller/ha-chassis.c \
	controller/ha-chassis.h \
	controller/if-status.c \
	controller/if-status.h \
	controller/ip-mcast.c \
	controller/ip-mcast.h \
	controller/lflow.c \
	controller/lflow.h \
	controller/lflow-cache.c \
	controller/lflow-cache.h \
	controller/lport.c \
	controller/lport.h \
	controller/ofctrl.c \
	controller/ofctrl.h \
	controller/ofctrl-seqno.c \
	controller/ofctrl-seqno.h \
	controller/pinctrl.c \
	controller/pinctrl.h \
	controller/patch.c \
	controller/patch.h \
	controller/ovn-controller.c \
	controller/ovn-controller.h \
	controller/physical.c \
	controller/physical.h \
	controller/mac-learn.c \
	controller/mac-learn.h

controller_ovn_controller_LDADD = lib/libovn.la $(OVS_LIBDIR)/libopenvswitch.la

man_MANS += controller/ovn-controller.8
EXTRA_DIST += controller/ovn-controller.8.xml
CLEANFILES += controller/ovn-controller.8

EXTRA_DIST += \
	controller/ovn-sb.dlopts \
	controller/vswitch.dlopts \
	$(controller_ddlog_sources)

controller_ddlog_sources = \
	controller/ovn_controller.dl
controller_ddlog_nodist_sources = \
	controller/OVN_Southbound.dl \
	controller/OVS.dl


if DDLOG
controller_ovn_controller_LDADD += \
	controller/ovn_controller_ddlog/target/release/libovn_controller_ddlog.la

controller_sb_opts = $$(cat $(srcdir)/controller/ovn-sb.dlopts)
controller/OVN_Southbound.dl: ovn-sb.ovsschema controller/ovn-sb.dlopts
	$(AM_V_GEN)$(OVSDB2DDLOG) -f $< --output-file $@ $(controller_sb_opts)

controller_ovs_opts = $$(cat $(srcdir)/controller/vswitch.dlopts)
controller/OVS.dl: $(OVS_SRCDIR)/vswitchd/vswitch.ovsschema controller/vswitch.dlopts
	$(AM_V_GEN)$(OVSDB2DDLOG) -f $< $(controller_ovs_opts) | sed 's/sFlow/SFlow/g' > $@.tmp && mv $@.tmp $@

BUILT_SOURCES +=controller/ovn_controller_ddlog/ddlog.h

controller/ovn_controller_ddlog/ddlog.h: controller/ddlog.stamp

controller_DDLOGFLAGS = -L $(DDLOGLIBDIR) -L $(builddir)/controller $(DDLOG_EXTRA_FLAGS)

controller/ddlog.stamp: $(controller_ddlog_sources) $(controller_ddlog_nodist_sources)
	$(AM_V_GEN)$(DDLOG) -i $< -o $(builddir)/controller $(controller_DDLOGFLAGS)
	$(AM_V_at)touch $@

CONTROLLER_LIB = 1
CONTROLLER_CLI = 0

controller_ddlog_targets = $(controller_lib_$(CONTROLLER_LIB)) $(controller_cli_$(CONTROLLER_CLI))
controller_lib_1 = controller/ovn_controller_ddlog/target/release/libovn_%_ddlog.la
controller_cli_1 = controller/ovn_controller_ddlog/target/release/ovn_%_cli
EXTRA_controller_ovn_controller_DEPENDENCIES = $(controller_cli_$(CONTROLLER_CLI))

controller_cargo_build = $(controller_cargo_build_$(CONTROLLER_LIB)$(CONTROLLER_CLI))
controller_cargo_build_01 = --features command-line --bin ovn_controller_cli
controller_cargo_build_10 = --lib
controller_cargo_build_11 = --features command-line

$(controller_ddlog_targets): controller/ddlog.stamp lib/libovn.la $(OVS_LIBDIR)/libopenvswitch.la
	$(AM_V_GEN)LIBOVN_DEPS=`$(libtool_deps) lib/libovn.la` && \
	LIBOPENVSWITCH_DEPS=`$(libtool_deps) $(OVS_LIBDIR)/libopenvswitch.la` && \
	cd controller/ovn_controller_ddlog && \
	RUSTC='$(RUSTC)' RUSTFLAGS="$(RUSTFLAGS)" \
	    cargo build --release $(CARGO_VERBOSE) $(controller_cargo_build) --no-default-features --features ovsdb,c_api
endif

CLEAN_LOCAL += clean-controller-ddlog
clean-controller-ddlog:
	rm -rf controller/ovn_controller_ddlog controller/ddlog.stamp

CLEANFILES += \
	controller/ddlog.stamp \
	controller/OVN_Southbound.dl \
	controller/OVS.dl
