bin_PROGRAMS += ovn/controller/ovn-controller
ovn_controller_ovn_controller_SOURCES = \
	ovn/controller/bfd.c \
	ovn/controller/bfd.h \
	ovn/controller/binding.c \
	ovn/controller/binding.h \
	ovn/controller/chassis.c \
	ovn/controller/chassis.h \
	ovn/controller/encaps.c \
	ovn/controller/encaps.h \
	ovn/controller/gchassis.c \
	ovn/controller/gchassis.h \
	ovn/controller/lflow.c \
	ovn/controller/lflow.h \
	ovn/controller/ofctrl.c \
	ovn/controller/ofctrl.h \
	ovn/controller/pinctrl.c \
	ovn/controller/pinctrl.h \
	ovn/controller/patch.c \
	ovn/controller/patch.h \
	ovn/controller/ovn-controller.c \
	ovn/controller/ovn-controller.h \
	ovn/controller/physical.c \
	ovn/controller/physical.h
ovn_controller_ovn_controller_LDADD = ovn/lib/libovn.la lib/libopenvswitch.la
man_MANS += ovn/controller/ovn-controller.8
EXTRA_DIST += ovn/controller/ovn-controller.8.xml
CLEANFILES += ovn/controller/ovn-controller.8

ovn_controller_idl_def = \
	ovn/controller/bfd-vswitch-idl.def \
	ovn/controller/bfd-ovn-sb-idl.def \
	ovn/controller/binding-ovn-sb-idl.def \
	ovn/controller/binding-vswitch-idl.def \
	ovn/controller/chassis-ovn-sb-idl.def \
	ovn/controller/chassis-vswitch-idl.def \
	ovn/controller/encaps-ovn-sb-idl.def \
	ovn/controller/encaps-vswitch-idl.def \
	ovn/controller/lflow-ovn-sb-idl.def \
	ovn/controller/ofctrl-vswitch-idl.def \
	ovn/controller/patch-ovn-sb-idl.def \
	ovn/controller/patch-vswitch-idl.def \
	ovn/controller/physical-ovn-sb-idl.def \
	ovn/controller/physical-vswitch-idl.def \
	ovn/controller/pinctrl-ovn-sb-idl.def \
	ovn/controller/pinctrl-vswitch-idl.def
$(ovn_controller_ovn_controller_SOURCES:.c=.$(OBJEXT)): \
	$(ovn_controller_idl_def:.def=.h)
%-vswitch-idl.h: %-vswitch-idl.def lib/vswitch-idl.ovsidl ovsdb/ovsdb-idlc.in
	$(AM_V_GEN)$(OVSDB_IDLC) c-idl-subset lib/vswitch-idl.ovsidl $< >$@.tmp
	$(AM_V_at)mv $@.tmp $@
%-ovn-sb-idl.h: %-ovn-sb-idl.def ovn/lib/ovn-sb-idl.ovsidl ovsdb/ovsdb-idlc.in
	$(AM_V_GEN)$(OVSDB_IDLC) c-idl-subset ovn/lib/ovn-sb-idl.ovsidl $< >$@.tmp
	$(AM_V_at)mv $@.tmp $@
EXTRA_DIST += $(ovn_controller_idl_def)
