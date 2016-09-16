# ovn-northd
bin_PROGRAMS += ovn/northd/ovn-northd
ovn_northd_ovn_northd_SOURCES = \
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
CLEANFILES += ovn/northd/ovn-northd.8
