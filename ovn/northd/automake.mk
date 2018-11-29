# ovn-northd
bin_PROGRAMS += ovn/northd/ovn-northd
ovn_northd_ovn_northd_SOURCES = ovn/northd/ovn-northd.c
ovn_northd_ovn_northd_LDADD = \
	ovn/lib/libovn.la \
	ovsdb/libovsdb.la \
	lib/libopenvswitch.la
man_MANS += ovn/northd/ovn-northd.8
EXTRA_DIST += ovn/northd/ovn-northd.8.xml

EXTRA_DIST += ovn/northd/ovn_northd.dl ovn/northd/ovn.dl ovn/northd/ovn.rs
CLEANFILES += ovn/northd/ovn-northd.8

if DDLOG

ovn/northd/ovn-northd.c: ovn/northd/ovn_northd_ddlog/ovn_northd_ddlog.h

ovn/northd/OVN_Northbound.dl: ovn/ovn-nb.ovsschema
	ovsdb2ddlog -f ovn/ovn-nb.ovsschema  > $@

ovn/northd/OVN_Southbound.dl: ovn/ovn-sb.ovsschema
	ovsdb2ddlog -f ovn/ovn-sb.ovsschema \
				-o SB_Global        	\
				-o Logical_Flow     	\
				-o Multicast_Group  	\
				-o Meter            	\
				-o Meter_Band       	\
				-o Datapath_Binding 	\
				-o Port_Binding     	\
				-o Gateway_Chassis  	\
				-o Port_Group       	\
				-o MAC_Binding      	\
				-o DHCP_Options     	\
				-o DHCPv6_Options   	\
				-o Address_Set      	\
				-o DNS              	\
				-o RBAC_Role        	\
				-o RBAC_Permission  	\
				-p Datapath_Binding 	\
				-p Port_Binding     	\
				-p Datapath_Binding 	\
				--ro Port_Binding.chassis       \
				-k Multicast_Group.datapath     \
				-k Multicast_Group.name         \
				-k Multicast_Group.tunnel_key   \
				-k Port_Binding.logical_port    \
				-k DNS.external_ids             \
				-k Datapath_Binding.external_ids\
				-k RBAC_Role.name               \
				-k Address_Set.name             \
				-k Port_Group.name              \
				-k Meter.name                   \
				> $@

CLEANFILES += ovn/northd/OVN_Northbound.dl ovn/northd/OVN_Southbound.dl

ovn/northd/ovn_northd_ddlog/target/debug/ovn_northd_cli: \
	ovn/northd/ovn_northd.dl	 \
	ovn/northd/OVN_Northbound.dl \
	ovn/northd/OVN_Southbound.dl
	$(AM_V_GEN)ddlog -i $< -L @DDLOG_LIB@
	$(AM_V_at)cd ovn/northd/ovn_northd_ddlog && \
		RUSTFLAGS='-L ../../lib/.libs -L ../../../lib/.libs -lssl -lcrypto' cargo build

ovn/northd/ovn_northd_ddlog/target/debug/libovn_northd_ddlog.la: \
	ovn/northd/ovn_northd_ddlog/target/debug/ovn_northd_cli

ovn/northd/ovn_northd_ddlog/ovn_northd_ddlog.h: \
	ovn/northd/ovn_northd_ddlog/target/debug/ovn_northd_cli

ovn_northd_ovn_northd_SOURCES += \
	ovn/northd/ovn_northd_ddlog/ovn_northd_ddlog.h

ovn_northd_ovn_northd_LDADD += \
	ovn/northd/ovn_northd_ddlog/target/debug/libovn_northd_ddlog.la

CLEANFILES += \
	ovn/northd/ovn_northd_ddlog/target/debug/libovn_northd_ddlog.la \
	ovn/northd/ovn_northd_ddlog/ovn_northd_ddlog.h \
	ovn/northd/ovn_northd_ddlog/target/debug/ovn_northd_cli
endif
