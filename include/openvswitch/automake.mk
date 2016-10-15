openvswitchincludedir = $(includedir)/openvswitch
openvswitchinclude_HEADERS = \
	include/openvswitch/compiler.h \
	include/openvswitch/dynamic-string.h \
	include/openvswitch/hmap.h \
	include/openvswitch/geneve.h \
	include/openvswitch/json.h \
	include/openvswitch/list.h \
	include/openvswitch/netdev.h \
	include/openvswitch/match.h \
	include/openvswitch/meta-flow.h \
	include/openvswitch/ofpbuf.h \
	include/openvswitch/ofp-actions.h \
	include/openvswitch/ofp-errors.h \
	include/openvswitch/ofp-msgs.h \
	include/openvswitch/ofp-parse.h \
	include/openvswitch/ofp-print.h \
	include/openvswitch/ofp-prop.h \
	include/openvswitch/ofp-util.h \
	include/openvswitch/shash.h \
	include/openvswitch/thread.h \
	include/openvswitch/token-bucket.h \
	include/openvswitch/tun-metadata.h \
	include/openvswitch/type-props.h \
	include/openvswitch/types.h \
	include/openvswitch/util.h \
	include/openvswitch/uuid.h \
	include/openvswitch/version.h \
	include/openvswitch/vconn.h \
	include/openvswitch/vlog.h
P4C_FILES += \
	include/openvswitch/flow.h.p4c \
	include/openvswitch/meta-flow.h.p4c \
	include/openvswitch/packets.h.p4c \
	include/openvswitch/types.h.p4c
