/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "ovn-northd.h"

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "bitmap.h"
#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "flow-template.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "ovn-northd.h"
#include "ovn/lex.h"
#include "ovn/lib/ovn-dhcp.h"
#include "ovn/northd/northd-nb-idl.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn/lib/ovn-util.h"
#include "ovn/actions.h"
#include "packets.h"
#include "poll-loop.h"
#include "smap.h"
#include "sset.h"
#include "stages.h"
#include "stream.h"
#include "stream-ssl.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovn_northd);

static unixctl_cb_func ovn_northd_exit;

struct northd_context {
    struct ovsdb_idl *ovnnb_idl;
    struct ovsdb_idl *ovnsb_idl;
    struct ovsdb_idl_txn *ovnnb_txn;
    struct ovsdb_idl_txn *ovnsb_txn;
};

/* --check-syntax: Check the .ftl input syntax and exit. */
static bool check_syntax;

/* -I, --include: Path to search for .ftl source files. */
static struct ds include_path;

/* --ovnnb-db, --ovnsb-db: Remotes for connecting to northbound and southbound
 * databases. */
static const char *ovnnb_db;
static const char *ovnsb_db;

#define MAC_ADDR_PREFIX 0x0A0000000000ULL
#define MAC_ADDR_SPACE 0xffffff

/* MAC address management (macam) table of "struct eth_addr"s, that holds the
 * MAC addresses allocated by the OVN ipam module. */
static struct hmap macam = HMAP_INITIALIZER(&macam);

#define MAX_OVN_TAGS 4096

/* Due to various hard-coded priorities need to implement ACLs, the
 * northbound database supports a smaller range of ACL priorities than
 * are available to logical flows.  This value is added to an ACL
 * priority to determine the ACL's logical flow priority. */
#define OVN_ACL_PRI_OFFSET 1000

#define REGBIT_CONNTRACK_DEFRAG "reg0[0]"
#define REGBIT_CONNTRACK_COMMIT "reg0[1]"
#define REGBIT_CONNTRACK_NAT    "reg0[2]"
#define REGBIT_DHCP_OPTS_RESULT "reg0[3]"

static void
usage(void)
{
    printf("\
%s: OVN northbound management daemon\n\
usage: %s [OPTIONS]\n\
\n\
Options:\n\
  --ovnnb-db=DATABASE       connect to ovn-nb database at DATABASE\n\
                            (default: %s)\n\
  --ovnsb-db=DATABASE       connect to ovn-sb database at DATABASE\n\
                            (default: %s)\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_nb_db(), default_sb_db());
    daemon_usage();
    vlog_usage();
    stream_usage("database", true, true, false);
}

struct tnlid_node {
    struct hmap_node hmap_node;
    uint32_t tnlid;
};

static void
destroy_tnlids(struct hmap *tnlids)
{
    struct tnlid_node *node;
    HMAP_FOR_EACH_POP (node, hmap_node, tnlids) {
        free(node);
    }
    hmap_destroy(tnlids);
}

static void
add_tnlid(struct hmap *set, uint32_t tnlid)
{
    struct tnlid_node *node = xmalloc(sizeof *node);
    hmap_insert(set, &node->hmap_node, hash_int(tnlid, 0));
    node->tnlid = tnlid;
}

static bool
tnlid_in_use(const struct hmap *set, uint32_t tnlid)
{
    const struct tnlid_node *node;
    HMAP_FOR_EACH_IN_BUCKET (node, hmap_node, hash_int(tnlid, 0), set) {
        if (node->tnlid == tnlid) {
            return true;
        }
    }
    return false;
}

static uint32_t
allocate_tnlid(struct hmap *set, const char *name, uint32_t max,
               uint32_t *hint)
{
    for (uint32_t tnlid = *hint + 1; tnlid != *hint;
         tnlid = tnlid + 1 <= max ? tnlid + 1 : 1) {
        if (!tnlid_in_use(set, tnlid)) {
            add_tnlid(set, tnlid);
            *hint = tnlid;
            return tnlid;
        }
    }

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    VLOG_WARN_RL(&rl, "all %s tunnel ids exhausted", name);
    return 0;
}

struct ovn_chassis_qdisc_queues {
    struct hmap_node key_node;
    uint32_t queue_id;
    struct uuid chassis_uuid;
};

static void
destroy_chassis_queues(struct hmap *set)
{
    struct ovn_chassis_qdisc_queues *node;
    HMAP_FOR_EACH_POP (node, key_node, set) {
        free(node);
    }
    hmap_destroy(set);
}

static void
add_chassis_queue(struct hmap *set, struct uuid *chassis_uuid,
                  uint32_t queue_id)
{
    struct ovn_chassis_qdisc_queues *node = xmalloc(sizeof *node);
    node->queue_id = queue_id;
    memcpy(&node->chassis_uuid, chassis_uuid, sizeof node->chassis_uuid);
    hmap_insert(set, &node->key_node, uuid_hash(chassis_uuid));
}

static bool
chassis_queueid_in_use(const struct hmap *set, struct uuid *chassis_uuid,
                       uint32_t queue_id)
{
    const struct ovn_chassis_qdisc_queues *node;
    HMAP_FOR_EACH_WITH_HASH (node, key_node, uuid_hash(chassis_uuid), set) {
        if (uuid_equals(chassis_uuid, &node->chassis_uuid)
            && node->queue_id == queue_id) {
            return true;
        }
    }
    return false;
}

static uint32_t
allocate_chassis_queueid(struct hmap *set, struct sbrec_chassis *chassis)
{
    for (uint32_t queue_id = QDISC_MIN_QUEUE_ID + 1;
         queue_id <= QDISC_MAX_QUEUE_ID;
         queue_id++) {
        if (!chassis_queueid_in_use(set, &chassis->header_.uuid, queue_id)) {
            add_chassis_queue(set, &chassis->header_.uuid, queue_id);
            return queue_id;
        }
    }

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    VLOG_WARN_RL(&rl, "all %s queue ids exhausted", chassis->name);
    return 0;
}

static void
free_chassis_queueid(struct hmap *set, struct sbrec_chassis *chassis,
                     uint32_t queue_id)
{
    struct ovn_chassis_qdisc_queues *node;
    HMAP_FOR_EACH_WITH_HASH (node, key_node,
                             uuid_hash(&chassis->header_.uuid),
                             set) {
        if (uuid_equals(&chassis->header_.uuid, &node->chassis_uuid)
            && node->queue_id == queue_id) {
            hmap_remove(set, &node->key_node);
            break;
        }
    }
}

static inline bool
port_has_qos_params(const struct smap *opts)
{
    return (smap_get(opts, "qos_max_rate") ||
            smap_get(opts, "qos_burst"));
}

/* The 'key' comes from nbs->header_.uuid or nbr->header_.uuid or
 * sb->external_ids:logical-switch. */
struct ovn_datapath {
    struct hmap_node key_node;  /* Index on 'key'. */
    struct uuid key;            /* (nbs/nbr)->header_.uuid. */

    const struct nbrec_logical_switch *nbs;  /* May be NULL. */
    const struct nbrec_logical_router *nbr;  /* May be NULL. */
    const struct sbrec_datapath_binding *sb; /* May be NULL. */

    struct ovs_list list;       /* In list of similar records. */

    /* Logical switch data. */
    struct ovn_port **router_ports;
    size_t n_router_ports;

    struct hmap port_tnlids;
    uint32_t port_key_hint;

    /* IPAM data. */
    struct hmap ipam;
};

struct macam_node {
    struct hmap_node hmap_node;
    struct eth_addr mac_addr; /* Allocated MAC address. */
};

static void
cleanup_macam(struct hmap *macam)
{
    struct macam_node *node;
    HMAP_FOR_EACH_POP (node, hmap_node, macam) {
        free(node);
    }
}

struct ipam_node {
    struct hmap_node hmap_node;
    uint32_t ip_addr; /* Allocated IP address. */
};

static void
destroy_ipam(struct hmap *ipam)
{
    struct ipam_node *node;
    HMAP_FOR_EACH_POP (node, hmap_node, ipam) {
        free(node);
    }
    hmap_destroy(ipam);
}

static struct ovn_datapath *
ovn_datapath_create(struct hmap *datapaths, const struct uuid *key,
                    const struct nbrec_logical_switch *nbs,
                    const struct nbrec_logical_router *nbr,
                    const struct sbrec_datapath_binding *sb)
{
    struct ovn_datapath *od = xzalloc(sizeof *od);
    od->key = *key;
    od->sb = sb;
    od->nbs = nbs;
    od->nbr = nbr;
    hmap_init(&od->port_tnlids);
    hmap_init(&od->ipam);
    od->port_key_hint = 0;
    hmap_insert(datapaths, &od->key_node, uuid_hash(&od->key));
    return od;
}

static void
ovn_datapath_destroy(struct hmap *datapaths, struct ovn_datapath *od)
{
    if (od) {
        /* Don't remove od->list.  It is used within build_datapaths() as a
         * private list and once we've exited that function it is not safe to
         * use it. */
        hmap_remove(datapaths, &od->key_node);
        destroy_tnlids(&od->port_tnlids);
        destroy_ipam(&od->ipam);
        free(od->router_ports);
        free(od);
    }
}

/* Returns 'od''s datapath type. */
static enum ovn_datapath_type
ovn_datapath_get_type(const struct ovn_datapath *od)
{
    return od->nbs ? DP_SWITCH : DP_ROUTER;
}

struct ovn_datapath *
ovn_datapath_find(struct hmap *datapaths, const struct uuid *uuid)
{
    struct ovn_datapath *od;

    HMAP_FOR_EACH_WITH_HASH (od, key_node, uuid_hash(uuid), datapaths) {
        if (uuid_equals(uuid, &od->key)) {
            return od;
        }
    }
    return NULL;
}

static struct ovn_datapath *
ovn_datapath_from_sbrec(struct hmap *datapaths,
                        const struct sbrec_datapath_binding *sb)
{
    struct uuid key;

    if (!smap_get_uuid(&sb->external_ids, "logical-switch", &key) &&
        !smap_get_uuid(&sb->external_ids, "logical-router", &key)) {
        return NULL;
    }
    return ovn_datapath_find(datapaths, &key);
}

static bool
lrouter_is_enabled(const struct nbrec_logical_router *lrouter)
{
    return !lrouter->enabled || *lrouter->enabled;
}

static void
join_datapaths(struct northd_context *ctx, struct hmap *datapaths,
               struct ovs_list *sb_only, struct ovs_list *nb_only,
               struct ovs_list *both)
{
    hmap_init(datapaths);
    ovs_list_init(sb_only);
    ovs_list_init(nb_only);
    ovs_list_init(both);

    const struct sbrec_datapath_binding *sb, *sb_next;
    SBREC_DATAPATH_BINDING_FOR_EACH_SAFE (sb, sb_next, ctx->ovnsb_idl) {
        struct uuid key;
        if (!smap_get_uuid(&sb->external_ids, "logical-switch", &key) &&
            !smap_get_uuid(&sb->external_ids, "logical-router", &key)) {
            ovsdb_idl_txn_add_comment(
                ctx->ovnsb_txn,
                "deleting Datapath_Binding "UUID_FMT" that lacks "
                "external-ids:logical-switch and "
                "external-ids:logical-router",
                UUID_ARGS(&sb->header_.uuid));
            sbrec_datapath_binding_delete(sb);
            continue;
        }

        if (ovn_datapath_find(datapaths, &key)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_INFO_RL(
                &rl, "deleting Datapath_Binding "UUID_FMT" with "
                "duplicate external-ids:logical-switch/router "UUID_FMT,
                UUID_ARGS(&sb->header_.uuid), UUID_ARGS(&key));
            sbrec_datapath_binding_delete(sb);
            continue;
        }

        struct ovn_datapath *od = ovn_datapath_create(datapaths, &key,
                                                      NULL, NULL, sb);
        ovs_list_push_back(sb_only, &od->list);
    }

    const struct nbrec_logical_switch *nbs;
    NBREC_LOGICAL_SWITCH_FOR_EACH (nbs, ctx->ovnnb_idl) {
        struct ovn_datapath *od = ovn_datapath_find(datapaths,
                                                    &nbs->header_.uuid);
        if (od) {
            od->nbs = nbs;
            ovs_list_remove(&od->list);
            ovs_list_push_back(both, &od->list);
        } else {
            od = ovn_datapath_create(datapaths, &nbs->header_.uuid,
                                     nbs, NULL, NULL);
            ovs_list_push_back(nb_only, &od->list);
        }
    }

    const struct nbrec_logical_router *nbr;
    NBREC_LOGICAL_ROUTER_FOR_EACH (nbr, ctx->ovnnb_idl) {
        if (!lrouter_is_enabled(nbr)) {
            continue;
        }

        struct ovn_datapath *od = ovn_datapath_find(datapaths,
                                                    &nbr->header_.uuid);
        if (od) {
            if (!od->nbs) {
                od->nbr = nbr;
                ovs_list_remove(&od->list);
                ovs_list_push_back(both, &od->list);
            } else {
                /* Can't happen! */
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl,
                             "duplicate UUID "UUID_FMT" in OVN_Northbound",
                             UUID_ARGS(&nbr->header_.uuid));
                continue;
            }
        } else {
            od = ovn_datapath_create(datapaths, &nbr->header_.uuid,
                                     NULL, nbr, NULL);
            ovs_list_push_back(nb_only, &od->list);
        }
    }
}

static uint32_t
ovn_datapath_allocate_key(struct hmap *dp_tnlids)
{
    static uint32_t hint;
    return allocate_tnlid(dp_tnlids, "datapath", (1u << 24) - 1, &hint);
}

/* Updates the southbound Datapath_Binding table so that it contains the
 * logical switches and routers specified by the northbound database.
 *
 * Initializes 'datapaths' to contain a "struct ovn_datapath" for every logical
 * switch and router. */
static void
build_datapaths(struct northd_context *ctx, struct hmap *datapaths)
{
    struct ovs_list sb_only, nb_only, both;

    join_datapaths(ctx, datapaths, &sb_only, &nb_only, &both);

    if (!ovs_list_is_empty(&nb_only)) {
        /* First index the in-use datapath tunnel IDs. */
        struct hmap dp_tnlids = HMAP_INITIALIZER(&dp_tnlids);
        struct ovn_datapath *od;
        LIST_FOR_EACH (od, list, &both) {
            add_tnlid(&dp_tnlids, od->sb->tunnel_key);
        }

        /* Add southbound record for each unmatched northbound record. */
        LIST_FOR_EACH (od, list, &nb_only) {
            uint16_t tunnel_key = ovn_datapath_allocate_key(&dp_tnlids);
            if (!tunnel_key) {
                break;
            }

            od->sb = sbrec_datapath_binding_insert(ctx->ovnsb_txn);

            /* Get the logical-switch or logical-router UUID to set in
             * external-ids. */
            char uuid_s[UUID_LEN + 1];
            sprintf(uuid_s, UUID_FMT, UUID_ARGS(&od->key));
            const char *key = od->nbs ? "logical-switch" : "logical-router";

            /* Get name to set in external-ids. */
            const char *name = od->nbs ? od->nbs->name : od->nbr->name;

            /* Set external-ids. */
            struct smap ids = SMAP_INITIALIZER(&ids);
            smap_add(&ids, key, uuid_s);
            if (*name) {
                smap_add(&ids, "name", name);
            }
            sbrec_datapath_binding_set_external_ids(od->sb, &ids);
            smap_destroy(&ids);

            sbrec_datapath_binding_set_tunnel_key(od->sb, tunnel_key);
        }
        destroy_tnlids(&dp_tnlids);
    }

    /* Delete southbound records without northbound matches. */
    struct ovn_datapath *od, *next;
    LIST_FOR_EACH_SAFE (od, next, list, &sb_only) {
        ovs_list_remove(&od->list);
        sbrec_datapath_binding_delete(od->sb);
        ovn_datapath_destroy(datapaths, od);
    }
}

struct ovn_port {
    struct hmap_node key_node;  /* Index on 'key'. */
    char *key;                  /* nbs->name, nbr->name, sb->logical_port. */
    char *json_key;             /* 'key', quoted for use in JSON. */

    const struct sbrec_port_binding *sb;         /* May be NULL. */

    /* Logical switch port data. */
    const struct nbrec_logical_switch_port *nbsp; /* May be NULL. */

    /* Logical router port data. */
    const struct nbrec_logical_router_port *nbrp; /* May be NULL. */

    struct lport_addresses lrp_networks;

    /* The port's peer:
     *
     *     - A switch port S of type "router" has a router port R as a peer,
     *       and R in turn has S has its peer.
     *
     *     - Two connected logical router ports have each other as peer. */
    struct ovn_port *peer;

    struct ovn_datapath *od;

    struct ovs_list list;       /* In list of similar records. */
};

static struct ovn_port *
ovn_port_create(struct hmap *ports, const char *key,
                const struct nbrec_logical_switch_port *nbsp,
                const struct nbrec_logical_router_port *nbrp,
                const struct sbrec_port_binding *sb)
{
    struct ovn_port *op = xzalloc(sizeof *op);

    struct ds json_key = DS_EMPTY_INITIALIZER;
    json_string_escape(key, &json_key);
    op->json_key = ds_steal_cstr(&json_key);

    op->key = xstrdup(key);
    op->sb = sb;
    op->nbsp = nbsp;
    op->nbrp = nbrp;
    hmap_insert(ports, &op->key_node, hash_string(op->key, 0));
    return op;
}

static void
ovn_port_destroy(struct hmap *ports, struct ovn_port *port)
{
    if (port) {
        /* Don't remove port->list.  It is used within build_ports() as a
         * private list and once we've exited that function it is not safe to
         * use it. */
        hmap_remove(ports, &port->key_node);

        destroy_lport_addresses(&port->lrp_networks);
        free(port->json_key);
        free(port->key);
        free(port);
    }
}

static struct ovn_port *
ovn_port_find(struct hmap *ports, const char *name)
{
    struct ovn_port *op;

    HMAP_FOR_EACH_WITH_HASH (op, key_node, hash_string(name, 0), ports) {
        if (!strcmp(op->key, name)) {
            return op;
        }
    }
    return NULL;
}

static uint32_t
ovn_port_allocate_key(struct ovn_datapath *od)
{
    return allocate_tnlid(&od->port_tnlids, "port",
                          (1u << 15) - 1, &od->port_key_hint);
}

static bool
ipam_is_duplicate_mac(struct eth_addr *ea, uint64_t mac64, bool warn)
{
    struct macam_node *macam_node;
    HMAP_FOR_EACH_WITH_HASH (macam_node, hmap_node, hash_uint64(mac64),
                             &macam) {
        if (eth_addr_equals(*ea, macam_node->mac_addr)) {
            if (warn) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "Duplicate MAC set: "ETH_ADDR_FMT,
                             ETH_ADDR_ARGS(macam_node->mac_addr));
            }
            return true;
        }
    }
    return false;
}

static bool
ipam_is_duplicate_ip(struct ovn_datapath *od, uint32_t ip, bool warn)
{
    struct ipam_node *ipam_node;
    HMAP_FOR_EACH_WITH_HASH (ipam_node, hmap_node, hash_int(ip, 0),
                             &od->ipam) {
        if (ipam_node->ip_addr == ip) {
            if (warn) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_WARN_RL(&rl, "Duplicate IP set: "IP_FMT,
                             IP_ARGS(htonl(ip)));
            }
            return true;
        }
    }
    return false;
}

static void
ipam_insert_mac(struct eth_addr *ea, bool check)
{
    if (!ea) {
        return;
    }

    uint64_t mac64 = eth_addr_to_uint64(*ea);
    /* If the new MAC was not assigned by this address management system or
     * check is true and the new MAC is a duplicate, do not insert it into the
     * macam hmap. */
    if (((mac64 ^ MAC_ADDR_PREFIX) >> 24)
        || (check && ipam_is_duplicate_mac(ea, mac64, true))) {
        return;
    }

    struct macam_node *new_macam_node = xmalloc(sizeof *new_macam_node);
    new_macam_node->mac_addr = *ea;
    hmap_insert(&macam, &new_macam_node->hmap_node, hash_uint64(mac64));
}

static void
ipam_insert_ip(struct ovn_datapath *od, uint32_t ip, bool check)
{
    if (!od) {
        return;
    }

    if (check && ipam_is_duplicate_ip(od, ip, true)) {
        return;
    }

    struct ipam_node *new_ipam_node = xmalloc(sizeof *new_ipam_node);
    new_ipam_node->ip_addr = ip;
    hmap_insert(&od->ipam, &new_ipam_node->hmap_node, hash_int(ip, 0));
}

static void
ipam_insert_lsp_addresses(struct ovn_datapath *od, struct ovn_port *op,
                          char *address)
{
    if (!od || !op || !address || !strcmp(address, "unknown")
        || is_dynamic_lsp_address(address)) {
        return;
    }

    struct lport_addresses laddrs;
    if (!extract_lsp_addresses(address, &laddrs)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "Extract addresses failed.");
        return;
    }
    ipam_insert_mac(&laddrs.ea, true);

    /* IP is only added to IPAM if the switch's subnet option
     * is set, whereas MAC is always added to MACAM. */
    if (!smap_get(&od->nbs->other_config, "subnet")) {
        destroy_lport_addresses(&laddrs);
        return;
    }

    for (size_t j = 0; j < laddrs.n_ipv4_addrs; j++) {
        uint32_t ip = ntohl(laddrs.ipv4_addrs[j].addr);
        ipam_insert_ip(od, ip, true);
    }

    destroy_lport_addresses(&laddrs);
}

static void
ipam_add_port_addresses(struct ovn_datapath *od, struct ovn_port *op)
{
    if (!od || !op) {
        return;
    }

    if (op->nbsp) {
        /* Add all the port's addresses to address data structures. */
        for (size_t i = 0; i < op->nbsp->n_addresses; i++) {
            ipam_insert_lsp_addresses(od, op, op->nbsp->addresses[i]);
        }
        if (op->nbsp->dynamic_addresses) {
            ipam_insert_lsp_addresses(od, op, op->nbsp->dynamic_addresses);
        }
    } else if (op->nbrp) {
        struct lport_addresses lrp_networks;
        if (!extract_lrp_networks(op->nbrp->mac, op->nbrp->networks,
                                  op->nbrp->n_networks, &lrp_networks)) {
            static struct vlog_rate_limit rl
                = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "Extract addresses failed.");
            return;
        }
        ipam_insert_mac(&lrp_networks.ea, true);

        if (!op->peer || !op->peer->nbsp || !op->peer->od || !op->peer->od->nbs
            || !smap_get(&op->peer->od->nbs->other_config, "subnet")) {
            destroy_lport_addresses(&lrp_networks);
            return;
        }

        for (size_t i = 0; i < lrp_networks.n_ipv4_addrs; i++) {
            uint32_t ip = ntohl(lrp_networks.ipv4_addrs[i].addr);
            ipam_insert_ip(op->peer->od, ip, true);
        }

        destroy_lport_addresses(&lrp_networks);
    }
}

static uint64_t
ipam_get_unused_mac(void)
{
    /* Stores the suffix of the most recently ipam-allocated MAC address. */
    static uint32_t last_mac;

    uint64_t mac64;
    struct eth_addr mac;
    uint32_t mac_addr_suffix, i;
    for (i = 0; i < MAC_ADDR_SPACE - 1; i++) {
        /* The tentative MAC's suffix will be in the interval (1, 0xfffffe). */
        mac_addr_suffix = ((last_mac + i) % (MAC_ADDR_SPACE - 1)) + 1;
        mac64 = MAC_ADDR_PREFIX | mac_addr_suffix;
        eth_addr_from_uint64(mac64, &mac);
        if (!ipam_is_duplicate_mac(&mac, mac64, false)) {
            last_mac = mac_addr_suffix;
            break;
        }
    }

    if (i == MAC_ADDR_SPACE) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "MAC address space exhausted.");
        mac64 = 0;
    }

    return mac64;
}

static uint32_t
ipam_get_unused_ip(struct ovn_datapath *od, uint32_t subnet, uint32_t mask)
{
    if (!od) {
        return 0;
    }

    uint32_t ip = 0;

    /* Find an unused IP address in subnet. x.x.x.1 is reserved for a
     * logical router port. */
    for (uint32_t i = 2; i < ~mask; i++) {
        uint32_t tentative_ip = subnet + i;
        if (!ipam_is_duplicate_ip(od, tentative_ip, false)) {
            ip = tentative_ip;
            break;
        }
    }

    if (!ip) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL( &rl, "Subnet address space has been exhausted.");
    }

    return ip;
}

static bool
ipam_allocate_addresses(struct ovn_datapath *od, struct ovn_port *op,
                        const char *addrspec, ovs_be32 subnet, ovs_be32 mask)
{
    if (!od || !op || !op->nbsp) {
        return false;
    }

    uint32_t ip = ipam_get_unused_ip(od, ntohl(subnet), ntohl(mask));
    if (!ip) {
        return false;
    }

    struct eth_addr mac;
    bool check_mac;
    int n = 0;

    if (ovs_scan(addrspec, ETH_ADDR_SCAN_FMT" dynamic%n",
                 ETH_ADDR_SCAN_ARGS(mac), &n)
        && addrspec[n] == '\0') {
        check_mac = true;
    } else {
        uint64_t mac64 = ipam_get_unused_mac();
        if (!mac64) {
            return false;
        }
        eth_addr_from_uint64(mac64, &mac);
        check_mac = false;
    }

    /* Add MAC/IP to MACAM/IPAM hmaps if both addresses were allocated
     * successfully. */
    ipam_insert_ip(od, ip, false);
    ipam_insert_mac(&mac, check_mac);

    char *new_addr = xasprintf(ETH_ADDR_FMT" "IP_FMT,
                               ETH_ADDR_ARGS(mac), IP_ARGS(htonl(ip)));
    nbrec_logical_switch_port_set_dynamic_addresses(op->nbsp, new_addr);
    free(new_addr);

    return true;
}

static void
build_ipam(struct hmap *datapaths, struct hmap *ports)
{
    /* IPAM generally stands for IP address management.  In non-virtualized
     * world, MAC addresses come with the hardware.  But, with virtualized
     * workloads, they need to be assigned and managed.  This function
     * does both IP address management (ipam) and MAC address management
     * (macam). */

    /* If the switch's other_config:subnet is set, allocate new addresses for
     * ports that have the "dynamic" keyword in their addresses column. */
    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (od->nbs) {
            const char *subnet_str = smap_get(&od->nbs->other_config,
                                              "subnet");
            if (!subnet_str) {
                continue;
            }

            ovs_be32 subnet, mask;
            char *error = ip_parse_masked(subnet_str, &subnet, &mask);
            if (error || mask == OVS_BE32_MAX || !ip_is_cidr(mask)) {
                static struct vlog_rate_limit rl
                    = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "bad 'subnet' %s", subnet_str);
                free(error);
                continue;
            }

            struct ovn_port *op;
            for (size_t i = 0; i < od->nbs->n_ports; i++) {
                const struct nbrec_logical_switch_port *nbsp =
                    od->nbs->ports[i];

                if (!nbsp) {
                    continue;
                }

                op = ovn_port_find(ports, nbsp->name);
                if (!op || (op->nbsp && op->peer)) {
                    /* Do not allocate addresses for logical switch ports that
                     * have a peer. */
                    continue;
                }

                for (size_t j = 0; j < nbsp->n_addresses; j++) {
                    if (is_dynamic_lsp_address(nbsp->addresses[j])
                        && !nbsp->dynamic_addresses) {
                        ipam_allocate_addresses(od, op, nbsp->addresses[j],
                                                subnet, mask);
                        break;
                    }
                }
            }
        }
    }
}

/* Tag allocation for nested containers.
 *
 * For a logical switch port with 'parent_name' and a request to allocate tags,
 * keeps a track of all allocated tags. */
struct tag_alloc_node {
    struct hmap_node hmap_node;
    char *parent_name;
    unsigned long *allocated_tags;  /* A bitmap to track allocated tags. */
};

static void
tag_alloc_destroy(struct hmap *tag_alloc_table)
{
    struct tag_alloc_node *node;
    HMAP_FOR_EACH_POP (node, hmap_node, tag_alloc_table) {
        bitmap_free(node->allocated_tags);
        free(node->parent_name);
        free(node);
    }
    hmap_destroy(tag_alloc_table);
}

static struct tag_alloc_node *
tag_alloc_get_node(struct hmap *tag_alloc_table, const char *parent_name)
{
    /* If a node for the 'parent_name' exists, return it. */
    struct tag_alloc_node *tag_alloc_node;
    HMAP_FOR_EACH_WITH_HASH (tag_alloc_node, hmap_node,
                             hash_string(parent_name, 0),
                             tag_alloc_table) {
        if (!strcmp(tag_alloc_node->parent_name, parent_name)) {
            return tag_alloc_node;
        }
    }

    /* Create a new node. */
    tag_alloc_node = xmalloc(sizeof *tag_alloc_node);
    tag_alloc_node->parent_name = xstrdup(parent_name);
    tag_alloc_node->allocated_tags = bitmap_allocate(MAX_OVN_TAGS);
    /* Tag 0 is invalid for nested containers. */
    bitmap_set1(tag_alloc_node->allocated_tags, 0);
    hmap_insert(tag_alloc_table, &tag_alloc_node->hmap_node,
                hash_string(parent_name, 0));

    return tag_alloc_node;
}

static void
tag_alloc_add_existing_tags(struct hmap *tag_alloc_table,
                            const struct nbrec_logical_switch_port *nbsp)
{
    /* Add the tags of already existing nested containers.  If there is no
     * 'nbsp->parent_name' or no 'nbsp->tag' set, there is nothing to do. */
    if (!nbsp->parent_name || !nbsp->parent_name[0] || !nbsp->tag) {
        return;
    }

    struct tag_alloc_node *tag_alloc_node;
    tag_alloc_node = tag_alloc_get_node(tag_alloc_table, nbsp->parent_name);
    bitmap_set1(tag_alloc_node->allocated_tags, *nbsp->tag);
}

static void
tag_alloc_create_new_tag(struct hmap *tag_alloc_table,
                         const struct nbrec_logical_switch_port *nbsp)
{
    if (!nbsp->tag_request) {
        return;
    }

    if (nbsp->parent_name && nbsp->parent_name[0]
        && *nbsp->tag_request == 0) {
        /* For nested containers that need allocation, do the allocation. */

        if (nbsp->tag) {
            /* This has already been allocated. */
            return;
        }

        struct tag_alloc_node *tag_alloc_node;
        int64_t tag;
        tag_alloc_node = tag_alloc_get_node(tag_alloc_table,
                                            nbsp->parent_name);
        tag = bitmap_scan(tag_alloc_node->allocated_tags, 0, 1, MAX_OVN_TAGS);
        if (tag == MAX_OVN_TAGS) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_ERR_RL(&rl, "out of vlans for logical switch ports with "
                        "parent %s", nbsp->parent_name);
            return;
        }
        bitmap_set1(tag_alloc_node->allocated_tags, tag);
        nbrec_logical_switch_port_set_tag(nbsp, &tag, 1);
    } else if (*nbsp->tag_request != 0) {
        /* For everything else, copy the contents of 'tag_request' to 'tag'. */
        nbrec_logical_switch_port_set_tag(nbsp, nbsp->tag_request, 1);
    }
}

void
build_lsp_addrs(char **addresses, size_t n_addresses,
                const char *dynamic_addresses,
                struct lport_addresses **lsp_addrsp, size_t *n_lsp_addrsp,
                bool *has_unknownp)
{
    struct lport_addresses *lpas = xmalloc(sizeof *lpas * (n_addresses + 1));
    size_t n_lpas = 0;
    bool has_unknown = false;
    for (size_t i = 0; i < n_addresses; i++) {
        const char *a = addresses[i];
        if (!strcmp(a, "unknown")) {
            has_unknown = true;
        } else {
            if (is_dynamic_lsp_address(a)) {
                a = dynamic_addresses;
                if (!a) {
                    continue;
                }
            }
            if (!extract_lsp_addresses(a, &lpas[n_lpas])) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
                VLOG_INFO_RL(&rl, "invalid address '%s'", a);
                continue;
            }
            n_lpas++;
        }
    }
    *lsp_addrsp = lpas;
    *n_lsp_addrsp = n_lpas;
    *has_unknownp = has_unknown;
}

void
build_ps_addrs(char **port_security, size_t n_port_security,
               struct lport_addresses **ps_addrsp, size_t *n_ps_addrsp)
{
    struct lport_addresses *lpas = xmalloc(sizeof *lpas * n_port_security);
    size_t n_lpas = 0;
    for (size_t i = 0; i < n_port_security; i++) {
        if (!extract_lsp_addresses(port_security[i], &lpas[n_lpas])) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_INFO_RL(&rl, "invalid syntax '%s' in port "
                         "security. No MAC address found", port_security[i]);
            continue;
        }
        n_lpas++;
    }
    *ps_addrsp = lpas;
    *n_ps_addrsp = n_lpas;
}

void
free_lp_addrs(struct lport_addresses *ps_addrs, size_t n_ps_addrs)
{
    for (int i = 0; i < n_ps_addrs; i++) {
        destroy_lport_addresses(&ps_addrs[i]);
    }
    free(ps_addrs);
}

static void
join_logical_ports(struct northd_context *ctx,
                   struct hmap *datapaths, struct hmap *ports,
                   struct hmap *chassis_qdisc_queues,
                   struct hmap *tag_alloc_table, struct ovs_list *sb_only,
                   struct ovs_list *nb_only, struct ovs_list *both)
{
    hmap_init(ports);
    ovs_list_init(sb_only);
    ovs_list_init(nb_only);
    ovs_list_init(both);

    const struct sbrec_port_binding *sb;
    SBREC_PORT_BINDING_FOR_EACH (sb, ctx->ovnsb_idl) {
        struct ovn_port *op = ovn_port_create(ports, sb->logical_port,
                                              NULL, NULL, sb);
        ovs_list_push_back(sb_only, &op->list);
    }

    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (od->nbs) {
            for (size_t i = 0; i < od->nbs->n_ports; i++) {
                const struct nbrec_logical_switch_port *nbsp
                    = od->nbs->ports[i];
                struct ovn_port *op = ovn_port_find(ports, nbsp->name);
                if (op) {
                    if (op->nbsp || op->nbrp) {
                        static struct vlog_rate_limit rl
                            = VLOG_RATE_LIMIT_INIT(5, 1);
                        VLOG_WARN_RL(&rl, "duplicate logical port %s",
                                     nbsp->name);
                        continue;
                    }
                    op->nbsp = nbsp;
                    ovs_list_remove(&op->list);

                    uint32_t queue_id = smap_get_int(&op->sb->options,
                                                     "qdisc_queue_id", 0);
                    if (queue_id && op->sb->chassis) {
                        add_chassis_queue(
                             chassis_qdisc_queues, &op->sb->chassis->header_.uuid,
                             queue_id);
                    }

                    ovs_list_push_back(both, &op->list);
                } else {
                    op = ovn_port_create(ports, nbsp->name, nbsp, NULL, NULL);
                    ovs_list_push_back(nb_only, &op->list);
                }

                op->od = od;
                ipam_add_port_addresses(od, op);
                tag_alloc_add_existing_tags(tag_alloc_table, nbsp);
            }
        } else {
            for (size_t i = 0; i < od->nbr->n_ports; i++) {
                const struct nbrec_logical_router_port *nbrp
                    = od->nbr->ports[i];

                struct lport_addresses lrp_networks;
                if (!extract_lrp_networks(nbrp->mac, nbrp->networks,
                                          nbrp->n_networks, &lrp_networks)) {
                    static struct vlog_rate_limit rl
                        = VLOG_RATE_LIMIT_INIT(5, 1);
                    VLOG_WARN_RL(&rl, "bad 'mac' %s", nbrp->mac);
                    continue;
                }

                if (!lrp_networks.n_ipv4_addrs && !lrp_networks.n_ipv6_addrs) {
                    continue;
                }

                struct ovn_port *op = ovn_port_find(ports, nbrp->name);
                if (op) {
                    if (op->nbsp || op->nbrp) {
                        static struct vlog_rate_limit rl
                            = VLOG_RATE_LIMIT_INIT(5, 1);
                        VLOG_WARN_RL(&rl, "duplicate logical router port %s",
                                     nbrp->name);
                        continue;
                    }
                    op->nbrp = nbrp;
                    ovs_list_remove(&op->list);
                    ovs_list_push_back(both, &op->list);

                    /* This port exists but should not have been
                     * initialized fully. */
                    ovs_assert(!op->lrp_networks.n_ipv4_addrs
                               && !op->lrp_networks.n_ipv6_addrs);
                } else {
                    op = ovn_port_create(ports, nbrp->name, NULL, nbrp, NULL);
                    ovs_list_push_back(nb_only, &op->list);
                }

                op->lrp_networks = lrp_networks;
                op->od = od;
                ipam_add_port_addresses(op->od, op);
            }
        }
    }

    /* Connect logical router ports, and logical switch ports of type "router",
     * to their peers. */
    struct ovn_port *op;
    HMAP_FOR_EACH (op, key_node, ports) {
        if (op->nbsp && !strcmp(op->nbsp->type, "router")) {
            const char *peer_name = smap_get(&op->nbsp->options, "router-port");
            if (!peer_name) {
                continue;
            }

            struct ovn_port *peer = ovn_port_find(ports, peer_name);
            if (!peer || !peer->nbrp) {
                continue;
            }

            peer->peer = op;
            op->peer = peer;
            op->od->router_ports = xrealloc(
                op->od->router_ports,
                sizeof *op->od->router_ports * (op->od->n_router_ports + 1));
            op->od->router_ports[op->od->n_router_ports++] = op;
        } else if (op->nbrp && op->nbrp->peer) {
            struct ovn_port *peer = ovn_port_find(ports, op->nbrp->peer);
            if (peer) {
                if (peer->nbrp) {
                    op->peer = peer;
                } else if (peer->nbsp) {
                    /* An ovn_port for a switch port of type "router" does have
                     * a router port as its peer (see the case above for
                     * "router" ports), but this is set via options:router-port
                     * in Logical_Switch_Port and does not involve the
                     * Logical_Router_Port's 'peer' column. */
                    static struct vlog_rate_limit rl =
                            VLOG_RATE_LIMIT_INIT(5, 1);
                    VLOG_WARN_RL(&rl, "Bad configuration: The peer of router "
                                 "port %s is a switch port", op->key);
                }
            }
        }
    }
}

static void
ovn_port_update_sbrec(const struct ovn_port *op,
                      struct hmap *chassis_qdisc_queues)
{
    sbrec_port_binding_set_datapath(op->sb, op->od->sb);
    if (op->nbrp) {
        /* If the router is for l3 gateway, it resides on a chassis
         * and its port type is "l3gateway". */
        const char *chassis = smap_get(&op->od->nbr->options, "chassis");
        if (chassis) {
            sbrec_port_binding_set_type(op->sb, "l3gateway");
        } else {
            sbrec_port_binding_set_type(op->sb, "patch");
        }

        const char *peer = op->peer ? op->peer->key : "<error>";
        struct smap new;
        smap_init(&new);
        smap_add(&new, "peer", peer);
        if (chassis) {
            smap_add(&new, "l3gateway-chassis", chassis);
        }
        sbrec_port_binding_set_options(op->sb, &new);
        smap_destroy(&new);

        sbrec_port_binding_set_parent_port(op->sb, NULL);
        sbrec_port_binding_set_tag(op->sb, NULL, 0);
        sbrec_port_binding_set_mac(op->sb, NULL, 0);
    } else {
        if (strcmp(op->nbsp->type, "router")) {
            uint32_t queue_id = smap_get_int(
                    &op->sb->options, "qdisc_queue_id", 0);
            bool has_qos = port_has_qos_params(&op->nbsp->options);
            struct smap options;

            if (op->sb->chassis && has_qos && !queue_id) {
                queue_id = allocate_chassis_queueid(chassis_qdisc_queues,
                                                    op->sb->chassis);
            } else if (!has_qos && queue_id) {
                free_chassis_queueid(chassis_qdisc_queues,
                                     op->sb->chassis,
                                     queue_id);
                queue_id = 0;
            }

            smap_clone(&options, &op->nbsp->options);
            if (queue_id) {
                smap_add_format(&options,
                                "qdisc_queue_id", "%d", queue_id);
            }
            sbrec_port_binding_set_options(op->sb, &options);
            smap_destroy(&options);
            sbrec_port_binding_set_type(op->sb, op->nbsp->type);
        } else {
            const char *chassis = NULL;
            if (op->peer && op->peer->od && op->peer->od->nbr) {
                chassis = smap_get(&op->peer->od->nbr->options, "chassis");
            }

            /* A switch port connected to a gateway router is also of
             * type "l3gateway". */
            if (chassis) {
                sbrec_port_binding_set_type(op->sb, "l3gateway");
            } else {
                sbrec_port_binding_set_type(op->sb, "patch");
            }

            const char *router_port = smap_get_def(&op->nbsp->options,
                                                   "router-port", "<error>");
            struct smap new;
            smap_init(&new);
            smap_add(&new, "peer", router_port);
            if (chassis) {
                smap_add(&new, "l3gateway-chassis", chassis);
            }

            const char *nat_addresses = smap_get(&op->nbsp->options,
                                           "nat-addresses");
            if (nat_addresses) {
                struct lport_addresses laddrs;
                if (!extract_lsp_addresses(nat_addresses, &laddrs)) {
                    static struct vlog_rate_limit rl =
                        VLOG_RATE_LIMIT_INIT(1, 1);
                    VLOG_WARN_RL(&rl, "Error extracting nat-addresses.");
                } else {
                    smap_add(&new, "nat-addresses", nat_addresses);
                    destroy_lport_addresses(&laddrs);
                }
            }
            sbrec_port_binding_set_options(op->sb, &new);
            smap_destroy(&new);
        }
        sbrec_port_binding_set_parent_port(op->sb, op->nbsp->parent_name);
        sbrec_port_binding_set_tag(op->sb, op->nbsp->tag, op->nbsp->n_tag);
        sbrec_port_binding_set_mac(op->sb, (const char **) op->nbsp->addresses,
                                   op->nbsp->n_addresses);
    }
}

/* Remove mac_binding entries that refer to logical_ports which are
 * deleted. */
static void
cleanup_mac_bindings(struct northd_context *ctx, struct hmap *ports)
{
    const struct sbrec_mac_binding *b, *n;
    SBREC_MAC_BINDING_FOR_EACH_SAFE (b, n, ctx->ovnsb_idl) {
        if (!b->logical_port || !ovn_port_find(ports, b->logical_port)) {
            sbrec_mac_binding_delete(b);
        }
    }
}

/* Updates the southbound Port_Binding table so that it contains the logical
 * switch ports specified by the northbound database.
 *
 * Initializes 'ports' to contain a "struct ovn_port" for every logical port,
 * using the "struct ovn_datapath"s in 'datapaths' to look up logical
 * datapaths. */
static void
build_ports(struct northd_context *ctx, struct hmap *datapaths,
            struct hmap *ports)
{
    struct ovs_list sb_only, nb_only, both;
    struct hmap tag_alloc_table = HMAP_INITIALIZER(&tag_alloc_table);
    struct hmap chassis_qdisc_queues = HMAP_INITIALIZER(&chassis_qdisc_queues);

    join_logical_ports(ctx, datapaths, ports, &chassis_qdisc_queues,
                       &tag_alloc_table, &sb_only, &nb_only, &both);

    struct ovn_port *op, *next;
    /* For logical ports that are in both databases, update the southbound
     * record based on northbound data.  Also index the in-use tunnel_keys.
     * For logical ports that are in NB database, do any tag allocation
     * needed. */
    LIST_FOR_EACH_SAFE (op, next, list, &both) {
        if (op->nbsp) {
            tag_alloc_create_new_tag(&tag_alloc_table, op->nbsp);
        }
        ovn_port_update_sbrec(op, &chassis_qdisc_queues);

        add_tnlid(&op->od->port_tnlids, op->sb->tunnel_key);
        if (op->sb->tunnel_key > op->od->port_key_hint) {
            op->od->port_key_hint = op->sb->tunnel_key;
        }
    }

    /* Add southbound record for each unmatched northbound record. */
    LIST_FOR_EACH_SAFE (op, next, list, &nb_only) {
        uint16_t tunnel_key = ovn_port_allocate_key(op->od);
        if (!tunnel_key) {
            continue;
        }

        op->sb = sbrec_port_binding_insert(ctx->ovnsb_txn);
        ovn_port_update_sbrec(op, &chassis_qdisc_queues);

        sbrec_port_binding_set_logical_port(op->sb, op->key);
        sbrec_port_binding_set_tunnel_key(op->sb, tunnel_key);
    }

    bool remove_mac_bindings = false;
    if (!ovs_list_is_empty(&sb_only)) {
        remove_mac_bindings = true;
    }

    /* Delete southbound records without northbound matches. */
    LIST_FOR_EACH_SAFE(op, next, list, &sb_only) {
        ovs_list_remove(&op->list);
        sbrec_port_binding_delete(op->sb);
        ovn_port_destroy(ports, op);
    }
    if (remove_mac_bindings) {
        cleanup_mac_bindings(ctx, ports);
    }

    tag_alloc_destroy(&tag_alloc_table);
    destroy_chassis_queues(&chassis_qdisc_queues);
}

#define OVN_MIN_MULTICAST 32768
#define OVN_MAX_MULTICAST 65535

struct multicast_group {
    const char *name;
    uint16_t key;               /* OVN_MIN_MULTICAST...OVN_MAX_MULTICAST. */
};

#define MC_FLOOD "_MC_flood"
static const struct multicast_group mc_flood = { MC_FLOOD, 65535 };

#define MC_UNKNOWN "_MC_unknown"
static const struct multicast_group mc_unknown = { MC_UNKNOWN, 65534 };

static bool
multicast_group_equal(const struct multicast_group *a,
                      const struct multicast_group *b)
{
    return !strcmp(a->name, b->name) && a->key == b->key;
}

/* Multicast group entry. */
struct ovn_multicast {
    struct hmap_node hmap_node; /* Index on 'datapath' and 'key'. */
    struct ovn_datapath *datapath;
    const struct multicast_group *group;

    struct ovn_port **ports;
    size_t n_ports, allocated_ports;
};

static uint32_t
ovn_multicast_hash(const struct ovn_datapath *datapath,
                   const struct multicast_group *group)
{
    return hash_pointer(datapath, group->key);
}

static struct ovn_multicast *
ovn_multicast_find(struct hmap *mcgroups, struct ovn_datapath *datapath,
                   const struct multicast_group *group)
{
    struct ovn_multicast *mc;

    HMAP_FOR_EACH_WITH_HASH (mc, hmap_node,
                             ovn_multicast_hash(datapath, group), mcgroups) {
        if (mc->datapath == datapath
            && multicast_group_equal(mc->group, group)) {
            return mc;
        }
    }
    return NULL;
}

static void
ovn_multicast_add(struct hmap *mcgroups, const struct multicast_group *group,
                  struct ovn_port *port)
{
    struct ovn_datapath *od = port->od;
    struct ovn_multicast *mc = ovn_multicast_find(mcgroups, od, group);
    if (!mc) {
        mc = xmalloc(sizeof *mc);
        hmap_insert(mcgroups, &mc->hmap_node, ovn_multicast_hash(od, group));
        mc->datapath = od;
        mc->group = group;
        mc->n_ports = 0;
        mc->allocated_ports = 4;
        mc->ports = xmalloc(mc->allocated_ports * sizeof *mc->ports);
    }
    if (mc->n_ports >= mc->allocated_ports) {
        mc->ports = x2nrealloc(mc->ports, &mc->allocated_ports,
                               sizeof *mc->ports);
    }
    mc->ports[mc->n_ports++] = port;
}

static void
ovn_multicast_destroy(struct hmap *mcgroups, struct ovn_multicast *mc)
{
    if (mc) {
        hmap_remove(mcgroups, &mc->hmap_node);
        free(mc->ports);
        free(mc);
    }
}

static void
ovn_multicast_update_sbrec(const struct ovn_multicast *mc,
                           const struct sbrec_multicast_group *sb)
{
    struct sbrec_port_binding **ports = xmalloc(mc->n_ports * sizeof *ports);
    for (size_t i = 0; i < mc->n_ports; i++) {
        ports[i] = CONST_CAST(struct sbrec_port_binding *, mc->ports[i]->sb);
    }
    sbrec_multicast_group_set_ports(sb, ports, mc->n_ports);
    free(ports);
}

/* Logical flow generation.
 *
 * This code generates the Logical_Flow table in the southbound database, as a
 * function of most of the northbound database.
 */

struct ovn_lflow {
    struct hmap_node hmap_node;

    struct ovn_datapath *od;
    enum ovn_stage stage;
    uint16_t priority;
    char *match;
    char *actions;
    const char *where;
};

static size_t
ovn_lflow_hash(const struct ovn_lflow *lflow)
{
    size_t hash = uuid_hash(&lflow->od->key);
    hash = hash_2words((lflow->stage << 16) | lflow->priority, hash);
    hash = hash_string(lflow->match, hash);
    return hash_string(lflow->actions, hash);
}

static bool
ovn_lflow_equal(const struct ovn_lflow *a, const struct ovn_lflow *b)
{
    return (a->od == b->od
            && a->stage == b->stage
            && a->priority == b->priority
            && !strcmp(a->match, b->match)
            && !strcmp(a->actions, b->actions));
}

static void
ovn_lflow_init(struct ovn_lflow *lflow, struct ovn_datapath *od,
               enum ovn_stage stage, uint16_t priority,
               char *match, char *actions, const char *where)
{
    lflow->od = od;
    lflow->stage = stage;
    lflow->priority = priority;
    lflow->match = match;
    lflow->actions = actions;
    lflow->where = where;
}

/* Adds a row with the specified contents to the Logical_Flow table. */
void
ovn_lflow_add_at(struct hmap *lflow_map, struct ovn_datapath *od,
                 enum ovn_stage stage, uint16_t priority,
                 const char *match, const char *actions, const char *where)
{
    ovs_assert(ovn_stage_to_datapath_type(stage) == ovn_datapath_get_type(od));

    struct ovn_lflow *lflow = xmalloc(sizeof *lflow);
    ovn_lflow_init(lflow, od, stage, priority,
                   xstrdup(match), xstrdup(actions), where);
    hmap_insert(lflow_map, &lflow->hmap_node, ovn_lflow_hash(lflow));
}

static struct ovn_lflow *
ovn_lflow_find(struct hmap *lflows, struct ovn_datapath *od,
               enum ovn_stage stage, uint16_t priority,
               const char *match, const char *actions)
{
    struct ovn_lflow target;
    ovn_lflow_init(&target, od, stage, priority,
                   CONST_CAST(char *, match), CONST_CAST(char *, actions),
                   NULL);

    struct ovn_lflow *lflow;
    HMAP_FOR_EACH_WITH_HASH (lflow, hmap_node, ovn_lflow_hash(&target),
                             lflows) {
        if (ovn_lflow_equal(lflow, &target)) {
            return lflow;
        }
    }
    return NULL;
}

static void
ovn_lflow_destroy(struct hmap *lflows, struct ovn_lflow *lflow)
{
    if (lflow) {
        hmap_remove(lflows, &lflow->hmap_node);
        free(lflow->match);
        free(lflow->actions);
        free(lflow);
    }
}

char *
build_lsp_macs(struct lport_addresses *lp_addrs, size_t n)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    for (size_t i = 0; i < n; i++) {
        if (i) {
            ds_put_cstr(&s, ", ");
        }
        ds_put_cstr(&s, lp_addrs[i].ea_s);
    }
    return ds_steal_cstr(&s);
}

char *
build_port_security_l2(struct lport_addresses *ps_addrs, size_t n)
{
    if (n == 0) {
        return xstrdup("0/0");
    }
    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_char(&s, '{');
    for (size_t i = 0; i < n; i++) {
        if (i) {
            ds_put_cstr(&s, ", ");
        }
        ds_put_cstr(&s, ps_addrs[i].ea_s);
    }
    ds_put_char(&s, '}');
    return ds_steal_cstr(&s);
}

static void
build_port_security_ipv4_arp_flow(struct ds *match,
                                  const struct lport_addresses *ps)
{
    ds_put_format(match, "(arp.sha == %s", ps->ea_s);
    if (!ps->n_ipv4_addrs) {
        ds_put_cstr(match, ")");
        return;
    }
    ds_put_cstr(match, " && arp.spa == {");
    for (size_t i = 0; i < ps->n_ipv4_addrs; i++) {
        if (i) {
            ds_put_cstr(match, ", ");
        }

        /* When the netmask is applied, if the host portion is
         * non-zero, the host can only use the specified
         * address in the arp.spa.  If zero, the host is allowed
         * to use any address in the subnet. */
        const struct ipv4_netaddr *ip4 = &ps->ipv4_addrs[i];
        if (ip4->plen == 32 || ip4->addr & ~ip4->mask) {
            ds_put_cstr(match, ip4->addr_s);
        } else {
            ds_put_format(match, "%s/%d", ip4->network_s, ip4->plen);
        }
    }
    ds_put_cstr(match, "})");
}

static void
build_port_security_ipv6_nd_flow(struct ds *match,
                                 const struct lport_addresses *ps)
{
    ds_put_format(match, "(nd.sll == {%s, 00:00:00:00:00:00} || "
                  "(nd.tll == {%s, 00:00:00:00:00:00}",
                  ps->ea_s, ps->ea_s);
    if (!ps->n_ipv6_addrs) {
        ds_put_cstr(match, "))");
        return;
    }

    struct in6_addr lla;
    in6_generate_lla(ps->ea, &lla);
    char ip6_str[INET6_ADDRSTRLEN + 1];
    ipv6_string_mapped(ip6_str, &lla);
    ds_put_format(match, " && nd.target == {%s", ip6_str);

    for (int i = 0; i < ps->n_ipv6_addrs; i++) {
        ds_put_format(match, ", %s", ps->ipv6_addrs[i].addr_s);
    }

    ds_put_format(match, "}))");
}

static void
build_port_security_ipv4_flow(enum ovn_pipeline pipeline,
                              const struct ipv4_netaddr *a, size_t n,
                              struct ds *match)
{
    ds_put_char(match, '(');
    if (pipeline == P_IN) {
        /* Permit use of the unspecified address for DHCP discovery */
        ds_put_cstr(match,
                    "(ip4.src == 0.0.0.0 && ip4.dst == 255.255.255.255 && "
                    "udp.src == 68 && udp.dst == 67) || ip4.src == {");
    } else {
        ds_put_cstr(match, "ip4.dst == {255.255.255.255, 224.0.0.0/4, ");
    }

    for (; n > 0; a++, n--) {
        /* When the netmask is applied, if the host portion is non-zero, the
         * host can only use the specified address.  If zero, the host is
         * allowed to use any address in the subnet.
         */
        if (a->plen == 32 || a->addr & ~a->mask) {
            ds_put_format(match, "%s, ", a->addr_s);
            if (pipeline == P_OUT && a->plen != 32) {
                ds_put_format(match, "%s, ", a->bcast_s);
            }
        } else {
            ds_put_format(match, "%s/%d, ", a->network_s, a->plen);
        }
    }

    /* Replace ", " by "}". */
    ds_chomp(match, ' ');
    ds_chomp(match, ',');
    ds_put_cstr(match, "})");
}

static void
build_port_security_ipv6_flow(enum ovn_pipeline pipeline, struct eth_addr ea,
                              struct ipv6_netaddr *a, size_t n,
                              struct ds *match)
{
    ds_put_char(match, '(');
    if (pipeline == P_IN) {
        /* Permit use of unspecified address for duplicate address
         * detection. */
        ds_put_cstr(match,
                    "(ip6.src == :: && ip6.dst == ff02::/16"
                    " && icmp6.type == {131, 135, 143}) || ip6.src == {");
    } else {
        ds_put_cstr(match, "ip6.dst == {");

    }

    char ip6_str[INET6_ADDRSTRLEN + 1];

    /* Allow link-local address. */
    struct in6_addr lla;
    in6_generate_lla(ea, &lla);
    ipv6_string_mapped(ip6_str, &lla);
    ds_put_format(match, "%s, ", ip6_str);

    /* Allow ip6.dst=ff00::/8 for multicast packets */
    if (pipeline == P_OUT) {
        ds_put_cstr(match, "ff00::/8, ");
    }
    for (; n > 0; a++, n--) {
        ipv6_string_mapped(ip6_str, &a->addr);
        ds_put_format(match, "%s, ", ip6_str);
    }
    /* Replace ", " by "}". */
    ds_chomp(match, ' ');
    ds_chomp(match, ',');
    ds_put_cstr(match, "})");
}

/**
 * Build port security constraints on ARP and IPv6 ND fields
 * and add logical flows to S_SWITCH_IN_PORT_SEC_ND stage.
 *
 * For each port security of the logical port, following
 * logical flows are added
 *   - If the port security has no IP (both IPv4 and IPv6) or
 *     if it has IPv4 address(es)
 *      - Priority 90 flow to allow ARP packets for known MAC addresses
 *        in the eth.src and arp.spa fields. If the port security
 *        has IPv4 addresses, allow known IPv4 addresses in the arp.tpa field.
 *
 *   - If the port security has no IP (both IPv4 and IPv6) or
 *     if it has IPv6 address(es)
 *     - Priority 90 flow to allow IPv6 ND packets for known MAC addresses
 *       in the eth.src and nd.sll/nd.tll fields. If the port security
 *       has IPv6 addresses, allow known IPv6 addresses in the nd.target field
 *       for IPv6 Neighbor Advertisement packet.
 *
 *   - Priority 80 flow to drop ARP and IPv6 ND packets.
 */
char *
build_port_security_nd(struct lport_addresses *ps_addrs, size_t n_ps_addrs)
{
    if (!n_ps_addrs) {
        return xstrdup("1");
    }

    struct ds match = DS_EMPTY_INITIALIZER;
    for (size_t i = 0; i < n_ps_addrs; i++) {
        struct lport_addresses *ps = &ps_addrs[i];

        if (i) {
            ds_put_cstr(&match, " || ");
        }
        ds_put_format(&match, "(eth.src == %s && ", ps->ea_s);

        int n = (ps->n_ipv4_addrs != 0) + (ps->n_ipv6_addrs != 0);
        if (n != 1) {
            ds_put_char(&match, '(');
            build_port_security_ipv4_arp_flow(&match, ps);
            ds_put_cstr(&match, " || ");
            build_port_security_ipv6_nd_flow(&match, ps);
            ds_put_char(&match, ')');
        } else if (ps->n_ipv4_addrs) {
            build_port_security_ipv4_arp_flow(&match, ps);
        } else {
            build_port_security_ipv6_nd_flow(&match, ps);
        }
        ds_put_char(&match, ')');
    }
    return ds_steal_cstr(&match);
}

/**
 * Build port security constraints on IPv4 and IPv6 src and dst fields
 * and add logical flows to S_SWITCH_(IN/OUT)_PORT_SEC_IP stage.
 *
 * For each port security of the logical port, following
 * logical flows are added
 *   - If the port security has IPv4 addresses,
 *     - Priority 90 flow to allow IPv4 packets for known IPv4 addresses
 *
 *   - If the port security has IPv6 addresses,
 *     - Priority 90 flow to allow IPv6 packets for known IPv6 addresses
 *
 *   - If the port security has IPv4 addresses or IPv6 addresses or both
 *     - Priority 80 flow to drop all IPv4 and IPv6 traffic
 */
char *
build_port_security_ip(enum ovn_pipeline pipeline,
                       struct lport_addresses *ps_addrs, size_t n_ps_addrs)
{
    struct ds match = DS_EMPTY_INITIALIZER;
    int n_ips = 0;
    for (size_t i = 0; i < n_ps_addrs; i++) {
        struct lport_addresses *ps = &ps_addrs[i];

        int n = (ps->n_ipv4_addrs != 0) + (ps->n_ipv6_addrs != 0);
        if (!n) {
            continue;
        }

        if (n_ips++) {
            ds_put_cstr(&match, " || ");
        }

        ds_put_format(&match, "(eth.%s == %s && ",
                      pipeline == P_IN ? "src" : "dst", ps->ea_s);
        if (n == 2) {
            ds_put_char(&match, '(');
        }
        if (ps->n_ipv4_addrs) {
            build_port_security_ipv4_flow(pipeline, ps->ipv4_addrs,
                                          ps->n_ipv4_addrs, &match);
        }
        if (n == 2) {
            ds_put_cstr(&match, " || ");
        }
        if (ps->n_ipv6_addrs) {
            build_port_security_ipv6_flow(pipeline, ps->ea,
                                          ps->ipv6_addrs, ps->n_ipv6_addrs,
                                          &match);
        }
        if (n == 2) {
            ds_put_char(&match, ')');
        }
        ds_put_char(&match, ')');
    }
    if (!match.length) {
        ds_put_char(&match, '1');
    }
    return ds_steal_cstr(&match);
}

static bool
lsp_is_enabled(const struct nbrec_logical_switch_port *lsp)
{
    return !lsp->enabled || *lsp->enabled;
}

char *
build_dhcp_option_args(const struct smap *dhcp_options)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    struct smap_node *node;
    SMAP_FOR_EACH (node, dhcp_options) {
        /* These are not options for the purpose of the put_dhcp_opts or
         * put_dhcpv6_opts logical actions. */
        if (!strcmp(node->key, "server_mac") ||
            !strcmp(node->key, "dhcpv6_stateless")) {
            continue;
        }

        if (s.length) {
            ds_put_cstr(&s, ", ");
        }
        ds_put_format(&s, "%s = %s", node->key, node->value);
    }
    return ds_steal_cstr(&s);
}

char *
build_dhcp_netmask(const char *cidr)
{
    ovs_be32 ip, mask;
    char *error = ip_parse_masked(cidr, &ip, &mask);
    return error ? xstrdup("<error>") : xasprintf(IP_FMT, IP_ARGS(mask));
}

char *
build_dhcp_server_mac(const struct smap *dhcp_options)
{
    struct eth_addr ea;

    /* Get the server MAC for DHCPv4 options. */
    const char *mac = smap_get(dhcp_options, "server_mac");
    if (mac && eth_addr_from_string(mac, &ea)) {
        return xstrdup(mac);
    }

    /* Get the server MAC for DHCPv6 options.
     *
     * (It is really odd that these have different names for our DHCPv4 and
     * DHCPv6 support.) */
    const char *id = smap_get(dhcp_options, "server_id");
    if (id && eth_addr_from_string(id, &ea)) {
        return xstrdup(id);
    }

    return xstrdup("<missing>");
}

char *
build_dhcp_server_ip(const struct smap *dhcp_options)
{
    const char *id = smap_get(dhcp_options, "server_id");
    if (id) {
        /* Get server IP for DHCPv4 options. */
        ovs_be32 ip;
        if (ip_parse(id, &ip)) {
            return xstrdup(id);
        }

        /* Get server IP for DHCPv6 options. */
        struct eth_addr ea;
        if (eth_addr_from_string(id, &ea)) {
            struct in6_addr lla;
            in6_generate_lla(ea, &lla);

            char server_ip[INET6_ADDRSTRLEN + 1];
            ipv6_string_mapped(server_ip, &lla);

            return xstrdup(server_ip);
        }
    }

    return xstrdup("<missing>");
}

bool
build_dhcp_stateful(const struct smap *dhcp_options)
{
    return !smap_get_bool(dhcp_options, "dhcpv6_stateless", false);
}

static bool
has_stateful_acl(struct ovn_datapath *od)
{
    for (size_t i = 0; i < od->nbs->n_acls; i++) {
        struct nbrec_acl *acl = od->nbs->acls[i];
        if (!strcmp(acl->action, "allow-related")) {
            return true;
        }
    }

    return false;
}

static void
build_pre_acls(struct ovn_datapath *od, struct hmap *lflows)
{
    bool has_stateful = has_stateful_acl(od);

    /* If there are any stateful ACL rules in this datapath, we must
     * send all IP packets through the conntrack action, which handles
     * defragmentation, in order to match L4 headers. */
    if (has_stateful) {
        for (size_t i = 0; i < od->n_router_ports; i++) {
            struct ovn_port *op = od->router_ports[i];
            /* Can't use ct() for router ports. Consider the
             * following configuration: lp1(10.0.0.2) on
             * hostA--ls1--lr0--ls2--lp2(10.0.1.2) on hostB, For a
             * ping from lp1 to lp2, First, the response will go
             * through ct() with a zone for lp2 in the ls2 ingress
             * pipeline on hostB.  That ct zone knows about this
             * connection. Next, it goes through ct() with the zone
             * for the router port in the egress pipeline of ls2 on
             * hostB.  This zone does not know about the connection,
             * as the icmp request went through the logical router
             * on hostA, not hostB. This would only work with
             * distributed conntrack state across all chassis. */
            struct ds match_in = DS_EMPTY_INITIALIZER;
            struct ds match_out = DS_EMPTY_INITIALIZER;

            ds_put_format(&match_in, "ip && inport == %s", op->json_key);
            ds_put_format(&match_out, "ip && outport == %s", op->json_key);
            ovn_lflow_add(lflows, od, S_SWITCH_IN_PRE_ACL, 110,
                          ds_cstr(&match_in), "next;");
            ovn_lflow_add(lflows, od, S_SWITCH_OUT_PRE_ACL, 110,
                          ds_cstr(&match_out), "next;");

            ds_destroy(&match_in);
            ds_destroy(&match_out);
        }
    }
}

/* For a 'key' of the form "IP:port" or just "IP", sets 'port' and
 * 'ip_address'.  The caller must free() the memory allocated for
 * 'ip_address'. */
static void
ip_address_and_port_from_lb_key(const char *key, char **ip_address,
                                uint16_t *port)
{
    char *ip_str, *start, *next;
    *ip_address = NULL;
    *port = 0;

    next = start = xstrdup(key);
    ip_str = strsep(&next, ":");
    if (!ip_str || !ip_str[0]) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad ip address for load balancer key %s", key);
        free(start);
        return;
    }

    ovs_be32 ip, mask;
    char *error = ip_parse_masked(ip_str, &ip, &mask);
    if (error || mask != OVS_BE32_MAX) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "bad ip address for load balancer key %s", key);
        free(start);
        free(error);
        return;
    }

    int l4_port = 0;
    if (next && next[0]) {
        if (!str_to_int(next, 0, &l4_port) || l4_port < 0 || l4_port > 65535) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad ip port for load balancer key %s", key);
            free(start);
            return;
        }
    }

    *port = l4_port;
    *ip_address = strdup(ip_str);
    free(start);
}

char *
build_load_balancer_ip_addresses(const struct smap *vips)
{
    struct sset ips = SSET_INITIALIZER(&ips);
    struct smap_node *node;
    SMAP_FOR_EACH (node, vips) {
        char *ip_address;
        uint16_t port;
        ip_address_and_port_from_lb_key(node->key, &ip_address, &port);
        if (ip_address) {
            sset_add_and_free(&ips, ip_address);
        }
    }

    struct ds s = DS_EMPTY_INITIALIZER;
    const char *ip;
    ds_put_char(&s, '{');
    SSET_FOR_EACH (ip, &ips) {
        ds_put_format(&s, "%s, ", ip);
    }
    ds_chomp(&s, ' ');
    ds_chomp(&s, ',');
    ds_put_char(&s, '}');
    return ds_steal_cstr(&s);
}

static void
build_acls(struct ovn_datapath *od, struct hmap *lflows)
{
    bool has_stateful = has_stateful_acl(od);

    /* Ingress or Egress ACL Table (Various priorities). */
    for (size_t i = 0; i < od->nbs->n_acls; i++) {
        struct nbrec_acl *acl = od->nbs->acls[i];
        bool ingress = !strcmp(acl->direction, "from-lport") ? true :false;
        enum ovn_stage stage = ingress ? S_SWITCH_IN_ACL : S_SWITCH_OUT_ACL;

        if (!strcmp(acl->action, "allow")
            || !strcmp(acl->action, "allow-related")) {
            /* If there are any stateful flows, we must even commit "allow"
             * actions.  This is because, while the initiater's
             * direction may not have any stateful rules, the server's
             * may and then its return traffic would not have an
             * associated conntrack entry and would return "+invalid". */
            if (!has_stateful) {
                ovn_lflow_add(lflows, od, stage,
                              acl->priority + OVN_ACL_PRI_OFFSET,
                              acl->match, "next;");
            } else {
                struct ds match = DS_EMPTY_INITIALIZER;

                /* Commit the connection tracking entry if it's a new
                 * connection that matches this ACL.  After this commit,
                 * the reply traffic is allowed by a flow we create at
                 * priority 65535, defined earlier.
                 *
                 * It's also possible that a known connection was marked for
                 * deletion after a policy was deleted, but the policy was
                 * re-added while that connection is still known.  We catch
                 * that case here and un-set ct_label.blocked (which will be done
                 * by ct_commit in the "stateful" stage) to indicate that the
                 * connection should be allowed to resume.
                 */
                ds_put_format(&match, "((ct.new && !ct.est)"
                                      " || (!ct.new && ct.est && !ct.rpl "
                                           "&& ct_label.blocked == 1)) "
                                      "&& (%s)", acl->match);
                ovn_lflow_add(lflows, od, stage,
                              acl->priority + OVN_ACL_PRI_OFFSET,
                              ds_cstr(&match),
                               REGBIT_CONNTRACK_COMMIT" = 1; next;");

                /* Match on traffic in the request direction for an established
                 * connection tracking entry that has not been marked for
                 * deletion.  There is no need to commit here, so we can just
                 * proceed to the next table. We use this to ensure that this
                 * connection is still allowed by the currently defined
                 * policy. */
                ds_clear(&match);
                ds_put_format(&match,
                              "!ct.new && ct.est && !ct.rpl"
                              " && ct_label.blocked == 0 && (%s)",
                              acl->match);
                ovn_lflow_add(lflows, od, stage,
                              acl->priority + OVN_ACL_PRI_OFFSET,
                              ds_cstr(&match), "next;");

                ds_destroy(&match);
            }
        } else if (!strcmp(acl->action, "drop")
                   || !strcmp(acl->action, "reject")) {
            struct ds match = DS_EMPTY_INITIALIZER;

            /* XXX Need to support "reject", treat it as "drop;" for now. */
            if (!strcmp(acl->action, "reject")) {
                VLOG_INFO("reject is not a supported action");
            }

            /* The implementation of "drop" differs if stateful ACLs are in
             * use for this datapath.  In that case, the actions differ
             * depending on whether the connection was previously committed
             * to the connection tracker with ct_commit. */
            if (has_stateful) {
                /* If the packet is not part of an established connection, then
                 * we can simply drop it. */
                ds_put_format(&match,
                              "(!ct.est || (ct.est && ct_label.blocked == 1)) "
                              "&& (%s)",
                              acl->match);
                ovn_lflow_add(lflows, od, stage, acl->priority +
                        OVN_ACL_PRI_OFFSET, ds_cstr(&match), "drop;");

                /* For an existing connection without ct_label set, we've
                 * encountered a policy change. ACLs previously allowed
                 * this connection and we committed the connection tracking
                 * entry.  Current policy says that we should drop this
                 * connection.  First, we set bit 0 of ct_label to indicate
                 * that this connection is set for deletion.  By not
                 * specifying "next;", we implicitly drop the packet after
                 * updating conntrack state.  We would normally defer
                 * ct_commit() to the "stateful" stage, but since we're
                 * dropping the packet, we go ahead and do it here. */
                ds_clear(&match);
                ds_put_format(&match,
                              "ct.est && ct_label.blocked == 0 && (%s)",
                              acl->match);
                ovn_lflow_add(lflows, od, stage,
                              acl->priority + OVN_ACL_PRI_OFFSET,
                              ds_cstr(&match), "ct_commit(ct_label=1/1);");

                ds_destroy(&match);
            } else {
                /* There are no stateful ACLs in use on this datapath,
                 * so a "drop" ACL is simply the "drop" logical flow action
                 * in all cases. */
                ovn_lflow_add(lflows, od, stage,
                              acl->priority + OVN_ACL_PRI_OFFSET,
                              acl->match, "drop;");
            }
        }
    }

    /* Add 34000 priority flow to allow DHCP reply from ovn-controller to all
     * logical ports of the datapath if the CMS has configured DHCPv4 options*/
    for (size_t i = 0; i < od->nbs->n_ports; i++) {
        if (od->nbs->ports[i]->dhcpv4_options) {
            const char *server_id = smap_get(
                &od->nbs->ports[i]->dhcpv4_options->options, "server_id");
            const char *server_mac = smap_get(
                &od->nbs->ports[i]->dhcpv4_options->options, "server_mac");
            const char *lease_time = smap_get(
                &od->nbs->ports[i]->dhcpv4_options->options, "lease_time");
            const char *router = smap_get(
                &od->nbs->ports[i]->dhcpv4_options->options, "router");
            if (server_id && server_mac && lease_time && router) {
                struct ds match = DS_EMPTY_INITIALIZER;
                const char *actions =
                    has_stateful ? "ct_commit; next;" : "next;";
                ds_put_format(&match, "outport == \"%s\" && eth.src == %s "
                              "&& ip4.src == %s && udp && udp.src == 67 "
                              "&& udp.dst == 68", od->nbs->ports[i]->name,
                              server_mac, server_id);
                ovn_lflow_add(
                    lflows, od, S_SWITCH_OUT_ACL, 34000, ds_cstr(&match),
                    actions);
                ds_destroy(&match);
            }
        }

        if (od->nbs->ports[i]->dhcpv6_options) {
            const char *server_mac = smap_get(
                &od->nbs->ports[i]->dhcpv6_options->options, "server_id");
            struct eth_addr ea;
            if (server_mac && eth_addr_from_string(server_mac, &ea)) {
                /* Get the link local IP of the DHCPv6 server from the
                 * server MAC. */
                struct in6_addr lla;
                in6_generate_lla(ea, &lla);

                char server_ip[INET6_ADDRSTRLEN + 1];
                ipv6_string_mapped(server_ip, &lla);

                struct ds match = DS_EMPTY_INITIALIZER;
                const char *actions = has_stateful ? "ct_commit; next;" :
                    "next;";
                ds_put_format(&match, "outport == \"%s\" && eth.src == %s "
                              "&& ip6.src == %s && udp && udp.src == 547 "
                              "&& udp.dst == 546", od->nbs->ports[i]->name,
                              server_mac, server_ip);
                ovn_lflow_add(
                    lflows, od, S_SWITCH_OUT_ACL, 34000, ds_cstr(&match),
                    actions);
                ds_destroy(&match);
            }
        }
    }
}

static void
build_qos(struct ovn_datapath *od, struct hmap *lflows) {
    ovn_lflow_add(lflows, od, S_SWITCH_IN_QOS_MARK, 0, "1", "next;");
    ovn_lflow_add(lflows, od, S_SWITCH_OUT_QOS_MARK, 0, "1", "next;");

    for (size_t i = 0; i < od->nbs->n_qos_rules; i++) {
        struct nbrec_qos *qos = od->nbs->qos_rules[i];
        bool ingress = !strcmp(qos->direction, "from-lport") ? true :false;
        enum ovn_stage stage = ingress ? S_SWITCH_IN_QOS_MARK : S_SWITCH_OUT_QOS_MARK;

        if (!strcmp(qos->key_action, "dscp")) {
            struct ds dscp_action = DS_EMPTY_INITIALIZER;

            ds_put_format(&dscp_action, "ip.dscp = %d; next;",
                          (uint8_t)qos->value_action);
            ovn_lflow_add(lflows, od, stage,
                          qos->priority,
                          qos->match, ds_cstr(&dscp_action));
            ds_destroy(&dscp_action);
        }
    }
}

static void
build_stateful(struct ovn_datapath *od, struct hmap *lflows)
{
    /* Load balancing rules for new connections get committed to conntrack
     * table.  So even if REGBIT_CONNTRACK_COMMIT is set in a previous table
     * a higher priority rule for load balancing below also commits the
     * connection, so it is okay if we do not hit the above match on
     * REGBIT_CONNTRACK_COMMIT. */
    for (int i = 0; i < od->nbs->n_load_balancer; i++) {
        struct nbrec_load_balancer *lb = od->nbs->load_balancer[i];
        struct smap *vips = &lb->vips;
        struct smap_node *node;

        SMAP_FOR_EACH (node, vips) {
            uint16_t port = 0;

            /* node->key contains IP:port or just IP. */
            char *ip_address = NULL;
            ip_address_and_port_from_lb_key(node->key, &ip_address, &port);
            if (!ip_address) {
                continue;
            }

            /* New connections in Ingress table. */
            char *action = xasprintf("ct_lb(%s);", node->value);
            struct ds match = DS_EMPTY_INITIALIZER;
            ds_put_format(&match, "ct.new && ip4.dst == %s", ip_address);
            if (port) {
                if (lb->protocol && !strcmp(lb->protocol, "udp")) {
                    ds_put_format(&match, " && udp.dst == %d", port);
                } else {
                    ds_put_format(&match, " && tcp.dst == %d", port);
                }
                ovn_lflow_add(lflows, od, S_SWITCH_IN_STATEFUL,
                              120, ds_cstr(&match), action);
            } else {
                ovn_lflow_add(lflows, od, S_SWITCH_IN_STATEFUL,
                              110, ds_cstr(&match), action);
            }

            free(ip_address);
            ds_destroy(&match);
            free(action);
       }
    }
}

static void
build_lswitch_flows(struct hmap *datapaths, struct hmap *ports,
                    struct hmap *lflows, struct hmap *mcgroups)
{
    /* This flow table structure is documented in ovn-northd(8), so please
     * update ovn-northd.8.xml if you change anything. */

    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    /* Build pre-ACL and ACL tables for both ingress and egress.
     * Ingress tables 3 through 9.  Egress tables 0 through 6. */
    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbs) {
            continue;
        }

        build_pre_acls(od, lflows);
        build_acls(od, lflows);
        build_qos(od, lflows);
        build_stateful(od, lflows);
    }

    /* Broadcast/multicast and unknown handling. */
    struct ovn_port *op;
    HMAP_FOR_EACH (op, key_node, ports) {
        if (op->nbsp && lsp_is_enabled(op->nbsp)) {
            ovn_multicast_add(mcgroups, &mc_flood, op);
            if (op->nbsp->has_unknown) {
                ovn_multicast_add(mcgroups, &mc_unknown, op);
            }
        }
    }

    ds_destroy(&match);
    ds_destroy(&actions);
}

/* Returns a string of the IP address of the router port 'op' that
 * overlaps with 'ip_s".  If one is not found, returns NULL.
 *
 * The caller must not free the returned string. */
static const char *
find_lrp_member_ip(const struct ovn_port *op, const char *ip_s)
{
    bool is_ipv4 = strchr(ip_s, '.') ? true : false;

    if (is_ipv4) {
        ovs_be32 ip;

        if (!ip_parse(ip_s, &ip)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad ip address %s", ip_s);
            return NULL;
        }

        for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            const struct ipv4_netaddr *na = &op->lrp_networks.ipv4_addrs[i];

            if (!((na->network ^ ip) & na->mask)) {
                /* There should be only 1 interface that matches the
                 * supplied IP.  Otherwise, it's a configuration error,
                 * because subnets of a router's interfaces should NOT
                 * overlap. */
                return na->addr_s;
            }
        }
    } else {
        struct in6_addr ip6;

        if (!ipv6_parse(ip_s, &ip6)) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad ipv6 address %s", ip_s);
            return NULL;
        }

        for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
            const struct ipv6_netaddr *na = &op->lrp_networks.ipv6_addrs[i];
            struct in6_addr xor_addr = ipv6_addr_bitxor(&na->network, &ip6);
            struct in6_addr and_addr = ipv6_addr_bitand(&xor_addr, &na->mask);

            if (ipv6_is_zero(&and_addr)) {
                /* There should be only 1 interface that matches the
                 * supplied IP.  Otherwise, it's a configuration error,
                 * because subnets of a router's interfaces should NOT
                 * overlap. */
                return na->addr_s;
            }
        }
    }

    return NULL;
}

static void
add_route(struct hmap *lflows, const struct ovn_port *op,
          const char *lrp_addr_s, const char *network_s, int plen,
          const char *gateway)
{
    bool is_ipv4 = strchr(network_s, '.') ? true : false;
    struct ds match = DS_EMPTY_INITIALIZER;

    /* IPv6 link-local addresses must be scoped to the local router port. */
    if (!is_ipv4) {
        struct in6_addr network;
        ovs_assert(ipv6_parse(network_s, &network));
        if (in6_is_lla(&network)) {
            ds_put_format(&match, "inport == %s && ", op->json_key);
        }
    }
    ds_put_format(&match, "ip%s.dst == %s/%d", is_ipv4 ? "4" : "6",
                  network_s, plen);

    struct ds actions = DS_EMPTY_INITIALIZER;
    ds_put_format(&actions, "ip.ttl--; %sreg0 = ", is_ipv4 ? "" : "xx");

    if (gateway) {
        ds_put_cstr(&actions, gateway);
    } else {
        ds_put_format(&actions, "ip%s.dst", is_ipv4 ? "4" : "6");
    }
    ds_put_format(&actions, "; "
                  "%sreg1 = %s; "
                  "eth.src = %s; "
                  "outport = %s; "
                  "flags.loopback = 1; "
                  "next;",
                  is_ipv4 ? "" : "xx",
                  lrp_addr_s,
                  op->lrp_networks.ea_s,
                  op->json_key);

    /* The priority here is calculated to implement longest-prefix-match
     * routing. */
    ovn_lflow_add(lflows, op->od, S_ROUTER_IN_IP_ROUTING, plen,
                  ds_cstr(&match), ds_cstr(&actions));
    ds_destroy(&match);
    ds_destroy(&actions);
}

static void
build_static_route_flow(struct hmap *lflows, struct ovn_datapath *od,
                        struct hmap *ports,
                        const struct nbrec_logical_router_static_route *route)
{
    ovs_be32 nexthop;
    const char *lrp_addr_s;
    unsigned int plen;
    bool is_ipv4;

    /* Verify that the next hop is an IP address with an all-ones mask. */
    char *error = ip_parse_cidr(route->nexthop, &nexthop, &plen);
    if (!error) {
        if (plen != 32) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad next hop mask %s", route->nexthop);
            return;
        }
        is_ipv4 = true;
    } else {
        free(error);

        struct in6_addr ip6;
        char *error = ipv6_parse_cidr(route->nexthop, &ip6, &plen);
        if (!error) {
            if (plen != 128) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "bad next hop mask %s", route->nexthop);
                return;
            }
            is_ipv4 = false;
        } else {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad next hop ip address %s", route->nexthop);
            free(error);
            return;
        }
    }

    char *prefix_s;
    if (is_ipv4) {
        ovs_be32 prefix;
        /* Verify that ip prefix is a valid IPv4 address. */
        error = ip_parse_cidr(route->ip_prefix, &prefix, &plen);
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad 'ip_prefix' in static routes %s",
                         route->ip_prefix);
            free(error);
            return;
        }
        prefix_s = xasprintf(IP_FMT, IP_ARGS(prefix & be32_prefix_mask(plen)));
    } else {
        /* Verify that ip prefix is a valid IPv6 address. */
        struct in6_addr prefix;
        error = ipv6_parse_cidr(route->ip_prefix, &prefix, &plen);
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "bad 'ip_prefix' in static routes %s",
                         route->ip_prefix);
            free(error);
            return;
        }
        struct in6_addr mask = ipv6_create_mask(plen);
        struct in6_addr network = ipv6_addr_bitand(&prefix, &mask);
        prefix_s = xmalloc(INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &network, prefix_s, INET6_ADDRSTRLEN);
    }

    /* Find the outgoing port. */
    struct ovn_port *out_port = NULL;
    if (route->output_port) {
        out_port = ovn_port_find(ports, route->output_port);
        if (!out_port) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
            VLOG_WARN_RL(&rl, "Bad out port %s for static route %s",
                         route->output_port, route->ip_prefix);
            goto free_prefix_s;
        }
        lrp_addr_s = find_lrp_member_ip(out_port, route->nexthop);
    } else {
        /* output_port is not specified, find the
         * router port matching the next hop. */
        int i;
        for (i = 0; i < od->nbr->n_ports; i++) {
            struct nbrec_logical_router_port *lrp = od->nbr->ports[i];
            out_port = ovn_port_find(ports, lrp->name);
            if (!out_port) {
                /* This should not happen. */
                continue;
            }

            lrp_addr_s = find_lrp_member_ip(out_port, route->nexthop);
            if (lrp_addr_s) {
                break;
            }
        }
    }

     if (!lrp_addr_s) {
        /* There is no matched out port. */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "No path for static route %s; next hop %s",
                     route->ip_prefix, route->nexthop);
        goto free_prefix_s;
    }

    add_route(lflows, out_port, lrp_addr_s, prefix_s, plen, route->nexthop);

free_prefix_s:
    free(prefix_s);
}

static void
op_put_v4_networks(struct ds *ds, const struct ovn_port *op, bool add_bcast)
{
    if (!add_bcast && op->lrp_networks.n_ipv4_addrs == 1) {
        ds_put_format(ds, "%s", op->lrp_networks.ipv4_addrs[0].addr_s);
        return;
    }

    ds_put_cstr(ds, "{");
    for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
        ds_put_format(ds, "%s, ", op->lrp_networks.ipv4_addrs[i].addr_s);
        if (add_bcast) {
            ds_put_format(ds, "%s, ", op->lrp_networks.ipv4_addrs[i].bcast_s);
        }
    }
    ds_chomp(ds, ' ');
    ds_chomp(ds, ',');
    ds_put_cstr(ds, "}");
}

static void
op_put_v6_networks(struct ds *ds, const struct ovn_port *op)
{
    if (op->lrp_networks.n_ipv6_addrs == 1) {
        ds_put_format(ds, "%s", op->lrp_networks.ipv6_addrs[0].addr_s);
        return;
    }

    ds_put_cstr(ds, "{");
    for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
        ds_put_format(ds, "%s, ", op->lrp_networks.ipv6_addrs[i].addr_s);
    }
    ds_chomp(ds, ' ');
    ds_chomp(ds, ',');
    ds_put_cstr(ds, "}");
}

static void
build_lrouter_flows(struct hmap *datapaths, struct hmap *ports,
                    struct hmap *lflows)
{
    /* This flow table structure is documented in ovn-northd(8), so please
     * update ovn-northd.8.xml if you change anything. */

    struct ds match = DS_EMPTY_INITIALIZER;
    struct ds actions = DS_EMPTY_INITIALIZER;

    /* Logical router ingress table 1: IP Input for IPv4. */
    struct ovn_port *op;
    HMAP_FOR_EACH (op, key_node, ports) {
        if (!op->nbrp) {
            continue;
        }


        if (op->lrp_networks.n_ipv4_addrs) {
            /* L3 admission control: drop packets that originate from an
             * IPv4 address owned by the router or a broadcast address
             * known to the router (priority 100). */
            ds_clear(&match);
            ds_put_cstr(&match, "ip4.src == ");
            op_put_v4_networks(&match, op, true);
            ovn_lflow_add(lflows, op->od, S_ROUTER_IN_IP_INPUT, 100,
                          ds_cstr(&match), "drop;");

            /* ICMP echo reply.  These flows reply to ICMP echo requests
             * received for the router's IP address. Since packets only
             * get here as part of the logical router datapath, the inport
             * (i.e. the incoming locally attached net) does not matter.
             * The ip.ttl also does not matter (RFC1812 section 4.2.2.9) */
            ds_clear(&match);
            ds_put_cstr(&match, "ip4.dst == ");
            op_put_v4_networks(&match, op, false);
            ds_put_cstr(&match, " && icmp4.type == 8 && icmp4.code == 0");

            ds_clear(&actions);
            ds_put_format(&actions,
                "ip4.dst <-> ip4.src; "
                "ip.ttl = 255; "
                "icmp4.type = 0; "
                "flags.loopback = 1; "
                "next; ");
            ovn_lflow_add(lflows, op->od, S_ROUTER_IN_IP_INPUT, 90,
                          ds_cstr(&match), ds_cstr(&actions));
        }

        /* ARP reply.  These flows reply to ARP requests for the router's own
         * IP address. */
        for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            ds_clear(&match);
            ds_put_format(&match,
                          "inport == %s && arp.tpa == %s && arp.op == 1",
                          op->json_key, op->lrp_networks.ipv4_addrs[i].addr_s);

            ds_clear(&actions);
            ds_put_format(&actions,
                "eth.dst = eth.src; "
                "eth.src = %s; "
                "arp.op = 2; /* ARP reply */ "
                "arp.tha = arp.sha; "
                "arp.sha = %s; "
                "arp.tpa = arp.spa; "
                "arp.spa = %s; "
                "outport = %s; "
                "flags.loopback = 1; "
                "output;",
                op->lrp_networks.ea_s,
                op->lrp_networks.ea_s,
                op->lrp_networks.ipv4_addrs[i].addr_s,
                op->json_key);
            ovn_lflow_add(lflows, op->od, S_ROUTER_IN_IP_INPUT, 90,
                          ds_cstr(&match), ds_cstr(&actions));
        }

        /* A set to hold all load-balancer vips that need ARP responses. */
        struct sset all_ips = SSET_INITIALIZER(&all_ips);

        for (int i = 0; i < op->od->nbr->n_load_balancer; i++) {
            struct nbrec_load_balancer *lb = op->od->nbr->load_balancer[i];
            struct smap *vips = &lb->vips;
            struct smap_node *node;

            SMAP_FOR_EACH (node, vips) {
                /* node->key contains IP:port or just IP. */
                char *ip_address = NULL;
                uint16_t port;

                ip_address_and_port_from_lb_key(node->key, &ip_address, &port);
                if (!ip_address) {
                    continue;
                }

                if (!sset_contains(&all_ips, ip_address)) {
                    sset_add(&all_ips, ip_address);
                }

                free(ip_address);
            }
        }

        const char *ip_address;
        SSET_FOR_EACH(ip_address, &all_ips) {
            ovs_be32 ip;
            if (!ip_parse(ip_address, &ip) || !ip) {
                continue;
            }

            ds_clear(&match);
            ds_put_format(&match,
                          "inport == %s && arp.tpa == "IP_FMT" && arp.op == 1",
                          op->json_key, IP_ARGS(ip));

            ds_clear(&actions);
            ds_put_format(&actions,
                "eth.dst = eth.src; "
                "eth.src = %s; "
                "arp.op = 2; /* ARP reply */ "
                "arp.tha = arp.sha; "
                "arp.sha = %s; "
                "arp.tpa = arp.spa; "
                "arp.spa = "IP_FMT"; "
                "outport = %s; "
                "flags.loopback = 1; "
                "output;",
                op->lrp_networks.ea_s,
                op->lrp_networks.ea_s,
                IP_ARGS(ip),
                op->json_key);
            ovn_lflow_add(lflows, op->od, S_ROUTER_IN_IP_INPUT, 90,
                          ds_cstr(&match), ds_cstr(&actions));
        }

        sset_destroy(&all_ips);

        ovs_be32 *snat_ips = xmalloc(sizeof *snat_ips * op->od->nbr->n_nat);
        size_t n_snat_ips = 0;
        for (int i = 0; i < op->od->nbr->n_nat; i++) {
            const struct nbrec_nat *nat;

            nat = op->od->nbr->nat[i];

            ovs_be32 ip;
            if (!ip_parse(nat->external_ip, &ip) || !ip) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "bad ip address %s in nat configuration "
                             "for router %s", nat->external_ip, op->key);
                continue;
            }

            if (!strcmp(nat->type, "snat")) {
                snat_ips[n_snat_ips++] = ip;
                continue;
            }

            /* ARP handling for external IP addresses.
             *
             * DNAT IP addresses are external IP addresses that need ARP
             * handling. */
            ds_clear(&match);
            ds_put_format(&match,
                          "inport == %s && arp.tpa == "IP_FMT" && arp.op == 1",
                          op->json_key, IP_ARGS(ip));

            ds_clear(&actions);
            ds_put_format(&actions,
                "eth.dst = eth.src; "
                "eth.src = %s; "
                "arp.op = 2; /* ARP reply */ "
                "arp.tha = arp.sha; "
                "arp.sha = %s; "
                "arp.tpa = arp.spa; "
                "arp.spa = "IP_FMT"; "
                "outport = %s; "
                "flags.loopback = 1; "
                "output;",
                op->lrp_networks.ea_s,
                op->lrp_networks.ea_s,
                IP_ARGS(ip),
                op->json_key);
            ovn_lflow_add(lflows, op->od, S_ROUTER_IN_IP_INPUT, 90,
                          ds_cstr(&match), ds_cstr(&actions));
        }

        ds_clear(&match);
        ds_put_cstr(&match, "ip4.dst == {");
        bool has_drop_ips = false;
        for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            bool snat_ip_is_router_ip = false;
            for (int j = 0; j < n_snat_ips; j++) {
                /* Packets to SNAT IPs should not be dropped. */
                if (op->lrp_networks.ipv4_addrs[i].addr == snat_ips[j]) {
                    snat_ip_is_router_ip = true;
                    break;
                }
            }
            if (snat_ip_is_router_ip) {
                continue;
            }
            ds_put_format(&match, "%s, ",
                          op->lrp_networks.ipv4_addrs[i].addr_s);
            has_drop_ips = true;
        }
        ds_chomp(&match, ' ');
        ds_chomp(&match, ',');
        ds_put_cstr(&match, "}");

        if (has_drop_ips) {
            /* Drop IP traffic to this router. */
            ovn_lflow_add(lflows, op->od, S_ROUTER_IN_IP_INPUT, 60,
                          ds_cstr(&match), "drop;");
        }

        free(snat_ips);
    }

    /* Logical router ingress table 1: IP Input for IPv6. */
    HMAP_FOR_EACH (op, key_node, ports) {
        if (!op->nbrp) {
            continue;
        }

        if (op->lrp_networks.n_ipv6_addrs) {
            /* L3 admission control: drop packets that originate from an
             * IPv6 address owned by the router (priority 100). */
            ds_clear(&match);
            ds_put_cstr(&match, "ip6.src == ");
            op_put_v6_networks(&match, op);
            ovn_lflow_add(lflows, op->od, S_ROUTER_IN_IP_INPUT, 100,
                          ds_cstr(&match), "drop;");

            /* ICMPv6 echo reply.  These flows reply to echo requests
             * received for the router's IP address. */
            ds_clear(&match);
            ds_put_cstr(&match, "ip6.dst == ");
            op_put_v6_networks(&match, op);
            ds_put_cstr(&match, " && icmp6.type == 128 && icmp6.code == 0");

            ds_clear(&actions);
            ds_put_cstr(&actions,
                        "ip6.dst <-> ip6.src; "
                        "ip.ttl = 255; "
                        "icmp6.type = 129; "
                        "flags.loopback = 1; "
                        "next; ");
            ovn_lflow_add(lflows, op->od, S_ROUTER_IN_IP_INPUT, 90,
                          ds_cstr(&match), ds_cstr(&actions));

            /* Drop IPv6 traffic to this router. */
            ds_clear(&match);
            ds_put_cstr(&match, "ip6.dst == ");
            op_put_v6_networks(&match, op);
            ovn_lflow_add(lflows, op->od, S_ROUTER_IN_IP_INPUT, 60,
                          ds_cstr(&match), "drop;");
        }

        /* ND reply.  These flows reply to ND solicitations for the
         * router's own IP address. */
        for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
            ds_clear(&match);
            ds_put_format(&match,
                    "inport == %s && nd_ns && ip6.dst == {%s, %s} "
                    "&& nd.target == %s",
                    op->json_key,
                    op->lrp_networks.ipv6_addrs[i].addr_s,
                    op->lrp_networks.ipv6_addrs[i].sn_addr_s,
                    op->lrp_networks.ipv6_addrs[i].addr_s);

            ds_clear(&actions);
            ds_put_format(&actions,
                          "put_nd(inport, ip6.src, nd.sll); "
                          "nd_na { "
                          "eth.src = %s; "
                          "ip6.src = %s; "
                          "nd.target = %s; "
                          "nd.tll = %s; "
                          "outport = inport; "
                          "flags.loopback = 1; "
                          "output; "
                          "};",
                          op->lrp_networks.ea_s,
                          op->lrp_networks.ipv6_addrs[i].addr_s,
                          op->lrp_networks.ipv6_addrs[i].addr_s,
                          op->lrp_networks.ea_s);
            ovn_lflow_add(lflows, op->od, S_ROUTER_IN_IP_INPUT, 90,
                          ds_cstr(&match), ds_cstr(&actions));
        }
    }

    /* NAT, Defrag and load balancing in Gateway routers. */
    struct ovn_datapath *od;
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbr) {
            continue;
        }

        /* NAT rules, packet defrag and load balancing are only valid on
         * Gateway routers. */
        if (!smap_get(&od->nbr->options, "chassis")) {
            continue;
        }

        /* A set to hold all ips that need defragmentation and tracking. */
        struct sset all_ips = SSET_INITIALIZER(&all_ips);

        for (int i = 0; i < od->nbr->n_load_balancer; i++) {
            struct nbrec_load_balancer *lb = od->nbr->load_balancer[i];
            struct smap *vips = &lb->vips;
            struct smap_node *node;

            SMAP_FOR_EACH (node, vips) {
                uint16_t port = 0;

                /* node->key contains IP:port or just IP. */
                char *ip_address = NULL;
                ip_address_and_port_from_lb_key(node->key, &ip_address, &port);
                if (!ip_address) {
                    continue;
                }

                if (!sset_contains(&all_ips, ip_address)) {
                    sset_add(&all_ips, ip_address);
                }

                /* Higher priority rules are added in DNAT table to match on
                 * ct.new which in-turn have group id as an action for load
                 * balancing. */
                ds_clear(&actions);
                ds_put_format(&actions, "ct_lb(%s);", node->value);

                ds_clear(&match);
                ds_put_format(&match, "ct.new && ip && ip4.dst == %s",
                              ip_address);
                free(ip_address);

                if (port) {
                    if (lb->protocol && !strcmp(lb->protocol, "udp")) {
                        ds_put_format(&match, " && udp && udp.dst == %d",
                                      port);
                    } else {
                        ds_put_format(&match, " && tcp && tcp.dst == %d",
                                      port);
                    }
                    ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT,
                                  120, ds_cstr(&match), ds_cstr(&actions));
                } else {
                    ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT,
                                  110, ds_cstr(&match), ds_cstr(&actions));
                }
            }
        }

        /* If there are any load balancing rules, we should send the
         * packet to conntrack for defragmentation and tracking.  This helps
         * with two things.
         *
         * 1. With tracking, we can send only new connections to pick a
         *    DNAT ip address from a group.
         * 2. If there are L4 ports in load balancing rules, we need the
         *    defragmentation to match on L4 ports. */
        const char *ip_address;
        SSET_FOR_EACH(ip_address, &all_ips) {
            ds_clear(&match);
            ds_put_format(&match, "ip && ip4.dst == %s", ip_address);
            ovn_lflow_add(lflows, od, S_ROUTER_IN_DEFRAG,
                          100, ds_cstr(&match), "ct_next;");
        }

        sset_destroy(&all_ips);

        for (int i = 0; i < od->nbr->n_nat; i++) {
            const struct nbrec_nat *nat;

            nat = od->nbr->nat[i];

            ovs_be32 ip, mask;

            char *error = ip_parse_masked(nat->external_ip, &ip, &mask);
            if (error || mask != OVS_BE32_MAX) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
                VLOG_WARN_RL(&rl, "bad external ip %s for nat",
                             nat->external_ip);
                free(error);
                continue;
            }

            /* Check the validity of nat->logical_ip. 'logical_ip' can
             * be a subnet when the type is "snat". */
            error = ip_parse_masked(nat->logical_ip, &ip, &mask);
            if (!strcmp(nat->type, "snat")) {
                if (error) {
                    static struct vlog_rate_limit rl =
                        VLOG_RATE_LIMIT_INIT(5, 1);
                    VLOG_WARN_RL(&rl, "bad ip network or ip %s for snat "
                                 "in router "UUID_FMT"",
                                 nat->logical_ip, UUID_ARGS(&od->key));
                    free(error);
                    continue;
                }
            } else {
                if (error || mask != OVS_BE32_MAX) {
                    static struct vlog_rate_limit rl =
                        VLOG_RATE_LIMIT_INIT(5, 1);
                    VLOG_WARN_RL(&rl, "bad ip %s for dnat in router "
                        ""UUID_FMT"", nat->logical_ip, UUID_ARGS(&od->key));
                    free(error);
                    continue;
                }
            }

            /* Ingress UNSNAT table: It is for already established connections'
             * reverse traffic. i.e., SNAT has already been done in egress
             * pipeline and now the packet has entered the ingress pipeline as
             * part of a reply. We undo the SNAT here.
             *
             * Undoing SNAT has to happen before DNAT processing.  This is
             * because when the packet was DNATed in ingress pipeline, it did
             * not know about the possibility of eventual additional SNAT in
             * egress pipeline. */
            if (!strcmp(nat->type, "snat")
                || !strcmp(nat->type, "dnat_and_snat")) {
                ds_clear(&match);
                ds_put_format(&match, "ip && ip4.dst == %s", nat->external_ip);
                ovn_lflow_add(lflows, od, S_ROUTER_IN_UNSNAT, 100,
                              ds_cstr(&match), "ct_snat; next;");
            }

            /* Ingress DNAT table: Packets enter the pipeline with destination
             * IP address that needs to be DNATted from a external IP address
             * to a logical IP address. */
            if (!strcmp(nat->type, "dnat")
                || !strcmp(nat->type, "dnat_and_snat")) {
                /* Packet when it goes from the initiator to destination.
                 * We need to zero the inport because the router can
                 * send the packet back through the same interface. */
                ds_clear(&match);
                ds_put_format(&match, "ip && ip4.dst == %s", nat->external_ip);
                ds_clear(&actions);
                ds_put_format(&actions,"flags.loopback = 1; ct_dnat(%s);",
                              nat->logical_ip);
                ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT, 100,
                              ds_cstr(&match), ds_cstr(&actions));
            }

            /* Egress SNAT table: Packets enter the egress pipeline with
             * source ip address that needs to be SNATted to a external ip
             * address. */
            if (!strcmp(nat->type, "snat")
                || !strcmp(nat->type, "dnat_and_snat")) {
                ds_clear(&match);
                ds_put_format(&match, "ip && ip4.src == %s", nat->logical_ip);
                ds_clear(&actions);
                ds_put_format(&actions, "ct_snat(%s);", nat->external_ip);

                /* The priority here is calculated such that the
                 * nat->logical_ip with the longest mask gets a higher
                 * priority. */
                ovn_lflow_add(lflows, od, S_ROUTER_OUT_SNAT,
                              count_1bits(ntohl(mask)) + 1,
                              ds_cstr(&match), ds_cstr(&actions));
            }
        }

        /* Re-circulate every packet through the DNAT zone.
        * This helps with three things.
        *
        * 1. Any packet that needs to be unDNATed in the reverse
        * direction gets unDNATed. Ideally this could be done in
        * the egress pipeline. But since the gateway router
        * does not have any feature that depends on the source
        * ip address being external IP address for IP routing,
        * we can do it here, saving a future re-circulation.
        *
        * 2. Established load-balanced connections automatically get
        * DNATed.
        *
        * 3. Any packet that was sent through SNAT zone in the
        * previous table automatically gets re-circulated to get
        * back the new destination IP address that is needed for
        * routing in the openflow pipeline. */
        ovn_lflow_add(lflows, od, S_ROUTER_IN_DNAT, 50,
                      "ip", "flags.loopback = 1; ct_dnat;");
    }

    /* Logical router ingress table 5: IP Routing.
     *
     * A packet that arrives at this table is an IP packet that should be
     * routed to the address in 'ip[46].dst'. This table sets outport to
     * the correct output port, eth.src to the output port's MAC
     * address, and '[xx]reg0' to the next-hop IP address (leaving
     * 'ip[46].dst', the packet’s final destination, unchanged), and
     * advances to the next table for ARP/ND resolution. */
    HMAP_FOR_EACH (op, key_node, ports) {
        if (!op->nbrp) {
            continue;
        }

        for (int i = 0; i < op->lrp_networks.n_ipv4_addrs; i++) {
            add_route(lflows, op, op->lrp_networks.ipv4_addrs[i].addr_s,
                      op->lrp_networks.ipv4_addrs[i].network_s,
                      op->lrp_networks.ipv4_addrs[i].plen, NULL);
        }

        for (int i = 0; i < op->lrp_networks.n_ipv6_addrs; i++) {
            add_route(lflows, op, op->lrp_networks.ipv6_addrs[i].addr_s,
                      op->lrp_networks.ipv6_addrs[i].network_s,
                      op->lrp_networks.ipv6_addrs[i].plen, NULL);
        }
    }

    /* Convert the static routes to flows. */
    HMAP_FOR_EACH (od, key_node, datapaths) {
        if (!od->nbr) {
            continue;
        }

        for (int i = 0; i < od->nbr->n_static_routes; i++) {
            const struct nbrec_logical_router_static_route *route;

            route = od->nbr->static_routes[i];
            build_static_route_flow(lflows, od, ports, route);
        }
    }

    /* XXX destination unreachable */

    /* Local router ingress table 6: ARP Resolution.
     *
     * Any packet that reaches this table is an IP packet whose next-hop IP
     * address is in reg0. (ip4.dst is the final destination.) This table
     * resolves the IP address in reg0 into an output port in outport and an
     * Ethernet address in eth.dst. */
    HMAP_FOR_EACH (op, key_node, ports) {
        if (op->nbrp) {
            /* This is a logical router port. If next-hop IP address in
             * '[xx]reg0' matches IP address of this router port, then
             * the packet is intended to eventually be sent to this
             * logical port. Set the destination mac address using this
             * port's mac address.
             *
             * The packet is still in peer's logical pipeline. So the match
             * should be on peer's outport. */
            if (op->peer && op->nbrp->peer) {
                if (op->lrp_networks.n_ipv4_addrs) {
                    ds_clear(&match);
                    ds_put_format(&match, "outport == %s && reg0 == ",
                                  op->peer->json_key);
                    op_put_v4_networks(&match, op, false);

                    ds_clear(&actions);
                    ds_put_format(&actions, "eth.dst = %s; next;",
                                  op->lrp_networks.ea_s);
                    ovn_lflow_add(lflows, op->peer->od, S_ROUTER_IN_ARP_RESOLVE,
                                  100, ds_cstr(&match), ds_cstr(&actions));
                }

                if (op->lrp_networks.n_ipv6_addrs) {
                    ds_clear(&match);
                    ds_put_format(&match, "outport == %s && xxreg0 == ",
                                  op->peer->json_key);
                    op_put_v6_networks(&match, op);

                    ds_clear(&actions);
                    ds_put_format(&actions, "eth.dst = %s; next;",
                                  op->lrp_networks.ea_s);
                    ovn_lflow_add(lflows, op->peer->od, S_ROUTER_IN_ARP_RESOLVE,
                                  100, ds_cstr(&match), ds_cstr(&actions));
                }
            }
        } else if (op->od->n_router_ports && strcmp(op->nbsp->type, "router")) {
            /* This is a logical switch port that backs a VM or a container.
             * Extract its addresses. For each of the address, go through all
             * the router ports attached to the switch (to which this port
             * connects) and if the address in question is reachable from the
             * router port, add an ARP/ND entry in that router's pipeline. */

            for (size_t i = 0; i < op->nbsp->n_lsp_addrs; i++) {
                const char *ea_s = op->nbsp->lsp_addrs[i].ea_s;
                for (size_t j = 0; j < op->nbsp->lsp_addrs[i].n_ipv4_addrs; j++) {
                    const char *ip_s = op->nbsp->lsp_addrs[i].ipv4_addrs[j].addr_s;
                    for (size_t k = 0; k < op->od->n_router_ports; k++) {
                        /* Get the Logical_Router_Port that the
                         * Logical_Switch_Port is connected to, as
                         * 'peer'. */
                        const char *peer_name = smap_get(
                            &op->od->router_ports[k]->nbsp->options,
                            "router-port");
                        if (!peer_name) {
                            continue;
                        }

                        struct ovn_port *peer = ovn_port_find(ports, peer_name);
                        if (!peer || !peer->nbrp) {
                            continue;
                        }

                        if (!find_lrp_member_ip(peer, ip_s)) {
                            continue;
                        }

                        ds_clear(&match);
                        ds_put_format(&match, "outport == %s && reg0 == %s",
                                      peer->json_key, ip_s);

                        ds_clear(&actions);
                        ds_put_format(&actions, "eth.dst = %s; next;", ea_s);
                        ovn_lflow_add(lflows, peer->od,
                                      S_ROUTER_IN_ARP_RESOLVE, 100,
                                      ds_cstr(&match), ds_cstr(&actions));
                    }
                }

                for (size_t j = 0; j < op->nbsp->lsp_addrs[i].n_ipv6_addrs; j++) {
                    const char *ip_s = op->nbsp->lsp_addrs[i].ipv6_addrs[j].addr_s;
                    for (size_t k = 0; k < op->od->n_router_ports; k++) {
                        /* Get the Logical_Router_Port that the
                         * Logical_Switch_Port is connected to, as
                         * 'peer'. */
                        const char *peer_name = smap_get(
                            &op->od->router_ports[k]->nbsp->options,
                            "router-port");
                        if (!peer_name) {
                            continue;
                        }

                        struct ovn_port *peer = ovn_port_find(ports, peer_name);
                        if (!peer || !peer->nbrp) {
                            continue;
                        }

                        if (!find_lrp_member_ip(peer, ip_s)) {
                            continue;
                        }

                        ds_clear(&match);
                        ds_put_format(&match, "outport == %s && xxreg0 == %s",
                                      peer->json_key, ip_s);

                        ds_clear(&actions);
                        ds_put_format(&actions, "eth.dst = %s; next;", ea_s);
                        ovn_lflow_add(lflows, peer->od,
                                      S_ROUTER_IN_ARP_RESOLVE, 100,
                                      ds_cstr(&match), ds_cstr(&actions));
                    }
                }
            }
        } else if (!strcmp(op->nbsp->type, "router")) {
            /* This is a logical switch port that connects to a router. */

            /* The peer of this switch port is the router port for which
             * we need to add logical flows such that it can resolve
             * ARP entries for all the other router ports connected to
             * the switch in question. */

            const char *peer_name = smap_get(&op->nbsp->options,
                                             "router-port");
            if (!peer_name) {
                continue;
            }

            struct ovn_port *peer = ovn_port_find(ports, peer_name);
            if (!peer || !peer->nbrp) {
                continue;
            }

            for (size_t i = 0; i < op->od->n_router_ports; i++) {
                const char *router_port_name = smap_get(
                                    &op->od->router_ports[i]->nbsp->options,
                                    "router-port");
                struct ovn_port *router_port = ovn_port_find(ports,
                                                             router_port_name);
                if (!router_port || !router_port->nbrp) {
                    continue;
                }

                /* Skip the router port under consideration. */
                if (router_port == peer) {
                   continue;
                }

                if (router_port->lrp_networks.n_ipv4_addrs) {
                    ds_clear(&match);
                    ds_put_format(&match, "outport == %s && reg0 == ",
                                  peer->json_key);
                    op_put_v4_networks(&match, router_port, false);

                    ds_clear(&actions);
                    ds_put_format(&actions, "eth.dst = %s; next;",
                                              router_port->lrp_networks.ea_s);
                    ovn_lflow_add(lflows, peer->od, S_ROUTER_IN_ARP_RESOLVE,
                                  100, ds_cstr(&match), ds_cstr(&actions));
                }

                if (router_port->lrp_networks.n_ipv6_addrs) {
                    ds_clear(&match);
                    ds_put_format(&match, "outport == %s && xxreg0 == ",
                                  peer->json_key);
                    op_put_v6_networks(&match, router_port);

                    ds_clear(&actions);
                    ds_put_format(&actions, "eth.dst = %s; next;",
                                  router_port->lrp_networks.ea_s);
                    ovn_lflow_add(lflows, peer->od, S_ROUTER_IN_ARP_RESOLVE,
                                  100, ds_cstr(&match), ds_cstr(&actions));
                }
            }
        }
    }

    ds_destroy(&match);
    ds_destroy(&actions);
}

/* Updates the Logical_Flow and Multicast_Group tables in the OVN_SB database,
 * constructing their contents based on the OVN_NB database. */
static void
build_lflows(struct northd_context *ctx, struct ftl *ftl,
             struct hmap *datapaths, struct hmap *ports)
{
    struct hmap lflows = HMAP_INITIALIZER(&lflows);
    struct hmap mcgroups = HMAP_INITIALIZER(&mcgroups);

    build_lswitch_flows(datapaths, ports, &lflows, &mcgroups);
    build_lrouter_flows(datapaths, ports, &lflows);
    ftl_run(ftl, ctx->ovnnb_idl, &lflows, datapaths);

    /* Push changes to the Logical_Flow table to database. */
    const struct sbrec_logical_flow *sbflow, *next_sbflow;
    SBREC_LOGICAL_FLOW_FOR_EACH_SAFE (sbflow, next_sbflow, ctx->ovnsb_idl) {
        struct ovn_datapath *od
            = (sbflow->logical_datapath
               ? ovn_datapath_from_sbrec(datapaths, sbflow->logical_datapath)
               : NULL);
        if (!od) {
            sbrec_logical_flow_delete(sbflow);
            continue;
        }

        enum ovn_datapath_type dp_type = od->nbs ? DP_SWITCH : DP_ROUTER;
        enum ovn_pipeline pipeline
            = !strcmp(sbflow->pipeline, "ingress") ? P_IN : P_OUT;
        struct ovn_lflow *lflow = ovn_lflow_find(
            &lflows, od, ovn_stage_build(dp_type, pipeline, sbflow->table_id),
            sbflow->priority, sbflow->match, sbflow->actions);
        if (lflow) {
            ovn_lflow_destroy(&lflows, lflow);
        } else {
            sbrec_logical_flow_delete(sbflow);
        }
    }
    struct ovn_lflow *lflow, *next_lflow;
    HMAP_FOR_EACH_SAFE (lflow, next_lflow, hmap_node, &lflows) {
        enum ovn_pipeline pipeline = ovn_stage_get_pipeline(lflow->stage);
        uint8_t table = ovn_stage_get_table(lflow->stage);

        sbflow = sbrec_logical_flow_insert(ctx->ovnsb_txn);
        sbrec_logical_flow_set_logical_datapath(sbflow, lflow->od->sb);
        sbrec_logical_flow_set_pipeline(
            sbflow, pipeline == P_IN ? "ingress" : "egress");
        sbrec_logical_flow_set_table_id(sbflow, table);
        sbrec_logical_flow_set_priority(sbflow, lflow->priority);
        sbrec_logical_flow_set_match(sbflow, lflow->match);
        sbrec_logical_flow_set_actions(sbflow, lflow->actions);

        /* Trim the source locator lflow->where, which looks something like
         * "ovn/northd/ovn-northd.c:1234", down to just the part following the
         * last slash, e.g. "ovn-northd.c:1234". */
        const char *slash = strrchr(lflow->where, '/');
#if _WIN32
        const char *backslash = strrchr(lflow->where, '\\');
        if (!slash || backslash > slash) {
            slash = backslash;
        }
#endif
        const char *where = slash ? slash + 1 : lflow->where;

        const struct smap ids = SMAP_CONST2(
            &ids,
            "stage-name", ovn_stage_to_str(lflow->stage),
            "source", where);
        sbrec_logical_flow_set_external_ids(sbflow, &ids);

        ovn_lflow_destroy(&lflows, lflow);
    }
    hmap_destroy(&lflows);

    /* Push changes to the Multicast_Group table to database. */
    const struct sbrec_multicast_group *sbmc, *next_sbmc;
    SBREC_MULTICAST_GROUP_FOR_EACH_SAFE (sbmc, next_sbmc, ctx->ovnsb_idl) {
        struct ovn_datapath *od = (sbmc->datapath
                                   ? ovn_datapath_from_sbrec(datapaths,
                                                             sbmc->datapath)
                                   : NULL);
        if (!od) {
            sbrec_multicast_group_delete(sbmc);
            continue;
        }

        struct multicast_group group = { .name = sbmc->name,
                                         .key = sbmc->tunnel_key };
        struct ovn_multicast *mc = ovn_multicast_find(&mcgroups, od, &group);
        if (mc) {
            ovn_multicast_update_sbrec(mc, sbmc);
            ovn_multicast_destroy(&mcgroups, mc);
        } else {
            sbrec_multicast_group_delete(sbmc);
        }
    }
    struct ovn_multicast *mc, *next_mc;
    HMAP_FOR_EACH_SAFE (mc, next_mc, hmap_node, &mcgroups) {
        sbmc = sbrec_multicast_group_insert(ctx->ovnsb_txn);
        sbrec_multicast_group_set_datapath(sbmc, mc->datapath->sb);
        sbrec_multicast_group_set_name(sbmc, mc->group->name);
        sbrec_multicast_group_set_tunnel_key(sbmc, mc->group->key);
        ovn_multicast_update_sbrec(mc, sbmc);
        ovn_multicast_destroy(&mcgroups, mc);
    }
    hmap_destroy(&mcgroups);
}

/* OVN_Northbound and OVN_Southbound have an identical Address_Set table.
 * We always update OVN_Southbound to match the current data in
 * OVN_Northbound, so that the address sets used in Logical_Flows in
 * OVN_Southbound is checked against the proper set.*/
static void
sync_address_sets(struct northd_context *ctx)
{
    struct shash sb_address_sets = SHASH_INITIALIZER(&sb_address_sets);

    const struct sbrec_address_set *sb_address_set;
    SBREC_ADDRESS_SET_FOR_EACH (sb_address_set, ctx->ovnsb_idl) {
        shash_add(&sb_address_sets, sb_address_set->name, sb_address_set);
    }

    const struct nbrec_address_set *nb_address_set;
    NBREC_ADDRESS_SET_FOR_EACH (nb_address_set, ctx->ovnnb_idl) {
        sb_address_set = shash_find_and_delete(&sb_address_sets,
                                               nb_address_set->name);
        if (!sb_address_set) {
            sb_address_set = sbrec_address_set_insert(ctx->ovnsb_txn);
            sbrec_address_set_set_name(sb_address_set, nb_address_set->name);
        }

        sbrec_address_set_set_addresses(sb_address_set,
                /* "char **" is not compatible with "const char **" */
                (const char **) nb_address_set->addresses,
                nb_address_set->n_addresses);
    }

    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE (node, next, &sb_address_sets) {
        sbrec_address_set_delete(node->data);
        shash_delete(&sb_address_sets, node);
    }
    shash_destroy(&sb_address_sets);
}

static void
ovnnb_db_run(struct northd_context *ctx, struct ftl *ftl,
             struct ovsdb_idl_loop *sb_loop)
{
    if (!ctx->ovnsb_txn || !ctx->ovnnb_txn) {
        return;
    }
    struct hmap datapaths, ports;
    build_datapaths(ctx, &datapaths);
    build_ports(ctx, &datapaths, &ports);
    build_ipam(&datapaths, &ports);
    build_lflows(ctx, ftl, &datapaths, &ports);

    sync_address_sets(ctx);

    struct ovn_datapath *dp, *next_dp;
    HMAP_FOR_EACH_SAFE (dp, next_dp, key_node, &datapaths) {
        ovn_datapath_destroy(&datapaths, dp);
    }
    hmap_destroy(&datapaths);

    struct ovn_port *port, *next_port;
    HMAP_FOR_EACH_SAFE (port, next_port, key_node, &ports) {
        ovn_port_destroy(&ports, port);
    }
    hmap_destroy(&ports);

    /* Copy nb_cfg from northbound to southbound database.
     *
     * Also set up to update sb_cfg once our southbound transaction commits. */
    const struct nbrec_nb_global *nb = nbrec_nb_global_first(ctx->ovnnb_idl);
    if (!nb) {
        nb = nbrec_nb_global_insert(ctx->ovnnb_txn);
    }
    const struct sbrec_sb_global *sb = sbrec_sb_global_first(ctx->ovnsb_idl);
    if (!sb) {
        sb = sbrec_sb_global_insert(ctx->ovnsb_txn);
    }
    sbrec_sb_global_set_nb_cfg(sb, nb->nb_cfg);
    sb_loop->next_cfg = nb->nb_cfg;

    cleanup_macam(&macam);
}

/* Handle changes to the 'chassis' column of the 'Port_Binding' table.  When
 * this column is not empty, it means we need to set the corresponding logical
 * port as 'up' in the northbound DB. */
static void
update_logical_port_status(struct northd_context *ctx)
{
    struct hmap lports_hmap;
    const struct sbrec_port_binding *sb;
    const struct nbrec_logical_switch_port *nbsp;

    struct lport_hash_node {
        struct hmap_node node;
        const struct nbrec_logical_switch_port *nbsp;
    } *hash_node;

    hmap_init(&lports_hmap);

    NBREC_LOGICAL_SWITCH_PORT_FOR_EACH(nbsp, ctx->ovnnb_idl) {
        hash_node = xzalloc(sizeof *hash_node);
        hash_node->nbsp = nbsp;
        hmap_insert(&lports_hmap, &hash_node->node, hash_string(nbsp->name, 0));
    }

    SBREC_PORT_BINDING_FOR_EACH(sb, ctx->ovnsb_idl) {
        nbsp = NULL;
        HMAP_FOR_EACH_WITH_HASH(hash_node, node,
                                hash_string(sb->logical_port, 0),
                                &lports_hmap) {
            if (!strcmp(sb->logical_port, hash_node->nbsp->name)) {
                nbsp = hash_node->nbsp;
                break;
            }
        }

        if (!nbsp) {
            /* The logical port doesn't exist for this port binding.  This can
             * happen under normal circumstances when ovn-northd hasn't gotten
             * around to pruning the Port_Binding yet. */
            continue;
        }

        if (sb->chassis && (!nbsp->up || !*nbsp->up)) {
            bool up = true;
            nbrec_logical_switch_port_set_up(nbsp, &up, 1);
        } else if (!sb->chassis && (!nbsp->up || *nbsp->up)) {
            bool up = false;
            nbrec_logical_switch_port_set_up(nbsp, &up, 1);
        }
    }

    HMAP_FOR_EACH_POP(hash_node, node, &lports_hmap) {
        free(hash_node);
    }
    hmap_destroy(&lports_hmap);
}

static struct dhcp_opts_map supported_dhcp_opts[] = {
    OFFERIP,
    DHCP_OPT_NETMASK,
    DHCP_OPT_ROUTER,
    DHCP_OPT_DNS_SERVER,
    DHCP_OPT_LOG_SERVER,
    DHCP_OPT_LPR_SERVER,
    DHCP_OPT_SWAP_SERVER,
    DHCP_OPT_POLICY_FILTER,
    DHCP_OPT_ROUTER_SOLICITATION,
    DHCP_OPT_NIS_SERVER,
    DHCP_OPT_NTP_SERVER,
    DHCP_OPT_SERVER_ID,
    DHCP_OPT_TFTP_SERVER,
    DHCP_OPT_CLASSLESS_STATIC_ROUTE,
    DHCP_OPT_MS_CLASSLESS_STATIC_ROUTE,
    DHCP_OPT_IP_FORWARD_ENABLE,
    DHCP_OPT_ROUTER_DISCOVERY,
    DHCP_OPT_ETHERNET_ENCAP,
    DHCP_OPT_DEFAULT_TTL,
    DHCP_OPT_TCP_TTL,
    DHCP_OPT_MTU,
    DHCP_OPT_LEASE_TIME,
    DHCP_OPT_T1,
    DHCP_OPT_T2
};

static struct dhcp_opts_map supported_dhcpv6_opts[] = {
    DHCPV6_OPT_IA_ADDR,
    DHCPV6_OPT_SERVER_ID,
    DHCPV6_OPT_DOMAIN_SEARCH,
    DHCPV6_OPT_DNS_SERVER
};

static void
check_and_add_supported_dhcp_opts_to_sb_db(struct northd_context *ctx)
{
    struct hmap dhcp_opts_to_add = HMAP_INITIALIZER(&dhcp_opts_to_add);
    for (size_t i = 0; (i < sizeof(supported_dhcp_opts) /
                            sizeof(supported_dhcp_opts[0])); i++) {
        hmap_insert(&dhcp_opts_to_add, &supported_dhcp_opts[i].hmap_node,
                    dhcp_opt_hash(supported_dhcp_opts[i].name));
    }

    const struct sbrec_dhcp_options *opt_row, *opt_row_next;
    SBREC_DHCP_OPTIONS_FOR_EACH_SAFE(opt_row, opt_row_next, ctx->ovnsb_idl) {
        struct dhcp_opts_map *dhcp_opt =
            dhcp_opts_find(&dhcp_opts_to_add, opt_row->name);
        if (dhcp_opt) {
            hmap_remove(&dhcp_opts_to_add, &dhcp_opt->hmap_node);
        } else {
            sbrec_dhcp_options_delete(opt_row);
        }
    }

    struct dhcp_opts_map *opt;
    HMAP_FOR_EACH (opt, hmap_node, &dhcp_opts_to_add) {
        struct sbrec_dhcp_options *sbrec_dhcp_option =
            sbrec_dhcp_options_insert(ctx->ovnsb_txn);
        sbrec_dhcp_options_set_name(sbrec_dhcp_option, opt->name);
        sbrec_dhcp_options_set_code(sbrec_dhcp_option, opt->code);
        sbrec_dhcp_options_set_type(sbrec_dhcp_option, opt->type);
    }

    hmap_destroy(&dhcp_opts_to_add);
}

static void
check_and_add_supported_dhcpv6_opts_to_sb_db(struct northd_context *ctx)
{
    struct hmap dhcpv6_opts_to_add = HMAP_INITIALIZER(&dhcpv6_opts_to_add);
    for (size_t i = 0; (i < sizeof(supported_dhcpv6_opts) /
                            sizeof(supported_dhcpv6_opts[0])); i++) {
        hmap_insert(&dhcpv6_opts_to_add, &supported_dhcpv6_opts[i].hmap_node,
                    dhcp_opt_hash(supported_dhcpv6_opts[i].name));
    }

    const struct sbrec_dhcpv6_options *opt_row, *opt_row_next;
    SBREC_DHCPV6_OPTIONS_FOR_EACH_SAFE(opt_row, opt_row_next, ctx->ovnsb_idl) {
        struct dhcp_opts_map *dhcp_opt =
            dhcp_opts_find(&dhcpv6_opts_to_add, opt_row->name);
        if (dhcp_opt) {
            hmap_remove(&dhcpv6_opts_to_add, &dhcp_opt->hmap_node);
        } else {
            sbrec_dhcpv6_options_delete(opt_row);
        }
    }

    struct dhcp_opts_map *opt;
    HMAP_FOR_EACH(opt, hmap_node, &dhcpv6_opts_to_add) {
        struct sbrec_dhcpv6_options *sbrec_dhcpv6_option =
            sbrec_dhcpv6_options_insert(ctx->ovnsb_txn);
        sbrec_dhcpv6_options_set_name(sbrec_dhcpv6_option, opt->name);
        sbrec_dhcpv6_options_set_code(sbrec_dhcpv6_option, opt->code);
        sbrec_dhcpv6_options_set_type(sbrec_dhcpv6_option, opt->type);
    }

    hmap_destroy(&dhcpv6_opts_to_add);
}

/* Updates the sb_cfg and hv_cfg columns in the northbound NB_Global table. */
static void
update_northbound_cfg(struct northd_context *ctx,
                      struct ovsdb_idl_loop *sb_loop)
{
    /* Update northbound sb_cfg if appropriate. */
    const struct nbrec_nb_global *nbg = nbrec_nb_global_first(ctx->ovnnb_idl);
    int64_t sb_cfg = sb_loop->cur_cfg;
    if (nbg && sb_cfg && nbg->sb_cfg != sb_cfg) {
        nbrec_nb_global_set_sb_cfg(nbg, sb_cfg);
    }

    /* Update northbound hv_cfg if appropriate. */
    if (nbg) {
        /* Find minimum nb_cfg among all chassis. */
        const struct sbrec_chassis *chassis;
        int64_t hv_cfg = nbg->nb_cfg;
        SBREC_CHASSIS_FOR_EACH (chassis, ctx->ovnsb_idl) {
            if (chassis->nb_cfg < hv_cfg) {
                hv_cfg = chassis->nb_cfg;
            }
        }

        /* Update hv_cfg. */
        if (nbg->hv_cfg != hv_cfg) {
            nbrec_nb_global_set_hv_cfg(nbg, hv_cfg);
        }
    }
}

/* Handle a fairly small set of changes in the southbound database. */
static void
ovnsb_db_run(struct northd_context *ctx, struct ovsdb_idl_loop *sb_loop)
{
    if (!ctx->ovnnb_txn || !ovsdb_idl_has_ever_connected(ctx->ovnsb_idl)) {
        return;
    }

    update_logical_port_status(ctx);
    update_northbound_cfg(ctx, sb_loop);
}

static void
parse_options(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum {
        OPT_CLEAR_INCLUDES,
        OPT_CHECK_SYNTAX,
        DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"include", required_argument, NULL, 'I'},
        {"clear-includes", no_argument, NULL, OPT_CLEAR_INCLUDES},
        {"check-syntax", no_argument, NULL, OPT_CHECK_SYNTAX},
        {"ovnsb-db", required_argument, NULL, 'd'},
        {"ovnnb-db", required_argument, NULL, 'D'},
        {"help", no_argument, NULL, 'h'},
        {"options", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    ds_init(&include_path);
    ds_put_cstr(&include_path, ovs_pkgdatadir());
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        DAEMON_OPTION_HANDLERS;
        VLOG_OPTION_HANDLERS;
        STREAM_SSL_OPTION_HANDLERS;

        case 'I':
            if (include_path.length) {
                ds_put_cstr(&include_path, PATH_SEPARATOR);
            }
            ds_put_cstr(&include_path, optarg);
            break;

        case OPT_CLEAR_INCLUDES:
            ds_clear(&include_path);
            break;

        case OPT_CHECK_SYNTAX:
            check_syntax = true;
            break;

        case 'd':
            ovnsb_db = optarg;
            break;

        case 'D':
            ovnnb_db = optarg;
            break;

        case 'h':
            usage();
            exit(EXIT_SUCCESS);

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        default:
            break;
        }
    }

    if (!ovnsb_db) {
        ovnsb_db = default_sb_db();
    }

    if (!ovnnb_db) {
        ovnnb_db = default_nb_db();
    }

    free(short_options);

    if (optind != argc) {
        ovs_fatal(0, "non-option arguments not supported "
                  "(use --help for help)");
    }
}

static void
add_column_noalert(struct ovsdb_idl *idl,
                   const struct ovsdb_idl_column *column)
{
    ovsdb_idl_add_column(idl, column);
    ovsdb_idl_omit_alert(idl, column);
}

int
main(int argc, char *argv[])
{
    int res = EXIT_SUCCESS;
    struct unixctl_server *unixctl;
    int retval;
    bool exiting;

    fatal_ignore_sigpipe();
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);

    daemonize_start(false);

    if (!check_syntax) {
        retval = unixctl_server_create(NULL, &unixctl);
        if (retval) {
            exit(EXIT_FAILURE);
        }
    }
    unixctl_command_register("exit", "", 0, 0, ovn_northd_exit, &exiting);

    daemonize_complete();

    /* We want to detect (almost) all changes to the ovn-nb db. */
    struct ovsdb_idl_loop ovnnb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnnb_db, &nbrec_idl_class, true, true));
    ovsdb_idl_omit_alert(ovnnb_idl_loop.idl, &nbrec_nb_global_col_sb_cfg);
    ovsdb_idl_omit_alert(ovnnb_idl_loop.idl, &nbrec_nb_global_col_hv_cfg);

    struct ftl *ftl;
    char *error = ftl_read("ovn.ftl", ds_cstr(&include_path),
                           ovnnb_idl_loop.idl, &ftl);
    if (check_syntax) {
        if (error) {
            ovs_fatal(0, "%s", error);
        } else{
            exit(0);
        }
    }
    if (error) {
        VLOG_FATAL("%s", error);
    }

    /* We want to detect only selected changes to the ovn-sb db. */
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnsb_db, &sbrec_idl_class, false, true));

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_sb_global);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_sb_global_col_nb_cfg);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_logical_flow);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_logical_flow_col_logical_datapath);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_logical_flow_col_pipeline);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_logical_flow_col_table_id);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_logical_flow_col_priority);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_logical_flow_col_match);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_logical_flow_col_actions);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_multicast_group);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_multicast_group_col_datapath);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_multicast_group_col_tunnel_key);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_multicast_group_col_name);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_multicast_group_col_ports);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_datapath_binding);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_datapath_binding_col_tunnel_key);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_datapath_binding_col_external_ids);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_port_binding);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_port_binding_col_datapath);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_port_binding_col_logical_port);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_port_binding_col_tunnel_key);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_port_binding_col_parent_port);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_port_binding_col_tag);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_port_binding_col_type);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_port_binding_col_options);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_port_binding_col_mac);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_port_binding_col_chassis);
    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_mac_binding);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_mac_binding_col_datapath);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_mac_binding_col_ip);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_mac_binding_col_mac);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_mac_binding_col_logical_port);
    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_dhcp_options);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dhcp_options_col_code);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dhcp_options_col_type);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dhcp_options_col_name);
    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_dhcpv6_options);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dhcpv6_options_col_code);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dhcpv6_options_col_type);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dhcpv6_options_col_name);
    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_address_set);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_address_set_col_name);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_address_set_col_addresses);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_chassis);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_chassis_col_nb_cfg);

    /* Main loop. */
    exiting = false;
    while (!exiting) {
        struct northd_context ctx = {
            .ovnnb_idl = ovnnb_idl_loop.idl,
            .ovnnb_txn = ovsdb_idl_loop_run(&ovnnb_idl_loop),
            .ovnsb_idl = ovnsb_idl_loop.idl,
            .ovnsb_txn = ovsdb_idl_loop_run(&ovnsb_idl_loop),
        };

        ovnnb_db_run(&ctx, ftl, &ovnsb_idl_loop);
        ovnsb_db_run(&ctx, &ovnsb_idl_loop);
        if (ctx.ovnsb_txn) {
            check_and_add_supported_dhcp_opts_to_sb_db(&ctx);
            check_and_add_supported_dhcpv6_opts_to_sb_db(&ctx);
        }

        unixctl_server_run(unixctl);
        unixctl_server_wait(unixctl);
        if (exiting) {
            poll_immediate_wake();
        }
        ovsdb_idl_loop_commit_and_wait(&ovnnb_idl_loop);
        ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);

        poll_block();
        if (should_service_stop()) {
            exiting = true;
        }
    }

    unixctl_server_destroy(unixctl);
    ovsdb_idl_loop_destroy(&ovnnb_idl_loop);
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);
    service_stop();

    exit(res);
}

static void
ovn_northd_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;

    unixctl_command_reply(conn, NULL);
}
