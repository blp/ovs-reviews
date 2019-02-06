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

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "bitmap.h"
#include "command-line.h"
#include "daemon.h"
#include "dirs.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "ovn/lex.h"
#include "ovn/lib/chassis-index.h"
#include "ovn/lib/logical-fields.h"
#include "ovn/lib/ovn-l7.h"
#include "ovn/lib/ovn-nb-idl.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn/lib/ovn-util.h"
#include "ovn/actions.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "smap.h"
#include "sset.h"
#include "svec.h"
#include "stream.h"
#include "stream-ssl.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"
#include "openvswitch/vlog.h"

#include "ovn/northd/ovn_northd_ddlog/ddlog.h"


VLOG_DEFINE_THIS_MODULE(ovn_northd);

static unixctl_cb_func ovn_northd_exit;

struct northd_context {
    struct ovsdb_idl *ovnnb_idl;
    struct ovsdb_idl *ovnsb_idl;
    struct ovsdb_idl_txn *ovnnb_txn;
    struct ovsdb_idl_txn *ovnsb_txn;
};

static const char *ovnnb_db;
static const char *ovnsb_db;
static const char *unixctl_path;


static void
ddlog_table_update(ddlog_prog ddlog, const char *table)
{
    int error;
    char *json;
    char *ddlog_table;

    ddlog_table = xasprintf("OVN_Southbound.DeltaPlus_%s", table);
    error = ddlog_dump_ovsdb_deltaplus_table(ddlog,
                                             ddlog_get_table_id(ddlog_table),
                                             &json);
    if (error) {
        VLOG_WARN("xxx delta-plus (%s) error: %d", ddlog_table, error);
        return;
    }
    VLOG_WARN("xxx delta-plus (%s): %s", ddlog_table, json);
    ddlog_free_json(json);
    free(ddlog_table);

    ddlog_table = xasprintf("OVN_Southbound.DeltaMinus_%s", table);
    error = ddlog_dump_ovsdb_deltaminus_table(ddlog,
                                              ddlog_get_table_id(ddlog_table),
                                              &json);
    if (error) {
        VLOG_WARN("xxx delta-minus (%s) error: %d", ddlog_table, error);
        return;
    }
    VLOG_WARN("xxx delta-minus (%s): %s", ddlog_table, json);
    ddlog_free_json(json);
    free(ddlog_table);

#if 0
    ddlog_table = xasprintf("OVN_Southbound.DeltaUpdate_%s", table);
    error = ddlog_dump_ovsdb_deltaupdate_table(ddlog, ddlog_table, &json);
    if (error) {
        VLOG_WARN("xxx delta-update (%s) error: %d", ddlog_table, error);
        return;
    }
    VLOG_WARN("xxx delta-update (%s): %s", ddlog_table, json);
    ddlog_free_json(json);
    free(ddlog_table);
#endif
}

static void
ovn_northd_ddlog_run(struct northd_context *ctx, ddlog_prog ddlog)
{
    struct svec updates = SVEC_EMPTY_INITIALIZER;
    ovsdb_idl_get_updates(ctx->ovnnb_idl, &updates);

    if (svec_is_empty(&updates)) {
        return;
    }

    if (ddlog_transaction_start(ddlog)) {
        VLOG_ERR("xxx Couldn't start transaction");
        return;
    }

    size_t i;
    const char *update;
    SVEC_FOR_EACH (i, update, &updates) {
        VLOG_WARN("xxx update: %s", update);
        if (ddlog_apply_ovsdb_updates(ddlog, "OVN_Northbound.", update)) {
            VLOG_ERR("xxx Couldn't add update");
            goto error;
        }
    }
    svec_destroy(&updates);

    if (ddlog_transaction_commit(ddlog)) {
        VLOG_ERR("xxx Couldn't commit transaction");
        goto error;
    }

    ddlog_table_update(ddlog, "SB_Global");
    ddlog_table_update(ddlog, "Datapath_Binding");
    ddlog_table_update(ddlog, "Port_Binding");
    ddlog_table_update(ddlog, "Logical_Flow");
    ddlog_table_update(ddlog, "Meter");
    ddlog_table_update(ddlog, "Meter_Band");

    return;

error:
    ddlog_transaction_rollback(ddlog);
}

/* Callback used by the ddlog engine to print error messages.  Note that this is
 * only used by the ddlog runtime, as opposed to the application code in
 * ovn_northd.dl, which uses the vlog facility directly.  */
static void
ddlog_print_error(const char *msg)
{
    VLOG_ERR("%s", msg);
}

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
  --unixctl=SOCKET          override default control socket name\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_nb_db(), default_sb_db());
    daemon_usage();
    vlog_usage();
    stream_usage("database", true, true, false);
}

static void
parse_options(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum {
        DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"ovnsb-db", required_argument, NULL, 'd'},
        {"ovnnb-db", required_argument, NULL, 'D'},
        {"unixctl", required_argument, NULL, 'u'},
        {"help", no_argument, NULL, 'h'},
        {"options", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

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

        case 'd':
            ovnsb_db = optarg;
            break;

        case 'D':
            ovnnb_db = optarg;
            break;

        case 'u':
            unixctl_path = optarg;
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
    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);

    daemonize_start(false);

    retval = unixctl_server_create(unixctl_path, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovn_northd_exit, &exiting);

    daemonize_complete();

    /* We want to detect (almost) all changes to the ovn-nb db. */
    struct ovsdb_idl_loop ovnnb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnnb_db, &nbrec_idl_class, true, true));
    ovsdb_idl_omit_alert(ovnnb_idl_loop.idl, &nbrec_nb_global_col_sb_cfg);
    ovsdb_idl_omit_alert(ovnnb_idl_loop.idl, &nbrec_nb_global_col_hv_cfg);

    /* We want to detect only selected changes to the ovn-sb db. */
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnsb_db, &sbrec_idl_class, false, true));

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_sb_global);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_sb_global_col_nb_cfg);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_sb_global_col_options);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_sb_global_col_ipsec);

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
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_port_binding_col_nat_addresses);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_port_binding_col_chassis);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_port_binding_col_gateway_chassis);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_gateway_chassis_col_chassis);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_gateway_chassis_col_name);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_gateway_chassis_col_priority);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_gateway_chassis_col_external_ids);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl,
                         &sbrec_gateway_chassis_col_options);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_port_binding_col_external_ids);
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
    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_port_group);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_port_group_col_name);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_port_group_col_ports);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_dns);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dns_col_datapaths);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dns_col_records);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_dns_col_external_ids);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_rbac_role);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_rbac_role_col_name);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_rbac_role_col_permissions);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_rbac_permission);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_rbac_permission_col_table);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_rbac_permission_col_authorization);
    add_column_noalert(ovnsb_idl_loop.idl,
                       &sbrec_rbac_permission_col_insert_delete);
    add_column_noalert(ovnsb_idl_loop.idl, &sbrec_rbac_permission_col_update);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_meter);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_meter_col_name);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_meter_col_unit);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_meter_col_bands);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_meter_band);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_meter_band_col_action);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_meter_band_col_rate);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_meter_band_col_burst_size);

    ovsdb_idl_add_table(ovnsb_idl_loop.idl, &sbrec_table_chassis);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_chassis_col_nb_cfg);
    ovsdb_idl_add_column(ovnsb_idl_loop.idl, &sbrec_chassis_col_name);

    /* Ensure that only a single ovn-northd is active in the deployment by
     * acquiring a lock called "ovn_northd" on the southbound database
     * and then only performing DB transactions if the lock is held. */
    ovsdb_idl_set_lock(ovnsb_idl_loop.idl, "ovn_northd");
    bool had_lock = false;

    ddlog_prog ddlog;
    ddlog = ddlog_run(1, true, NULL, 0, ddlog_print_error);
    if (!ddlog) {
        VLOG_EMER("xxx Couldn't create ddlog instance");
    }

    /* Main loop. */
    exiting = false;
    while (!exiting) {
        struct northd_context ctx = {
            .ovnnb_idl = ovnnb_idl_loop.idl,
            .ovnnb_txn = ovsdb_idl_loop_run(&ovnnb_idl_loop),
            .ovnsb_idl = ovnsb_idl_loop.idl,
            .ovnsb_txn = ovsdb_idl_loop_run(&ovnsb_idl_loop),
        };

        if (!had_lock && ovsdb_idl_has_lock(ovnsb_idl_loop.idl)) {
            VLOG_INFO("ovn-northd lock acquired. "
                      "This ovn-northd instance is now active.");
            had_lock = true;
        } else if (had_lock && !ovsdb_idl_has_lock(ovnsb_idl_loop.idl)) {
            VLOG_INFO("ovn-northd lock lost. "
                      "This ovn-northd instance is now on standby.");
            had_lock = false;
        }

        if (ovsdb_idl_has_lock(ovnsb_idl_loop.idl)) {
            ovn_northd_ddlog_run(&ctx, ddlog);
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

    ddlog_stop(ddlog);

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
