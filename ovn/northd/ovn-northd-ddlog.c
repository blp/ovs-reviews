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
#include "jsonrpc.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "ovn/lex.h"
#include "ovn/lib/chassis-index.h"
#include "ovn/lib/logical-fields.h"
#include "ovn/lib/ovn-l7.h"
#include "ovn/lib/ovn-util.h"
#include "ovn/actions.h"
#include "openvswitch/poll-loop.h"
#include "ovsdb-error.h"
#include "ovsdb/ovsdb.h"
#include "ovsdb/table.h"
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
    struct ovsdb_idl *ovnsb_idl;
    struct ovsdb_idl_txn *ovnsb_txn;
};

static const char *ovnnb_db;
static const char *ovnsb_db;
static const char *unixctl_path;


static void
ddlog_table_update(struct ds *ds, ddlog_prog ddlog, const char *table)
{
    int error;
    char *updates;

    error = ddlog_dump_ovsdb_delta(ddlog, "OVN_Southbound", table, &updates);
    if (error) {
        VLOG_WARN("xxx delta (%s) error: %d", table, error);
        return;
    }

    if (!strlen(updates)) {
        ddlog_free_json(updates);
        return;
    }

    ds_put_cstr(ds, updates);
    ds_put_char(ds, ',');
    ddlog_free_json(updates);
}


static struct json *
nb_ddlog_run(ddlog_prog ddlog, struct json *updates)
{
    if (!updates) {
        return NULL;
    }

    if (ddlog_transaction_start(ddlog)) {
        VLOG_ERR("xxx Couldn't start transaction");
        return NULL;
    }

    char *updates_s = json_to_string(updates, 0);
    VLOG_WARN("xxx update: %s", updates_s);
    if (ddlog_apply_ovsdb_updates(ddlog, "OVN_Northbound.", updates_s)) {
        VLOG_ERR("xxx Couldn't add update");
        free(updates_s);
        goto error;
    }
    free(updates_s);

    if (ddlog_transaction_commit(ddlog)) {
        VLOG_ERR("xxx Couldn't commit transaction");
        goto error;
    }

    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_cstr(&ds, "[\"OVN_Southbound\",");

    //ddlog_table_update(&ds, ddlog, "SB_Global");
    ddlog_table_update(&ds, ddlog, "Datapath_Binding");
    ddlog_table_update(&ds, ddlog, "Port_Binding");
    ddlog_table_update(&ds, ddlog, "Logical_Flow");
    ddlog_table_update(&ds, ddlog, "Meter");
    ddlog_table_update(&ds, ddlog, "Meter_Band");

    ds_chomp(&ds, ',');
    ds_put_cstr(&ds, "]");

    /* xxx Return null if there were no updates. */

    VLOG_WARN("xxx pre-ops: %s", ds_cstr(&ds));
    struct json *ops = json_from_string(ds_steal_cstr(&ds));
    VLOG_WARN("xxx postops: %s", json_to_string(ops, 0));

    return ops;

error:
    ddlog_transaction_rollback(ddlog);
    return NULL;
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

static struct jsonrpc *
open_jsonrpc(const char *server)
{
    struct stream *stream;
    int error;

    error = stream_open_block(jsonrpc_stream_open(server, &stream,
                              DSCP_DEFAULT), -1, &stream);
    if (error == EAFNOSUPPORT) {
        struct pstream *pstream;

        error = jsonrpc_pstream_open(server, &pstream, DSCP_DEFAULT);
        if (error) {
            ovs_fatal(error, "failed to connect or listen to \"%s\"", server);
        }

        VLOG_INFO("%s: waiting for connection...", server);
        error = pstream_accept_block(pstream, &stream);
        if (error) {
            ovs_fatal(error, "failed to accept connection on \"%s\"", server);
        }

        pstream_close(pstream);
    } else if (error) {
        ovs_fatal(error, "failed to connect to \"%s\"", server);
    }

    return jsonrpc_open(stream);
}

static void
check_txn(int error, struct jsonrpc_msg **reply_)
{
    struct jsonrpc_msg *reply = *reply_;

    if (error) {
        VLOG_WARN("xxx transaction failed");
    }

    if (reply->error) {
        VLOG_WARN("xxx transaction returned error: %s",
                  json_to_string(reply->error, 0));
    }
}

/* xxx Stolen from ovsdb-client.  See if it should be refactored. */
static void
check_ovsdb_error(struct ovsdb_error *error)
{
    if (error) {
        ovs_fatal(0, "%s", ovsdb_error_to_string(error));
    }
}

static struct ovsdb_schema *
fetch_schema(struct jsonrpc *rpc, const char *database)
{
    struct jsonrpc_msg *request, *reply;
    struct ovsdb_schema *schema;

    request = jsonrpc_create_request("get_schema",
                                     json_array_create_1(
                                         json_string_create(database)),
                                     NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    check_ovsdb_error(ovsdb_schema_from_json(reply->result, &schema));
    jsonrpc_msg_destroy(reply);

    return schema;
}

static struct jsonrpc *
open_rpc(const char *db_name, const char *database, struct json **request_id) {
    struct jsonrpc *rpc = open_jsonrpc(db_name);

    struct ovsdb_schema *schema = fetch_schema(rpc, database);
    struct json *monitor_requests = json_object_create();

    /* xxx This should be smarter about ignoring not needed ones */
    size_t n = shash_count(&schema->tables);
    const struct shash_node **nodes = shash_sort(&schema->tables);

    for (int i = 0; i < n; i++) {
        struct json *monitor_request_array = json_array_create_empty();
        json_array_add(monitor_request_array, json_object_create());

        struct ovsdb_table_schema *table = nodes[i]->data;
        json_object_put(monitor_requests, table->name, monitor_request_array);
    }
    free(nodes);

    /* xxx Should ovs_fatal be used? */
    /* xxx Should set "db_change_aware" and handle the implications. */

    struct json *monitor = json_array_create_3(json_string_create(database),
                                               json_string_create(database),
                                               monitor_requests);

    struct jsonrpc_msg *request;
    request = jsonrpc_create_request("monitor", monitor, NULL);
    *request_id = json_clone(request->id);
    jsonrpc_send(rpc, request);

    return rpc;
}

static struct json *
do_transact(struct jsonrpc *rpc, struct json *transaction)
{
    struct jsonrpc_msg *request, *reply;

    /* xxx Make db_change aware */
#if 0
    if (db_change_aware == 1) {
        send_db_change_aware(rpc);
    }
#endif

    request = jsonrpc_create_request("transact", transaction, NULL);
    check_txn(jsonrpc_transact_block(rpc, request, &reply), &reply);
    struct json *result = json_clone(reply->result);
    jsonrpc_msg_destroy(reply);
    VLOG_WARN("xxx transact: %s", json_to_string(result, 0));

    return result;
}

static struct json *
handle_monitor(struct jsonrpc *rpc, struct json *request_id)
{
    struct jsonrpc_msg *msg;
    int error;
    struct json *updates = NULL;

    error = jsonrpc_recv(rpc, &msg);
    if (error == EAGAIN) {
        return NULL;
    } else if (error) {
        /* xxx Shouldn't be fatal */
        ovs_fatal(error, "receive failed");
    }

    if (msg->type == JSONRPC_REQUEST && !strcmp(msg->method, "echo")) {
        jsonrpc_send(rpc, jsonrpc_create_reply(json_clone(msg->params),
                                               msg->id));
    } else if (msg->type == JSONRPC_REPLY
               && json_equal(msg->id, request_id)) {
        updates = json_clone(msg->result);
    } else if (msg->type == JSONRPC_NOTIFY
               && !strcmp(msg->method, "update")) {
        struct json *params = msg->params;
        if (params->type == JSON_ARRAY
            && params->array.n == 2
            && params->array.elems[0]->type == JSON_STRING) {
            updates = json_clone(params->array.elems[1]);
        }
    } else if (msg->type == JSONRPC_NOTIFY
               && !strcmp(msg->method, "monitor_canceled")) {
        /* xxx Not the correct behavior. */
        VLOG_WARN("xxx database was removed");
    } else {
        /* xxx Not the correct behavior. */
        VLOG_WARN("bad response: type:%d, error:%s", msg->type,
                  json_to_string(msg->error,0));
    }

    jsonrpc_msg_destroy(msg);
    return updates;
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

    struct json *nb_id;
    struct jsonrpc *nb_rpc = open_rpc(ovnnb_db, "OVN_Northbound", &nb_id);

    struct json *sb_id;
    struct jsonrpc *sb_rpc = open_rpc(ovnsb_db, "OVN_Southbound", &sb_id);

#if 0
    /* We want to detect only selected changes to the ovn-sb db. */
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnsb_db, &sbrec_idl_class, false, true));

    /* Ensure that only a single ovn-northd is active in the deployment by
     * acquiring a lock called "ovn_northd" on the southbound database
     * and then only performing DB transactions if the lock is held. */
    ovsdb_idl_set_lock(ovnsb_idl_loop.idl, "ovn_northd");
    bool had_lock = false;
#endif

    ddlog_prog ddlog;
    ddlog = ddlog_run(1, true, NULL, 0, ddlog_print_error);
    if (!ddlog) {
        VLOG_EMER("xxx Couldn't create ddlog instance");
    }

    /* Main loop. */
    exiting = false;
    while (!exiting) {
#if 0
        struct northd_context ctx = {
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
#endif

        struct json *updates, *ops;

        updates = handle_monitor(nb_rpc, nb_id);
        ops = nb_ddlog_run(ddlog, updates);
        json_destroy(updates);

        /* Apply updates to the Southbound. */
        if (ops) {
            do_transact(sb_rpc, ops);
            json_destroy(ops);
        }

#if 0
        updates = handle_monitor(sb_rpc, sb_id);
        ops = sb_ddlog_run(ddlog, updates);
        json_destroy(updates);

        /* Apply updates to the Northbound. */
        if (ops) {
            do_transact(nb_rpc, ops);
            json_destroy(ops);
        }
#endif

        unixctl_server_run(unixctl);
        unixctl_server_wait(unixctl);
        if (exiting) {
            poll_immediate_wake();
        }

        jsonrpc_run(nb_rpc);
        jsonrpc_wait(nb_rpc);
        jsonrpc_recv_wait(nb_rpc);

        poll_block();
        if (should_service_stop()) {
            exiting = true;
        }
    }

    jsonrpc_close(nb_rpc);

    ddlog_stop(ddlog);

    unixctl_server_destroy(unixctl);
#if 0
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);
#endif
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
