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
#include <fcntl.h>
#include <unistd.h>

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
#include "lib/chassis-index.h"
#include "ovn/logical-fields.h"
#include "lib/ovn-l7.h"
#include "lib/ovn-util.h"
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

#include "northd/ovn_northd_ddlog/ddlog.h"

VLOG_DEFINE_THIS_MODULE(ovn_northd);

static const char *nb_input_relations[] = {
    "NB_Global",
    "Logical_Switch",
    "Logical_Switch_Port",
    "Address_Set",
    "Port_Group",
    "Load_Balancer",
    "ACL",
    "QoS",
    "Meter",
    "Meter_Band",
    "Logical_Router",
    "Logical_Router_Policy",
    "Logical_Router_Port",
    "Logical_Router_Static_Route",
    "NAT",
    "DHCP_Options",
    "Connection",
    "DNS",
    "SSL",
    "Gateway_Chassis",
    "HA_Chassis",
    "HA_Chassis_Group",
    "Load_Balancer_Health_Check",
};

static const char *sb_input_relations[] = {
    "SB_Global",
    "Chassis",
    "Encap",
    "Connection",
    "SSL",
    "Address_Set",
    "Port_Group",
    "Logical_Flow",
    "Multicast_Group",
    "Meter",
    "Meter_Band",
    "Datapath_Binding",
    "Port_Binding",
    "MAC_Binding",
    "DHCP_Options",
    "DHCPv6_Options",
    "DNS",
    "RBAC_Role",
    "RBAC_Permission",
    "Gateway_Chassis",
    "IP_Multicast",
    "HA_Chassis",
    "HA_Chassis_Group",
    "Controller_Event",
    "Service_Monitor",
};

struct northd_status {
    bool had_lock;
    bool paused;
};

static unixctl_cb_func ovn_northd_exit;
static unixctl_cb_func ovn_northd_pause;
static unixctl_cb_func ovn_northd_resume;
static unixctl_cb_func ovn_northd_is_paused;
static unixctl_cb_func ovn_northd_status;

/* --ddlog-record: The name of a file to which to record DDlog commands for
 * later replay.  Useful for debugging.  If null (by default), DDlog commands
 * are not recorded. */
static const char *record_file;

static const char *ovnnb_db;
static const char *ovnsb_db;
static const char *unixctl_path;

/* Connection state machine.
 *
 * When a JSON-RPC session connects, sends a "monitor" request for
 * the Database table in the _Server database and transitions to the
 * S_SERVER_MONITOR_COND_REQUESTED state.  If the session drops and
 * reconnects, or if the FSM receives a "monitor_canceled" notification for a
 * table it is monitoring, the FSM starts over again in the same way. */
#define STATES                                                          \
    /* Waits for "get_schema" reply, then sends "monitor"               \
     * request whose details are informed by the schema, and            \
     * transitions to S_DATA_MONITOR_REQUESTED. */                      \
    STATE(S_DATA_SCHEMA_REQUESTED)                                      \
                                                                        \
    /* Waits for "monitor" reply.  If successful, replaces the          \
     * contents by the data carried in the reply and transitions to     \
     * S_MONITORING.  On failure, transitions to S_ERROR. */            \
    STATE(S_DATA_MONITOR_REQUESTED)                                     \
                                                                        \
    /* State that processes "update" notifications for the database. */ \
    STATE(S_MONITORING)                                                 \
                                                                        \
    /* Terminal error state that indicates that nothing useful can be   \
     * done, for example because the database server doesn't actually   \
     * have the desired database.  We maintain the session with the     \
     * database server anyway.  If it starts serving the database       \
     * that we want, or if someone fixes and restarts the database,     \
     * then it will kill the session and we will automatically          \
     * reconnect and try again. */                                      \
    STATE(S_ERROR)                                                      \
                                                                        \
    /* Terminal state that indicates we connected to a useless server   \
     * in a cluster, e.g. one that is partitioned from the rest of      \
     * the cluster. We're waiting to retry. */                          \
    STATE(S_RETRY)

enum northd_state {
#define STATE(NAME) NAME,
    STATES
#undef STATE
};

static const char *
northd_state_to_string(enum northd_state state)
{
    switch (state) {
#define STATE(NAME) case NAME: return #NAME;
        STATES
#undef STATE
    default: return "<unknown>";
    }
}

enum northd_monitoring {
    NORTHD_NOT_MONITORING,     /* Database is not being monitored. */
    NORTHD_MONITORING,         /* Database has "monitor" outstanding. */
    NORTHD_MONITORING_COND,    /* Database has "monitor_cond" outstanding. */
};

struct northd_db {
    struct northd_ctx *ctx;

    char *name;
    struct json *monitor_id;
    struct json *schema;
    enum northd_monitoring monitoring;

    /* Database locking. */
    char *lock_name;            /* Name of lock we need, NULL if none. */
    bool has_lock;              /* Has db server told us we have the lock? */
    bool is_lock_contended;     /* Has db server told us we can't get lock? */
    struct json *lock_request_id; /* JSON-RPC ID of in-flight lock request. */
};

struct northd_ctx {
    //struct northd_db server;
    struct northd_db data;

    ddlog_prog ddlog;

    /* Session state.
     *
     *'state_seqno' is a snapshot of the session's sequence number as returned
     * jsonrpc_session_get_seqno(session), so if it differs from the value that
     * function currently returns then the session has reconnected and the
     * state machine must restart.  */
    struct jsonrpc_session *session; /* Connection to the server. */
    enum northd_state state;         /* Current session state. */
    unsigned int state_seqno;        /* See above. */
    struct json *request_id;         /* JSON ID for request awaiting reply. */
};

static void northd_set_lock(struct northd_ctx *ctx, const char *lock_name);
static bool northd_has_lock(const struct northd_ctx *ctx);
//static bool northd_is_lock_contended(const struct northd_ctx *ctx);

static struct jsonrpc_msg *northd_db_compose_lock_request(
    struct northd_db *db);
static struct jsonrpc_msg *northd_db_compose_unlock_request(
    struct northd_db *db);

static void northd_db_parse_lock_reply(struct northd_db *,
                                       const struct json *result);
static bool northd_db_parse_lock_notify(struct northd_db *,
                                        const struct json *params,
                                        bool new_has_lock);

static void ddlog_handle_update(struct northd_ctx *, bool northbound,
                                const struct json *);
static struct json * get_nb_ops(struct northd_ctx *);
static struct json * get_sb_ops(struct northd_ctx *);

static int ddlog_handle_reconnect(struct northd_ctx *ctx, bool northbound,
                                  const struct json *table_updates);

static bool
debug_dump_callback(uintptr_t arg OVS_UNUSED, const ddlog_record *rec)
{
    char *str = ddlog_dump_record(rec);
    VLOG_INFO("%s", str);
    ddlog_string_free(str);

    return true;
}

/* Debug-dump DDlog table.
 *
 * `table` must be declared as `output relation` in DDlog. Typically, to use
 * this function, one would add the `output` qualifier to the table of interest
 * and re-compile the DDlog program. */
OVS_UNUSED static void
ddlog_table_debug_dump(ddlog_prog ddlog, const char *table)
{
    table_id tid = ddlog_get_table_id(table);
    if (tid == -1) {
        VLOG_ERR("Unknown output table %s", table);
        return;
    }
    VLOG_INFO("Dump %s", table);
    ddlog_dump_table(ddlog, tid, debug_dump_callback, 0);
}

/* Debug-dump all tables of interest. */
static void
ddlog_debug_dump(ddlog_prog ddlog OVS_UNUSED)
{
    /* Uncomment to enable DDlog profiling */
#if 0
    char *profile = ddlog_profile(ddlog);
    VLOG_INFO("DDlog profile:\n%s", profile);
    ddlog_string_free(profile);
#endif

#if 0
    ddlog_table_debug_dump(ddlog, "lswitch.SwitchPortIPv4Address");
    ddlog_table_debug_dump(ddlog, "OVN_Southbound.Out_Port_Binding");
    ddlog_table_debug_dump(ddlog, "helpers.SwitchRouterPeer");
    ddlog_table_debug_dump(ddlog, "lrouter.RouterPortPeer");
    ddlog_table_debug_dump(ddlog, "lrouter.RouterPort");
#endif
}

static struct northd_ctx *
northd_ctx_create(const char *server, const char *database, ddlog_prog ddlog)
{
    struct northd_ctx *ctx;

    ctx = xzalloc(sizeof *ctx);
    ctx->session = jsonrpc_session_open(server, true);
    ctx->state_seqno = UINT_MAX;
    ctx->request_id = NULL;

    ctx->data.ctx = ctx;
    ctx->data.name = xstrdup(database);
    ctx->data.monitor_id = json_array_create_2(json_string_create("monid"),
                                               json_string_create(database));

    ctx->ddlog = ddlog;

    return ctx;
}

static void
northd_db_destroy(struct northd_db *db)
{
    json_destroy(db->monitor_id);
    json_destroy(db->schema);
}

static void
northd_ctx_destroy(struct northd_ctx *ctx)
{
    if (ctx) {
        jsonrpc_session_close(ctx->session);

        northd_db_destroy(&ctx->data);
        json_destroy(ctx->request_id);
        free(ctx);
    }
}

/* Forces 'ctx' to drop its connection to the database and reconnect. */
static void
northd_force_reconnect(struct northd_ctx *ctx)
{
    if (ctx->session) {
        jsonrpc_session_force_reconnect(ctx->session);
    }
}

static void northd_transition_at(struct northd_ctx *, enum northd_state,
                                 const char *where);
#define northd_transition(CTX, STATE) \
    northd_transition_at(CTX, STATE, OVS_SOURCE_LOCATOR)

static void
northd_transition_at(struct northd_ctx *ctx, enum northd_state new_state,
                     const char *where)
{
    VLOG_DBG("%s: %s -> %s at %s",
             ctx->session ? jsonrpc_session_get_name(ctx->session) : "void",
             northd_state_to_string(ctx->state),
             northd_state_to_string(new_state),
             where);
    ctx->state = new_state;
}

static void northd_retry_at(struct northd_ctx *, const char *where);
#define northd_retry(CTX) northd_retry_at(CTX, OVS_SOURCE_LOCATOR)

static void
northd_retry_at(struct northd_ctx *ctx, const char *where)
{
    if (ctx->session && jsonrpc_session_get_n_remotes(ctx->session) > 1) {
        northd_force_reconnect(ctx);
        northd_transition_at(ctx, S_RETRY, where);
    } else {
        northd_transition_at(ctx, S_ERROR, where);
    }
}

static void
northd_send_request(struct northd_ctx *ctx, struct jsonrpc_msg *request)
{
    /* xxx We should add comments. */
    json_destroy(ctx->request_id);
    ctx->request_id = json_clone(request->id);
    if (ctx->session) {
        jsonrpc_session_send_block(ctx->session, request);
    }
}

static void
northd_send_schema_request(struct northd_ctx *ctx, struct northd_db *db)
{
    northd_send_request(ctx, jsonrpc_create_request(
                             "get_schema",
                             json_array_create_1(json_string_create(
                                                     db->name)),
                             NULL));
}

static void
northd_send_transact(struct northd_ctx *ctx, struct json *ddlog_ops)
{
    /* xxx Need to store txn id */
    northd_send_request(ctx, jsonrpc_create_request("transact", ddlog_ops,
                                                    NULL));
}

static void
northd_db_handle_update(struct northd_db *db,
                        const struct json *table_updates)
{
    /* xxx This string comparison isn't very efficient. */
    if (!strcmp(db->name, "OVN_Northbound")) {
        ddlog_handle_update(db->ctx, true, table_updates);
    } else if (!strcmp(db->name, "OVN_Southbound")) {
        ddlog_handle_update(db->ctx, false, table_updates);
    } else {
        VLOG_WARN("xxx Unknown db");
    }

    /* This update may have implications for the other side, so
     * immediately wake to check for more changes to be applied. */
    poll_immediate_wake();

    ddlog_debug_dump(db->ctx->ddlog);
}

static void
northd_send_monitor_request(struct northd_ctx *ctx, struct northd_db *db)
{
    struct ovsdb_schema *schema;
    struct ovsdb_error *error;

    if (db->schema) {
        VLOG_DBG("xxx schema: %s", json_to_string(db->schema, 0));
    } else {
        VLOG_DBG("xxx no schema");
    }
    error = ovsdb_schema_from_json(db->schema, &schema);
    if (error) {
        /* xxx Handle this error better.  Probably restart FSM.
         * xxx Parsing should probably happen when schema fetched. */
        VLOG_INFO("xxx couldn't parse schema: %s",
                  ovsdb_error_to_string(error));
        return;
    }

    struct json *monitor_requests = json_object_create();

    /* xxx This should be smarter about ignoring not needed ones.
     * xxx There's a lot more logic for this in
     * xxx ovsdb_idl_send_monitor_request(). */
    size_t n = shash_count(&schema->tables);
    const struct shash_node **nodes = shash_sort(&schema->tables);

    for (int i = 0; i < n; i++) {
        struct json *monitor_request_array = json_array_create_empty();
        json_array_add(monitor_request_array, json_object_create());

        struct ovsdb_table_schema *table = nodes[i]->data;
        json_object_put(monitor_requests, table->name, monitor_request_array);
    }
    free(nodes);

    ovsdb_schema_destroy(schema);

    // db->cond_changed = false;    xxx Needed?

    northd_send_request(
        ctx,
        jsonrpc_create_request(
            "monitor",
            json_array_create_3(json_string_create(db->name),
                                json_clone(db->monitor_id), monitor_requests),
            NULL));
}

static void
northd_restart_fsm(struct northd_ctx *ctx)
{
    /* xxx Free outstanding txn id? */
    northd_send_schema_request(ctx, &ctx->data);
    ctx->state = S_DATA_SCHEMA_REQUESTED;

    /* xxx This isn't the proper way to call it.  Just fixing build issue. */
    ddlog_handle_reconnect(ctx, true, NULL);
}

static void
northd_process_response(struct northd_ctx *ctx, struct jsonrpc_msg *msg)
{
    bool ok = msg->type == JSONRPC_REPLY;
    if (!ok) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        char *s = jsonrpc_msg_to_string(msg);
        VLOG_INFO_RL(&rl, "%s: received unexpected %s response in "
                     "%s state: %s", jsonrpc_session_get_name(ctx->session),
                     jsonrpc_msg_type_to_string(msg->type),
                     northd_state_to_string(ctx->state),
                     s);
        free(s);
        northd_retry(ctx);
        return;
    }

    switch (ctx->state) {
    case S_DATA_SCHEMA_REQUESTED:
        json_destroy(ctx->data.schema);
        ctx->data.schema = json_clone(msg->result);
        northd_send_monitor_request(ctx, &ctx->data);
        northd_transition(ctx, S_DATA_MONITOR_REQUESTED);
        break;

    case S_DATA_MONITOR_REQUESTED:
        ctx->data.monitoring = NORTHD_MONITORING;
        northd_transition(ctx, S_MONITORING);
        northd_db_handle_update(&ctx->data, msg->result);
        break;

    case S_MONITORING:
        /* We don't normally have a request outstanding in this state.  If we
         * do, it's a "monitor_cond_change", which means that the conditional
         * monitor clauses were updated.
         *
         * If further condition changes were pending, send them now. */
#if 0
        /* xxx Handle this. */
        northd_send_cond_change(ctx);
        ctx->data.cond_seqno++;
#endif
        break;

    case S_ERROR:
    case S_RETRY:
        /* Nothing to do in this state. */
        break;

    default:
        OVS_NOT_REACHED();
    }
}

static bool
northd_db_handle_update_rpc(struct northd_db *db,
                            const struct jsonrpc_msg *msg)
{
    if (msg->type == JSONRPC_NOTIFY) {
        if (!strcmp(msg->method, "update")
            && msg->params->type == JSON_ARRAY
            && msg->params->array.n == 2
            && json_equal(msg->params->array.elems[0], db->monitor_id)) {
            northd_db_handle_update(db, msg->params->array.elems[1]);
            return true;
        }
    }
    return false;
}

static struct jsonrpc_msg *
northd_db_set_lock(struct northd_db *db, const char *lock_name)
{
    /* xxx Getting to build. */
    //ovs_assert(!db->txn);
    //ovs_assert(hmap_is_empty(&db->outstanding_txns));

    if (db->lock_name
        && (!lock_name || strcmp(lock_name, db->lock_name))) {
        /* Release previous lock. */
        struct jsonrpc_msg *msg = northd_db_compose_unlock_request(db);
        free(db->lock_name);
        db->lock_name = NULL;
        db->is_lock_contended = false;
        return msg;
    }

    if (lock_name && !db->lock_name) {
        /* Acquire new lock. */
        db->lock_name = xstrdup(lock_name);
        return northd_db_compose_lock_request(db);
    }

    return NULL;
}

/* If 'lock_name' is nonnull, configures 'ctx' to obtain the named lock from
 * the database server and to avoid modifying the database when the lock cannot
 * be acquired (that is, when another client has the same lock).
 *
 * If 'lock_name' is NULL, drops the locking requirement and releases the
 * lock. */
static void
northd_set_lock(struct northd_ctx *ctx, const char *lock_name)
{
    for (;;) {
        struct jsonrpc_msg *msg = northd_db_set_lock(&ctx->data, lock_name);
        if (!msg) {
            break;
        }
        if (ctx->session) {
            jsonrpc_session_send(ctx->session, msg);
        }
    }
}

/* Returns true if 'ctx' is configured to obtain a lock and owns that lock.
 *
 * Locking and unlocking happens asynchronously from the database client's
 * point of view, so the information is only useful for optimization (e.g. if
 * the client doesn't have the lock then there's no point in trying to write to
 * the database). */
static bool
northd_has_lock(const struct northd_ctx *ctx)
{
    return ctx->data.has_lock;
}

#if 0  /* xxx not used */
/* Returns true if 'ctx' is configured to obtain a lock but the database server
 * has indicated that some other client already owns the requested lock. */
static bool
northd_is_lock_contended(const struct northd_ctx *ctx)
{
    return ctx->data.is_lock_contended;
}
#endif

static void
northd_db_update_has_lock(struct northd_db *db, bool new_has_lock)
{
    if (new_has_lock && !db->has_lock) {
        if (db->ctx->state == S_MONITORING) {
            /* xxx Changed to build. */
            //db->change_seqno++;
        } else {
            /* We're setting up a session, so don't signal that the database
             * changed.  Finalizing the session will increment change_seqno
             * anyhow. */
        }
        db->is_lock_contended = false;
    }
    db->has_lock = new_has_lock;
}

static bool
northd_db_process_lock_replies(struct northd_db *db,
                               const struct jsonrpc_msg *msg)
{
    if (msg->type == JSONRPC_REPLY
        && db->lock_request_id
        && json_equal(db->lock_request_id, msg->id)) {
        /* Reply to our "lock" request. */
        northd_db_parse_lock_reply(db, msg->result);
        return true;
    }

    if (msg->type == JSONRPC_NOTIFY) {
        if (!strcmp(msg->method, "locked")) {
            /* We got our lock. */
            return northd_db_parse_lock_notify(db, msg->params, true);
        } else if (!strcmp(msg->method, "stolen")) {
            /* Someone else stole our lock. */
            return northd_db_parse_lock_notify(db, msg->params, false);
        }
    }

    return false;
}

static struct jsonrpc_msg *
northd_db_compose_lock_request__(struct northd_db *db,
                                    const char *method)
{
    northd_db_update_has_lock(db, false);

    json_destroy(db->lock_request_id);
    db->lock_request_id = NULL;

    struct json *params = json_array_create_1(json_string_create(
                                                  db->lock_name));
    return jsonrpc_create_request(method, params, NULL);
}

static struct jsonrpc_msg *
northd_db_compose_lock_request(struct northd_db *db)
{
    struct jsonrpc_msg *msg = northd_db_compose_lock_request__(db, "lock");
    db->lock_request_id = json_clone(msg->id);
    return msg;
}

static struct jsonrpc_msg *
northd_db_compose_unlock_request(struct northd_db *db)
{
    return northd_db_compose_lock_request__(db, "unlock");
}

static void
northd_db_parse_lock_reply(struct northd_db *db, const struct json *result)
{
    bool got_lock;

    json_destroy(db->lock_request_id);
    db->lock_request_id = NULL;

    if (result->type == JSON_OBJECT) {
        const struct json *locked;

        locked = shash_find_data(json_object(result), "locked");
        got_lock = locked && locked->type == JSON_TRUE;
    } else {
        got_lock = false;
    }

    northd_db_update_has_lock(db, got_lock);
    if (!got_lock) {
        db->is_lock_contended = true;
    }
}

static bool
northd_db_parse_lock_notify(struct northd_db *db, const struct json *params,
                            bool new_has_lock)
{
    if (db->lock_name
        && params->type == JSON_ARRAY
        && json_array(params)->n > 0
        && json_array(params)->elems[0]->type == JSON_STRING) {
        const char *lock_name = json_string(json_array(params)->elems[0]);

        if (!strcmp(db->lock_name, lock_name)) {
            northd_db_update_has_lock(db, new_has_lock);
            if (!new_has_lock) {
                db->is_lock_contended = true;
            }
            return true;
        }
    }
    return false;
}

static void
northd_process_msg(struct northd_ctx *ctx, struct jsonrpc_msg *msg)
{
    bool is_response = (msg->type == JSONRPC_REPLY ||
                        msg->type == JSONRPC_ERROR);

    /* Process a reply to an outstanding request. */
    if (is_response
        && ctx->request_id && json_equal(ctx->request_id, msg->id)) {
        json_destroy(ctx->request_id);
        ctx->request_id = NULL;
        northd_process_response(ctx, msg);
        return;
    }

    /* Process database contents updates. */
    if (northd_db_handle_update_rpc(&ctx->data, msg)) {
        return;
    }

    /* Process "lock" replies and related notifications. */
    if (northd_db_process_lock_replies(&ctx->data, msg)) {
        return;
    }

#if 0
    /* Process response to a database transaction we submitted. */
    if (is_response && northd_db_txn_process_reply(&ctx->data, msg)) {
        return;
    }
#endif

    /* Unknown message.  Log at a low level because this can happen if
     * northd_txn_destroy() is called to destroy a transaction before
     * we receive the reply.
     *
     * (We could sort those out from other kinds of unknown messages by
     * using distinctive IDs for transactions, if it seems valuable to
     * do so, and then it would be possible to use different log
     * levels. XXX?) */
    char *s = jsonrpc_msg_to_string(msg);
    VLOG_DBG("%s: received unexpected %s message: %s",
             jsonrpc_session_get_name(ctx->session),
             jsonrpc_msg_type_to_string(msg->type), s);
    free(s);
}

/* Processes a batch of messages from the database server on 'ctx'. */
static void
northd_run(struct northd_ctx *ctx, bool run_deltas)
{
    VLOG_DBG("xxx ========= northd_run: %s", ctx->data.name);

    if (!ctx->session) {
#if 0
        northd_txn_abort_all(ctx);
#endif
        VLOG_INFO("xxx no session");
        return;
    }

#if 0
    ovs_assert(!ctx->data.txn);
#endif

    jsonrpc_session_run(ctx->session);
    for (int i = 0; jsonrpc_session_is_connected(ctx->session) && i < 50;
         i++) {
        struct jsonrpc_msg *msg;
        unsigned int seqno;

        VLOG_DBG("xxx northd_run: iter %d", i);

        seqno = jsonrpc_session_get_seqno(ctx->session);
        if (ctx->state_seqno != seqno) {
            ctx->state_seqno = seqno;
#if 0
            northd_txn_abort_all(ctx);
#endif
            northd_restart_fsm(ctx);

            if (ctx->data.lock_name) {
                jsonrpc_session_send(
                    ctx->session,
                    northd_db_compose_lock_request(&ctx->data));
            }
        }

        msg = jsonrpc_session_recv(ctx->session);
        if (!msg) {
            break;
        }
        northd_process_msg(ctx, msg);
        jsonrpc_msg_destroy(msg);
    }

    /* xxx This string comparison isn't very efficient. */
    if (run_deltas && !ctx->request_id) {
        if (!strcmp(ctx->data.name, "OVN_Northbound")) {
            struct json *ops = get_nb_ops(ctx);
            if (ops) {
                northd_send_transact(ctx->data.ctx, ops);
            }
        } else if (!strcmp(ctx->data.name, "OVN_Southbound")) {
            struct json *ops = get_sb_ops(ctx);
            if (ops) {
                northd_send_transact(ctx->data.ctx, ops);
            }
        } else {
            VLOG_WARN("xxx Unknown db");
        }
    }
}

/* Arranges for poll_block() to wake up when northd_run() has something to
 * do or when activity occurs on a transaction on 'ctx'. */
static void
northd_wait(struct northd_ctx *ctx)
{
    if (!ctx->session) {
        return;
    }
    jsonrpc_session_wait(ctx->session);
    jsonrpc_session_recv_wait(ctx->session);
}

/* ddlog-specific actions. */

static void
ddlog_table_update(struct ds *ds, ddlog_prog ddlog,
                   const char *db, const char *table)
{
    int error;
    char *updates;

    error = ddlog_dump_ovsdb_delta(ddlog, db, table, &updates);
    if (error) {
        VLOG_INFO("xxx delta (%s) error: %d", table, error);
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
get_sb_ops(struct northd_ctx *ctx)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "SB_Global");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "Datapath_Binding");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "Port_Binding");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "Logical_Flow");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "Meter");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "Meter_Band");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "Multicast_Group");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "Gateway_Chassis");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "Port_Group");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "MAC_Binding");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "DHCP_Options");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "DHCPv6_Options");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "Address_Set");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "DNS");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "RBAC_Role");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "RBAC_Permission");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "IP_Multicast");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "HA_Chassis");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "HA_Chassis_Group");
    //ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "Controller_Event");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Southbound", "Service_Monitor");

    ds_chomp(&ds, ',');

    if (!ds.length) {
        return NULL;
    }
    char *ops_s;
    ops_s = xasprintf("[\"OVN_Southbound\",%s]", ds_steal_cstr(&ds));

    struct json *ops = json_from_string(ops_s);
    free(ops_s);
    VLOG_DBG("xxx sb postops: %s", json_to_string(ops, JSSF_PRETTY));

    return ops;
}

static struct json *
get_nb_ops(struct northd_ctx *ctx)
{

    struct ds ds = DS_EMPTY_INITIALIZER;

    ddlog_table_update(&ds, ctx->ddlog, "OVN_Northbound",
                       "Logical_Switch_Port");
    ddlog_table_update(&ds, ctx->ddlog, "OVN_Northbound", "NB_Global");

    ds_chomp(&ds, ',');

    if (!ds.length) {
        return NULL;
    }
    char *ops_s;
    ops_s = xasprintf("[\"OVN_Northbound\",%s]", ds_steal_cstr(&ds));

    struct json *ops = json_from_string(ops_s);
    free(ops_s);
    VLOG_DBG("xxx nb postops: %s", json_to_string(ops, JSSF_PRETTY));

    return ops;
}

static void
ddlog_handle_update(struct northd_ctx *ctx, bool northbound,
                    const struct json *table_updates)
{
    if (!table_updates) {
        return;
    }

    if (ddlog_transaction_start(ctx->ddlog)) {
        VLOG_WARN("xxx Couldn't start transaction");
        return;
    }

    VLOG_DBG("xxx %s update: %s", northbound ? "nb" : "sb",
             json_to_string(table_updates, JSSF_PRETTY));

    const char *prefix = northbound ? "OVN_Northbound." : "OVN_Southbound.";

    char *updates_s = json_to_string(table_updates, 0);
    if (ddlog_apply_ovsdb_updates(ctx->ddlog, prefix, updates_s)) {
        VLOG_WARN("xxx Couldn't add update");
        free(updates_s);
        goto error;
    }
    free(updates_s);

    if (ddlog_transaction_commit(ctx->ddlog)) {
        VLOG_WARN("xxx Couldn't commit transaction");
        goto error;
    }

    return;

error:
    ddlog_transaction_rollback(ctx->ddlog);
}

static int
ddlog_clear_nb(struct northd_ctx *ctx)
{
    int ret;

    for (int i = 0; i < ARRAY_SIZE(nb_input_relations) - 1; i++) {
        char *table;
        table = xasprintf("OVN_Northbound.%s", nb_input_relations[i]);
        ret = ddlog_clear_relation(ctx->ddlog, ddlog_get_table_id(table));
        free(table);
        if (ret) {
            return ret;
        }
    }
    return 0;
}

static int
ddlog_clear_sb(struct northd_ctx *ctx)
{
    int ret;

    for (int i = 0; i < ARRAY_SIZE(sb_input_relations) - 1; i++) {
        char *table;
        table = xasprintf("OVN_Southbound.%s", sb_input_relations[i]);
        ret = ddlog_clear_relation(ctx->ddlog, ddlog_get_table_id(table));
        free(table);
        if (ret) {
            return ret;
        }
    }
    return 0;
}

/* Invoked when an SB or NB connection is lost and later restored.
 * The database snapshot stored in DDlog may be stale at this point.
 * To re-synchronize DDlog with OVSDB, clear all SB (NB) relations
 * and re-populate them with a complete state snapshot stored in
 * `table_updates`.  If OVSDB state happens to be exactly the same
 * as before the disconnect, DDlog will not produce any outputs, and
 * re-synchonization is complete.  If, however, either NB or SB state
 * has changed, DDlog may produce a set of updates to one or both
 * databases. */
static int
ddlog_handle_reconnect(struct northd_ctx *ctx, bool northbound,
                       const struct json *table_updates)
{
    int res;

    if (!table_updates) {
        return -1;
    }

    if ((res = ddlog_transaction_start(ctx->ddlog))) {
        VLOG_WARN("xxx Couldn't start transaction");
        return res;
    }

    if (northbound) {
        if ((res = ddlog_clear_nb(ctx))) {
            goto error;
        }
    } else {
        if ((res = ddlog_clear_sb(ctx))) {
            goto error;
        }
    }

    VLOG_DBG("xxx %s update: %s", northbound ? "nb" : "sb",
             json_to_string(table_updates, JSSF_PRETTY));

    const char *prefix = northbound ? "OVN_Northbound." : "OVN_Southbound.";

    char *updates_s = json_to_string(table_updates, 0);
    if ((res = ddlog_apply_ovsdb_updates(ctx->ddlog, prefix, updates_s))) {
        VLOG_WARN("xxx Couldn't add update");
        free(updates_s);
        goto error;
    }
    free(updates_s);

    if ((res = ddlog_transaction_commit(ctx->ddlog))) {
        VLOG_WARN("xxx Couldn't commit transaction");
        goto error;
    }

    return 0;

error:
    ddlog_transaction_rollback(ctx->ddlog);
    return res;
}

/* Callback used by the ddlog engine to print error messages.  Note that
 * this is only used by the ddlog runtime, as opposed to the application
 * code in ovn_northd.dl, which uses the vlog facility directly.  */
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
        OPT_DDLOG_RECORD
    };
    static const struct option long_options[] = {
        {"ddlog-record", required_argument, NULL, OPT_DDLOG_RECORD},
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

        case OPT_DDLOG_RECORD:
            record_file = optarg;
            break;

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

    if (!unixctl_path) {
        char *abs_unixctl_path = get_abs_unix_ctl_path();
        retval = unixctl_server_create(abs_unixctl_path, &unixctl);
        free(abs_unixctl_path);
    } else {
        retval = unixctl_server_create(unixctl_path, &unixctl);
    }

    if (retval) {
        exit(EXIT_FAILURE);
    }

    struct northd_status status = {
        .had_lock = false,
        .paused = false,
    };
    unixctl_command_register("exit", "", 0, 0, ovn_northd_exit, &exiting);
    unixctl_command_register("pause", "", 0, 0, ovn_northd_pause, &status);
    unixctl_command_register("resume", "", 0, 0, ovn_northd_resume, &status);
    unixctl_command_register("is-paused", "", 0, 0, ovn_northd_is_paused,
                             &status);
    unixctl_command_register("status", "", 0, 0, ovn_northd_status, &status);

    daemonize_complete();

    ddlog_prog ddlog;
    ddlog = ddlog_run(1, true, NULL, 0, ddlog_print_error);
    if (!ddlog) {
        VLOG_ERR("xxx Couldn't create ddlog instance");
    }

    int replay_fd = -1;
    if (record_file) {
        replay_fd = open(record_file, O_CREAT | O_WRONLY | O_TRUNC, 0666);
        if (replay_fd < 0) {
            ovs_fatal(errno, "%s: could not create DDlog record file",
                record_file);
        }

        if (ddlog_record_commands(ddlog, replay_fd)) {
            ovs_fatal(0, "could not enable DDlog command recording");
        }
    }

    struct northd_ctx *nb_ctx = northd_ctx_create(ovnnb_db, "OVN_Northbound",
                                                  ddlog);
    struct northd_ctx *sb_ctx = northd_ctx_create(ovnsb_db, "OVN_Southbound",
                                                  ddlog);

    /* Ensure that only a single ovn-northd is active in the deployment by
     * acquiring a lock called "ovn_northd" on the southbound database
     * and then only performing DB transactions if the lock is held. */
    northd_set_lock(sb_ctx, "ovn_northd");

    /* Main loop. */
    exiting = false;
    while (!exiting) {
        /* xxx Test that failover actually works. */
        if (!status.had_lock && northd_has_lock(sb_ctx)) {
            VLOG_INFO("ovn-northd lock acquired. "
                      "This ovn-northd instance is now active.");
            status.had_lock = true;
        } else if (status.had_lock && !northd_has_lock(sb_ctx)) {
            VLOG_INFO("ovn-northd lock lost. "
                      "This ovn-northd instance is now on standby.");
            status.had_lock = false;
        }

        bool run_deltas = (northd_has_lock(sb_ctx) &&
                           nb_ctx->state == S_MONITORING &&
                           sb_ctx->state == S_MONITORING);

        northd_run(nb_ctx, run_deltas);
        northd_wait(nb_ctx);

        northd_run(sb_ctx, run_deltas);
        northd_wait(sb_ctx);

        unixctl_server_run(unixctl);
        unixctl_server_wait(unixctl);
        if (exiting) {
            poll_immediate_wake();
        }

        poll_block();
        if (should_service_stop()) {
            exiting = true;
        }
    }

    northd_ctx_destroy(nb_ctx);
    northd_ctx_destroy(sb_ctx);

    ddlog_stop(ddlog);

    if (replay_fd >= 0) {
        fsync(replay_fd);
        close(replay_fd);
    }

    unixctl_server_destroy(unixctl);
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

static void
ovn_northd_status(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *status_)
{
    const struct northd_status *status = status_;
    /*
     * Use a labelled formatted output so we can add more to the status command
     * later without breaking any consuming scripts
     */
    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "Status: %s\n",
                  status->paused ? "paused"
                  : status->had_lock ? "active"
                  : "standby");
    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}

static void
ovn_northd_pause(struct unixctl_conn *conn, int argc OVS_UNUSED,
                 const char *argv[] OVS_UNUSED, void *status_ OVS_UNUSED)
{
    unixctl_command_reply(conn, NULL); /* XXX */
}

static void
ovn_northd_resume(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *status_ OVS_UNUSED)
{
    unixctl_command_reply(conn, NULL); /* XXX */
}

static void
ovn_northd_is_paused(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *status_)
{
    const struct northd_status *status = status_;
    unixctl_command_reply(conn, status->paused ? "true" : "false");
}
