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
#include "sset.h"
#include "stream.h"
#include "stream-ssl.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"
#include "openvswitch/vlog.h"

#include "northd/ovn_northd_ddlog/ddlog.h"

VLOG_DEFINE_THIS_MODULE(ovn_northd);

#include "northd/ovn-northd-ddlog-nb.inc"
#include "northd/ovn-northd-ddlog-sb.inc"

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

/* Frequently used table ids. */
static table_id WARNING_TABLE_ID;

/* Initialize frequently used table ids. */
static void init_table_ids(void) {
    WARNING_TABLE_ID = ddlog_get_table_id("Warning");
}

/*
 * Accumulates DDlog delta to be sent to OVSDB.
 *
 * FIXME: There is currently no global northd state descriptor shared by NB and
 * SB connections.  We should probably introduce it and move this variable there
 * instead of declaring it as a global variable.
 */
static ddlog_delta *delta;


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
    struct northd_db data;

    ddlog_prog ddlog;
    char *prefix;
    const char **input_relations;
    const char **output_relations;
    const char **output_only_relations;

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

static void ddlog_handle_update(struct northd_ctx *, const struct json *);
static struct json *get_database_ops(struct northd_ctx *);

static int ddlog_handle_reconnect(struct northd_ctx *ctx,
                                  const struct json *table_updates);

static struct northd_ctx *
northd_ctx_create(const char *server, const char *database, ddlog_prog ddlog,
                  const char **input_relations,
                  const char **output_relations,
                  const char **output_only_relations)
{
    struct northd_ctx *ctx;

    ctx = xzalloc(sizeof *ctx);
    ctx->prefix = xasprintf("%s.", database);
    ctx->session = jsonrpc_session_open(server, true);
    ctx->state_seqno = UINT_MAX;
    ctx->request_id = NULL;

    ctx->input_relations = input_relations;
    ctx->output_relations = output_relations;
    ctx->output_only_relations = output_only_relations;

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
    struct json *comment = json_object_create();
    json_object_put_string(comment, "op", "comment");
    json_object_put_string(comment, "comment", "ovn-northd-ddlog");
    json_array_add(ddlog_ops, comment);
    northd_send_request(ctx, jsonrpc_create_request("transact", ddlog_ops,
                                                    NULL));
}

static void
northd_db_handle_update(struct northd_db *db, const struct json *table_updates)
{
    ddlog_handle_update(db->ctx, table_updates);

    /* This update may have implications for the other side, so
     * immediately wake to check for more changes to be applied. */
    poll_immediate_wake();
}

static void
northd_send_monitor_request(struct northd_ctx *ctx, struct northd_db *db)
{
    struct ovsdb_schema *schema;
    struct ovsdb_error *error;

    error = ovsdb_schema_from_json(db->schema, &schema);
    if (error) {
        VLOG_ERR("couldn't parse schema (%s)", ovsdb_error_to_string(error));
        return;
    }

    struct json *monitor_requests = json_object_create();

    /* xxx This should be smarter about ignoring not needed ones.
     * xxx There's a lot more logic for this in
     * xxx ovsdb_idl_send_monitor_request(). */
    size_t n = shash_count(&schema->tables);
    const struct shash_node **nodes = shash_sort(&schema->tables);
    for (int i = 0; i < n; i++) {
        struct ovsdb_table_schema *table = nodes[i]->data;

        /* Only subscribe to input relations we care about. */
        for (const char **p = ctx->input_relations; *p; p++) {
            if (!strcmp(table->name, *p)) {
                json_object_put(monitor_requests, table->name,
                                json_array_create_1(json_object_create()));
                break;
            }
        }
    }
    free(nodes);

    ovsdb_schema_destroy(schema);

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
    northd_send_schema_request(ctx, &ctx->data);
    ctx->state = S_DATA_SCHEMA_REQUESTED;

    /* xxx This isn't the proper way to call it.  Just fixing build issue. */
    ddlog_handle_reconnect(ctx, NULL);
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

static void
northd_db_update_has_lock(struct northd_db *db, bool new_has_lock)
{
    if (new_has_lock && !db->has_lock) {
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

    /* Unknown message.  Log at a low level because this can happen if
     * northd_txn_destroy() is called to destroy a transaction before
     * we receive the reply. */
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
    if (!ctx->session) {
        return;
    }

    jsonrpc_session_run(ctx->session);
    for (int i = 0; jsonrpc_session_is_connected(ctx->session) && i < 50;
         i++) {
        struct jsonrpc_msg *msg;
        unsigned int seqno;

        seqno = jsonrpc_session_get_seqno(ctx->session);
        if (ctx->state_seqno != seqno) {
            ctx->state_seqno = seqno;
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

    if (run_deltas && !ctx->request_id) {
        struct json *ops = get_database_ops(ctx);
        if (ops) {
            northd_send_transact(ctx->data.ctx, ops);
        }
    }
}

static void
northd_update_probe_interval_cb(
    uintptr_t probe_intervalp_,
    table_id table OVS_UNUSED,
    const ddlog_record *rec,
    bool polarity OVS_UNUSED)
{
    int *probe_intervalp = (int *) probe_intervalp_;

    uint64_t x = ddlog_get_u64(rec);
    if (x > 1000) {
        *probe_intervalp = x;
    }
}

static void
northd_update_probe_interval(struct northd_ctx *nb, struct northd_ctx *sb)
{
    /* Default probe interval for NB and SB DB connections. */
    int probe_interval = 5000;
    table_id tid = ddlog_get_table_id("Northd_Probe_Interval");
    ddlog_delta *probe_delta = ddlog_delta_get_table(delta, tid);
    ddlog_delta_enumerate(probe_delta, northd_update_probe_interval_cb, (uintptr_t) &probe_interval);

    jsonrpc_session_set_probe_interval(nb->session, probe_interval);
    jsonrpc_session_set_probe_interval(sb->session, probe_interval);
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

/* Generate OVSDB update command for delta-plus, delta-minus, and delta-update
 * tables. */
static void
ddlog_table_update_deltas(struct ds *ds, ddlog_prog ddlog,
                          const char *db, const char *table)
{
    int error;
    char *updates;

    error = ddlog_dump_ovsdb_delta_tables(ddlog, delta, db, table, &updates);
    if (error) {
        VLOG_INFO("DDlog error %d dumping delta for table %s", error, table);
        return;
    }

    if (!updates[0]) {
        ddlog_free_json(updates);
        return;
    }

    ds_put_cstr(ds, updates);
    ds_put_char(ds, ',');
    ddlog_free_json(updates);
}

/* Generate OVSDB update command for a direct-output table;
 * clear  */
static void
ddlog_table_update_output(struct ds *ds, ddlog_prog ddlog,
                   const char *db, const char *table)
{
    int error;
    char *updates;

    error = ddlog_dump_ovsdb_output_table(ddlog, delta, db, table, &updates);
    if (error) {
        VLOG_INFO("xxx ddlog_table_update_output (%s) error: %d", table, error);
        return;
    }
    char *table_name = xasprintf("%s.Out_%s", db, table);
    ddlog_delta_clear_table(delta, ddlog_get_table_id(table_name));
    free(table_name);

    if (!updates[0]) {
        ddlog_free_json(updates);
        return;
    }

    ds_put_cstr(ds, updates);
    ds_put_char(ds, ',');
    ddlog_free_json(updates);
}

static struct json *
get_database_ops(struct northd_ctx *ctx)
{
    struct ds ops_s = DS_EMPTY_INITIALIZER;
    ds_put_char(&ops_s, '[');
    json_string_escape(ctx->data.name, &ops_s);
    ds_put_char(&ops_s, ',');
    size_t start_len = ops_s.length;

    for (const char **p = ctx->output_relations; *p; p++) {
        ddlog_table_update_deltas(&ops_s, ctx->ddlog, ctx->data.name, *p);
    }
    for (const char **p = ctx->output_only_relations; *p; p++) {
        ddlog_table_update_output(&ops_s, ctx->ddlog, ctx->data.name, *p);
    }

    struct json *ops;
    if (ops_s.length > start_len) {
        ds_chomp(&ops_s, ',');
        ds_put_char(&ops_s, ']');
        ops = json_from_string(ds_cstr(&ops_s));
    } else {
        ops = NULL;
    }

    ds_destroy(&ops_s);

    return ops;
}

static void warning_cb(
    uintptr_t arg OVS_UNUSED,
    table_id table OVS_UNUSED,
    const ddlog_record *rec,
    bool polarity)
{
    size_t len;
    const char *s = ddlog_get_str_with_length(rec, &len);
    if (polarity) {
        VLOG_WARN("New warning: %.*s", (int)len, s);
    } else {
        VLOG_WARN("Warning cleared: %.*s", (int)len, s);
    }
}

static int ddlog_commit(ddlog_prog ddlog) {
    ddlog_delta *new_delta = ddlog_transaction_commit_dump_changes(ddlog);
    if (!delta) {
        VLOG_WARN("xxx Couldn't commit transaction");
        return -1;
    }

    /* Remove warnings from delta and output them straight away. */
    ddlog_delta *warnings = ddlog_delta_remove_table(new_delta, WARNING_TABLE_ID);
    ddlog_delta_enumerate(warnings, warning_cb, 0);
    ddlog_free_delta(warnings);

    /* Merge changes into `delta`. */
    ddlog_delta_union(delta, new_delta);

    return 0;
}

static void
ddlog_handle_update(struct northd_ctx *ctx, const struct json *table_updates)
{
    if (!table_updates) {
        return;
    }

    if (ddlog_transaction_start(ctx->ddlog)) {
        VLOG_WARN("DDlog failed to start transaction");
        return;
    }

    char *updates_s = json_to_string(table_updates, 0);
    if (ddlog_apply_ovsdb_updates(ctx->ddlog, ctx->prefix, updates_s)) {
        VLOG_WARN("DDlog failed to apply updates");
        free(updates_s);
        goto error;
    }
    free(updates_s);

    /* Commit changes to DDlog.  Invoke `change_cb` for each modified output
     * record.  This call will block until `change_cb` has been called for each
     * update.
     */
    if (ddlog_commit(ctx->ddlog)) {
        goto error;
    }

    return;

error:
    ddlog_transaction_rollback(ctx->ddlog);
}

static int
ddlog_clear(struct northd_ctx *ctx)
{
    for (int i = 0; ctx->input_relations[i]; i++) {
        char *table = xasprintf("%s%s", ctx->prefix, ctx->input_relations[i]);
        int ret = ddlog_clear_relation(ctx->ddlog, ddlog_get_table_id(table));
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
ddlog_handle_reconnect(struct northd_ctx *ctx,
                       const struct json *table_updates)
{
    int res;

    if (!table_updates) {
        return -1;
    }

    if ((res = ddlog_transaction_start(ctx->ddlog))) {
        VLOG_WARN("DDlog failed to start transaction following reconnection");
        return res;
    }

    res = ddlog_clear(ctx);
    if (res) {
        goto error;
    }

    char *updates_s = json_to_string(table_updates, 0);
    res = ddlog_apply_ovsdb_updates(ctx->ddlog, ctx->prefix, updates_s);
    free(updates_s);
    if (res) {
        VLOG_WARN("DDlog failed to apply updates following reconnection");
        goto error;
    }

    if ((res = ddlog_commit(ctx->ddlog))) {
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
        OVN_DAEMON_OPTION_ENUMS,
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
        OVN_DAEMON_LONG_OPTIONS,
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
        OVN_DAEMON_OPTION_HANDLERS;
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

    if (!ovnsb_db || !ovnsb_db[0]) {
        ovnsb_db = default_sb_db();
    }

    if (!ovnnb_db || !ovnnb_db[0]) {
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

    init_table_ids();

    fatal_ignore_sigpipe();
    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);

    daemonize_start(false);

    char *abs_unixctl_path = get_abs_unix_ctl_path(unixctl_path);
    retval = unixctl_server_create(abs_unixctl_path, &unixctl);
    free(abs_unixctl_path);

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
    ddlog = ddlog_run(1, false, NULL, 0, ddlog_print_error, &delta);
    if (!ddlog) {
        ovs_fatal(0, "DDlog instance could not be created");
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

    struct northd_ctx *nb_ctx = northd_ctx_create(
        ovnnb_db, "OVN_Northbound", ddlog,
        nb_input_relations, nb_output_relations, nb_output_only_relations);
    struct northd_ctx *sb_ctx = northd_ctx_create(
        ovnsb_db, "OVN_Southbound", ddlog,
        sb_input_relations, sb_output_relations, sb_output_only_relations);

    /* Main loop. */
    exiting = false;
    while (!exiting) {
        if (!status.paused) {
            /* Ensure that only a single ovn-northd is active in the deployment
             * by acquiring a lock called "ovn_northd" on the southbound
             * database and then only performing DB transactions if the lock is
             * held. */
            if (!northd_has_lock(sb_ctx)) {
                northd_set_lock(sb_ctx, "ovn_northd");
            }

            if (!status.had_lock && northd_has_lock(sb_ctx)) {
                VLOG_INFO("ovn-northd lock acquired. "
                          "This ovn-northd instance is now active.");
                status.had_lock = true;
            } else if (status.had_lock && !northd_has_lock(sb_ctx)) {
                VLOG_INFO("ovn-northd lock lost. "
                          "This ovn-northd instance is now on standby.");
                status.had_lock = false;
            }
        } else {
            /* ovn-northd is paused
             *    - we still want to handle any db updates and update the
             *      local IDL. Otherwise, when it is resumed, the local IDL
             *      copy will be out of sync.
             *    - but we don't want to create any txns.
             * */
            if (northd_has_lock(sb_ctx)) {
                /* make sure we don't hold the lock while paused */
                VLOG_INFO("This ovn-northd instance is now paused.");
                northd_set_lock(sb_ctx, NULL);
                status.had_lock = false;
            }
        }

        bool run_deltas = (northd_has_lock(sb_ctx) &&
                           nb_ctx->state == S_MONITORING &&
                           sb_ctx->state == S_MONITORING);

        northd_run(nb_ctx, run_deltas);
        northd_wait(nb_ctx);

        northd_run(sb_ctx, run_deltas);
        northd_wait(sb_ctx);

        northd_update_probe_interval(nb_ctx, sb_ctx);

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
ovn_northd_pause(struct unixctl_conn *conn, int argc OVS_UNUSED,
                const char *argv[] OVS_UNUSED, void *status_)
{
    struct northd_status  *status = status_;
    status->paused = true;

    unixctl_command_reply(conn, NULL);
}

static void
ovn_northd_resume(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *status_)
{
    struct northd_status *status = status_;
    status->paused = false;

    unixctl_command_reply(conn, NULL);
}

static void
ovn_northd_is_paused(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *status_)
{
    struct northd_status *status = status_;
    if (status->paused) {
        unixctl_command_reply(conn, "true");
    } else {
        unixctl_command_reply(conn, "false");
    }
}

static void
ovn_northd_status(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *status_)
{
    struct northd_status *status = status_;
    char *status_string;

    if (status->paused) {
        status_string = "paused";
    } else {
        status_string = status->had_lock ? "active" : "standby";
    }

    /*
     * Use a labelled formatted output so we can add more to the status command
     * later without breaking any consuming scripts
     */
    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "Status: %s\n", status_string);
    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}
