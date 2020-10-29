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

#include "command-line.h"
#include "daemon.h"
#include "fatal-signal.h"
#include "hash.h"
#include "jsonrpc.h"
#include "lib/ovn-util.h"
#include "openvswitch/hmap.h"
#include "openvswitch/json.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "ovsdb-types.h"
#include "ovsdb/ovsdb.h"
#include "ovsdb/table.h"
#include "stream-ssl.h"
#include "stream.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"

#include "northd/ovn_northd_ddlog/ddlog.h"

VLOG_DEFINE_THIS_MODULE(ovn_northd);

#include "northd/ovn-northd-ddlog-nb.inc"
#include "northd/ovn-northd-ddlog-sb.inc"

struct northd_status {
    bool locked;
    bool pause;
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
static table_id NB_CFG_TIMESTAMP_ID;

/* Initialize frequently used table ids. */
static void init_table_ids(void)
{
    WARNING_TABLE_ID = ddlog_get_table_id("Warning");
    NB_CFG_TIMESTAMP_ID = ddlog_get_table_id("NbCfgTimestamp");
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
 * When a JSON-RPC session connects, sends a "get_schema" request
 * and transitions to S_SCHEMA_REQUESTED. */
#define STATES                                                          \
    /* Waiting for "get_schema" reply.  Once received, sends            \
     * "monitor" request whose details are informed by the              \
     * schema, and transitions to S_MONITOR_REQUESTED. */               \
    STATE(S_SCHEMA_REQUESTED)                                           \
                                                                        \
    /* Waits for "monitor" reply.  On failure, transitions to           \
     * S_ERROR.  If successful, replaces our snapshot of database       \
     * contents by the data carried in the reply and:                   \
     *                                                                  \
     *   - If this database needs a lock:                               \
     *                                                                  \
     *       + If northd is not paused, sends a lock request and        \
     *         transitions to S_LOCK_REQUESTED.                         \
     *                                                                  \
     *       + If northd is paused, transition to S_PAUSED.             \
     *                                                                  \
     *   - Otherwise, if there are any output-only tables, sends        \
     *     "transact" request for their data and transitions to         \
     *     S_OUTPUT_ONLY_DATA_REQUESTED.                                \
     *                                                                  \
     *   - Otherwise, transitions to S_MONITORING. */                   \
    STATE(S_MONITOR_REQUESTED)                                          \
                                                                        \
    /* We need the lock and we're paused.  We haven't requested         \
     * the lock (or we unlocked it).                                    \
     *                                                                  \
     * Waits for northd to be un-paused.  Then, sends a lock            \
     * request and transitions to S_LOCK_REQUESTED. */                  \
    STATE(S_PAUSED)                                                     \
                                                                        \
    /* We're waiting for a reply for our lock request.  Once we         \
     * get the reply:                                                   \
     *                                                                  \
     *   - If we did get the lock:                                      \
     *                                                                  \
     *       + If there are any output-only tables, send                \
     *         "transact" request for their data and transition         \
     *         to S_OUTPUT_ONLY_DATA_REQUESTED.                         \
     *                                                                  \
     *       + Otherwise, transition to S_MONITORING.                   \
     *                                                                  \
     *   - If we didn't get the lock, transition to S_LOCK_CONTENDED.   \
     *                                                                  \
     * (We must ignore notifications that we got or lost the lock       \
     * when we're in this state, because they must be old.) */          \
    STATE(S_LOCK_REQUESTED)                                             \
                                                                        \
    /* We got a negative reply to our lock request.  We're              \
     * waiting for a notification that we got the lock.                 \
     *                                                                  \
     * (It's important that we ignore notifications that we got         \
     * the lock when we're not in this state, because they must         \
     * be old.)                                                         \
     *                                                                  \
     * When we get the lock:                                            \
     *                                                                  \
     *   - If there are any output-only tables, send "transact"         \
     *     request for their data and transition to                     \
     *     S_OUTPUT_ONLY_DATA_REQUESTED.                                \
     *                                                                  \
     * - Otherwise, transition to S_MONITORING. */                      \
    STATE(S_LOCK_CONTENDED)                                             \
                                                                        \
    /* Waits for reply to "transact" request for data in output-only    \
     * tables.  Once received, uses the data to initialize the local    \
     * idea of what's in those tables, and transitions to               \
     * S_MONITORING.                                                    \
     *                                                                  \
     * If we get a notification that we lost the lock, transition       \
     * to S_LOCK_CONTENDED. */                                          \
    STATE(S_OUTPUT_ONLY_DATA_REQUESTED)                                 \
                                                                        \
    /* State that just processes "update" notifications for the         \
     * database.                                                        \
     *                                                                  \
     * If we get a notification that we lost the lock, transition       \
     * to S_LOCK_CONTENDED. */                                          \
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

struct northd_ctx {
    ddlog_prog ddlog;
    char *prefix;
    const char **input_relations;
    const char **output_relations;
    const char **output_only_relations;

    bool has_timestamp_columns;

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

    /* Database info. */
    char *db_name;
    struct json *monitor_id;
    struct json *schema;
    struct json *output_only_data;
    enum northd_monitoring monitoring;

    /* Database locking. */
    const char *lock_name;      /* Name of lock we need, NULL if none. */
    bool paused;
};

enum lock_status {
    NOT_LOCKED,      /* We don't have the lock and we didn't ask for it. */
    REQUESTED_LOCK,  /* We asked for the lock but we didn't get it yet. */
    HAS_LOCK,        /* We have the lock. */
};

static enum lock_status northd_lock_status(const struct northd_ctx *);

static void northd_send_unlock_request(struct northd_ctx *);

static bool northd_parse_lock_reply(const struct json *result);

static void northd_handle_update(struct northd_ctx *, bool clear,
                                 const struct json *table_updates);
static struct json *get_database_ops(struct northd_ctx *);
static int ddlog_clear(struct northd_ctx *);

static void
northd_ctx_connection_status(struct unixctl_conn *conn, int argc OVS_UNUSED,
                             const char *argv[] OVS_UNUSED, void *ctx_)
{
    const struct northd_ctx *ctx = ctx_;
    bool connected = jsonrpc_session_is_connected(ctx->session);
    unixctl_command_reply(conn, connected ? "connected" : "not connected");
}

static void
northd_ctx_cluster_state_reset(struct unixctl_conn *conn, int argc OVS_UNUSED,
                               const char *argv[] OVS_UNUSED, void *ctx OVS_UNUSED)
{
    VLOG_INFO("XXX cluster state tracking not yet implemented");
    unixctl_command_reply(conn, NULL);
}

static struct northd_ctx *
northd_ctx_create(const char *server, const char *database,
                  const char *unixctl_command_prefix,
                  const char *lock_name,
                  ddlog_prog ddlog,
                  const char **input_relations,
                  const char **output_relations,
                  const char **output_only_relations)
{
    struct northd_ctx *ctx;

    ctx = xzalloc(sizeof *ctx);
    ctx->prefix = xasprintf("%s::", database);
    ctx->session = jsonrpc_session_open(server, true);
    ctx->state_seqno = UINT_MAX;
    ctx->request_id = NULL;

    ctx->input_relations = input_relations;
    ctx->output_relations = output_relations;
    ctx->output_only_relations = output_only_relations;

    ctx->db_name = xstrdup(database);
    ctx->monitor_id = json_array_create_2(json_string_create("monid"),
                                               json_string_create(database));
    ctx->lock_name = lock_name;

    ctx->ddlog = ddlog;

    char *cmd = xasprintf("%s-connection-status", unixctl_command_prefix);
    unixctl_command_register(cmd, "", 0, 0,
                             northd_ctx_connection_status, ctx);
    free(cmd);

    cmd = xasprintf("%s-cluster-state-reset", unixctl_command_prefix);
    unixctl_command_register(cmd, "", 0, 0,
                             northd_ctx_cluster_state_reset, NULL);
    free(cmd);

    return ctx;
}

static void
northd_ctx_destroy(struct northd_ctx *ctx)
{
    if (ctx) {
        jsonrpc_session_close(ctx->session);

        json_destroy(ctx->monitor_id);
        json_destroy(ctx->schema);
        json_destroy(ctx->output_only_data);

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

#define northd_retry(CTX) northd_retry_at(CTX, OVS_SOURCE_LOCATOR)
static void
northd_retry_at(struct northd_ctx *ctx, const char *where)
{
    northd_send_unlock_request(ctx);

    if (ctx->session && jsonrpc_session_get_n_remotes(ctx->session) > 1) {
        northd_force_reconnect(ctx);
        northd_transition_at(ctx, S_RETRY, where);
    } else {
        northd_transition_at(ctx, S_ERROR, where);
    }
}

/* Returns true if 'ctx' is configured to obtain a lock and owns that lock.
 *
 * Locking and unlocking happens asynchronously from the database client's
 * point of view, so the information is only useful for optimization (e.g. if
 * the client doesn't have the lock then there's no point in trying to write to
 * the database). */
static enum lock_status
northd_lock_status(const struct northd_ctx *ctx)
{
    if (!ctx->lock_name) {
        return NOT_LOCKED;
    }

    switch (ctx->state) {
    case S_SCHEMA_REQUESTED:
    case S_MONITOR_REQUESTED:
    case S_PAUSED:
    case S_ERROR:
    case S_RETRY:
        return NOT_LOCKED;

    case S_LOCK_REQUESTED:
    case S_LOCK_CONTENDED:
        return REQUESTED_LOCK;

    case S_OUTPUT_ONLY_DATA_REQUESTED:
    case S_MONITORING:
        return HAS_LOCK;
    }

    OVS_NOT_REACHED();
}

static void
northd_send_request(struct northd_ctx *ctx, struct jsonrpc_msg *request)
{
    json_destroy(ctx->request_id);
    ctx->request_id = json_clone(request->id);
    if (ctx->session) {
        jsonrpc_session_send(ctx->session, request);
    }
}

static void
northd_send_schema_request(struct northd_ctx *ctx)
{
    northd_send_request(ctx, jsonrpc_create_request(
                             "get_schema",
                             json_array_create_1(json_string_create(
                                                     ctx->db_name)),
                             NULL));
}

static void
northd_send_transact(struct northd_ctx *ctx, struct json *ddlog_ops)
{
    struct json *comment = json_object_create();
    json_object_put_string(comment, "op", "comment");
    json_object_put_string(comment, "comment", "ovn-northd-ddlog");
    json_array_add(ddlog_ops, comment);

    if (ctx->lock_name) {
        struct json *assertion = json_object_create();
        json_object_put_string(assertion, "op", "assert");
        json_object_put_string(assertion, "lock", ctx->lock_name);
        json_array_add(ddlog_ops, assertion);
    }

    northd_send_request(ctx, jsonrpc_create_request("transact", ddlog_ops,
                                                    NULL));
}

static bool
northd_send_monitor_request(struct northd_ctx *ctx)
{
    struct ovsdb_schema *schema;
    struct ovsdb_error *error = ovsdb_schema_from_json(ctx->schema, &schema);
    if (error) {
        VLOG_ERR("couldn't parse schema (%s)", ovsdb_error_to_string(error));
        return false;
    }

    const struct ovsdb_table_schema *nb_global = shash_find_data(
        &schema->tables, "NB_Global");
    ctx->has_timestamp_columns
        = (nb_global
           && shash_find_data(&nb_global->columns, "nb_cfg_timestamp")
           && shash_find_data(&nb_global->columns, "sb_cfg_timestamp"));

    struct json *monitor_requests = json_object_create();

    /* This should be smarter about ignoring not needed ones.  There's a lot
     * more logic for this in ovsdb_idl_send_monitor_request(). */
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
            json_array_create_3(json_string_create(ctx->db_name),
                                json_clone(ctx->monitor_id), monitor_requests),
            NULL));
    return true;
}

/* Sends the database server a request for all the row UUIDs in output-only
 * tables. */
static void
northd_send_output_only_data_request(struct northd_ctx *ctx)
{
    json_destroy(ctx->output_only_data);
    ctx->output_only_data = NULL;

    struct json *ops = json_array_create_1(json_string_create(ctx->db_name));
    for (size_t i = 0; ctx->output_only_relations[i]; i++) {
        const char *table = ctx->output_only_relations[i];
        struct json *op = json_object_create();
        json_object_put_string(op, "op", "select");
        json_object_put_string(op, "table", table);
        json_object_put(op, "columns",
                        json_array_create_1(json_string_create("_uuid")));
        json_object_put(op, "where", json_array_create_empty());
        json_array_add(ops, op);
    }
    VLOG_WARN("sending output-only data request");

    northd_send_request(ctx,
                        jsonrpc_create_request("transact", ops, NULL));
}

static struct jsonrpc_msg *
northd_compose_lock_request__(struct northd_ctx *ctx, const char *method)
{
    struct json *params = json_array_create_1(json_string_create(
                                                  ctx->lock_name));
    return jsonrpc_create_request(method, params, NULL);
}

static void
northd_send_lock_request(struct northd_ctx *ctx)
{
    northd_send_request(ctx, northd_compose_lock_request__(ctx, "lock"));
}

/* This sends an unlock request, if 'ctx' has a defined lock and
 * is in a state that holds a lock or has requested a lock.
 *
 * When this sends an unlock request, the caller needs to
 * transition 'ctx' to some other state (because otherwise the
 * current state is still defined as holding or requesting a
 * lock). */
static void
northd_send_unlock_request(struct northd_ctx *ctx)
{
    if (ctx->lock_name && northd_lock_status(ctx) != NOT_LOCKED) {
        northd_send_request(ctx, northd_compose_lock_request__(ctx, "unlock"));

        /* We don't care to track the unlock reply. */
        free(ctx->request_id);
        ctx->request_id = NULL;
    }
}

static bool
northd_process_response(struct northd_ctx *ctx, struct jsonrpc_msg *msg)
{
    if (msg->type != JSONRPC_REPLY && msg->type != JSONRPC_ERROR) {
        return false;
    }

    if (!json_equal(ctx->request_id, msg->id)) {
        return false;
    }
    json_destroy(ctx->request_id);
    ctx->request_id = NULL;

    if (msg->type == JSONRPC_ERROR) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        char *s = jsonrpc_msg_to_string(msg);
        VLOG_INFO_RL(&rl, "%s: received unexpected %s response in "
                     "%s state: %s", jsonrpc_session_get_name(ctx->session),
                     jsonrpc_msg_type_to_string(msg->type),
                     northd_state_to_string(ctx->state),
                     s);
        free(s);
        northd_retry(ctx);
        return true;
    }

    switch (ctx->state) {
    case S_SCHEMA_REQUESTED:
        json_destroy(ctx->schema);
        ctx->schema = json_clone(msg->result);
        if (northd_send_monitor_request(ctx)) {
            northd_transition(ctx, S_MONITOR_REQUESTED);
        } else {
            northd_retry(ctx);
        }
        break;

    case S_MONITOR_REQUESTED:
        ctx->monitoring = NORTHD_MONITORING;
        northd_handle_update(ctx, true, msg->result);
        if (ctx->paused) {
            northd_transition(ctx, S_PAUSED);
        } else if (ctx->lock_name) {
            northd_send_lock_request(ctx);
            northd_transition(ctx, S_LOCK_REQUESTED);
        } else if (ctx->output_only_relations[0]) {
            northd_send_output_only_data_request(ctx);
            northd_transition(ctx, S_OUTPUT_ONLY_DATA_REQUESTED);
        } else {
            northd_transition(ctx, S_MONITORING);
        }
        break;

    case S_PAUSED:
        /* (No outstanding requests.) */
        break;

    case S_LOCK_REQUESTED:
        if (northd_parse_lock_reply(msg->result)) {
            /* We got the lock. */
            if (ctx->output_only_relations[0]) {
                northd_send_output_only_data_request(ctx);
                northd_transition(ctx, S_OUTPUT_ONLY_DATA_REQUESTED);
            } else {
                northd_transition(ctx, S_MONITORING);
            }
        } else {
            /* We did not get the lock. */
            northd_transition(ctx, S_LOCK_CONTENDED);
        }
        break;

    case S_LOCK_CONTENDED:
        /* (No outstanding requests.) */
        break;

    case S_OUTPUT_ONLY_DATA_REQUESTED:
        ctx->output_only_data = msg->result;
        msg->result = NULL;
        northd_transition(ctx, S_MONITORING);
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

    return true;
}

static bool
northd_handle_update_rpc(struct northd_ctx *ctx,
                         const struct jsonrpc_msg *msg)
{
    if (msg->type == JSONRPC_NOTIFY) {
        if (!strcmp(msg->method, "update")
            && msg->params->type == JSON_ARRAY
            && msg->params->array.n == 2
            && json_equal(msg->params->array.elems[0], ctx->monitor_id)) {
            northd_handle_update(ctx, false, msg->params->array.elems[1]);
            return true;
        }
    }
    return false;
}

static void
northd_pause(struct northd_ctx *ctx)
{
    if (!ctx->paused && ctx->lock_name && ctx->state != S_PAUSED) {
        ctx->paused = true;
        VLOG_INFO("This ovn-northd instance is now paused.");
        if (northd_lock_status(ctx) != NOT_LOCKED) {
            northd_send_unlock_request(ctx);
        }
        if (ctx->state > S_PAUSED) {
            northd_transition(ctx, S_PAUSED);
        }
    }
}

static void
northd_unpause(struct northd_ctx *ctx)
{
    if (ctx->paused) {
        ovs_assert(ctx->lock_name);

        switch (ctx->state) {
        case S_SCHEMA_REQUESTED:
        case S_MONITOR_REQUESTED:
            /* Nothing to do. */
            break;

        case S_PAUSED:
            northd_send_lock_request(ctx);
            northd_transition(ctx, S_LOCK_REQUESTED);
            break;

        case S_LOCK_REQUESTED:
        case S_LOCK_CONTENDED:
        case S_OUTPUT_ONLY_DATA_REQUESTED:
        case S_MONITORING:
        case S_ERROR:
        case S_RETRY:
            OVS_NOT_REACHED();
        }

        ctx->paused = false;
    }

}

static bool
northd_process_lock_notify(struct northd_ctx *ctx,
                           const struct jsonrpc_msg *msg)
{
    if (msg->type != JSONRPC_NOTIFY) {
        return false;
    }

    int got_lock = (!strcmp(msg->method, "locked") ? true
                    : !strcmp(msg->method, "stolen") ? false
                    : -1);
    if (got_lock < 0) {
        return false;
    }

    if (!ctx->lock_name
        || msg->params->type != JSON_ARRAY
        || json_array(msg->params)->n != 1
        || json_array(msg->params)->elems[0]->type != JSON_STRING) {
        return false;
    }

    const char *lock_name = json_string(json_array(msg->params)->elems[0]);
    if (strcmp(ctx->lock_name, lock_name)) {
        return false;
    }

    switch (ctx->state) {
    case S_SCHEMA_REQUESTED:
    case S_MONITOR_REQUESTED:
    case S_PAUSED:
    case S_LOCK_REQUESTED:
    case S_ERROR:
    case S_RETRY:
        /* Ignore lock notification.  It must be stale, resulting
         * from an old "lock" request. */
        VLOG_DBG("received stale lock notification \"%s\" in state %s",
                 msg->method, northd_state_to_string(ctx->state));
        return true;

    case S_LOCK_CONTENDED:
        if (got_lock) {
            if (ctx->output_only_relations[0]) {
                northd_send_output_only_data_request(ctx);
                northd_transition(ctx, S_OUTPUT_ONLY_DATA_REQUESTED);
            } else {
                northd_transition(ctx, S_MONITORING);
            }
        } else {
            /* Should not be possible: we know that we received a
             * reply to our lock request, which means that there
             * should be no outstanding stale lock
             * notifications. */
            VLOG_WARN("\"stolen\" notification in LOCK_CONTENDED state");
        }
        return true;

    case S_OUTPUT_ONLY_DATA_REQUESTED:
    case S_MONITORING:
        if (!got_lock) {
            VLOG_INFO("northd lock stolen by another client");
            northd_transition(ctx, S_LOCK_CONTENDED);
        } else {
            /* Should not be possible: we already had the * lock. */
            VLOG_WARN("\"locked\" notification in %s state",
                      northd_state_to_string(ctx->state));
        }
        return true;
    }
    OVS_NOT_REACHED();
}

static bool
northd_parse_lock_reply(const struct json *result)
{
    if (result->type == JSON_OBJECT) {
        const struct json *locked
            = shash_find_data(json_object(result), "locked");
        return locked && locked->type == JSON_TRUE;
    } else {
        return false;
    }
}

static void
northd_process_msg(struct northd_ctx *ctx, struct jsonrpc_msg *msg)
{
    if (!northd_process_response(ctx, msg)
        && !northd_process_lock_notify(ctx, msg)
        && !northd_handle_update_rpc(ctx, msg)) {
        /* Unknown message.  Log at debug level because this can
         * happen if northd_txn_destroy() is called to destroy a
         * transaction before we receive the reply, or in other
         * corner cases. */
        char *s = jsonrpc_msg_to_string(msg);
        VLOG_DBG("%s: received unexpected %s message: %s",
                 jsonrpc_session_get_name(ctx->session),
                 jsonrpc_msg_type_to_string(msg->type), s);
        free(s);
    }
}

/* Processes a batch of messages from the database server on 'ctx'. */
static void
northd_run(struct northd_ctx *ctx, bool run_deltas)
{
    if (!ctx->session) {
        return;
    }

    for (int i = 0; jsonrpc_session_is_connected(ctx->session) && i < 50;
         i++) {
        struct jsonrpc_msg *msg;
        unsigned int seqno;

        seqno = jsonrpc_session_get_seqno(ctx->session);
        if (ctx->state_seqno != seqno) {
            ctx->state_seqno = seqno;

            if (ctx->state != S_PAUSED) {
                northd_send_schema_request(ctx);
                ctx->state = S_SCHEMA_REQUESTED;
            }
        }

        msg = jsonrpc_session_recv(ctx->session);
        if (!msg) {
            break;
        }
        northd_process_msg(ctx, msg);
        jsonrpc_msg_destroy(msg);
    }
    jsonrpc_session_run(ctx->session);

    if (run_deltas && !ctx->request_id) {
        struct json *ops = get_database_ops(ctx);
        if (ops) {
            northd_send_transact(ctx, ops);
        }
    }
}

static void
northd_update_probe_interval_cb(
    uintptr_t probe_intervalp_,
    table_id table OVS_UNUSED,
    const ddlog_record *rec,
    ssize_t weight OVS_UNUSED)
{
    int *probe_intervalp = (int *) probe_intervalp_;

    uint64_t x = ddlog_get_u64(rec);
    if (x > 1000) {
        *probe_intervalp = x;
    }
}

static void
set_probe_interval(struct jsonrpc_session *session, int override_interval)
{
#define DEFAULT_PROBE_INTERVAL_MSEC 5000
    const char *name = jsonrpc_session_get_name(session);
    int default_interval = (!stream_or_pstream_needs_probes(name)
                            ? 0 : DEFAULT_PROBE_INTERVAL_MSEC);
    jsonrpc_session_set_probe_interval(session,
                                       MAX(override_interval, default_interval));
}

static void
northd_update_probe_interval(struct northd_ctx *nb, struct northd_ctx *sb)
{
    /* -1 means the default probe interval. */
    int probe_interval = -1;
    table_id tid = ddlog_get_table_id("Northd_Probe_Interval");
    ddlog_delta *probe_delta = ddlog_delta_get_table(delta, tid);
    ddlog_delta_enumerate(probe_delta, northd_update_probe_interval_cb, (uintptr_t) &probe_interval);

    set_probe_interval(nb->session, probe_interval);
    set_probe_interval(sb->session, probe_interval);
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

/* Generate OVSDB update command for a output-only table. */
static void
ddlog_table_update_output(struct ds *ds, ddlog_prog ddlog,
                          const char *db, const char *table)
{
    int error;
    char *updates;

    error = ddlog_dump_ovsdb_output_table(ddlog, delta, db, table, &updates);
    if (error) {
        VLOG_WARN("%s: failed to generate update commands for "
                  "output-only table (error %d)", table, error);
        return;
    }
    char *table_name = xasprintf("%s::Out_%s", db, table);
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

/* A set of UUIDs.
 *
 * Not fully abstracted: the client still uses plain struct hmap, for
 * example. */

/* A node within a set of uuids. */
struct uuidset_node {
    struct hmap_node hmap_node;
    struct uuid uuid;
};

static void uuidset_delete(struct hmap *uuidset, struct uuidset_node *);

static void
uuidset_destroy(struct hmap *uuidset)
{
    if (uuidset) {
        struct uuidset_node *node, *next;

        HMAP_FOR_EACH_SAFE (node, next, hmap_node, uuidset) {
            uuidset_delete(uuidset, node);
        }
        hmap_destroy(uuidset);
    }
}

static struct uuidset_node *
uuidset_find(struct hmap *uuidset, const struct uuid *uuid)
{
    struct uuidset_node *node;

    HMAP_FOR_EACH_WITH_HASH (node, hmap_node, uuid_hash(uuid), uuidset) {
        if (uuid_equals(uuid, &node->uuid)) {
            return node;
        }
    }

    return NULL;
}

static void
uuidset_insert(struct hmap *uuidset, const struct uuid *uuid)
{
    if (!uuidset_find(uuidset, uuid)) {
        struct uuidset_node *node = xmalloc(sizeof *node);
        node->uuid = *uuid;
        hmap_insert(uuidset, &node->hmap_node, uuid_hash(&node->uuid));
    }
}

static void
uuidset_delete(struct hmap *uuidset, struct uuidset_node *node)
{
    hmap_remove(uuidset, &node->hmap_node);
    free(node);
}

static struct ovsdb_error *
parse_output_only_data(const struct json *txn_result, size_t index,
                       struct hmap *uuidset)
{
    if (txn_result->type != JSON_ARRAY || txn_result->array.n <= index) {
        return ovsdb_syntax_error(txn_result, NULL,
                                  "transaction result missing for "
                                  "output-only relation %"PRIuSIZE, index);
    }

    struct ovsdb_parser p;
    ovsdb_parser_init(&p, txn_result->array.elems[0], "select result");
    const struct json *rows = ovsdb_parser_member(&p, "rows", OP_ARRAY);
    struct ovsdb_error *error = ovsdb_parser_finish(&p);
    if (error) {
        return error;
    }

    for (size_t i = 0; i < rows->array.n; i++) {
        const struct json *row = rows->array.elems[i];

        ovsdb_parser_init(&p, row, "row");
        const struct json *uuid = ovsdb_parser_member(&p, "_uuid", OP_ARRAY);
        error = ovsdb_parser_finish(&p);
        if (error) {
            return error;
        }

        struct ovsdb_base_type base_type = OVSDB_BASE_UUID_INIT;
        union ovsdb_atom atom;
        error = ovsdb_atom_from_json(&atom, &base_type, uuid, NULL);
        if (error) {
            return error;
        }
        uuidset_insert(uuidset, &atom.uuid);
    }

    return NULL;
}

static bool
get_ddlog_uuid(const ddlog_record *rec, struct uuid *uuid)
{
    if (!ddlog_is_int(rec)) {
        return false;
    }

    __uint128_t u128 = ddlog_get_u128(rec);
    uuid->parts[0] = u128 >> 96;
    uuid->parts[1] = u128 >> 64;
    uuid->parts[2] = u128 >> 32;
    uuid->parts[3] = u128;
    return true;
}

struct dump_index_data {
    ddlog_prog prog;
    struct hmap *rows_present;
    const char *table;
    struct ds *ops_s;
};

static void OVS_UNUSED
index_cb(uintptr_t data_, const ddlog_record *rec)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
    struct dump_index_data *data = (struct dump_index_data *) data_;

    /* Extract the rec's row UUID as 'uuid'. */
    const ddlog_record *rec_uuid = ddlog_get_named_struct_field(rec, "_uuid");
    if (!rec_uuid) {
        VLOG_WARN_RL(&rl, "%s: row has no _uuid column", data->table);
        return;
    }
    struct uuid uuid;
    if (!get_ddlog_uuid(rec_uuid, &uuid)) {
        VLOG_WARN_RL(&rl, "%s: _uuid column has unexpected type", data->table);
        return;
    }

    /* If a row with the given UUID was already in the database, then
     * send a operation to update it; otherwise, send an operation to
     * insert it.  */
    struct uuidset_node *node = uuidset_find(data->rows_present, &uuid);
    char *s = NULL;
    int ret;
    if (node) {
        uuidset_delete(data->rows_present, node);
        ret = ddlog_into_ovsdb_update_str(data->prog, data->table, rec, &s);
    } else {
        ret = ddlog_into_ovsdb_insert_str(data->prog, data->table, rec, &s);
    }
    if (ret) {
        VLOG_WARN_RL(&rl, "%s: ddlog could not convert row into database op",
                     data->table);
        return;
    }
    ds_put_format(data->ops_s, "%s,", s);
    ddlog_free_json(s);
}

static struct json *
where_uuid_equals(const struct uuid *uuid)
{
    return
        json_array_create_1(
            json_array_create_3(
                json_string_create("_uuid"),
                json_string_create("=="),
                json_array_create_2(
                    json_string_create("uuid"),
                    json_string_create_nocopy(
                        xasprintf(UUID_FMT, UUID_ARGS(uuid))))));
}

static void
add_delete_row_op(const char *table, const struct uuid *uuid, struct ds *ops_s)
{
    struct json *op = json_object_create();
    json_object_put_string(op, "op", "delete");
    json_object_put_string(op, "table", table);
    json_object_put(op, "where", where_uuid_equals(uuid));
    json_to_ds(op, 0, ops_s);
    json_destroy(op);
    ds_put_char(ops_s, ',');
}

static void
northd_update_sb_cfg_cb(
    uintptr_t new_sb_cfgp_,
    table_id table OVS_UNUSED,
    const ddlog_record *rec,
    ssize_t weight)
{
    int64_t *new_sb_cfgp = (int64_t *) new_sb_cfgp_;

    if (weight < 0) {
        return;
    }

    if (ddlog_get_int(rec, NULL, 0) <= sizeof *new_sb_cfgp) {
        *new_sb_cfgp = ddlog_get_i64(rec);
    }
}

static struct json *
get_database_ops(struct northd_ctx *ctx)
{
    struct ds ops_s = DS_EMPTY_INITIALIZER;
    ds_put_char(&ops_s, '[');
    json_string_escape(ctx->db_name, &ops_s);
    ds_put_char(&ops_s, ',');
    size_t start_len = ops_s.length;

    for (const char **p = ctx->output_relations; *p; p++) {
        ddlog_table_update_deltas(&ops_s, ctx->ddlog, ctx->db_name, *p);
    }

    if (ctx->output_only_data) {
        /*
         * We just reconnected to the database (or connected for the first time
         * in this execution).  We assume that the contents of the output-only
         * tables might have changed (this is especially true the first time we
         * connect to the database a given execution, of course; we can't
         * assume that the tables have any particular contents in this case).
         *
         * ctx->output_only_data is a database reply that tells us the
         * UUIDs of the rows that exist in the database.  Our strategy is to
         * compare these UUIDs to the UUIDs of the rows that exist in the DDlog
         * analogues of these tables, and then add, delete, or update rows as
         * necessary.
         *
         * (ctx->output_only_data only gives row UUIDs, not full row
         * contents.  That means that for rows that exist in OVSDB and in
         * DDLog, we always send an update to set all the columns.  It wouldn't
         * save bandwidth to do anything else, since we'd always have to send
         * the full row contents in one direction and if there were differences
         * we'd have to send the contents in both directions.  With this
         * strategy we only send them in one direction even in the worst case.)
         *
         * (We can't just send an operation to delete all the rows and then
         * re-add them all in the same transaction, because ovsdb-server
         * rejecting deleting a row with a given UUID and the adding the same
         * UUID back in a single transaction.)
         */
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 2);

        for (size_t i = 0; ctx->output_only_relations[i]; i++) {
            const char *table = ctx->output_only_relations[i];

            /* Parse the list of row UUIDs received from OVSDB. */
            struct hmap rows_present = HMAP_INITIALIZER(&rows_present);
            struct ovsdb_error *error = parse_output_only_data(
                ctx->output_only_data, i, &rows_present);
            if (error) {
                char *s = ovsdb_error_to_string_free(error);
                VLOG_WARN_RL(&rl, "%s", s);
                free(s);
                uuidset_destroy(&rows_present);
                continue;
            }

            /* Get the index_id for the DDlog table.
             *
             * We require output-only tables to have an accompanying index
             * named <table>_Index. */
            char *index = xasprintf("%s_Index", table);
            index_id idxid = ddlog_get_index_id(index);
            if (idxid == -1) {
                VLOG_WARN_RL(&rl, "%s: unknown index", index);
                free(index);
                uuidset_destroy(&rows_present);
                continue;
            }
            free(index);

            /* For each row in the index, update a corresponding OVSDB row, if
             * there is one, otherwise insert a new row. */
            struct dump_index_data cbdata = {
                ctx->ddlog, &rows_present, table, &ops_s
            };
            ddlog_dump_index(ctx->ddlog, idxid, index_cb, (uintptr_t) &cbdata);

            /* Any uuids remaining in 'rows_present' are rows that are in OVSDB
             * but not DDlog.  Delete them from OVSDB. */
            struct uuidset_node *node;
            HMAP_FOR_EACH (node, hmap_node, &rows_present) {
                add_delete_row_op(table, &node->uuid, &ops_s);
            }
            uuidset_destroy(&rows_present);

            /* Discard any queued output to this table, since we just
             * did a full sync to it. */
            struct ds tmp = DS_EMPTY_INITIALIZER;
            ddlog_table_update_output(&tmp, ctx->ddlog, ctx->db_name, table);
            ds_destroy(&tmp);
        }

        json_destroy(ctx->output_only_data);
        ctx->output_only_data = NULL;
    } else {
        for (const char **p = ctx->output_only_relations; *p; p++) {
            ddlog_table_update_output(&ops_s, ctx->ddlog, ctx->db_name, *p);
        }
    }

    /* If we're updating nb::NB_Global.sb_cfg, then also update
     * sb_cfg_timestamp.
     *
     * XXX If the transaction we're sending to the database fails, then
     * currently as written we'll never find out about it and sb_cfg_timestamp
     * will not be updated.
     */
    static int64_t old_sb_cfg = INT64_MIN;
    static int64_t old_sb_cfg_timestamp = INT64_MIN;
    int64_t new_sb_cfg = old_sb_cfg;
    if (ctx->has_timestamp_columns) {
        table_id sb_cfg_tid = ddlog_get_table_id("SbCfg");
        ddlog_delta *sb_cfg_delta = ddlog_delta_get_table(delta, sb_cfg_tid);
        ddlog_delta_enumerate(sb_cfg_delta, northd_update_sb_cfg_cb,
                              (uintptr_t) &new_sb_cfg);
        ddlog_free_delta(sb_cfg_delta);

        if (new_sb_cfg != old_sb_cfg) {
            old_sb_cfg = new_sb_cfg;
            old_sb_cfg_timestamp = time_wall_msec();
            ds_put_format(&ops_s, "{\"op\":\"update\",\"table\":\"NB_Global\",\"where\":[],"
                          "\"row\":{\"sb_cfg_timestamp\":%"PRId64"}},", old_sb_cfg_timestamp);
        }
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

static void
warning_cb(uintptr_t arg OVS_UNUSED,
           table_id table OVS_UNUSED,
           const ddlog_record *rec,
           ssize_t weight)
{
    size_t len;
    const char *s = ddlog_get_str_with_length(rec, &len);
    if (weight > 0) {
        VLOG_WARN("New warning: %.*s", (int)len, s);
    } else {
        VLOG_WARN("Warning cleared: %.*s", (int)len, s);
    }
}

static int
ddlog_commit(ddlog_prog ddlog)
{
    ddlog_delta *new_delta = ddlog_transaction_commit_dump_changes(ddlog);
    if (!delta) {
        VLOG_WARN("Transaction commit failed");
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

static const struct json *
json_object_get(const struct json *json, const char *member_name)
{
    return (json && json->type == JSON_OBJECT
            ? shash_find_data(json_object(json), member_name)
            : NULL);
}

/* Returns the new value of NB_Global::nb_cfg, if any, from the updates in
 * <table-updates> provided by the caller, or INT64_MIN if none is present. */
static int64_t
get_nb_cfg(const struct json *table_updates)
{
    const struct json *nb_global = json_object_get(table_updates, "NB_Global");
    if (nb_global) {
        struct shash_node *row;
        SHASH_FOR_EACH (row, json_object(nb_global)) {
            const struct json *value = row->data;
            const struct json *new = json_object_get(value, "new");
            const struct json *nb_cfg = json_object_get(new, "nb_cfg");
            if (nb_cfg && nb_cfg->type == JSON_INTEGER) {
                return json_integer(nb_cfg);
            }
        }
    }
    return INT64_MIN;
}

static void
northd_handle_update(struct northd_ctx *ctx, bool clear,
                     const struct json *table_updates)
{
    if (!table_updates) {
        return;
    }

    if (ddlog_transaction_start(ctx->ddlog)) {
        VLOG_WARN("DDlog failed to start transaction");
        return;
    }

    if (clear && ddlog_clear(ctx)) {
        goto error;
    }
    char *updates_s = json_to_string(table_updates, 0);
    if (ddlog_apply_ovsdb_updates(ctx->ddlog, ctx->prefix, updates_s)) {
        VLOG_WARN("DDlog failed to apply updates");
        free(updates_s);
        goto error;
    }
    free(updates_s);

    /* Whenever a new 'nb_cfg' value comes in, take the current time and push
     * it into the NbCfgTimestamp relation for the DDlog program to put into
     * nb::NB_Global.nb_cfg_timestamp. */
    static int64_t old_nb_cfg = INT64_MIN;
    static int64_t old_nb_cfg_timestamp = INT64_MIN;
    int64_t new_nb_cfg = old_nb_cfg;
    int64_t new_nb_cfg_timestamp = old_nb_cfg_timestamp;
    if (ctx->has_timestamp_columns) {
        new_nb_cfg = get_nb_cfg(table_updates);
        if (new_nb_cfg == INT64_MIN) {
            new_nb_cfg = old_nb_cfg == INT64_MIN ? 0 : old_nb_cfg;
        }
        if (new_nb_cfg != old_nb_cfg) {
            new_nb_cfg_timestamp = time_wall_msec();

            ddlog_cmd *updates[2];
            int n_updates = 0;
            if (old_nb_cfg_timestamp != INT64_MIN) {
                updates[n_updates++] = ddlog_delete_val_cmd(
                    NB_CFG_TIMESTAMP_ID, ddlog_i64(old_nb_cfg_timestamp));
            }
            updates[n_updates++] = ddlog_insert_cmd(
                NB_CFG_TIMESTAMP_ID, ddlog_i64(new_nb_cfg_timestamp));
            if (ddlog_apply_updates(ctx->ddlog, updates, n_updates) < 0) {
                goto error;
            }
        }
    }

    /* Commit changes to DDlog. */
    if (ddlog_commit(ctx->ddlog)) {
        goto error;
    }
    old_nb_cfg = new_nb_cfg;
    old_nb_cfg_timestamp = new_nb_cfg_timestamp;

    /* This update may have implications for the other side, so
     * immediately wake to check for more changes to be applied. */
    poll_immediate_wake();

    return;

error:
    ddlog_transaction_rollback(ctx->ddlog);
}

static int
ddlog_clear(struct northd_ctx *ctx)
{
    int n_failures = 0;
    for (int i = 0; ctx->input_relations[i]; i++) {
        char *table = xasprintf("%s%s", ctx->prefix, ctx->input_relations[i]);
        if (ddlog_clear_relation(ctx->ddlog, ddlog_get_table_id(table))) {
            n_failures++;
        }
        free(table);
    }
    if (n_failures) {
        VLOG_WARN("failed to clear %d tables in %s database",
                  n_failures, ctx->db_name);
    }
    return n_failures;
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
        .locked = false,
        .pause = false,
    };
    unixctl_command_register("exit", "", 0, 0, ovn_northd_exit, &exiting);
    unixctl_command_register("status", "", 0, 0, ovn_northd_status, &status);


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
        ovnnb_db, "OVN_Northbound", "nb", NULL, ddlog,
        nb_input_relations, nb_output_relations, nb_output_only_relations);
    struct northd_ctx *sb_ctx = northd_ctx_create(
        ovnsb_db, "OVN_Southbound", "sb", "ovn_northd", ddlog,
        sb_input_relations, sb_output_relations, sb_output_only_relations);

    unixctl_command_register("pause", "", 0, 0, ovn_northd_pause, sb_ctx);
    unixctl_command_register("resume", "", 0, 0, ovn_northd_resume, sb_ctx);
    unixctl_command_register("is-paused", "", 0, 0, ovn_northd_is_paused,
                             sb_ctx);

    daemonize_complete();

    /* Main loop. */
    exiting = false;
    while (!exiting) {
        bool has_lock = northd_lock_status(sb_ctx) == HAS_LOCK;
        if (!sb_ctx->paused) {
            if (has_lock && !status.locked) {
                VLOG_INFO("ovn-northd lock acquired. "
                          "This ovn-northd instance is now active.");
            } else if (!has_lock && status.locked) {
                VLOG_INFO("ovn-northd lock lost. "
                          "This ovn-northd instance is now on standby.");
            }
        }
        status.locked = has_lock;
        status.pause = sb_ctx->paused;

        bool run_deltas = (northd_lock_status(sb_ctx) == HAS_LOCK &&
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
                const char *argv[] OVS_UNUSED, void *sb_ctx_)
{
    struct northd_ctx *sb_ctx = sb_ctx_;
    northd_pause(sb_ctx);
    unixctl_command_reply(conn, NULL);
}

static void
ovn_northd_resume(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *sb_ctx_)
{
    struct northd_ctx *sb_ctx = sb_ctx_;
    northd_unpause(sb_ctx);
    unixctl_command_reply(conn, NULL);
}

static void
ovn_northd_is_paused(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[] OVS_UNUSED, void *sb_ctx_)
{
    struct northd_ctx *sb_ctx = sb_ctx_;
    if (sb_ctx->paused) {
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

    if (status->pause) {
        status_string = "paused";
    } else {
        status_string = status->locked ? "active" : "standby";
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
