/*
 * Copyright (c) 2014, 2016, 2017 Nicira, Inc.
 *
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

#include "raft-rpc.h"
#include <stdlib.h>
#include <string.h>
#include "compiler.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "openvswitch/json.h"
#include "openvswitch/vlog.h"
#include "sset.h"

VLOG_DEFINE_THIS_MODULE(raft_rpc);

const char *
raft_rpc_type_to_string(enum raft_rpc_type status)
{
    switch (status) {
#define RAFT_RPC(ENUM, NAME) case ENUM: return #NAME;
        RAFT_RPC_TYPES
#undef RAFT_RPC
            }
    return "<unknown>";
}

bool
raft_rpc_type_from_string(const char *s, enum raft_rpc_type *status)
{
#define RAFT_RPC(ENUM, NAME)                    \
    if (!strcmp(s, #NAME)) {                    \
        *status = ENUM;                         \
        return true;                            \
    }
    RAFT_RPC_TYPES
#undef RAFT_RPC
        return false;
}

#define RAFT_RPC(ENUM, NAME)                                            \
    static void raft_##NAME##_destroy(struct raft_##NAME *);            \
    static void raft_##NAME##_to_jsonrpc(const struct raft_##NAME *,    \
                                         struct json *);                \
    static void raft_##NAME##_from_jsonrpc(struct ovsdb_parser *,       \
                                           struct raft_##NAME *);
RAFT_RPC_TYPES
#undef RAFT_RPC

static void
raft_hello_request_destroy(struct raft_hello_request *rq OVS_UNUSED)
{
}

static void
raft_append_request_destroy(struct raft_append_request *rq)
{
    for (size_t i = 0; i < rq->n_entries; i++) {
        json_destroy(rq->entries[i].data);
    }
    free(rq->entries);
}

static void
raft_append_reply_destroy(struct raft_append_reply *rpy OVS_UNUSED)
{
}

static void
raft_vote_request_destroy(struct raft_vote_request *rq OVS_UNUSED)
{
}

static void
raft_vote_reply_destroy(struct raft_vote_reply *rpy OVS_UNUSED)
{
}

static void
raft_add_server_request_destroy(struct raft_add_server_request *rq)
{
    free(rq->address);
}

static void
raft_add_server_reply_destroy(struct raft_add_server_reply *rpy)
{
    sset_destroy(&rpy->remotes);
}

static void
raft_remove_server_reply_destroy(
    struct raft_remove_server_reply *rpy OVS_UNUSED)
{
}

static void
raft_install_snapshot_request_destroy(
    struct raft_install_snapshot_request *rq)
{
    json_destroy(rq->last_servers);
    json_destroy(rq->data);
}

static void
raft_install_snapshot_reply_destroy(
    struct raft_install_snapshot_reply *rpy OVS_UNUSED)
{
}

static void
raft_execute_command_request_destroy(
    struct raft_execute_command_request *rq)
{
    json_destroy(rq->data);
}

static void
raft_execute_command_reply_destroy(
    struct raft_execute_command_reply *rpy OVS_UNUSED)
{
}

static void
raft_remove_server_request_destroy(
    struct raft_remove_server_request *rq OVS_UNUSED)
{
}

static void
raft_become_leader_destroy(struct raft_become_leader *rpc OVS_UNUSED)
{
}

static void
raft_hello_request_to_jsonrpc(const struct raft_hello_request *rq OVS_UNUSED,
                              struct json *args OVS_UNUSED)
{
}

static void
raft_hello_request_from_jsonrpc(struct ovsdb_parser *p OVS_UNUSED,
                                struct raft_hello_request *rq OVS_UNUSED)
{
}

const char *
raft_append_result_to_string(enum raft_append_result result)
{
    switch (result) {
    case RAFT_APPEND_OK:
        return "OK";
    case RAFT_APPEND_INCONSISTENCY:
        return "inconsistency";
    case RAFT_APPEND_IO_ERROR:
        return "I/O error";
    default:
        return NULL;
    }
}

bool
raft_append_result_from_string(const char *s, enum raft_append_result *resultp)
{
    for (enum raft_append_result result = 0; ; result++) {
        const char *s2 = raft_append_result_to_string(result);
        if (!s2) {
            *resultp = 0;
            return false;
        } else if (!strcmp(s, s2)) {
            *resultp = result;
            return true;
        }
    }
}

static void
raft_append_request_to_jsonrpc(const struct raft_append_request *rq,
                               struct json *args)
{
    json_object_put_uint(args, "term", rq->term);
    json_object_put_uint(args, "prev_log_index", rq->prev_log_index);
    json_object_put_uint(args, "prev_log_term", rq->prev_log_term);
    json_object_put_uint(args, "leader_commit", rq->leader_commit);

    struct json **entries = xmalloc(rq->n_entries * sizeof *entries);
    for (size_t i = 0; i < rq->n_entries; i++) {
        entries[i] = raft_entry_to_json(&rq->entries[i]);
    }
    json_object_put(args, "log", json_array_create(entries, rq->n_entries));
}

static void
raft_append_request_from_jsonrpc(struct ovsdb_parser *p,
                                 struct raft_append_request *rq)
{
    rq->term = raft_parse_uint(p, "term");
    rq->prev_log_index = raft_parse_uint(p, "prev_log_index");
    rq->prev_log_term = raft_parse_uint(p, "prev_log_term");
    rq->leader_commit = raft_parse_uint(p, "leader_commit");

    const struct json *log = ovsdb_parser_member(p, "log", OP_ARRAY);
    if (!log) {
        return;
    }
    const struct json_array *entries = json_array(log);
    rq->entries = xmalloc(entries->n * sizeof *rq->entries);
    rq->n_entries = 0;
    for (size_t i = 0; i < entries->n; i++) {
        struct ovsdb_error *error = raft_entry_from_json(entries->elems[i],
                                                         &rq->entries[i]);
        if (error) {
            ovsdb_parser_put_error(p, error);
            break;
        }
        rq->n_entries++;
    }
}

static void
raft_append_reply_to_jsonrpc(const struct raft_append_reply *rpy,
                             struct json *args)
{
    json_object_put_uint(args, "term", rpy->term);
    json_object_put_uint(args, "log_end", rpy->log_end);
    json_object_put_uint(args, "prev_log_index", rpy->prev_log_index);
    json_object_put_uint(args, "prev_log_term", rpy->prev_log_term);
    json_object_put_uint(args, "n_entries", rpy->n_entries);
    json_object_put_string(args, "result",
                           raft_append_result_to_string(rpy->result));
}

static void
raft_append_reply_from_jsonrpc(struct ovsdb_parser *p,
                               struct raft_append_reply *rpy)
{
    rpy->term = raft_parse_uint(p, "term");
    rpy->log_end = raft_parse_uint(p, "log_end");
    rpy->prev_log_index = raft_parse_uint(p, "prev_log_index");
    rpy->prev_log_term = raft_parse_uint(p, "prev_log_term");
    rpy->n_entries = raft_parse_uint(p, "n_entries");

    const char *result = raft_parse_required_string(p, "result");
    if (result && !raft_append_result_from_string(result, &rpy->result)) {
        ovsdb_parser_raise_error(p, "unknown result \"%s\"", result);
    }
}

static void
raft_vote_request_to_jsonrpc(const struct raft_vote_request *rq,
                             struct json *args)
{
    json_object_put_uint(args, "term", rq->term);
    json_object_put_uint(args, "last_log_index", rq->last_log_index);
    json_object_put_uint(args, "last_log_term", rq->last_log_term);
    if (rq->leadership_transfer) {
        json_object_put(args, "leadership_transfer",
                        json_boolean_create(true));
    }
}

static void
raft_vote_request_from_jsonrpc(struct ovsdb_parser *p,
                               struct raft_vote_request *rq)
{
    rq->term = raft_parse_uint(p, "term");
    rq->last_log_index = raft_parse_uint(p, "last_log_index");
    rq->last_log_term = raft_parse_uint(p, "last_log_term");
    rq->leadership_transfer
        = raft_parse_optional_boolean(p, "leadership_transfer") == 1;
}

static void
raft_vote_reply_to_jsonrpc(const struct raft_vote_reply *rpy,
                           struct json *args)
{
    json_object_put_uint(args, "term", rpy->term);
    json_object_put_format(args, "vote", UUID_FMT, UUID_ARGS(&rpy->vote));
}

static void
raft_vote_reply_from_jsonrpc(struct ovsdb_parser *p,
                             struct raft_vote_reply *rpy)
{
    rpy->term = raft_parse_uint(p, "term");
    rpy->vote = raft_parse_required_uuid(p, "vote");
}

static void
raft_add_server_reply_to_jsonrpc(const struct raft_add_server_reply *rpy,
                                 struct json *args)
{
    json_object_put(args, "success", json_boolean_create(rpy->success));
    if (!sset_is_empty(&rpy->remotes)) {
        json_object_put(args, "remotes", raft_remotes_to_json(&rpy->remotes));
    }
}

static void
raft_remove_server_reply_to_jsonrpc(const struct raft_remove_server_reply *rpy,
                                    struct json *args)
{
    json_object_put(args, "success", json_boolean_create(rpy->success));
}

static void
raft_add_server_reply_from_jsonrpc(struct ovsdb_parser *p,
                                   struct raft_add_server_reply *rpy)
{
    rpy->success = raft_parse_required_boolean(p, "success");

    sset_init(&rpy->remotes);
    const struct json *json = ovsdb_parser_member(p, "remotes",
                                                  OP_ARRAY | OP_OPTIONAL);
    if (json) {
        struct ovsdb_error *error = raft_remotes_from_json(json,
                                                           &rpy->remotes);
        if (error) {
            ovsdb_parser_put_error(p, error);
        }
    }
}

static void
raft_remove_server_reply_from_jsonrpc(struct ovsdb_parser *p,
                                      struct raft_remove_server_reply *rpy)
{
    rpy->success = raft_parse_required_boolean(p, "success");
}

static void
raft_install_snapshot_request_to_jsonrpc(
    const struct raft_install_snapshot_request *rq, struct json *args)
{
    json_object_put_uint(args, "term", rq->term);
    json_object_put_uint(args, "last_index", rq->last_index);
    json_object_put_uint(args, "last_term", rq->last_term);
    json_object_put(args, "last_servers", json_clone(rq->last_servers));

    json_object_put(args, "data", json_clone(rq->data));
}

static void
raft_install_snapshot_request_from_jsonrpc(
    struct ovsdb_parser *p, struct raft_install_snapshot_request *rq)
{
    rq->last_servers = json_nullable_clone(
        ovsdb_parser_member(p, "last_servers", OP_OBJECT));
    ovsdb_parser_put_error(p, raft_servers_validate_json(rq->last_servers));

    rq->term = raft_parse_uint(p, "term");
    rq->last_index = raft_parse_uint(p, "last_index");
    rq->last_term = raft_parse_uint(p, "last_term");

    rq->data = json_nullable_clone(
        ovsdb_parser_member(p, "data", OP_OBJECT | OP_ARRAY));
}

static void
raft_install_snapshot_reply_to_jsonrpc(
    const struct raft_install_snapshot_reply *rpy, struct json *args)
{
    json_object_put_uint(args, "term", rpy->term);
    json_object_put_uint(args, "last_index", rpy->last_index);
    json_object_put_uint(args, "last_term", rpy->last_term);
}

static void
raft_install_snapshot_reply_from_jsonrpc(
    struct ovsdb_parser *p,
    struct raft_install_snapshot_reply *rpy)
{
    rpy->term = raft_parse_uint(p, "term");
    rpy->last_index = raft_parse_uint(p, "last_index");
    rpy->last_term = raft_parse_uint(p, "last_term");
}

static void
raft_execute_command_request_to_jsonrpc(
    const struct raft_execute_command_request *rq, struct json *args)
{
    json_object_put(args, "data", json_clone(rq->data));
    json_object_put_format(args, "prereq", UUID_FMT, UUID_ARGS(&rq->prereq));
    json_object_put_format(args, "result", UUID_FMT, UUID_ARGS(&rq->result));
}

static void
raft_execute_command_request_from_jsonrpc(
    struct ovsdb_parser *p, struct raft_execute_command_request *rq)
{
    rq->data = json_nullable_clone(ovsdb_parser_member(p, "data",
                                                       OP_OBJECT | OP_ARRAY));
    rq->prereq = raft_parse_required_uuid(p, "prereq");
    rq->result = raft_parse_required_uuid(p, "result");
}

static void
raft_execute_command_reply_to_jsonrpc(
    const struct raft_execute_command_reply *rpy, struct json *args)
{
    json_object_put_format(args, "result", UUID_FMT, UUID_ARGS(&rpy->result));
    json_object_put_string(args, "status",
                           raft_command_status_to_string(rpy->status));
}

static void
raft_execute_command_reply_from_jsonrpc(
    struct ovsdb_parser *p, struct raft_execute_command_reply *rpy)
{
    rpy->result = raft_parse_required_uuid(p, "result");

    const char *status = raft_parse_required_string(p, "status");
    if (status && !raft_command_status_from_string(status, &rpy->status)) {
        ovsdb_parser_raise_error(p, "unknown status \"%s\"", status);
    }
}

static void
raft_add_server_request_to_jsonrpc(const struct raft_add_server_request *rq,
                                   struct json *args)
{
    json_object_put_string(args, "address", rq->address);
}

static void
raft_remove_server_request_to_jsonrpc(
    const struct raft_remove_server_request *rq, struct json *args)
{
    json_object_put_format(args, "server_id", SID_FMT, SID_ARGS(&rq->sid));
}

static void
raft_become_leader_to_jsonrpc(const struct raft_become_leader *rpc,
                              struct json *args)
{
    json_object_put_uint(args, "term", rpc->term);
}

static void
raft_add_server_request_from_jsonrpc(struct ovsdb_parser *p,
                                     struct raft_add_server_request *rq)
{
    rq->address = nullable_xstrdup(raft_parse_required_string(p, "address"));
}

static void
raft_remove_server_request_from_jsonrpc(struct ovsdb_parser *p,
                                        struct raft_remove_server_request *rq)
{
    rq->sid = raft_parse_required_uuid(p, "server_id");
}

static void
raft_become_leader_from_jsonrpc(struct ovsdb_parser *p,
                                struct raft_become_leader *rpc)
{
    rpc->term = raft_parse_uint(p, "term");
}


struct jsonrpc_msg *
raft_rpc_to_jsonrpc(const struct uuid *cid,
                    const struct uuid *sid,
                    const union raft_rpc *rpc)
{
    struct json *args = json_object_create();
    if (!uuid_is_zero(cid)) {
        json_object_put_format(args, "cluster", UUID_FMT, UUID_ARGS(cid));
    }
    if (!uuid_is_zero(&rpc->common.sid)) {
        json_object_put_format(args, "to", UUID_FMT,
                               UUID_ARGS(&rpc->common.sid));
    }
    json_object_put_format(args, "from", UUID_FMT, UUID_ARGS(sid));
    if (rpc->common.comment) {
        json_object_put_string(args, "comment", rpc->common.comment);
    }

    switch (rpc->common.type) {
#define RAFT_RPC(ENUM, NAME)                        \
    case ENUM:                                      \
        raft_##NAME##_to_jsonrpc(&rpc->NAME, args); \
        break;
    RAFT_RPC_TYPES
#undef RAFT_RPC
    default:
        OVS_NOT_REACHED();
    }

    return jsonrpc_create_notify(raft_rpc_type_to_string(rpc->common.type),
                                 json_array_create_1(args));
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_rpc_from_jsonrpc(struct uuid *cidp,
                      const struct uuid *sid,
                      const struct jsonrpc_msg *msg,
                      union raft_rpc *rpc)
{
    memset(rpc, 0, sizeof *rpc);
    if (msg->type != JSONRPC_NOTIFY) {
        return ovsdb_error(NULL, "expecting notify RPC but received %s",
                           jsonrpc_msg_type_to_string(msg->type));
    }

    if (!raft_rpc_type_from_string(msg->method, &rpc->common.type)) {
        return ovsdb_error(NULL, "unknown method %s", msg->method);
    }

    if (json_array(msg->params)->n != 1) {
        return ovsdb_error(NULL,
                           "%s RPC has %"PRIuSIZE" parameters (expected 1)",
                           msg->method, json_array(msg->params)->n);
    }

    struct ovsdb_parser p;
    ovsdb_parser_init(&p, json_array(msg->params)->elems[0],
                      "raft %s RPC", msg->method);

    bool is_hello = rpc->common.type == RAFT_RPC_HELLO_REQUEST;
    bool is_add = rpc->common.type == RAFT_RPC_ADD_SERVER_REQUEST;

    struct uuid cid;
    if (raft_parse_uuid__(&p, "cluster", is_add, &cid)
        && !uuid_equals(&cid, cidp)) {
        if (uuid_is_zero(cidp)) {
            *cidp = cid;
            VLOG_INFO("learned cluster ID "CID_FMT, CID_ARGS(&cid));
        } else {
            ovsdb_parser_raise_error(&p, "wrong cluster "CID_FMT" "
                                     "(expected "CID_FMT")",
                                     CID_ARGS(&cid), CID_ARGS(cidp));
        }
    }

    struct uuid to_sid;
    if (raft_parse_uuid__(&p, "to", is_add || is_hello, &to_sid)
        && !uuid_equals(&to_sid, sid)) {
        ovsdb_parser_raise_error(&p, "misrouted message (addressed to "
                                 SID_FMT" but we're "SID_FMT")",
                                 SID_ARGS(&to_sid), SID_ARGS(sid));
    }

    rpc->common.sid = raft_parse_required_uuid(&p, "from");
    rpc->common.comment = nullable_xstrdup(
        raft_parse_optional_string(&p, "comment"));

    switch (rpc->common.type) {
#define RAFT_RPC(ENUM, NAME)                            \
        case ENUM:                                      \
            raft_##NAME##_from_jsonrpc(&p, &rpc->NAME); \
            break;
    RAFT_RPC_TYPES
#undef RAFT_RPC

    default:
        OVS_NOT_REACHED();
    }

    struct ovsdb_error *error = ovsdb_parser_finish(&p);
    if (error) {
        raft_rpc_destroy(rpc);
    }
    return error;
}

void
raft_rpc_destroy(union raft_rpc *rpc)
{
    if (!rpc) {
        return;
    }

    free(rpc->common.comment);

    switch (rpc->common.type) {
#define RAFT_RPC(ENUM, NAME)                    \
        case ENUM:                              \
            raft_##NAME##_destroy(&rpc->NAME);  \
            break;
    RAFT_RPC_TYPES
#undef RAFT_RPC
    }
}
