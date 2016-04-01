/*
 * Copyright (c) 2014, 2016 Nicira, Inc.
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

#include "raft.h"

#include <errno.h>
#include <unistd.h>

#include "hmap.h"
#include "json.h"
#include "openvswitch/list.h"
#include "openvswitch/vlog.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "ovsdb/log.h"
#include "socket-util.h"
#include "util.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(raft);

#define RAFT_MAGIC "OVSDB RAFT"

//static void raft_run_reconfigure(struct raft *);

struct raft;
union raft_rpc;

enum raft_role {
    RAFT_FOLLOWER,
    RAFT_CANDIDATE,
    RAFT_LEADER
};

enum raft_timer {
    RAFT_FAST,
    RAFT_SLOW
};

enum raft_server_phase {
    RAFT_PHASE_STABLE,          /* Not being changed. */

    /* Phases for servers being added. */
    RAFT_PHASE_CATCHUP,         /* Populating new server's log. */
    RAFT_PHASE_CAUGHT_UP,       /* Waiting for prev configuration to commit. */
    RAFT_PHASE_COMMITTING,      /* Waiting for new configuration to commit. */

    /* Phases for servers to be removed. */
    RAFT_PHASE_REMOVE,          /* To be removed. */
};

struct raft_server {
    struct hmap_node hmap_node; /* Hashed based on 'sid'. */

    struct uuid sid;            /* Randomly generater server ID. */
    char *address;              /* "(tcp|ssl):1.2.3.4:5678" */

    /* Volatile state on candidates.  Reinitialized at start of election. */
    bool voted;              /* Has this server already voted? */

    /* Volatile state on leaders.  Reinitialized after election. */
    uint64_t next_index;     /* Index of next log entry to send this server. */
    uint64_t match_index;    /* Index of max log entry server known to have. */
    enum raft_server_phase phase;
    struct uuid reply_xid;      /* For use in AddServer/RemoveServer reply. */
    struct uuid reply_sid;      /* For use in AddServer/RemoveServer reply. */
};

enum raft_entry_type {
    RAFT_DATA,
    RAFT_SERVERS
};

struct raft_entry {
    uint64_t term;
    enum raft_entry_type type;
    char *data;
};

/* The Raft state machine. */
struct raft {
    struct ovsdb_log *storage;

/* Persistent derived state.
 *
 * This must be updated on stable storage before responding to RPCs, but it can
 * be derived from the header, snapshot, and log in 'storage'. */

    struct uuid cid;            /* Cluster ID (immutable for the cluster). */
    struct uuid sid;            /* Server ID (immutable for the server). */

    struct hmap servers;        /* Contains "struct raft_server"s. */
    struct raft_server *me;     /* This server (points into 'servers'). */

/* Persistent state on all servers.
 *
 * Must be updated on stable storage before responding to RPCs. */

    uint64_t current_term;      /* Initialized to 0 and only increases. */
    struct uuid voted_for;      /* In current term, or all-zeros if none. */

    /* The log.
     *
     * A new Raft instance contains an empty log:  log_start=1, log_end=1.
     * Over time, the log grows:                   log_start=1, log_end=N.
     * At some point, the server takes a snapshot: log_start=N, log_end=N.
     * The log continues to grow:                  log_start=N, log_end=N+1...
     *
     * Must be updated on stable storage before responding to RPCs. */
    struct raft_entry *log;     /* Log entry i is in log[i - log_start]. */
    uint64_t log_start;         /* Index of first entry in log. */
    uint64_t log_end;           /* Index of last entry in log, plus 1. */
    size_t allocated_log;       /* Allocated entries in 'log'. */

    /* Snapshot state (see Figure 5.1)
     *
     * This is the state of the cluster as of the last discarded log entry,
     * that is, at log index 'log_start - 1' (called prevIndex in Figure 5.1).
     * Only committed log entries can be included in a snapshot.
     *
     * XXX where's the snapshot itself? */
    uint64_t prev_term;               /* Term for index 'log_start - 1'. */
    struct hmap prev_servers;         /* Contains "struct raft_server"s. */
    char *snapshot;

/* Volatile state. */

    /* On leaders. */
    struct hmap add_servers;    /* Contains "struct raft_server"s to add. */
    struct raft_server *remove_server; /* Server being removed. */

    /* On all servers. */
    enum raft_role role;        /* Current role. */
    uint64_t commit_index;      /* Max log index known to be committed. */
    uint64_t last_applied;      /* Max log index applied to state machine. */
    struct raft_server *leader; /* XXX Is this useful? */

    /* Candidates only.  Reinitialized at start of election. */
    int n_votes;                /* Number of votes for me. */
};

enum raft_rpc_type {
    /* AppendEntries RPC. */
    RAFT_RPC_APPEND_REQUEST,
    RAFT_RPC_APPEND_REPLY,

    /* RequestVote RPC. */
    RAFT_RPC_VOTE_REQUEST,
    RAFT_RPC_VOTE_REPLY,

    /* AddServer RPC. */
    RAFT_RPC_ADD_SERVER_REQUEST,
    RAFT_RPC_ADD_SERVER_REPLY,

    /* RemoveServer RPC. */
    RAFT_RPC_REMOVE_SERVER_REQUEST,
    RAFT_RPC_REMOVE_SERVER_REPLY,

    /* InstallSnapshot RPC. */
    RAFT_RPC_SNAPSHOT_REQUEST,
    RAFT_RPC_SNAPSHOT_REPLY,
};

struct raft_rpc_common {
    enum raft_rpc_type type;    /* One of RAFT_RPC_*. */
    struct uuid sid;            /* SID of peer server. */
    struct uuid xid;            /* To match up requests and replies. */
};

struct raft_append_request {
    struct raft_rpc_common common;
    uint64_t term;              /* Leader's term. */
    struct uuid leader_sid;     /* So follower can redirect clients. */
    uint64_t prev_log_index;    /* Log entry just before new ones. */
    uint64_t prev_log_term;     /* Term of prev_log_index entry. */
    uint64_t leader_commit;     /* Leader's commit_index. */

    /* The append request includes 0 or more log entries.  entries[0] is for
     * log entry 'prev_log_index + 1', and so on.
     *
     * A heartbeat append_request has no terms. */
    struct raft_entry *entries;
    int n_entries;
};

struct raft_append_reply {
    struct raft_rpc_common common;

    /* Copied from the state machine of the reply's sender. */
    uint64_t term;             /* Current term, for leader to update itself. */
    uint64_t log_end;          /* To allow capping next_index, see 4.2.1. */

    /* Copied from request. */
    uint64_t prev_log_index;   /* Log entry just before new ones. */
    uint64_t prev_log_term;    /* Term of prev_log_index entry. */
    int n_entries;

    /* Result. */
    bool success;
};

struct raft_vote_request {
    struct raft_rpc_common common;
    uint64_t term;           /* Candidate's term. */
    int candidate_id;        /* Candidate ID, 0 <= candidate_id < n_servers. */
    uint64_t last_log_index; /* Index of candidate's last log entry. */
    uint64_t last_log_term;  /* Term of candidate's last log entry. */
};

struct raft_vote_reply {
    struct raft_rpc_common common;
    uint64_t term;          /* Current term, for candidate to update itself. */
    bool vote_granted;      /* True means candidate received vote. */
};

struct raft_server_request {
    struct raft_rpc_common common;
    struct uuid sid;            /* Server to add or remove. */
    char *address;              /* For adding server only. */
};

enum raft_server_status {
    /* The operation could not be initiated because this server is not the
     * current leader.  Only the leader can add or remove servers. */
    RAFT_SERVER_NOT_LEADER,

    /* The operation could not be initiated because there was nothing to do.
     * For adding a new server, this means that the server is already part of
     * the cluster, and for removing a server, the server to be removed was not
     * part of the cluster. */
    RAFT_SERVER_NO_OP,

    /* The operation could not be initiated because an identical operation was
     * already in progress. */
    RAFT_SERVER_IN_PROGRESS,

    /* Adding a server failed because of a timeout.  This could mean that the
     * server was entirely unreachable, or that it became unreachable partway
     * through populating it with an initial copy of the log.  In the latter
     * case, retrying the operation should resume where it left off. */
    RAFT_SERVER_TIMEOUT,

    /* The operation was initiated but it later failed because this server lost
     * cluster leadership.  The operation may be retried against the new
     * cluster leader.  For adding a server, if the log was already partially
     * copied to the new server, retrying the operation should resume where it
     * left off. */
    RAFT_SERVER_LOST_LEADERSHIP,

    /* Adding a server was canceled by submission of an operation to remove the
     * same server, or removing a server was canceled by submission of an
     * operation to add the same server. */
    RAFT_SERVER_CANCELED,

    /* Adding or removing a server could not be initiated because the operation
     * to remove or add the server, respectively, has been logged but not
     * committed.  The new operation may be retried once the former operation
     * commits. */
    RAFT_SERVER_COMMITTING,

    /* Removing a server could not be initiated because, taken together with
     * any other scheduled server removals, the cluster would be empty.  (This
     * calculation ignores scheduled or uncommitted add server operations
     * because of the possibility that they could fail.)  */
    RAFT_SERVER_EMPTY,

    /* Success. */
    RAFT_SERVER_OK,
};

struct raft_server_reply {
    struct raft_rpc_common common;
    enum raft_server_status status;
    const char *leader_address;
    struct uuid leader_sid;
};

struct raft_snapshot_request {
    struct raft_rpc_common common;

    uint64_t term;              /* Leader's term. */
    struct uuid leader_sid;     /* So follower can redirect clients. */

    uint64_t last_index;        /* Replaces everything up to this index. */
    uint64_t last_term;         /* Term of last_index. */

    /* Server configuration. */
    struct uuid *servers;
    size_t n_servers;

    /* Data. */
    uint64_t offset;
    const char *data;
    size_t len;

    /* Is this the last chunk? */
    bool done;
};

struct raft_snapshot_reply {
    struct raft_rpc_common common;

    uint64_t term;              /* For leader to update itself. */
};

union raft_rpc {
    struct raft_rpc_common common;
    struct raft_append_request append_request;
    struct raft_append_reply append_reply;
    struct raft_vote_request vote_request;
    struct raft_vote_reply vote_reply;
    struct raft_server_request server_request;
    struct raft_server_reply server_reply;
    struct raft_snapshot_request snapshot_request;
    struct raft_snapshot_reply snapshot_reply;
};

static struct raft_server *
raft_find_server__(struct hmap *servers, const struct uuid *uuid)
{
    struct raft_server *s;
    HMAP_FOR_EACH_IN_BUCKET (s, hmap_node, uuid_hash(uuid), servers) {
        if (uuid_equals(uuid, &s->sid)) {
            return s;
        }
    }
    return NULL;
}

static struct raft_server *
raft_find_server(struct raft *raft, const struct uuid *uuid)
{
    return raft_find_server__(&raft->servers, uuid);
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_parse_address(const char *address,
                   const char **classp, struct sockaddr_storage *ssp)
{
    const char *class;
    if (!strncmp(address, "ssl:", 4)) {
        class = "ssl";
    } else if (!strncmp(address, "tcp:", 4)) {
        class = "tcp";
    } else {
        return ovsdb_error(NULL, "%s: expected \"tcp\" or \"ssl\" address",
                           address);
    }

    struct sockaddr_storage ss;
    if (!inet_parse_active(address + 4, RAFT_PORT, &ss)) {
        return ovsdb_error(NULL, "%s: syntax error in address", address);
    }

    if (classp) {
        *classp = class;
    }
    if (ssp) {
        *ssp = ss;
    }
    return NULL;
}

/* Creates a new Raft cluster and initializes it to consist of a single server,
 * the one on which this function is called.
 *
 * Creates the local copy of the cluster's log in 'file_name', which must not
 * already exist.
 *
 * The new server is located at 'local_address', which must take one of the
 * forms "tcp:IP[:PORT]" or "ssl:IP[:PORT]", where IP is an IPv4 address or a
 * square bracket enclosed IPv6 address.  PORT, if present, is a port number
 * that defaults to RAFT_PORT.
 *
 * This only creates the on-disk file.  Use raft_open() to start operating the
 * local server in the new cluster.
 *
 * Returns null if successful, otherwise an ovsdb_error describing the
 * problem. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_create(const char *file_name, const char *local_address,
            const char *data)
{
    /* Parse and verify validity of the local address.
     *
     * XXX Test that the local machine can bind the local address. */
    struct ovsdb_error *error = raft_parse_address(local_address, NULL, NULL);
    if (error) {
        return error;
    }

    /* Create log file. */
    struct ovsdb_log *storage;
    error = ovsdb_log_open(file_name, RAFT_MAGIC, OVSDB_LOG_CREATE,
                           -1, &storage);
    if (error) {
        return error;
    }

    /* Write header record. */
    struct uuid cid = uuid_generate();
    struct uuid sid = uuid_generate();
    struct json *header = json_object_create();
    json_object_put(header, "cluster_id", json_uuid_create(&cid));
    json_object_put(header, "server_id", json_uuid_create(&sid));
    error = ovsdb_log_write_json(storage, header);
    json_destroy(header);
    if (error) {
        goto error;
    }

    /* Write snapshot record. */
    struct json *prev_servers = json_object_create();
    json_object_put(prev_servers, xasprintf(UUID_FMT, UUID_ARGS(&sid)),
                    json_string_create(local_address));
    struct json *snapshot = json_object_create();
    json_object_put(snapshot, "prev_term", json_integer_create(0));
    json_object_put(snapshot, "prev_index", json_integer_create(0));
    json_object_put(snapshot, "prev_servers", prev_servers);
    if (data) {
        json_object_put_string(snapshot, "data", data);
    }
    error = ovsdb_log_write_json(storage, snapshot);
    json_destroy(snapshot);
    if (error) {
        goto error;
    }

    error = ovsdb_log_commit(storage);
    if (error) {
        goto error;
    }

    ovsdb_log_close(storage);
    return NULL;

error:
    ovsdb_log_close(storage);
    unlink(file_name);
    return error;
}

static struct raft_entry *
raft_add_entry(struct raft *raft,
               uint64_t term, enum raft_entry_type type, char *data)
{
    if (raft->log_end - raft->log_start >= raft->allocated_log) {
        raft->log = x2nrealloc(raft->log, &raft->allocated_log,
                               sizeof *raft->log);
    }

    struct raft_entry *entry = &raft->log[raft->log_end++ - raft->log_start];
    entry->type = type;
    entry->term = term;
    entry->data = data;
    return entry;
}

static uint64_t
parse_integer(struct ovsdb_parser *p, const char *name)
{
    const struct json *json = ovsdb_parser_member(p, name, OP_INTEGER);
    return json ? json_integer(json) : 0;
}

static bool
parse_uuid__(struct ovsdb_parser *p, const char *name, bool optional,
             struct uuid *uuid)
{
    enum ovsdb_parser_types types = OP_STRING | (optional ? OP_OPTIONAL : 0);
    const struct json *json = ovsdb_parser_member(p, name, types);
    if (json) {
        if (uuid_from_string(uuid, json_string(json))) {
            return true;
        }
        ovsdb_parser_raise_error(p, "%s is not a valid UUID", name);
    }
    *uuid = UUID_ZERO;
    return false;
}

static struct uuid
parse_required_uuid(struct ovsdb_parser *p, const char *name)
{
    struct uuid uuid;
    parse_uuid__(p, name, false, &uuid);
    return uuid;
}

static bool
parse_optional_uuid(struct ovsdb_parser *p, const char *name,
                    struct uuid *uuid)
{
    return parse_uuid__(p, name, true, uuid);
}

static void
raft_server_destroy(struct raft_server *s)
{
    if (s) {
        free(s->address);
        free(s);
    }
}

static void
destroy_servers(struct hmap *servers)
{
    struct raft_server *s, *next;
    HMAP_FOR_EACH_SAFE (s, next, hmap_node, servers) {
        hmap_remove(servers, &s->hmap_node);
        raft_server_destroy(s);
    }
    hmap_destroy(servers);
}

static struct raft_server *
raft_server_clone(const struct raft_server *src)
{
    struct raft_server *dst = xmemdup(src, sizeof *src);
    dst->address = xstrdup(dst->address);
    return dst;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
parse_servers(const struct json *json, struct hmap *servers)
{
    if (shash_is_empty(json_object(json))) {
        return ovsdb_syntax_error(json, NULL, "must have at least one server");
    }

    /* Parse new servers. */
    struct hmap new_servers = HMAP_INITIALIZER(&new_servers);
    struct shash_node *node;
    SHASH_FOR_EACH (node, json_object(json)) {
        /* Parse server UUID. */
        struct uuid sid;
        if (!uuid_from_string(&sid, node->name)) {
            destroy_servers(&new_servers);
            return ovsdb_syntax_error(json, NULL, "%s is a not a UUID",
                                      node->name);
        }

        /* Parse server address. */
        const struct json *address_json = node->data;
        if (address_json->type != JSON_STRING) {
            destroy_servers(&new_servers);
            return ovsdb_syntax_error(json, NULL, "%s value is not string",
                                      node->name);
        }
        const char *address = json_string(address_json);
        struct ovsdb_error *error = raft_parse_address(address, NULL, NULL);
        if (error) {
            destroy_servers(&new_servers);
            return error;
        }

        struct raft_server *s = xzalloc(sizeof *s);
        s->sid = sid;
        s->address = xstrdup(address);
        hmap_insert(&new_servers, &s->hmap_node, uuid_hash(&s->sid));
    }

    /* XXX at this point we possibly should migrate old servers' data to the
     * new servesr. */

    /* Swap old and new servers, then destroy old ones. */
    hmap_swap(servers, &new_servers);
    destroy_servers(&new_servers);

    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
parse_log_record(struct raft *raft, const struct json *entry)
{
    /* All log records include "term", plus at most one of:
     *
     *     - "index" and "data".
     *
     *     - "index" and "servers".
     *
     *     - "vote".
     */

    struct ovsdb_parser p;
    ovsdb_parser_init(&p, entry, "raft log entry");

    /* Parse "term". */
    uint64_t term = parse_integer(&p, "term");
    if (term < raft->current_term) {
        ovsdb_parser_raise_error(&p, "log entry term %"PRIu64" precedes "
                                 "current term %"PRIu64".",
                                 term, raft->current_term);
        goto done;
    } else {
        raft->current_term = term;
        raft->voted_for = UUID_ZERO;
    }

    /* Parse "vote". */
    struct uuid vote;
    if (parse_optional_uuid(&p, "vote", &vote)) {
        if (uuid_is_zero(&raft->voted_for)) {
            raft->voted_for = vote;
        } else if (!uuid_equals(&raft->voted_for, &vote)) {
            ovsdb_parser_raise_error(&p, "log entry term %"PRIu64 " votes for "
                                     "both "UUID_FMT" and "UUID_FMT, term,
                                     UUID_ARGS(&raft->voted_for),
                                     UUID_ARGS(&vote));
        }
        goto done;
    }

    /* Parse "index". */
    const struct json *index_json = ovsdb_parser_member(
        &p, "index", OP_INTEGER | OP_OPTIONAL);
    if (!index_json) {
        goto done;
    }
    uint64_t index = json_integer(index_json);
    if (index != raft->log_end) {
        ovsdb_parser_raise_error(&p, "log entry index %"PRIu64" differs from "
                                 "expected %"PRIu64, index, raft->log_end);
        goto done;
    }

    /* Parse "servers". */
    const struct json *servers = ovsdb_parser_member(&p, "servers",
                                                     OP_OBJECT | OP_OPTIONAL);
    if (servers) {
        struct ovsdb_error *error = parse_servers(servers, &raft->servers);
        if (error) {
            ovsdb_error_destroy(ovsdb_parser_finish(&p));
            return error;
        }

        raft_add_entry(raft, term, RAFT_SERVERS, json_to_string(servers, 0));
        goto done;
    }

    /* Parse "data". */
    const struct json *data = ovsdb_parser_member(&p, "data", OP_STRING);
    if (data) {
        raft_add_entry(raft, term, RAFT_DATA, xstrdup(json_string(data)));
    }

done:
    return ovsdb_parser_finish(&p);
}

/* Starts the local server in an existing Raft cluster, using the local copy of
 * the cluster's log in 'file_name'. */
struct ovsdb_error *
raft_open(const char *file_name, struct raft **raftp)
{
    struct raft *raft = xzalloc(sizeof *raft);
    hmap_init(&raft->servers);
    hmap_init(&raft->prev_servers);
    hmap_init(&raft->add_servers);

    struct ovsdb_error *error;
    error = ovsdb_log_open(file_name, RAFT_MAGIC, OVSDB_LOG_READ_WRITE,
                           -1, &raft->storage);
    if (error) {
        goto error;
    }

    /* Read header record. */
    struct json *header;
    error = ovsdb_log_read_json(raft->storage, &header);
    if (error) {
        goto error;
    }
    struct ovsdb_parser p;
    ovsdb_parser_init(&p, header, "raft header");
    raft->cid = parse_required_uuid(&p, "cluster_id");
    raft->sid = parse_required_uuid(&p, "server_id");
    error = ovsdb_parser_finish(&p);
    json_destroy(header);
    if (error) {
        goto error;
    }

    /* Read snapshot record. */
    struct json *snapshot;
    error = ovsdb_log_read_json(raft->storage, &snapshot);
    if (error) {
        goto error;
    }
    ovsdb_parser_init(&p, snapshot, "raft snapshot");
    raft->prev_term = parse_integer(&p, "prev_term");
    raft->log_start = raft->log_end = parse_integer(&p, "prev_index") + 1;
    const struct json *prev_servers_json = ovsdb_parser_member(
        &p, "prev_servers", OP_OBJECT);
    const struct json *data = ovsdb_parser_member(
        &p, "data", OP_STRING | OP_OPTIONAL);
    error = ovsdb_parser_finish(&p);
    if (error) {
        json_destroy(snapshot);
        goto error;
    }

    if (data) {
        raft->snapshot = xstrdup(json_string(data));
    }

    error = parse_servers(prev_servers_json, &raft->prev_servers);
    json_destroy(snapshot);
    if (error) {
        goto error;
    }

    /* Read log records. */
    for (;;) {
        struct json *entry;
        error = ovsdb_log_read_json(raft->storage, &entry);
        if (!entry) {
            break;
        }

        error = parse_log_record(raft, entry);
    }
    if (error) {
        /* We assume that the error is due to a partial write while appending
         * to the file before a crash, so log it and continue. */
        char *error_string = ovsdb_error_to_string(error);
        VLOG_WARN("%s", error_string);
        free(error_string);
        ovsdb_error_destroy(error);
        error = NULL;
    }

    /* If none of the log entries populated the servers, then they're the same
     * as 'raft->prev_servers', so copy them. */
    if (hmap_is_empty(&raft->servers)) {
        struct raft_server *s;
        HMAP_FOR_EACH (s, hmap_node, &raft->prev_servers) {
            struct raft_server *s2 = raft_server_clone(s);
            hmap_insert(&raft->servers, &s2->hmap_node, uuid_hash(&s2->sid));
        }
    }

    /* Find our own server.
     *
     * XXX It seems that this could fail if the server is restarted during the
     * process of removing it but before removal is committed, what to do about
     * that? */
    raft->me = raft_find_server(raft, &raft->sid);
    if (!raft->me) {
        error = ovsdb_error(NULL, "server does not belong to cluster");
        goto error;
    }

    *raftp = raft;
    return NULL;

error:
    raft_close(raft);
    *raftp = NULL;
    return error;
}

void
raft_close(struct raft *raft)
{
    if (!raft) {
        return;
    }

    /* XXX if we're leader then invoke the leadership transfer procedure? */

    ovsdb_log_close(raft->storage);

    destroy_servers(&raft->servers);

    for (uint64_t index = raft->log_start; index < raft->log_end; index++) {
        struct raft_entry *e = &raft->log[index - raft->log_start];
        free(e->data);
    }
    free(raft->log);

    destroy_servers(&raft->prev_servers);
    free(raft->snapshot);

    destroy_servers(&raft->add_servers);
    raft_server_destroy(raft->remove_server);

    free(raft);
}

#if 0
static void
raft_send_server_reply(struct raft *raft,
                       const struct uuid *sid, const struct uuid *xid,
                       enum raft_server_status status)
{
    union raft_rpc rpy = {
        .server_reply = {
            .common = {
                .type = RAFT_RPC_ADD_SERVER_REPLY,
                .sid = *sid,
                .xid = *xid,
            },
            .status = status,

            /* XXX do we maintain leaderHint properly? */
            .leader_address = raft->leader ? raft->leader->address : NULL,
            .leader_sid = raft->leader ? raft->leader->sid : UUID_ZERO,
        }
    };
    raft->ops->send(raft, &rpy);
}

static void
raft_server_destroy(struct raft_server *s)
{
    if (s) {
        free(s->address);
        free(s);
    }
}

static void
raft_become_follower(struct raft *raft)
{
    if (raft->role == RAFT_FOLLOWER) {
        return;
    }

    raft->role = RAFT_FOLLOWER;
    raft->ops->reset_timer(raft, RAFT_SLOW);

    /* Notify clients about lost leadership.
     *
     * We do not reverse our changes to 'raft->servers' because the new
     * configuration is already part of the log.  Possibly the configuration
     * log entry will not be committed, but until we know that we must use the
     * new configuration.  Our AppendEntries processing will properly update
     * the server configuration later, if necessary. */
    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->add_servers) {
        raft_send_server_reply(raft, &s->sid, &s->reply_xid,
                               RAFT_SERVER_LOST_LEADERSHIP);
    }
    if (raft->remove_server) {
        raft_send_server_reply(raft, &raft->remove_server->reply_sid,
                               &raft->remove_server->reply_xid,
                               RAFT_SERVER_LOST_LEADERSHIP);
        raft_server_destroy(raft->remove_server);
        raft->remove_server = NULL;
    }
}

static void
raft_send_append_request(struct raft *raft, struct raft_server *peer, int n)
{
    ovs_assert(raft->leader == raft->me);

    union raft_rpc rq = {
        .append_request = {
            .common = {
                .type = RAFT_RPC_APPEND_REQUEST,
                .sid = peer->sid,
            },
            .term = raft->current_term,
            .leader_sid = raft->me->sid,
            .prev_log_index = peer->next_index - 1,
            .prev_log_term = (peer->next_index - 1 >= raft->log_start
                              ? raft->log[peer->next_index - 1
                                          - raft->log_start].term
                              : raft->prev_term),
            .leader_commit = raft->commit_index,
            .entries = &raft->log[peer->next_index - raft->log_start],
            .n_entries = n,
        },
    };
    uuid_generate(&rq.append_request.common.xid);
    raft->ops->send(raft, &rq);
}

static void
raft_send_heartbeats(struct raft *raft)
{
    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        if (s != raft->me) {
            /* XXX should also retransmit unacknowledged append requests */
            raft_send_append_request(raft, s, 0);
        }
    }
}

static void
raft_server_init_leader(struct raft *raft, struct raft_server *s)
{
    s->next_index = raft->log_end;
    s->match_index = 0;
    s->phase = RAFT_PHASE_STABLE;
}

static void
raft_become_leader(struct raft *raft)
{
    ovs_assert(raft->role != RAFT_LEADER);
    raft->role = RAFT_LEADER;
    raft->leader = raft->me;

    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        raft_server_init_leader(raft, s);
    }

    raft_send_heartbeats(raft);
}

/* Processes term 'term' received in an incoming Raft RPC.  Returns true if the
 * caller should continue processing the RPC, false if the caller should reject
 * it due to a stale term. */
static bool
raft_receive_term__(struct raft *raft, uint64_t term)
{
    /* Section 3.3 says:
     *
     *     Current terms are exchanged whenever servers communicate; if one
     *     server’s current term is smaller than the other’s, then it updates
     *     its current term to the larger value.  If a candidate or leader
     *     discovers that its term is out of date, it immediately reverts to
     *     follower state.  If a server receives a request with a stale term
     *     number, it rejects the request.
     */
    if (term > raft->current_term) {
        raft->current_term = term;
        uuid_zero(&raft->voted_for);
        raft_become_follower(raft);
    } else if (term < raft->current_term) {
        return false;
    }
    return true;
}

static bool
raft_handle_append_entries(struct raft *raft,
                           uint64_t prev_log_index, uint64_t prev_log_term,
                           const struct raft_entry *entries, int n_entries)
{
    if (prev_log_index >= raft->log_end
        || (raft->log[prev_log_index - raft->log_start].term
            != prev_log_term)) {
        /* Section 3.5: "When sending an AppendEntries RPC, the leader includes
         * the index and term of the entry in its log that immediately precedes
         * the new entries. If the follower does not find an entry in its log
         * with the same index and term, then it refuses the new entries." */
        return false;
    }

    /* Figure 3.1: "If an existing entry conflicts with a new one (same
     * index but different terms), delete the existing entry and all that
     * follow it." */
    int i;
    for (i = 0; i < n_entries; i++) {
        uint64_t log_index = (prev_log_index + 1) + i;
        if (log_index >= raft->log_end) {
            break;
        }
        if (raft->log[log_index - raft->log_start].term != entries[i].term) {
            /* Truncate the log, deleting all of the entries at 'log_index'
             * and afterward. */
            while (raft->log_end > log_index) {
                struct raft_entry *entry = &raft->log[--raft->log_end
                                                      - raft->log_start];
                free(entry->data);
            }
            break;
        }
    }

    /* Figure 3.1: "Append any entries not already in the log." */
    for (; i < n_entries; i++) {
        const struct raft_entry *entry = &entries[i];
        raft_add_entry__(raft, entry->term, xstrdup(entry->data));
    }

    return true;
}

static bool
raft_handle_append_request__(struct raft *raft,
                             const struct raft_append_request *rq)
{
    /* We do not check whether we know the server that sent the AppendEntries *
     * request to be the leader.  As section 4.1 says, "A server accepts
     * AppendEntries requests from a leader that is not part of the server’s
     * latest configuration.  Otherwise, a new server could never be added to
     * the cluster (it would never accept any log entries preceding the
     * configuration entry that adds the server)." */

    if (!raft_receive_term__(raft, rq->term)) {
        /* Section 3.3: "If a server receives a request with a stale term
         * number, it rejects the request." */
        return false;
    }

    /* First check for the common case, where the AppendEntries request is
     * entirely for indexes covered by 'log_start' ... 'log_end - 1', something
     * like this:
     *
     *     rq->prev_log_index
     *       | first_entry_index
     *       |   |         nth_entry_index
     *       |   |           |
     *       v   v           v
     *         +---+---+---+---+
     *       T | T | T | T | T |
     *         +---+-------+---+
     *     +---+---+---+---+
     *   T | T | T | T | T |
     *     +---+---+---+---+
     *       ^               ^
     *       |               |
     *   log_start        log_end
     * */
    uint64_t first_entry_index = rq->prev_log_index + 1;
    uint64_t nth_entry_index = rq->prev_log_index + rq->n_entries;
    if (OVS_LIKELY(first_entry_index >= raft->log_start)) {
        return raft_handle_append_entries(raft,
                                          rq->prev_log_index,
                                          rq->prev_log_term,
                                          rq->entries, rq->n_entries);
    }

    /* Now a series of checks for odd cases, where the AppendEntries request
     * extends earlier than the beginning of our log, into the log entries
     * discarded by the most recent snapshot. */

    /*
     * Handle the case where the indexes covered by rq->entries[] are entirely
     * disjoint with 'log_start - 1' ... 'log_end - 1', as shown below.  So,
     * everything in the AppendEntries request must already have been
     * committed, and we might as well return true.
     *
     *     rq->prev_log_index
     *       | first_entry_index
     *       |   |         nth_entry_index
     *       |   |           |
     *       v   v           v
     *         +---+---+---+---+
     *       T | T | T | T | T |
     *         +---+-------+---+
     *                             +---+---+---+---+
     *                           T | T | T | T | T |
     *                             +---+---+---+---+
     *                               ^               ^
     *                               |               |
     *                           log_start        log_end
     */
    if (nth_entry_index < raft->log_start - 1) {
        return true;
    }

    /*
     * Handle the case where the last entry in rq->entries[] has the same index
     * as 'log_start - 1', so we can compare their terms:
     *
     *     rq->prev_log_index
     *       | first_entry_index
     *       |   |         nth_entry_index
     *       |   |           |
     *       v   v           v
     *         +---+---+---+---+
     *       T | T | T | T | T |
     *         +---+-------+---+
     *                         +---+---+---+---+
     *                       T | T | T | T | T |
     *                         +---+---+---+---+
     *                           ^               ^
     *                           |               |
     *                       log_start        log_end
     *
     * There's actually a sub-case where rq->n_entries == 0, in which we
     * compare rq->prev_term:
     *
     *     rq->prev_log_index
     *       |
     *       |
     *       |
     *       v
     *       T
     *
     *         +---+---+---+---+
     *       T | T | T | T | T |
     *         +---+---+---+---+
     *           ^               ^
     *           |               |
     *       log_start        log_end
     */
    if (nth_entry_index == raft->log_start - 1) {
        return (rq->n_entries
                ? raft->prev_term == rq->entries[rq->n_entries - 1].term
                : raft->prev_term == rq->prev_log_term);
    }

    /*
     * We now know that the data in rq->entries[] overlaps the data in
     * raft->log[], as shown below, with some positive 'ofs':
     *
     *     rq->prev_log_index
     *       | first_entry_index
     *       |   |             nth_entry_index
     *       |   |               |
     *       v   v               v
     *         +---+---+---+---+---+
     *       T | T | T | T | T | T |
     *         +---+-------+---+---+
     *                     +---+---+---+---+
     *                   T | T | T | T | T |
     *                     +---+---+---+---+
     *                       ^               ^
     *                       |               |
     *                   log_start        log_end
     *
     *           |<-- ofs -->|
     *
     * We transform this into the following by trimming the first 'ofs'
     * elements off of rq->entries[], ending up with the following.  Notice how
     * we retain the term but not the data for rq->entries[ofs - 1]:
     *
     *                  first_entry_index + ofs - 1
     *                   | first_entry_index + ofs
     *                   |   |  nth_entry_index + ofs
     *                   |   |   |
     *                   v   v   v
     *                     +---+---+
     *                   T | T | T |
     *                     +---+---+
     *                     +---+---+---+---+
     *                   T | T | T | T | T |
     *                     +---+---+---+---+
     *                       ^               ^
     *                       |               |
     *                   log_start        log_end
     */
    uint64_t ofs = raft->log_start - first_entry_index;
    return raft_handle_append_entries(
        raft,
        raft->log_start - 1, rq->entries[ofs - 1].term,
        &rq->entries[ofs], rq->n_entries - ofs);
}

static void
raft_handle_append_request(struct raft *raft,
                           const struct raft_append_request *rq)
{
    bool success = raft_handle_append_request__(raft, rq);

    /* Figure 3.1: "If leaderCommit > commitIndex, set commitIndex =
     * min(leaderCommit, index of last new entry)" */
    if (success && rq->leader_commit > raft->commit_index) {
        raft->commit_index = MIN(rq->leader_commit,
                                 rq->prev_log_index + rq->n_entries);

        /* Figure 3.1: "If commitIndex > lastApplied, increment
         * lastApplied, apply log[lastApplied] to state machine
         * (section 3.5)." */
        while (raft->commit_index > raft->last_applied) {
            raft->last_applied++;

            struct raft_entry *e = &raft->log[raft->last_applied
                                              - raft->log_start];
            if (e->type == RAFT_CONFIGURATION) {
                raft_run_reconfigure(raft);
            } else {
                /* XXX apply log[lastApplied]. */
            }
        }
    }

    /* Send reply. */
    union raft_rpc reply = {
        .append_reply = {
            .common = {
                .type = RAFT_RPC_APPEND_REPLY,
                .sid = rq->common.sid,
                .xid = rq->common.xid,
            },
            .term = raft->current_term,
            .log_end = raft->log_end,
            .prev_log_index = rq->prev_log_index,
            .prev_log_term = rq->prev_log_term,
            .n_entries = rq->n_entries,
            .success = success,
        }
    };
    raft->ops->send(raft, &reply);
}

static struct raft_server *
raft_find_peer(struct raft *raft, const struct uuid *uuid)
{
    struct raft_server *s = raft_find_server(raft, uuid);
    return s != raft->me ? s : NULL;
}

static struct raft_server *
raft_find_new_server(struct raft *raft, const struct uuid *uuid)
{
    return raft_find_server__(&raft->add_servers, uuid);
}

static void
raft_handle_append_reply(struct raft *raft,
                         const struct raft_append_reply *rpy)
{
    if (!raft_receive_term__(raft, rpy->term)) {
        return;
    }
    if (raft->role != RAFT_LEADER) {
        /* XXX log */
        return;
    }

    /* Most commonly we'd be getting an AppendEntries reply from a configured
     * server (e.g. a peer), but we can also get them from servers in the
     * process of being added. */
    struct raft_server *s = raft_find_peer(raft, &rpy->common.sid);
    if (!s) {
        s = raft_find_new_server(raft, &rpy->common.sid);
        if (!s) {
            /* XXX log */
            return;
        }
    }

    if (rpy->success) {
        /* Figure 3.1: "If successful, update nextIndex and matchIndex for
         * follower (section 3.5)." */
        uint64_t min_index = rpy->prev_log_index + rpy->n_entries;
        if (s->next_index < min_index) {
            s->next_index = min_index;
        }
        if (s->match_index < min_index) {
            s->match_index = min_index;
        }
    } else {
        /* Figure 3.1: "If AppendEntries fails because of log inconsistency,
         * decrement nextIndex and retry (section 3.5)."
         *
         * We also implement the optimization suggested in section 4.2.1:
         * "Various approaches can make nextIndex converge to its correct value
         * more quickly, including those described in Chapter 3. The simplest
         * approach to solving this particular problem of adding a new server,
         * however, is to have followers return the length of their logs in the
         * AppendEntries response; this allows the leader to cap the follower’s
         * nextIndex accordingly." */
        if (s->next_index > 0) {
            s->next_index = MIN(s->next_index - 1, rpy->log_end);
        } else {
            /* XXX log */
        }
    }

    if (s->next_index < raft->log_start) {
        /* XXX Send installsnapshot. */
    } else if (s->next_index < raft->log_end) {
        raft_send_append_request(raft, s, 1);
    } else if (s->phase == RAFT_PHASE_CATCHUP) {
        s->phase = RAFT_PHASE_CAUGHT_UP;
        raft_run_reconfigure(raft);
    }
}

static bool
raft_handle_vote_request__(struct raft *raft,
                           const struct raft_vote_request *rq)
{
    if (!raft_receive_term__(raft, rq->term)) {
        return false;
    }

    /* Figure 3.1: "If votedFor is null or candidateId, and candidate's vote is
     * at least as up-to-date as receiver's log, grant vote (sections 3.4,
     * 3.6)." */
    if (uuid_equals(&raft->voted_for, &rq->common.sid)) {
        /* Already voted for this candidate in this term.  Resend vote. */
        return true;
    } else if (!uuid_is_zero(&raft->voted_for)) {
        /* Already voted for different candidate in this term. */
        return false;
    }

    /* Section 3.6.1: "The RequestVote RPC implements this restriction: the RPC
     * includes information about the candidate’s log, and the voter denies its
     * vote if its own log is more up-to-date than that of the candidate.  Raft
     * determines which of two logs is more up-to-date by comparing the index
     * and term of the last entries in the logs.  If the logs have last entries
     * with different terms, then the log with the later term is more
     * up-to-date.  If the logs end with the same term, then whichever log is
     * longer is more up-to-date." */
    uint64_t last_term = (raft->log_end > raft->log_start
                          ? raft->log[raft->log_end - 1 - raft->log_start].term
                          : raft->prev_term);
    if (last_term > rq->last_log_term
        || (last_term == rq->last_log_term
            && raft->log_end - 1 > rq->last_log_index)) {
        /* Our log is more up-to-date than the peer's, so withhold vote. */
        return false;
    }

    /* Vote for the peer. */
    raft->voted_for = rq->common.sid;
    return true;
}

static void
raft_handle_vote_request(struct raft *raft,
                         const struct raft_vote_request *rq)
{
    bool vote_granted = raft_handle_vote_request__(raft, rq);
    union raft_rpc rpy = {
        .vote_reply = {
            .common = {
                .type = RAFT_RPC_VOTE_REPLY,
                .sid = rq->common.sid,
                .xid = rq->common.xid
            },
            .term = raft->current_term,
            .vote_granted = vote_granted
        },
    };
    raft->ops->send(raft, &rpy);
}

static void
raft_handle_vote_reply(struct raft *raft,
                       const struct raft_vote_reply *rpy)
{
    if (!raft_receive_term__(raft, rpy->term)) {
        return;
    }

    if (raft->role != RAFT_CANDIDATE) {
        return;
    }

    struct raft_server *s = raft_find_peer(raft, &rpy->common.sid);
    if (!s || s->voted) {
        return;
    }

    s->voted = true;
    if (rpy->vote_granted
        && ++raft->n_votes > hmap_count(&raft->servers) / 2) {
        raft_become_leader(raft);
    }
}

/* Returns true if 'raft''s log contains reconfiguration entries that have not
 * yet been committed. */
static bool
raft_has_uncommitted_configuration(const struct raft *raft)
{
    for (uint64_t i = raft->commit_index + 1; i < raft->log_end; i++) {
        ovs_assert(i >= raft->log_start);
        const struct raft_entry *e = &raft->log[i - raft->log_start];
        if (e->type == RAFT_CONFIGURATION) {
            return false;
        }
    }
    return true;
}

static void
raft_run_reconfigure(struct raft *raft)
{
    ovs_assert(raft->role == RAFT_LEADER);

    /* Reconfiguration only progresses when configuration changes commit. */
    if (raft_has_uncommitted_configuration(raft)) {
        return;
    }

    /* If we were waiting for a configuration change to commit, it's done. */
    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        if (s->phase == RAFT_PHASE_COMMITTING) {
            raft_send_server_reply(raft, &s->reply_sid, &s->reply_xid,
                                   RAFT_SERVER_OK);
            s->phase = RAFT_PHASE_STABLE;
        }
    }
    if (raft->remove_server) {
        raft_send_server_reply(raft, &raft->remove_server->reply_sid,
                               &raft->remove_server->reply_xid,
                               RAFT_SERVER_OK);
        raft_server_destroy(raft->remove_server);
        raft->remove_server = NULL;
    }

    /* If a new server is caught up, add it to the configuration.  */
    HMAP_FOR_EACH (s, hmap_node, &raft->add_servers) {
        if (s->phase == RAFT_PHASE_CAUGHT_UP) {
            /* Move 's' from 'raft->add_servers' to 'raft->servers'. */
            hmap_remove(&raft->add_servers, &s->hmap_node);
            hmap_insert(&raft->servers, &s->hmap_node, uuid_hash(&s->uuid));

            /* Mark 's' as waiting for commit. */
            s->phase = RAFT_PHASE_COMMITTING;

            /* XXX add log entry */

            return;
        }
    }

    /* Remove a server, if one is scheduled for removal. */
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        if (s->phase == RAFT_PHASE_REMOVE) {
            hmap_remove(&raft->servers, &s->hmap_node);
            raft->remove_server = s;

            /* XXX add log entry */

            return;
        }
    }
}

static int
raft_handle_add_server_request__(struct raft *raft,
                                 const struct raft_server_request *rq)
{
    /* Figure 4.1: "1. Reply NOT_LEADER if not leader (section 6.2)." */
    if (raft->role != RAFT_LEADER) {
        return RAFT_SERVER_NOT_LEADER;
    }

    /* Check for an existing server. */
    struct raft_server *s = raft_find_server(raft, &rq->sid);
    if (s) {
        /* If the server is scheduled to be removed, cancel it. */
        if (s->phase != RAFT_PHASE_REMOVE) {
            s->phase = RAFT_PHASE_STABLE;
            raft_send_server_reply(raft, &s->reply_sid, &s->reply_xid,
                                   RAFT_SERVER_CANCELED);
            return RAFT_SERVER_OK;
        }

        /* Cannot add a server that is already part of the configuration. */
        return RAFT_SERVER_NO_OP;
    }

    /* Check for a server being removed. */
    if (raft->remove_server
        && uuid_equals(&rq->sid, &raft->remove_server->sid)) {
        return RAFT_SERVER_COMMITTING;
    }

    /* Check for a server already being added. */
    if (raft_find_new_server(raft, &rq->sid)) {
        return RAFT_SERVER_IN_PROGRESS;
    }

    /* Add server to 'add_servers'. */
    s = xzalloc(sizeof *s);
    hmap_insert(&raft->add_servers, &s->hmap_node);
    raft_server_init_leader(raft, s);
    s->sid = rq->sid;
    s->address = xstrdup(rq->address);
    s->reply_sid = rq->common.sid;
    s->reply_xid = rq->common.xid;
    s->phase = RAFT_PHASE_CATCHUP;

    /* XXX call raft->ops->reconnect().  Or maybe not; if the new server has to
     * connect to us then we already have a connection? */

    /* Start sending the log.  If this is the first time we've tried to add
     * this server, then this will quickly degenerate into an InstallSnapshot
     * followed by a series of AddEntries, but if it's a retry of an earlier
     * AddRequest that was interrupted (e.g. by a timeout or a loss of
     * leadership) then it will gracefully resume populating the log.
     *
     * See the last few paragraphs of section 4.2.1 for further insight. */
    raft_send_append_request(raft, s, 0);

    return -1;
}

static void
raft_handle_add_server_request(struct raft *raft,
                               const struct raft_server_request *rq)
{
    int status = raft_handle_add_server_request__(raft, rq);
    if (status >= 0) {
        raft_send_server_reply(raft, &rq->common.sid, &rq->common.xid, status);
    } else {
        /* Operation in progress, reply will be sent later. */
    }
}

static void
raft_handle_add_server_reply(struct raft *raft OVS_UNUSED,
                             const struct raft_server_reply *rpc OVS_UNUSED)
{
    /* XXX */
}

static int
raft_handle_remove_server_request__(struct raft *raft,
                                    const struct raft_server_request *rq)
{
    /* Figure 4.1: "1. Reply NOT_LEADER if not leader (section 6.2)." */
    if (raft->role != RAFT_LEADER) {
        return RAFT_SERVER_NOT_LEADER;
    }

    /* If the server to remove is currently waiting to be added, cancel it. */
    struct raft_server *target = raft_find_new_server(raft, &rq->sid);
    if (target) {
        raft_send_server_reply(raft, &target->reply_sid, &target->reply_xid,
                               RAFT_SERVER_CANCELED);
        hmap_remove(&raft->add_servers, &target->hmap_node);
        raft_server_destroy(target);
        return RAFT_SERVER_OK;
    }

    /* If the server isn't configured, report that. */
    target = raft_find_server(raft, &rq->sid);
    if (!target) {
        return RAFT_SERVER_NO_OP;
    }

    /* Check whether we're waiting for the addition of the server to commit. */
    if (target->phase == RAFT_PHASE_COMMITTING) {
        return RAFT_SERVER_COMMITTING;
    }

    /* Check whether the server is already scheduled for removal. */
    if (target->phase == RAFT_PHASE_REMOVE) {
        return RAFT_SERVER_IN_PROGRESS;
    }

    /* Make sure that if we remove this server then that at least one other
     * server will be left.  We don't count servers currently being added (in
     * 'add_servers') since those could fail. */
    struct raft_server *s;
    int n = 0;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        if (s != target && s->phase != RAFT_PHASE_REMOVE) {
            n++;
        }
    }
    if (!n) {
        return RAFT_SERVER_EMPTY;
    }

    /* Mark the server for removal. */
    s->phase = RAFT_PHASE_REMOVE;
    s->reply_sid = rq->common.sid;
    s->reply_xid = rq->common.xid;

    raft_run_reconfigure(raft);
    return -1;
}

static void
raft_handle_remove_server_request(struct raft *raft,
                                  const struct raft_server_request *rq)
{
    int status = raft_handle_remove_server_request__(raft, rq);
    if (status >= 0) {
        raft_send_server_reply(raft, &rq->common.sid, &rq->common.xid,
                               status);
    } else {
        /* Operation in progress, reply will be sent later. */
    }
}

static void
raft_handle_remove_server_reply(struct raft *raft OVS_UNUSED,
                                const struct raft_server_reply *rpc OVS_UNUSED)
{
    /* XXX */
}

static void
raft_handle_snapshot_request__(struct raft *raft,
                             const struct raft_snapshot_request *rq)
{
    if (!raft_receive_term__(raft, rq->term)) {
        return;
    }

    /* XXX snapshot */
}

static void
raft_handle_snapshot_request(struct raft *raft,
                             const struct raft_snapshot_request *rq)
{
    raft_handle_snapshot_request__(raft, rq);

    union raft_rpc rpy = {
        .snapshot_reply = {
            .common = {
                .type = RAFT_RPC_SNAPSHOT_REPLY,
                .sid = rq->common.sid,
                .xid = rq->common.xid,
            },
            .term = raft->current_term,
        },
    };
    raft->ops->send(raft, &rpy);
}

static void
raft_handle_snapshot_reply(struct raft *raft,
                           const struct raft_snapshot_reply *rpy)
{
    if (!raft_receive_term__(raft, rpy->term)) {
        return;
    }
    /* XXX */
}

void
raft_receive(struct raft *raft, const union raft_rpc *rpc)
{
    switch (rpc->common.type) {
    case RAFT_RPC_APPEND_REQUEST:
        raft_handle_append_request(raft, &rpc->append_request);
        break;
    case RAFT_RPC_APPEND_REPLY:
        raft_handle_append_reply(raft, &rpc->append_reply);
        break;
    case RAFT_RPC_VOTE_REQUEST:
        raft_handle_vote_request(raft, &rpc->vote_request);
        break;
    case RAFT_RPC_VOTE_REPLY:
        raft_handle_vote_reply(raft, &rpc->vote_reply);
        break;
    case RAFT_RPC_ADD_SERVER_REQUEST:
        raft_handle_add_server_request(raft, &rpc->server_request);
        break;
    case RAFT_RPC_ADD_SERVER_REPLY:
        raft_handle_add_server_reply(raft, &rpc->server_reply);
        break;
    case RAFT_RPC_REMOVE_SERVER_REQUEST:
        raft_handle_remove_server_request(raft, &rpc->server_request);
        break;
    case RAFT_RPC_REMOVE_SERVER_REPLY:
        raft_handle_remove_server_reply(raft, &rpc->server_reply);
        break;
    case RAFT_RPC_SNAPSHOT_REQUEST:
        raft_handle_snapshot_request(raft, &rpc->snapshot_request);
        break;
    case RAFT_RPC_SNAPSHOT_REPLY:
        raft_handle_snapshot_reply(raft, &rpc->snapshot_reply);
        break;
    default:
        OVS_NOT_REACHED();
    }
}
#endif
