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
#include "jsonrpc.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/vlog.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "ovsdb/log.h"
#include "poll-loop.h"
#include "random.h"
#include "seq.h"
#include "socket-util.h"
#include "stream.h"
#include "timeval.h"
#include "util.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(raft);

#define RAFT_MAGIC "OVSDB RAFT"

static void raft_run_reconfigure(struct raft *);

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

    struct uuid sid;            /* Randomly generated server ID. */
    char *address;              /* "(tcp|ssl):1.2.3.4:5678" */
    struct jsonrpc_session *js; /* Connection to this server. */

    /* Volatile state on candidates.  Reinitialized at start of election. */
    bool voted;              /* Has this server already voted? */

    /* Volatile state on leaders.  Reinitialized after election. */
    uint64_t next_index;     /* Index of next log entry to send this server. */
    uint64_t match_index;    /* Index of max log entry server known to have. */
    enum raft_server_phase phase;
    struct uuid reply_sid;      /* For use in AddServer/RemoveServer reply. */
};

static void raft_server_init_leader(struct raft *, struct raft_server *);

enum raft_entry_type {
    RAFT_DATA,
    RAFT_SERVERS
};

struct raft_entry {
    uint64_t term;
    enum raft_entry_type type;
    char *data;
};

struct raft_conn {
    struct ovs_list list_node;
    struct jsonrpc_session *js;
    struct uuid sid;
};

struct raft_command {
    struct ovs_refcount refcnt;
    enum raft_command_status status;
};

enum raft_waiter_type {
    RAFT_W_COMMAND,
    RAFT_W_APPEND
};

struct raft_waiter {
    struct ovs_list list_node;
    uint64_t fsync_seqno;
    enum raft_waiter_type type;
    union {
        struct {
            struct raft_command *cmd;
            uint64_t index;
        } command;

        struct {
            struct raft_append_request *rq; /* Does not include 'entries'. */
        } append;
    };
};

static struct raft_waiter *raft_waiter_create(struct raft *,
                                              enum raft_waiter_type);

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
     * Only committed log entries can be included in a snapshot. */
    uint64_t prev_term;               /* Term for index 'log_start - 1'. */
    struct hmap prev_servers;         /* Contains "struct raft_server"s. */
    char *snapshot;                   /* Data of snapshot, or NULL if none. */

/* Volatile state. */

    enum raft_role role;        /* Current role. */
    uint64_t commit_index;      /* Max log index known to be committed. */
    uint64_t last_applied;      /* Max log index applied to state machine. */
    struct raft_server *leader; /* XXX Is this useful? */

#define ELECTION_TIME_BASE_MSEC 1024
#define ELECTION_TIME_RANGE_MSEC 1024
    long long int election_timeout;

    /* File synchronization. */
    pthread_t fsync_thread;
    struct ovs_mutex fsync_mutex;
    uint64_t fsync_next OVS_GUARDED;
    uint64_t fsync_cur OVS_GUARDED;
    struct seq *fsync_request;
    struct seq *fsync_complete;
    struct ovs_list waiters;

    /* Network connections. */
    struct pstream *listener;
    long long int listen_backoff;
    struct ovs_list conns;

    /* Leaders only.  Reinitialized after becoming leader. */
    struct hmap add_servers;    /* Contains "struct raft_server"s to add. */
    struct raft_server *remove_server; /* Server being removed. */

    /* Candidates only.  Reinitialized at start of election. */
    int n_votes;                /* Number of votes for me. */
};

static void *
raft_fsync_thread(void *raft_)
{
    struct raft *raft = raft_;
    for (;;) {
        ovsrcu_quiesce_start();

        uint64_t request_seq = seq_read(raft->fsync_request);

        ovs_mutex_lock(&raft->fsync_mutex);
        uint64_t next = raft->fsync_next;
        uint64_t cur = raft->fsync_cur;
        ovs_mutex_unlock(&raft->fsync_mutex);

        if (next == UINT64_MAX) {
            break;
        }

        if (cur != next) {
            /* XXX following has really questionable thread-safety. */
            struct ovsdb_error *error = ovsdb_log_commit(raft->storage);
            if (!error) {
                ovs_mutex_lock(&raft->fsync_mutex);
                raft->fsync_cur = next;
                ovs_mutex_unlock(&raft->fsync_mutex);

                seq_change(raft->fsync_complete);
            } else {
                char *error_string = ovsdb_error_to_string(error);
                VLOG_WARN("%s", error_string);
                free(error_string);
                ovsdb_error_destroy(error);
            }
        }

        seq_wait(raft->fsync_request, request_seq);
        poll_block();
    }
    return NULL;
}

#define RAFT_RPC_TYPES                                                  \
    /* AppendEntries RPC. */                                            \
    RAFT_RPC(RAFT_RPC_APPEND_REQUEST, "append_request")                 \
    RAFT_RPC(RAFT_RPC_APPEND_REPLY, "append_reply")                     \
                                                                        \
    /* RequestVote RPC. */                                              \
    RAFT_RPC(RAFT_RPC_VOTE_REQUEST, "vote_request")                     \
    RAFT_RPC(RAFT_RPC_VOTE_REPLY, "vote_reply")                         \
                                                                        \
    /* AddServer RPC. */                                                \
    RAFT_RPC(RAFT_RPC_ADD_SERVER_REQUEST, "add_server_request")         \
    RAFT_RPC(RAFT_RPC_ADD_SERVER_REPLY, "add_server_reply")             \
                                                                        \
    /* RemoveServer RPC. */                                             \
    RAFT_RPC(RAFT_RPC_REMOVE_SERVER_REQUEST, "remove_server_request")   \
    RAFT_RPC(RAFT_RPC_REMOVE_SERVER_REPLY, "remove_server_reply")       \
                                                                        \
    /* InstallSnapshot RPC. */                                          \
    RAFT_RPC(RAFT_RPC_INSTALL_SNAPSHOT_REQUEST, "install_snapshot_request") \
    RAFT_RPC(RAFT_RPC_INSTALL_SNAPSHOT_REPLY, "install_snapshot_reply")

enum raft_rpc_type {
#define RAFT_RPC(ENUM, NAME) ENUM,
    RAFT_RPC_TYPES
#undef RAFT_RPC
};

static const char *
raft_rpc_type_to_string(enum raft_rpc_type status)
{
    switch (status) {
#define RAFT_RPC(ENUM, NAME) case ENUM: return NAME;
        RAFT_RPC_TYPES
#undef RAFT_RPC
            }
    return "<unknown>";
}

static bool
raft_rpc_type_from_string(const char *s, enum raft_rpc_type *status)
{
#define RAFT_RPC(ENUM, NAME)                    \
    if (!strcmp(s, NAME)) {                     \
        *status = ENUM;                         \
        return true;                            \
    }
    RAFT_RPC_TYPES
#undef RAFT_RPC
        return false;
}

struct raft_rpc_common {
    enum raft_rpc_type type;    /* One of RAFT_RPC_*. */
    struct uuid sid;            /* SID of peer server. */
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
    unsigned int n_entries;
};

struct raft_append_reply {
    struct raft_rpc_common common;

    /* Copied from the state machine of the reply's sender. */
    uint64_t term;             /* Current term, for leader to update itself. */
    uint64_t log_end;          /* To allow capping next_index, see 4.2.1. */

    /* Copied from request. */
    uint64_t prev_log_index;   /* Log entry just before new ones. */
    uint64_t prev_log_term;    /* Term of prev_log_index entry. */
    unsigned int n_entries;

    /* Result. */
    bool success;
};

static void raft_send_append_reply(struct raft *,
                                   const struct raft_append_request *,
                                   bool success);
static void raft_update_match_index(struct raft *, struct raft_server *,
                                    uint64_t min_index);

struct raft_vote_request {
    struct raft_rpc_common common;
    uint64_t term;           /* Candidate's term. */
    uint64_t last_log_index; /* Index of candidate's last log entry. */
    uint64_t last_log_term;  /* Term of candidate's last log entry. */
};

struct raft_vote_reply {
    struct raft_rpc_common common;
    uint64_t term;          /* Current term, for candidate to update itself. */

    /* XXX is there any value in sending a reply with vote_granted==false? */
    bool vote_granted;      /* True means candidate received vote. */
};

struct raft_server_request {
    struct raft_rpc_common common;
    struct uuid sid;            /* Server to add or remove. */
    char *address;              /* For adding server only. */
};

#define RAFT_SERVER_STATUS_LIST                                         \
    /* The operation could not be initiated because this server is not  \
     * the current leader.  Only the leader can add or remove           \
     * servers. */                                                      \
    RSS(RAFT_SERVER_NOT_LEADER, "not-leader")                           \
                                                                        \
    /* The operation could not be initiated because there was nothing   \
     * to do.  For adding a new server, this means that the server is   \
     * already part of the cluster, and for removing a server, the      \
     * server to be removed was not part of the cluster. */             \
    RSS(RAFT_SERVER_NO_OP, "no-op")                                     \
                                                                        \
    /* The operation could not be initiated because an identical        \
     * operation was already in progress. */                            \
    RSS(RAFT_SERVER_IN_PROGRESS, "in-progress")                         \
                                                                        \
    /* Adding a server failed because of a timeout.  This could mean    \
     * that the server was entirely unreachable, or that it became      \
     * unreachable partway through populating it with an initial copy   \
     * of the log.  In the latter case, retrying the operation should   \
     * resume where it left off. */                                     \
    RSS(RAFT_SERVER_TIMEOUT, "timeout")                                 \
                                                                        \
    /* The operation was initiated but it later failed because this     \
     * server lost cluster leadership.  The operation may be retried    \
     * against the new cluster leader.  For adding a server, if the log \
     * was already partially copied to the new server, retrying the     \
     * operation should resume where it left off. */                    \
    RSS(RAFT_SERVER_LOST_LEADERSHIP, "lost-leadership")                 \
                                                                        \
    /* Adding a server was canceled by submission of an operation to    \
     * remove the same server, or removing a server was canceled by     \
     * submission of an operation to add the same server. */            \
    RSS(RAFT_SERVER_CANCELED, "canceled")                               \
                                                                        \
    /* Adding or removing a server could not be initiated because the   \
     * operation to remove or add the server, respectively, has been    \
     * logged but not committed.  The new operation may be retried once \
     * the former operation commits. */                                 \
    RSS(RAFT_SERVER_COMMITTING, "committing")                           \
                                                                        \
    /* Removing a server could not be initiated because, taken together \
     * with any other scheduled server removals, the cluster would be   \
     * empty.  (This calculation ignores scheduled or uncommitted add   \
     * server operations because of the possibility that they could     \
     * fail.)  */                                                       \
    RSS(RAFT_SERVER_EMPTY, "empty")                                     \
                                                                        \
    /* Success. */                                                      \
    RSS(RAFT_SERVER_OK, "success")

enum raft_server_status {
#define RSS(ENUM, NAME) ENUM,
    RAFT_SERVER_STATUS_LIST
#undef RSS
};

static const char *
raft_server_status_to_string(enum raft_server_status status)
{
    switch (status) {
#define RSS(ENUM, NAME) case ENUM: return NAME;
        RAFT_SERVER_STATUS_LIST
#undef RSS
            }
    return "<unknown>";
}

static bool
raft_server_status_from_string(const char *s, enum raft_server_status *status)
{
#define RSS(ENUM, NAME)                         \
    if (!strcmp(s, NAME)) {                     \
        *status = ENUM;                         \
        return true;                            \
    }
    RAFT_SERVER_STATUS_LIST
#undef RSS
    return false;
}

struct raft_server_reply {
    struct raft_rpc_common common;
    enum raft_server_status status;
    char *leader_address;
    struct uuid leader_sid;
};

struct raft_install_snapshot_request {
    struct raft_rpc_common common;

    uint64_t term;              /* Leader's term. */
    struct uuid leader_sid;     /* So follower can redirect clients. */

    uint64_t last_index;        /* Replaces everything up to this index. */
    uint64_t last_term;         /* Term of last_index. */

    struct hmap servers;        /* Contains "struct raft_server"s. */

    /* Data.
     *
     * The data must be a valid UTF-8 string, because it is going to be sent as
     * a JSON string.  That means that chunks must not be chosen so as to break
     * apart multibyte characters (because that would create invalid UTF-8).
     *
     * The data need not be null-terminated. */
    uint64_t offset;
    char *data;
    size_t len;

    /* Is this the last chunk? */
    bool done;
};

struct raft_install_snapshot_reply {
    struct raft_rpc_common common;

    /* XXX how do we handle lost fragments? */
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
    struct raft_install_snapshot_request install_snapshot_request;
    struct raft_install_snapshot_reply install_snapshot_reply;
};

static void raft_receive(struct raft *, const union raft_rpc *);
static void raft_send(struct raft *, const union raft_rpc *);
static void raft_send_append_request(struct raft *,
                                     struct raft_server *, unsigned int n);
static void raft_rpc_destroy(union raft_rpc *);
static struct jsonrpc_msg *raft_rpc_to_jsonrpc(const struct raft *,
                                               const union raft_rpc *);
static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_rpc_from_jsonrpc(const struct raft *, const struct jsonrpc_msg *,
                      union raft_rpc *);

static void raft_become_leader(struct raft *);

static struct raft_server *
raft_find_server__(const struct hmap *servers, const struct uuid *sid)
{
    struct raft_server *s;
    HMAP_FOR_EACH_IN_BUCKET (s, hmap_node, uuid_hash(sid), servers) {
        if (uuid_equals(sid, &s->sid)) {
            return s;
        }
    }
    return NULL;
}

static struct raft_server *
raft_find_server(const struct raft *raft, const struct uuid *sid)
{
    return raft_find_server__(&raft->servers, sid);
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

static char *
raft_make_address_passive(const char *address_)
{
    char *address = xstrdup(address_);
    char *p = strchr(address, ':') + 1;
    char *host = inet_parse_token(&p);
    char *port = inet_parse_token(&p);

    struct ds paddr = DS_EMPTY_INITIALIZER;
    ds_put_format(&paddr, "p%.3s:%s:", address, port);
    if (strchr(host, ':')) {
        ds_put_format(&paddr, "[%s]", host);
    } else {
        ds_put_cstr(&paddr, host);
    }
    free(address);
    return ds_steal_cstr(&paddr);
}

static struct ovsdb_error *
raft_write_header(struct ovsdb_log *storage,
                  const struct uuid *cid, const struct uuid *sid)
{
    struct json *header = json_object_create();
    json_object_put(header, "cluster_id", json_uuid_create(cid));
    json_object_put(header, "server_id", json_uuid_create(sid));
    struct ovsdb_error *error = ovsdb_log_write_json(storage, header);
    json_destroy(header);
    return error;
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
    error = ovsdb_log_open(file_name, RAFT_MAGIC, OVSDB_LOG_CREATE_EXCL,
                           -1, &storage);
    if (error) {
        return error;
    }

    /* Write header record. */
    struct uuid cid = uuid_generate();
    struct uuid sid = uuid_generate();
    error = raft_write_header(storage, &cid, &sid);
    if (error) {
        goto error;
    }

    /* Write snapshot record. */
    struct json *prev_servers = json_object_create();
    char sid_s[UUID_LEN + 1];
    sprintf(sid_s, UUID_FMT, UUID_ARGS(&sid));
    json_object_put(prev_servers, sid_s, json_string_create(local_address));
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

static struct json *
raft_entry_to_json(const struct raft_entry *e)
{
    struct json *json = json_object_create();
    json_object_put_uint(json, "term", e->term);
    if (e->type == RAFT_DATA) {
        json_object_put_string(json, "data", e->data);
    } else {
        /* XXX what if json_from_string() reports an error? */
        json_object_put(json, "servers", json_from_string(e->data));
    }
    return json;
}

static struct json *
raft_entry_to_json_with_index(const struct raft *raft, uint64_t index)
{
    ovs_assert(index >= raft->log_start && index < raft->log_end);
    struct json *json = raft_entry_to_json(&raft->log[index
                                                      - raft->log_start]);
    json_object_put_uint(json, "index", index);
    return json;
}

static uint64_t
parse_uint(struct ovsdb_parser *p, const char *name)
{
    const struct json *json = ovsdb_parser_member(p, name, OP_INTEGER);
    return json ? json_integer(json) : 0;
}

static bool
parse_boolean(struct ovsdb_parser *p, const char *name)
{
    const struct json *json = ovsdb_parser_member(p, name, OP_BOOLEAN);
    return json && json_boolean(json);
}

static const char *
parse_string__(struct ovsdb_parser *p, const char *name, bool optional)
{
    enum ovsdb_parser_types types = OP_STRING | (optional ? OP_OPTIONAL : 0);
    const struct json *json = ovsdb_parser_member(p, name, types);
    return json ? json_string(json) : NULL;
}

static const char  *
parse_required_string(struct ovsdb_parser *p, const char *name)
{
    return parse_string__(p, name, false);
}

static const char  *
parse_optional_string(struct ovsdb_parser *p, const char *name)
{
    return parse_string__(p, name, true);
}

static bool
parse_uuid__(struct ovsdb_parser *p, const char *name, bool optional,
             struct uuid *uuid)
{
    const char *s = parse_string__(p, name, optional);
    if (s) {
        if (uuid_from_string(uuid, s)) {
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
        jsonrpc_session_close(s->js);
        free(s->address);
        free(s);
    }
}

static void
raft_servers_destroy(struct hmap *servers)
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

static void
raft_servers_clone(struct hmap *dst, struct hmap *src)
{
    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, src) {
        struct raft_server *s2 = raft_server_clone(s);
        hmap_insert(dst, &s2->hmap_node, uuid_hash(&s2->sid));
    }
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_servers_from_json__(const struct json *json, struct hmap *servers)
{
    if (!json || json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "servers must be JSON object");
    } else if (shash_is_empty(json_object(json))) {
        return ovsdb_syntax_error(json, NULL, "must have at least one server");
    }

    /* Parse new servers. */
    struct shash_node *node;
    SHASH_FOR_EACH (node, json_object(json)) {
        /* Parse server UUID. */
        struct uuid sid;
        if (!uuid_from_string(&sid, node->name)) {
            return ovsdb_syntax_error(json, NULL, "%s is a not a UUID",
                                      node->name);
        }

        /* Parse server address. */
        const struct json *address_json = node->data;
        if (address_json->type != JSON_STRING) {
            return ovsdb_syntax_error(json, NULL, "%s value is not string",
                                      node->name);
        }
        const char *address = json_string(address_json);
        struct ovsdb_error *error = raft_parse_address(address, NULL, NULL);
        if (error) {
            return error;
        }

        struct raft_server *s = xzalloc(sizeof *s);
        s->sid = sid;
        s->address = xstrdup(address);
        hmap_insert(servers, &s->hmap_node, uuid_hash(&s->sid));
    }

    return NULL;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_servers_from_json(const struct json *json, struct hmap *servers)
{
    hmap_init(servers);
    struct ovsdb_error *error = raft_servers_from_json__(json, servers);
    if (error) {
        raft_servers_destroy(servers);
    }
    return error;
}

static struct json *
raft_servers_to_json(const struct hmap *servers)
{
    struct json *json = json_object_create();
    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, servers) {
        char sid_s[UUID_LEN + 1];
        sprintf(sid_s, UUID_FMT, UUID_ARGS(&s->sid));
        json_object_put_string(json, sid_s, s->address);
    }
    return json;
}

static void
raft_set_servers(struct raft *raft, const struct hmap *new_servers)
{
    struct raft_server *s, *next;
    HMAP_FOR_EACH_SAFE (s, next, hmap_node, &raft->servers) {
        if (!raft_find_server__(new_servers, &s->sid)) {
            if (raft->me == s) {
                raft->me = NULL;
                /* XXX */
            }
            /* XXX raft->leader */
            /* XXX raft->remove_server */
            hmap_remove(&raft->servers, &s->hmap_node);
            raft_server_destroy(s);
        }
    }

    HMAP_FOR_EACH_SAFE (s, next, hmap_node, new_servers) {
        if (!raft_find_server__(&raft->servers, &s->sid)) {
            struct raft_server *new = xzalloc(sizeof *new);
            new->sid = s->sid;
            new->address = xstrdup(s->address);
            new->voted = true;  /* XXX conservative */
            raft_server_init_leader(raft, new);
        }
    }
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_entry_from_json(struct json *json, struct raft_entry *e)
{
    memset(e, 0, sizeof *e);

    struct ovsdb_parser p;
    ovsdb_parser_init(&p, json, "raft log entry");
    e->term = parse_uint(&p, "term");
    const struct json *servers_json = ovsdb_parser_member(
        &p, "servers", OP_OBJECT | OP_OPTIONAL);
    if (servers_json) {
        struct hmap servers;
        struct ovsdb_error *error = raft_servers_from_json(servers_json,
                                                           &servers);
        if (error) {
            return error;
        }
        raft_servers_destroy(&servers);

        e->type = RAFT_SERVERS;
        e->data = json_to_string(servers_json, 0);
    } else {
        const struct json *data = ovsdb_parser_member(&p, "data", OP_STRING);
        if (data) {
            e->type = RAFT_DATA;
            e->data = xstrdup(json_string(data));
        }
    }

    struct ovsdb_error *error = ovsdb_parser_finish(&p);
    if (error) {
        free(e->data);
    }
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

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_write_entry(struct raft *raft,
                 uint64_t term, enum raft_entry_type type, char *data)
{
    /* XXX when one write fails we need to make all subsequent writes fail (or
     * just not attempt them) since omitting some writes is fatal */

    raft_add_entry(raft, term, type, data);
    struct json *json = raft_entry_to_json_with_index(raft, raft->log_end - 1);
    struct ovsdb_error *error = ovsdb_log_write_json(raft->storage, json);
    json_destroy(json);

    if (error) {
        /* XXX? */
        free(&raft->log[--raft->log_end].data);
    }

    return error;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_write_state(struct raft *raft, uint64_t term, const struct uuid *vote)
{
    struct json *json = json_object_create();
    json_object_put_uint(json, "term", term);
    if (vote) {
        json_object_put_format(json, "vote", UUID_FMT, UUID_ARGS(vote));
    }
    struct ovsdb_error *error = ovsdb_log_write_json(raft->storage, json);
    json_destroy(json);

    return error;
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
    uint64_t term = parse_uint(&p, "term");
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
    const struct json *servers_json
        = ovsdb_parser_member(&p, "servers", OP_OBJECT | OP_OPTIONAL);
    if (servers_json) {
        struct hmap servers;
        struct ovsdb_error *error = raft_servers_from_json(servers_json,
                                                           &servers);
        if (error) {
            ovsdb_error_destroy(ovsdb_parser_finish(&p));
            return error;
        }

        raft_set_servers(raft, &servers);
        raft_servers_destroy(&servers);
        raft_add_entry(raft, term, RAFT_SERVERS,
                       json_to_string(servers_json, 0));
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

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_read(struct raft *raft)
{
    /* Read header record. */
    struct json *header;
    struct ovsdb_error *error = ovsdb_log_read_json(raft->storage, &header);
    if (error || !header) {
        /* Report error or end-of-file. */
        return error;
    }
    struct ovsdb_parser p;
    ovsdb_parser_init(&p, header, "raft header");
    raft->cid = parse_required_uuid(&p, "cluster_id");
    raft->sid = parse_required_uuid(&p, "server_id");
    error = ovsdb_parser_finish(&p);
    json_destroy(header);
    if (error) {
        return error;
    }

    /* Read snapshot record. */
    struct json *snapshot;
    error = ovsdb_log_read_json(raft->storage, &snapshot);
    if (error || !snapshot) {
        /* Report error or end-of-file. */
        return error;
    }
    ovsdb_parser_init(&p, snapshot, "raft snapshot");
    raft->prev_term = parse_uint(&p, "prev_term");
    raft->log_start = raft->log_end = parse_uint(&p, "prev_index") + 1;
    const struct json *prev_servers_json = ovsdb_parser_member(
        &p, "prev_servers", OP_OBJECT);
    const struct json *data = ovsdb_parser_member(
        &p, "data", OP_STRING | OP_OPTIONAL);
    error = ovsdb_parser_finish(&p);
    if (error) {
        json_destroy(snapshot);
        return error;
    }

    raft->snapshot = xstrdup(data ? json_string(data) : "");

    struct hmap prev_servers;
    error = raft_servers_from_json(prev_servers_json, &prev_servers);
    json_destroy(snapshot);
    if (error) {
        return error;
    }
    hmap_swap(&prev_servers, &raft->prev_servers);
    raft_servers_destroy(&prev_servers);

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
        raft_servers_clone(&raft->servers, &raft->prev_servers);
    }

    return NULL;
}

static void
raft_reset_timer(struct raft *raft)
{
    raft->election_timeout = (time_msec()
                              + ELECTION_TIME_BASE_MSEC
                              + random_range(ELECTION_TIME_RANGE_MSEC));
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_open__(const char *file_name, enum ovsdb_log_open_mode mode,
            struct raft **raftp)
{
    struct raft *raft = xzalloc(sizeof *raft);
    raft->role = RAFT_FOLLOWER;
    raft_reset_timer(raft);
    hmap_init(&raft->servers);
    hmap_init(&raft->prev_servers);
    hmap_init(&raft->add_servers);
    raft->listen_backoff = LLONG_MIN;
    ovs_list_init(&raft->conns);
    ovs_mutex_init(&raft->fsync_mutex);
    raft->fsync_request = seq_create();
    raft->fsync_complete = seq_create();
    ovs_list_init(&raft->waiters);

    struct ovsdb_error *error = ovsdb_log_open(file_name, RAFT_MAGIC, mode,
                                               -1, &raft->storage);
    if (error) {
        goto error;
    }

    raft->fsync_thread = ovs_thread_create("raft_fsync",
                                           raft_fsync_thread, raft);

    error = raft_read(raft);
    if (error) {
        goto error;
    }
    *raftp = raft;
    return NULL;

error:
    raft_close(raft);
    *raftp = NULL;
    return error;
}

/* Starts the local server in an existing Raft cluster, using the local copy of
 * the cluster's log in 'file_name'. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_open(const char *file_name, struct raft **raftp)
{
    struct raft *raft;
    struct ovsdb_error *error = raft_open__(file_name, OVSDB_LOG_READ_WRITE,
                                            &raft);
    if (!error && (uuid_is_zero(&raft->cid) || !raft->snapshot)) {
        error = ovsdb_error(NULL, "%s: not a fully initialized log",
                            file_name);
    }
    if (error) {
        goto error;
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

/* Adds a new server, the one one which this function is called, to an existing
 * Raft cluster.
 *
 * Creates the local copy of the cluster's log in 'file_name'.  If 'file_name'
 * already exists, then it must be from a previous call to this function for
 * the same cluster and the same 'local_address'; if so, then the previous
 * attempt to join the cluster will resume.
 *
 * The new server is located at 'local_address', which must take one of the
 * forms "tcp:IP[:PORT]" or "ssl:IP[:PORT]", where IP is an IPv4 address or a
 * square bracket enclosed IPv6 address.  PORT, if present, is a port number
 * that defaults to RAFT_PORT.
 *
 * Joining the cluster requiring contacting it.  Thus, the 'n_remotes'
 * addresses in 'remote_addresses' specify the addresses of existing servers in
 * the cluster.  One server out of the existing cluster is sufficient, as long
 * as that server is reachable and not partitioned from the current cluster
 * leader.  If multiple servers from the cluster are specified, then it is
 * sufficient for any of them to meet this criterion.
 *
 * 'cid' is optional.  If specified, the new server will join only the cluster
 * with the given cluster ID.
 *
 * This function blocks until the join succeeds or fails.
 */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_join(const char *file_name, const char *local_address,
          const char *remote_addresses[] OVS_UNUSED /* XXX */,
          size_t n_remotes OVS_UNUSED /* XXX */,
          const struct uuid *cid_, struct raft **raftp)
{
    struct raft *raft = NULL;

    /* Parse and verify validity of the local address.
     *
     * XXX Test that the local machine can bind the local address. */
    struct ovsdb_error *error = raft_parse_address(local_address, NULL, NULL);
    if (error) {
        goto error;
    }

    /* Read the log, if there is one, or create it otherwise. */
    error = raft_open__(file_name, OVSDB_LOG_CREATE, &raft);
    if (error) {
        goto error;
    }

    /* Check the cluster ID, if specified, against the one in the file, if
     * there was one. */
    if (cid_ && !uuid_is_zero(&raft->cid) && !uuid_equals(&raft->cid, cid_)) {
        error = ovsdb_error(NULL, "%s: already initialized for cluster "
                            UUID_FMT" (expected "UUID_FMT")",
                            file_name, UUID_ARGS(&raft->cid), UUID_ARGS(cid_));
        goto error;
    }
    if (uuid_is_zero(&raft->cid)) {
        raft->sid = uuid_generate();
        if (cid_) {
            raft->cid = *cid_;
            error = raft_write_header(raft->storage, &raft->cid, &raft->sid);
            if (error) {
                goto error;
            }
        }
    }

    raft->me = raft_find_server(raft, &raft->sid);
    if (raft->me) {
        /* Already joined to this cluster.  Nothing to do. */
        *raftp = raft;
        return NULL;
    }

    /* Connect to all of the 'remote_addresses' in parallel.
     * Send each of them an AddServer RPC.
     * For each response:
     *
     *     - Adopt the cid in the response, or report an error if we have one
     *       already and it's different.
     *
     *     - addserver reply NOT_LEADER: open connection to leader.
     *
     *     - installsnapshot/appendentries: focus on this connection unless it
     *       dies */

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

    ovs_mutex_lock(&raft->fsync_mutex);
    raft->fsync_next = UINT64_MAX;
    ovs_mutex_unlock(&raft->fsync_mutex);
    seq_change(raft->fsync_request);
    xpthread_join(raft->fsync_thread, NULL);

    ovsdb_log_close(raft->storage);

    raft_servers_destroy(&raft->servers);

    for (uint64_t index = raft->log_start; index < raft->log_end; index++) {
        struct raft_entry *e = &raft->log[index - raft->log_start];
        free(e->data);
    }
    free(raft->log);

    raft_servers_destroy(&raft->prev_servers);
    free(raft->snapshot);

    struct raft_conn *conn, *next;
    LIST_FOR_EACH_SAFE (conn, next, list_node, &raft->conns) {
        jsonrpc_session_close(conn->js);
        ovs_list_remove(&conn->list_node);
        free(conn);
    }

    raft_servers_destroy(&raft->add_servers);
    raft_server_destroy(raft->remove_server);

    free(raft);
}

static void
raft_run_session(struct raft *raft, struct jsonrpc_session *s,
                 struct uuid *sid)
{
    jsonrpc_session_run(s);
    for (size_t i = 0; i < 50; i++) {
        struct jsonrpc_msg *msg = jsonrpc_session_recv(s);
        if (!msg) {
            break;
        }

        union raft_rpc rpc;
        struct ovsdb_error *error = raft_rpc_from_jsonrpc(raft, msg, &rpc);
        if (error) {
            char *error_s = ovsdb_error_to_string(error);
            ovsdb_error_destroy(error);
            VLOG_INFO("%s: %s", jsonrpc_session_get_name(s), error_s);
            free(error_s);
            break;
        }
        if (sid) {
            if (uuid_is_zero(sid)) {
                *sid = rpc.common.sid;
            } else if (!uuid_equals(sid, &rpc.common.sid)) {
                static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
                VLOG_WARN_RL(&rl, "%s: remote server ID changed from "
                             UUID_FMT" to "UUID_FMT,
                             jsonrpc_session_get_name(s),
                             UUID_ARGS(sid), UUID_ARGS(&rpc.common.sid));
            }
        }
        raft_receive(raft, &rpc);
        raft_rpc_destroy(&rpc);
    }
}

static void
raft_waiter_complete(struct raft *raft, struct raft_waiter *w)
{
    switch (w->type) {
    case RAFT_W_COMMAND:
        raft_update_match_index(raft, raft->me, w->command.index);
        break;

    case RAFT_W_APPEND:
        raft_send_append_reply(raft, w->append.rq, true);
        break;
    }
}

static void
raft_command_unref(struct raft_command *cmd)
{
    if (cmd && ovs_refcount_unref(&cmd->refcnt) == 1) {
        free(cmd);
    }
}

static void
raft_waiter_destroy(struct raft_waiter *w)
{
    if (!w) {
        return;
    }

    switch (w->type) {
    case RAFT_W_COMMAND:
        raft_command_unref(w->command.cmd);
        break;

    case RAFT_W_APPEND:
        free(w->append.rq);
        break;
    }
    free(w);
}

static void
raft_waiters_run(struct raft *raft)
{
    if (ovs_list_is_empty(&raft->waiters)) {
        return;
    }

    ovs_mutex_lock(&raft->fsync_mutex);
    uint64_t cur = raft->fsync_cur;
    ovs_mutex_unlock(&raft->fsync_mutex);

    struct raft_waiter *w, *next;
    LIST_FOR_EACH_SAFE (w, next, list_node, &raft->waiters) {
        if (cur < w->fsync_seqno) {
            break;
        }
        raft_waiter_complete(raft, w);
        ovs_list_remove(&w->list_node);
        raft_waiter_destroy(w);
    }
}

static void
raft_waiters_wait(struct raft *raft)
{
    if (ovs_list_is_empty(&raft->waiters)) {
        return;
    }

    uint64_t complete = seq_read(raft->fsync_complete);

    ovs_mutex_lock(&raft->fsync_mutex);
    uint64_t cur = raft->fsync_cur;
    ovs_mutex_unlock(&raft->fsync_mutex);

    struct raft_waiter *w, *next;
    LIST_FOR_EACH_SAFE (w, next, list_node, &raft->waiters) {
        if (cur < w->fsync_seqno) {
            seq_wait(raft->fsync_complete, complete);
        } else {
            poll_immediate_wake();
        }
        break;
    }
}

static void
raft_set_term(struct raft *raft, uint64_t term, const struct uuid *vote)
{
    struct ovsdb_error *error = raft_write_state(raft, term, vote);
    if (error) {
        /* XXX */
    }
    /* XXX need to commit before replying */
    raft->current_term = term;
    raft->voted_for = vote ? *vote : UUID_ZERO;
}


static void
raft_accept_vote(struct raft *raft, struct raft_server *s, bool granted)
{
    if (s->voted) {
        return;
    }
    s->voted = true;
    if (granted
        && ++raft->n_votes > hmap_count(&raft->servers) / 2) {
        raft_become_leader(raft);
    }
}

static void
raft_start_election(struct raft *raft)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    ovs_assert(raft->role != RAFT_LEADER);
    raft->role = RAFT_CANDIDATE;
    raft_reset_timer(raft);

    /* XXX what if we're not part of the server set? */

    raft_set_term(raft, raft->current_term + 1, &raft->sid);
    raft->n_votes = 0;

    VLOG_INFO_RL(&rl, "term %"PRIu64": starting election", raft->current_term);

    struct raft_server *peer;
    HMAP_FOR_EACH (peer, hmap_node, &raft->servers) {
        peer->voted = false;
        if (peer == raft->me) {
            continue;
        }

        union raft_rpc rq = {
            .vote_request = {
                .common = {
                    .type = RAFT_RPC_VOTE_REQUEST,
                    .sid = peer->sid,
                },
                .term = raft->current_term,
                .last_log_index = raft->log_end - 1,
                .last_log_term = (
                    raft->log_end > raft->log_start
                    ? raft->log[raft->log_end - raft->log_start].term
                    : raft->prev_term),
            },
        };
        raft_send(raft, &rq);
    }

    /* Vote for ourselves. */
    raft_accept_vote(raft, raft->me, true);

    /* XXX how do we handle outstanding waiters? */
}

void
raft_run(struct raft *raft)
{
    raft_waiters_run(raft);

    if (!raft->listener && time_msec() >= raft->listen_backoff) {
        char *paddr = raft_make_address_passive(raft->me->address);
        int error = pstream_open(paddr, &raft->listener, DSCP_DEFAULT);
        if (error) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "%s: listen failed (%s)",
                         paddr, ovs_strerror(error));
            raft->listen_backoff = time_msec() + 1000;
        }
        free(paddr);
    }

    if (raft->listener) {
        struct stream *stream;
        int error = pstream_accept(raft->listener, &stream);
        if (!error) {
            struct raft_conn *conn = xzalloc(sizeof *conn);
            conn->js = jsonrpc_session_open_unreliably(jsonrpc_open(stream),
                                                       DSCP_DEFAULT);
            ovs_list_push_back(&raft->conns, &conn->list_node);
        } else if (error != EAGAIN) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "%s: accept failed: %s",
                         pstream_get_name(raft->listener),
                         ovs_strerror(error));
        }
    }

    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        if (!s->js && s != raft->me) {
            s->js = jsonrpc_session_open(s->address, true);
        }
        if (s->js) {
            raft_run_session(raft, s->js, &s->sid);
        }
    }

    struct raft_conn *conn, *next;
    LIST_FOR_EACH_SAFE (conn, next, list_node, &raft->conns) {
        raft_run_session(raft, conn->js, &conn->sid);
        if (!jsonrpc_session_is_alive(conn->js)) {
            jsonrpc_session_close(conn->js);
            ovs_list_remove(&conn->list_node);
            free(conn);
        }
    }

    if (time_msec() >= raft->election_timeout) {
        raft_start_election(raft);
    }
    /* XXX if we're leader and we're idle, send empty appendrequest */
}

void
raft_wait(struct raft *raft)
{
    raft_waiters_wait(raft);

    if (raft->listener) {
        pstream_wait(raft->listener);
    } else {
        poll_timer_wait_until(raft->listen_backoff);
    }

    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        if (s->js) {
            jsonrpc_session_wait(s->js);
            jsonrpc_session_recv_wait(s->js);
        }
    }

    struct raft_conn *conn;
    LIST_FOR_EACH (conn, list_node, &raft->conns) {
        jsonrpc_session_wait(conn->js);
        jsonrpc_session_recv_wait(conn->js);
    }

    poll_timer_wait_until(raft->election_timeout);
}

static struct raft_waiter *
raft_waiter_create(struct raft *raft, enum raft_waiter_type type)
{
    ovs_mutex_lock(&raft->fsync_mutex);
    uint64_t seqno = ++raft->fsync_next;
    ovs_mutex_unlock(&raft->fsync_mutex);

    seq_change(raft->fsync_request);

    struct raft_waiter *w = xzalloc(sizeof *w);
    ovs_list_push_back(&raft->waiters, &w->list_node);
    w->fsync_seqno = seqno;
    w->type = type;
    return w;
}

struct raft_command *
raft_command_execute(struct raft *raft, const void *data)
{
    struct raft_command *cmd = xzalloc(sizeof *cmd);
    if (raft->role != RAFT_LEADER) {
        cmd->status = RAFT_CMD_NOT_LEADER;
        return cmd;
    }

    uint64_t index = raft->log_end;
    ovs_refcount_init(&cmd->refcnt);
    cmd->status = RAFT_CMD_INCOMPLETE;

    /* Write to local log.
     *
     * XXX If this server is being removed from the configuration then we
     * should not writ to the local log; see section 4.2.2.  Or we could
     * implement leadership transfer. */
    struct ovsdb_error *error = raft_write_entry(raft, raft->current_term,
                                                 RAFT_DATA, xstrdup(data));
    if (!error) {
        ovs_refcount_ref(&cmd->refcnt);

        struct raft_waiter *w = raft_waiter_create(raft, RAFT_W_COMMAND);
        w->command.cmd = cmd;
        w->command.index = index;
    } else {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        char *s = ovsdb_error_to_string(error);
        VLOG_WARN_RL(&rl, "%s", s);
        free(s);
        ovsdb_error_destroy(error);

        /* XXX make this a hard failure if cluster has <=2 servers. */
    }

    /* Write to remote logs. */
    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->servers) {
        if (s != raft->me && s->next_index == raft->log_end - 1) {
            raft_send_append_request(raft, s, 1);
            s->next_index++;    /* XXX Is this a valid way to pipeline? */
        }
    }

    return cmd;
}

static void
raft_rpc_destroy(union raft_rpc *rpc)
{
    if (!rpc) {
        return;
    }

    switch (rpc->common.type) {
    case RAFT_RPC_APPEND_REQUEST:
        for (size_t i = 0; i < rpc->append_request.n_entries; i++) {
            free(rpc->append_request.entries[i].data);
        }
        free(rpc->append_request.entries);
        break;
    case RAFT_RPC_APPEND_REPLY:
    case RAFT_RPC_VOTE_REQUEST:
    case RAFT_RPC_VOTE_REPLY:
        break;
    case RAFT_RPC_ADD_SERVER_REQUEST:
    case RAFT_RPC_REMOVE_SERVER_REQUEST:
        free(rpc->server_request.address);
        break;
    case RAFT_RPC_ADD_SERVER_REPLY:
    case RAFT_RPC_REMOVE_SERVER_REPLY:
        free(rpc->server_reply.leader_address);
        break;
    case RAFT_RPC_INSTALL_SNAPSHOT_REQUEST:
        raft_servers_destroy(&rpc->install_snapshot_request.servers);
        free(rpc->install_snapshot_request.data);
        break;
    case RAFT_RPC_INSTALL_SNAPSHOT_REPLY:
        break;
    }
}

/* raft_rpc_to/from_jsonrpc(). */

static void
raft_append_request_to_jsonrpc(const struct raft_append_request *rq,
                               struct json *args)
{
    json_object_put_uint(args, "term", rq->term);
    if (!uuid_is_zero(&rq->leader_sid)) {
        json_object_put_format(args, "leader",
                               UUID_FMT, UUID_ARGS(&rq->leader_sid));
    }
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
    rq->term = parse_uint(p, "term");
    parse_optional_uuid(p, "leader", &rq->leader_sid);
    rq->prev_log_index = parse_uint(p, "prev_log_index");
    rq->prev_log_term = parse_uint(p, "prev_log_term");
    rq->leader_commit = parse_uint(p, "leader_commit");

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
    json_object_put(args, "success", json_boolean_create(rpy->success));
}

static void
raft_append_reply_from_jsonrpc(struct ovsdb_parser *p,
                               struct raft_append_reply *rpy)
{
    rpy->term = parse_uint(p, "term");
    rpy->log_end = parse_uint(p, "log_end");
    rpy->prev_log_index = parse_uint(p, "prev_log_index");
    rpy->prev_log_term = parse_uint(p, "prev_log_term");
    rpy->n_entries = parse_uint(p, "n_entries");
    rpy->success = parse_boolean(p, "success");
}

static void
raft_vote_request_to_jsonrpc(const struct raft_vote_request *rq,
                             struct json *args)
{
    json_object_put_uint(args, "term", rq->term);
    json_object_put_uint(args, "last_log_index", rq->last_log_index);
    json_object_put_uint(args, "last_log_term", rq->last_log_term);
}

static void
raft_vote_request_from_jsonrpc(struct ovsdb_parser *p,
                               struct raft_vote_request *rq)
{
    rq->term = parse_uint(p, "term");
    rq->last_log_index = parse_uint(p, "last_log_index");
    rq->last_log_term = parse_uint(p, "last_log_term");
}

static void
raft_vote_reply_to_jsonrpc(const struct raft_vote_reply *rpy,
                           struct json *args)
{
    json_object_put_uint(args, "term", rpy->term);
    json_object_put(args, "vote_granted",
                    json_boolean_create(rpy->vote_granted));
}

static void
raft_vote_reply_from_jsonrpc(struct ovsdb_parser *p,
                             struct raft_vote_reply *rpy)
{
    rpy->term = parse_uint(p, "term");
    rpy->vote_granted = parse_boolean(p, "vote_granted");
}

static void
raft_server_request_to_jsonrpc(const struct raft_server_request *rq,
                               struct json *args)
{
    json_object_put_format(args, "server_id", UUID_FMT, UUID_ARGS(&rq->sid));
    if (rq->address) {
        json_object_put_string(args, "address", rq->address);
    }
}

static void
raft_server_request_from_jsonrpc(struct ovsdb_parser *p,
                                 struct raft_server_request *rq)
{
    rq->sid = parse_required_uuid(p, "server_id");
    if (rq->common.type == RAFT_RPC_ADD_SERVER_REQUEST) {
        const struct json *json = ovsdb_parser_member(p, "address", OP_STRING);
        if (json) {
            rq->address = xstrdup(json_string(json));
        }
    }
}

static void
raft_server_reply_to_jsonrpc(const struct raft_server_reply *rpy,
                             struct json *args)
{
    json_object_put_string(args, "status",
                           raft_server_status_to_string(rpy->status));
    if (rpy->leader_address) {
        json_object_put_string(args, "leader_address", rpy->leader_address);
        json_object_put_format(args, "leader", UUID_FMT,
                               UUID_ARGS(&rpy->leader_sid));
    }
}

static void
raft_server_reply_from_jsonrpc(struct ovsdb_parser *p,
                               struct raft_server_reply *rpy)
{
    const char *status = parse_required_string(p, "status");
    if (status && !raft_server_status_from_string(status, &rpy->status)) {
        ovsdb_parser_raise_error(p, "unknown server status \"%s\"",
                                 status);
    }

    const char *leader_address = parse_optional_string(p, "leader_address");
    rpy->leader_address = leader_address ? xstrdup(leader_address) : NULL;
    if (rpy->leader_address) {
        rpy->leader_sid = parse_required_uuid(p, "leader");
    }
}

static void
raft_install_snapshot_request_to_jsonrpc(
    const struct raft_install_snapshot_request *rq, struct json *args)
{
    json_object_put_uint(args, "term", rq->term);
    json_object_put_format(args, "leader",
                           UUID_FMT, UUID_ARGS(&rq->leader_sid));
    json_object_put_uint(args, "last_index", rq->last_index);
    json_object_put_uint(args, "last_term", rq->last_term);
    json_object_put(args, "servers", raft_servers_to_json(&rq->servers));

    json_object_put_uint(args, "offset", rq->offset);
    json_object_put(args, "data",
                    json_string_create_nocopy(xmemdup0(rq->data, rq->len)));

    json_object_put(args, "done", json_boolean_create(rq->done));
}

static void
raft_install_snapshot_request_from_jsonrpc(
    struct ovsdb_parser *p, struct raft_install_snapshot_request *rq)
{
    const struct json *servers = ovsdb_parser_member(p, "servers", OP_OBJECT);
    struct ovsdb_error *error = raft_servers_from_json(servers, &rq->servers);
    if (error) {
        ovsdb_parser_put_error(p, error);
        return;
    }

    rq->term = parse_uint(p, "term");
    rq->leader_sid = parse_required_uuid(p, "leader");
    rq->last_index = parse_uint(p, "last_index");
    rq->last_term = parse_uint(p, "last_term");

    rq->offset = parse_uint(p, "offset");
    rq->data = xstrdup(parse_required_string(p, "data"));
    rq->len = strlen(rq->data);

    rq->done = parse_boolean(p, "done");
}

static void
raft_install_snapshot_reply_to_jsonrpc(
    const struct raft_install_snapshot_reply *rpy, struct json *args)
{
    json_object_put_uint(args, "term", rpy->term);
}

static void
raft_install_snapshot_reply_from_jsonrpc(
    struct ovsdb_parser *p,
    struct raft_install_snapshot_reply *rpy)
{
    rpy->term = parse_uint(p, "term");
}

static struct jsonrpc_msg *
raft_rpc_to_jsonrpc(const struct raft *raft,
                    const union raft_rpc *rpc)
{
    struct json *args = json_object_create();
    json_object_put_format(args, "cluster", UUID_FMT, UUID_ARGS(&raft->cid));
    json_object_put_format(args, "from", UUID_FMT, UUID_ARGS(&raft->sid));
    json_object_put_format(args, "to", UUID_FMT, UUID_ARGS(&rpc->common.sid));

    switch (rpc->common.type) {
    case RAFT_RPC_APPEND_REQUEST:
        raft_append_request_to_jsonrpc(&rpc->append_request,
                                       args);
        break;
    case RAFT_RPC_APPEND_REPLY:
        raft_append_reply_to_jsonrpc(&rpc->append_reply, args);
        break;
    case RAFT_RPC_VOTE_REQUEST:
        raft_vote_request_to_jsonrpc(&rpc->vote_request, args);
        break;
    case RAFT_RPC_VOTE_REPLY:
        raft_vote_reply_to_jsonrpc(&rpc->vote_reply, args);
        break;
    case RAFT_RPC_ADD_SERVER_REQUEST:
        raft_server_request_to_jsonrpc(&rpc->server_request, args);
        break;
    case RAFT_RPC_ADD_SERVER_REPLY:
        raft_server_reply_to_jsonrpc(&rpc->server_reply, args);
        break;
    case RAFT_RPC_REMOVE_SERVER_REQUEST:
        raft_server_request_to_jsonrpc(&rpc->server_request, args);
        break;
    case RAFT_RPC_REMOVE_SERVER_REPLY:
        raft_server_reply_to_jsonrpc(&rpc->server_reply, args);
        break;
    case RAFT_RPC_INSTALL_SNAPSHOT_REQUEST:
        raft_install_snapshot_request_to_jsonrpc(
            &rpc->install_snapshot_request, args);
        break;
    case RAFT_RPC_INSTALL_SNAPSHOT_REPLY:
        raft_install_snapshot_reply_to_jsonrpc(
            &rpc->install_snapshot_reply, args);
        break;
    default:
        OVS_NOT_REACHED();
    }

    return jsonrpc_create_notify(raft_rpc_type_to_string(rpc->common.type),
                                 json_array_create_1(args));
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_rpc_from_jsonrpc(const struct raft *raft,
                      const struct jsonrpc_msg *msg, union raft_rpc *rpc)
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

    bool is_add = rpc->common.type == RAFT_RPC_ADD_SERVER_REQUEST;
    struct uuid cid;
    if (parse_uuid__(&p, "cluster", is_add, &cid)
        && !uuid_equals(&cid, &raft->cid)) {
        ovsdb_parser_raise_error(&p, "wrong cluster "UUID_FMT" "
                                 "(expected "UUID_FMT")",
                                 UUID_ARGS(&cid), UUID_ARGS(&raft->cid));
    }

    struct uuid to_sid;
    if (parse_uuid__(&p, "to", is_add, &to_sid)
        && !uuid_equals(&to_sid, &raft->sid)) {
        ovsdb_parser_raise_error(&p, "misrouted message (addressed to "
                                 UUID_FMT" but we're "UUID_FMT")",
                                 UUID_ARGS(&to_sid),
                                 UUID_ARGS(&raft->sid));
    }

    rpc->common.sid = parse_required_uuid(&p, "from");

    switch (rpc->common.type) {
    case RAFT_RPC_APPEND_REQUEST:
        raft_append_request_from_jsonrpc(&p, &rpc->append_request);
        break;
    case RAFT_RPC_APPEND_REPLY:
        raft_append_reply_from_jsonrpc(&p, &rpc->append_reply);
        break;
    case RAFT_RPC_VOTE_REQUEST:
        raft_vote_request_from_jsonrpc(&p, &rpc->vote_request);
        break;
    case RAFT_RPC_VOTE_REPLY:
        raft_vote_reply_from_jsonrpc(&p, &rpc->vote_reply);
        break;
    case RAFT_RPC_ADD_SERVER_REQUEST:
        raft_server_request_from_jsonrpc(&p, &rpc->server_request);
        break;
    case RAFT_RPC_ADD_SERVER_REPLY:
        raft_server_reply_from_jsonrpc(&p, &rpc->server_reply);
        break;
    case RAFT_RPC_REMOVE_SERVER_REQUEST:
        raft_server_request_from_jsonrpc(&p, &rpc->server_request);
        break;
    case RAFT_RPC_REMOVE_SERVER_REPLY:
        raft_server_reply_from_jsonrpc(&p, &rpc->server_reply);
        break;
    case RAFT_RPC_INSTALL_SNAPSHOT_REQUEST:
        raft_install_snapshot_request_from_jsonrpc(
            &p, &rpc->install_snapshot_request);
        break;
    case RAFT_RPC_INSTALL_SNAPSHOT_REPLY:
        raft_install_snapshot_reply_from_jsonrpc(
            &p, &rpc->install_snapshot_reply);
        break;
    default:
        OVS_NOT_REACHED();
    }

    struct ovsdb_error *error = ovsdb_parser_finish(&p);
    if (error) {
        raft_rpc_destroy(rpc);
    }
    return error;
}

static void
raft_send_server_reply(struct raft *raft,
                       const struct uuid *sid, enum raft_server_status status)
{
    union raft_rpc rpy = {
        .server_reply = {
            .common = {
                .type = RAFT_RPC_ADD_SERVER_REPLY,
                .sid = *sid,
            },
            .status = status,

            /* XXX do we maintain leaderHint properly? */
            .leader_address = raft->leader ? raft->leader->address : NULL,
            .leader_sid = raft->leader ? raft->leader->sid : UUID_ZERO,
        }
    };
    raft_send(raft, &rpy);
}

static void
raft_become_follower(struct raft *raft)
{
    if (raft->role == RAFT_FOLLOWER) {
        return;
    }

    raft->role = RAFT_FOLLOWER;
    raft_reset_timer(raft);

    /* Notify clients about lost leadership.
     *
     * We do not reverse our changes to 'raft->servers' because the new
     * configuration is already part of the log.  Possibly the configuration
     * log entry will not be committed, but until we know that we must use the
     * new configuration.  Our AppendEntries processing will properly update
     * the server configuration later, if necessary. */
    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, &raft->add_servers) {
        raft_send_server_reply(raft, &s->sid, RAFT_SERVER_LOST_LEADERSHIP);
    }
    if (raft->remove_server) {
        raft_send_server_reply(raft, &raft->remove_server->reply_sid,
                               RAFT_SERVER_LOST_LEADERSHIP);
        raft_server_destroy(raft->remove_server);
        raft->remove_server = NULL;
    }

    /* XXX how do we handle outstanding waiters? */
}

static void
raft_send_append_request(struct raft *raft,
                         struct raft_server *peer, unsigned int n)
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
    raft_send(raft, &rq);
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
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    VLOG_INFO_RL(&rl, "term %"PRIu64": elected leader by %d+ of "
                 "%"PRIuSIZE" servers", raft->current_term,
                 raft->n_votes, hmap_count(&raft->servers));

    ovs_assert(raft->role != RAFT_LEADER);
    raft->role = RAFT_LEADER;
    raft->leader = raft->me;
    raft->election_timeout = LLONG_MAX;

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
        raft_set_term(raft, term, NULL);
        raft_become_follower(raft);
    } else if (term < raft->current_term) {
        return false;
    }
    return true;
}

static void
raft_get_servers_from_log(struct raft *raft)
{
    for (uint64_t index = raft->log_end - 1; index >= raft->log_start;
         index--) {
        struct raft_entry *e = &raft->log[index - raft->log_start];
        if (e->type == RAFT_SERVERS) {
            struct json *json = json_from_string(e->data);
            struct hmap servers;
            struct ovsdb_error *error = raft_servers_from_json(json, &servers);
            ovs_assert(!error);
            raft_set_servers(raft, &servers);
            raft_servers_destroy(&servers);
            json_destroy(json);
            return;
        }
    }
    raft_set_servers(raft, &raft->prev_servers);
}

/* Returns 1 on success, 0 for failure, -1 for an operation in progress. */
static int
raft_handle_append_entries(struct raft *raft,
                           const struct raft_append_request *rq,
                           uint64_t prev_log_index, uint64_t prev_log_term,
                           const struct raft_entry *entries,
                           unsigned int n_entries)
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
    unsigned int i;
    bool servers_changed = false;
    for (i = 0; ; i++) {
        if (i >= n_entries) {
            /* No change. */
            return true;
        }

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
                if (entry->type == RAFT_SERVERS) {
                    servers_changed = true;
                }
                free(entry->data);
            }
            break;
        }
    }

    /* Figure 3.1: "Append any entries not already in the log." */
    struct ovsdb_error *error = NULL;
    for (; i < n_entries; i++) {
        const struct raft_entry *entry = &entries[i];
        error = raft_write_entry(raft, entry->term, entry->type,
                                 xstrdup(entry->data));
        if (error) {
            break;
        }
        if (entry->type == RAFT_SERVERS) {
            servers_changed = true;
        }
    }

    if (servers_changed) {
        raft_get_servers_from_log(raft);
    }

    if (error) {
        return false;
    }

    struct raft_waiter *w = raft_waiter_create(raft, RAFT_W_APPEND);
    w->append.rq = xmemdup(rq, sizeof *rq);
    w->append.rq->entries = NULL;
    return -1;
}

/* Returns 1 on success, 0 for failure, -1 for an operation in progress. */
static int
raft_handle_append_request__(struct raft *raft,
                             const struct raft_append_request *rq)
{
    /* We do not check whether we know the server that sent the AppendEntries
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

    raft_reset_timer(raft);

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
        return raft_handle_append_entries(raft, rq,
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
        raft, rq,
        raft->log_start - 1, rq->entries[ofs - 1].term,
        &rq->entries[ofs], rq->n_entries - ofs);
}

/* This doesn't use rq->entries (but it does use rq->n_entries). */
static void
raft_send_append_reply(struct raft *raft, const struct raft_append_request *rq,
                       bool success)
{
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
            if (e->type == RAFT_SERVERS) {
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
            },
            .term = raft->current_term,
            .log_end = raft->log_end,
            .prev_log_index = rq->prev_log_index,
            .prev_log_term = rq->prev_log_term,
            .n_entries = rq->n_entries,
            .success = success,
        }
    };
    raft_send(raft, &reply);
}

static void
raft_handle_append_request(struct raft *raft,
                           const struct raft_append_request *rq)
{
    int status = raft_handle_append_request__(raft, rq);
    if (status >= 0) {
        raft_send_append_reply(raft, rq, status);
    }
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
raft_update_match_index(struct raft *raft, struct raft_server *s,
                        uint64_t min_index)
{
    if (s->match_index >= min_index) {
        return;
    }

    s->match_index = min_index;

    /* Figure 3.1: "If there exists an N such that N > commitIndex, a
     * majority of matchIndex[i] >= N, and log[N].term == currentTerm, set
     * commitIndex = N (sections 3.5 and 3.6)."
     *
     * This loop cannot just bail out when it comes across a log entry that
     * does not match the criteria.  For example, Figure 3.7(d2) shows a
     * case where the log entry for term 2 cannot be committed directly
     * (because it is not for the current term) but it can be committed as
     * a side effect of commit the entry for term 4 (the current term).
     * XXX Is there a more efficient way to do this? */
    printf("log=%"PRIu64"...%"PRIu64", commitIndex=%"PRIu64"\n",
           raft->log_start, raft->log_end, raft->commit_index);
    for (uint64_t n = MAX(raft->commit_index, raft->log_start);
         n < raft->log_end; n++) {
        ovs_assert(n >= raft->log_start);
        if (raft->log[n - raft->log_start].term == raft->current_term) {
            size_t count = 0;
            struct raft_server *s2;
            HMAP_FOR_EACH (s2, hmap_node, &raft->servers) {
                if (s2->match_index >= n) {
                    count++;
                }
            }
            if (count == hmap_count(&raft->servers)) {
                raft->commit_index = n;
                printf("commitIndex=%"PRIu64"\n", n);
            }
        }
    }
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
        raft_update_match_index(raft, s, min_index);
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
    struct ovsdb_error *error = raft_write_state(raft, raft->current_term,
                                                 &raft->voted_for);
    if (error) {
        /* XXX */
    }
    /* XXX need to commit before replying */

    raft_reset_timer(raft);

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
            },
            .term = raft->current_term,
            .vote_granted = vote_granted
        },
    };
    raft_send(raft, &rpy);
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
    if (s) {
        raft_accept_vote(raft, s, rpy->vote_granted);
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
        if (e->type == RAFT_SERVERS) {
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
            raft_send_server_reply(raft, &s->reply_sid, RAFT_SERVER_OK);
            s->phase = RAFT_PHASE_STABLE;
        }
    }
    if (raft->remove_server) {
        raft_send_server_reply(raft, &raft->remove_server->reply_sid,
                               RAFT_SERVER_OK);
        raft_server_destroy(raft->remove_server);
        raft->remove_server = NULL;
    }

    /* If a new server is caught up, add it to the configuration.  */
    HMAP_FOR_EACH (s, hmap_node, &raft->add_servers) {
        if (s->phase == RAFT_PHASE_CAUGHT_UP) {
            /* Move 's' from 'raft->add_servers' to 'raft->servers'. */
            hmap_remove(&raft->add_servers, &s->hmap_node);
            hmap_insert(&raft->servers, &s->hmap_node, uuid_hash(&s->sid));

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
            raft_send_server_reply(raft, &s->reply_sid, RAFT_SERVER_CANCELED);
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
    hmap_insert(&raft->add_servers, &s->hmap_node, uuid_hash(&s->sid));
    raft_server_init_leader(raft, s);
    s->sid = rq->sid;
    s->address = xstrdup(rq->address);
    s->reply_sid = rq->common.sid;
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
        raft_send_server_reply(raft, &rq->common.sid, status);
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
        raft_send_server_reply(raft, &target->reply_sid, RAFT_SERVER_CANCELED);
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

    raft_run_reconfigure(raft);
    return -1;
}

static void
raft_handle_remove_server_request(struct raft *raft,
                                  const struct raft_server_request *rq)
{
    int status = raft_handle_remove_server_request__(raft, rq);
    if (status >= 0) {
        raft_send_server_reply(raft, &rq->common.sid, status);
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
raft_handle_install_snapshot_request__(
    struct raft *raft, const struct raft_install_snapshot_request *rq)
{
    if (!raft_receive_term__(raft, rq->term)) {
        return;
    }

    /* XXX snapshot */
}

static void
raft_handle_install_snapshot_request(
    struct raft *raft, const struct raft_install_snapshot_request *rq)
{
    raft_handle_install_snapshot_request__(raft, rq);

    union raft_rpc rpy = {
        .install_snapshot_reply = {
            .common = {
                .type = RAFT_RPC_INSTALL_SNAPSHOT_REPLY,
                .sid = rq->common.sid,
            },
            .term = raft->current_term,
        },
    };
    raft_send(raft, &rpy);
}

static void
raft_handle_install_snapshot_reply(
    struct raft *raft, const struct raft_install_snapshot_reply *rpy)
{
    if (!raft_receive_term__(raft, rpy->term)) {
        return;
    }
    /* XXX */
}

static void
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
    case RAFT_RPC_INSTALL_SNAPSHOT_REQUEST:
        raft_handle_install_snapshot_request(raft,
                                             &rpc->install_snapshot_request);
        break;
    case RAFT_RPC_INSTALL_SNAPSHOT_REPLY:
        raft_handle_install_snapshot_reply(raft, &rpc->install_snapshot_reply);
        break;
    default:
        OVS_NOT_REACHED();
    }
}

static void
raft_send__(struct raft *raft, const union raft_rpc *rpc,
            struct jsonrpc_session *js)
{
    jsonrpc_session_send(js, raft_rpc_to_jsonrpc(raft, rpc));
}

static void
raft_send(struct raft *raft, const union raft_rpc *rpc)
{
    if (uuid_equals(&rpc->common.sid, &raft->sid)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_WARN_RL(&rl, "attempting to send RPC to self");
        return;
    }

    struct raft_server *s = raft_find_peer(raft, &rpc->common.sid);
    if (s && s->js && jsonrpc_session_is_connected(s->js)) {
        raft_send__(raft, rpc, s->js);
        return;
    }

    struct raft_conn *conn;
    LIST_FOR_EACH (conn, list_node, &raft->conns) {
        if (uuid_equals(&conn->sid, &rpc->common.sid)) {
            raft_send__(raft, rpc, conn->js);
        }
    }

    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
    VLOG_WARN_RL(&rl, UUID_FMT": no connection, cannot send RPC",
                 UUID_ARGS(&rpc->common.sid));
}
