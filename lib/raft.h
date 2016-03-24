/*
 * Copyright (c) 2014 Nicira, Inc.
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

#ifndef RAFT_H
#define RAFT_H 1

/* Abstract implementation of the Raft consensus algorithm.
 *
 * Based on the description in Ongaro and Ousterhout, "In Search of an
 * Understandable Consensus Algorithm (Extended Version)."
 */

#include <stdbool.h>
#include <stdint.h>
#include "uuid.h"

struct raft;
struct raft_append_request;
struct raft_vote_request;

enum raft_role {
    RAFT_FOLLOWER,
    RAFT_CANDIDATE,
    RAFT_LEADER
};

enum raft_timer {
    RAFT_FAST,
    RAFT_SLOW
};

struct raft_ops {
    void (*reset_timer)(struct raft *, enum raft_timer);

    void (*send_append_request)(struct raft *,
                                const struct raft_append_request *);
    void (*send_vote_request)(struct raft *,
                              const struct raft_vote_request *);

    void (*commit)(struct raft *, const void *);

    void *(*clone_data)(struct raft *, const void *data);
    void (*free_data)(struct raft *, void *data);
};

struct raft_log_entry {
    uint64_t term;
    void *data;
};

/* The Raft state machine. */
struct raft {
    const struct raft_ops *ops;

    /* Persistent state on all servers.
     *
     * Must be updated on stable storage before responding to RPCs. */
    int id;                     /* This server's ID, 0 <= id < n_servers. */
    int n_servers;              /* Number of servers in the Raft cluster. */
    uint64_t current_term;      /* Initialized to 0 and only increases. */
    int voted_for;              /* Candidate ID or -1 if none. */

    /* The log.
     *
     * Raft log entries use 1-based indexing.  We artifically add a log entry
     * 0, with term 0 and NULL data, to represent the empty initial log.
     *
     * XXX need an offset here to account for compaction? */
    uint64_t log_len;           /* Number of log entries. */
    size_t allocated_log;       /* Allocated entries in 'log'. */
    struct raft_log_entry *log; /* log[i] is log entry i. */

    /* Volatile state on all servers. */
    enum raft_role role;        /* Current role. */
    uint64_t commit_index;      /* Max log index known to be committed. */
    uint64_t last_applied;      /* Max log index applied to state machine. */
    int leader_id;

    /* Volatile state on candidates.  Reinitialized at start of election. */
    uint32_t votes;
    int n_votes;

    /* Volatile state on leaders.  (Reinitialized after election.)
     *
     * Each of these points to an array of 'n_servers' elements. */
    uint64_t *next_index;    /* Index of next log entry to send each server. */
    uint64_t *match_index;   /* Index of max log entry server known to have. */
};

void raft_init(struct raft *, const struct raft_ops *, int id, int n_servers);
void raft_copy(struct raft *, const struct raft *);
void raft_destroy(struct raft *);

bool raft_run(struct raft *);
void raft_wait(struct raft *);

uint64_t raft_add_log_entry(struct raft *, const void *data);

void raft_timer_expired(struct raft *);

struct raft_rpc {
    int peer_id;                /* 0 <= peer_id < raft->n_servers
                                 * and peer_id != raft->id. */
    struct uuid xid;            /* To match up requests and replies. */
    uint64_t term;              /* Current term. */
};

struct raft_append_request {
    struct raft_rpc rpc;
    int leader_id;              /* So follower can redirect clients. */
    uint64_t prev_log_index;    /* Log entry just before new ones. */
    uint64_t prev_log_term;     /* Term of prev_log_index entry. */
    uint64_t leader_commit;     /* Leader's commit_index. */

    /* The append request includes 0 or more log entries.  entries[0] is for
     * log entry 'prev_log_index + 1', and so on.
     *
     * A heartbeat append_request has no terms. */
    int n_entries;
    struct raft_log_entry *entries;
};

struct raft_append_reply {
    struct raft_rpc rpc;
    bool success;               /* True if follower had entry matching
                                 * prev_log_index and prev_log_term. */

    /* Copied from request. */
    uint64_t prev_log_index;    /* Log entry just before new ones. */
    uint64_t prev_log_term;     /* Term of prev_log_index entry. */
    int n_entries;
};

void raft_receive_append_request(struct raft *,
                                 const struct raft_append_request *,
                                 struct raft_append_reply *);
void raft_receive_append_reply(struct raft *,
                               const struct raft_append_reply *);

struct raft_vote_request {
    struct raft_rpc rpc;
    int candidate_id;        /* Candidate ID, 0 <= candidate_id < n_servers. */
    uint64_t last_log_index; /* Index of candidate's last log entry. */
    uint64_t last_log_term;  /* Term of candidate's last log entry. */
};

struct raft_vote_reply {
    struct raft_rpc rpc;
    bool vote_granted;       /* True means candidate received vote. */
};

void raft_receive_vote_request(struct raft *,
                               const struct raft_vote_request *,
                               struct raft_vote_reply *);
void raft_receive_vote_reply(struct raft *, const struct raft_vote_reply *);

#endif /* lib/raft.h */
