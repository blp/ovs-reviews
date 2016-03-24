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

#include <config.h>

#include "raft.h"

#include "util.h"

static struct raft_log_entry *raft_add_log_entry__(struct raft *,
                                                   uint64_t term, void *data);

void
raft_init(struct raft *raft, const struct raft_ops *ops, int id, int n_servers)
{
    raft->ops = ops;
    raft->id = id;
    raft->n_servers = n_servers;
    raft->current_term = 1;
    raft->voted_for = -1;

    raft->log_len = 0;
    raft->allocated_log = 0;
    raft->log = NULL;

    raft->role = RAFT_FOLLOWER;
    raft->commit_index = 0;
    raft->last_applied = 0;
    raft->leader_id = -1;

    raft->votes = 0;
    raft->n_votes = 0;

    raft->next_index = xcalloc(n_servers, sizeof *raft->next_index);
    raft->match_index = xcalloc(n_servers, sizeof *raft->match_index);

    raft_add_log_entry__(raft, 0, NULL);
}

void
raft_copy(struct raft *new, const struct raft *old)
{
    int i;

    *new = *old;
    new->allocated_log = new->log_len;
    new->log = xmalloc(new->log_len * sizeof *new->log);
    for (i = 0; i < new->log_len; i++) {
        new->log[i].term = old->log[i].term;
        new->log[i].data = (old->log[i].data
                            ? old->ops->clone_data(new, old->log[i].data)
                            : NULL);
    }
    new->next_index = xmemdup(new->next_index,
                              new->n_servers * sizeof *new->next_index);
    new->match_index = xmemdup(new->match_index,
                               new->n_servers * sizeof *new->match_index);
}

void
raft_destroy(struct raft *raft)
{
    if (!raft) {
        return;
    }

    for (int i = 1; i < raft->log_len; i++) {
        raft->ops->free_data(raft, raft->log[i].data);
    }

    free(raft->log);
    free(raft->next_index);
    free(raft->match_index);
}

static struct raft_log_entry *
raft_add_log_entry__(struct raft *raft, uint64_t term, void *data)
{
    struct raft_log_entry *entry;

    if (raft->log_len >= raft->allocated_log) {
        raft->log = x2nrealloc(raft->log, &raft->allocated_log,
                               sizeof *raft->log);
    }
    entry = &raft->log[raft->log_len++];
    entry->term = term;
    entry->data = data;
    return entry;
}

static struct raft_log_entry *
raft_clone_and_add_log_entry__(struct raft *raft,
                               uint64_t term, const void *data)
{
    return raft_add_log_entry__(raft, term, raft->ops->clone_data(raft, data));
}

static void
raft_send_append_request(struct raft *raft, int peer_id, int n)
{
    struct raft_log_entry *entries = &raft->log[raft->log_len - n];
    struct raft_append_request rq;

    ovs_assert(entries > raft->log);

    uuid_generate(&rq.rpc.xid);
    rq.rpc.peer_id = peer_id;
    rq.rpc.term = raft->current_term;

    rq.leader_id = raft->id;
    rq.prev_log_index = raft->log_len - (n + 1);
    rq.prev_log_term = entries[-1].term;
    rq.leader_commit = raft->commit_index;
    rq.n_entries = n;
    rq.entries = entries;
    raft->ops->send_append_request(raft, &rq);
}

uint64_t
raft_add_log_entry(struct raft *raft, const void *data)
{
    if (raft->role == RAFT_LEADER) {
        raft_clone_and_add_log_entry__(raft, raft->current_term, data);

        raft->ops->reset_timer(raft, RAFT_FAST);
        for (int peer_id = 0; peer_id < raft->n_servers; peer_id++) {
            if (peer_id != raft->id) {
                raft_send_append_request(raft, peer_id, 1);
            }
        }
        return raft->log_len;
    } else {
        return 0;
    }
}

static void
raft_become_follower(struct raft *raft)
{
    if (raft->role != RAFT_FOLLOWER) {
        raft->role = RAFT_FOLLOWER;
        raft->ops->reset_timer(raft, RAFT_SLOW);
    }
}

static void
raft_receive_rpc(struct raft *raft, const struct raft_rpc *rpc)
{
    if (rpc->term > raft->current_term) {
        raft->current_term = rpc->term;
        raft->voted_for = -1;
        raft_become_follower(raft);
    }
}

static void
raft_send_heartbeats(struct raft *raft)
{
    for (int peer_id = 0; peer_id < raft->n_servers; peer_id++) {
        if (peer_id != raft->id) {
            /* XXX should also retransmit unacknowledged append requests */
            raft_send_append_request(raft, peer_id, 0);
        }
    }
}

static void
raft_become_leader(struct raft *raft)
{
    raft->role = RAFT_LEADER;
    for (int i = 0; i < raft->n_servers; i++) {
        raft->next_index[i] = raft->log_len + 1;
        raft->match_index[i] = 0; /* ??? */
    }
    raft_send_heartbeats(raft);
}

/* Makes 'raft' become a candidate and start an election.  (If 'raft' is
 * already a candidate, starts a new election.) */
static void
raft_become_candidate(struct raft *raft)
{
    raft->role = RAFT_CANDIDATE;
    raft->current_term++;
    raft->voted_for = raft->id;
    raft->votes = 1u << raft->id;
    raft->n_votes = 1;
    for (int peer_id = 0; peer_id < raft->n_servers; peer_id++) {
        if (peer_id != raft->id) {
            struct raft_vote_request rq;

            uuid_generate(&rq.rpc.xid);
            rq.rpc.peer_id = peer_id;
            rq.rpc.term = raft->current_term;

            rq.candidate_id = raft->id;
            rq.last_log_index = raft->log_len;
            rq.last_log_term = raft->log[raft->log_len - 1].term;
            raft->ops->send_vote_request(raft, &rq);
        }
    }
    raft->ops->reset_timer(raft, RAFT_SLOW);
}

void
raft_receive_append_request(struct raft *raft,
                            const struct raft_append_request *rq,
                            struct raft_append_reply *rpy)
{
    raft_receive_rpc(raft, &rq->rpc);
    if (rq->rpc.term == raft->current_term) {
        raft->leader_id = rq->leader_id;
    }
    rpy->rpc = rq->rpc;
    rpy->rpc.term = raft->current_term;
    if (raft->role == RAFT_CANDIDATE && rq->rpc.term == raft->current_term) {
        raft_become_follower(raft);
    }

    rpy->prev_log_index = rq->prev_log_index;
    rpy->prev_log_term = rq->prev_log_term;
    rpy->n_entries = rq->n_entries;

    if (rq->rpc.term < raft->current_term) {
        rpy->success = false;
    } else if (rq->prev_log_index >= raft->log_len
               || raft->log[rq->prev_log_index].term != rq->prev_log_term) {
        rpy->success = false;
    } else {
        int i;

        rpy->success = true;
        for (i = 0; i < rq->n_entries; i++) {
            uint64_t log_index = (rq->prev_log_term + 1) + i;
            if (log_index >= raft->log_len) {
                break;
            }
            if (raft->log[log_index].term != rq->entries[i].term) {
                /* Truncate the log, deleting all of the entries at 'log_index'
                 * and afterward. */
                while (raft->log_len > log_index) {
                    struct raft_log_entry *entry = &raft->log[--raft->log_len];
                    raft->ops->free_data(raft, entry->data);
                }
                break;
            }
        }
        if (i < rq->n_entries) {
            for (; i < rq->n_entries; i++) {
                const struct raft_log_entry *entry = &rq->entries[i];
                raft_clone_and_add_log_entry__(raft, entry->term,
                                               entry->data);
            }
            if (rq->leader_commit > raft->commit_index) {
                raft->commit_index = MIN(rq->leader_commit,
                                         rq->prev_log_index + rq->n_entries);
            }
        }
    }
}

void
raft_receive_append_reply(struct raft *raft,
                          const struct raft_append_reply *rpy)
{
    raft_receive_rpc(raft, &rpy->rpc);
    if (raft->role != RAFT_LEADER) {
        return;
    }

    /* XXX check that the reply xid matches the request we sent */
    if (rpy->success) {
        uint64_t min_index = rpy->prev_log_index + rpy->n_entries;
        if (raft->next_index[rpy->rpc.peer_id] < min_index) {
            raft->next_index[rpy->rpc.peer_id] = min_index;
        }
        if (raft->match_index[rpy->rpc.peer_id] < min_index) {
            raft->match_index[rpy->rpc.peer_id] = min_index;
        }
    } else {
        int next_index = rpy->prev_log_index;
        raft_send_append_request(raft, rpy->rpc.peer_id,
                                 raft->log_len - next_index);
    }
}

void
raft_receive_vote_request(struct raft *raft,
                          const struct raft_vote_request *rq,
                          struct raft_vote_reply *rpy)
{
    raft_receive_rpc(raft, &rq->rpc);
    rpy->rpc = rq->rpc;
    rpy->rpc.term = raft->current_term;
    if (rq->rpc.term < raft->current_term) {
        rpy->vote_granted = false;
    } else if (raft->voted_for != -1 && raft->voted_for != rq->rpc.peer_id) {
        rpy->vote_granted = false;
    } else if (raft->log[raft->log_len - 1].term > rq->last_log_term) {
        rpy->vote_granted = false;
    } else if (raft->log_len > rq->last_log_index + 1) {
        rpy->vote_granted = false;
    } else {
        raft->voted_for = rq->rpc.peer_id;
        rpy->vote_granted = true;
    }
}

void
raft_receive_vote_reply(struct raft *raft, const struct raft_vote_reply *rpy)
{
    uint32_t bit = 1u << rpy->rpc.peer_id;

    raft_receive_rpc(raft, &rpy->rpc);
    if (raft->role == RAFT_CANDIDATE
        && rpy->rpc.term == raft->current_term
        && rpy->vote_granted
        && !(raft->votes & bit)) {
        raft->votes |= bit;
        raft->n_votes++;
        if (raft->n_votes > raft->n_servers / 2) {
            raft_become_leader(raft);
        }
    }
}

void
raft_timer_expired(struct raft *raft)
{
    if (raft->role == RAFT_FOLLOWER) {
        raft_become_candidate(raft);
    } else if (raft->role == RAFT_CANDIDATE) {
        raft_become_candidate(raft);
    } else {
        /* This needs to be the fast timer. */
        ovs_assert(raft->role == RAFT_LEADER);
        raft_send_heartbeats(raft);
    }
}

static bool
raft_majority_at_least_match_index(const struct raft *raft, uint64_t n)
{
    int count = 0;
    int i;

    for (i = 0; i < raft->n_servers; i++) {
        count += i == raft->id || raft->match_index[i] >= n;
    }
    return count > raft->n_servers / 2;
}

bool
raft_run(struct raft *raft)
{
    bool did_anything = false;

    if (raft->role == RAFT_LEADER) {
        for (;;) {
            uint64_t n = raft->commit_index + 1;
            if (n >= raft->log_len
                || raft->log[n].term != raft->current_term) {
                break;
            }

            if (raft_majority_at_least_match_index(raft, n)) {
                did_anything = true;
                raft->commit_index++;
            } else {
                break;
            }
        }
    }

    while (raft->commit_index > raft->last_applied) {
        raft->ops->commit(raft, raft->log[++raft->last_applied].data);
        did_anything = true;
    }

    return did_anything;
}
