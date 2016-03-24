/*
 * Copyright (c) 2014, 2015, 2016 Nicira, Inc.
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

#include <getopt.h>

#include "command-line.h"
#include "model-checker.h"
#include "openvswitch/dynamic-string.h"
#include "raft.h"

struct rpc {
    enum rpc_type {
        RPC_APPEND_REQUEST,
        RPC_APPEND_REPLY,
        RPC_VOTE_REQUEST,
        RPC_VOTE_REPLY
    } type;
    union {
        struct raft_rpc common;
        struct raft_append_request append_request;
        struct raft_append_reply append_reply;
        struct raft_vote_request vote_request;
        struct raft_vote_reply vote_reply;
    } u;
};

struct raft_model {
    struct raft_system *system;
    struct raft raft;
    struct rpc **queue;
    size_t n_queue;
};

struct raft_system {
    struct raft_model *rms;
    int n_rms;

    int commit_index;
    struct raft_log_entry *committed;
};

static void raft_mc_system_init(struct mc *);
static void raft_mc_system_mutate(struct mc *, const void *system);
static void raft_mc_system_destroy(const struct mc *, void *system);

OVS_NO_RETURN static void usage(void);
static struct mc_options *parse_options(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    const struct mc_class raft_mc_class = {
        raft_mc_system_init,
        raft_mc_system_mutate,
        raft_mc_system_destroy,
    };

    struct mc_options *options;
    struct mc_results *results;

    set_program_name(argv[0]);

    options = parse_options(argc, argv);
    results = mc_run (&raft_mc_class, options);
    mc_results_print (results, stdout);
    mc_results_destroy (results);

    return 0;
}

static struct mc_options *
parse_options(int argc, char *argv[])
{
    enum {
        MC_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
        OFP_VERSION_OPTION_ENUMS,
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        MC_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);
    struct mc_options *mc_options = mc_options_create();
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        MC_OPTION_HANDLERS(mc_options)

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    return mc_options;
}

OVS_NO_RETURN static void
usage(void)
{
    printf("%s: Raft implementation test utility\n"
           "usage: %s [OPTIONS]\n",
           program_name, program_name);
    mc_usage();
    printf("\nOther options:\n"
           "  -h, --help                  display this help message\n");
    exit(EXIT_SUCCESS);
}

static struct rpc *
rpc_create(enum rpc_type type, const void *u, size_t size)
{
    struct rpc *rpc = xmalloc(sizeof *rpc);
    rpc->type = type;
    memcpy(&rpc->u, u, size);
    return rpc;
}

static void
rpc_destroy(struct rpc *rpc)
{
    if (!rpc) {
        return;
    }

    if (rpc->type == RPC_APPEND_REQUEST) {
        for (int i = 0; i < rpc->u.append_request.n_entries; i++) {
            free(rpc->u.append_request.entries[i].data);
        }
        free(rpc->u.append_request.entries);
    }
    free(rpc);
}

static void
unshare_append_request(struct raft_append_request *rq)
{
    rq->entries = xmemdup(rq->entries,
                          rq->n_entries * sizeof *rq->entries);
    for (int i = 0; i < rq->n_entries; i++) {
        rq->entries[i].data = xmemdup(rq->entries[i].data, sizeof(int));
    }
}

static struct rpc *
rpc_clone(const struct rpc *rpc)
{
    struct rpc *new = xmemdup(rpc, sizeof *rpc);
    if (new->type == RPC_APPEND_REQUEST) {
        unshare_append_request(&new->u.append_request);
    }
    return new;
}

static void
raft_system_reset_timer(struct raft *raft OVS_UNUSED,
                        enum raft_timer timer OVS_UNUSED)
{
    /* Nothing to do. */
}

static struct raft_model *
raft_model_from_raft(const struct raft *raft)
{
    return CONTAINER_OF(raft, struct raft_model, raft);
}

static void
raft_system_enqueue(struct raft_system *s, int src_id, struct rpc *rpc)
{
    int dst_id = rpc->u.common.peer_id;
    struct raft_model *rm;

    ovs_assert(src_id >= 0 && src_id < s->n_rms);
    ovs_assert(dst_id >= 0 && dst_id < s->n_rms);
    ovs_assert(src_id != dst_id);

    rpc->u.common.peer_id = src_id;

    rm = &s->rms[dst_id];
    rm->queue = xrealloc(rm->queue, (rm->n_queue + 1) * sizeof *rm->queue);
    rm->queue[rm->n_queue++] = rpc;
}

static void
raft_system_send_append_request(struct raft *raft,
                                const struct raft_append_request *rq)
{
    struct raft_model *rm = raft_model_from_raft(raft);
    struct raft_system *s = rm->system;
    struct rpc *rpc;

    rpc = rpc_create(RPC_APPEND_REQUEST, rq, sizeof *rq);
    unshare_append_request(&rpc->u.append_request);
    raft_system_enqueue(s, raft->id, rpc);
}

static void
raft_system_send_vote_request(struct raft *raft,
                              const struct raft_vote_request *rq)
{
    struct raft_model *rm = raft_model_from_raft(raft);
    struct raft_system *s = rm->system;

    raft_system_enqueue(s, raft->id,
                        rpc_create(RPC_VOTE_REQUEST, rq, sizeof *rq));
}

static void
raft_system_commit(struct raft *raft OVS_UNUSED, const void *data OVS_UNUSED)
{
    /* Nothing to do. */
}

static void *
raft_system_clone_data(struct raft *raft OVS_UNUSED, const void *data_)
{
    const int *data = data_;

    return xmemdup(data, sizeof *data);
}

static void
raft_system_free_data(struct raft *raft OVS_UNUSED, void *data_)
{
    int *data = data_;

    free(data);
}

static int
get_data(const void *data_)
{
    const int *data = data_;
    return data ? *data : 0;
}

static struct raft_ops raft_system_ops = {
    raft_system_reset_timer,
    raft_system_send_append_request,
    raft_system_send_vote_request,
    raft_system_commit,
    raft_system_clone_data,
    raft_system_free_data
};

static void
raft_system_destroy(struct raft_system *s)
{
    if (!s) {
        return;
    }

    for (struct raft_model *rm = s->rms; rm < &s->rms[s->n_rms]; rm++) {
        raft_destroy(&rm->raft);
        for (size_t i = 0; i < rm->n_queue; i++) {
            rpc_destroy(rm->queue[i]);
        }
        free(rm->queue);
    }
    for (int i = 0; i <= s->commit_index; i++) {
        free(s->committed[i].data);
    }
    free(s->committed);
    free(s->rms);
    free(s);
}

static struct raft_system *
raft_system_clone(const struct raft_system *old)
{
    struct raft_system *new;

    new = xmalloc(sizeof *new);
    new->n_rms = old->n_rms;
    new->rms = xmalloc(old->n_rms * sizeof *old->rms);
    for (int i = 0; i < new->n_rms; i++) {
        struct raft_model *old_rm = &old->rms[i];
        struct raft_model *new_rm = &new->rms[i];

        new_rm->system = new;
        raft_copy(&new_rm->raft, &old_rm->raft);
        new_rm->n_queue = old_rm->n_queue;
        new_rm->queue = xmalloc(old_rm->n_queue * sizeof *old_rm->queue);
        for (size_t j = 0; j < old_rm->n_queue; j++) {
            new_rm->queue[j] = rpc_clone(old_rm->queue[j]);
        }
    }
    new->commit_index = old->commit_index;
    new->committed = xmemdup(old->committed,
                             (old->commit_index + 1) * sizeof *old->committed);
    for (int i = 0; i <= new->commit_index; i++) {
        struct raft_log_entry *e = &new->committed[i];
        e->data = e->data ? xmemdup(e->data, 4) : NULL;
    }

    return new;
}

static void
raft_check_election_safety(struct mc *mc, const struct raft_system *s)
{
    int n_leaders;
    uint64_t leader_term;

    n_leaders = 0;
    leader_term = 0;
    for (size_t i = 0; i < s->n_rms; i++) {
        struct raft_model *rm = &s->rms[i];
        if (rm->raft.role == RAFT_LEADER) {
            if (rm->raft.current_term > leader_term) {
                leader_term = rm->raft.current_term;
                n_leaders = 1;
            } else if (rm->raft.current_term == leader_term) {
                n_leaders++;
            }
        }
    }
    if (n_leaders > 1) {
        struct ds leaders = DS_EMPTY_INITIALIZER;

        for (size_t i = 0; i < s->n_rms; i++) {
            struct raft_model *rm = &s->rms[i];
            if (rm->raft.role == RAFT_LEADER
                && rm->raft.current_term == leader_term) {
                ds_put_format(&leaders, " %"PRIuSIZE, i);
            }
        }
        mc_error(mc, "multiple leaders for term %"PRIx64":%s",
                 leader_term, ds_cstr(&leaders));
        ds_destroy(&leaders);
    }
}

static void
raft_check_log_matching(struct mc *mc, const struct raft_system *s)
{
    for (const struct raft_model *a = s->rms; a < &s->rms[s->n_rms]; a++) {
        for (const struct raft_model *b = a + 1; b < &s->rms[s->n_rms]; b++) {
            for (int i = MIN(a->raft.log_len, b->raft.log_len) - 1;
                 i > 0; i--) {
                if (a->raft.log[i].term == b->raft.log[i].term) {
                    for (; i > 0; i--) {
                        const int *a_data = a->raft.log[i].data;
                        const int *b_data = b->raft.log[i].data;
                        if (a->raft.log[i].term != b->raft.log[i].term
                            || *a_data != *b_data) {
                            mc_error(mc, "log match property violated");
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }
}

static void
raft_check_leader_completeness(struct mc *mc, struct raft_system *s)
{
    for (struct raft_model *rm = s->rms; rm < &s->rms[s->n_rms]; rm++) {
        if (rm->raft.role == RAFT_LEADER) {
            for (int i = 0; i <= s->commit_index; i++) {
                if (s->committed[i].term > rm->raft.current_term) {
                    break;
                }

                if (i >= rm->raft.log_len) {
                    mc_error(mc, "leader lacks log entry %d", i);
                    return;
                }
                if (rm->raft.log[i].term != s->committed[i].term
                    || (get_data(rm->raft.log[i].data) !=
                        get_data(s->committed[i].data))) {
                    mc_error(mc, "leader has wrong log entry %d", i);
                    return;
                }
            }

            if (s->commit_index < rm->raft.commit_index) {
                s->committed = xrealloc(
                    s->committed,
                    (rm->raft.commit_index + 1) * sizeof *s->committed);
                while (s->commit_index < rm->raft.commit_index) {
                    s->commit_index++;
                    struct raft_log_entry *e = &s->committed[s->commit_index];
                    *e = rm->raft.log[s->commit_index];
                    e->data = e->data ? xmemdup(e->data, sizeof(int)) : NULL;
                }
            }
        }
    }
}

static void
raft_check_state_machine_safety(struct mc *mc, const struct raft_system *s)
{
    for (uint64_t i = 1; ; i++) {
        int first = 0;
        int n = 0;

        for (struct raft_model *rm = s->rms; rm < &s->rms[s->n_rms]; rm++) {
            if (rm->raft.last_applied >= i) {
                int data = get_data(rm->raft.log[i].data);
                if (!n) {
                    first = data;
                } else if (data != first) {
                    mc_error(mc, "state machine safety violation");
                    return;
                }
                n++;
            }
        }
        if (n < 2) {
            break;
        }
    }
}

static void
raft_system_check(struct mc *mc, struct raft_system *s)
{
    raft_check_election_safety(mc, s);
    raft_check_log_matching(mc, s);
    raft_check_leader_completeness(mc, s);
    raft_check_state_machine_safety(mc, s);
}

static void
raft_mc_system_init(struct mc *mc)
{
    struct raft_system *s;

    s = xzalloc(sizeof *s);
    s->n_rms = 3;
    s->rms = xmalloc(s->n_rms * sizeof *s->rms);
    for (size_t i = 0; i < s->n_rms; i++) {
        struct raft_model *rm = &s->rms[i];

        rm->system = s;
        raft_init(&rm->raft, &raft_system_ops, i, s->n_rms);
        rm->queue = NULL;
        rm->n_queue = 0;
    }
    s->commit_index = 0;
    s->committed = xzalloc((s->commit_index + 1) * sizeof *s->committed);

    mc_name_operation(mc, "initial state");
    raft_system_check(mc, s);
    mc_add_state(mc, s);
}

static void
add_state(struct mc *mc, struct raft_system *s)
{
    raft_system_check(mc, s);
    /* XXX check for duplicates */
    mc_add_state(mc, s);
}

static void
drop_queue(struct raft_model *rm, int idx)
{
    rpc_destroy(rm->queue[idx]);

    rm->n_queue--;
    for (int i = idx; i < rm->n_queue; i++) {
        rm->queue[i] = rm->queue[i + 1];
    }
}

static void
apply_queue(struct raft_system *s, struct raft_model *rm, int idx)
{
    struct raft_append_reply append_reply;
    struct raft_vote_reply vote_reply;
    struct rpc *rpc = rm->queue[idx];

    switch (rpc->type) {
    case RPC_APPEND_REQUEST:
        raft_receive_append_request(&rm->raft, &rpc->u.append_request,
                                    &append_reply);
        raft_system_enqueue(s, rm->raft.id,
                            rpc_create(RPC_APPEND_REPLY, &append_reply,
                                       sizeof append_reply));
        break;

    case RPC_APPEND_REPLY:
        raft_receive_append_reply(&rm->raft, &rpc->u.append_reply);
        break;

    case RPC_VOTE_REQUEST:
        raft_receive_vote_request(&rm->raft, &rpc->u.vote_request,
                                  &vote_reply);
        raft_system_enqueue(s, rm->raft.id,
                            rpc_create(RPC_VOTE_REPLY, &vote_reply,
                                       sizeof vote_reply));
        break;

    case RPC_VOTE_REPLY:
        raft_receive_vote_reply(&rm->raft, &rpc->u.vote_reply);
        break;

    default:
        OVS_NOT_REACHED();
    }
}

static const char *
raft_role_name(enum raft_role role)
{
    switch (role) {
    case RAFT_FOLLOWER: return "follower";
    case RAFT_CANDIDATE: return "candidate";
    case RAFT_LEADER: return "leader";
    default: OVS_NOT_REACHED();
    }
}

static const char *
rpc_type_name(enum rpc_type type)
{
    switch (type) {
    case RPC_APPEND_REQUEST: return "append_request";
    case RPC_APPEND_REPLY: return "append_reply";
    case RPC_VOTE_REQUEST: return "vote_request";
    case RPC_VOTE_REPLY: return "vote_reply";
    default: OVS_NOT_REACHED();
    }
}

static void
raft_mc_system_mutate(struct mc *mc, const void *s_)
{
    const struct raft_system *s = s_;

    for (int i = 0; i < s->n_rms; i++) {
        struct raft_model *rm = &s->rms[i];

        /* raft_timer_expired(). */
        if (mc_include_state(mc)) {
            struct raft_system *new = raft_system_clone(s);
            struct raft_model *new_rm = &new->rms[i];
            struct ds s = DS_EMPTY_INITIALIZER;

            raft_timer_expired(&new_rm->raft);
            if (new_rm->raft.role != rm->raft.role) {
                ds_put_format(&s, ", %s -> %s",
                              raft_role_name(rm->raft.role),
                              raft_role_name(new_rm->raft.role));
            }
            if (new_rm->raft.current_term != rm->raft.current_term) {
                ds_put_format(&s, ", term %"PRIu64" -> %"PRIu64,
                              rm->raft.current_term,
                              new_rm->raft.current_term);
            }
            mc_name_operation(mc, "raft %d expire timer%s", i, ds_cstr(&s));
            ds_destroy(&s);

            add_state(mc, new);
        }

        /* raft_run(). */
        {
            struct raft_system *new = raft_system_clone(s);
            if (raft_run(&new->rms[i].raft) && mc_include_state(mc)) {
                struct raft_model *new_rm = &new->rms[i];
                struct ds s = DS_EMPTY_INITIALIZER;

                if (new_rm->raft.role != rm->raft.role) {
                    ds_put_format(&s, ", %s -> %s",
                                  raft_role_name(rm->raft.role),
                                  raft_role_name(new_rm->raft.role));
                }
                if (new_rm->raft.current_term != rm->raft.current_term) {
                    ds_put_format(&s, ", term %"PRIu64" -> %"PRIu64,
                                  rm->raft.current_term,
                                  new_rm->raft.current_term);
                }
                if (new_rm->raft.commit_index != rm->raft.commit_index) {
                    ds_put_format(&s, ", committed %"PRIu64" -> %"PRIu64,
                                  rm->raft.commit_index,
                                  new_rm->raft.commit_index);
                }

                mc_name_operation(mc, "raft %d run%s", i, ds_cstr(&s));
                add_state(mc, new);
                ds_destroy(&s);
            } else {
                raft_system_destroy(new);
            }
        }

        /* raft_add_log_entry(). */
        if (rm->raft.role == RAFT_LEADER) {
            if (mc_include_state(mc)) {
                struct raft_system *new = raft_system_clone(s);
                static int data = 1;

                raft_add_log_entry(&new->rms[i].raft, &data);
                mc_name_operation(mc, "raft %d add log entry %d", i, data);
                add_state(mc, new);

                data++;
            }
        }

        /* raft_receive_*(). */
        if (rm->n_queue > 0) {
            if (mc_include_state(mc)) {
                struct raft_system *new = raft_system_clone(s);
                struct raft_model *new_rm = &new->rms[i];
                enum rpc_type type = new_rm->queue[0]->type;
                struct ds s = DS_EMPTY_INITIALIZER;

                apply_queue(new, new_rm, 0);
                drop_queue(new_rm, 0);

                if (new_rm->raft.role != rm->raft.role) {
                    ds_put_format(&s, ", %s -> %s",
                                  raft_role_name(rm->raft.role),
                                  raft_role_name(new_rm->raft.role));
                }
                if (new_rm->raft.current_term != rm->raft.current_term) {
                    ds_put_format(&s, ", term %"PRIu64" -> %"PRIu64,
                                  rm->raft.current_term,
                                  new_rm->raft.current_term);
                }
                if (new_rm->raft.commit_index != rm->raft.commit_index) {
                    ds_put_format(&s, ", committed %"PRIu64" -> %"PRIu64,
                                  rm->raft.commit_index,
                                  new_rm->raft.commit_index);
                }

                mc_name_operation(mc, "raft %d receive %s%s", i,
                                  rpc_type_name(type), ds_cstr(&s));
                add_state(mc, new);
                ds_destroy(&s);
            }

            if (mc_include_state(mc)) {
                struct raft_system *new = raft_system_clone(s);
                struct raft_model *new_rm = &new->rms[i];
                enum rpc_type type = new_rm->queue[0]->type;

                drop_queue(new_rm, 0);
                mc_name_operation(mc, "raft %d drop %s", i,
                                  rpc_type_name(type));

                add_state(mc, new);
            }
        }
    }
}

static void
raft_mc_system_destroy(const struct mc *mc OVS_UNUSED, void *s_)
{
    struct raft_system *s = s_;

    raft_system_destroy(s);
}
