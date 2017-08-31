/* Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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

#include "trigger.h"

#include <limits.h>

#include "execution.h"
#include "openvswitch/json.h"
#include "jsonrpc.h"
#include "ovsdb.h"
#include "ovsdb-error.h"
#include "poll-loop.h"
#include "server.h"
#include "transaction.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(trigger);

static void ovsdb_trigger_try(struct ovsdb_trigger *, long long int now);
static void ovsdb_trigger_complete(struct ovsdb_trigger *);

void
ovsdb_trigger_init(struct ovsdb_session *session, struct ovsdb *db,
                   struct ovsdb_trigger *trigger,
                   struct json *request, long long int now,
                   bool read_only)
{
    trigger->session = session;
    trigger->db = db;
    ovs_list_push_back(&trigger->db->triggers, &trigger->node);
    trigger->request = request;
    trigger->result = NULL;
    trigger->progress = NULL;
    trigger->created = now;
    trigger->timeout_msec = LLONG_MAX;
    trigger->read_only = read_only;
    ovsdb_trigger_try(trigger, now);
}

void
ovsdb_trigger_destroy(struct ovsdb_trigger *trigger)
{
    ovs_list_remove(&trigger->node);
    json_destroy(trigger->request);
    json_destroy(trigger->result);
}

bool
ovsdb_trigger_is_complete(const struct ovsdb_trigger *trigger)
{
    return trigger->result && !trigger->progress;
}

struct json *
ovsdb_trigger_steal_result(struct ovsdb_trigger *trigger)
{
    struct json *result = trigger->result;
    trigger->result = NULL;
    return result;
}

void
ovsdb_trigger_run(struct ovsdb *db, long long int now)
{
    struct ovsdb_trigger *t, *next;
    bool run_triggers;

    run_triggers = db->run_triggers;
    db->run_triggers = false;
    int i = 0;
    LIST_FOR_EACH_SAFE (t, next, node, &db->triggers) {
        if (run_triggers
            || now - t->created >= t->timeout_msec
            || t->progress) {
            ovsdb_trigger_try(t, now);
        }
        i++;
    }
}

void
ovsdb_trigger_wait(struct ovsdb *db, long long int now)
{
    if (db->run_triggers) {
        poll_immediate_wake();
    } else {
        long long int deadline = LLONG_MAX;
        struct ovsdb_trigger *t;

        LIST_FOR_EACH (t, node, &db->triggers) {
            if (t->created < LLONG_MAX - t->timeout_msec) {
                long long int t_deadline = t->created + t->timeout_msec;
                if (deadline > t_deadline) {
                    deadline = t_deadline;
                    if (now >= deadline) {
                        break;
                    }
                }
            }
        }

        if (deadline < LLONG_MAX) {
            poll_timer_wait_until(deadline);
        }
    }
}

static void
ovsdb_trigger_try(struct ovsdb_trigger *t, long long int now)
{
    /* Handle "initialized" state. */
    if (!t->result) {
        ovs_assert(!t->progress);

        bool durable;
        struct ovsdb_txn *txn = ovsdb_execute_compose(
            t->db, t->session, t->request, t->read_only,
            now - t->created, &t->timeout_msec, &durable, &t->result);
        if (!txn) {
            if (t->result) {
                /* Complete (with error). */
                ovsdb_trigger_complete(t);
            } else {
                /* Unsatisfied "wait" condition.  Take no action now, retry
                 * later. */
            }
            return;
        }

        /* Transition to "committing" state. */
        t->progress = ovsdb_txn_propose_commit(txn, durable);

        /* If the transaction committed synchronously, complete it and
         * transition to "complete".  This is more than an optimization because
         * the file-based storage isn't implemented to read back the
         * transactions that we write (which is an ugly way to break the
         * abstraction). */
        if (ovsdb_txn_progress_is_complete(t->progress)
            && !ovsdb_txn_progress_get_error(t->progress)) {
            ovsdb_txn_complete(txn);
            ovsdb_txn_progress_destroy(t->progress);
            t->progress = NULL;
            ovsdb_trigger_complete(t);
            return;
        }

        /* Fall through to the general handling for the "committing" state.  We
         * abort the transaction--if and when it eventually commits, we'll read
         * it back from storage and replay it locally. */
        ovsdb_txn_abort(txn);
    }

    /* Handle "committing" state. */
    if (t->progress) {
        if (!ovsdb_txn_progress_is_complete(t->progress)) {
            return;
        }

        /* Transition to "complete". */
        struct ovsdb_error *error
            = ovsdb_error_clone(ovsdb_txn_progress_get_error(t->progress));
        ovsdb_txn_progress_destroy(t->progress);
        t->progress = NULL;

        if (error) {
            if (true /* XXX */) {
                /* Permanent error.  Transition to "completed" state to report
                 * it. */
                json_array_add(t->result, ovsdb_error_to_json(error));
                ovsdb_error_destroy(error);
                ovsdb_trigger_complete(t);
            } else {
                /* Temporary error.  Transition back to "initialized" state to
                 * try again. */
                json_destroy(t->result);
                t->result = NULL;
            }
        } else {
            /* Success. */
            ovsdb_trigger_complete(t);
        }

        return;
    }

    OVS_NOT_REACHED();
}

static void
ovsdb_trigger_complete(struct ovsdb_trigger *t)
{
    ovs_assert(t->result != NULL);
    ovs_list_remove(&t->node);
    ovs_list_push_back(&t->session->completions, &t->node);
}
