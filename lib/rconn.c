/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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
#include "rconn.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "coverage.h"
#include "ofpbuf.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(rconn);

enum rconn_state {
    S_VOID,

    S_BACKOFF,
    S_CONNECTING,
    S_CONNECTED,

    S_PASSIVE
};

static const char *
rconn_state_to_string(enum rconn_state state)
{
    switch (state) {
    case S_VOID: return "VOID";
    case S_BACKOFF: return "BACKOFF";
    case S_CONNECTING: return "CONNECTING";
    case S_CONNECTED: return "CONNECTED";
    case S_PASSIVE: return "PASSIVE";
    default: OVS_NOT_REACHED();
    }
}

/* A reliable connection to an OpenFlow switch or controller.
 *
 * See the large comment in rconn.h for more information. */
struct rconn {
    struct ovs_mutex mutex;

    enum rconn_state state;
    long long int timeout;

    char *target;               /* Target passed to vconn_open(). */
    char *name;                 /* Human friendly name for logging. */

    struct pvconn *pvconn;
    struct vconn *vconn;

    unsigned int backoff;       /* In milliseconds. */
    unsigned int max_backoff;   /* In milliseconds. */
    long long int backoff_deadline;

    unsigned int probe_interval;
    uint32_t allowed_versions;
    uint8_t dscp;

    time_t last_connection;
    time_t last_disconnect;
    int last_error;
};

static bool rconn_log_connection_attempts(const struct rconn *);

/* Creates and returns a new rconn.
 *
 * 'probe_interval' is a number of seconds.  If the interval passes once
 * without an OpenFlow message being received from the peer, the rconn sends
 * out an "echo request" message.  If the interval passes again without a
 * message being received, the rconn disconnects and re-connects to the peer.
 * Setting 'probe_interval' to 0 disables this behavior.
 *
 * 'max_backoff' is the maximum number of seconds between attempts to connect
 * to the peer.  The actual interval starts at 1 second and doubles on each
 * failure until it reaches 'max_backoff'.  If 0 is specified, the default of
 * 8 seconds is used.
 *
 * The new rconn is initially unconnected.  Use rconn_connect() or
 * rconn_connect_unreliably() to connect it.
 *
 * Connections made by the rconn will automatically negotiate an OpenFlow
 * protocol version acceptable to both peers on the connection.  The version
 * negotiated will be one of those in the 'allowed_versions' bitmap: version
 * 'x' is allowed if allowed_versions & (1 << x) is nonzero.  (The underlying
 * vconn will treat an 'allowed_versions' of 0 as OFPUTIL_DEFAULT_VERSIONS.)
 */
struct rconn *
rconn_create(const char *target, const char *name)
{
    enum rconn_state initial_state;
    if (!vconn_verify_name(target)) {
        initial_state = S_BACKOFF;
    } else if (!pvconn_verify_name(target)) {
        initial_state = S_PASSIVE;
    } else {
        VLOG_WARN("%s: not a valid active or passive remote", target);
        return NULL;
    }

    struct rconn *rconn = xzalloc(sizeof *rconn);
    ovs_mutex_init(&rconn->mutex);
    rconn->state = initial_state;
    rconn->timeout = LLONG_MIN; /* XXX oops this needs to be corrected */
    rconn->name = xstrdup(name);
    rconn->target = xstrdup(target);
    rconn->backoff = 1000;
    rconn->max_backoff = 8000;
    rconn->allowed_versions = 0;
    rconn->dscp = DSCP_DEFAULT;
    rconn->last_connection = TIME_MIN;
    rconn->last_disconnect = TIME_MIN;
    return rconn;
}

/* Frees 'rconn'. */
void
rconn_destroy(struct rconn *rconn)
{
    if (rconn) {
        ovs_mutex_lock(&rconn->mutex);
        free(rconn->name);
        free(rconn->target);
        pvconn_close(rconn->pvconn);
        ovs_mutex_unlock(&rconn->mutex);
        ovs_mutex_destroy(&rconn->mutex);

        free(rconn);
    }
}

static void
state_transition(struct rconn *rconn, enum rconn_state state,
                 long long int timeout)
    OVS_REQUIRES(rconn->mutex)
{
    VLOG_DBG("%s: entering state %s",
             rconn->name, rconn_state_to_string(state));
    rconn->state = state;
    rconn->timeout = timeout;
}

static void
connection_failed(struct rconn *rconn, int retval)
    OVS_REQUIRES(rconn->mutex)
{
    rconn->last_error = retval;
    if (rconn->vconn) {
        vconn_close(rconn->vconn);
        rconn->vconn = NULL;
    }

    long long int now = time_msec();
    if (rconn->state == S_CONNECTED) {
        rconn->last_disconnect = now;
    }

    if (now >= rconn->backoff_deadline) {
        rconn->backoff = 1000;
    } else if (rconn->backoff < rconn->max_backoff / 2) {
        rconn->backoff = MAX(1000, 2 * rconn->backoff);
        VLOG_INFO("%s: waiting %u seconds before reconnect",
                  rconn->name, rconn->backoff / 1000);
    } else {
        if (rconn_log_connection_attempts(rconn)) {
            VLOG_INFO("%s: continuing to retry connections in the "
                      "background but suppressing further logging",
                      rconn->name);
        }
        rconn->backoff = rconn->max_backoff;
    }
    VLOG_INFO("backoff %u", rconn->backoff);
    rconn->backoff_deadline = timeval_add(now, rconn->backoff);
    state_transition(rconn, S_BACKOFF, rconn->backoff_deadline);
}

static void
start_connection(struct rconn *rconn)
    OVS_REQUIRES(rconn->mutex)
{
    int error;

    if (rconn_log_connection_attempts(rconn)) {
        VLOG_INFO("%s: connecting...", rconn->name);
    }
    //rconn->n_attempted_connections++;
    error = vconn_open(rconn->target, rconn->allowed_versions, rconn->dscp,
                       &rconn->vconn);
    if (!error) {
        state_transition(rconn, S_CONNECTING,
                         timeval_add(time_msec(), MAX(1000, rconn->backoff)));
    } else {
        VLOG_WARN("%s: connection failed (%s)",
                  rconn->name, ovs_strerror(error));
        rconn->backoff_deadline = LLONG_MAX; /* Prevent resetting backoff. */
        connection_failed(rconn, error);
    }
}

static long long int
timed_out(const struct rconn *rconn)
{
    return time_msec() >= rconn->timeout;
}

static void
rconn_run__(struct rconn *rconn)
    OVS_REQUIRES(rconn->mutex)
{
    switch (rconn->state) {
    case S_VOID:
        break;

    case S_BACKOFF:
        if (timed_out(rconn)) {
            start_connection(rconn);
        }
        break;

    case S_CONNECTING:
        vconn_run(rconn->vconn);
        int error = vconn_connect(rconn->vconn);
        if (!error) {
            state_transition(rconn, S_CONNECTED, LLONG_MAX);
            rconn->last_connection = time_now();
        } else if (error != EAGAIN) {
            connection_failed(rconn, error);
        } else if (timed_out(rconn)) {
            connection_failed(rconn, ETIMEDOUT);
        }
        break;

    case S_CONNECTED:
        break;

    case S_PASSIVE:
        if (!rconn->pvconn) {
            error = pvconn_open(rconn->target, rconn->allowed_versions,
                                rconn->dscp, &rconn->pvconn);
            if (error) {
                VLOG_WARN("%s: listen failed (%s)",
                          rconn->name, ovs_strerror(error));
                state_transition(rconn, S_VOID, LLONG_MAX);
            }
        } else {
            /* Nothing to do, there's no function pvconn_run(). */
            rconn->timeout = LLONG_MAX;
        }
        break;
    }
}

/* Performs whatever activities are necessary to maintain 'rconn': if 'rconn'
 * is disconnected, attempts to (re)connect, backing off as necessary; if
 * 'rconn' is connected, attempts to send packets in the send queue, if any. */
void
rconn_run(struct rconn *rconn)
{
    int state;

    ovs_mutex_lock(&rconn->mutex);
    do {
        state = rconn->state;
        rconn_run__(rconn);
    } while (state != rconn->state);
    ovs_mutex_unlock(&rconn->mutex);
}

void
rconn_wait(struct rconn *rconn)
{
    ovs_mutex_lock(&rconn->mutex);
    poll_timer_wait_until(rconn->timeout);
    if (rconn->vconn) {
        vconn_run_wait(rconn->vconn);
    }
    ovs_mutex_unlock(&rconn->mutex);
}

void
rconn_accept_wait(struct rconn *rconn)
{
    ovs_mutex_lock(&rconn->mutex);
    if (rconn->pvconn) {
        pvconn_wait(rconn->pvconn);
    }
    ovs_mutex_unlock(&rconn->mutex);
}

struct vconn *
rconn_accept(struct rconn *rconn)
{
    struct vconn *vconn = NULL;
    int error;

    ovs_mutex_lock(&rconn->mutex);
    switch (rconn->state) {
    case S_VOID:
    case S_BACKOFF:
    case S_CONNECTING:
        break;

    case S_CONNECTED:
        vconn = rconn->vconn;
        rconn->vconn = NULL;
        break;

    case S_PASSIVE:
        error = pvconn_accept(rconn->pvconn, &vconn);
        if (!error) {
            rconn->last_connection = time_now();
        } else if (error != EAGAIN) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
            VLOG_WARN_RL(&rl, "%s: accept failed (%s)",
                         rconn->name, ovs_strerror(error));
        }
        break;
    }
    ovs_mutex_unlock(&rconn->mutex);

    return vconn;
}

void
rconn_disconnected(struct rconn *rconn)
{
    ovs_mutex_lock(&rconn->mutex);
    if (rconn->state == S_CONNECTED) {
        connection_failed(rconn, 0);
    }
    ovs_mutex_unlock(&rconn->mutex);
}

const char *
rconn_get_target(const struct rconn *rconn)
{
    return rconn->target;
}

const char *
rconn_get_name(const struct rconn *rconn)
{
    return rconn->name;
}

static void
rconn_connection_parameter_changed(struct rconn *rconn)
    OVS_REQUIRES(rconn->mutex)
{
    if (rconn->state == S_PASSIVE && rconn->pvconn) {
        pvconn_close(rconn->pvconn);
        rconn->pvconn = NULL;
    } else if (rconn->state == S_CONNECTING) {
        connection_failed(rconn, 0);
    }
}

bool
rconn_is_passive(const struct rconn *rconn)
{
    return rconn->state == S_PASSIVE;
}

void
rconn_set_dscp(struct rconn *rconn, uint8_t dscp)
{
    ovs_mutex_lock(&rconn->mutex);
    if (rconn->dscp != dscp) {
        rconn->dscp = dscp;
        rconn_connection_parameter_changed(rconn);
    }
    ovs_mutex_unlock(&rconn->mutex);
}

uint8_t
rconn_get_dscp(const struct rconn *rconn)
{
    return rconn->dscp;
}

void
rconn_set_allowed_versions(struct rconn *rconn, uint32_t allowed_versions)
{
    ovs_mutex_lock(&rconn->mutex);
    if (rconn->allowed_versions != allowed_versions) {
        rconn->allowed_versions = allowed_versions;
        rconn_connection_parameter_changed(rconn);
    }
    ovs_mutex_unlock(&rconn->mutex);
}

uint32_t
rconn_get_allowed_versions(const struct rconn *rconn)
{
    return rconn->allowed_versions;
}

void
rconn_set_max_backoff(struct rconn *rconn, int max_backoff)
{
    ovs_mutex_lock(&rconn->mutex);
    if (rconn->max_backoff != max_backoff) {
        rconn->max_backoff = max_backoff;
        if (rconn->state == S_BACKOFF && rconn->backoff > rconn->max_backoff) {
            rconn->backoff_deadline -= rconn->backoff - rconn->max_backoff;
            rconn->timeout = rconn->backoff_deadline;
            rconn->backoff = rconn->max_backoff;
        }
    }
    ovs_mutex_unlock(&rconn->mutex);
}

int
rconn_get_max_backoff(const struct rconn *rconn)
{
    return rconn->max_backoff;
}

void
rconn_set_probe_interval(struct rconn *rconn, int probe_interval)
{
    ovs_mutex_lock(&rconn->mutex);
    if (rconn->probe_interval != probe_interval) {
        rconn->probe_interval = probe_interval;
        rconn_connection_parameter_changed(rconn);
    }
    ovs_mutex_unlock(&rconn->mutex);
}

int
rconn_get_probe_interval(const struct rconn *rconn)
{
    return rconn->probe_interval;
}

/* Returns true if 'rc' is currently logging information about connection
 * attempts, false if logging should be suppressed because 'rc' hasn't
 * successfully connected in too long. */
static bool
rconn_log_connection_attempts(const struct rconn *rc)
    OVS_REQUIRES(rc->mutex)
{
    return rc->backoff < rc->max_backoff;
}

const char *
rconn_get_state(const struct rconn *rconn)
{
    return rconn_state_to_string(rconn->state);
}

time_t
rconn_get_last_connection(const struct rconn *rconn)
{
    return rconn->last_connection;
}

time_t
rconn_get_last_disconnect(const struct rconn *rconn)
{
    return rconn->last_disconnect;
}

/* Returns a value that explains why 'rc' last disconnected:
 *
 *   - 0 means that the last disconnection was caused by a call to
 *     rconn_disconnect(), or that 'rc' is new and has not yet completed its
 *     initial connection or connection attempt.
 *
 *   - EOF means that the connection was closed in the normal way by the peer.
 *
 *   - A positive integer is an errno value that represents the error.
 */
int
rconn_get_last_error(const struct rconn *rconn)
{
    return rconn->last_error;
}
