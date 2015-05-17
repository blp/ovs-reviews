/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
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

#ifndef RCONN_H
#define RCONN_H 1

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include "openvswitch/types.h"
#include "ovs-thread.h"

/* A wrapper around vconn that provides (optional) reliability.
 *
 * An rconn optionally provides reliable communication, in this sense: the
 * rconn will re-connect, with exponential backoff, when the underlying vconn
 * disconnects.
 *
 *
 * Thread-safety
 * =============
 *
 * Fully thread-safe.
 */

struct rconn *rconn_create(const char *target, const char *name);
void rconn_destroy(struct rconn *);

void rconn_run(struct rconn *);
void rconn_wait(struct rconn *);
void rconn_accept_wait(struct rconn *);

struct vconn *rconn_accept(struct rconn *);
void rconn_disconnected(struct rconn *);

const char *rconn_get_target(const struct rconn *);
const char *rconn_get_name(const struct rconn *);

bool rconn_is_passive(const struct rconn *);

void rconn_set_dscp(struct rconn *rc, uint8_t dscp);
uint8_t rconn_get_dscp(const struct rconn *rc);

void rconn_set_allowed_versions(struct rconn *, uint32_t allowed_versions);
uint32_t rconn_get_allowed_versions(const struct rconn *);

void rconn_set_max_backoff(struct rconn *, int max_backoff);
int rconn_get_max_backoff(const struct rconn *);

void rconn_set_probe_interval(struct rconn *, int inactivity_probe_interval);
int rconn_get_probe_interval(const struct rconn *);

void rconn_reconnect(struct rconn *);
void rconn_disconnect(struct rconn *);

int rconn_failure_duration(const struct rconn *);

const char *rconn_get_state(const struct rconn *);
time_t rconn_get_last_connection(const struct rconn *);
time_t rconn_get_last_disconnect(const struct rconn *);
int rconn_get_last_error(const struct rconn *);

#endif /* rconn.h */
