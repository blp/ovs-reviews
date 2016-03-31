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

#ifndef RAFT_H
#define RAFT_H 1

#include <stddef.h>

/* Implementation of the Raft consensus algorithm.
 *
 *
 * References
 * ==========
 *
 * Based on Diego Ongaro's Ph.D. thesis, "Consensus: Bridging Theory and
 * Practice", available at https://ramcloud.stanford.edu/~ongaro/thesis.pdf.
 * References to sections, pages, and figures are from this thesis.  Quotations
 * in comments also come from this work, in accordance with its license notice,
 * reproduced below:
 *
 *     Copyright 2014 by Diego Andres Ongaro. All Rights Reserved.
 *
 *     This work is licensed under a Creative Commons Attribution-3.0 United
 *     States License.  http://creativecommons.org/licenses/by/3.0/us/
 *
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include "compiler.h"

struct raft;
struct uuid;

/* Default TCP port number for OVSDB RAFT. */
#define RAFT_PORT 6641

struct ovsdb_error *raft_create(const char *file_name,
                                const char *local_address,
                                const char *data)
    OVS_WARN_UNUSED_RESULT;

struct ovsdb_error *raft_open(const char *file_name, struct raft **);

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
int raft_join(const char *file_name, const char *local_address,
              const char *remote_addresses[], size_t n_remotes,
              const struct uuid *cid, struct raft **);

void raft_close(struct raft *);

bool raft_run(struct raft *);
void raft_wait(struct raft *);

uint64_t raft_add_log_entry(struct raft *, const void *data);

#endif /* lib/raft.h */
