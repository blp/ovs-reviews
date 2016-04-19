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

int raft_join(const char *file_name, const char *local_address,
              const char *remote_addresses[], size_t n_remotes,
              const struct uuid *cid, struct raft **);

void raft_close(struct raft *);

void raft_run(struct raft *);
void raft_wait(struct raft *);

uint64_t raft_add_log_entry(struct raft *, const void *data);

#endif /* lib/raft.h */
