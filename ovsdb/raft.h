/*
 * Copyright (c) 2014, 2016, 2017 Nicira, Inc.
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
#include "uuid.h"

struct json;
struct ovsdb_log;
struct raft;
struct sset;

#define RAFT_MAGIC "CLUSTER"

/* Setting up a new cluster. */
struct ovsdb_error *raft_create_cluster(const char *file_name,
                                        const char *name,
                                        const char *local_address,
                                        const struct json *snapshot)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *raft_join_cluster(const char *file_name, const char *name,
                                      const char *local_address,
                                      const struct sset *remote_addrs,
                                      const struct uuid *cid)
    OVS_WARN_UNUSED_RESULT;

struct raft_metadata {
    struct uuid sid;            /* Server ID. */
    struct uuid cid;            /* Cluster ID.  All-zeros if not yet known. */
    char *name;                 /* Schema name. */
    char *local;                /* Local address. */
};
struct ovsdb_error *raft_read_metadata(struct ovsdb_log *,
                                       struct raft_metadata *);
void raft_metadata_destroy(struct raft_metadata *);

/* Starting up or shutting down a server within a cluster. */
struct ovsdb_error *raft_open(struct ovsdb_log *, struct raft **)
    OVS_WARN_UNUSED_RESULT;
void raft_close(struct raft *);

/* Information. */
const char *raft_get_name(const struct raft *);
const struct uuid *raft_get_cid(const struct raft *);
const struct uuid *raft_get_sid(const struct raft *);
bool raft_is_connected(const struct raft *);
bool raft_is_leader(const struct raft *);

/* Joining and leaving a cluster */
bool raft_is_joining(const struct raft *);

void raft_leave(struct raft *);
bool raft_is_leaving(const struct raft *);
bool raft_left(const struct raft *);

/* Failure. */
bool raft_failed(const struct raft *);

/* Running a server. */
void raft_run(struct raft *);
void raft_wait(struct raft *);

/* Reading snapshots and log entries. */
const struct json *raft_next_entry(struct raft *, struct uuid *eid,
                                   bool *is_snapshot);
bool raft_has_next_entry(const struct raft *);

uint64_t raft_get_applied_index(const struct raft *);
uint64_t raft_get_commit_index(const struct raft *);

/* Writing log entries (executing commands). */
enum raft_command_status {
    RAFT_CMD_INCOMPLETE,        /* In progress, please wait. */
    RAFT_CMD_SUCCESS,           /* Committed. */
    RAFT_CMD_NOT_LEADER,        /* Failed because we are not the leader. */
    RAFT_CMD_BAD_PREREQ,        /* Failed because prerequisite check failed. */
    RAFT_CMD_LOST_LEADERSHIP,   /* Leadership lost after command initiation. */
    RAFT_CMD_SHUTDOWN,          /* Raft server joining or left or shut down. */
    RAFT_CMD_IO_ERROR,          /* I/O error. */
    RAFT_CMD_TIMEOUT,           /* Request to remote leader timed out. */
};
const char *raft_command_status_to_string(enum raft_command_status);
bool raft_command_status_from_string(const char *, enum raft_command_status *);

struct raft_command *raft_command_execute(struct raft *,
                                          const struct json *data,
                                          const struct uuid *prereq,
                                          struct uuid *result)
    OVS_WARN_UNUSED_RESULT;
enum raft_command_status raft_command_get_status(const struct raft_command *);
uint64_t raft_command_get_commit_index(const struct raft_command *);
void raft_command_unref(struct raft_command *);
void raft_command_wait(const struct raft_command *);

/* Replacing the local log by a snapshot. */
bool raft_has_grown(const struct raft *);
struct ovsdb_error *raft_store_snapshot(struct raft *,
                                        const struct json *new_snapshot)
    OVS_WARN_UNUSED_RESULT;

/* Cluster management. */
void raft_take_leadership(struct raft *);
void raft_transfer_leadership(struct raft *);

#endif /* lib/raft.h */
