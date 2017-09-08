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

#ifndef RAFT_PRIVATE_H
#define RAFT_PRIVATE_H 1

/* Data structures for use internally within the Raft implementation. */

#include "raft.h"
#include "openvswitch/hmap.h"
#include "openvswitch/uuid.h"
#include <stdint.h>

struct ds;
struct ovsdb_parser;
struct sset;

struct ovsdb_error *raft_address_validate(const char *address)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *raft_address_validate_json(const struct json *address)
    OVS_WARN_UNUSED_RESULT;

struct ovsdb_error *raft_remotes_from_json(const struct json *,
                                           struct sset *remotes)
    OVS_WARN_UNUSED_RESULT;
struct json *raft_remotes_to_json(const struct sset *);

enum raft_server_phase {
    RAFT_PHASE_STABLE,          /* Not being changed. */

    /* Phases for servers being added. */
    RAFT_PHASE_CATCHUP,         /* Populating new server's log. */
    RAFT_PHASE_CAUGHT_UP,       /* Waiting for prev configuration to commit. */
    RAFT_PHASE_COMMITTING,      /* Waiting for new configuration to commit. */

    /* Phases for servers to be removed. */
    RAFT_PHASE_REMOVE,          /* To be removed. */
};

const char *raft_server_phase_to_string(enum raft_server_phase);

struct raft_server {
    struct hmap_node hmap_node; /* Hashed based on 'sid'. */

    struct uuid sid;            /* Server ID. */
    char *address;              /* "(tcp|ssl):1.2.3.4:5678" */

    /* Volatile state on candidates.  Reinitialized at start of election. */
    struct uuid vote;           /* Server ID of vote, or all-zeros. */

    /* Volatile state on leaders.  Reinitialized after election. */
    uint64_t next_index;     /* Index of next log entry to send this server. */
    uint64_t match_index;    /* Index of max log entry server known to have. */
    enum raft_server_phase phase;
    /* For use in adding and removing servers: */
    struct uuid requester_sid;  /* Nonzero if requested via RPC. */
    struct unixctl_conn *requester_conn; /* Only if requested via unixctl. */
};

void raft_server_destroy(struct raft_server *);
void raft_servers_destroy(struct hmap *servers);
struct raft_server *raft_server_add(struct hmap *servers,
                                    const struct uuid *sid,
                                    const char *address);
struct ovsdb_error *raft_servers_from_json__(const struct json *,
                                             struct hmap *servers)
    OVS_WARN_UNUSED_RESULT;

struct ovsdb_error *raft_servers_from_json(const struct json *,
                                           struct hmap *servers)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *raft_servers_validate_json(const struct json *);
    OVS_WARN_UNUSED_RESULT
struct json *raft_servers_to_json(const struct hmap *servers);
void raft_servers_format(const struct hmap *servers, struct ds *ds);

struct ovsdb_error *raft_servers_validate_json(const struct json *)
    OVS_WARN_UNUSED_RESULT;

struct raft_entry {
    uint64_t term;
    struct json *data;
    struct uuid eid;
    struct json *servers;
};

void raft_entry_destroy(struct raft_entry *);
struct json *raft_entry_to_json(const struct raft_entry *);
struct ovsdb_error *raft_entry_from_json(struct json *, struct raft_entry *)
    OVS_WARN_UNUSED_RESULT;

#define SID_FMT "%04x"
#define SID_ARGS(SID) uuid_prefix(SID, 4)

#define CID_FMT "%04x"
#define CID_ARGS(CID) uuid_prefix(CID, 4)

uint64_t raft_parse_uint(struct ovsdb_parser *, const char *name);
bool raft_parse_required_boolean(struct ovsdb_parser *, const char *name);
int raft_parse_optional_boolean(struct ovsdb_parser *, const char *name);
const char *raft_parse_required_string(struct ovsdb_parser *,
                                           const char *name);
const char *raft_parse_optional_string(struct ovsdb_parser *,
                                           const char *name);
bool raft_parse_uuid__(struct ovsdb_parser *, const char *name, bool optional,
                       struct uuid *);
struct uuid raft_parse_required_uuid(struct ovsdb_parser *, const char *name);
bool raft_parse_optional_uuid(struct ovsdb_parser *, const char *name,
                         struct uuid *);

#endif /* raft-private.h */
