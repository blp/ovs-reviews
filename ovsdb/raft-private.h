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
#include "openvswitch/uuid.h"
#include <stdint.h>

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
