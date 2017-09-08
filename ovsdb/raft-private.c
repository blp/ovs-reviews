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

#include <config.h>

#include "raft-private.h"

#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "socket-util.h"
#include "sset.h"

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_address_validate(const char *address)
{
    if (!strncmp(address, "unix:", 5)) {
        return NULL;
    } else if (!strncmp(address, "ssl:", 4) || !strncmp(address, "tcp:", 4)) {
        struct sockaddr_storage ss;
        if (!inet_parse_active(address + 4, 0, &ss)) {
            return ovsdb_error(NULL, "%s: syntax error in address", address);
        }
        return NULL;
    } else {
        return ovsdb_error(NULL, "%s: expected \"tcp\" or \"ssl\" address",
                           address);
    }
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_address_validate_json(const struct json *address)
{
    if (address->type != JSON_STRING) {
        return ovsdb_syntax_error(address, NULL,
                                  "server address is not string");
    }
    return raft_address_validate(json_string(address));
}

void
raft_entry_destroy(struct raft_entry *e)
{
    if (e) {
        json_destroy(e->data);
        json_destroy(e->servers);
    }
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_entry_from_json(struct json *json, struct raft_entry *e)
{
    memset(e, 0, sizeof *e);

    struct ovsdb_parser p;
    ovsdb_parser_init(&p, json, "raft log entry");
    e->term = raft_parse_uint(&p, "term");
    e->data = json_nullable_clone(
        ovsdb_parser_member(&p, "data", OP_OBJECT | OP_ARRAY | OP_OPTIONAL));
    e->eid = e->data ? raft_parse_required_uuid(&p, "eid") : UUID_ZERO;
    e->servers = json_nullable_clone(
        ovsdb_parser_member(&p, "servers", OP_OBJECT | OP_OPTIONAL));
    if (e->servers) {
        ovsdb_parser_put_error(&p, raft_servers_validate_json(e->servers));
    }

    struct ovsdb_error *error = ovsdb_parser_finish(&p);
    if (error) {
        raft_entry_destroy(e);
    }
    return error;
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_remotes_from_json(const struct json *json, struct sset *remotes)
{
    sset_init(remotes);

    const struct json_array *array = json_array(json);
    if (!array->n) {
        return ovsdb_syntax_error(json, NULL,
                                  "at least one remote address is required");
    }
    for (size_t i = 0; i < array->n; i++) {
        const struct json *address = array->elems[i];
        struct ovsdb_error *error = raft_address_validate_json(address);
        if (error) {
            return error;
        }
        sset_add(remotes, json_string(address));
    }
    return NULL;
}

struct json *
raft_remotes_to_json(const struct sset *sset)
{
    struct json *array;
    const char *s;

    array = json_array_create_empty();
    SSET_FOR_EACH (s, sset) {
        json_array_add(array, json_string_create(s));
    }
    return array;
}

uint64_t
raft_parse_uint(struct ovsdb_parser *p, const char *name)
{
    const struct json *json = ovsdb_parser_member(p, name, OP_INTEGER);
    return json ? json_integer(json) : 0;
}

static int
raft_parse_boolean__(struct ovsdb_parser *p, const char *name, bool optional)
{
    enum ovsdb_parser_types types = OP_BOOLEAN | (optional ? OP_OPTIONAL : 0);
    const struct json *json = ovsdb_parser_member(p, name, types);
    return json ? json_boolean(json) : -1;
}

bool
raft_parse_required_boolean(struct ovsdb_parser *p, const char *name)
{
    return raft_parse_boolean__(p, name, false);
}

/* Returns true or false if present, -1 if absent. */
int
raft_parse_optional_boolean(struct ovsdb_parser *p, const char *name)
{
    return raft_parse_boolean__(p, name, true);
}

static const char *
raft_parse_string__(struct ovsdb_parser *p, const char *name, bool optional)
{
    enum ovsdb_parser_types types = OP_STRING | (optional ? OP_OPTIONAL : 0);
    const struct json *json = ovsdb_parser_member(p, name, types);
    return json ? json_string(json) : NULL;
}

const char *
raft_parse_required_string(struct ovsdb_parser *p, const char *name)
{
    return raft_parse_string__(p, name, false);
}

const char *
raft_parse_optional_string(struct ovsdb_parser *p, const char *name)
{
    return raft_parse_string__(p, name, true);
}

bool
raft_parse_uuid__(struct ovsdb_parser *p, const char *name, bool optional,
             struct uuid *uuid)
{
    const char *s = raft_parse_string__(p, name, optional);
    if (s) {
        if (uuid_from_string(uuid, s)) {
            return true;
        }
        ovsdb_parser_raise_error(p, "%s is not a valid UUID", name);
    }
    *uuid = UUID_ZERO;
    return false;
}

struct uuid
raft_parse_required_uuid(struct ovsdb_parser *p, const char *name)
{
    struct uuid uuid;
    raft_parse_uuid__(p, name, false, &uuid);
    return uuid;
}

bool
raft_parse_optional_uuid(struct ovsdb_parser *p, const char *name,
                    struct uuid *uuid)
{
    return raft_parse_uuid__(p, name, true, uuid);
}

