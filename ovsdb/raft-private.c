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

#include "openvswitch/dynamic-string.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "socket-util.h"
#include "sset.h"

/* Addresses of Raft servers. */

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

/* Sets of Raft server addresses. */

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_addresses_from_json(const struct json *json, struct sset *addresses)
{
    sset_init(addresses);

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
        sset_add(addresses, json_string(address));
    }
    return NULL;
}

struct json *
raft_addresses_to_json(const struct sset *sset)
{
    struct json *array;
    const char *s;

    array = json_array_create_empty();
    SSET_FOR_EACH (s, sset) {
        json_array_add(array, json_string_create(s));
    }
    return array;
}

/* raft_server. */

const char *
raft_server_phase_to_string(enum raft_server_phase phase)
{
    switch (phase) {
    case RAFT_PHASE_STABLE: return "stable";
    case RAFT_PHASE_CATCHUP: return "adding: catchup";
    case RAFT_PHASE_CAUGHT_UP: return "adding: caught up";
    case RAFT_PHASE_COMMITTING: return "adding: committing";
    case RAFT_PHASE_REMOVE: return "removing";
    default: return "<error>";
    }
}

void
raft_server_destroy(struct raft_server *s)
{
    if (s) {
        free(s->address);
        free(s);
    }
}

void
raft_servers_destroy(struct hmap *servers)
{
    struct raft_server *s, *next;
    HMAP_FOR_EACH_SAFE (s, next, hmap_node, servers) {
        hmap_remove(servers, &s->hmap_node);
        raft_server_destroy(s);
    }
    hmap_destroy(servers);
}

struct raft_server *
raft_server_add(struct hmap *servers, const struct uuid *sid,
                const char *address)
{
    struct raft_server *s = xzalloc(sizeof *s);
    s->sid = *sid;
    s->address = xstrdup(address);
    hmap_insert(servers, &s->hmap_node, uuid_hash(sid));
    return s;
}

static struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_servers_from_json__(const struct json *json, struct hmap *servers)
{
    if (!json || json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "servers must be JSON object");
    } else if (shash_is_empty(json_object(json))) {
        return ovsdb_syntax_error(json, NULL, "must have at least one server");
    }

    /* Parse new servers. */
    struct shash_node *node;
    SHASH_FOR_EACH (node, json_object(json)) {
        /* Parse server UUID. */
        struct uuid sid;
        if (!uuid_from_string(&sid, node->name)) {
            return ovsdb_syntax_error(json, NULL, "%s is a not a UUID",
                                      node->name);
        }

        const struct json *address = node->data;
        struct ovsdb_error *error = raft_address_validate_json(address);
        if (error) {
            return error;
        }

        raft_server_add(servers, &sid, json_string(address));
    }

    return NULL;
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_servers_from_json(const struct json *json, struct hmap *servers)
{
    hmap_init(servers);
    struct ovsdb_error *error = raft_servers_from_json__(json, servers);
    if (error) {
        raft_servers_destroy(servers);
    }
    return error;
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
raft_servers_validate_json(const struct json *json)
{
    struct hmap servers = HMAP_INITIALIZER(&servers);
    struct ovsdb_error *error = raft_servers_from_json__(json, &servers);
    raft_servers_destroy(&servers);
    return error;
}

struct json *
raft_servers_to_json(const struct hmap *servers)
{
    struct json *json = json_object_create();
    struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, servers) {
        char sid_s[UUID_LEN + 1];
        sprintf(sid_s, UUID_FMT, UUID_ARGS(&s->sid));
        json_object_put_string(json, sid_s, s->address);
    }
    return json;
}

void
raft_servers_format(const struct hmap *servers, struct ds *ds)
{
    int i = 0;
    const struct raft_server *s;
    HMAP_FOR_EACH (s, hmap_node, servers) {
        if (i++) {
            ds_put_cstr(ds, ", ");
        }
        ds_put_format(ds, SID_FMT"(%s)", SID_ARGS(&s->sid), s->address);
    }
}

/* Raft log entries. */

void
raft_entry_destroy(struct raft_entry *e)
{
    if (e) {
        json_destroy(e->data);
        json_destroy(e->servers);
    }
}

struct json *
raft_entry_to_json(const struct raft_entry *e)
{
    struct json *json = json_object_create();
    json_object_put_uint(json, "term", e->term);
    if (e->data) {
        json_object_put(json, "data", json_clone(e->data));
        json_object_put_format(json, "eid", UUID_FMT, UUID_ARGS(&e->eid));
    }
    if (e->servers) {
        json_object_put(json, "servers", json_clone(e->servers));
    }
    return json;
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

