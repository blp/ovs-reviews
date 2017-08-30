/* Copyright (c) 2009, 2010, 2011, 2016, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this storage except in compliance with the License.
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

#include "storage.h"
#include <string.h>
#include "log.h"
#include "ovsdb-error.h"
#include "openvswitch/json.h"
#include "openvswitch/vlog.h"
#include "poll-loop.h"
#include "ovsdb.h"
#include "raft.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(storage);

/* There are three kinds of storage:
 *
 *    - Standalone, backed by a disk file.  'log' is nonnull, 'raft' is null.
 *
 *    - Clustered, backed by a Raft cluster.  'log' is null, 'raft' is nonnull.
 *
 *    - Memory only, unbacked.  'log' and 'raft' are null. */
struct ovsdb_storage {
    struct ovsdb_log *log;
    struct raft *raft;
    struct ovsdb_error *error;
    unsigned int n_read;
};

/* Opens 'filename' for use as storage.  If 'rw', opens it for read/write access,
 * otherwise read-only.  If successful, stores the new storage in '*storagep'
 * and returns NULL; on failure, stores NULL in '*storagep' and returns the
 * error.
 *
 * The returned storage might be clustered or standalone, depending on what
 * 'filename' contains. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_storage_open(const char *filename, bool rw,
                   struct ovsdb_storage **storagep)
{
    struct ovsdb_log *log;
    struct ovsdb_error *error;
    error = ovsdb_log_open(filename, OVSDB_MAGIC"|"RAFT_MAGIC,
                           rw ? OVSDB_LOG_READ_WRITE : OVSDB_LOG_READ_ONLY,
                           -1, &log);
    if (error) {
        return error;
    }

    struct raft *raft = NULL;
    if (!strcmp(ovsdb_log_get_magic(log), RAFT_MAGIC)) {
        error = raft_open__(log, &raft, NULL, NULL);
        log = NULL;
        if (error) {
            return error;
        }
    }

    struct ovsdb_storage *storage = xzalloc(sizeof *storage);
    storage->log = log;
    storage->raft = raft;
    *storagep = storage;
    return NULL;
}

/* Creates and returns new storage without any backing.  Nothing will be read
 * from the storage, and writes are discarded. */
struct ovsdb_storage *
ovsdb_storage_create_unbacked(void)
{
    return xzalloc(sizeof(struct ovsdb_storage));
}

void
ovsdb_storage_close(struct ovsdb_storage *storage)
{
    if (storage) {
        ovsdb_log_close(storage->log);
        raft_close(storage->raft);
        ovsdb_error_destroy(storage->error);
        free(storage);
    }
}

const char *
ovsdb_storage_get_model(const struct ovsdb_storage *storage)
{
    return storage->raft ? "clustered" : "standalone";
}

bool
ovsdb_storage_is_clustered(const struct ovsdb_storage *storage)
{
    return storage->raft != NULL;
}

bool
ovsdb_storage_is_connected(const struct ovsdb_storage *storage)
{
    return !storage->raft || raft_is_connected(storage->raft);
}

bool
ovsdb_storage_is_leader(const struct ovsdb_storage *storage)
{
    return !storage->raft || raft_is_leaving(storage->raft);
}

const struct uuid *
ovsdb_storage_get_cid(const struct ovsdb_storage *storage)
{
    return storage->raft ? raft_get_cid(storage->raft) : NULL;
}

const struct uuid *
ovsdb_storage_get_sid(const struct ovsdb_storage *storage)
{
    return storage->raft ? raft_get_sid(storage->raft) : NULL;
}

void
ovsdb_storage_run(struct ovsdb_storage *storage)
{
    if (storage->raft) {
        raft_run(storage->raft);
    }
}

void
ovsdb_storage_wait(struct ovsdb_storage *storage)
{
    if (storage->raft) {
        raft_wait(storage->raft);
    }
}

/* Returns 'storage''s embedded name, if it has one, otherwise null.
 *
 * Only clustered storage has a built-in name.  */
const char *
ovsdb_storage_get_name(const struct ovsdb_storage *storage)
{
    return storage->raft ? raft_get_name(storage->raft) : NULL;
}

/* Attempts to read a log record from 'storage'.
 *
 * If successful, returns NULL and stores in '*jsonp' the JSON object that the
 * record contains.  The caller owns the data and must eventually free it (with
 * json_destroy()).
 *
 * If a read error occurs, returns the error and stores NULL in '*jsonp'.
 *
 * If the read reaches end of file, returns NULL and stores NULL in
 * '*jsonp'. */
struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_storage_read(struct ovsdb_storage *storage,
                   struct ovsdb_schema **schemap,
                   struct json **txnp,
                   struct uuid *txnid)
{
    *schemap = NULL;
    *txnp = NULL;
    if (txnid) {
        *txnid = UUID_ZERO;
    }

    struct json *json;
    struct json *schema_json = NULL;
    struct json *txn_json = NULL;
    if (storage->raft) {
        bool is_snapshot;
        json = json_nullable_clone(
            raft_next_entry(storage->raft, txnid, &is_snapshot));
        if (!json) {
            return NULL;
        } else if (json->type != JSON_ARRAY || json->u.array.n != 2) {
            json_destroy(json);
            return ovsdb_error(NULL, "invalid commit format");
        }

        struct json **e = json->u.array.elems;
        schema_json = e[0]->type != JSON_NULL ? e[0] : NULL;
        txn_json = e[1]->type != JSON_NULL ? e[1] : NULL;
    } else if (storage->log) {
        struct ovsdb_error *error = ovsdb_log_read(storage->log, &json);
        if (error || !json) {
            return error;
        }

        if (!storage->n_read++) {
            schema_json = json;
        } else {
            txn_json = json;
        }
    } else {
        /* Unbacked.  Nothing to do. */
        return NULL;
    }

    /* If we got this far then we must have at least a schema or a
     * transaction. */
    ovs_assert(schema_json || txn_json);

    if (schema_json) {
        struct ovsdb_schema *schema;
        struct ovsdb_error *error = ovsdb_schema_from_json(schema_json,
                                                           &schema);
        if (error) {
            json_destroy(json);
            return error;
        }

        const char *storage_name = ovsdb_storage_get_name(storage);
        const char *schema_name = schema->name;
        if (storage_name && strcmp(storage_name, schema_name)) {
            error = ovsdb_error(NULL, "name %s in header does not match "
                                "name %s in schema",
                                storage_name, schema_name);
            json_destroy(json);
            ovsdb_schema_destroy(schema);
            return error;
        }

        *schemap = schema;
    }

    if (txn_json) {
        *txnp = json_clone(txn_json);
    }

    json_destroy(json);
    return NULL;
}

bool
ovsdb_storage_read_wait(struct ovsdb_storage *storage)
{
    if (storage->raft) {
        return raft_has_next_entry(storage->raft);
    } else {
        /* XXX */
        return false;
    }
}

void
ovsdb_storage_unread(struct ovsdb_storage *storage)
{
    if (storage->error) {
        return;
    }

    if (storage->raft) {
        if (!storage->error) {
            storage->error = ovsdb_error(NULL, "inconsistent data");
        }
    } else if (storage->log) {
        ovsdb_log_unread(storage->log);
    }
}

struct ovsdb_write {
    struct ovsdb_error *error;
    struct raft_command *command;
};

struct ovsdb_write * OVS_WARN_UNUSED_RESULT
ovsdb_storage_write(struct ovsdb_storage *storage, const struct json *data,
                    const struct uuid *prereq, struct uuid *resultp,
                    bool durable)
{
    ovs_assert(data->type == JSON_ARRAY && data->u.array.n == 2);

    struct ovsdb_write *w = xzalloc(sizeof *w);
    struct uuid result = UUID_ZERO;
    if (storage->error) {
        w->error = ovsdb_error_clone(storage->error);
    } else if (storage->raft) {
        w->command = raft_command_execute(storage->raft, data,
                                          prereq, &result);
    } else if (storage->log) {
        w->error = ovsdb_log_write(storage->log, data->u.array.elems[1]);
        if (!w->error && durable) {
            w->error = ovsdb_log_commit(storage->log);
        }
    } else {
        /* When 'error' and 'command' are both null, it indicates that the
         * command is complete.  This is fine since this unbacked storage drops
         * writes. */
    }
    if (resultp) {
        *resultp = result;
    }
    return w;
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_storage_write_block(struct ovsdb_storage *storage,
                          const struct json *data, const struct uuid *prereq,
                          struct uuid *resultp, bool durable)
{
    struct ovsdb_write *w = ovsdb_storage_write(storage, data,
                                                prereq, resultp, durable);
    while (!ovsdb_write_is_complete(w)) {
        if (storage->raft) {
            raft_run(storage->raft);
        }

        ovsdb_write_wait(w);
        if (storage->raft) {
            raft_wait(storage->raft);
        }
        poll_block();
    }

    struct ovsdb_error *error = ovsdb_error_clone(ovsdb_write_get_error(w));
    ovsdb_write_destroy(w);
    return error;
}

bool
ovsdb_write_is_complete(const struct ovsdb_write *w)
{
    return (w->error
            || !w->command
            || raft_command_get_status(w->command) != RAFT_CMD_INCOMPLETE);
}

const struct ovsdb_error *
ovsdb_write_get_error(const struct ovsdb_write *w_)
{
    struct ovsdb_write *w = CONST_CAST(struct ovsdb_write *, w_);
    if (w->command) {
        enum raft_command_status status = raft_command_get_status(w->command);
        ovs_assert(status != RAFT_CMD_INCOMPLETE);
        if (status != RAFT_CMD_SUCCESS) {
            w->error = ovsdb_error(NULL, "%s",
                                   raft_command_status_to_string(status));
        }
        raft_command_unref(w->command);
        w->command = NULL;
    }

    return w->error;
}

void
ovsdb_write_wait(const struct ovsdb_write *w)
{
    if (ovsdb_write_is_complete(w)) {
        poll_immediate_wake();
    }
}

void
ovsdb_write_destroy(struct ovsdb_write *w)
{
    if (w) {
        raft_command_unref(w->command);
        ovsdb_error_destroy(w->error);
        free(w);
    }
}

off_t
ovsdb_storage_get_offset(const struct ovsdb_storage *storage)
{
    if (storage->raft) {
        /* XXX */
        return 1000000;
    } else if (storage->log) {
        return ovsdb_log_get_offset(storage->log);
    } else {
        /* XXX */
        return 1000000;
    }
}

struct ovsdb_error *ovsdb_storage_replace(struct ovsdb_storage *,
                                          const struct json **, size_t n);
