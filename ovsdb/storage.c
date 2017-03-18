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
#include "openvswitch/json.h"
#include "raft.h"
#include "util.h"

struct ovsdb_storage {
    struct ovsdb_log *log;
    struct raft *raft;
    struct ovsdb_error *error;
};

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_storage_open(const char *name, bool rw, struct ovsdb_storage **storagep)
{
    struct ovsdb_log *log;
    struct ovsdb_error *error;
    error = ovsdb_log_open(name, OVSDB_MAGIC"|"RAFT_MAGIC,
                           rw ? OVSDB_LOG_READ_WRITE : OVSDB_LOG_READ_ONLY,
                           -1, &log);
    if (error) {
        return error;
    }

    struct raft *raft = NULL;
    if (!strcmp(ovsdb_log_get_magic(log), RAFT_MAGIC)) {
        error = raft_open__(log, &raft);
        log = NULL;
        if (error) {
            return error;
        }
    }

    struct ovsdb_storage *storage = xmalloc(sizeof *storage);
    storage->log = log;
    storage->raft = raft;
    *storagep = storage;
    return NULL;
}

void
ovsdb_storage_close(struct ovsdb_storage *);

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
ovsdb_storage_read(struct ovsdb_storage *storage, struct json **jsonp,
                   struct uuid *txnid)
{
    *txnid = UUID_ZERO;         /* XXX */

    if (storage->raft) {
        bool is_snapshot;
        const struct json *data = raft_next_entry(storage->raft, &is_snapshot);
        *jsonp = data ? json_clone(data) : NULL;
        return NULL;
    } else {
        return ovsdb_log_read(storage->log, jsonp);
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
    } else {
        ovsdb_log_unread(storage->log);
    }
}

struct ovsdb_write {
    struct ovsdb_error *error;
    struct raft_command *command;

};

struct ovsdb_write * OVS_WARN_UNUSED_RESULT
ovsdb_storage_write(struct ovsdb_storage *storage, const struct json *,
                    const struct uuid *prereq, bool durable)
{
    struct ovsdb_write *w = xzalloc(sizeof *w);
    if (storage->error) {
        w->error = ovsdb_error_clone(storage->error);
    } else if (storage->raft) {
        w->command = raft_command_execute(storage->raft, data);
    } else {
        w->error = ovsdb_log_write(storage->log, json);
        if (!error && durable) {
            w->error = ovsdb_log_commit(storage->log);
        }
    }
    return w;
}

bool
ovsdb_write_is_complete(const struct ovsdb_write *w)
{
    return (w->error
            || raft_command_get_status(w->command) != RAFT_CMD_INCOMPLETE);
}

const struct ovsdb_error *
ovsdb_write_get_error(const struct ovsdb_write *w)
{
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
    } else {
        return ovsdb_log_get_offset(storage->log);
    }
}

struct ovsdb_error *ovsdb_storage_replace(struct ovsdb_storage *,
                                          const struct json **, size_t n);
