/* Copyright (c) 2009, 2010, 2011, 2017 Nicira, Inc.
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

#ifndef OVSDB_LOG_H
#define OVSDB_LOG_H 1

#include <sys/types.h>
#include "compiler.h"

struct ds;
struct json;
struct ovsdb_log;

/* Access mode for opening an OVSDB log. */
enum ovsdb_log_open_mode {
    OVSDB_LOG_READ_ONLY,        /* Open existing file, read-only. */
    OVSDB_LOG_READ_WRITE,       /* Open existing file, read/write. */
    OVSDB_LOG_CREATE_EXCL,      /* Create new file, read/write. */
    OVSDB_LOG_CREATE            /* Create or open file, read/write. */
};

#define OVSDB_MAGIC "JSON"

struct ovsdb_error *ovsdb_log_open(const char *name, const char *magic,
                                   enum ovsdb_log_open_mode,
                                   int locking, struct ovsdb_log **)
    OVS_WARN_UNUSED_RESULT;
void ovsdb_log_close(struct ovsdb_log *);

const char *ovsdb_log_get_magic(const struct ovsdb_log *);

struct ovsdb_error *ovsdb_log_read(struct ovsdb_log *, struct json **)
    OVS_WARN_UNUSED_RESULT;
void ovsdb_log_unread(struct ovsdb_log *);

void ovsdb_log_compose_record(const struct json *, const char *magic,
                              struct ds *header, struct ds *data);

struct ovsdb_error *ovsdb_log_write(struct ovsdb_log *, const struct json *)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_log_commit(struct ovsdb_log *)
    OVS_WARN_UNUSED_RESULT;

off_t ovsdb_log_get_offset(const struct ovsdb_log *);

struct ovsdb_error *ovsdb_log_replace(struct ovsdb_log *,
                                      struct json **entries, size_t n)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_log_replace_start(struct ovsdb_log *old,
                                            struct ovsdb_log **newp)
    OVS_WARN_UNUSED_RESULT;
struct ovsdb_error *ovsdb_log_replace_commit(struct ovsdb_log *old,
                                             struct ovsdb_log *new)
    OVS_WARN_UNUSED_RESULT;
void ovsdb_log_replace_abort(struct ovsdb_log *new);

#endif /* ovsdb/log.h */
