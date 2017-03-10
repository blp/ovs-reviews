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

#ifndef OVSDB_STORAGE_H
#define OVSDB_STORAGE_H 1

#include <sys/types.h>
#include "compiler.h"

struct json;
struct ovsdb_storage;
struct ovsdb_completion;

struct ovsdb_error *ovsdb_storage_open(const char *name, bool rw,
                                       struct ovsdb_storage **)
    OVS_WARN_UNUSED_RESULT;
void ovsdb_storage_close(struct ovsdb_storage *);

void ovsdb_storage_run(struct ovsdb_storage *);
void ovsdb_storage_wait(struct ovsdb_storage *);

const char *ovsdb_storage_get_name(const struct ovsdb_storage *);

struct ovsdb_error *ovsdb_storage_read(struct ovsdb_storage *, struct json **,
                                       struct uuid *)
    OVS_WARN_UNUSED_RESULT;
void ovsdb_storage_read_wait(struct ovsdb_storage *);

void ovsdb_storage_unread(struct ovsdb_storage *);

struct ovsdb_completion *ovsdb_storage_write(struct ovsdb_storage *,
                                             const struct json *,
                                             const struct uuid *prereq,
                                             bool durable)
    OVS_WARN_UNUSED_RESULT;
bool ovsdb_completion_get_status(const struct ovsdb_completion *);
const struct ovsdb_error *ovsdb_completion_get_error(
    const struct ovsdb_completion *);
void ovsdb_completion_wait(const struct ovsdb_completion *);
void ovsdb_completion_destroy(struct ovsdb_completion *);

off_t ovsdb_storage_get_offset(const struct ovsdb_storage *);

struct ovsdb_error *ovsdb_storage_replace(struct ovsdb_storage *,
                                          const struct json **, size_t n);

#endif /* ovsdb/storage.h */
