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

#include <stdbool.h>
#include "compiler.h"
#include "log.h"

struct ovsdb;
struct ovsdb_storage;
struct ovsdb_schema;

struct ovsdb_error *ovsdb_storage_open(const char *file_name,
                                       bool read_only, int locking,
                                       struct ovsdb_storage **storagep)
    OVS_WARN_UNUSED_RESULT;

void ovsdb_storage_close(struct ovsdb_storage *);

const char *ovsdb_storage_get_name(const struct ovsdb_storage *);



struct ovsdb_error *ovsdb_storage_commit(struct ovsdb_storage *,
                                         struct json *, bool durable);





struct ovsdb_error *ovsdb_storage_save_copy(const char *storage_name,
                                            const char *comment,
                                            const struct ovsdb *)
    OVS_WARN_UNUSED_RESULT;

struct ovsdb_error *ovsdb_storage_compact(struct ovsdb_storage *);

struct ovsdb_error *ovsdb_storage_read_schema(const char *storage_name,
                                              struct ovsdb_schema **)
    OVS_WARN_UNUSED_RESULT;

#endif /* ovsdb/storage.h */
