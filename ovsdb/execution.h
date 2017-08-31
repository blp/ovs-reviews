/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2017 Nicira, Inc.
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

#ifndef OVSDB_EXECUTION_H
#define OVSDB_EXECUTION_H 1

#include <stdbool.h>

struct json;
struct ovsdb;
struct ovsdb_session;

struct ovsdb_txn *ovsdb_execute_compose(
    struct ovsdb *, const struct ovsdb_session *,
    const struct json *params, bool read_only,
    long long int elapsed_msec, long long int *timeout_msec,
    bool *durable, struct json **);

struct json *ovsdb_execute(struct ovsdb *, const struct ovsdb_session *,
                           const struct json *params, bool read_only,
                           long long int elapsed_msec,
                           long long int *timeout_msec);

#endif  /* execution.h */
