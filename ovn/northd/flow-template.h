/*
 * Copyright (c) 2016 Nicira, Inc.
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

#ifndef OVN_NORTHD_FLOW_TEMPLATE_H
#define OVN_NORTHD_FLOW_TEMPLATE_H 1

/* Flow template language
 * ======================
 */

#include "openvswitch/compiler.h"

struct ftl;
struct hmap;
struct ovsdb_idl;

char *ftl_read(const char *file_name, const char *include_path,
               struct ovsdb_idl *, struct ftl **)
    OVS_WARN_UNUSED_RESULT;
void ftl_destroy(struct ftl *);

void ftl_run(struct ftl *, struct ovsdb_idl *,
             struct hmap *flows, struct hmap *ovn_datapaths);
void ftl_wait(struct ftl *);

#endif /* ovn/northd/flow-template.h */
