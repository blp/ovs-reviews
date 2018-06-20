/* Copyright (c) 2015, 2016 Nicira, Inc.
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

#ifndef OVN_PATCH_H
#define OVN_PATCH_H 1

/* Patch Ports
 * ===========
 *
 * This module adds and removes patch ports between the integration bridge and
 * physical bridges, as directed by other-config:ovn-bridge-mappings. */

#include "ovn/controller/patch-ovn-sb-idl.h"
#include "ovn/controller/patch-vswitch-idl.h"

struct hmap;

void patch_run(struct patch_ovsrec_txn *,
               const struct patch_ovsrec_bridge_table *,
               const struct patch_ovsrec_open_vswitch_table *,
               const struct patch_ovsrec_port_table *,
               const struct patch_sbrec_port_binding_table *,
               const struct patch_ovsrec_bridge *br_int,
               const struct patch_sbrec_chassis *);

#endif /* ovn/patch.h */
