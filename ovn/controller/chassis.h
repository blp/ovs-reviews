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

#ifndef OVN_CHASSIS_H
#define OVN_CHASSIS_H 1

#include "ovn/controller/chassis-ovn-sb-idl.h"
#include "ovn/controller/chassis-vswitch-idl.h"
#include <stdbool.h>

struct ovsdb_idl;

void chassis_register_ovs_idl(struct ovsdb_idl *);
const struct chassis_sbrec_chassis *chassis_run(
    struct chassis_sbrec_txn *,
    struct chassis_sbrec_chassis_by_name *,
    const struct chassis_ovsrec_open_vswitch_table *,
    const char *chassis_id,
    const struct chassis_ovsrec_bridge *br_int);
bool chassis_cleanup(struct chassis_sbrec_txn *,
                     const struct chassis_sbrec_chassis *);

#endif /* ovn/chassis.h */
