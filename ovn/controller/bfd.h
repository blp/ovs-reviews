/* Copyright (c) 2017 Red Hat, Inc.
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

#ifndef OVN_BFD_H
#define OVN_BFD_H 1

#include "ovn/controller/bfd-ovn-sb-idl.h"
#include "ovn/controller/bfd-vswitch-idl.h"

struct hmap;
struct ovsdb_idl;
struct sset;

void bfd_register_ovs_idl(struct ovsdb_idl *);
void bfd_run(struct bfd_sbrec_chassis_by_name *,
             struct bfd_sbrec_port_binding_by_datapath *,
             const struct bfd_ovsrec_interface_table *,
             const struct bfd_ovsrec_bridge *br_int,
             const struct sbrec_chassis *chassis_rec,
             const struct hmap *local_datapaths);
void  bfd_calculate_active_tunnels(const struct bfd_ovsrec_bridge *br_int,
                                   struct sset *active_tunnels);

#endif
