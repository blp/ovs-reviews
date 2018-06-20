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


#ifndef OVN_BINDING_H
#define OVN_BINDING_H 1

#include "ovn/controller/binding-ovn-sb-idl.h"
#include "ovn/controller/binding-vswitch-idl.h"
#include <stdbool.h>

struct hmap;
struct ovsdb_idl;
struct sset;

void binding_register_ovs_idl(struct ovsdb_idl *);
void binding_run(struct binding_sbrec_txn *,
                 struct binding_ovsrec_txn *,
                 struct binding_sbrec_chassis_by_name *,
                 struct binding_sbrec_datapath_binding_by_tunnel_key *,
                 struct binding_sbrec_port_binding_by_datapath *,
                 struct binding_sbrec_port_binding_by_logical_port *,
                 const struct binding_ovsrec_port_table *,
                 const struct binding_ovsrec_qos_table *,
                 const struct binding_sbrec_port_binding_table *,
                 const struct binding_ovsrec_bridge *br_int,
                 const struct binding_sbrec_chassis *,
                 const struct sset *active_tunnels,
                 struct hmap *local_datapaths,
                 struct sset *local_lports, struct sset *local_lport_ids);
bool binding_cleanup(struct binding_sbrec_txn *,
                     const struct sbrec_port_binding_table *,
                     const struct sbrec_chassis *);

#endif /* ovn/binding.h */
