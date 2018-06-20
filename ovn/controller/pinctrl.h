
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

#ifndef PINCTRL_H
#define PINCTRL_H 1

#include "ovn/controller/pinctrl-vswitch-idl.h"
#include "ovn/controller/pinctrl-ovn-sb-idl.h"

#include <stdint.h>

#include "lib/sset.h"
#include "openvswitch/meta-flow.h"

struct hmap;

void pinctrl_init(void);
void pinctrl_run(struct pinctrl_sbrec_txn *,
                 struct pinctrl_sbrec_chassis_by_name *,
                 struct pinctrl_sbrec_datapath_binding_by_tunnel_key *,
                 struct pinctrl_sbrec_port_binding_by_datapath *,
                 struct pinctrl_sbrec_port_binding_by_tunnel_key_datapath *,
                 struct pinctrl_sbrec_port_binding_by_logical_port *,
                 const struct pinctrl_sbrec_dns_table *,
                 const struct pinctrl_sbrec_mac_binding_table *,
                 const struct pinctrl_ovsrec_bridge *,
                 const struct pinctrl_sbrec_chassis *,
                 const struct hmap *local_datapaths,
                 const struct sset *active_tunnels);
void pinctrl_wait(struct pinctrl_sbrec_txn *);
void pinctrl_destroy(void);

#endif /* ovn/pinctrl.h */
