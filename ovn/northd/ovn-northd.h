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

#ifndef OVN_NORTHD_H
#define OVN_NORTHD_H 1

#include <stddef.h>
#include "openvswitch/util.h"
#include "stages.h"

struct hmap;
struct lport_addresses;
struct smap;
struct uuid;

void build_lsp_addrs(char **addresses, size_t n_addresses,
                     const char *dynamic_addresses,
                     struct lport_addresses **lsp_addrsp, size_t *n_lsp_addrsp,
                     bool *has_unknownp);
void build_ps_addrs(char **port_security, size_t n_port_security,
                    struct lport_addresses **ps_addrsp, size_t *n_ps_addrsp);
void free_lp_addrs(struct lport_addresses *, size_t n);

char *build_lsp_macs(struct lport_addresses *, size_t n);

char *build_port_security_l2(struct lport_addresses *, size_t n);

char *build_port_security_ip(enum ovn_pipeline,
                             struct lport_addresses *, size_t n);

char *build_port_security_nd(struct lport_addresses *, size_t n);

char *build_load_balancer_ip_addresses(const struct smap *vips);

char *build_dhcp_option_args(const struct smap *dhcp_options);
char *build_dhcp_netmask(const char *cidr);
char *build_dhcp_server_mac(const struct smap *dhcp_options);
char *build_dhcp_server_ip(const struct smap *dhcp_options);
bool build_dhcp_stateful(const struct smap *dhcp_options);

struct ovn_datapath *ovn_datapath_find(struct hmap *datapaths,
                                       const struct uuid *);

/* Adds a row with the specified contents to the Logical_Flow table. */
#define ovn_lflow_add(LFLOWS, OD, STAGE, PRIORITY, MATCH, ACTIONS) \
    ovn_lflow_add_at(LFLOWS, OD, STAGE, PRIORITY, MATCH, ACTIONS,  \
                     OVS_SOURCE_LOCATOR)

void ovn_lflow_add_at(struct hmap *lflows, struct ovn_datapath *od,
                      enum ovn_stage stage, uint16_t priority,
                      const char *match, const char *actions,
                      const char *where);

#endif /* ovn-northd.h */
