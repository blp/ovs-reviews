/* Copyright (c) 2016 Red Hat, Inc.
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

#include <assert.h>
#include <config.h>
#include "command-line.h"
#include "openvswitch/ofp-actions.h"
#include "ovstest.h"
#include "ovn/lib/actions.h"
#include "ovn/lib/ovn-dhcp.h"
#include "ovn/lib/expr.h"
#include "ovn/lib/logical-fields.h"
#include "shash.h"

static void
add_logical_register(struct shash *symtab, enum mf_field_id id)
{
    char name[8];

    snprintf(name, sizeof name, "reg%d", id - MFF_REG0);
    expr_symtab_add_field(symtab, name, id, NULL, false);
}

static void
test_put_dhcp_opts_action(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    if (argc != 4) {
        printf("Usage: %s reg_name dhcp-options expected-dhcp-opt-codes",
                argv[0]);
        exit(1);
    }

    struct hmap dhcp_opts = HMAP_INITIALIZER(&dhcp_opts);

    dhcp_opt_add(&dhcp_opts, "offerip", 0, "ipv4");
    dhcp_opt_add(&dhcp_opts, "netmask", 1, "ipv4");
    dhcp_opt_add(&dhcp_opts, "router",  3, "ipv4");
    dhcp_opt_add(&dhcp_opts, "dns_server", 6, "ipv4");
    dhcp_opt_add(&dhcp_opts, "log_server", 7, "ipv4");
    dhcp_opt_add(&dhcp_opts, "lpr_server",  9, "ipv4");
    dhcp_opt_add(&dhcp_opts, "swap_server", 16, "ipv4");
    dhcp_opt_add(&dhcp_opts, "policy_filter", 21, "ipv4");
    dhcp_opt_add(&dhcp_opts, "router_solicitation",  32, "ipv4");
    dhcp_opt_add(&dhcp_opts, "nis_server", 41, "ipv4");
    dhcp_opt_add(&dhcp_opts, "ntp_server", 42, "ipv4");
    dhcp_opt_add(&dhcp_opts, "server_id",  54, "ipv4");
    dhcp_opt_add(&dhcp_opts, "tftp_server", 66, "ipv4");
    dhcp_opt_add(&dhcp_opts, "classless_static_route", 121,
                 "static_routes");
    dhcp_opt_add(&dhcp_opts, "ip_forward_enable",  19, "bool");
    dhcp_opt_add(&dhcp_opts, "router_discovery", 31, "bool");
    dhcp_opt_add(&dhcp_opts, "ethernet_encap", 36, "bool");
    dhcp_opt_add(&dhcp_opts, "default_ttl",  23, "uint8");
    dhcp_opt_add(&dhcp_opts, "tcp_ttl", 37, "uint8");
    dhcp_opt_add(&dhcp_opts, "mtu", 26, "uint16");
    dhcp_opt_add(&dhcp_opts, "lease_time",  51, "uint32");

    struct shash symtab;
    shash_init(&symtab);
#define MFF_LOG_REG(ID) add_logical_register(&symtab, ID);
    MFF_LOG_REGS;
#undef MFF_LOG_REG

    struct action_params ap = {
        .symtab = &symtab,
        .dhcp_opts = &dhcp_opts,
    };


    char *actions = xasprintf("put_dhcp_opts(%s, %s);", argv[1], argv[2]);
    uint64_t ofpacts_stub[128 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(
        ofpacts_stub);
    struct expr *prereqs;
    char *error;

    error = actions_parse_string(actions, &ap, &ofpacts, &prereqs);
    dhcp_opts_destroy(&dhcp_opts);
    free(actions);
    if (error) {
        printf("actions_parse_string failed with error - %s\n", error);
        free(error);
        exit(1);
    }

    if (ofpacts.size < (sizeof(struct ofpact_controller) +
        sizeof(struct action_header))) {
        ovs_fatal(1, "Error. put_dhcp_opts parse action failed : "
                  " ofpact_controller not configured");
    }

    struct ofpact_controller *oc = ofpbuf_pull(&ofpacts, sizeof *oc);
    if (!oc->pause) {
        ovs_fatal(1, "Error. put_dhcp_opts parse action failed : pause flag "
                  " not set in ofpact_controller");
    }
    struct action_header *ah = ofpbuf_pull(&ofpacts, sizeof *ah);
    if (ah->opcode != htonl(ACTION_OPCODE_PUT_DHCP_OPTS)) {
        ovs_fatal(1, "Error. put_dhcp_opts parse action failed : put_dhcp_opts "
                  "action header flag not set");
    }

    uint32_t *reg_idx = ofpbuf_pull(&ofpacts, sizeof *reg_idx);
    const struct mf_field *field = mf_from_name(argv[1]);
    if (!field) {
        ovs_fatal(1, "Error. Invalid register name : %s", argv[1]);
    }

    if (*reg_idx != (field->id - MFF_REG0)) {
        ovs_fatal(1, "Error. put_dhcp_opts parse action failed : status register "
                     "id in userdata doesn't match. Expected - [%d] :"
                     " Actual - [%d]\n", field->id - MFF_REG0, *reg_idx);
    }

    uint64_t expected_dhcp_opts_stub[128 / 8];
    struct ofpbuf expected_dhcp_opts = OFPBUF_STUB_INITIALIZER(
        expected_dhcp_opts_stub);
    if (ofpbuf_put_hex(&expected_dhcp_opts, argv[3], NULL)[0] != '\0') {
        ovs_fatal(1, "Error. Invalid expected dhcp opts");
    }

    if (oc->userdata_len  !=
            (expected_dhcp_opts.size + sizeof *ah + sizeof(uint32_t))) {
        ovs_fatal(1, "Error. put_dhcp_opts parse action failed : userdata length"
                  " mismatch. Expected - %"PRIuSIZE" : Actual - %"PRIu16"",
                  expected_dhcp_opts.size + sizeof *ah, oc->userdata_len);
    }

    if (memcmp(ofpacts.data, expected_dhcp_opts.data, expected_dhcp_opts.size)) {
        ovs_fatal(1, "Error. put_dhcp_opts parse action failed : dhcp opts are"
                  " not as expected");
    }

    exit(0);
}

OVSTEST_REGISTER("test-ovn-put-dhcp-opts-action", test_put_dhcp_opts_action);
