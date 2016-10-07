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

#ifndef OVN_NORTHD_STAGES_H
#define OVN_NORTHD_STAGES_H 1

#include <stdint.h>
#include "util.h"

/* Logical pipeline stages. */

/* The two pipelines in an OVN logical flow table. */
enum ovn_pipeline {
    P_IN,                       /* Ingress pipeline. */
    P_OUT                       /* Egress pipeline. */
};

/* The two purposes for which ovn-northd uses OVN logical datapaths. */
enum ovn_datapath_type {
    DP_SWITCH,                  /* OVN logical switch. */
    DP_ROUTER                   /* OVN logical router. */
};

/* Returns an "enum ovn_stage" built from the arguments.
 *
 * (It's better to use ovn_stage_build() for type-safety reasons, but inline
 * functions can't be used in enums or switch cases.) */
#define OVN_STAGE_BUILD(DP_TYPE, PIPELINE, TABLE) \
    (((DP_TYPE) << 9) | ((PIPELINE) << 8) | (TABLE))

/* A stage within an OVN logical switch or router.
 *
 * An "enum ovn_stage" indicates whether the stage is part of a logical switch
 * or router, whether the stage is part of the ingress or egress pipeline, and
 * the table within that pipeline.  The first three components are combined to
 * form the stage's full name, e.g. S_SWITCH_IN_PORT_SEC_L2,
 * S_ROUTER_OUT_DELIVERY. */
enum ovn_stage {
#define PIPELINE_STAGES                                               \
    /* Logical switch ingress stages. */                              \
    PIPELINE_STAGE(SWITCH, IN,  PORT_SEC_L2,    0, "ls_in_port_sec_l2")     \
    PIPELINE_STAGE(SWITCH, IN,  PORT_SEC_IP,    1, "ls_in_port_sec_ip")     \
    PIPELINE_STAGE(SWITCH, IN,  PORT_SEC_ND,    2, "ls_in_port_sec_nd")     \
    PIPELINE_STAGE(SWITCH, IN,  PRE_ACL,        3, "ls_in_pre_acl")      \
    PIPELINE_STAGE(SWITCH, IN,  PRE_LB,         4, "ls_in_pre_lb")         \
    PIPELINE_STAGE(SWITCH, IN,  PRE_STATEFUL,   5, "ls_in_pre_stateful")    \
    PIPELINE_STAGE(SWITCH, IN,  ACL,            6, "ls_in_acl")          \
    PIPELINE_STAGE(SWITCH, IN,  QOS_MARK,       7, "ls_in_qos_mark")      \
    PIPELINE_STAGE(SWITCH, IN,  LB,             8, "ls_in_lb")           \
    PIPELINE_STAGE(SWITCH, IN,  STATEFUL,       9, "ls_in_stateful")     \
    PIPELINE_STAGE(SWITCH, IN,  ARP_ND_RSP,     10, "ls_in_arp_rsp")      \
    PIPELINE_STAGE(SWITCH, IN,  DHCP_OPTIONS,   11, "ls_in_dhcp_options") \
    PIPELINE_STAGE(SWITCH, IN,  DHCP_RESPONSE,  12, "ls_in_dhcp_response") \
    PIPELINE_STAGE(SWITCH, IN,  L2_LKUP,        13, "ls_in_l2_lkup")      \
                                                                      \
    /* Logical switch egress stages. */                               \
    PIPELINE_STAGE(SWITCH, OUT, PRE_LB,       0, "ls_out_pre_lb")     \
    PIPELINE_STAGE(SWITCH, OUT, PRE_ACL,      1, "ls_out_pre_acl")     \
    PIPELINE_STAGE(SWITCH, OUT, PRE_STATEFUL, 2, "ls_out_pre_stateful")  \
    PIPELINE_STAGE(SWITCH, OUT, LB,           3, "ls_out_lb")            \
    PIPELINE_STAGE(SWITCH, OUT, ACL,          4, "ls_out_acl")            \
    PIPELINE_STAGE(SWITCH, OUT, QOS_MARK,     5, "ls_out_qos_mark")       \
    PIPELINE_STAGE(SWITCH, OUT, STATEFUL,     6, "ls_out_stateful")       \
    PIPELINE_STAGE(SWITCH, OUT, PORT_SEC_IP,  7, "ls_out_port_sec_ip")    \
    PIPELINE_STAGE(SWITCH, OUT, PORT_SEC_L2,  8, "ls_out_port_sec_l2")    \
                                                                      \
    /* Logical router ingress stages. */                              \
    PIPELINE_STAGE(ROUTER, IN,  ADMISSION,   0, "lr_in_admission")    \
    PIPELINE_STAGE(ROUTER, IN,  IP_INPUT,    1, "lr_in_ip_input")     \
    PIPELINE_STAGE(ROUTER, IN,  DEFRAG,      2, "lr_in_defrag")       \
    PIPELINE_STAGE(ROUTER, IN,  UNSNAT,      3, "lr_in_unsnat")       \
    PIPELINE_STAGE(ROUTER, IN,  DNAT,        4, "lr_in_dnat")         \
    PIPELINE_STAGE(ROUTER, IN,  IP_ROUTING,  5, "lr_in_ip_routing")   \
    PIPELINE_STAGE(ROUTER, IN,  ARP_RESOLVE, 6, "lr_in_arp_resolve")  \
    PIPELINE_STAGE(ROUTER, IN,  ARP_REQUEST, 7, "lr_in_arp_request")  \
                                                                      \
    /* Logical router egress stages. */                               \
    PIPELINE_STAGE(ROUTER, OUT, SNAT,      0, "lr_out_snat")          \
    PIPELINE_STAGE(ROUTER, OUT, DELIVERY,  1, "lr_out_delivery")

#define PIPELINE_STAGE(DP_TYPE, PIPELINE, STAGE, TABLE, NAME)   \
    S_##DP_TYPE##_##PIPELINE##_##STAGE                          \
        = OVN_STAGE_BUILD(DP_##DP_TYPE, P_##PIPELINE, TABLE),
    PIPELINE_STAGES
#undef PIPELINE_STAGE
};

/* Returns an "enum ovn_stage" built from the arguments. */
static inline enum ovn_stage
ovn_stage_build(enum ovn_datapath_type dp_type, enum ovn_pipeline pipeline,
                uint8_t table)
{
    return OVN_STAGE_BUILD(dp_type, pipeline, table);
}

/* Returns the pipeline to which 'stage' belongs. */
static inline enum ovn_pipeline
ovn_stage_get_pipeline(enum ovn_stage stage)
{
    return (stage >> 8) & 1;
}

/* Returns the table to which 'stage' belongs. */
static inline uint8_t
ovn_stage_get_table(enum ovn_stage stage)
{
    return stage & 0xff;
}

const char *ovn_stage_to_str(enum ovn_stage);
bool ovn_stage_from_string(const char *, enum ovn_stage *);

enum ovn_datapath_type ovn_stage_to_datapath_type(enum ovn_stage);

#endif /* ovn/northd/stages.h */
