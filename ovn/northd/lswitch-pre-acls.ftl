/* -*- c -*-
 *
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

/* Ingress and Egress Pre-ACL Table (Priority 0): Packets are
 * allowed by default. */
for (ls in Logical_Switch) {
    flow(ls, LS_IN_PRE_ACL, 0, 1) { next; };
    flow(ls, LS_OUT_PRE_ACL, 0, 1) { next; };
}

/* If there are any stateful ACL rules in this datapath, we must
 * send all IP packets through the conntrack action, which handles
 * defragmentation, in order to match L4 headers. */
for (ls in Logical_Switch if ls.has_stateful_acl) {
    /* Ingress and Egress Pre-ACL Table (Priority 110).
     *
     * Not to do conntrack on ND packets. */
    flow(ls, LS_IN_PRE_ACL, 110, nd) { next; };
    flow(ls, LS_OUT_PRE_ACL, 110, nd) { next; };

    /* Ingress and Egress Pre-ACL Table (Priority 100).
     *
     * Regardless of whether the ACL is "from-lport" or "to-lport",
     * we need rules in both the ingress and egress table, because
     * the return traffic needs to be followed.
     *
     * 'REGBIT_CONNTRACK_DEFRAG' is set to let the pre-stateful table send
     * it to conntrack for tracking and defragmentation. */
    flow(ls, LS_IN_PRE_ACL, 100, ip) { reg0[0] = 1; next; };
    flow(ls, LS_OUT_PRE_ACL, 100, ip) { reg0[0] = 1; next; };
}

/* This ignores L4 port information in the key because fragmented packets may
 * not have L4 information.  The pre-stateful table will send the packet
 * through ct() action to de-fragment.  In stateful table, we will eventually
 * look at L4 information.
 *
 * If multiple load balancers have the same IP address but different L4
 * information, this will generate duplicate logical flows, but that's OK. */
for (lb in Load_Balancer) {
    with (A = lb.ip_addresses) {
        flow(lb.ls, LS_IN_PRE_LB, 100, ip4.dst == <A>) { reg0[0] = 1; next; };
    }
}
for (ls in Logical_Switch) {
    if (ls.load_balancer != []) {
        flow(ls, LS_OUT_PRE_LB, 100, ip4) { reg0[0] = 1; next; };
    }
}
