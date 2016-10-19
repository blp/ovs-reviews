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

/* Ingress and Egress ACL Table (Priority 0): Packets are allowed by
 * default.  A related rule at priority 1 is added below if there
 * are any stateful ACLs in this datapath. */
for (ls in Logical_Switch) {
    flow(ls, LS_IN_ACL, 0, 1) { next; };
    flow(ls, LS_OUT_ACL, 0, 1) { next; };
}

for (ls in Logical_Switch if ls.has_stateful_acl) {
    /* Ingress and Egress ACL Table (Priority 1).
     *
     * By default, traffic is allowed.  This is partially handled by
     * the Priority 0 ACL flows added earlier, but we also need to
     * commit IP flows.  This is because, while the initiater's
     * direction may not have any stateful rules, the server's may
     * and then its return traffic would not have an associated
     * conntrack entry and would return "+invalid".
     *
     * We use "ct_commit" for a connection that is not already known
     * by the connection tracker.  Once a connection is committed,
     * subsequent packets will hit the flow at priority 0 that just
     * uses "next;"
     *
     * We also check for established connections that have ct_label.blocked
     * set on them.  That's a connection that was disallowed, but is
     * now allowed by policy again since it hit this default-allow flow.
     * We need to set ct_label.blocked=0 to let the connection continue,
     * which will be done by ct_commit() in the "stateful" stage.
     * Subsequent packets will hit the flow at priority 0 that just
     * uses "next;". */
    flow(ls, LS_IN_ACL, 1, ip && (!ct.est || (ct.est && ct_label.blocked)))
        { reg0[1] = 1; next; };
    flow(ls, LS_OUT_ACL, 1, ip && (!ct.est || (ct.est && ct_label.blocked)))
        { reg0[1] = 1; next; };

    /* Ingress and Egress ACL Table (Priority 65535).
     *
     * Always drop traffic that's in an invalid state.  Also drop
     * reply direction packets for connections that have been marked
     * for deletion (bit 0 of ct_label is set).
     *
     * This is enforced at a higher priority than ACLs can be defined. */
    flow(ls, LS_IN_ACL, 65535, ct.inv || (ct.est && ct.rpl && ct_label.blocked))
        { drop; };
    flow(ls, LS_OUT_ACL, 65535, ct.inv || (ct.est && ct.rpl && ct_label.blocked))
        { drop; };

    /* Ingress and Egress ACL Table (Priority 65535).
     *
     * Allow reply traffic that is part of an established
     * conntrack entry that has not been marked for deletion
     * (bit 0 of ct_label).  We only match traffic in the
     * reply direction because we want traffic in the request
     * direction to hit the currently defined policy from ACLs.
     *
     * This is enforced at a higher priority than ACLs can be defined. */
    flow(ls, LS_IN_ACL, 65535,
         (ct.est && !ct.rel && !ct.new && !ct.inv
          && ct.rpl && !ct_label.blocked))
        { next; };
    flow(ls, LS_OUT_ACL, 65535,
         (ct.est && !ct.rel && !ct.new && !ct.inv
          && ct.rpl && !ct_label.blocked))
        { next; };

    /* Ingress and Egress ACL Table (Priority 65535).
     *
     * Allow traffic that is related to an existing conntrack entry that
     * has not been marked for deletion (bit 0 of ct_label).
     *
     * This is enforced at a higher priority than ACLs can be defined.
     *
     * NOTE: This does not support related data sessions (eg,
     * a dynamically negotiated FTP data channel), but will allow
     * related traffic such as an ICMP Port Unreachable through
     * that's generated from a non-listening UDP port.  */
    flow(ls, LS_IN_ACL, 65535,
         !ct.est && ct.rel && !ct.new && !ct.inv && !ct_label.blocked)
        { next; };
    flow(ls, LS_OUT_ACL, 65535,
         !ct.est && ct.rel && !ct.new && !ct.inv && !ct_label.blocked)
        { next; };

    /* Ingress and Egress ACL Table (Priority 65535).
     *
     * Not to do conntrack on ND packets. */
    flow(ls, LS_IN_ACL, 65535, nd) { next; };
    flow(ls, LS_OUT_ACL, 65535, nd) { next; };
}
