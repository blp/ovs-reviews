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

for (ls in Logical_Switch) {
    /* Ingress and Egress stateful Table (Priority 0): Packets are
     * allowed by default. */
    flow(ls, LS_IN_STATEFUL, 0, 1) { next; };
    flow(ls, LS_OUT_STATEFUL, 0, 1) { next; };

    /* If REGBIT_CONNTRACK_COMMIT is set as 1, then the packets should be
     * committed to conntrack. We always set ct_label.blocked to 0 here as
     * any packet that makes it this far is part of a connection we
     * want to allow to continue. */
    flow(ls, LS_IN_STATEFUL, 100, reg0[1] == 1) {
        ct_commit(ct_label=0/1);
        next;
    };
    flow(ls, LS_OUT_STATEFUL, 100, reg0[1] == 1) {
        ct_commit(ct_label=0/1);
        next;
    };

    /* If REGBIT_CONNTRACK_NAT is set as 1, then packets should just be sent
     * through nat (without committing).
     *
     * reg0[1] is set for new connections and
     * REGBIT_CONNTRACK_NAT is set for established connections. So they
     * don't overlap.
     */
    flow(ls, LS_IN_STATEFUL, 100, reg0[2] == 1) { ct_lb; };
    flow(ls, LS_OUT_STATEFUL, 100, reg0[2] == 1) { ct_lb; };
}
