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

/* Logical router ingress table 0: Admission control framework. */
for (lr in Logical_Router) {
    /* Logical VLANs not supported.
     * Broadcast/multicast source address is invalid. */
    flow(lr, LR_IN_ADMISSION, 100, vlan.present || eth.src[40]) { drop; };
}

/* Logical router ingress table 0: match (priority 50). */
for (lrp in Logical_Router_Port if lrp.enabled) {
    with (P = lrp.name,
          E = lrp.mac) {
        flow(lrp.lr, LR_IN_ADMISSION, 50,
             inport == "<P>" && (eth.mcast || eth.dst == <E>)) { next; };
    }
}

/* Logical router ingress table 1: IP Input. */
for (lr in Logical_Router) {
    /* L3 admission control: drop multicast and broadcast source, localhost
     * source or destination, and zero network source or destination
     * (priority 100). */
    flow(lr, LR_IN_IP_INPUT, 100,
         (ip4.mcast ||
          ip4.src == 255.255.255.255 ||
          ip4.src == 127.0.0.0/8 ||
          ip4.dst == 127.0.0.0/8 ||
          ip4.src == 0.0.0.0/8 ||
          ip4.dst == 0.0.0.0/8)) { drop; };

    /* ARP reply handling.  Use ARP replies to populate the logical
     * router's ARP table. */
    flow(lr, LR_IN_IP_INPUT, 90, arp.op == 2)
        { put_arp(inport, arp.spa, arp.sha); };

    /* Drop Ethernet local broadcast.  By definition this traffic should
     * not be forwarded. */
    flow(lr, LR_IN_IP_INPUT, 50, eth.bcast) { drop; };

    /* TTL discard.
     *
     * XXX Need to send ICMP time exceeded if !ip.later_frag. */
    flow(lr, LR_IN_IP_INPUT, 30, ip4 && ip.ttl == {0, 1}) { drop; };

    /* ND advertisement handling.  Use advertisements to populate
     * the logical router's ARP/ND table. */
    flow(lr, LR_IN_IP_INPUT, 90, nd_na) { put_nd(inport, nd.target, nd.tll); };

    /* Learn from neighbor solicitations that were not directed at
     * us.  (A priority-90 flow will respond to requests to us and
     * learn the sender's mac address. */
    flow(lr, LR_IN_IP_INPUT, 80, nd_na) { put_nd(inport, ip6.src, nd.sll); };

    /* Pass other traffic not already handled to the next table for
     * routing. */
    flow(lr, LR_IN_IP_INPUT, 0, 1) { next; };
}

/* NAT, Defrag and load balancing in Gateway routers. */
for (lr in Logical_Router) {
    /* Packets are allowed by default. */
    flow(lr, LR_IN_DEFRAG, 0, 1) { next; };
    flow(lr, LR_IN_UNSNAT, 0, 1) { next; };
    flow(lr, LR_OUT_SNAT, 0, 1) { next; };
    flow(lr, LR_IN_DNAT, 0, 1) { next; };
}

for (lr in Logical_Router) {
    flow(lr, LR_IN_ARP_RESOLVE, 0, ip4) { get_arp(outport, reg0); next; };
    flow(lr, LR_IN_ARP_RESOLVE, 0, ip6) { get_nd(outport, xxreg0); next; };
}

/* Local router ingress table 6: ARP request.
 *
 * In the common case where the Ethernet destination has been resolved,
 * this table outputs the packet (priority 0).  Otherwise, it composes
 * and sends an ARP request (priority 100). */
for (lr in Logical_Router) {
    flow(lr, LR_IN_ARP_REQUEST, 100, eth.dst == 00:00:00:00:00:00) {
        arp {
            eth.dst = ff:ff:ff:ff:ff:ff;
            arp.spa = reg1;
            arp.tpa = reg0;
            arp.op = 1;  /* ARP request */
            output;
        };
    };

    flow(lr, LR_IN_ARP_REQUEST, 0, 1) { output; };
}

/* Logical router egress table 1: Delivery (priority 100).
 *
 * Priority 100 rules deliver packets to enabled logical ports. */
for (lrp in Logical_Router_Port if lrp.enabled) {
    with (P = lrp.name) {
        flow(lrp.lr, LR_OUT_DELIVERY, 100, outport == "<P>") { output; };
    }
}
