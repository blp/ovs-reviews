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

include "lswitch-pre-acls.ftl";
include "lswitch-pre-lb.ftl";
include "lswitch-pre-stateful.ftl";
include "lswitch-acls.ftl";
include "lswitch-lb.ftl";
include "lswitch-stateful.ftl";

/* Logical switch ingress table 0: Admission control framework (priority
 * 100). */
for (lsp in Logical_Switch_Port) {
    /* Logical VLANs not supported. */
    flow(lsp.ls, LS_IN_PORT_SEC_L2, 100, vlan.present) { drop; };

    /* Broadcast/multicast source address is invalid. */
    flow(lsp.ls, LS_IN_PORT_SEC_L2, 100, eth.src[40]) { drop; };

    /* Port security flows have priority 50 (see below) and will continue
     * to the next table if packet source is acceptable. */
}

/* Logical switch ingress table 0: Ingress port security - L2
 *  (priority 50).
 *  Ingress table 1: Ingress port security - IP (priority 90 and 80)
 *  Ingress table 2: Ingress port security - ND (priority 90 and 80)
 */
for (lsp in Logical_Switch_Port if lsp.enabled) {
    with (P = lsp.name,
          L2 = lsp.port_security_l2,
          IP = lsp.port_security_ip_ingress,
          ND = lsp.port_security_nd)
    {
        if (lsp.port_security != []) {
            flow(lsp.ls, LS_IN_PORT_SEC_L2, 50, inport == "<P>" && eth.src == <L2>) { next; };
            flow(lsp.ls, LS_IN_PORT_SEC_IP, 90, inport == "<P>" && (<IP>)) {
                next;
            };
            flow(lsp.ls, LS_IN_PORT_SEC_IP, 80, inport == "<P>" && ip && eth.src == <L2>) {
                drop;
            };

            flow(lsp.ls, LS_IN_PORT_SEC_ND, 90, inport == "<P>" && (<ND>)) { next; };
            flow(lsp.ls, LS_IN_PORT_SEC_ND, 80, inport == "<P>" && (arp || nd)) { drop; };
        } else {
            flow(lsp.ls, LS_IN_PORT_SEC_L2, 50, inport == "<P>") { next; };
        }
    }
}

/* Ingress table 1 and 2: Port security - IP and ND, by default goto next.
 * (priority 0). */
for (lsp in Logical_Switch_Port) {
    flow(lsp.ls, LS_IN_PORT_SEC_ND, 0, 1) { next; };
    flow(lsp.ls, LS_IN_PORT_SEC_IP, 0, 1) { next; };
}

/* Ingress table 9: Respond to ARP/ND requests, for ports that are up and for
 * router ports (up or not), but not from localnet ports. */
for (lsp in Logical_Switch_Port) {
    if (lsp.type == "localnet") {
        with (P = lsp.name) {
            flow(lsp.ls, LS_IN_ARP_RSP, 100, inport == "<P>") { next; };
        }
    }
}
for (ls in Logical_Switch) {
    flow(ls, LS_IN_ARP_RSP, 0, 1) { next; };
}
for (lspip in Logical_Switch_Port_IP if lspip.lsp.up) {
    with (E = lspip.mac, A = lspip.ip, P = lspip.lsp.name) {
        if (lspip.ip_version == 4) {
            flow(lspip.lsp.ls, LS_IN_ARP_RSP, 50,
                 arp.tpa == <A> && arp.op == 1) {
                eth.dst = eth.src;
                eth.src = <E>;
                arp.op = 2;     /* ARP reply */
                arp.tha = arp.sha;
                arp.sha = <E>;
                arp.tpa = arp.spa;
                arp.spa = <A>;
                outport = inport;
                flags.loopback = 1;
                output;
            };

            /* Do not reply to an ARP request from the port that owns the
             * address (otherwise a DHCP client that ARPs to check for a
             * duplicate address will fail).  Instead, forward it the usual
             * way.
             *
             * (Another alternative would be to simply drop the packet.  If
             * everything is working as it is configured, then this would
             * produce equivalent results, since no one should reply to the
             * request.  But ARPing for one's own IP address is intended to
             * detect situations where the network is not working as
             * configured, so dropping the request would frustrate that
             * intent.) */
            flow(lspip.lsp.ls, LS_IN_ARP_RSP, 100,
                 arp.tpa == <A> && arp.op == 1 && inport == "<P>") {
                next;
            };
        } else {
            /* For ND solicitations, we need to listen for both the unicast
             * IPv6 address and its all-nodes multicast address, but always
             * respond with the unicast IPv6 address. */
            with (S = lspip.sn_ip) {
                flow(lspip.lsp.ls, LS_IN_ARP_RSP, 50,
                     nd_ns && ip6.dst == {<A>, <S>} && nd.target == <A>) {
                    nd_na {
                        eth.src = <E>;
                        ip6.src = <A>;
                        nd.target = <A>;
                        nd.tll = <E>;
                        outport = inport;
                        flags.loopback = 1;
                        output;
                    };
                };

                /* Do not reply to a solicitation from the port that owns
                 * the address (otherwise DAD detection will fail). */
                flow(lspip.lsp.ls, LS_IN_ARP_RSP, 100,
                     nd_ns && ip6.dst == {<A>, <S>} && nd.target == <A>
                     && inport == "<P>") {
                    next;
                };
            }
        }
    }
}

/* Ingress table 10 and 11: DHCP options and response, by default goto next.
 * (priority 0). */
for (ls in Logical_Switch) {
    flow(ls, LS_IN_DHCP_OPTIONS, 0, 1) { next; };
    flow(ls, LS_IN_DHCP_RESPONSE, 0, 1) { next; };
}
for (lspip in Logical_Switch_Port_IP
     if lspip.lsp.enabled && lspip.lsp.type != "router") {
    with (P = lspip.lsp.name,
          A = lspip.ip,
          E = lspip.mac) {
        if (lspip.ip_version == 4) {
            if (lspip.lsp.dhcpv4_options != []
                /*&& !((lspip.ip ^ lspip.lsp.dhcpv4_options.host)
                  & lspip.lsp.dhcpv4_options.netmask)*/) {
                with (M = lspip.lsp.dhcpv4_options.netmask,
                      O = lspip.lsp.dhcpv4_options.option_args,
                      SM = lspip.lsp.dhcpv4_options.server_mac,
                      SI = lspip.lsp.dhcpv4_options.server_ip) {
                    flow(lspip.lsp.ls, LS_IN_DHCP_OPTIONS, 100,
                         inport == "<P>" && eth.src == <E>
                         && ip4.src == 0.0.0.0 && ip4.dst == 255.255.255.255
                         && udp.src == 68 && udp.dst == 67) {
                        reg0[3] = put_dhcp_opts(offerip = <A>,
                                                netmask = <M>,
                                                <O>); next;
                    };

                    /* If reg0[3] is set, it means the put_dhcp_opts action is
                     * successful. */
                    flow(lspip.lsp.ls, LS_IN_DHCP_RESPONSE, 100,
                         inport == "<P>" && eth.src == <E>
                         && ip4.src == 0.0.0.0 && ip4.dst == 255.255.255.255
                         && udp.src == 68 && udp.dst == 67
                         && reg0[3]) {
                        eth.dst = eth.src;
                        eth.src = <SM>;
                        ip4.dst = <A>;
                        ip4.src = <SI>;
                        udp.src = 67;
                        udp.dst = 68;
                        outport = inport;
                        flags.loopback = 1;
                        output;
                    };
                }
            }
        } else {
            with (O = lspip.lsp.dhcpv6_options.option_args,
                  SM = lspip.lsp.dhcpv6_options.server_mac,
                  SI = lspip.lsp.dhcpv6_options.server_ip) {
                /* Stateful DHCPv6 includes an IP address,
                 * stateless DHCPv6 is options-only. */
                if (lspip.lsp.dhcpv6_options.stateful) {
                    flow(lspip.lsp.ls, LS_IN_DHCP_OPTIONS, 100,
                         inport == "<P>" && eth.src == <E>
                         && ip6.dst == ff02::1:2
                         && udp.src == 546 && udp.dst == 547) {
                        reg0[3] = put_dhcpv6_opts(ia_addr = <A>, <O>);
                        next;
                    };
                } else {
                    flow(lspip.lsp.ls, LS_IN_DHCP_OPTIONS, 100,
                         inport == "<P>" && eth.src == <E>
                         && ip6.dst == ff02::1:2
                         && udp.src == 546 && udp.dst == 547) {
                        reg0[3] = put_dhcpv6_opts(<O>);
                        next;
                    };
                }

                /* If reg0[3] is set, it means the put_dhcpv6_opts action is
                 * successful. */
                flow(lspip.lsp.ls, LS_IN_DHCP_RESPONSE, 100,
                     inport == "<P>" && eth.src == <E>
                     && ip6.dst == ff02::1:2
                     && udp.src == 546 && udp.dst == 547
                     && reg0[3]) {
                    eth.dst = eth.src;
                    eth.src = <SM>;
                    ip6.dst = ip6.src;
                    ip6.src = <SI>;
                    udp.src = 547;
                    udp.dst = 546;
                    outport = inport;
                    flags.loopback = 1;
                    output;
                };
            }
        }
    }
}

/* Ingress table 12: Destination lookup, broadcast and multicast handling
 * (priority 100). */
for (ls in Logical_Switch) {
    flow(ls, LS_IN_L2_LKUP, 100, eth.mcast) {
        outport = "_MC_flood";
        output;
    };
}

/* Ingress table 12: Destination lookup, unicast handling (priority 50), */
for (lsp in Logical_Switch_Port) {
    if (lsp.macs != "") {
        with (P = lsp.name, M = lsp.macs) {
            flow(lsp.ls, LS_IN_L2_LKUP, 50, eth.dst == {<M>}) {
                outport = "<P>";
                output;
            };
        }
    }
}
for (ls in Logical_Switch) {
    flow(ls, LS_IN_L2_LKUP, 0, 1) {
        outport = "_MC_unknown";
        output;
    };
}

/* Egress table 6: Egress port security - IP (priorities 90 and 80)
 * if port security enabled.
 *
 * Egress table 7: Egress port security - L2 (priorities 50 and 150).
 *
 * Priority 50 rules implement port security for enabled logical port.
 *
 * Priority 150 rules drop packets to disabled logical ports: so that they
 * don't even receive multicast or broadcast packets. */
for (lsp in Logical_Switch_Port) {
    with (P = lsp.name,
          L2 = lsp.port_security_l2,
          IP = lsp.port_security_ip_egress)
    {
        if (lsp.port_security != []) {
            flow(lsp.ls, LS_OUT_PORT_SEC_IP, 90,
                 outport == "<P>" && (<IP>)) { next; };
            flow(lsp.ls, LS_OUT_PORT_SEC_IP, 80,
                 outport == "<P>" && ip && eth.dst == <L2>) { drop; };
        }

        if (lsp.enabled) {
            flow(lsp.ls, LS_OUT_PORT_SEC_L2, 50, outport == "<P>" && eth.dst == <L2>) { output; };
        } else {
            flow(lsp.ls, LS_OUT_PORT_SEC_L2, 150, outport == "<P>") { drop; };
        }
    }
}
for (ls in Logical_Switch) {
    flow(ls, LS_OUT_PORT_SEC_IP, 0, 1) { next; };
    flow(ls, LS_OUT_PORT_SEC_L2, 100, eth.mcast) { output; };
}
