/*
 * Copyright (c) 2009, 2013 Nicira, Inc.
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

#ifndef PCAP_FILE_H
#define PCAP_FILE_H 1

#include <stdio.h>
#include "openvswitch/types.h"

struct flow;
struct ofpbuf;

/* PCAP file reading and writing. */
FILE *pcap_open(const char *file_name, const char *mode);
int pcap_read_header(FILE *);
void pcap_write_header(FILE *);
int pcap_read(FILE *, struct ofpbuf **, long long int *when);
void pcap_write(FILE *, struct ofpbuf *);

/* Extracting TCP stream data from an Ethernet packet capture. */

struct tcp_reader *tcp_reader_open(void);
void tcp_reader_close(struct tcp_reader *);
struct ofpbuf *tcp_reader_run(struct tcp_reader *, const struct flow *,
                              const struct ofpbuf *);

struct pcap_tcp {
    FILE *file;
    ovs_be32 hosts[2];
    ovs_be16 ports[2];
    uint32_t seqnos[2];
};

void pcap_tcp_open(struct pcap_tcp *, FILE *,
                   ovs_be32 hosts[2], ovs_be16 ports[2]);
void pcap_tcp_close(struct pcap_tcp *);
void pcap_tcp_send(struct pcap_tcp *, int src, const void *, size_t);

#endif /* pcap-file.h */
