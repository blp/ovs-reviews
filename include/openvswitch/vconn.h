/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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

#ifndef OPENVSWITCH_VCONN_H
#define OPENVSWITCH_VCONN_H 1

/* OpenFlow connections
 * ====================
 *
 * vconn
 * -----
 *
 * A vconn is a connection to an OpenFlow switch or controller.  It abstracts
 * away the underlying network connection, which allows for a variety of
 * transports (TCP, SSL, Unix domain sockets, ...).
 *
 * A vconn maintains a message transmission queue.  The caller can ensure that
 * the queue length is bounded by using a "vconn_packet_counter" (see below) to
 * count the number of untransmitted messages of appropriate types.  The vconn
 * does not guarantee reliable delivery of queued messages: if a connection
 * drops, then there is no inherent way to determine whether a queued message
 * was received by the peer.
 *
 * (The "v" in "vconn" stands for "vswitch" or "virtual".)
 *
 *
 * pvconn
 * ------
 *
 * A pvconn listens for incoming OpenFlow connections, abstracting away the
 * underlying transport.
 *
 *
 * vconn_packet_counter
 * --------------------
 *
 * A vconn packet counter can count packets queued for tranmission on a vconn,
 * allowing the vconn's client to bound the number of queued messages.  The
 * client should allocate one vconn_packet_counter for each category of message
 * that the client wants to account separately.  For example, it might be
 * desirable to keep track of asynchronously generated OpenFlow messages
 * separately from those sent as replies to requests, and if so then each
 * category would have its own vconn_packet_counter.
 *
 * To account a particular message to a vconn_packet_counter, pass the counter
 * to vconn_send() or vconn_send_with_limit() at transmission time.  The
 * message will then be counted in the vconn_packet_counter's packet and byte
 * counts.  Subsequently, when the message passes from the vconn queue into the
 * network, the message will be removed from its vconn_packet_counter's packet
 * and byte counts.  If message transmission happens immediately, as commonly
 * happens, the increase and later decrease in the vconn_packet_counter's
 * counts may not be visible to the client.
 *
 *
 * Thread-safety
 * =============
 *
 * The vconn and pvconn functions are conditionally thread-safe: they may be
 * called from different threads only on different vconn (or pvconn) objects.
 *
 * The vconn_packet_counter functions are fully thread safe, in the sense that
 * calling them from arbitrary threads on arbitrary objects will yield correct,
 * linearizable results.  However, a common use case for vconn_packet_counter
 * would be to wake up to send more messages when the counter decreases to some
 * level (such as zero).  This isn't possible in a race-free way when different
 * threads call vconn_run() and vconn_packet_counter_n_packets(), since calling
 * the former can decrease vconn_packet_counter counters.  The current source
 * tree doesn't try this kind of thing.
 */

#include <stdbool.h>
#include <openvswitch/list.h>
#include <openvswitch/types.h>
#include <openflow/openflow.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ofpbuf;
struct pvconn;
struct pvconn_class;
struct vconn;
struct vconn_class;
struct vconn_packet_counter;

void vconn_usage(bool active, bool passive, bool bootstrap);

/* Active vconns: virtual connections to OpenFlow devices. */
int vconn_verify_name(const char *name);
int vconn_open(const char *name, uint32_t allowed_versions, uint8_t dscp,
               struct vconn **vconnp);
void vconn_close(struct vconn *);
const char *vconn_get_name(const struct vconn *);

uint32_t vconn_get_allowed_versions(const struct vconn *);
void vconn_set_allowed_versions(struct vconn *, uint32_t allowed_versions);
int vconn_get_version(const struct vconn *);
void vconn_set_recv_any_version(struct vconn *);

int vconn_connect(struct vconn *);
int vconn_recv(struct vconn *, struct ofpbuf **);
int vconn_send(struct vconn *, struct ofpbuf *, struct vconn_packet_counter *);
int vconn_send_with_limit(struct vconn *, struct ofpbuf *,
                          struct vconn_packet_counter *, int queue_limit);

int vconn_recv_xid(struct vconn *, ovs_be32 xid, struct ofpbuf **);
int vconn_transact(struct vconn *, struct ofpbuf *, struct ofpbuf **);
int vconn_transact_noreply(struct vconn *, struct ofpbuf *, struct ofpbuf **);
int vconn_transact_multiple_noreply(struct vconn *, struct ovs_list *requests,
                                    struct ofpbuf **replyp);
int vconn_bundle_transact(struct vconn *, struct ovs_list *requests,
                          uint16_t bundle_flags,
                          void (*error_reporter)(const struct ofp_header *));

void vconn_run(struct vconn *);
void vconn_run_wait(struct vconn *);

int vconn_get_status(const struct vconn *);
unsigned int vconn_count_txqlen(const struct vconn *);
time_t vconn_get_last_activity(const struct vconn *);

int vconn_open_block(const char *name, uint32_t allowed_versions, uint8_t dscp,
                     struct vconn **);
int vconn_connect_block(struct vconn *);
int vconn_send_block(struct vconn *, struct ofpbuf *);
int vconn_recv_block(struct vconn *, struct ofpbuf **);

enum vconn_wait_type {
    WAIT_CONNECT,
    WAIT_RECV,
    WAIT_SEND
};
void vconn_wait(struct vconn *, enum vconn_wait_type);
void vconn_connect_wait(struct vconn *);
void vconn_recv_wait(struct vconn *);
void vconn_send_wait(struct vconn *);

/* Passive vconns: virtual listeners for incoming OpenFlow connections. */
int pvconn_verify_name(const char *name);
int pvconn_open(const char *name, uint32_t allowed_versions, uint8_t dscp,
                struct pvconn **pvconnp);
const char *pvconn_get_name(const struct pvconn *);
void pvconn_close(struct pvconn *);
int pvconn_accept(struct pvconn *, struct vconn **);
void pvconn_wait(struct pvconn *);

/* Packet counters. */
struct vconn_packet_counter *vconn_packet_counter_create(void);
void vconn_packet_counter_destroy(struct vconn_packet_counter *);

unsigned int vconn_packet_counter_n_packets(
    const struct vconn_packet_counter *);
unsigned int vconn_packet_counter_n_bytes(const struct vconn_packet_counter *);

#ifdef __cplusplus
}
#endif

#endif /* vconn.h */
