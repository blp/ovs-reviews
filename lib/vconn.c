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

#include <config.h>
#include "vconn-provider.h"
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include "coverage.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "flow.h"
#include "ofp-errors.h"
#include "ofp-msgs.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"
#include "socket-util.h"

VLOG_DEFINE_THIS_MODULE(vconn);

COVERAGE_DEFINE(vconn_open);
COVERAGE_DEFINE(vconn_received);
COVERAGE_DEFINE(vconn_sent);
COVERAGE_DEFINE(vconn_discarded);
COVERAGE_DEFINE(vconn_overflow);

/* Counts packets and bytes queued into an vconn by a given source. */
struct vconn_packet_counter {
    struct ovs_mutex mutex;
    unsigned int n_packets OVS_GUARDED; /* Number of packets queued. */
    unsigned int n_bytes OVS_GUARDED;   /* Number of bytes queued. */
    int ref_cnt OVS_GUARDED;            /* Number of owners. */
};

static void vconn_packet_counter_inc(struct vconn_packet_counter *,
                                     unsigned int n_bytes);
static void vconn_packet_counter_dec(struct vconn_packet_counter *,
                                     unsigned int n_bytes);

static const struct vconn_class *vconn_classes[] = {
    &tcp_vconn_class,
    &unix_vconn_class,
#ifdef HAVE_OPENSSL
    &ssl_vconn_class,
#endif
};

static const struct pvconn_class *pvconn_classes[] = {
    &ptcp_pvconn_class,
    &punix_pvconn_class,
#ifdef HAVE_OPENSSL
    &pssl_pvconn_class,
#endif
};

/* Rate limit for individual OpenFlow messages going over the vconn, output at
 * DBG level.  This is very high because, if these are enabled, it is because
 * we really need to see them. */
static struct vlog_rate_limit ofmsg_rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Rate limit for OpenFlow message parse errors.  These always indicate a bug
 * in the peer and so there's not much point in showing a lot of them. */
static struct vlog_rate_limit bad_ofmsg_rl = VLOG_RATE_LIMIT_INIT(1, 5);

static int do_recv(struct vconn *, struct ofpbuf **);
static void vconn_send__(struct vconn *, struct ofpbuf *,
                         struct vconn_packet_counter *);
static int vconn_run_tx__(struct vconn *);
static void vconn_run_tx(struct vconn *);
static void vconn_flush_tx(struct vconn *);
static void vconn_record_error(struct vconn *, int error);

/* Check the validity of the vconn class structures. */
static void
check_vconn_classes(void)
{
#ifndef NDEBUG
    size_t i;

    for (i = 0; i < ARRAY_SIZE(vconn_classes); i++) {
        const struct vconn_class *class = vconn_classes[i];
        ovs_assert(class->name != NULL);
        ovs_assert(class->open != NULL);
        if (class->close || class->recv || class->send
            || class->run || class->run_wait || class->wait) {
            ovs_assert(class->close != NULL);
            ovs_assert(class->recv != NULL);
            ovs_assert(class->send != NULL);
            ovs_assert(class->wait != NULL);
        } else {
            /* This class delegates to another one. */
        }
    }

    for (i = 0; i < ARRAY_SIZE(pvconn_classes); i++) {
        const struct pvconn_class *class = pvconn_classes[i];
        ovs_assert(class->name != NULL);
        ovs_assert(class->listen != NULL);
        if (class->close || class->accept || class->wait) {
            ovs_assert(class->close != NULL);
            ovs_assert(class->accept != NULL);
            ovs_assert(class->wait != NULL);
        } else {
            /* This class delegates to another one. */
        }
    }
#endif
}

/* Prints information on active (if 'active') and passive (if 'passive')
 * connection methods supported by the vconn.  If 'bootstrap' is true, also
 * advertises options to bootstrap the CA certificate. */
void
vconn_usage(bool active, bool passive, bool bootstrap OVS_UNUSED)
{
    /* Really this should be implemented via callbacks into the vconn
     * providers, but that seems too heavy-weight to bother with at the
     * moment. */

    printf("\n");
    if (active) {
        printf("Active OpenFlow connection methods:\n");
        printf("  tcp:IP[:PORT]           "
               "PORT (default: %d) at remote IP\n", OFP_PORT);
#ifdef HAVE_OPENSSL
        printf("  ssl:IP[:PORT]           "
               "SSL PORT (default: %d) at remote IP\n", OFP_PORT);
#endif
        printf("  unix:FILE               Unix domain socket named FILE\n");
    }

    if (passive) {
        printf("Passive OpenFlow connection methods:\n");
        printf("  ptcp:[PORT][:IP]        "
               "listen to TCP PORT (default: %d) on IP\n",
               OFP_PORT);
#ifdef HAVE_OPENSSL
        printf("  pssl:[PORT][:IP]        "
               "listen for SSL on PORT (default: %d) on IP\n",
               OFP_PORT);
#endif
        printf("  punix:FILE              "
               "listen on Unix domain socket FILE\n");
    }

#ifdef HAVE_OPENSSL
    printf("PKI configuration (required to use SSL):\n"
           "  -p, --private-key=FILE  file with private key\n"
           "  -c, --certificate=FILE  file with certificate for private key\n"
           "  -C, --ca-cert=FILE      file with peer CA certificate\n");
    if (bootstrap) {
        printf("  --bootstrap-ca-cert=FILE  file with peer CA certificate "
               "to read or create\n");
    }
#endif
}

/* Given 'name', a connection name in the form "TYPE:ARGS", stores the class
 * named "TYPE" into '*classp' and returns 0.  Returns EAFNOSUPPORT and stores
 * a null pointer into '*classp' if 'name' is in the wrong form or if no such
 * class exists. */
static int
vconn_lookup_class(const char *name, const struct vconn_class **classp)
{
    size_t prefix_len;

    prefix_len = strcspn(name, ":");
    if (name[prefix_len] != '\0') {
        size_t i;

        for (i = 0; i < ARRAY_SIZE(vconn_classes); i++) {
            const struct vconn_class *class = vconn_classes[i];
            if (strlen(class->name) == prefix_len
                && !memcmp(class->name, name, prefix_len)) {
                *classp = class;
                return 0;
            }
        }
    }

    *classp = NULL;
    return EAFNOSUPPORT;
}

/* Returns 0 if 'name' is a connection name in the form "TYPE:ARGS" and TYPE is
 * a supported connection type, otherwise EAFNOSUPPORT.  */
int
vconn_verify_name(const char *name)
{
    const struct vconn_class *class;
    return vconn_lookup_class(name, &class);
}

/* Attempts to connect to an OpenFlow device.  'name' is a connection name in
 * the form "TYPE:ARGS", where TYPE is an active vconn class's name and ARGS
 * are vconn class-specific.
 *
 * The vconn will automatically negotiate an OpenFlow protocol version
 * acceptable to both peers on the connection.  The version negotiated will be
 * one of those in the 'allowed_versions' bitmap: version 'x' is allowed if
 * allowed_versions & (1 << x) is nonzero.  If 'allowed_versions' is zero, then
 * OFPUTIL_DEFAULT_VERSIONS are allowed.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * stores a pointer to the new connection in '*vconnp', otherwise a null
 * pointer.  */
int
vconn_open(const char *name, uint32_t allowed_versions, uint8_t dscp,
           struct vconn **vconnp)
{
    const struct vconn_class *class;
    struct vconn *vconn;
    char *suffix_copy;
    int error;

    COVERAGE_INC(vconn_open);
    check_vconn_classes();

    if (!allowed_versions) {
        allowed_versions = OFPUTIL_DEFAULT_VERSIONS;
    }

    /* Look up the class. */
    error = vconn_lookup_class(name, &class);
    if (!class) {
        goto error;
    }

    /* Call class's "open" function. */
    suffix_copy = xstrdup(strchr(name, ':') + 1);
    error = class->open(name, allowed_versions, suffix_copy, &vconn, dscp);
    free(suffix_copy);
    if (error) {
        goto error;
    }

    /* Success. */
    ovs_assert(vconn->state != VCS_CONNECTING || vconn->vclass->connect);
    *vconnp = vconn;
    return 0;

error:
    *vconnp = NULL;
    return error;
}

/* Allows 'vconn' to perform maintenance activities, such as flushing output
 * buffers. */
void
vconn_run(struct vconn *vconn)
{
    switch (vconn->state) {
    case VCS_CONNECTING:
    case VCS_SEND_HELLO:
    case VCS_RECV_HELLO:
        vconn_connect(vconn);
        break;

    case VCS_CONNECTED:
        if (vconn->probe_interval) {
            time_t now = time_now();
            time_t idle = now - vconn->last_activity;
            if (idle >= vconn->probe_interval) {
                VLOG_DBG("%s: idle %u seconds, sending inactivity probe",
                         vconn->name, (unsigned int) idle);
                vconn->probe_time = now;

                /* The order is important: if vconn_send__() transitions to
                 * VCS_DISCONNECTED, we don't want to transition back to
                 * VCS_IDLE. */
                vconn->state = VCS_IDLE;
                vconn_send__(vconn, make_echo_request(vconn->version), NULL);
            }
        }
        break;

    case VCS_IDLE:
        if (time_now() >= vconn->probe_time + vconn->probe_interval) {
            VLOG_ERR("%s: no response to inactivity probe after %u "
                     "seconds, disconnecting", vconn->name,
                     (unsigned int) (time_now() - vconn->probe_time));
            vconn_record_error(vconn, ETIMEDOUT);
        }
        break;

    case VCS_SEND_ERROR:
    case VCS_DISCONNECTED:
        break;
    }

    if (vconn->vclass->run) {
        (vconn->vclass->run)(vconn);
    }

    vconn_run_tx(vconn);
}

/* Arranges for the poll loop to wake up when 'vconn' needs to perform
 * maintenance activities. */
void
vconn_run_wait(struct vconn *vconn)
{
    if (vconn->state == VCS_CONNECTING ||
        vconn->state == VCS_SEND_HELLO ||
        vconn->state == VCS_RECV_HELLO) {
        vconn_connect_wait(vconn);
    }

    if (vconn->vclass->run_wait) {
        (vconn->vclass->run_wait)(vconn);
    }
}

/* Returns 0 if 'vconn' is healthy (connecting or connected), a positive errno
 * value if the connection died abnormally (connection failed or aborted), or
 * EOF if the connection was closed in a normal way. */
int
vconn_get_status(const struct vconn *vconn)
{
    return vconn->error == EAGAIN ? 0 : vconn->error;
}

unsigned int
vconn_count_txqlen(const struct vconn *vconn)
{
    return list_size(&vconn->txq);
}

int
vconn_open_block(const char *name, uint32_t allowed_versions, uint8_t dscp,
                 struct vconn **vconnp)
{
    struct vconn *vconn;
    int error;

    fatal_signal_run();

    error = vconn_open(name, allowed_versions, dscp, &vconn);
    if (!error) {
        error = vconn_connect_block(vconn);
    }

    if (error) {
        vconn_close(vconn);
        *vconnp = NULL;
    } else {
        *vconnp = vconn;
    }
    return error;
}

/* Closes 'vconn'. */
void
vconn_close(struct vconn *vconn)
{
    if (vconn != NULL) {
        vconn_flush_tx(vconn);

        char *name = vconn->name;
        (vconn->vclass->close)(vconn);
        free(name);
    }
}

/* Returns the name of 'vconn', that is, the string passed to vconn_open(). */
const char *
vconn_get_name(const struct vconn *vconn)
{
    return vconn->name;
}

/* Returns the allowed_versions of 'vconn', that is,
 * the allowed_versions passed to vconn_open(). */
uint32_t
vconn_get_allowed_versions(const struct vconn *vconn)
{
    return vconn->allowed_versions;
}

/* Sets the allowed_versions of 'vconn', overriding
 * the allowed_versions passed to vconn_open(). */
void
vconn_set_allowed_versions(struct vconn *vconn, uint32_t allowed_versions)
{
    vconn->allowed_versions = allowed_versions;
}

/* Returns the OpenFlow version negotiated with the peer, or -1 if version
 * negotiation is not yet complete.
 *
 * A vconn that has successfully connected (that is, vconn_connect() or
 * vconn_send() or vconn_recv() has returned 0) always negotiated a version. */
int
vconn_get_version(const struct vconn *vconn)
{
    return vconn->version ? vconn->version : -1;
}

/* By default, a vconn accepts only OpenFlow messages whose version matches the
 * one negotiated for the connection.  A message received with a different
 * version is an error that causes the vconn to drop the connection.
 *
 * This functions allows 'vconn' to accept messages with any OpenFlow version.
 * This is useful in the special case where 'vconn' is used as an vconn
 * "monitor" connection (see vconn_add_monitor()), that is, where 'vconn' is
 * used as a target for mirroring OpenFlow messages for debugging and
 * troubleshooting.
 *
 * This function should be called after a successful vconn_open() or
 * pvconn_accept() but before the connection completes, that is, before
 * vconn_connect() returns success.  Otherwise, messages that arrive on 'vconn'
 * beforehand with an unexpected version will the vconn to drop the
 * connection. */
void
vconn_set_recv_any_version(struct vconn *vconn)
{
    vconn->recv_any_version = true;
}

/* Configures the "probe interval", used for detecting an OpenFlow session that
 * has been disconnected, to 'probe_interval' seconds.  A 'probe_interval' of 0
 * disables connection probing.
 *
 * See the large comment at the top of vconn.h for more information on
 * connection probing. */
void
vconn_set_probe_interval(struct vconn *vconn, int probe_interval)
{
    vconn->probe_interval = probe_interval ? MAX(5, probe_interval) : 0;
}

/* Returns the probe interval, in seconds.  An interval of 0 indicates that
 * connection probing is disabled. */
int
vconn_get_probe_interval(const struct vconn *vconn)
{
    return vconn->probe_interval;
}

static void
vcs_connecting(struct vconn *vconn)
{
    int retval = (vconn->vclass->connect)(vconn);
    ovs_assert(retval != EINPROGRESS);
    if (!retval) {
        vconn->state = VCS_SEND_HELLO;
    } else {
        vconn_record_error(vconn, retval);
    }
}

static void
vcs_send_hello(struct vconn *vconn)
{
    vconn_send__(vconn, ofputil_encode_hello(vconn->allowed_versions), NULL);
    vconn->state = VCS_RECV_HELLO;
}

static char *
version_bitmap_to_string(uint32_t bitmap)
{
    struct ds s;

    ds_init(&s);
    if (!bitmap) {
        ds_put_cstr(&s, "no versions");
    } else if (is_pow2(bitmap)) {
        ds_put_cstr(&s, "version ");
        ofputil_format_version(&s, leftmost_1bit_idx(bitmap));
    } else if (is_pow2((bitmap >> 1) + 1)) {
        ds_put_cstr(&s, "version ");
        ofputil_format_version(&s, leftmost_1bit_idx(bitmap));
        ds_put_cstr(&s, " and earlier");
    } else {
        ds_put_cstr(&s, "versions ");
        ofputil_format_version_bitmap(&s, bitmap);
    }
    return ds_steal_cstr(&s);
}

static void
vcs_recv_hello(struct vconn *vconn)
{
    struct ofpbuf *b;
    int retval;

    retval = do_recv(vconn, &b);
    if (!retval) {
        enum ofptype type;
        enum ofperr error;

        error = ofptype_decode(&type, b->data);
        if (!error && type == OFPTYPE_HELLO) {
            char *peer_s, *local_s;
            uint32_t common_versions;

            if (!ofputil_decode_hello(b->data, &vconn->peer_versions)) {
                struct ds msg = DS_EMPTY_INITIALIZER;
                ds_put_format(&msg, "%s: unknown data in hello:\n",
                              vconn->name);
                ds_put_hex_dump(&msg, b->data, b->size, 0, true);
                VLOG_WARN_RL(&bad_ofmsg_rl, "%s", ds_cstr(&msg));
                ds_destroy(&msg);
            }

            local_s = version_bitmap_to_string(vconn->allowed_versions);
            peer_s = version_bitmap_to_string(vconn->peer_versions);

            common_versions = vconn->peer_versions & vconn->allowed_versions;
            if (!common_versions) {
                vconn->version = leftmost_1bit_idx(vconn->peer_versions);
                VLOG_WARN_RL(&bad_ofmsg_rl,
                             "%s: version negotiation failed (we support "
                             "%s, peer supports %s)",
                             vconn->name, local_s, peer_s);
                vconn->state = VCS_SEND_ERROR;
            } else {
                vconn->version = leftmost_1bit_idx(common_versions);
                VLOG_DBG("%s: negotiated OpenFlow version 0x%02x "
                         "(we support %s, peer supports %s)", vconn->name,
                         vconn->version, local_s, peer_s);
                vconn->state = VCS_CONNECTED;
            }

            free(local_s);
            free(peer_s);

            ofpbuf_delete(b);
            return;
        } else {
            char *s = ofp_to_string(b->data, b->size, 1);
            VLOG_WARN_RL(&bad_ofmsg_rl,
                         "%s: received message while expecting hello: %s",
                         vconn->name, s);
            free(s);
            retval = EPROTO;
            ofpbuf_delete(b);
        }
    }

    vconn_record_error(vconn, retval == EOF ? ECONNRESET : retval);
}

static void
vcs_send_error(struct vconn *vconn)
{
    char s[128];
    char *local_s, *peer_s;

    local_s = version_bitmap_to_string(vconn->allowed_versions);
    peer_s = version_bitmap_to_string(vconn->peer_versions);
    snprintf(s, sizeof s, "We support %s, you support %s, no common versions.",
             local_s, peer_s);
    free(peer_s);
    free(local_s);

    vconn_send__(vconn, ofperr_encode_hello(OFPERR_OFPHFC_INCOMPATIBLE,
                                            vconn->version, s), NULL);
    /* XXX this won't wait for the txq to empty */
    vconn_record_error(vconn, EPROTO);
}

/* Tries to complete the connection on 'vconn'. If 'vconn''s connection is
 * complete, returns 0 if the connection was successful or a positive errno
 * value if it failed.  If the connection is still in progress, returns
 * EAGAIN. */
int
vconn_connect(struct vconn *vconn)
{
    enum vconn_state last_state;

    do {
        last_state = vconn->state;
        switch (vconn->state) {
        case VCS_CONNECTING:
            vcs_connecting(vconn);
            break;

        case VCS_SEND_HELLO:
            vcs_send_hello(vconn);
            break;

        case VCS_RECV_HELLO:
            vcs_recv_hello(vconn);
            break;

        case VCS_CONNECTED:
        case VCS_IDLE:
            return 0;

        case VCS_SEND_ERROR:
            vcs_send_error(vconn);
            break;

        case VCS_DISCONNECTED:
            return vconn->error;

        default:
            OVS_NOT_REACHED();
        }
    } while (vconn->state != last_state);

    return EAGAIN;
}

static int
check_msg_version(struct vconn *vconn, const struct ofpbuf *msg)
{
    /* It's OK if 'msg' has the expected version. */
    const struct ofp_header *oh = msg->data;
    if (oh->version == vconn->version) {
        return 0;
    }

    /* It's OK if 'vconn' can receive any version of OpenFlow. */
    if (vconn->recv_any_version) {
        return 0;
    }

    /* It's OK if 'msg' is one of the special invariant messages. */
    enum ofptype type;
    if (!ofptype_decode(&type, oh)
        && (type == OFPTYPE_HELLO ||
            type == OFPTYPE_ERROR ||
            type == OFPTYPE_ECHO_REQUEST ||
            type == OFPTYPE_ECHO_REPLY)) {
        return 0;
    }

    /* Not OK.  Log it and send an error reply. */
    VLOG_ERR_RL(&bad_ofmsg_rl, "%s: received OpenFlow version "
                "0x%02"PRIx8" != expected %02x",
                vconn->name, oh->version, vconn->version);
    vconn_send__(vconn, ofperr_encode_reply(OFPERR_OFPBRC_BAD_VERSION, oh),
                 NULL);
    return EAGAIN;
}

static void
vconn_record_error(struct vconn *vconn, int error)
{
    if (error != EAGAIN && vconn->state != VCS_DISCONNECTED) {
        /* On Windows, when a peer terminates without calling a closesocket()
         * on socket fd, we get WSAECONNRESET. Don't print warning messages for
         * that case. */
        if (error == EOF
#ifdef _WIN32
            || error == WSAECONNRESET
#endif
            ) {
            VLOG_DBG("%s: connection closed by peer", vconn->name);
        } else {
            VLOG_WARN("%s: connection dropped (%s)", vconn->name,
                      ovs_strerror(error));
        }

        vconn->state = VCS_DISCONNECTED;
        vconn->error = error;
    }
}

/* Tries to receive an OpenFlow message from 'vconn'.  If successful, stores
 * the received message into '*msgp' and returns 0.  The caller is responsible
 * for destroying the message with ofpbuf_delete().  On failure, returns a
 * positive errno value and stores a null pointer into '*msgp'.  On normal
 * connection close, returns EOF.
 *
 * vconn_recv will not block waiting for a packet to arrive.  If no packets
 * have been received, it returns EAGAIN immediately. */
int
vconn_recv(struct vconn *vconn, struct ofpbuf **msgp)
{
    int retval;

    retval = vconn_connect(vconn);
    if (!retval) {
        struct ofpbuf *msg;

        retval = do_recv(vconn, &msg);
        if (!retval) {
            retval = check_msg_version(vconn, msg);
            if (!retval) {
                *msgp = msg;
                return 0;
            }
            ofpbuf_delete(msg);
        }
    }

    vconn_record_error(vconn, retval);
    *msgp = NULL;
    return retval;
}

static int
do_recv(struct vconn *vconn, struct ofpbuf **msgp)
{
    int retval = (vconn->vclass->recv)(vconn, msgp);
    if (!retval) {
        COVERAGE_INC(vconn_received);
        if (VLOG_IS_DBG_ENABLED()) {
            char *s = ofp_to_string((*msgp)->data, (*msgp)->size, 1);
            VLOG_DBG_RL(&ofmsg_rl, "%s: received: %s", vconn->name, s);
            free(s);
        }
        if (vconn->state == VCS_IDLE) {
            vconn->state = VCS_CONNECTED;
        }
        vconn->last_activity = time_now();
    }
    return retval;
}

static void
vconn_send__(struct vconn *vconn, struct ofpbuf *msg,
             struct vconn_packet_counter *counter)
{
    ofpmsg_update_length(msg);

    /* Add to counter, if any.
     *
     * This reuses 'msg->header' as a private pointer while 'msg' is in the
     * txq. */
    if (counter) {
        vconn_packet_counter_inc(counter, msg->size);
    }
    msg->header = counter;

    list_push_back(&vconn->txq, &msg->list_node);

    /* If the queue was empty before we added 'msg', try to send some
     * packets.  (But if the queue had packets in it, it's because the
     * vconn is backlogged and there's no point in stuffing more into it
     * now.  We'll get back to that in vconn_run().) */
    if (vconn->txq.next == &msg->list_node) {
        vconn_run_tx__(vconn);
    }
}

/* Queues 'msg' for transmission on 'vconn'.  Increments 'counter', if nonnull,
 * while the packet is in flight, and decrements again when it has been sent
 * (or discarded due to disconnection).  Returns 0 if successful, otherwise a
 * positive errno value.  Either way, 'vconn' takes ownership of 'msg'.
 *
 * This function does not inherently limit the size of the queue maintained for
 * 'vconn', so the caller must use it carefully to avoid using an arbitrary
 * amount of memory.
 *
 * Because 'msg' may be sent (or discarded) before this function returns, the
 * caller may not be able to observe any change in 'counter'. */
int
vconn_send(struct vconn *vconn, struct ofpbuf *msg,
           struct vconn_packet_counter *counter)
{
    ovs_assert(msg->size >= sizeof(struct ofp_header));

    int error = vconn_connect(vconn);
    if (!error) {
        vconn_send__(vconn, msg, counter);
        return 0;
    } else {
        ofpbuf_delete(msg);
        return ENOTCONN;
    }
}

/* Like vconn_send(), but returns EAGAIN (and deletes 'msg') if 'counter' is
 * already at 'queue_limit' or more packets. */
int
vconn_send_with_limit(struct vconn *rc, struct ofpbuf *msg,
                      struct vconn_packet_counter *counter, int queue_limit)
{
    if (vconn_packet_counter_n_packets(counter) < queue_limit) {
        vconn_send__(rc, msg, counter);
        return 0;
    } else {
        COVERAGE_INC(vconn_overflow);
        ofpbuf_delete(msg);
        return EAGAIN;
    }
}

static int
vconn_run_tx__(struct vconn *vconn)
{
    struct ofpbuf *msg = ofpbuf_from_list(list_pop_front(&vconn->txq));
    unsigned int n_bytes = msg->size;
    struct vconn_packet_counter *counter = msg->header;

    /* Eagerly remove 'msg' from the txq.  We can't remove it from the list
     * after sending, if sending is successful, because it is then owned by the
     * vconn, which might have freed it already. */
    list_remove(&msg->list_node);
    msg->header = NULL;

    int error;
    if (!VLOG_IS_DBG_ENABLED()) {
        COVERAGE_INC(vconn_sent);
        error = (vconn->vclass->send)(vconn, msg);
    } else {
        char *s = ofp_to_string(msg->data, msg->size, 1);
        error = (vconn->vclass->send)(vconn, msg);
        if (error != EAGAIN) {
            VLOG_DBG_RL(&ofmsg_rl, "%s: sent (%s): %s",
                        vconn->name, ovs_strerror(error), s);
        }
        free(s);
    }

    if (error) {
        msg->header = counter;
        list_push_front(&vconn->txq, &msg->list_node);
        vconn_record_error(vconn, error);
        return error;
    }

    COVERAGE_INC(vconn_sent);
    if (counter) {
        vconn_packet_counter_dec(counter, n_bytes);
    }
    return 0;
}

static void
vconn_run_tx(struct vconn *vconn)
{
    while (!list_is_empty(&vconn->txq)) {
        int error = vconn_run_tx__(vconn);
        if (error) {
            break;
        }
        vconn->last_activity = time_now();
    }
}

/* Drops all the packets from 'rc''s send queue and decrements their queue
 * counts. */
static void
vconn_flush_tx(struct vconn *vconn)
{
    while (!list_is_empty(&vconn->txq)) {
        struct ofpbuf *b = ofpbuf_from_list(list_pop_front(&vconn->txq));
        struct vconn_packet_counter *counter = b->header;
        if (counter) {
            vconn_packet_counter_dec(counter, b->size);
        }
        COVERAGE_INC(vconn_discarded);
        ofpbuf_delete(b);
    }
}

/* Same as vconn_connect(), except that it waits until the connection on
 * 'vconn' completes or fails.  Thus, it will never return EAGAIN. */
int
vconn_connect_block(struct vconn *vconn)
{
    int error;

    while ((error = vconn_connect(vconn)) == EAGAIN) {
        vconn_run(vconn);
        vconn_run_wait(vconn);
        vconn_connect_wait(vconn);
        poll_block();
    }
    ovs_assert(error != EINPROGRESS);

    return error;
}

/* Same as vconn_send, except that it waits until 'msg' can be transmitted. */
int
vconn_send_block(struct vconn *vconn, struct ofpbuf *msg)
{
    int retval;

    fatal_signal_run();

    while ((retval = vconn_send(vconn, msg, NULL)) == EAGAIN) {
        vconn_run(vconn);
        vconn_run_wait(vconn);
        vconn_send_wait(vconn);
        poll_block();
    }
    return retval;
}

/* Same as vconn_recv, except that it waits until a message is received. */
int
vconn_recv_block(struct vconn *vconn, struct ofpbuf **msgp)
{
    int retval;

    fatal_signal_run();

    while ((retval = vconn_recv(vconn, msgp)) == EAGAIN) {
        vconn_run(vconn);
        vconn_run_wait(vconn);
        vconn_recv_wait(vconn);
        poll_block();
    }
    return retval;
}

static int
vconn_recv_xid__(struct vconn *vconn, ovs_be32 xid, struct ofpbuf **replyp,
                 void (*error_reporter)(const struct ofp_header *))
{
    for (;;) {
        ovs_be32 recv_xid;
        struct ofpbuf *reply;
        const struct ofp_header *oh;
        enum ofptype type;
        int error;

        error = vconn_recv_block(vconn, &reply);
        if (error) {
            *replyp = NULL;
            return error;
        }
        oh = reply->data;
        recv_xid = oh->xid;
        if (xid == recv_xid) {
            *replyp = reply;
            return 0;
        }

        error = ofptype_decode(&type, oh);
        if (!error && type == OFPTYPE_ERROR && error_reporter) {
            error_reporter(oh);
        } else {
            VLOG_DBG_RL(&bad_ofmsg_rl, "%s: received reply with xid %08"PRIx32
                        " != expected %08"PRIx32,
                        vconn->name, ntohl(recv_xid), ntohl(xid));
        }
        ofpbuf_delete(reply);
    }
}

/* Waits until a message with a transaction ID matching 'xid' is received on
 * 'vconn'.  Returns 0 if successful, in which case the reply is stored in
 * '*replyp' for the caller to examine and free.  Otherwise returns a positive
 * errno value, or EOF, and sets '*replyp' to null.
 *
 * 'request' is always destroyed, regardless of the return value. */
int
vconn_recv_xid(struct vconn *vconn, ovs_be32 xid, struct ofpbuf **replyp)
{
    return vconn_recv_xid__(vconn, xid, replyp, NULL);
}

static int
vconn_transact__(struct vconn *vconn, struct ofpbuf *request,
                 struct ofpbuf **replyp,
                 void (*error_reporter)(const struct ofp_header *))
{
    ovs_be32 send_xid = ((struct ofp_header *) request->data)->xid;
    int error;

    *replyp = NULL;
    error = vconn_send_block(vconn, request);
    if (error) {
        ofpbuf_delete(request);
    }
    return error ? error : vconn_recv_xid__(vconn, send_xid, replyp,
                                            error_reporter);
}

/* Sends 'request' to 'vconn' and blocks until it receives a reply with a
 * matching transaction ID.  Returns 0 if successful, in which case the reply
 * is stored in '*replyp' for the caller to examine and free.  Otherwise
 * returns a positive errno value, or EOF, and sets '*replyp' to null.
 *
 * 'request' should be an OpenFlow request that requires a reply.  Otherwise,
 * if there is no reply, this function can end up blocking forever (or until
 * the peer drops the connection).
 *
 * 'request' is always destroyed, regardless of the return value. */
int
vconn_transact(struct vconn *vconn, struct ofpbuf *request,
               struct ofpbuf **replyp)
{
    return vconn_transact__(vconn, request, replyp, NULL);
}

/* Sends 'request' followed by a barrier request to 'vconn', then blocks until
 * it receives a reply to the barrier.  If successful, stores the reply to
 * 'request' in '*replyp', if one was received, and otherwise NULL, then
 * returns 0.  Otherwise returns a positive errno value, or EOF, and sets
 * '*replyp' to null.
 *
 * This function is useful for sending an OpenFlow request that doesn't
 * ordinarily include a reply but might report an error in special
 * circumstances.
 *
 * 'request' is always destroyed, regardless of the return value. */
int
vconn_transact_noreply(struct vconn *vconn, struct ofpbuf *request,
                       struct ofpbuf **replyp)
{
    ovs_be32 request_xid;
    ovs_be32 barrier_xid;
    struct ofpbuf *barrier;
    int error;

    *replyp = NULL;

    /* Send request. */
    request_xid = ((struct ofp_header *) request->data)->xid;
    error = vconn_send_block(vconn, request);
    if (error) {
        ofpbuf_delete(request);
        return error;
    }

    /* Send barrier. */
    barrier = ofputil_encode_barrier_request(vconn_get_version(vconn));
    barrier_xid = ((struct ofp_header *) barrier->data)->xid;
    error = vconn_send_block(vconn, barrier);
    if (error) {
        ofpbuf_delete(barrier);
        return error;
    }

    for (;;) {
        struct ofpbuf *msg;
        ovs_be32 msg_xid;
        int error;

        error = vconn_recv_block(vconn, &msg);
        if (error) {
            ofpbuf_delete(*replyp);
            *replyp = NULL;
            return error;
        }

        msg_xid = ((struct ofp_header *) msg->data)->xid;
        if (msg_xid == request_xid) {
            if (*replyp) {
                VLOG_WARN_RL(&bad_ofmsg_rl, "%s: duplicate replies with "
                             "xid %08"PRIx32, vconn->name, ntohl(msg_xid));
                ofpbuf_delete(*replyp);
            }
            *replyp = msg;
        } else {
            ofpbuf_delete(msg);
            if (msg_xid == barrier_xid) {
                return 0;
            } else {
                VLOG_DBG_RL(&bad_ofmsg_rl, "%s: reply with xid %08"PRIx32
                            " != expected %08"PRIx32" or %08"PRIx32,
                            vconn->name, ntohl(msg_xid),
                            ntohl(request_xid), ntohl(barrier_xid));
            }
        }
    }
}

/* vconn_transact_noreply() for a list of "struct ofpbuf"s, sent one by one.
 * All of the requests on 'requests' are always destroyed, regardless of the
 * return value. */
int
vconn_transact_multiple_noreply(struct vconn *vconn, struct ovs_list *requests,
                                struct ofpbuf **replyp)
{
    struct ofpbuf *request;

    LIST_FOR_EACH_POP (request, list_node, requests) {
        int error;

        error = vconn_transact_noreply(vconn, request, replyp);
        if (error || *replyp) {
            ofpbuf_list_delete(requests);
            return error;
        }
    }

    *replyp = NULL;
    return 0;
}

static enum ofperr
vconn_bundle_reply_validate(struct ofpbuf *reply,
                            struct ofputil_bundle_ctrl_msg *request,
                            void (*error_reporter)(const struct ofp_header *))
{
    const struct ofp_header *oh;
    enum ofptype type;
    enum ofperr error;
    struct ofputil_bundle_ctrl_msg rbc;

    oh = reply->data;
    error = ofptype_decode(&type, oh);
    if (error) {
        return error;
    }

    if (type == OFPTYPE_ERROR) {
        error_reporter(oh);
        return ofperr_decode_msg(oh, NULL);
    }
    if (type != OFPTYPE_BUNDLE_CONTROL) {
        return OFPERR_OFPBRC_BAD_TYPE;
    }

    error = ofputil_decode_bundle_ctrl(oh, &rbc);
    if (error) {
        return error;
    }

    if (rbc.bundle_id != request->bundle_id) {
        return OFPERR_OFPBFC_BAD_ID;
    }

    if (rbc.type != request->type + 1) {
        return OFPERR_OFPBFC_BAD_TYPE;
    }

    return 0;
}

/* Send bundle control message 'bc' of 'type' via 'vconn', and wait for either
 * an error or the corresponding bundle control message response.
 *
 * 'error_reporter' is called for any error responses received, which may be
 * also regarding earlier OpenFlow messages than this bundle control message.
 *
 * Returns errno value, or 0 when successful. */
static int
vconn_bundle_control_transact(struct vconn *vconn,
                              struct ofputil_bundle_ctrl_msg *bc,
                              uint16_t type,
                              void (*error_reporter)(const struct ofp_header *))
{
    struct ofpbuf *request, *reply;
    int error;
    enum ofperr ofperr;

    bc->type = type;
    request = ofputil_encode_bundle_ctrl_request(vconn->version, bc);
    ofpmsg_update_length(request);
    error = vconn_transact__(vconn, request, &reply, error_reporter);
    if (error) {
        return error;
    }

    ofperr = vconn_bundle_reply_validate(reply, bc, error_reporter);
    if (ofperr) {
        VLOG_WARN_RL(&bad_ofmsg_rl, "Bundle %s failed (%s).",
                     type == OFPBCT_OPEN_REQUEST ? "open"
                     : type == OFPBCT_CLOSE_REQUEST ? "close"
                     : type == OFPBCT_COMMIT_REQUEST ? "commit"
                     : type == OFPBCT_DISCARD_REQUEST ? "discard"
                     : "control message",
                     ofperr_to_string(ofperr));
    }
    ofpbuf_delete(reply);

    return ofperr ? EPROTO : 0;
}

/* Checks if error responses can be received on 'vconn'. */
static void
vconn_recv_error(struct vconn *vconn,
                 void (*error_reporter)(const struct ofp_header *))
{
    int error;

    do {
        struct ofpbuf *reply;

        error = vconn_recv(vconn, &reply);
        if (!error) {
            const struct ofp_header *oh;
            enum ofptype type;
            enum ofperr ofperr;

            oh = reply->data;
            ofperr = ofptype_decode(&type, oh);
            if (!ofperr && type == OFPTYPE_ERROR) {
                error_reporter(oh);
            } else {
                VLOG_DBG_RL(&bad_ofmsg_rl,
                            "%s: received unexpected reply with xid %08"PRIx32,
                            vconn->name, ntohl(oh->xid));
            }
            ofpbuf_delete(reply);
        }
    } while (!error);
}

static int
vconn_bundle_add_msg(struct vconn *vconn, struct ofputil_bundle_ctrl_msg *bc,
                     struct ofpbuf *msg,
                     void (*error_reporter)(const struct ofp_header *))
{
    struct ofputil_bundle_add_msg bam;
    struct ofpbuf *request;
    int error;

    bam.bundle_id = bc->bundle_id;
    bam.flags = bc->flags;
    bam.msg = msg->data;

    request = ofputil_encode_bundle_add(vconn->version, &bam);
    ofpmsg_update_length(request);

    error = vconn_send_block(vconn, request);
    if (!error) {
        /* Check for an error return, so that the socket buffer does not become
         * full of errors. */
        vconn_recv_error(vconn, error_reporter);
    }
    return error;
}

int
vconn_bundle_transact(struct vconn *vconn, struct ovs_list *requests,
                      uint16_t flags,
                      void (*error_reporter)(const struct ofp_header *))
{
    struct ofputil_bundle_ctrl_msg bc;
    struct ofpbuf *request;
    int error;

    memset(&bc, 0, sizeof bc);
    bc.flags = flags;
    error = vconn_bundle_control_transact(vconn, &bc, OFPBCT_OPEN_REQUEST,
                                          error_reporter);
    if (error) {
        return error;
    }

    LIST_FOR_EACH (request, list_node, requests) {
        error = vconn_bundle_add_msg(vconn, &bc, request, error_reporter);
        if (error) {
            break;
        }
    }

    if (!error) {
        error = vconn_bundle_control_transact(vconn, &bc,
                                              OFPBCT_COMMIT_REQUEST,
                                              error_reporter);
    } else {
        /* Do not overwrite the error code from vconn_bundle_add_msg().
         * Any error in discard should be either reported or logged, so it
         * should not get lost. */
        vconn_bundle_control_transact(vconn, &bc, OFPBCT_DISCARD_REQUEST,
                                      error_reporter);
    }
    return error;
}

void
vconn_wait(struct vconn *vconn, enum vconn_wait_type wait)
{
    ovs_assert(wait == WAIT_CONNECT || wait == WAIT_RECV || wait == WAIT_SEND);

    switch (vconn->state) {
    case VCS_CONNECTING:
        wait = WAIT_CONNECT;
        break;

    case VCS_SEND_HELLO:
    case VCS_SEND_ERROR:
        wait = WAIT_SEND;
        break;

    case VCS_RECV_HELLO:
        wait = WAIT_RECV;
        break;

    case VCS_CONNECTED:
        if (vconn->probe_interval) {
            poll_timer_wait_until(1000LL * (vconn->last_activity
                                            + vconn->probe_interval));
        }
        break;

    case VCS_IDLE:
        poll_timer_wait_until(1000LL * (vconn->probe_time
                                        + vconn->probe_interval));
        break;

    case VCS_DISCONNECTED:
        poll_immediate_wake();
        return;
    }
    (vconn->vclass->wait)(vconn, wait);
}

void
vconn_connect_wait(struct vconn *vconn)
{
    vconn_wait(vconn, WAIT_CONNECT);
}

void
vconn_recv_wait(struct vconn *vconn)
{
    vconn_wait(vconn, WAIT_RECV);
}

void
vconn_send_wait(struct vconn *vconn)
{
    vconn_wait(vconn, WAIT_SEND);
}

/* Given 'name', a connection name in the form "TYPE:ARGS", stores the class
 * named "TYPE" into '*classp' and returns 0.  Returns EAFNOSUPPORT and stores
 * a null pointer into '*classp' if 'name' is in the wrong form or if no such
 * class exists. */
static int
pvconn_lookup_class(const char *name, const struct pvconn_class **classp)
{
    size_t prefix_len;

    prefix_len = strcspn(name, ":");
    if (name[prefix_len] != '\0') {
        size_t i;

        for (i = 0; i < ARRAY_SIZE(pvconn_classes); i++) {
            const struct pvconn_class *class = pvconn_classes[i];
            if (strlen(class->name) == prefix_len
                && !memcmp(class->name, name, prefix_len)) {
                *classp = class;
                return 0;
            }
        }
    }

    *classp = NULL;
    return EAFNOSUPPORT;
}

/* Returns 0 if 'name' is a connection name in the form "TYPE:ARGS" and TYPE is
 * a supported connection type, otherwise EAFNOSUPPORT.  */
int
pvconn_verify_name(const char *name)
{
    const struct pvconn_class *class;
    return pvconn_lookup_class(name, &class);
}

/* Attempts to start listening for OpenFlow connections.  'name' is a
 * connection name in the form "TYPE:ARGS", where TYPE is an passive vconn
 * class's name and ARGS are vconn class-specific.
 *
 * vconns accepted by the pvconn will automatically negotiate an OpenFlow
 * protocol version acceptable to both peers on the connection.  The version
 * negotiated will be one of those in the 'allowed_versions' bitmap: version
 * 'x' is allowed if allowed_versions & (1 << x) is nonzero.  If
 * 'allowed_versions' is zero, then OFPUTIL_DEFAULT_VERSIONS are allowed.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * stores a pointer to the new connection in '*pvconnp', otherwise a null
 * pointer.  */
int
pvconn_open(const char *name, uint32_t allowed_versions, uint8_t dscp,
            struct pvconn **pvconnp)
{
    const struct pvconn_class *class;
    struct pvconn *pvconn;
    char *suffix_copy;
    int error;

    check_vconn_classes();

    if (!allowed_versions) {
        allowed_versions = OFPUTIL_DEFAULT_VERSIONS;
    }

    /* Look up the class. */
    error = pvconn_lookup_class(name, &class);
    if (!class) {
        goto error;
    }

    /* Call class's "open" function. */
    suffix_copy = xstrdup(strchr(name, ':') + 1);
    error = class->listen(name, allowed_versions, suffix_copy, &pvconn, dscp);
    free(suffix_copy);
    if (error) {
        goto error;
    }

    /* Success. */
    *pvconnp = pvconn;
    return 0;

error:
    *pvconnp = NULL;
    return error;
}

/* Returns the name that was used to open 'pvconn'.  The caller must not
 * modify or free the name. */
const char *
pvconn_get_name(const struct pvconn *pvconn)
{
    return pvconn->name;
}

/* Closes 'pvconn'. */
void
pvconn_close(struct pvconn *pvconn)
{
    if (pvconn != NULL) {
        char *name = pvconn->name;
        (pvconn->pvclass->close)(pvconn);
        free(name);
    }
}

/* Tries to accept a new connection on 'pvconn'.  If successful, stores the new
 * connection in '*new_vconn' and returns 0.  Otherwise, returns a positive
 * errno value.
 *
 * The new vconn will automatically negotiate an OpenFlow protocol version
 * acceptable to both peers on the connection.  The version negotiated will be
 * no lower than 'min_version' and no higher than 'max_version'.
 *
 * pvconn_accept() will not block waiting for a connection.  If no connection
 * is ready to be accepted, it returns EAGAIN immediately. */
int
pvconn_accept(struct pvconn *pvconn, struct vconn **new_vconn)
{
    int retval = (pvconn->pvclass->accept)(pvconn, new_vconn);
    if (retval) {
        *new_vconn = NULL;
    } else {
        ovs_assert((*new_vconn)->state != VCS_CONNECTING
                   || (*new_vconn)->vclass->connect);
    }
    return retval;
}

void
pvconn_wait(struct pvconn *pvconn)
{
    (pvconn->pvclass->wait)(pvconn);
}

/* Initializes 'vconn' as a new vconn named 'name', implemented via 'class'.
 * The initial connection status, supplied as 'connect_status', is interpreted
 * as follows:
 *
 *      - 0: 'vconn' is connected.  Its 'send' and 'recv' functions may be
 *        called in the normal fashion.
 *
 *      - EAGAIN: 'vconn' is trying to complete a connection.  Its 'connect'
 *        function should be called to complete the connection.
 *
 *      - Other positive errno values indicate that the connection failed with
 *        the specified error.
 *
 * After calling this function, vconn_close() must be used to destroy 'vconn',
 * otherwise resources will be leaked.
 *
 * The caller retains ownership of 'name'. */
void
vconn_init(struct vconn *vconn, const struct vconn_class *class,
           int connect_status, const char *name, uint32_t allowed_versions)
{
    memset(vconn, 0, sizeof *vconn);
    vconn->vclass = class;
    vconn->state = (connect_status == EAGAIN ? VCS_CONNECTING
                    : !connect_status ? VCS_SEND_HELLO
                    : VCS_DISCONNECTED);
    vconn->error = connect_status;
    vconn->allowed_versions = allowed_versions;
    vconn->name = xstrdup(name);
    list_init(&vconn->txq);
    vconn->last_activity = time_now();
    ovs_assert(vconn->state != VCS_CONNECTING || class->connect);
}

void
pvconn_init(struct pvconn *pvconn, const struct pvconn_class *class,
            const char *name, uint32_t allowed_versions)
{
    pvconn->pvclass = class;
    pvconn->name = xstrdup(name);
    pvconn->allowed_versions = allowed_versions;
}

struct vconn_packet_counter *
vconn_packet_counter_create(void)
{
    struct vconn_packet_counter *c = xzalloc(sizeof *c);
    ovs_mutex_init(&c->mutex);
    ovs_mutex_lock(&c->mutex);
    c->ref_cnt = 1;
    ovs_mutex_unlock(&c->mutex);
    return c;
}

void
vconn_packet_counter_destroy(struct vconn_packet_counter *c)
{
    if (c) {
        bool dead;

        ovs_mutex_lock(&c->mutex);
        ovs_assert(c->ref_cnt > 0);
        dead = !--c->ref_cnt && !c->n_packets;
        ovs_mutex_unlock(&c->mutex);

        if (dead) {
            ovs_mutex_destroy(&c->mutex);
            free(c);
        }
    }
}

static void
vconn_packet_counter_inc(struct vconn_packet_counter *c, unsigned int n_bytes)
{
    ovs_mutex_lock(&c->mutex);
    c->n_packets++;
    c->n_bytes += n_bytes;
    ovs_mutex_unlock(&c->mutex);
}

static void
vconn_packet_counter_dec(struct vconn_packet_counter *c, unsigned int n_bytes)
{
    bool dead = false;

    ovs_mutex_lock(&c->mutex);
    ovs_assert(c->n_packets > 0);
    ovs_assert(c->n_packets == 1
               ? c->n_bytes == n_bytes
               : c->n_bytes > n_bytes);
    c->n_packets--;
    c->n_bytes -= n_bytes;
    dead = !c->n_packets && !c->ref_cnt;
    ovs_mutex_unlock(&c->mutex);

    if (dead) {
        ovs_mutex_destroy(&c->mutex);
        free(c);
    }
}

unsigned int
vconn_packet_counter_n_packets(const struct vconn_packet_counter *c)
{
    unsigned int n;

    ovs_mutex_lock(&c->mutex);
    n = c->n_packets;
    ovs_mutex_unlock(&c->mutex);

    return n;
}

unsigned int
vconn_packet_counter_n_bytes(const struct vconn_packet_counter *c)
{
    unsigned int n;

    ovs_mutex_lock(&c->mutex);
    n = c->n_bytes;
    ovs_mutex_unlock(&c->mutex);

    return n;
}
