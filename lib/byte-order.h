/*
 * Copyright (c) 2008, 2010, 2011, 2013, 2015 Nicira, Inc.
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
#ifndef BYTE_ORDER_H
#define BYTE_ORDER_H 1

#include <arpa/inet.h>
#include <sys/types.h>
#include <inttypes.h>
#include "openvswitch/types.h"

static inline uint16_t
uint16_byteswap(uint16_t x)
{
    return (x >> 8) | (x << 8);
}

static inline uint32_t
uint32_byteswap(uint32_t x)
{
    return (((x & 0x000000ff) << 24) |
            ((x & 0x0000ff00) <<  8) |
            ((x & 0x00ff0000) >>  8) |
            ((x & 0xff000000) >> 24));
}

static inline uint64_t
uint64_byteswap(uint64_t x)
{
    return ((uint64_t) uint32_byteswap(x) << 32) | uint32_byteswap(x >> 32);
}

#ifndef __CHECKER__
#ifndef _WIN32
#ifndef WORDS_BIGENDIAN
static inline ovs_be64 htonll(uint64_t x) { return uint64_byteswap(x); }
#else
static inline ovs_be64 htonll(uint64_t x) { return x; }
#endif
static inline uint64_t ntohll(ovs_be64 x) { return htonll(x); }
#endif /* _WIN32 */
#else
/* Making sparse happy with these functions also makes them unreadable, so
 * don't bother to show it their implementations. */
ovs_be64 htonll(uint64_t);
uint64_t ntohll(ovs_be64);
#endif

/* These macros may substitute for htons(), htonl(), and htonll() in contexts
 * where function calls are not allowed, such as case labels.  They should not
 * be used elsewhere because all of them evaluate their argument many times. */
#if defined(WORDS_BIGENDIAN) || __CHECKER__
#define CONSTANT_HTONS(VALUE) ((OVS_FORCE ovs_be16) ((VALUE) & 0xffff))
#define CONSTANT_HTONL(VALUE) ((OVS_FORCE ovs_be32) ((VALUE) & 0xffffffff))
#define CONSTANT_HTONLL(VALUE) \
        ((OVS_FORCE ovs_be64) ((VALUE) & UINT64_C(0xffffffffffffffff)))
#else
#define CONSTANT_HTONS(VALUE)                       \
        (((((ovs_be16) (VALUE)) & 0xff00) >> 8) |   \
         ((((ovs_be16) (VALUE)) & 0x00ff) << 8))
#define CONSTANT_HTONL(VALUE)                           \
        (((((ovs_be32) (VALUE)) & 0x000000ff) << 24) |  \
         ((((ovs_be32) (VALUE)) & 0x0000ff00) <<  8) |  \
         ((((ovs_be32) (VALUE)) & 0x00ff0000) >>  8) |  \
         ((((ovs_be32) (VALUE)) & 0xff000000) >> 24))
#define CONSTANT_HTONLL(VALUE)                                           \
        (((((ovs_be64) (VALUE)) & UINT64_C(0x00000000000000ff)) << 56) | \
         ((((ovs_be64) (VALUE)) & UINT64_C(0x000000000000ff00)) << 40) | \
         ((((ovs_be64) (VALUE)) & UINT64_C(0x0000000000ff0000)) << 24) | \
         ((((ovs_be64) (VALUE)) & UINT64_C(0x00000000ff000000)) <<  8) | \
         ((((ovs_be64) (VALUE)) & UINT64_C(0x000000ff00000000)) >>  8) | \
         ((((ovs_be64) (VALUE)) & UINT64_C(0x0000ff0000000000)) >> 24) | \
         ((((ovs_be64) (VALUE)) & UINT64_C(0x00ff000000000000)) >> 40) | \
         ((((ovs_be64) (VALUE)) & UINT64_C(0xff00000000000000)) >> 56))
#endif

#if WORDS_BIGENDIAN
#define BYTES_TO_BE32(B1, B2, B3, B4) \
    (OVS_FORCE ovs_be32)((uint32_t)(B1) << 24 | (B2) << 16 | (B3) << 8 | (B4))
#define BE16S_TO_BE32(B1, B2) \
    (OVS_FORCE ovs_be32)((uint32_t)(B1) << 16 | (B2))
#else
#define BYTES_TO_BE32(B1, B2, B3, B4) \
    (OVS_FORCE ovs_be32)((uint32_t)(B1) | (B2) << 8 | (B3) << 16 | (B4) << 24)
#define BE16S_TO_BE32(B1, B2) \
    (OVS_FORCE ovs_be32)((uint32_t)(B1) | (B2) << 16)
#endif

/* Conversion between host and "Intel" byte order. */
#ifndef __CHECKER__
#ifdef WORDS_BIGENDIAN
static inline ovs_le16 htois(uint16_t x) { return uint16_byteswap(x); }
static inline ovs_le32 htoil(uint32_t x) { return uint32_byteswap(x); }
static inline ovs_le64 htoill(uint64_t x) { return uint64_byteswap(x); }
#else
static inline ovs_le16 htois(uint16_t x) { return x; }
static inline ovs_le32 htoil(uint32_t x) { return x; }
static inline ovs_le64 htoill(uint64_t x) { return x; }
#endif
static inline uint16_t itohs(ovs_be16 x) { return htois(x); }
static inline uint32_t itohl(ovs_be32 x) { return htoil(x); }
static inline uint64_t itohll(ovs_be64 x) { return htoill(x); }
#else
/* Making sparse happy with these functions also makes them unreadable, so
 * don't bother to show it their implementations. */
ovs_le16 htois(uint16_t x);
ovs_le32 htoil(uint32_t x);
ovs_le64 htoill(uint64_t x);
uint16_t itohs(ovs_be16 x);
uint32_t itohl(ovs_be32 x);
uint64_t itohll(ovs_be64 x);
#endif

#endif /* byte-order.h */
