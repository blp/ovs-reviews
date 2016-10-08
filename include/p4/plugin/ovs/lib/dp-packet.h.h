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

#ifndef OVS_LIB_DP_PACKET_H_H
#define	OVS_LIB_DP_PACKET_H_H 1
//::
//:: # NOTE: we don't have to specify metadata in the packet struct in the datapath.
//:: # The parser can set the value of the metadata but only the final results (after
//:: # constant propagation) are written in the cache. The only thing different from
//:: # how native OVS treat metadata is that, in P4/OVS case, parser can set metadata
//:: # to some arbitrary value, whereas in native OVS, the value of the metadata before
//:: # being processed by the cache and match-action tables is always 0.

/* -- Used in lib/dp-packet.h -- */
#define OVS_HDR_ATTRS \
//::  for header_name in ordered_header_instances_regular:
    uint16_t ${header_name}_ofs; \
    uint8_t ${header_name}_valid; \
//::  #endfor
    \

/* -- Used in lib/dp-packet.h -- */
#define OVS_HDR_GET_DP_PACKET_OFS \
//::  for header_name in ordered_header_instances_regular:
static inline void * dp_packet_${header_name}(const struct dp_packet *b) { \
    return b->${header_name}_ofs != UINT16_MAX \
        ? (char *) dp_packet_data(b) + b->${header_name}_ofs \
        : NULL; \
} \
//::  #endfor
\

#endif	/* OVS_LIB_DP_PACKET_H_H */
