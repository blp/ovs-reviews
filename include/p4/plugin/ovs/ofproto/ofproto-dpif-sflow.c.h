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
//::
//:: import helpers

#ifndef OVS_OFPROTO_OFPROTO_DPIF_SFLOW_C_H
#define	OVS_OFPROTO_OFPROTO_DPIF_SFLOW_C_H 1

/* -- Called in ofproto/ofproto-dpif-sflow.h -- */
#define OVS_SFLOW_READ_SET_ACTION_CASES \
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in helpers.get_ordered_header_instances_non_virtual(ordered_header_instances_non_virtual):
    case OVS_KEY_ATTR_${header_name.upper()}: \
        break; \
//::  #endfor
    case OVS_KEY_ATTR_VALID: \
        break; \
    \

#endif	/* OVS_OFPROTO_OFPROTO_DPIF_SFLOW_C_H */
