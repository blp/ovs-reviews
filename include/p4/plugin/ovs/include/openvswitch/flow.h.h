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

#ifndef OVS_INCLUDE_OPENVSWITCH_FLOW_H_H
#define	OVS_INCLUDE_OPENVSWITCH_FLOW_H_H 1

/* -- Used in include/openvswitch/flow.h -- */
#define OVS_FIELDS \
//::  for header_name in helpers.get_ordered_header_instances_non_virtual(ordered_header_instances_non_virtual):
    struct ${header_name}_padded_header ${header_name}; \
//::  #endfor
    struct valid_padded_header valid; \
    \

#endif	/* OVS_INCLUDE_OPENVSWITCH_FLOW_H_H */
