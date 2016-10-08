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
//:: aligned_field_info = helpers.get_align_field_info(field_info, header_info, ordered_header_instances_all)
//:: ordered_header_instances_non_virtual = helpers.get_ordered_header_instances_non_virtual(ordered_header_instances_non_virtual)
//:: (ordered_aligned_field_instances_non_virtual__name_width, _) = helpers.get_ordered_header_and_aligned_field_instances_non_virtual__name_width(
//::                                                                    ordered_header_instances_non_virtual,
//::                                                                    header_info, aligned_field_info)

#ifndef OVS_INCLUDE_OPENVSWITCH_TYPES_H_H
#define	OVS_INCLUDE_OPENVSWITCH_TYPES_H_H 1

/* -- Used in include/openvswitch/types.h -- */
//::  for field_name, bit_width in ordered_aligned_field_instances_non_virtual__name_width:
//::    if not (bit_width in [8, 16, 32, 64]):
struct ${field_name}_t {
    uint8_t data[${bit_width}/8];
};
//::    #endif
//::  #endfor

#endif	/* OVS_INCLUDE_OPENVSWITCH_TYPES_H_H */
