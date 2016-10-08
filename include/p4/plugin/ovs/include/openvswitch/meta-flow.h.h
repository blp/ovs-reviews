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
//:: (_, ordered_header_instances_non_virtual_aligned_field__name_width) = helpers.get_ordered_header_and_aligned_field_instances_non_virtual__name_width(
//::                                                                            ordered_header_instances_non_virtual,
//::                                                                            header_info, aligned_field_info)

#ifndef OVS_INCLUDE_OPENVSWITCH_META_FLOW_H_H
#define	OVS_INCLUDE_OPENVSWITCH_META_FLOW_H_H 1

/* -- Included in include/openvswitch/meta-flow.h -- */

/* NOTE:
 * 1. Don't forget to add preceding tabs in the following fields, otherwise, will result in errors.
 * 2. For now prerequisites are not handled and all fields are maskable.
 */

//::  base_oxm_offset = 1 # We use 1 as the base line offset. If new NXOXM_ET_* fixed fields are added in OVS
//::                      # this number will have to be updated accordingly.
//::  for header_name in ordered_header_instances_non_virtual:
//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
    /* "${field_name}".
     *
     * ${field_name} field.
     *
     * Type: be${bit_width}.
     * Formatting: hexadecimal.
     * Maskable: bitwise.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: none.
     * OXM: NXOXM_ET_${field_name.upper()}(${base_oxm_offset}) since OF1.5 and v2.5.
     */
    MFF_${field_name.upper()},
//::      base_oxm_offset += 1

//::    #endfor
//::  #endfor
//::
//::  for header_name in ordered_header_instances_regular:
    /* "${header_name}_valid".
     *
     * ${header_name}_valid field.
     *
     * Type: u${8}.
     * Formatting: hexadecimal.
     * Maskable: bitwise.
     * Prerequisites: none.
     * Access: read/write.
     * NXM: none.
     * OXM: NXOXM_ET_${header_name.upper()}_VALID(${base_oxm_offset}) since OF1.5 and v2.5.
     */
    MFF_${header_name.upper()}_VALID,
//::      base_oxm_offset += 1

//::  #endfor

/* Do NOT REMOVE THIS. */
    // MFF_N_IDS

#endif	/* OVS_INCLUDE_OPENVSWITCH_META_FLOW_H_H */
