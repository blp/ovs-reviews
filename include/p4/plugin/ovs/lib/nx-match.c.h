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

#ifndef OVS_LIB_NX_MATCH_C_H
#define	OVS_LIB_NX_MATCH_C_H 1

/* -- Used in lib/nx-match.c -- */
#define OVS_MATCH_PUT_RAW \
//::  for header_name in ordered_header_instances_non_virtual:
//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
//::      if bit_width in [8, 16, 32, 64]:
    nxm_put_${bit_width}m(b, MFF_${field_name.upper()}, oxm, \
               flow->${header_name}.hdr.${field_name}, \
               match->wc.masks.${header_name}.hdr.${field_name}); \
//::      else:
//::        # We assume that all fields are, at least, byte aligned.
    nxm_put(b, MFF_${field_name.upper()}, oxm, \
            &flow->${header_name}.hdr.${field_name}, \
            &match->wc.masks.${header_name}.hdr.${field_name}, \
            sizeof flow->${header_name}.hdr.${field_name}); \
//::      #endif
//::    #endfor
    \
//::  #endfor
//::  for header_name in ordered_header_instances_regular:
    nxm_put_8m(b, MFF_${header_name.upper()}_VALID, oxm, \
               flow->valid.hdr.${header_name}_valid, \
               match->wc.masks.valid.hdr.${header_name}_valid); \
//::  #endfor
    \

#endif	/* OVS_LIB_NX_MATCH_C_H */
