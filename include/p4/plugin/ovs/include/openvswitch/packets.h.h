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

#ifndef OVS_INCLUDE_OPENVSWITCH_PACKETS_H_H
#define	OVS_INCLUDE_OPENVSWITCH_PACKETS_H_H 1

//::  for header_name in ordered_header_instances_non_virtual:
//::    header_len = sum([bit_width for _, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]])/8
#define ${header_name.upper()}_HEADER_LEN ${header_len}
//::  #endfor
#define VALID_HEADER_LEN ${len(ordered_header_instances_regular)}

/* -- Used in include/openvswitch/packets.h -- */
//::  for header_name in ordered_header_instances_non_virtual:
//::    run_bit_width = 0
OVS_PACKED(
struct ${header_name}_header {
//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
//::      if bit_width in [8, 16, 32, 64]:
    uint${bit_width}_t ${field_name};
//::      else:
//::        # We assume that all fields are, at least, byte aligned.
    struct ${field_name}_t ${field_name};
//::      #endif
//::      run_bit_width += bit_width
//::    #endfor
});
BUILD_ASSERT_DECL(${header_name.upper()}_HEADER_LEN == sizeof(struct ${header_name}_header));

OVS_PACKED(
struct ${header_name}_padded_header {
    struct ${header_name}_header hdr;
//::    pad_bits = 64 - (run_bit_width % 64)
//::    pad_bytes = 0
//::    if pad_bits < 64:
//::      pad_bytes = pad_bits/8
    uint8_t pad[${pad_bytes}];
//::    #endif
});
BUILD_ASSERT_DECL(${header_name.upper()}_HEADER_LEN+${pad_bytes} == sizeof(struct ${header_name}_padded_header));

//::  #endfor
//::
OVS_PACKED(
struct valid_header {
//::  for header_name in ordered_header_instances_regular:
    uint8_t ${header_name}_valid;
//::  #endfor
});
BUILD_ASSERT_DECL(VALID_HEADER_LEN == sizeof(struct valid_header));

OVS_PACKED(
struct valid_padded_header {
    struct valid_header hdr;
//::    pad_bits = 64 - ((len(ordered_header_instances_regular) * 8) % 64)
//::    pad_bytes = 0
//::    if pad_bits < 64:
//::      pad_bytes = pad_bits/8
    uint8_t pad[${pad_bytes}];
//::    #endif
    });
BUILD_ASSERT_DECL(VALID_HEADER_LEN+${pad_bytes} == sizeof(struct valid_padded_header));

#endif	/* OVS_INCLUDE_OPENVSWITCH_PACKETS_H_H */
