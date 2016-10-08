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

#ifndef OVS_DATAPATH_LINUX_COMPAT_INCLUDE_LINUX_OPENVSWITCH_H_H
#define	OVS_DATAPATH_LINUX_COMPAT_INCLUDE_LINUX_OPENVSWITCH_H_H 1

/* -- Used in datapath/linux/compat/include/linux/openvswitch.h -- */
#define OVS_KEY_ATTRS \
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in ordered_header_instances_non_virtual:
    OVS_KEY_ATTR_${header_name.upper()}, \
//::  #endfor
    OVS_KEY_ATTR_VALID, \
    \

/* -- Used in datapath/linux/compat/include/linux/openvswitch.h -- */
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in ordered_header_instances_non_virtual:
struct ovs_key_${header_name} {
//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
//::      if bit_width in [8, 16, 32, 64]:
    uint${bit_width}_t ${field_name};
//::      else:
    struct ${field_name}_t ${field_name};
//::      #endif
//::    #endfor
};

//::  #endfor
struct ovs_key_valid {
//::  for header_name in ordered_header_instances_regular:
    uint8_t ${header_name}_valid;
//::  #endfor
    };

#endif	/* OVS_DATAPATH_LINUX_COMPAT_INCLUDE_LINUX_OPENVSWITCH_H_H */
