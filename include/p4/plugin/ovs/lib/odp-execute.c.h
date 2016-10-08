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
//:: ordered_header_instances_metadata = helpers.get_ordered_header_instances_metadata(ordered_header_instances_metadata)

#ifndef OVS_LIB_ODP_EXECUTE_C_H
#define	OVS_LIB_ODP_EXECUTE_C_H 1

/* -- Used in lib/odp-execute.c -- */
//::  for header_name in ordered_header_instances_regular:
static void odp_set_${header_name}(struct dp_packet *packet, const struct ovs_key_${header_name} *key,
            const struct ovs_key_${header_name} *mask)
{
    struct ${header_name}_header *${header_name} = dp_packet_${header_name}(packet);

//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
//::      if bit_width in [8, 16, 32, 64]:
    uint${bit_width}_t ${field_name} = key->${field_name} | (${header_name}->${field_name} & ~mask->${field_name});
//::      else:
    struct ${field_name}_t ${field_name};
    for (size_t i = 0; i < sizeof(struct ${field_name}_t); i++) {
        ((uint8_t *) &${field_name})[i] = ((const uint8_t *) &key->${field_name})[i] |
            (((const uint8_t *) &${header_name}->${field_name})[i] &
            ~((const uint8_t *) &mask->${field_name})[i]);
    }
//::      #endif
//::    #endfor

    packet_set_${header_name}(
//::    for field_name, _ in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
        ${field_name},
//::    #endfor
        packet);
}

//::  #endfor
//::
static void odp_set_valid(struct dp_packet *packet, const struct ovs_key_valid *key,
                          const struct ovs_key_valid *mask)
{
//::  for header_name in ordered_header_instances_regular:
    uint8_t ${header_name}_valid = key->${header_name}_valid | (packet->${header_name}_valid & ~mask->${header_name}_valid);
//::  #endfor

    packet_set_valid(
//::  for header_name in ordered_header_instances_regular:
        ${header_name}_valid,
//::  #endfor
        packet);
}

/* -- Used in lib/odp-execute.c -- */
#define OVS_ODP_EXECUTE_SET_ACTION_CASES \
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in ordered_header_instances_metadata:
    case OVS_KEY_ATTR_${header_name.upper()}: \
        break; \
//::  #endfor
//::  for header_name in ordered_header_instances_regular:
    case OVS_KEY_ATTR_${header_name.upper()}: \
    { \
        const struct ovs_key_${header_name} *${header_name}_key = \
            nl_attr_get_unspec(a, sizeof(struct ovs_key_${header_name})); \
        packet_set_${header_name}( \
//::    for field_name, _ in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
            ${header_name}_key->${field_name}, \
//::    #endfor
            packet); \
        break; \
    } \
//::  #endfor
    case OVS_KEY_ATTR_VALID: \
    { \
        const struct ovs_key_valid *valid_key = \
            nl_attr_get_unspec(a, sizeof(struct ovs_key_valid)); \
        packet_set_valid( \
//::  for header_name in ordered_header_instances_regular:
            valid_key->${header_name}_valid, \
//::  #endfor
            packet); \
        break; \
    } \
    \

/* -- Used in lib/odp-execute.c -- */
#define OVS_ODP_EXECUTE_MASKED_SET_ACTION_CASES \
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in ordered_header_instances_metadata:
    case OVS_KEY_ATTR_${header_name.upper()}: \
        break; \
//::  #endfor
//::  for header_name in ordered_header_instances_regular:
    case OVS_KEY_ATTR_${header_name.upper()}: \
        odp_set_${header_name}(packet, nl_attr_get(a), \
                get_mask(a, struct ovs_key_${header_name})); \
        break; \
//::  #endfor
    case OVS_KEY_ATTR_VALID: \
        odp_set_valid(packet, nl_attr_get(a), \
                      get_mask(a, struct ovs_key_valid)); \
        break; \
    \

#endif	/* OVS_LIB_ODP_EXECUTE_C_H */
