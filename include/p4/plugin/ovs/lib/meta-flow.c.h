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

#ifndef OVS_LIB_META_FLOW_C_H
#define	OVS_LIB_META_FLOW_C_H 1

/* -- Used in lib/meta-flow.c -- */
#define OVS_GET_VALUE_CASES \
//::  for header_name in ordered_header_instances_non_virtual:
//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
    case MFF_${field_name.upper()}: \
//::      if bit_width in [8, 16, 32, 64]:
        value->${helpers.std_type_prefix[bit_width]} = flow->${header_name}.hdr.${field_name}; \
//::      else:
//::        # We assume that all fields are, at least, byte aligned.
        memcpy(value->data, &flow->${header_name}.hdr.${field_name}, \
            sizeof flow->${header_name}.hdr.${field_name}); \
//::      #endif
        break; \
//::    #endfor
//::  #endfor
//::  for header_name in ordered_header_instances_regular:
    case MFF_${header_name.upper()}_VALID: \
        value->u8 = flow->valid.hdr.${header_name}_valid; \
        break; \
//::  #endfor
\

/* -- Used in lib/meta-flow.c -- */
#define OVS_IS_VALUE_VALID_CASES \
//::  for header_name in ordered_header_instances_non_virtual:
//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
    case MFF_${field_name.upper()}: \
        return true; \
//::    #endfor
//::  #endfor
//::  for header_name in ordered_header_instances_regular:
    case MFF_${header_name.upper()}_VALID: \
        return true; \
//::  #endfor
\

/* -- Used in lib/meta-flow.c -- */
#define OVS_IS_ALL_WILD_CASES \
//::  for header_name in ordered_header_instances_non_virtual:
//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
    case MFF_${field_name.upper()}: \
//::      if bit_width in [8, 16, 32, 64]:
        return !wc->masks.${header_name}.hdr.${field_name}; \
//::      else:
        return is_all_zeros(&wc->masks.${header_name}.hdr.${field_name}, \
            sizeof wc->masks.${header_name}.hdr.${field_name}); \
//::      #endif
//::    #endfor
//::  #endfor
//::  for header_name in ordered_header_instances_regular:
    case MFF_${header_name.upper()}_VALID: \
        return !wc->masks.valid.hdr.${header_name}_valid; \
//::  #endfor
\

/* -- Used in lib/meta-flow.c -- */
#define OVS_SET_FLOW_VALUE_CASES \
//::  for header_name in ordered_header_instances_non_virtual:
//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
    case MFF_${field_name.upper()}: \
//::      if bit_width in [8, 16, 32, 64]:
        flow->${header_name}.hdr.${field_name} = value->${helpers.std_type_prefix[bit_width]}; \
//::      else:
//::        # We assume that all fields are, at least, byte aligned.
        memcpy(&flow->${header_name}.hdr.${field_name}, value->data, \
            sizeof flow->${header_name}.hdr.${field_name}); \
//::      #endif
        break; \
//::    #endfor
//::  #endfor
//::  for header_name in ordered_header_instances_regular:
    case MFF_${header_name.upper()}_VALID: \
        flow->valid.hdr.${header_name}_valid = value->u8; \
        break; \
//::  #endfor
\

/* -- Used in lib/meta-flow.c -- */
#define OVS_SET_VALUE_CASES \
//::  for header_name in ordered_header_instances_non_virtual:
//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
    case MFF_${field_name.upper()}: \
//::      if bit_width == 8:
        match->wc.masks.${header_name}.hdr.${field_name} = 0xff; \
        match->flow.${header_name}.hdr.${field_name} = value->${helpers.std_type_prefix[bit_width]}; \
//::      elif bit_width in [16, 32, 64]:
        match->wc.masks.${header_name}.hdr.${field_name} = OVS_BE${bit_width}_MAX; \
        match->flow.${header_name}.hdr.${field_name} = value->${helpers.std_type_prefix[bit_width]}; \
//::      else:
//::        # We assume that all fields are, at least, byte aligned.
        memset(&match->wc.masks.${header_name}.hdr.${field_name}, 0xff, \
               sizeof match->wc.masks.${header_name}.hdr.${field_name}); \
        memcpy(&match->flow.${header_name}.hdr.${field_name}, value->data, \
               sizeof match->flow.${header_name}.hdr.${field_name}); \
//::      #endif
        break; \
//::    #endfor
//::  #endfor
//::  for header_name in ordered_header_instances_regular:
    case MFF_${header_name.upper()}_VALID: \
        match->wc.masks.valid.hdr.${header_name}_valid = 0xff; \
        match->flow.valid.hdr.${header_name}_valid = value->u8; \
        break; \
//::  #endfor
\

/* -- Used in lib/meta-flow.c -- */
#define OVS_SET_WILD_CASES \
//::  for header_name in ordered_header_instances_non_virtual:
//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
    case MFF_${field_name.upper()}: \
//::      if bit_width in [8, 16, 32, 64]:
        match->flow.${header_name}.hdr.${field_name} = 0; \
        match->wc.masks.${header_name}.hdr.${field_name} = 0; \
//::      else:
//::        # We assume that all fields are, at least, byte aligned.
        memset(&match->flow.${header_name}.hdr.${field_name}, 0, \
               sizeof match->flow.${header_name}.hdr.${field_name}); \
        memset(&match->wc.masks.${header_name}.hdr.${field_name}, 0, \
               sizeof match->wc.masks.${header_name}.hdr.${field_name}); \
//::      #endif
        break; \
//::    #endfor
//::  #endfor
//::  for header_name in ordered_header_instances_regular:
    case MFF_${header_name.upper()}_VALID: \
        match->flow.valid.hdr.${header_name}_valid = 0; \
        match->wc.masks.valid.hdr.${header_name}_valid = 0; \
        break; \
//::  #endfor
\

/* -- Used in lib/meta-flow.c -- */
#define OVS_SET_CASES \
//::  for header_name in ordered_header_instances_non_virtual:
//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
    case MFF_${field_name.upper()}: \
//::      if bit_width in [8, 16, 32, 64]:
        match->flow.${header_name}.hdr.${field_name} = value->${helpers.std_type_prefix[bit_width]} & mask->${helpers.std_type_prefix[bit_width]}; \
        match->wc.masks.${header_name}.hdr.${field_name} = mask->${helpers.std_type_prefix[bit_width]}; \
//::      else:
//::        # We assume that all fields are, at least, byte aligned.
        for (size_t i = 0; i < sizeof match->flow.${header_name}.hdr.${field_name}; i++) { \
            ((uint8_t *) &match->flow.${header_name}.hdr.${field_name})[i] = (value->data)[i] & (mask->data)[i]; \
            ((uint8_t *) &match->wc.masks.${header_name}.hdr.${field_name})[i] = (mask->data)[i]; \
        } \
//::      #endif
        break; \
//::    #endfor
//::  #endfor
//::  for header_name in ordered_header_instances_regular:
    case MFF_${header_name.upper()}_VALID: \
        match->flow.valid.hdr.${header_name}_valid = value->u8 & mask->u8; \
        match->wc.masks.valid.hdr.${header_name}_valid = mask->u8; \
        break; \
//::  #endfor
\

#endif	/* OVS_LIB_META_FLOW_C_H */
