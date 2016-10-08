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

#ifndef OVS_LIB_FLOW_C_H
#define	OVS_LIB_FLOW_C_H 1

/* -- Used in lib/flow.c -- */
#define OVS_HDR_RESET_ATTRS \
//::  for header_name in ordered_header_instances_regular:
    packet->${header_name}_ofs = UINT16_MAX; \
    packet->${header_name}_valid = 0; \
//::  #endfor
    \

/* -- Used in lib/flow.c -- */
#define OVS_MINIFLOW_EXTRACT_METADATA_DEFS \
//::  for header_name in ordered_header_instances_metadata:
    struct ${header_name}_padded_header ${header_name} = {{0},{0}}; \
    bool is_${header_name}_header_touched = false; \
    \
//::  #endfor
    struct valid_padded_header valid = {{0},{0}}; \
    \

/* -- Used in lib/flow.c -- */
#define OVS_MINIFLOW_EXTRACT \
    { \
        OVS_MINIFLOW_START \
    } \
    \

//::  for state, parse_info in parse_states.items():
#define OVS_MINIFLOW_${state.upper()} \
//::    # a. --- Handle call sequence -------------------------------
//::    call_id = 0
//::    for call in parse_info["call_sequence"]:
//::      type = call[0]
//::      if type == "extract":
//::        header_name = call[1]
    if (OVS_UNLIKELY(size < sizeof(struct ${header_name}_header))) \
    { \
        OVS_MINIFLOW_OUT \
    } \
    \
    packet->${header_name}_ofs = ((char *) data) - l2; \
    struct ${header_name}_padded_header *${header_name} = (struct ${header_name}_padded_header *) data_pull(&data, &size, \
        sizeof(struct ${header_name}_header)); \
//::        # TODO: offset increase should be based on header length expression. This needs to be implemented.
    miniflow_push_bytes_word_aligned_64(mf, ${header_name}, ${header_name}, sizeof(struct ${header_name}_header), \
        sizeof(struct ${header_name}_padded_header) / sizeof(uint64_t)); \
	valid.hdr.${header_name}_valid = 1; \
    \
//::      elif type == "set":
//::        destination = call[1]
//::        metadata_name = field_info[destination]["parent_header"]
//::        aligned_metadata = {"name": aligned_field_info[destination]["name"],
//::                            "mask": aligned_field_info[destination]["mask"],
//::                            "bit_offset_hdr": aligned_field_info[destination]["bit_offset_hdr"],
//::                            "bit_width": aligned_field_info[destination]["bit_width"]}
//::        source_type = call[2]
//::        if source_type == "immediate":
//::          source_value = hex(helpers.byte_array_to_int(call[3]))
//::          if aligned_metadata["mask"]:
//::            if aligned_metadata["bit_width"] in [8, 16, 32, 64]:
    ${metadata_name}.hdr.${aligned_metadata["name"]} = ${helpers.hton_postfix[aligned_metadata["bit_width"]]}(((uint${aligned_metadata["bit_width"]}_t) ${source_value}) << ${aligned_metadata["bit_offset_hdr"]}) \
        | (_${metadata_name}.hdr.${aligned_metadata["name"]} & ~${helpers.hton_postfix[aligned_metadata["bit_width"]]}(${hex(aligned_metadata["mask"])})); \
//::            else:
//::              # TODO: handle this case (for arbitrary byte combinations).
//::              assert(False)
//::            #endif
//::          else:
//::            if aligned_metadata["bit_width"] in [8, 16, 32, 64]:
    ${metadata_name}.hdr.${aligned_metadata["name"]} = ${helpers.hton_postfix[aligned_metadata["bit_width"]]}((uint${aligned_metadata["bit_width"]}_t) ${source_value}); \
//::            else:
//::              # TODO: handle this case (for arbitrary byte combinations).
//::              assert(False)
//::            #endif
//::          #endif
//::        elif source_type == "latest":
//::          source = call[3]
//::          header_name = field_info[source]["parent_header"]
//::          aligned_field = {"name": aligned_field_info[source]["name"],
//::                           "mask": aligned_field_info[source]["mask"],
//::                           "bit_offset_hdr": aligned_field_info[source]["bit_offset_hdr"],
//::                           "bit_width": aligned_field_info[source]["bit_width"]}
//::          # P4 2014 specification assumes that the referenced source header in set_metadata() is already extracted
//::          # at this point.
//::          if header_name in ordered_header_instances_regular:
//::            if aligned_field["mask"]:
//::              if aligned_field["bit_width"] in [8, 16, 32, 64]:
    uint${aligned_field["bit_width"]}_t value_${call_id} = (${helpers.hton_postfix[aligned_field["bit_width"]]}(${header_name}->hdr.${aligned_field["name"]}) & ${hex(aligned_field["mask"])}) >> ${aligned_field["bit_offset_hdr"]}; \
//::              else:
//::                # TODO: handle this case (for arbitrary byte combinations).
//::                assert(False)
//::              #endif
//::            else:
//::              if aligned_field["bit_width"] in [8, 16, 32, 64]:
    uint${aligned_field["bit_width"]}_t value_${call_id} = ${helpers.hton_postfix[aligned_field["bit_width"]]}(${header_name}->hdr.${aligned_field["name"]}); \
//::              else:
//::                # TODO: handle this case (for arbitrary byte combinations).
//::                assert(False)
//::              #endif
//::            #endif
//::          elif header_name in ordered_header_instances_metadata:
//::            if aligned_field["mask"]:
//::              if aligned_field["bit_width"] in [8, 16, 32, 64]:
    uint${aligned_field["bit_width"]}_t value_${call_id} = (${helpers.hton_postfix[aligned_field["bit_width"]]}(${metadata_name}.hdr.${aligned_field["name"]}) & ${hex(aligned_field["mask"])}) >> ${aligned_field["bit_offset_hdr"]}; \
//::              else:
//::                # TODO: handle this case (for arbitrary byte combinations).
//::                assert(False)
//::              #endif
//::            else:
//::              if aligned_field["bit_width"] in [8, 16, 32, 64]:
    uint${aligned_field["bit_width"]}_t value_${call_id} = ${helpers.hton_postfix[aligned_field["bit_width"]]}(${metadata_name}.hdr.${aligned_field["name"]}); \
//::              else:
//::                # TODO: handle this case (for arbitrary byte combinations).
//::                assert(False)
//::              #endif
//::            #endif
//::          else:
//::            assert(False)
//::          #endif
//::          if aligned_metadata["mask"]:
//::            if aligned_metadata["bit_width"] in [8, 16, 32, 64]:
    ${metadata_name}.hdr.${aligned_metadata["name"]} = ${helpers.hton_postfix[aligned_field["bit_width"]]}(((uint${aligned_metadata["bit_width"]}_t) value_${call_id}) << ${aligned_metadata["bit_offset_hdr"]}) \
        | (${metadata_name}.hdr.${aligned_metadata["name"]} & ~${helpers.hton_postfix[aligned_field["bit_width"]]}(${hex(aligned_metadata["mask"])})); \
//::            else:
//::              # TODO: handle this case (for arbitrary byte combinations).
//::              assert(False)
//::            #endif
//::          else:
//::            if aligned_metadata["bit_width"] in [8, 16, 32, 64]:
    ${metadata_name}.hdr.${aligned_metadata["name"]} = ${helpers.hton_postfix[aligned_field["bit_width"]]}((uint${aligned_metadata["bit_width"]}_t) value_${call_id}); \
//::            else:
//::              # TODO: handle this case (for arbitrary byte combinations).
//::              assert(False)
//::            #endif
//::          #endif
//::        else:
//::          assert(False)
//::        #endif
    is_${metadata_name}_header_touched = true; \
    \
//::      else:
//::        assert(False)
//::      #endif
//::      call_id += 1
//::    #endfor
//::    # a. --- Handle state transitions -------------------------------
//::    branch_on = parse_info['branch_on']
//::    branch_to = parse_info['branch_to']
//::    case_id = 0
//::    for case in branch_to:
//::      case_type, case_value, case_mask, case_next_state = case
//::      if case_type == "value":
//::        branch_id = 0
//::        key_id = 0
//::        for key_type, key_value in branch_on:
//::          if key_type == "field_ref":
//::            header_name = field_info[key_value]["parent_header"]
//::            aligned_field = {"name": aligned_field_info[key_value]["name"],
//::                             "mask": aligned_field_info[key_value]["mask"],
//::                             "bit_offset_hdr": aligned_field_info[key_value]["bit_offset_hdr"],
//::                             "bit_width": aligned_field_info[key_value]["bit_width"]}
//::            if header_name in ordered_header_instances_regular:
//::              if aligned_field["bit_width"] in [8, 16, 32, 64]:
//::                if aligned_field["mask"]:
    bool check_${case_id}_${branch_id} = (((${helpers.hton_postfix[aligned_field["bit_width"]]}(${header_name}->hdr.${aligned_field["name"]}) & ${hex(aligned_field["mask"])}) >> ${aligned_field["bit_offset_hdr"]}) == ${hex(helpers.byte_array_to_int(case_value[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))}); \
//::                else:
    bool check_${case_id}_${branch_id} = (${helpers.hton_postfix[aligned_field["bit_width"]]}(${header_name}->hdr.${aligned_field["name"]}) == ${hex(helpers.byte_array_to_int(case_value[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))}); \
//::                #endif
//::                key_id += helpers.key_id_ofs[aligned_field["bit_width"]]
//::              elif aligned_field["bit_width"] <= 64:
//::                if aligned_field["mask"]:
    bool check_${case_id}_${branch_id} = false; \
    { \
        uint64_t temp = 0; \
//::                  for i in range(aligned_field["bit_width"]/8):
        temp |= ((const uint8_t *) &${header_name}->hdr.${aligned_field["name"]})[${i}]; temp <<= (${aligned_field["bit_width"]} - (8 * (${i} + 1))); \
//::                  #endfor
        check_${case_id}_${branch_id} = ((temp & ${hex(aligned_field["mask"])}) >> ${aligned_field["bit_offset_hdr"]} == ${hex(helpers.byte_array_to_int(case_value[key_id:key_id + (aligned_field["bit_width"]/8)]))}); \
    } \
//::                else:
    bool check_${case_id}_${branch_id} = false; \
    { \
        uint64_t temp = 0; \
//::                  for i in range(aligned_field["bit_width"]/8):
        temp |= ((const uint8_t *) &${header_name}->hdr.${aligned_field["name"]})[${i}]; temp <<= (${aligned_field["bit_width"]} - (8 * (${i} + 1))); \
//::                  #endfor
        check_${case_id}_${branch_id} = (temp == ${hex(helpers.byte_array_to_int(case_value[key_id:key_id + (aligned_field["bit_width"]/8)]))}); \
    } \
//::                #endif
//::                key_id += aligned_field["bit_width"]/8
//::              else:
//::                # TODO: right now only covers up to 64 bits, look into how to extend this range.
//::                assert(False)
//::              #endif
//::            elif header_name in ordered_header_instances_metadata:
//::              if aligned_field["bit_width"] in [8, 16, 32, 64]:
//::                if aligned_field_mask:
    bool check_${case_id}_${branch_id} = (((${helpers.hton_postfix[aligned_field["bit_width"]]}(${header_name}.hdr.${aligned_field["name"]}) & ${hex(aligned_field["mask"])}) >> ${aligned_field["bit_offset_hdr"]}) == ${hex(helpers.byte_array_to_int(case_value[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))}); \
//::                else:
    bool check_${case_id}_${branch_id} = (${helpers.hton_postfix[aligned_field["bit_width"]]}(${header_name}.hdr.${aligned_field["name"]}) == ${hex(helpers.byte_array_to_int(case_value[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))}); \
//::                #endif
//::                key_id += helpers.key_id_ofs[aligned_field["bit_width"]]
//::              elif aligned_field["bit_width"] <= 64:
//::                if aligned_field["mask"]:
    bool check_${case_id}_${branch_id} = false; \
    { \
        uint64_t temp = 0; \
//::                  for i in range(aligned_field["bit_width"]/8):
        temp |= ((const uint8_t *) &${header_name}.hdr.${aligned_field["name"]})[${i}]; temp <<= (${aligned_field["bit_width"]} - (8 * (${i} + 1))); \
//::                  #endfor
        check_${case_id}_${branch_id} = ((temp & ${hex(aligned_field["mask"])}) >> ${aligned_field["bit_offset_hdr"]} == ${hex(helpers.byte_array_to_int(case_value[key_id:key_id + (aligned_field["bit_width"]/8)]))}); \
    } \
//::                else:
    bool check_${case_id}_${branch_id} = false; \
    { \
        uint64_t temp = 0; \
//::                  for i in range(aligned_field["bit_width"]/8):
        temp |= ((const uint8_t *) &${header_name}.hdr.${aligned_field["name"]})[${i}]; temp <<= (${aligned_field["bit_width"]} - (8 * (${i} + 1))); \
//::                  #endfor
        check_${case_id}_${branch_id} = (temp == ${hex(helpers.byte_array_to_int(case_value[key_id:key_id + (aligned_field["bit_width"]/8)]))}); \
    } \
//::                #endif
//::                key_id += aligned_field["bit_width"]/8
//::              else:
//::                # TODO: right now only covers up to 64 bits, look into how to extend this range.
//::                assert(False)
//::              #endif
//::            #endif
//::          elif key_type == "current":
//::            key_bit_offset, key_bit_width = key_value
//::            aligned_key = {}
//::            aligned_key["bit_base_offset"] = int(key_bit_offset/8)*8
//::            aligned_key["bit_offset"] = key_bit_offset - aligned_key["bit_base_offset"]
//::            aligned_key["bit_width"] = int(helpers.ceil((aligned_key["bit_offset"]+key_bit_width)/8.0) * 8)
//::            aligned_key["bit_offset_hdr"] = aligned_key["bit_width"] - ((aligned_key["bit_offset"] % aligned_key["bit_width"]) + key_bit_width)
//::            aligned_key["mask"] = ((1 << key_bit_width) - 1) << aligned_key["bit_offset_hdr"]
//::            aligned_key["mask"] = 0 if (((1 << aligned_key["bit_width"]) - 1) == aligned_key["mask"]) else aligned_key["mask"]
    if (OVS_UNLIKELY(size < (${aligned_key["bit_base_offset"]/8} + ${aligned_key["bit_width"]/8}))) { OVS_MINIFLOW_OUT } \
//::            if aligned_key["bit_width"] in [8, 16, 32, 64]:
//::              if aligned_key["mask"]:
    bool check_${case_id}_${branch_id} = (((${helpers.hton_postfix[aligned_field["bit_width"]]}((*(${helpers.std_type[aligned_field["bit_width"]]} *) (((char *) data) + ${aligned_key["bit_base_offset"]/8}))) & ${hex(aligned_key["mask"])}) >> ${aligned_key["bit_offset_hdr"]}) == ${hex(helpers.byte_array_to_int(case_value[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))}); \
//::              else:
    bool check_${case_id}_${branch_id} = (${helpers.hton_postfix[aligned_field["bit_width"]]}((*(${helpers.std_type[aligned_field["bit_width"]]} *) (((char *) data) + ${aligned_key["bit_base_offset"]/8}))) == ${hex(helpers.byte_array_to_int(case_value[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))}); \
//::              #endif
//::              key_id += helpers.key_id_ofs[aligned_field["bit_width"]]
//::            else:
//::              # TODO: right now only covers up to 64 bits, look into how to extend this range.
//::              assert(False)
//::            #endif
//::          else:
//::            assert(False)
//::          #endif
//::          branch_id += 1
//::        #endfor
    if ( \
//::        branch_id = 0
//::        for key_type, key_value in branch_on:
        check_${case_id}_${branch_id} && \
//::          branch_id += 1
//::        #endfor
        true) \
//::      elif case_type == "value_masked":
//::        branch_id = 0
//::        key_id = 0
//::        for key_type, key_value in branch_on:
//::          if key_type == "field_ref":
//::            header_name = field_info[key_value]["parent_header"]
//::            aligned_field = {"name": aligned_field_info[key_value]["name"],
//::                             "mask": aligned_field_info[key_value]["mask"],
//::                             "bit_offset_hdr": aligned_field_info[key_value]["bit_offset_hdr"],
//::                             "bit_width": aligned_field_info[key_value]["bit_width"]}
//::            if header_name in ordered_header_instances_regular:
//::              if aligned_field["bit_width"] in [8, 16, 32, 64]:
//::                if aligned_field["mask"]:
    bool check_${case_id}_${branch_id} = (((${helpers.hton_postfix[aligned_field["bit_width"]]}(${header_name}->hdr.${aligned_field["name"]}) & ${hex(aligned_field["mask"])}) >> ${aligned_field["bit_offset_hdr"]}) == (${hex(helpers.byte_array_to_int(case_value[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))} & ${hex(byte_array_to_int(case_mask[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))})); \
//::                else:
    bool check_${case_id}_${branch_id} = (${helpers.hton_postfix[aligned_field["bit_width"]]}(${header_name}->hdr.${aligned_field["name"]}) == (${hex(helpers.byte_array_to_int(case_value[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))} & ${hex(byte_array_to_int(case_mask[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))})); \
//::                #endif
//::                key_id += helpers.key_id_ofs[aligned_field["bit_width"]]
//::              elif aligned_field["bit_width"] <= 64:
//::                if aligned_field["mask"]:
    bool check_${case_id}_${branch_id} = false; \
    { \
        uint64_t temp = 0; \
//::                  for i in range(aligned_field["bit_width"]/8):
        temp |= ((const uint8_t *) &${header_name}->hdr.${aligned_field["name"]})[${i}]; temp <<= (${aligned_field["bit_width"]} - (8 * (${i} + 1))); \
//::                  #endfor
        check_${case_id}_${branch_id} = ((temp & ${hex(aligned_field["mask"])}) >> ${aligned_field["bit_offset_hdr"]} == (${hex(helpers.byte_array_to_int(case_value[key_id:key_id + (aligned_field["bit_width"]/8)]))} & ${hex(helpers.byte_array_to_int(case_mask[key_id:key_id + (aligned_field["bit_width"]/8)]))})); \
    } \
//::                else:
    bool check_${case_id}_${branch_id} = false; \
    { \
        uint64_t temp = 0; \
//::                  for i in range(aligned_field["bit_width"]/8):
        temp |= ((const uint8_t *) &${header_name}->hdr.${aligned_field["name"]})[${i}]; temp <<= (${aligned_field["bit_width"]} - (8 * (${i} + 1))); \
//::                  #endfor
        check_${case_id}_${branch_id} = (temp == (${hex(helpers.byte_array_to_int(case_value[key_id:key_id + (aligned_field["bit_width"]/8)]))} & ${hex(helpers.byte_array_to_int(case_mask[key_id:key_id + (aligned_field["bit_width"]/8)]))})); \
    } \
//::                #endif
//::                key_id += aligned_field["bit_width"]/8
//::              else:
//::                # TODO: right now only covers up to 64 bits, look into how to extend this range.
//::                assert(False)
//::              #endif
//::            elif header_name in ordered_header_instances_metadata:
//::              if aligned_field["bit_width"] in [8, 16, 32, 64]:
//::                if aligned_field["mask"]:
    bool check_${case_id}_${branch_id} = (((${helpers.hton_postfix[aligned_field["bit_width"]]}(${header_name}.hdr.${aligned_field["name"]}) & ${hex(aligned_field["mask"])}) >> ${aligned_field["bit_offset_hdr"]}) == (${hex(helpers.byte_array_to_int(case_value[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))} & ${hex(helpers.byte_array_to_int(case_mask[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))})); \
//::                else:
    bool check_${case_id}_${branch_id} = (${helpers.hton_postfix[aligned_field["bit_width"]]}(${header_name}.hdr.${aligned_field["name"]}) == (${hex(helpers.byte_array_to_int(case_value[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))} & ${hex(helpers.byte_array_to_int(case_mask[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))})); \
//::                #endif
//::                key_id += helpers.key_id_ofs[aligned_field["bit_width"]]
//::              elif aligned_field["bit_width"] <= 64:
//::                if aligned_field["mask"]:
    bool check_${case_id}_${branch_id} = false; \
    { \
        uint64_t temp = 0; \
//::                  for i in range(aligned_field["bit_width"]/8):
        temp |= ((const uint8_t *) &_${header_name}.hdr.${aligned_field["name"]})[${i}]; temp <<= (${aligned_field["bit_width"]} - (8 * (${i} + 1))); \
//::                  #endfor
        check_${case_id}_${branch_id} = ((temp & ${hex(aligned_field["mask"])}) >> ${aligned_field["bit_offset_hdr"]} == (${hex(helpers.byte_array_to_int(case_value[key_id:key_id + (aligned_field["bit_width"]/8)]))} & ${hex(helpers.byte_array_to_int(case_mask[key_id:key_id + (aligned_field["bit_width"]/8)]))})); \
    } \
//::                else:
    bool check_${case_id}_${branch_id} = false; \
    { \
        uint64_t temp = 0; \
//::                  for i in range(aligned_field["bit_width"]/8):
        temp |= ((const uint8_t *) &_${header_name}.hdr.${aligned_field["name"]})[${i}]; temp <<= (${aligned_field["bit_width"]} - (8 * (${i} + 1))); \
//::                  #endfor
        check_${case_id}_${branch_id} = (temp == (${hex(helpers.byte_array_to_int(case_value[key_id:key_id + (aligned_field["bit_width"]/8)]))} & ${hex(helpers.byte_array_to_int(case_mask[key_id:key_id + (aligned_field["bit_width"]/8)]))})); \
    } \
//::                #endif
//::                key_id += aligned_field["bit_width"]/8
//::              else:
//::                # TODO: right now only covers up to 64 bits, look into how to extend this range.
//::                assert(False)
//::              #endif
//::            #endif
//::          elif key_type == "current":
//::            key_bit_offset, key_bit_width = key_value
//::            aligned_key = {}
//::            aligned_key["bit_base_offset"] = int(key_bit_offset/8)*8
//::            aligned_key["bit_offset"] = key_bit_offset - aligned_key["bit_base_offset"]
//::            aligned_key["bit_width"] = int(helpers.ceil((aligned_key["bit_offset"]+key_bit_width)/8.0) * 8)
//::            aligned_key["bit_offset_hdr"] = aligned_key["bit_width"] - ((aligned_key["bit_offset"] % aligned_key["bit_width"]) + key_bit_width)
//::            aligned_key["mask"] = ((1 << key_bit_width) - 1) << aligned_key["bit_offset_hdr"]
//::            aligned_key["mask"] = 0 if (((1 << aligned_key["bit_width"]) - 1) == aligned_key["mask"]) else aligned_key["mask"]
    if (OVS_UNLIKELY(size < (${aligned_key["bit_base_offset"]/8} + ${aligned_key["bit_width"]/8}))) { OVS_MINIFLOW_OUT } \
//::            if aligned_key["bit_width"] in [8, 16, 32, 64]:
//::              if aligned_key["mask"]:
    bool check_${case_id}_${branch_id} = (((${helpers.hton_postfix[aligned_field["bit_width"]]}((*(${helpers.std_type[aligned_field["bit_width"]]} *) (((char *) data) + ${aligned_key["bit_base_offset"]/8}))) & ${hex(aligned_key["mask"])}) >> ${aligned_key["bit_offset_hdr"]}) == (${hex(helpers.byte_array_to_int(case_value[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))} & ${hex(helpers.byte_array_to_int(case_mask[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))})); \
//::              else:
    bool check_${case_id}_${branch_id} = (${helpers.hton_postfix[aligned_field["bit_width"]]}((*(${helpers.std_type[aligned_field["bit_width"]]} *) (((char *) data) + ${aligned_key["bit_base_offset"]/8}))) == (${hex(helpers.byte_array_to_int(case_value[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))} & ${hex(helpers.byte_array_to_int(case_mask[key_id:key_id + helpers.key_id_ofs[aligned_field["bit_width"]]]))})); \
//::              #endif
//::              key_id += helpers.key_id_ofs[aligned_field["bit_width"]]
//::            else:
//::              # TODO: right now only covers up to 64 bits, look into how to extend this range.
//::              assert(False)
//::            #endif
//::          else:
//::            assert(False)
//::          #endif
//::          branch_id += 1
//::        #endfor
    if ( \
//::        branch_id = 0
//::        for key_type, key_value in branch_on:
        check_${case_id}_${branch_id} && \
//::          branch_id += 1
//::        #endfor
        true) \
//::      elif case_type == "default":
//::        pass
//::      else:
//::        assert(False)
//::      #endif
    { \
//::      if case_next_state[0] == "parse_state":
        OVS_MINIFLOW_${case_next_state[1].upper()} \
//::      elif case_next_state[0] == "table" or case_next_state[0] == "conditional_table":
        OVS_MINIFLOW_OUT \
//::      else:
//::        assert(False)
//::      #endif
    } \
    \
//::      case_id += 1
//::    #endfor

//::  #endfor
//::
#define OVS_MINIFLOW_OUT \
//::  for header_name in ordered_header_instances_metadata:
    if (OVS_LIKELY(is_${header_name}_header_touched)) \
    { \
        miniflow_push_bytes_word_aligned_64(mf, ${header_name}, &${header_name}, sizeof(struct ${header_name}_header), \
        sizeof(struct ${header_name}_padded_header) / sizeof(uint64_t)); \
    } \
//::  #endfor
    \
	miniflow_push_bytes_word_aligned_64(mf, valid, &valid, sizeof(struct valid_header), \
            sizeof(struct valid_padded_header) / sizeof(uint64_t)); \
    goto out_; \
    \

/* -- Used in lib/flow.c -- */
#define OVS_FLOW_WC_MASK \
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in ordered_header_instances_metadata:
    WC_MASK_FIELD(wc, ${header_name}); \
//::  #endfor
//::  for header_name in ordered_header_instances_regular:
    if (flow->valid.hdr.${header_name}_valid == 1) { \
        WC_MASK_FIELD(wc, ${header_name}); \
    } \
//::  #endfor
	\

/* -- Used in lib/flow.c -- */
#define OVS_FLOW_WC_MAP \
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in ordered_header_instances_metadata:
    FLOWMAP_SET(map, ${header_name}); \
//::  #endfor
//::  for header_name in ordered_header_instances_regular:
    if (flow->valid.hdr.${header_name}_valid == 1) { \
        FLOWMAP_SET(map, ${header_name}); \
    } \
//::  #endfor
    FLOWMAP_SET(map, valid); \
    \

#endif	/* OVS_LIB_FLOW_C_H */
