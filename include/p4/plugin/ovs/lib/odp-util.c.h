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

#ifndef OVS_LIB_ODP_UTIL_C_H
#define	OVS_LIB_ODP_UTIL_C_H 1

/* -- Used in lib/odp-util.c -- */
#define OVS_KEY_ATTRS_TO_STRING_CASES \
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in ordered_header_instances_non_virtual:
    case OVS_KEY_ATTR_${header_name.upper()}: return "${header_name}"; \
//::  #endfor
    case OVS_KEY_ATTR_VALID: return "valid"; \
    \

/* -- Used in lib/odp-util.c -- */
#define OVS_FORMAT_ODP_KEY_ATTR_CASES \
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in ordered_header_instances_non_virtual:
    case OVS_KEY_ATTR_${header_name.upper()}: { \
        break; \
    } \
//::  #endfor
    case OVS_KEY_ATTR_VALID: { \
        break; \
    } \
    \

/* These are disabled to avoid spurious test failures. */
#define OVS_FORMAT_ODP_KEY_ATTR_CASES_DISABLED \
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in ordered_header_instances_non_virtual:
    case OVS_KEY_ATTR_${header_name.upper()}: { \
        const struct ovs_key_${header_name} *key = nl_attr_get(a); \
        const struct ovs_key_${header_name} *mask = ma ? nl_attr_get(ma) : NULL; \
        \
//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
//::      if bit_width in [8, 16, 32, 64]:
        format_u${bit_width}x(ds, "${field_name}", key->${field_name}, MASK(mask, ${field_name}), verbose); \
//::      else:
        format_bex(ds, "${field_name}", (const uint8_t *) &key->${field_name}, \
                   mask ? (const uint8_t (*)[]) &mask->${field_name} : NULL, \
                   sizeof(struct ${field_name}_t), verbose); \
//::      #endif
//::    #endfor
        ds_chomp(ds, ','); \
        break; \
    } \
//::  #endfor
    case OVS_KEY_ATTR_VALID: { \
        const struct ovs_key_valid *key = nl_attr_get(a); \
        const struct ovs_key_valid *mask = ma ? nl_attr_get(ma) : NULL; \
        \
//::  for header_name in ordered_header_instances_regular:
        format_u8x(ds, "${header_name}_valid", key->${header_name}_valid, MASK(mask, ${header_name}_valid), verbose); \
//::  #endfor
        ds_chomp(ds, ','); \
        break; \
    } \
    \

/* -- Used in lib/odp-util.c -- */
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in ordered_header_instances_non_virtual:
static void get_${header_name}_key(const struct flow *flow, struct ovs_key_${header_name} *${header_name});
static void put_${header_name}_key(const struct ovs_key_${header_name} *${header_name}, struct flow *flow);

//::  #endfor
//::
static void get_valid_key(const struct flow *flow, struct ovs_key_valid *valid);
static void put_valid_key(const struct ovs_key_valid *valid, struct flow *flow);

/* -- Used in lib/odp-util.c -- */
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in ordered_header_instances_non_virtual:
static void get_${header_name}_key(const struct flow *flow, struct ovs_key_${header_name} *${header_name})
{
//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
    ${header_name}->${field_name} = flow->${header_name}.hdr.${field_name};
//::    #endfor
}
static void put_${header_name}_key(const struct ovs_key_${header_name} *${header_name}, struct flow *flow)
{
//::    for field_name, bit_width in ordered_header_instances_non_virtual_aligned_field__name_width[header_name]:
    flow->${header_name}.hdr.${field_name} = ${header_name}->${field_name};
//::    #endfor
}

//::  #endfor
//::
static void get_valid_key(const struct flow *flow, struct ovs_key_valid *valid)
{
//::  for header_name in ordered_header_instances_regular:
    valid->${header_name}_valid = flow->valid.hdr.${header_name}_valid;
//::  #endfor
}
static void put_valid_key(const struct ovs_key_valid *valid, struct flow *flow)
{
//::  for header_name in ordered_header_instances_regular:
    flow->valid.hdr.${header_name}_valid = valid->${header_name}_valid;
//::  #endfor
}

/* -- Used in lib/odp-util.c -- */
//::  for header_name in ordered_header_instances_regular:
static void commit_set_${header_name}_action(const struct flow *flow, struct flow *base_flow,
               struct ofpbuf *odp_actions,
               struct flow_wildcards *wc,
               bool use_masked)
{
    struct ovs_key_${header_name} key, base, mask;

    get_${header_name}_key(flow, &key);
    get_${header_name}_key(base_flow, &base);
    get_${header_name}_key(&wc->masks, &mask);

    if (commit(OVS_KEY_ATTR_${header_name.upper()}, use_masked,
        &key, &base, &mask, sizeof key, odp_actions)) {
        put_${header_name}_key(&base, base_flow);
        put_${header_name}_key(&mask, &wc->masks);
    }
}

//::  #endfor
//::
static void commit_set_valid_action(const struct flow *flow, struct flow *base_flow,
               struct ofpbuf *odp_actions,
               struct flow_wildcards *wc,
               bool use_masked)
{
    struct ovs_key_valid key, base, mask;

    get_valid_key(flow, &key);
    get_valid_key(base_flow, &base);
    get_valid_key(&wc->masks, &mask);

    if (commit(OVS_KEY_ATTR_VALID, use_masked,
        &key, &base, &mask, sizeof key, odp_actions)) {
            put_valid_key(&base, base_flow);
            put_valid_key(&mask, &wc->masks);
    }
}

/* -- Used in lib/odp-util.c -- */
#define OVS_COMMIT_ODP_ACTIONS_FUNCS \
//::  for header_name in ordered_header_instances_regular:
    commit_set_${header_name}_action(flow, base, odp_actions, wc, use_masked); \
//::  #endfor
    commit_set_valid_action(flow, base, odp_actions, wc, use_masked); \
    \

/* -- Used in lib/odp-util.c -- */
#define OVS_FLOW_KEY_ATTR_LENS \
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in ordered_header_instances_non_virtual:
    [OVS_KEY_ATTR_${header_name.upper()}] = { .len = sizeof(struct ovs_key_${header_name}) }, \
//::  #endfor
    [OVS_KEY_ATTR_VALID] = { .len = sizeof(struct ovs_key_valid) }, \
    \

/* -- Used in lib/odp-util.c -- */
#define OVS_FLOW_KEY_FROM_FLOW \
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in ordered_header_instances_non_virtual:
    struct ovs_key_${header_name} *${header_name}; \
    ${header_name} = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_${header_name.upper()}, sizeof *${header_name}); \
    get_${header_name}_key(data, ${header_name}); \
    \
//::  #endfor
    struct ovs_key_valid *valid; \
    valid = nl_msg_put_unspec_uninit(buf, OVS_KEY_ATTR_VALID, sizeof *valid); \
    get_valid_key(data, valid); \
    \

/* -- Used in lib/odp-util.c -- */
#define OVS_FLOW_KEY_TO_FLOW \
//::  # TODO: remove metadata that is not touched in the parser.
//::  for header_name in ordered_header_instances_non_virtual:
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_${header_name.upper()})) { \
        const struct ovs_key_${header_name} *${header_name}; \
        \
        ${header_name} = nl_attr_get(attrs[OVS_KEY_ATTR_${header_name.upper()}]); \
        put_${header_name}_key(${header_name}, flow); \
        if (is_mask) { \
            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_${header_name.upper()}; \
        } \
    } \
    if (!is_mask) { \
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_${header_name.upper()}; \
    } \
    \
//::  #endfor
    if (present_attrs & (UINT64_C(1) << OVS_KEY_ATTR_VALID)) { \
        const struct ovs_key_valid *valid; \
        \
        valid = nl_attr_get(attrs[OVS_KEY_ATTR_VALID]); \
        put_valid_key(valid, flow); \
        if (is_mask) { \
            expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_VALID; \
        } \
    } \
    if (!is_mask) { \
        expected_attrs |= UINT64_C(1) << OVS_KEY_ATTR_VALID; \
    } \
    \

#endif	/* OVS_LIB_ODP_UTIL_C_H */
