
import math
ceil = math.ceil


def byte_array_to_int(byte_array):
    result = 0
    length = len(byte_array)
    for i in xrange(length):
        result += byte_array[length - 1 - i] << (8 * i)
    return result


hton_postfix = {8: "", 16: "htons", 32: "htonl", 64: "htonll"}
key_id_ofs = {8: 4, 16: 4, 32: 4, 64: 8}
std_type = {8: "uint8_t", 16: "ovs_be16", 32: "ovs_be32", 64: "ovs_be64"}
std_type_prefix = {8: "u8", 16: "be16", 32: "be32", 64: "be64"}


def get_ordered_header_instances_non_virtual(ordered_header_instances_non_virtual):
    return [header_name for header_name in ordered_header_instances_non_virtual
            if header_name != "standard_metadata" and header_name != "intrinsic_metadata"]


def get_ordered_header_instances_metadata(ordered_header_instances_metadata):
    return [header_name for header_name in ordered_header_instances_metadata
            if header_name != "standard_metadata" and header_name != "intrinsic_metadata"]

def get_align_field_info(field_info, header_info, ordered_header_instances_all):
    aligned_field_info = {}
    for header_name in ordered_header_instances_all:
        header = header_info[header_name]
        field_names = []
        run_bit_width = 0
        for field_name in header['fields']:
            bit_width = field_info[field_name]['bit_width']
            run_bit_width += bit_width
            if run_bit_width % 8 == 0:
                if field_names:
                    # We are assuming that smaller fields (i.e., less than a byte)
                    # combine together to align on a byte boundary.
                    if run_bit_width <= 1024:
                        field_names += [field_name]
                        total_bit_width = sum([field_info[f]['bit_width'] for f in field_names])
                        trunc_field_names = [f[len(header_name) + 1:] for f in field_names]
                        aligned_field_name = header_name + '_' + reduce(lambda x, y: x + '_' + y, trunc_field_names)
                        run_bit_width = 0
                        field_names.reverse()
                        for field_name in field_names:
                            bit_width = field_info[field_name]['bit_width']
                            # TODO: this may break for fields greater than 64 bits, look into this!
                            mask = (2 ** bit_width - 1) << run_bit_width
                            aligned_field_info[field_name] = {"name": aligned_field_name,
                                                              "bit_width": total_bit_width,
                                                              "mask": mask,
                                                              "bit_offset_hdr": run_bit_width}
                            run_bit_width += bit_width
                    else:
                        # The aligned field's size is larger than 1024 (something isn't right!)
                        assert(False)
                else:
                    aligned_field_name = header_name + '_' + field_name[len(header_name) + 1:]
                    aligned_field_info[field_name] = {"name": aligned_field_name,
                                                      "bit_width": bit_width,
                                                      "mask": 0,
                                                      "bit_offset_hdr": 0}
                run_bit_width = 0
                field_names = []
            else:
                field_names += [field_name]
    return aligned_field_info


def get_ordered_header_and_aligned_field_instances_non_virtual__name_width(ordered_header_instances_non_virtual,
                                                                           header_info, aligned_field_info):
    ordered_aligned_field_instances_non_virtual__name_width = []
    ordered_header_instances_non_virtual_aligned_field__name_width = {}
    for header_name in ordered_header_instances_non_virtual:
        ordered_header_instances_non_virtual_aligned_field__name_width[header_name] = []
        processed_fields = []
        for field_name in header_info[header_name]["fields"]:
            bit_width = aligned_field_info[field_name]["bit_width"]
            field_name = aligned_field_info[field_name]["name"]
            if field_name in processed_fields:
                continue
            processed_fields += [field_name]
            ordered_aligned_field_instances_non_virtual__name_width += [(field_name, bit_width)]
            ordered_header_instances_non_virtual_aligned_field__name_width[header_name] += [(field_name,
                                                                                             bit_width)]
    return (ordered_aligned_field_instances_non_virtual__name_width,
            ordered_header_instances_non_virtual_aligned_field__name_width)
