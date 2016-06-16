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

#include <config.h>
#include <grpc/grpc.h>
#include <grpc/impl/codegen/byte_buffer_reader.h>
#include <stdio.h>

#include "util.h"

int
main(int argc, char *argv[])
{
    if (argc == 2 && !strcmp(argv[1], "client")) {
        grpc_init();
        grpc_channel *channel = grpc_insecure_channel_create(
            "127.0.0.1:50051", NULL, NULL);
        void *call_handle = grpc_channel_register_call(
            channel, "/helloworld.Greeter/SayHello", NULL, NULL);
        grpc_completion_queue *cq = grpc_completion_queue_create(NULL);
        grpc_call *call = grpc_channel_create_registered_call(
            channel, NULL, UINT16_MAX /* ??? */, cq, call_handle,
            gpr_inf_future(GPR_CLOCK_REALTIME), NULL);

        char data[7] = "\n\005world";
        gpr_slice slice = gpr_slice_from_copied_buffer(data, sizeof data);
        grpc_byte_buffer *send_bb = grpc_raw_byte_buffer_create(&slice, 1);
        grpc_byte_buffer *recv_bb = NULL;

        grpc_metadata_array recv_initial_metadata;
        grpc_metadata_array_init(&recv_initial_metadata);
        grpc_metadata_array recv_trailing_metadata;
        grpc_metadata_array_init(&recv_trailing_metadata);
        grpc_status_code status;
        char *status_details = NULL;
        size_t status_details_capacity = 0;

        grpc_op ops[6] = {
            { .op = GRPC_OP_SEND_INITIAL_METADATA },
            { .op = GRPC_OP_SEND_MESSAGE, .data.send_message = send_bb },
            { .op = GRPC_OP_RECV_INITIAL_METADATA,
              .data.recv_initial_metadata = &recv_initial_metadata },
            { .op = GRPC_OP_RECV_MESSAGE, .data.recv_message = &recv_bb },
            { .op = GRPC_OP_SEND_CLOSE_FROM_CLIENT },
            { .op = GRPC_OP_RECV_STATUS_ON_CLIENT,
              .data.recv_status_on_client = {
                    .trailing_metadata = &recv_trailing_metadata,
                    .status = &status,
                    .status_details = &status_details,
                    .status_details_capacity = &status_details_capacity,
                }
            },
        };
        grpc_call_error error = grpc_call_start_batch(call, ops,
                                                      ARRAY_SIZE(ops),
                                                      NULL /* XXX */, NULL);
        if (error) {
            ovs_fatal(0, "grpc_call_start_batch returned %d", error);
        }

        grpc_event event = grpc_completion_queue_next(
            cq, gpr_inf_future(GPR_CLOCK_REALTIME), NULL);
        printf("%d, %d\n", event.type, event.success);

        grpc_byte_buffer_reader r;
        grpc_byte_buffer_reader_init(&r, recv_bb);
        gpr_slice s;
        size_t ofs = 0;
        while (grpc_byte_buffer_reader_next(&r, &s)) {
            const uint8_t *data = GPR_SLICE_START_PTR(s);
            size_t length = GPR_SLICE_LENGTH(s);
            ovs_hex_dump(stdout, data, length, ofs, true);
            ofs += length;
        }
        grpc_byte_buffer_reader_destroy(&r);
    } else if (argc == 2 && !strcmp(argv[1], "server")) {
        grpc_init();
        grpc_server *server = grpc_server_create(NULL, NULL);
        grpc_server_register_method(server, "/helloworld.Greeter/SayHello",
                                    NULL,
                                    GRPC_SRM_PAYLOAD_READ_INITIAL_BYTE_BUFFER,
                                    0);

    } else {
        ovs_fatal(0, "usage: %s client|server", argv[0]);
    }
    return 0;
}
