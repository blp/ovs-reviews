/*
 * Copyright (c) 2014, 2016, 2017 Nicira, Inc.
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

#ifndef MC_H
#define MC_H 1

#include "uuid.h"


enum mc_rpc_client_msg_type {
    MC_RPC_CHOOSE,
    MC_RPC_ASSERT
};

enum mc_rpc_choose_req_type {
    MC_RPC_CHOOSE_LOG_OPEN,
    MC_RPC_CHOOSE_LOG_READ,
    MC_RPC_CHOOSE_LOG_WRITE,
    MC_RPC_CHOOSE_LOG_COMMIT,
    MC_RPC_CHOOSE_LOG_REPLACE_START,
    MC_RPC_CHOOSE_LOG_REPLACE_COMMIT,
    MC_RPC_CHOOSE_TIMER,
    MC_RPC_CHOOSE_NETWORK_OPEN,
    MC_RPC_CHOOSE_NETWORK_SEND,
    MC_RPC_CHOOSE_NETWORK_RECV,
    MC_RPC_NONE
};

struct mc_rpc_client_msg_common {
    enum mc_rpc_client_msg_type type;
    struct uuid sid;
};

struct mc_rpc_choose_req {
    struct mc_rpc_client_msg_common common;
    enum mc_rpc_choose_req_type type;
};

enum mc_rpc_server_msg_type {
    MC_RPC_REPLY_NORMAL,
    MC_RPC_REPLY_ERROR
};

struct mc_rpc_choose_reply {
    enum mc_rpc_server_msg_type type;
};

#endif /* tests/mc/mc.h */
