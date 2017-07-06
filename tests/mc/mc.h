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

enum mc_rpc_msg_type {
    MC_RPC_HELLO,
    MC_RPC_CHOOSE_REQ,
    MC_RPC_CHOOSE_REPLY,
    MC_RPC_ASSERT
};

enum mc_rpc_choose_req_type {
    MC_RPC_CHOOSE_REQ_LOG,
    MC_RPC_CHOOSE_REQ_TIMER,
    MC_RPC_CHOOSE_REQ_NETWORK,
};

enum mc_rpc_choose_subtype {
    MC_RPC_SUBTYPE_OPEN,
    MC_RPC_SUBTYPE_READ,
    MC_RPC_SUBTYPE_WRITE,
    MC_RPC_SUBTYPE_SEND,
    MC_RPC_SUBTYPE_RECV,
    MC_RPC_SUBTYPE_COMMIT,
    MC_RPC_SUBTYPE_REPLACE_START,
    MC_RPC_SUBTYPE_REPLACE_COMMIT
};

enum mc_rpc_choose_reply_type {
    MC_RPC_CHOOSE_REPLY_NORMAL,
    MC_RPC_CHOOSE_REPLY_ERROR,
};

struct mc_rpc_common {
    enum mc_rpc_msg_type type;
    /* Due to the single machine setup
     * pid is a good way to identify the 
     * sender given that the model checker 
     * spawns all processes */
    pid_t pid;
};

struct mc_rpc_hello {
    struct mc_rpc_common common;
};

struct mc_rpc_choose_req {
    struct mc_rpc_common common;
    enum mc_rpc_choose_req_type type;
    enum mc_rpc_choose_subtype subtype;
    void* data;
};

struct mc_rpc_choose_reply {
    struct mc_rpc_common common;
    enum mc_rpc_choose_reply_type reply;
};

#endif /* tests/mc/mc.h */
