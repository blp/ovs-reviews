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

#include "process.h"

#define MC_RPC_TYPES						\
    MC_RPC(MC_RPC_HELLO, "mc_hello")				\
    MC_RPC(MC_RPC_BYE, "mc_bye")				\
    MC_RPC(MC_RPC_CHOOSE_REQ, "mc_choose_req")			\
    MC_RPC(MC_RPC_CHOOSE_REPLY, "mc_choose_reply")		\
    MC_RPC(MC_RPC_ASSERT, "mc_assert")				\
    
enum mc_rpc_type {
#define MC_RPC(ENUM, NAME) ENUM,
    MC_RPC_TYPES
#undef MC_RPC
};

#define MC_RPC_CHOOSE_TYPES						\
    MC_RPC_CHOOSE(MC_RPC_CHOOSE_REQ_LOG, "mc_rpc_choose_req_log")	\
    MC_RPC_CHOOSE(MC_RPC_CHOOSE_REQ_TIMER, "mc_rpc_choose_req_timer")	\
    MC_RPC_CHOOSE(MC_RPC_CHOOSE_REQ_NETWORK, "mc_rpc_choose_req_network") \
    MC_RPC_CHOOSE(MC_RPC_CHOOSE_REQ_UNIXCTL, "mc_rpc_choose_req_unixctl") \
    
enum mc_rpc_choose_req_type {
#define MC_RPC_CHOOSE(ENUM, NAME) ENUM,
    MC_RPC_CHOOSE_TYPES
#undef MC_RPC_CHOOSE
};

#define MC_RPC_SUBTYPES							\
    MC_RPC_SUBTYPE(MC_RPC_SUBTYPE_OPEN, "mc_rpc_subtype_open")		\
    MC_RPC_SUBTYPE(MC_RPC_SUBTYPE_CLIENT_CREATE, "mc_rpc_subtype_client_create") \
    MC_RPC_SUBTYPE(MC_RPC_SUBTYPE_SERVER_CREATE, "mc_rpc_subtype_server_create") \
    MC_RPC_SUBTYPE(MC_RPC_SUBTYPE_CLIENT_TRANSACT, "mc_rpc_subtype_client_transact") \
    MC_RPC_SUBTYPE(MC_RPC_SUBTYPE_SERVER_RECV, "mc_rpc_subtype_server_recv") \
    MC_RPC_SUBTYPE(MC_RPC_SUBTYPE_READ, "mc_rpc_subtype_read")		\
    MC_RPC_SUBTYPE(MC_RPC_SUBTYPE_WRITE, "mc_rpc_subtype_write")	\
    MC_RPC_SUBTYPE(MC_RPC_SUBTYPE_SEND, "mc_rpc_subtype_send")		\
    MC_RPC_SUBTYPE(MC_RPC_SUBTYPE_RECV, "mc_rpc_subtype_recv")		\
    MC_RPC_SUBTYPE(MC_RPC_SUBTYPE_COMMIT, "mc_rpc_subtype_commit")	\
    MC_RPC_SUBTYPE(MC_RPC_SUBTYPE_REPLACE_START, "mc_rpc_subtype_replace_start") \
    MC_RPC_SUBTYPE(MC_RPC_SUBTYPE_REPLACE_COMMIT, "mc_rpc_subtype_replace_commit") \
    
enum mc_rpc_subtype {
#define MC_RPC_SUBTYPE(ENUM, NAME) ENUM,
    MC_RPC_SUBTYPES
#undef MC_RPC_SUBTYPE
};

enum mc_rpc_choose_reply_type {
    MC_RPC_CHOOSE_REPLY_NORMAL,
    MC_RPC_CHOOSE_REPLY_ERROR,
};

struct mc_rpc_common {
    enum mc_rpc_type type;
    /* Due to the single machine setup
     * pid is a good way to identify the 
     * sender given that the model checker 
     * spawns all processes */
    pid_t pid;
    int tid;
};

struct mc_rpc_choose_req {
    struct mc_rpc_common common;
    enum mc_rpc_choose_req_type type;
    enum mc_rpc_subtype subtype;
    /* Data specific to a particular action
     * e.g. a log write or a network send */
    void *data;
};

struct mc_rpc_choose_reply {
    struct mc_rpc_common common;
    enum mc_rpc_choose_reply_type reply;
};

union mc_rpc {
    struct mc_rpc_common common;
    struct mc_rpc_choose_req choose_req;
    struct mc_rpc_choose_reply choose_reply;
};

struct jsonrpc_msg *mc_rpc_to_jsonrpc(const union mc_rpc *rpc);
void mc_rpc_from_jsonrpc(const struct jsonrpc_msg *msg, union mc_rpc *rpc);

#endif /* tests/mc/mc.h */
