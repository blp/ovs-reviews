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

#include <config.h>
#include <unistd.h>
#include <string.h>
#include "mc.h"
#include "mc_wrap.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(mc_wrap);

static enum mc_rpc_choose_reply_type
mc_wrap_get_choose_reply(struct jsonrpc *mc_conn,
			 enum mc_rpc_choose_req_type type,
			 enum mc_rpc_subtype subtype)
{
    if (mc_conn == NULL) {
	return MC_RPC_CHOOSE_REPLY_NORMAL;
    }
    
    union mc_rpc rpc;
    rpc.common.type = MC_RPC_CHOOSE_REQ;
    rpc.common.pid = getpid();
    rpc.choose_req.type = type;
    rpc.choose_req.subtype = subtype;

    struct jsonrpc_msg *reply;
    int err = jsonrpc_transact_block(mc_conn, mc_rpc_to_jsonrpc(&rpc),
				     &reply);

    if (err != 0) {
	ovs_fatal(err, "Failed to get a reply from model checker");
    }

    memset(&rpc, 0, sizeof(rpc));
    mc_rpc_from_jsonrpc(reply, &rpc);   
    return rpc.choose_reply.reply;
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_open(const char *name,
		       const char *magic,
		       enum ovsdb_log_open_mode open_mode,
		       int locking, struct ovsdb_log **filep,
		       struct jsonrpc *mc_conn)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_LOG,
				     MC_RPC_SUBTYPE_OPEN);

    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return ovsdb_log_open(name, magic, open_mode, locking, filep);
    } else {
	return ovsdb_io_error(0, "Fake model checker error");
    }
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_read(struct ovsdb_log *file, struct json **jsonp,
		       struct jsonrpc *mc_conn)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_LOG,
				     MC_RPC_SUBTYPE_READ);
    
    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return ovsdb_log_read(file, jsonp);
    } else {
	return ovsdb_io_error(0, "Fake model checker error");
    }
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_write(struct ovsdb_log *file, const struct json *json,
			struct jsonrpc *mc_conn)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_LOG,
				     MC_RPC_SUBTYPE_WRITE);
    
    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return ovsdb_log_write(file, json);
    } else {
	return ovsdb_io_error(0, "Fake model checker error");
    }
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_commit(struct ovsdb_log *file,
			 struct jsonrpc *mc_conn)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_LOG,
				     MC_RPC_SUBTYPE_COMMIT);
    
    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return ovsdb_log_commit(file);
    } else {
	return ovsdb_io_error(0, "Fake model checker error");
    }
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_replace_start(struct ovsdb_log *old, struct ovsdb_log **newp,
				struct jsonrpc *mc_conn)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_LOG,
				     MC_RPC_SUBTYPE_REPLACE_START);
    
    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return ovsdb_log_replace_start(old, newp);
    } else {
	return ovsdb_io_error(0, "Fake model checker error");
    }
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_replace_commit(struct ovsdb_log *old, struct ovsdb_log *new,
				 struct jsonrpc *mc_conn)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_LOG,
				     MC_RPC_SUBTYPE_REPLACE_COMMIT);
    
    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return ovsdb_log_replace_commit(old, new);
    } else {
	return ovsdb_io_error(0, "Fake model checker error");
    }
}

int
mc_wrap_unixctl_client_create(const char *path, struct jsonrpc **client,
			      struct jsonrpc *mc_conn)
{
    return unixctl_client_create(path, client);
}

int
mc_wrap_unixctl_client_transact(struct jsonrpc *client,
				const char *command,
				int argc, char *argv[],
				char **result, char **error,
				struct jsonrpc *mc_conn)
{
    return unixctl_client_transact(client, command, argc,
				   argv, result, error);
}
