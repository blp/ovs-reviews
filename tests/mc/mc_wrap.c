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
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "mc_wrap.h"
#include "openvswitch/vlog.h"
#include "stream.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(mc_wrap);

struct jsonrpc *
mc_wrap_connect(char *mc_addr)
{
    if (mc_addr) {
	struct stream *s;
	int error = stream_open(mc_addr, &s, DSCP_DEFAULT);
	if (error != 0) {
	    ovs_fatal(0, "Can't connect to model checker, %s\n",
		      ovs_strerror(error));
	}
	return jsonrpc_open(s);
    }

    return NULL;
}

/* Use this to send a hello or bye RPC to the Model Checker 
 * at the start and exit of all threads (including the
 * main thread). Importantly this must be done before the thread
 * in question does any operations that are interposed on by
 * the model checker. 
 *
 * The tid (or thread id) is an argument that needs to be specified
 * very carefully. The caller must ensure the property that (assuming
 * that the model checker drives the process in a deterministic way)
 * the thread id allocated to a thread created at a particular point
 * in the execution must be the SAME FOR EVERY EXECUTION. 
 * This will allow the model checker to have a DETERMINISTIC COMBINATION 
 * of the following for EVERY EXECUTION at a particular model checking state.
 * 1) process id (assigned by the model checker itself and deterministic
 *    for a particular config file given to model checker), 
 * 2) thread id
 * 3) id of that thread's current action blocked in the model checker
 */
void
mc_wrap_send_hello_or_bye(struct jsonrpc *mc_conn,
			  enum mc_rpc_type type,
			  int tid, const char *where)
{
    if (mc_conn) {
	ovs_assert(type == MC_RPC_HELLO || type == MC_RPC_BYE);

	union mc_rpc rpc;
	rpc.common.type = type;
	rpc.common.pid = getpid();
	rpc.common.tid = tid;
	rpc.common.where = where;
	    
	int err = jsonrpc_send_block(mc_conn, mc_rpc_to_jsonrpc(&rpc));
	
	if (err != 0) {
	    ovs_fatal(err, "Failed to send hello/bye RPC to model checker");
	}
    }   
}

/*
 * No global state in this library to ensure thread safety, since multiple
 * threads can be in the same wrapper at once */

static enum mc_rpc_choose_reply_type
mc_wrap_get_choose_reply(struct jsonrpc *mc_conn,
			 enum mc_rpc_choose_req_type type,
			 enum mc_rpc_subtype subtype,
			 const void *data, int tid, const char *where)
{
    if (mc_conn == NULL) {
	return MC_RPC_CHOOSE_REPLY_NORMAL;
    }
    
    union mc_rpc rpc;
    rpc.common.type = MC_RPC_CHOOSE_REQ;
    rpc.common.pid = getpid();
    rpc.common.tid = tid;
    rpc.common.where = where;
    rpc.choose_req.type = type;
    rpc.choose_req.subtype = subtype;
    rpc.choose_req.data = (void*) data;

    int err = jsonrpc_send_block(mc_conn, mc_rpc_to_jsonrpc(&rpc));

    if (err != 0) {
	ovs_fatal(err, "Failed to send choose RPC to model checker");
    }

    struct jsonrpc_msg *reply;
    err = jsonrpc_recv_block(mc_conn, &reply);

    if (err != 0) {
	ovs_fatal(err, "Failed to receive choose RPC to model checker");
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
		       struct jsonrpc *mc_conn, int tid,
		       const char *where)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_LOG,
				     MC_RPC_SUBTYPE_OPEN, NULL, tid, where);

    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return ovsdb_log_open(name, magic, open_mode, locking, filep);
    } else {
	return ovsdb_io_error(0, "Fake model checker error");
    }
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_read(struct ovsdb_log *file, struct json **jsonp,
		       struct jsonrpc *mc_conn, int tid, const char *where)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_LOG,
				     MC_RPC_SUBTYPE_READ, NULL, tid, where);
    
    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return ovsdb_log_read(file, jsonp);
    } else {
	return ovsdb_io_error(0, "Fake model checker error");
    }
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_write(struct ovsdb_log *file, const struct json *json,
			struct jsonrpc *mc_conn, int tid, const char *where)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_LOG,
				     MC_RPC_SUBTYPE_WRITE, NULL, tid, where);
    
    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return ovsdb_log_write(file, json);
    } else {
	return ovsdb_io_error(0, "Fake model checker error");
    }
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_commit(struct ovsdb_log *file,
			 struct jsonrpc *mc_conn, int tid, const char *where)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_LOG,
				     MC_RPC_SUBTYPE_COMMIT, NULL, tid, where);
    
    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return ovsdb_log_commit(file);
    } else {
	return ovsdb_io_error(0, "Fake model checker error");
    }
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_replace_start(struct ovsdb_log *old, struct ovsdb_log **newp,
				struct jsonrpc *mc_conn, int tid, const char *where)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_LOG,
				     MC_RPC_SUBTYPE_REPLACE_START, NULL, tid, where);
    
    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return ovsdb_log_replace_start(old, newp);
    } else {
	return ovsdb_io_error(0, "Fake model checker error");
    }
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_replace_commit(struct ovsdb_log *old, struct ovsdb_log *new,
				 struct jsonrpc *mc_conn, int tid, const char *where)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_LOG,
				     MC_RPC_SUBTYPE_REPLACE_COMMIT, NULL, tid, where);
    
    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return ovsdb_log_replace_commit(old, new);
    } else {
	return ovsdb_io_error(0, "Fake model checker error");
    }
}

int OVS_WARN_UNUSED_RESULT
mc_wrap_unixctl_server_create(const char *path,
			      struct unixctl_server **serverp,
			      struct jsonrpc *mc_conn, int tid,
			      const char *where)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_UNIXCTL,
				     MC_RPC_SUBTYPE_SERVER_CREATE, NULL,
				     tid, where);
    
    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return unixctl_server_create(path, serverp);
    } else {
	/* For now we do not explicitly fail this */
	ovs_assert(0);
	return ENOENT;
    }
}

int OVS_WARN_UNUSED_RESULT
mc_wrap_unixctl_client_create(const char *path, struct jsonrpc **client,
			      struct jsonrpc *mc_conn, int tid, const char *where)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_UNIXCTL,
				     MC_RPC_SUBTYPE_CLIENT_CREATE,
				     NULL, tid, where);
    
    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return unixctl_client_create(path, client);
    } else {
	/* For now we do not explicitly fail this */
	ovs_assert(0);
	return ECONNREFUSED;
    }
}

int OVS_WARN_UNUSED_RESULT
mc_wrap_unixctl_client_transact(struct jsonrpc *client,
				const char *command,
				int argc, char *argv[],
				char **result, char **error,
				struct jsonrpc *mc_conn, int tid,
				const char *where)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_UNIXCTL,
				     MC_RPC_SUBTYPE_CLIENT_TRANSACT,
				     NULL, tid, where);
    
    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	return unixctl_client_transact(client, command, argc,
				       argv, result, error);
    } else {
	/* For now we do not explicitly fail this */
	ovs_assert(0);
	return EIO;
    }
}

/*
 * This is just supposed to allow blocking on the model checker, so that
 * we can make the execution deterministic */
void
mc_wrap_noexecute_server_transact(struct jsonrpc *mc_conn, int tid,
				  const char *where)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_UNIXCTL,
				     MC_RPC_SUBTYPE_SERVER_RECV,
				     NULL, tid, where);
    
    ovs_assert(reply == MC_RPC_CHOOSE_REPLY_NORMAL); 
}

int
mc_wrap_jsonrpc_session_send(struct jsonrpc_session *s,
			     struct jsonrpc_msg *msg,
			     struct jsonrpc *mc_conn,
			     int tid, const char *where)
{
    enum mc_rpc_choose_reply_type reply;
    
    if (mc_conn == NULL) {
	return jsonrpc_session_send(s, msg);
    }
    
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_NETWORK,
				     MC_RPC_SUBTYPE_JS_SEND,
				     NULL, tid, where);
    
    if (reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	/* If model checking then we convert this non-blocking call into a
	 * blocking call */
	return jsonrpc_session_send_block(s, msg);
    } else {
	/* If this happened due to s->rpc being NULL then probably
	 * we should send a message to the model checker ?. Although
	 * currently */
	jsonrpc_msg_destroy(msg);
	return ENOTCONN;
    }
}

struct jsonrpc_msg *
mc_wrap_jsonrpc_session_recv(struct jsonrpc_session *s,
			     struct jsonrpc *mc_conn,
			     int tid, const char *where)
{
    struct jsonrpc_msg *msg = jsonrpc_session_recv(s);
    if(!msg) {
	/* We only interpose on a (non-blocking) jsonrpc_session_recv 
	 * call when there is actually something to receive */
	return NULL;
    }

    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_NETWORK,
				     MC_RPC_SUBTYPE_JS_NB_RECV,
				     NULL, tid, where);

    /* No point in failing this call */
    ovs_assert(reply == MC_RPC_CHOOSE_REPLY_NORMAL);
    return msg;
}

void
mc_wrap_ovs_mutex_lock(const struct ovs_mutex *mutex,
		       struct jsonrpc *mc_conn,
		       int tid, const char *where)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_THREAD,
				     MC_RPC_SUBTYPE_LOCK,
				     mutex, tid, where);
    
    ovs_assert(reply == MC_RPC_CHOOSE_REPLY_NORMAL);
    ovs_mutex_lock(mutex);
}

void
mc_wrap_ovs_mutex_unlock(const struct ovs_mutex *mutex,
			 struct jsonrpc *mc_conn,
			 int tid, const char *where)
{
    enum mc_rpc_choose_reply_type reply;
    reply = mc_wrap_get_choose_reply(mc_conn, MC_RPC_CHOOSE_REQ_THREAD,
				     MC_RPC_SUBTYPE_UNLOCK,
				     mutex, tid, where);
    
    ovs_assert(reply == MC_RPC_CHOOSE_REPLY_NORMAL);
    ovs_mutex_unlock(mutex);
}
