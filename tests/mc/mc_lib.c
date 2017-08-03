/*
 * Copyright (c) 2016, 2017 Nicira, Inc.
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
#include <fcntl.h>
#include <unistd.h>
#include "jsonrpc.h"
#include "mc.h"
#include "mc_internal.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/list.h"
#include "openvswitch/vlog.h"
#include "openvswitch/util.h"
#include "process.h"
#include "stream.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(mc_lib);

static const bool trueval = true;
static const bool falseval = false;

static bool mc_rpc_type_from_string(const char *s, enum mc_rpc_type *status);
static bool
mc_rpc_choose_req_type_from_string(const char *s,
				   enum mc_rpc_choose_req_type *status);
static bool mc_rpc_subtype_from_string(const char *s,
				       enum mc_rpc_subtype *status);
static void mc_choose_req_to_jsonrpc(const struct mc_rpc_choose_req *rq,
				     struct json *args);
static void mc_choose_req_from_jsonrpc(const struct json *j,
				       struct mc_rpc_choose_req *rq);
static void mc_choose_reply_to_jsonrpc(const struct mc_rpc_choose_reply *rq,
				       struct json *args);
static void mc_choose_reply_from_jsonrpc(const struct json *j,
					 struct mc_rpc_choose_reply *rq);
static inline const void *
__get_member(const struct json *j) {
    if (j != NULL) {
	switch(j->type) {
	case JSON_FALSE:
	    return &falseval;
	case JSON_TRUE:
	    return &trueval;
	case JSON_OBJECT:
	    return j;
	case JSON_ARRAY:
	    return &(j->u.array);
	case JSON_INTEGER:
	    return &(j->u.integer);
	case JSON_REAL:
	    return &(j->u.real);
	case JSON_STRING:
	    return j->u.string;
	case JSON_NULL:
	case JSON_N_TYPES:
	    return NULL;
	}
    }
    
    return j;
}

const void *
get_member(const struct json *json, const char *name) {
    if (!json) {
	return NULL;
    }
    ovs_assert(json->type == JSON_OBJECT);
    return __get_member(shash_find_data(json->u.object, name));
}

const void *
get_first_member(const struct json *json, char **name, bool copy_name) {
    if (!json) {
	return NULL;
    }
    ovs_assert(json->type == JSON_OBJECT);
    struct shash_node *n = shash_first(json->u.object);

    if (copy_name) {
	*name = xmalloc(strlen(n->name) + 1);
	strcpy(*name, n->name);
    } else {
	*name = n->name;
    }
    
    return __get_member(n->data);
}

const void *
get_member_or_die(const struct json *json, const char *name, 
		  int err_no, const char *format, ...) {
    const void *member = get_member(json, name);

    if (member) {
	return member;
    }

    va_list args;
    va_start(args, format);
    ovs_fatal_valist(err_no, format, args);

    OVS_NOT_REACHED();
    return NULL;
}

/*
 * De-allocation is responsibility of caller
 */
const char *
get_str_member_copy(const struct json *json, const char *name) {
    const char *src = get_member(json, name);
    char *dst = NULL;
    
    if (src) {
	dst = xmalloc(strlen(src) + 1);
	strcpy(dst, src);
    }
    
    return dst;
}

const char *
get_str_member_copy_or_die(const struct json *json, const char *name,
			   int err_no, const char *format, ...)
{
    const char *ret = get_str_member_copy(json, name);
    
    if (ret) {
	return ret;
    }
    
    va_list args;
    va_start(args, format);
    ovs_fatal_valist(err_no, format, args);
    
    OVS_NOT_REACHED();
    return NULL;
}

const char *
mc_rpc_type_to_string(enum mc_rpc_type status)
{
    switch (status) {
#define MC_RPC(ENUM, NAME) case ENUM: return NAME;
        MC_RPC_TYPES
#undef MC_RPC
            }
    return "<unknown>";
}

static bool
mc_rpc_type_from_string(const char *s, enum mc_rpc_type *status)
{
#define MC_RPC(ENUM, NAME)			\
    if (!strcmp(s, NAME)) {                     \
        *status = ENUM;                         \
        return true;                            \
    }
    MC_RPC_TYPES
#undef MC_RPC
    return false;
}

const char *
mc_rpc_choose_req_type_to_string(enum mc_rpc_choose_req_type status)
{
    switch (status) {
#define MC_RPC_CHOOSE(ENUM, NAME) case ENUM: return NAME;
        MC_RPC_CHOOSE_TYPES
#undef MC_RPC_CHOOSE
            }
    return "<unknown>";
}

static bool
mc_rpc_choose_req_type_from_string(const char *s, enum mc_rpc_choose_req_type *status)
{
#define MC_RPC_CHOOSE(ENUM, NAME)		\
    if (!strcmp(s, NAME)) {                     \
        *status = ENUM;                         \
        return true;                            \
    }
    MC_RPC_CHOOSE_TYPES
#undef MC_RPC_CHOOSE
    return false;
}

const char *
mc_rpc_subtype_to_string(enum mc_rpc_subtype status)
{
    switch (status) {
#define MC_RPC_SUBTYPE(ENUM, NAME) case ENUM: return NAME;
        MC_RPC_SUBTYPES
#undef MC_RPC_SUBTYPE
            }
    return "<unknown>";
}

static bool
mc_rpc_subtype_from_string(const char *s, enum mc_rpc_subtype *status)
{
#define MC_RPC_SUBTYPE(ENUM, NAME)		\
    if (!strcmp(s, NAME)) {                     \
        *status = ENUM;                         \
        return true;                            \
    }
    MC_RPC_SUBTYPES
#undef MC_RPC_SUBTYPE
    return false;
}

static void
mc_choose_req_to_jsonrpc(const struct mc_rpc_choose_req *rq,
			 struct json *args)
{
    json_object_put_string(args, "type",
			   mc_rpc_choose_req_type_to_string(rq->type));
    json_object_put_string(args, "subtype",
			   mc_rpc_subtype_to_string(rq->subtype));

    /* XXX serialize the arbitrary data here */
}

static void
mc_choose_req_from_jsonrpc(const struct json *j,
			   struct mc_rpc_choose_req *rq)
{
    ovs_assert(mc_rpc_choose_req_type_from_string(get_member(j, "type"),
						  &rq->type));
    
    ovs_assert(mc_rpc_subtype_from_string(get_member(j, "subtype"),
					  &rq->subtype));
    
    /* XXX deserialize the arbitary data instead of this */
    rq->data = NULL;
}

static void
mc_choose_reply_to_jsonrpc(const struct mc_rpc_choose_reply *rq,
			   struct json *args)
{
    if (rq->reply == MC_RPC_CHOOSE_REPLY_NORMAL) {
	json_object_put_string(args, "reply",
			       "mc_rpc_choose_reply_normal");
    } else if (rq->reply == MC_RPC_CHOOSE_REPLY_ERROR) {
	json_object_put_string(args, "reply",
			       "mc_rpc_choose_reply_error");
    } else ovs_assert(0);
}

static void
mc_choose_reply_from_jsonrpc(const struct json *j,
			     struct mc_rpc_choose_reply *rq)
{
    if (!strcmp(get_member(j, "reply"), "mc_rpc_choose_reply_normal")) {
	rq->reply = MC_RPC_CHOOSE_REPLY_NORMAL;
    } else if (!strcmp(get_member(j, "reply"), "mc_rpc_choose_reply_normal")) {
	rq->reply = MC_RPC_CHOOSE_REPLY_ERROR;
    } else ovs_assert(0);
}

struct jsonrpc_msg *
mc_rpc_to_jsonrpc(const union mc_rpc *rpc)
{
    struct json *args = json_object_create();
    json_object_put(args, "pid", json_integer_create(rpc->common.pid));
    json_object_put(args, "tid", json_integer_create(rpc->common.tid));
    json_object_put_string(args, "where", rpc->common.where);
			   
    switch (rpc->common.type) {
    case MC_RPC_HELLO:
    case MC_RPC_BYE:
	break;

    case MC_RPC_CHOOSE_REQ:
	mc_choose_req_to_jsonrpc(&rpc->choose_req, args);
	break;
	
    case MC_RPC_CHOOSE_REPLY:
	mc_choose_reply_to_jsonrpc(&rpc->choose_reply, args);
	break;

    case MC_RPC_ASSERT:
	/** Handle Me !! **/
	break;
    }

    return jsonrpc_create_notify(mc_rpc_type_to_string(rpc->common.type),
				 json_array_create_1(args));
}

void
mc_rpc_from_jsonrpc(const struct jsonrpc_msg *msg, union mc_rpc *rpc)
{
    memset(rpc, 0, sizeof *rpc);
    ovs_assert(msg->type == JSONRPC_NOTIFY);
    ovs_assert(mc_rpc_type_from_string(msg->method, &rpc->common.type));

    struct json *json = json_array(msg->params)->elems[0];
    rpc->common.pid = *(pid_t*)get_member(json, "pid");
    rpc->common.tid = *(int*)get_member(json, "tid");
    rpc->common.where = get_member(json, "where");
	
    switch (rpc->common.type) {
    case MC_RPC_HELLO:
    case MC_RPC_BYE:
	break;

    case MC_RPC_CHOOSE_REQ:
	mc_choose_req_from_jsonrpc(json, &rpc->choose_req);
	break;
	
    case MC_RPC_CHOOSE_REPLY:
	mc_choose_reply_from_jsonrpc(json, &rpc->choose_reply);
	break;

    case MC_RPC_ASSERT:
	/** Handle Me !! **/
	break;
    }
}
