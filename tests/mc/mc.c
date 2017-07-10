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
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/list.h"
#include "openvswitch/vlog.h"
#include "openvswitch/util.h"
#include "process.h"
#include "stream.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(mc);

struct mc_process {
    char* name;
    char** run_cmd;
    struct jsonrpc_session *js;
    struct ovs_list list_node;

    /* If this is non-null then the 
     * process is running (as far as
     * the model checker knows) */
    struct process *proc_p;
    bool failure_inject;
    int delay_start;
    bool running;
};

struct mc_conn {
    struct ovs_list list_node;
    struct jsonrpc_session *js;
    unsigned int js_seqno;
};

static struct ovs_list mc_processes = OVS_LIST_INITIALIZER(&mc_processes);
static struct ovs_list mc_conns = OVS_LIST_INITIALIZER(&mc_conns);
static const char* listen_addr = NULL;
static struct pstream *listener = NULL;
static bool all_processes_running = false;

static const bool trueval = true;
static const bool falseval = false;

static const char *
mc_rpc_type_to_string(enum mc_rpc_type status)
{
    switch (status) {
#define MC_RPC(ENUM, NAME) case ENUM: return NAME;
        MC_RPC_TYPES
#undef MC_RPC
            }
    return "<unknown>";
}

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

static const void *
get_member(const struct json *json, const char *name) {
    if (!json) {
	return NULL;
    }
    ovs_assert(json->type == JSON_OBJECT);
    return __get_member(shash_find_data(json->u.object, name));
}

static const void *
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

static const void *
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
static const char *
get_str_member_copy(const struct json *json, const char *name) {
    const char *src = get_member(json, name);
    char *dst = NULL;
    
    if (src) {
	dst = xmalloc(strlen(src) + 1);
	strcpy(dst, src);
    }
    
    return dst;
}

static const char *
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

static struct jsonrpc_msg *
mc_rpc_to_jsonrpc(const union mc_rpc *rpc)
{
    struct json *args = json_object_create();
    json_object_put(args, "pid", json_integer_create(rpc->common.pid));

    switch (rpc->common.type) {
    case MC_RPC_HELLO:
	break;

    case MC_RPC_CHOOSE_REQ:
	/** Handle Me !! **/
	break;
	
    case MC_RPC_CHOOSE_REPLY:
	/** Handle Me !! **/
	break;
	
    case MC_RPC_ASSERT:
	/** Handle Me !! **/
	break;
    }

    return jsonrpc_create_notify(mc_rpc_type_to_string(rpc->common.type),
				 json_array_create_1(args));
}

static void
mc_rpc_from_jsonrpc(const struct jsonrpc_msg *msg, union mc_rpc *rpc)
{
    memset(rpc, 0, sizeof *rpc);
    ovs_assert(msg->type == JSONRPC_NOTIFY);
    ovs_assert(mc_rpc_type_from_string(msg->method, &rpc->common.type));

    rpc->common.pid = *(pid_t*)get_member(json_array(msg->params)->elems[0],
					  "pid");
    
    switch (rpc->common.type) {
    case MC_RPC_HELLO:
	break;

    case MC_RPC_CHOOSE_REQ:
	/** Handle Me !! **/
	break;
	
    case MC_RPC_CHOOSE_REPLY:
	/** Handle Me !! **/
	break;
	
    case MC_RPC_ASSERT:
	/** Handle Me !! **/
	break;
    }
}

static bool
mc_receive_rpc(struct jsonrpc_session *js, union mc_rpc *rpc)
{
    struct jsonrpc_msg *msg = jsonrpc_session_recv(js);
    if (!msg) {
        return false;
    }

    mc_rpc_from_jsonrpc(msg, rpc);
    return true;
}

static void
mc_start_process(struct mc_process *new_proc) {
    /* Prepare to redirect stderr and stdout of the process to a file
     * and then start the process */

    int stdout_copy = dup(fileno(stdout));
    int stderr_copy = dup(fileno(stderr));
    
    char path[strlen(new_proc->name) + 4];
    strcpy(path, new_proc->name);
    strcpy(path + strlen(new_proc->name), ".out");
    int fdout = open(path, O_CREAT|O_RDWR|O_TRUNC, S_IRWXU);

    strcpy(path + strlen(new_proc->name), ".err");
    int fderr = open(path, O_CREAT|O_RDWR|O_TRUNC, S_IRWXU);

    if (fdout < 0 || fderr < 0) {
	ovs_fatal(errno, "Cannot open outfile for process %s",
		  new_proc->name);
    }
    
    dup2(fdout, fileno(stdout));
    dup2(fderr, fileno(stderr));
    
    int err = process_start(new_proc->run_cmd, &(new_proc->proc_p));

    /* Restore our stdout and stderr */
    dup2(stdout_copy, fileno(stdout));
    dup2(stderr_copy, fileno(stderr));
	
    if (err != 0) {
	ovs_fatal(err, "Cannot start process %s", new_proc->name);
    }

    new_proc->running = true;

    close(stdout_copy);
    close(stderr_copy);
    close(fdout);
    close(fderr);
}

static void
mc_start_all_processes(void)
{
    struct mc_process *new_proc;
    LIST_FOR_EACH (new_proc, list_node, &mc_processes) {
	if (!new_proc->running) {
	    if (new_proc->delay_start > 0) {
		sleep(new_proc->delay_start);
	    }
	    
	    mc_start_process(new_proc);
	}
    }
    all_processes_running = true;
}

static void
mc_load_config_run(struct json *config) {
    
    const struct json *run_conf = get_member_or_die(config, "run_config", 0,
						    "Cannot find run_config");
    listen_addr = get_str_member_copy_or_die(run_conf, "listen_address",
					     0, "Cannot find listen_address");

}

static void
mc_load_config_processes(struct json *config) {

    const struct json_array *mc_conf =
	get_member_or_die(config, "model_check_execute", 0,
			  "Cannot find the execute config");
    
    struct mc_process *new_proc;
    for (int i = 0; i < mc_conf->n; i++) {
	new_proc = xmalloc(sizeof(struct mc_process));

	const struct json *exe = get_first_member(mc_conf->elems[i],
						  &(new_proc->name),
						  true);

	const struct json_array *cmd =
	    get_member_or_die(exe, "command",
			      0, "Did not find command for %s\n", new_proc->name);
	
	char **run_cmd = xmalloc(sizeof(char*) * (cmd->n + 1));
	int j = 0;
	for (; j < cmd->n; j++) {
	    run_cmd[j] = xmalloc(strlen(json_string(cmd->elems[j]) + 1));
	    strcpy(run_cmd[j], json_string(cmd->elems[j]));
	}
	run_cmd[j] = NULL;
	new_proc->run_cmd = run_cmd;
	
	/* Should we failure inject this process ? */

	new_proc->failure_inject =
	    *(bool*) get_member_or_die(exe, "failure_inject",
				      0,
				      "Did not find failure_inject for %s\n",
				      new_proc->name);
	

	new_proc->delay_start = 0;
	const void *result = get_member(exe, "delay_start");
	if (result) {
	    new_proc->delay_start = *(int *)result;
	}
	
	new_proc->running = false;
	ovs_list_push_back(&mc_processes, &new_proc->list_node);
    }
}

static void
mc_load_config(const char *filename)
{
    struct json *config = json_from_file(filename);
   
    if (config->type == JSON_STRING) {
	ovs_fatal(0, "Cannot read the json config in %s\n%s", filename,
		  config->u.string);
    }
    
    mc_load_config_run(config);
    mc_load_config_processes(config);
    json_destroy(config);
}

static void
mc_run_session(struct jsonrpc_session *js)
{
    jsonrpc_session_run(js);
    union mc_rpc rpc;
    mc_receive_rpc(js, &rpc);
}

static void
mc_run(void)
{
    if (!listener) {
	int error = pstream_open(listen_addr, &listener, DSCP_DEFAULT);
	
	if (error) {
	    ovs_fatal(error, "Cannot open the listening conn due to %s\n",
		      ovs_strerror(error));
	}
    }
    
    if (!all_processes_running) {
	mc_start_all_processes();
    }
    
    if (listener) {
	struct stream *stream;
	int error = pstream_accept(listener, &stream);
	if (!error) {
	    struct mc_conn *conn = xzalloc(sizeof *conn);
	    ovs_list_push_back(&mc_conns, &conn->list_node);
	    conn->js = jsonrpc_session_open_unreliably(
			     jsonrpc_open(stream), DSCP_DEFAULT);
	    conn->js_seqno = jsonrpc_session_get_seqno(conn->js);	    
	} 
    }
}

int
main(int argc, char *argv[])
{
    if (argc < 2) {
	ovs_fatal(0, "Usage is ./mc <configfile>. Not enough arguments provided");
    }

    mc_load_config(argv[1]);
    
    for(;;) {
    	mc_run();
    }
    
    return 0;
}
