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
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include "jsonrpc.h"
#include "mc.h"
#include "mc_internal.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/list.h"
#include "openvswitch/vlog.h"
#include "openvswitch/util.h"
#include "poll-loop.h"
#include "process.h"
#include "signals.h"
#include "stream.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(mc);

struct mc_thread;

#define MC_ACTION_TYPES							\
    MC_ACTION(MC_ACTION_RPC_REPLY_ERROR, "mc_action_rpc_reply_error")	\
    MC_ACTION(MC_ACTION_RPC_REPLY_NORMAL, "mc_action_rpc_reply_normal")	\
    MC_ACTION(MC_ACTION_TIMER_SHORT, "mc_action_timer_short")		\
    MC_ACTION(MC_ACTION_TIMER_TRIGGER, "mc_action_timer_trigger")	\
    MC_ACTION(MC_ACTION_CRASH_PROCESS, "mc_action_crash_process")	\
    
enum mc_action_type {
#define MC_ACTION(ENUM, NAME) ENUM,
    MC_ACTION_TYPES
#undef MC_ACTION
};

#define MC_SEARCH_STRATEGY_TYPES					\
    MC_SEARCH_STRATEGY(MC_SEARCH_STRATEGY_BREADTH, "mc_search_strategy_breadth") \
    MC_SEARCH_STRATEGY(MC_SEARCH_STRATEGY_DEPTH, "mc_search_strategy_depth") \
    MC_SEARCH_STRATEGY(MC_SEARCH_STRATEGY_SINGLE, "mc_search_strategy_single") \
    MC_SEARCH_STRATEGY(MC_SEARCH_STRATEGY_RANDOM, "mc_search_strategy_random") \
    MC_SEARCH_STRATEGY(MC_SEARCH_STRATEGY_DPOR, "mc_search_strategy_dpor") \
    
enum mc_search_strategy {
#define MC_SEARCH_STRATEGY(ENUM, NAME) ENUM,
    MC_SEARCH_STRATEGY_TYPES
#undef MC_SEARCH_STRATEGY
};

#define MC_FSM_STATES							\
    MC_FSM(MC_FSM_PRE_INIT, "mc_fsm_pre_init")				\
    MC_FSM(MC_FSM_RESTORE_INIT_WAIT, "mc_fsm_restore_init_wait")	\
    MC_FSM(MC_FSM_RESTORE_MID_STATE, "mc_fsm_restore_mid_state")	\
    MC_FSM(MC_FSM_RESTORE_ACTION_WAIT, "mc_fsm_restore_action_wait")	\
    MC_FSM(MC_FSM_NEW_ACTION_WAIT, "mc_fsm_new_action_wait")		\
    MC_FSM(MC_FSM_NEW_STATE, "mc_fsm_new_state")			\

enum mc_fsm_state {
#define MC_FSM(ENUM, NAME) ENUM,
    MC_FSM_STATES
#undef MC_FSM
};

struct mc_action {
    struct ovs_list list_node;
    enum mc_action_type type;
    int p_idx; /* Index into the mc_procs array */
    int t_idx; /* Index into the thread array */
    enum mc_rpc_choose_req_type choosetype;
    enum mc_rpc_subtype subtype;
    void *data;
};

struct mc_state {
    struct mc_action **path;
    int length;
};

struct mc_queue_item {
    struct ovs_list list_node;
    struct mc_state *state;
    struct mc_action *action;    
};

struct mc_thread {
    /* Only one of these can be be non-NULL at one time, (but
     * both can be NULL at the same time). 
     * If applying is non-NULL then it points to the 
     * action current being applied to the state that this thread was 
     * previously in.
     * If blocked is non-NULL then it points to the action
     * that this thread is currently blocked on in the model checker */
    struct mc_action *applying;
    struct mc_action *blocked;
    struct jsonrpc *js;
    bool valid;
};

struct mc_process {
    char *name;
    char **run_cmd;
    
    struct process *p;

    struct mc_thread *threads;
    int num_threads;
    
    /* Config Options */
    bool failure_inject;

    /* Status data */
    bool running;
    size_t thread_arr_size;
};

struct mc_conn {
    struct ovs_list list_node;
    struct jsonrpc *js;
};

static struct mc_process *mc_procs = NULL;
static int num_procs = 0;
static int max_threads_per_proc = 0;

static struct ovs_list mc_conns = OVS_LIST_INITIALIZER(&mc_conns);
static const char *listen_addr = NULL;
static struct pstream *listener = NULL;

static char **setup_cmd = NULL;
static char **cleanup_cmd = NULL;

static struct ovs_list mc_actions = OVS_LIST_INITIALIZER(&mc_actions);
static struct ovs_list mc_queue = OVS_LIST_INITIALIZER(&mc_queue);
static enum mc_fsm_state fsm_state = MC_FSM_PRE_INIT;
static enum mc_search_strategy strategy = MC_SEARCH_STRATEGY_BREADTH;
static const char *search_strategy = NULL;

static bool mc_receive_rpc(struct jsonrpc *js, struct mc_process *p,
			   union mc_rpc *rpc);
static void mc_start_process(struct mc_process *new_proc);
static void mc_start_all_processes(void);
static void mc_load_config_run(struct json *config);
static void mc_load_config_processes(struct json *config);
static void mc_load_config(const char *filename);
static void mc_handle_hello_or_bye(struct jsonrpc *js,
				   const union mc_rpc *rpc);
static void mc_handle_rpc(struct jsonrpc *js, struct mc_process *proc,
			  const union mc_rpc *rpc);
static void mc_run_conn(struct jsonrpc *js, struct mc_process *proc);
static void mc_run(void);

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
    
    int err = process_start(new_proc->run_cmd, &(new_proc->p));

    /* Restore our stdout and stderr */
    dup2(stdout_copy, fileno(stdout));
    dup2(stderr_copy, fileno(stderr));
	
    if (err != 0) {
	ovs_fatal(err, "Cannot start process %s", new_proc->name);
    }

    new_proc->running = true;
    new_proc->threads = xzalloc(sizeof(struct mc_thread) *
				  max_threads_per_proc);
    
    close(stdout_copy);
    close(stderr_copy);
    close(fdout);
    close(fderr);
}

static void
mc_process_death(struct mc_process *proc)
{
    process_destroy(proc->p);
    proc->p = NULL;

    for (int i = 0; i < max_threads_per_proc; i++) {
	if (proc->threads[i].valid) {
	    jsonrpc_close(proc->threads[i].js);
	    /* XXX FIX ME !!! Free any other thread members here */
	}
    }

    free(proc->threads);
    proc->running = false;
    proc->num_threads = 0;
}

static void
mc_kill_process(struct mc_process *proc)
{
    int err = process_kill(proc->p, SIGKILL);
    if (err != 0) {
	/* Currently assume that a parent can always kill
	   its child */
	ovs_fatal(err, "Cannot kill process %s", proc->name);
    }

    mc_process_death(proc);
}

static void
exec_cmd_and_wait(char **cmd, char *name_err_msg)
{
    struct process *p;
    int err = process_start(cmd, &p);
    if (err != 0) {
	ovs_fatal(err, "Cannot start the %s process", name_err_msg);
    }

    while (!process_exited(p)) {
	process_run();
	process_wait(p);
	poll_block();
    }
    
    if (process_status(p) != 0) {
	ovs_fatal(process_status(p), "%s process returned error",
		  name_err_msg);
    }
}

static void
mc_start_all_processes(void)
{
    for (int i = 0; i < num_procs; i++) {
	if (mc_procs[i].running) {
	    mc_kill_process(&mc_procs[i]);
	}
    }

    /* Assume that the cleanup command is idempotent.
       It should not fail, even if cleanup is not required */
    exec_cmd_and_wait(cleanup_cmd, "Cleanup");
    exec_cmd_and_wait(setup_cmd, "Setup");
    
    for (int i = 0; i < num_procs; i++) {
	mc_start_process(&mc_procs[i]);
    }
}

static void
mc_load_config_run(struct json *config)
{
    const struct json *run_conf = get_member_or_die(config, "run_config", 0,
						    "Cannot find run_config");
    listen_addr = get_str_member_copy_or_die(run_conf, "listen_address",
					     0, "Cannot find listen_address");

    max_threads_per_proc = *(int*) get_member_or_die(run_conf,
						     "max_threads_per_proc",
						     0,
						     "Cant find threads_per_proc");

    search_strategy = get_str_member_copy_or_die(run_conf,
						 "search_strategy",
						 0,
						 "Cant find search strategy");
}

static char**
get_cmd_from_json(const struct json_array *jsoncmd) {
    char **cmd = xmalloc(sizeof(char*) * (jsoncmd->n + 1));
    int i = 0;
    for (; i < jsoncmd->n; i++) {
	cmd[i] = xmalloc(strlen(json_string(jsoncmd->elems[i]) + 1));
	strcpy(cmd[i], json_string(jsoncmd->elems[i]));
    }
    cmd[i] = NULL;

    return cmd;
}

static void
mc_load_config_processes(struct json *config)
{
    const struct json_array *jsoncmd;
    
    const struct json *mc_setup = get_member(config, "model_check_setup");
    if (mc_setup) {
	jsoncmd = get_member(mc_setup, "command");

	if (jsoncmd) {
	    setup_cmd = get_cmd_from_json(jsoncmd);
	}
    }

    const struct json_array *mc_conf =
	get_member_or_die(config, "model_check_execute", 0,
			  "Cannot find the execute config");
    
    mc_procs = xzalloc(sizeof(struct mc_process) * mc_conf->n);
    num_procs = mc_conf->n;
    
    for (int i = 0; i < mc_conf->n; i++) {
	const struct json *exe = get_first_member(mc_conf->elems[i],
						  &(mc_procs[i].name),
						  true);
	mc_procs[i].run_cmd =
	    get_cmd_from_json(get_member_or_die(exe, "command",
						0,
						"Did not find command for %s\n",
						mc_procs[i].name));
	
	/* Should we failure inject this process ? */
	mc_procs[i].failure_inject =
	    *(bool*) get_member_or_die(exe, "failure_inject",
				       0,
				       "Did not find failure_inject for %s\n",
				       mc_procs[i].name);
    }

    const struct json *mc_cleanup = get_member(config, "model_check_cleanup");
    if (mc_cleanup) {
	jsoncmd = get_member(mc_cleanup, "command");

	if (jsoncmd) {
	    cleanup_cmd = get_cmd_from_json(jsoncmd);
	}
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
mc_handle_hello_or_bye(struct jsonrpc *js, const union mc_rpc *rpc)
{
    for (int i = 0; i < num_procs; i++) {
	if (rpc->common.pid == process_pid(mc_procs[i].p)) {
	    int tid = rpc->common.tid;
	    ovs_assert(tid >= 0);
	    
	    if (rpc->common.type == MC_RPC_HELLO) {
		mc_procs[i].threads[tid].js = js;
		mc_procs[i].threads[tid].valid = true;
		mc_procs[i].num_threads++;
		
		struct mc_conn *conn;
		LIST_FOR_EACH (conn, list_node, &mc_conns) {
		    if (conn->js == js) {
			ovs_list_remove(&conn->list_node);
			free(conn);
			break;
		    }
		}
	    } else if (rpc->common.type == MC_RPC_BYE) {
		jsonrpc_close(mc_procs[i].threads[tid].js);
		mc_procs[i].threads[tid].valid = false;
		/** FIX ME !!! free other thread members here **/
		mc_procs[i].num_threads--;

		if (mc_procs[i].num_threads == 0) {
		    mc_process_death(&mc_procs[i]);
		}
	    }
	}
    }
}

static void
mc_handle_choose_req(const struct mc_process *proc,
		     const struct mc_rpc_choose_req *rq)
{
    union mc_rpc rpc;
    rpc.common.type = MC_RPC_CHOOSE_REPLY;
    rpc.common.pid = 0;
    rpc.common.tid = 0;
    rpc.choose_reply.reply = MC_RPC_CHOOSE_REPLY_NORMAL;

    int tid = rq->common.tid;
    int error = jsonrpc_send_block(proc->threads[tid].js,
    				   mc_rpc_to_jsonrpc(&rpc));
    
    if (error != 0) {
    	ovs_fatal(error, "Cannot send choose reply to %s\n", proc->name);
    }
}

static void
mc_handle_rpc(struct jsonrpc *js, struct mc_process *proc,
	      const union mc_rpc *rpc)
{
    switch (rpc->common.type) {
    case MC_RPC_HELLO:
    case MC_RPC_BYE:
	mc_handle_hello_or_bye(js, rpc);
	break;
	
    case MC_RPC_CHOOSE_REQ:
	mc_handle_choose_req(proc, &rpc->choose_req);
	break;

    case MC_RPC_CHOOSE_REPLY:
	ovs_assert(0);
	break;

    case MC_RPC_ASSERT:
	/** Handle Me !! **/
	break;
    }
}

static bool
mc_receive_rpc(struct jsonrpc *js, struct mc_process *p, union mc_rpc *rpc)
{
    struct jsonrpc_msg *msg;
    int error = jsonrpc_recv(js, &msg);
    
    if (error != 0) {
	if (error != EAGAIN) {
	    if (error == EOF) {
		VLOG_INFO("End-of-File from %s\n", p->name);
	    } else {
		VLOG_ERR("Error in receiving rpc: %s\n", ovs_strerror(error));
	    }
	}
	return false;
    }
    
    mc_rpc_from_jsonrpc(msg, rpc);
    return true;
}

static void
mc_run_conn(struct jsonrpc *js, struct mc_process *proc)
{
    if (js) {
	jsonrpc_run(js);
	
	union mc_rpc rpc;
	if (mc_receive_rpc(js, proc, &rpc)) {
	    mc_handle_rpc(js, proc, &rpc);
	}
    } else if (proc && proc->running) {
	/* This has been called from a process context
	 * which the model checker believes to be running
	 * but the jsonrpc connection either is null or
	 * it is no longer alive */
    }
}

static void
mc_run(void)
{
    if (fsm_state == MC_FSM_PRE_INIT) {
	mc_start_all_processes();
	fsm_state = MC_FSM_RESTORE_INIT_WAIT;
    }
    
    if (listener) {
	struct stream *stream;
	int error = pstream_accept(listener, &stream);
	if (!error) {
	    struct mc_conn *conn = xzalloc(sizeof *conn);
	    ovs_list_push_back(&mc_conns, &conn->list_node);
	    conn->js = jsonrpc_open(stream);
	} 
    }

    struct mc_conn *conn, *next;
    LIST_FOR_EACH_SAFE (conn, next, list_node, &mc_conns) {
	ovs_assert(conn->js != NULL);
	mc_run_conn(conn->js, NULL);
    }

    process_run();
    for (int i= 0; i < num_procs; i++) {	
	if (mc_procs[i].running && !process_exited(mc_procs[i].p)) {
	    for (int j = 0; j < max_threads_per_proc; j++) {
		if (mc_procs[i].threads[j].valid) {
		    mc_run_conn(mc_procs[i].threads[j].js, &mc_procs[i]);
		}
	    }
	} else if (mc_procs[i].running && process_exited(mc_procs[i].p)) {
	    /* XXX. Model checker thinks the process is 
	     * running but it is not running anymore ? **/

	    /* Use this check to judge if the process was killed
	       by some signal (e.g. SIGSEGV) */
	    if (WIFSIGNALED(process_status(mc_procs[i].p))) {
		fprintf(stderr, "%s %s\n", mc_procs[i].name,
			process_status_msg(process_status(mc_procs[i].p)));
	    }

	    /* This might need to be eventually moved, but remember to
	     * to call it */
	    mc_process_death(&mc_procs[i]);
	} else if (!mc_procs[i].running) {
	    /* XXX. This should only be the case when we
	     * crash the process deliberately at some stage 

	     * This should instead be handled in a get_process_actions() 
	     * function called from a larger get_enabled_actions()
	     * function. One of the "actions" that can be applied
	     * to a state is to restart a deliberately crashed 
	     * process */
	} /* XXX another else branch here should check for
	   * timeouts of processes that are believed to be
	   * running but have not contacted the model checker
	   * for a decision on a syscall or libcall 
	   * i.e. they might be stuck in an infinite loop */
    }
}

int
main(int argc, char *argv[])
{
    if (argc < 2) {
	ovs_fatal(0, "Usage is ./mc <configfile>. Not enough arguments provided");
    }

    mc_load_config(argv[1]);
    
    if (!listener) {
	int error = pstream_open(listen_addr, &listener, DSCP_DEFAULT);
	
	if (error) {
	    ovs_fatal(error, "Cannot open the listening conn due to %s\n",
		      ovs_strerror(error));
	}
    }

    /* Add the initial state to the queue */
    struct mc_queue_item *item = xzalloc(sizeof *item) ;
    item->state = NULL;
    item->action = NULL;
    ovs_list_push_back(&mc_queue, &item->list_node);
    
    while(!ovs_list_is_empty(&mc_queue)) {
    	mc_run();
    }
    
    return 0;
}
