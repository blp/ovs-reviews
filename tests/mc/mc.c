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
#include "random.h"
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
    MC_ACTION(MC_ACTION_UNKNOWN, "mc_action_unknown")	\
    
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
    int refcount;
    enum mc_action_type type;
    int p_idx; /* Index into the mc_procs array */
    int t_idx; /* Index into the thread array */
    char *where;
    enum mc_rpc_choose_req_type choosetype;
    enum mc_rpc_subtype subtype;
    void *data;
};

/* Initial state is represented by path = NULL and length = 0 
 * Subsequent states are represented by the sequence of actions 
 * applied to the initial state */ 
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
    /* If blocked is non-NULL then it points to the action
     * that this thread is currently blocked on in the model checker */
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

static struct ovs_list mc_queue = OVS_LIST_INITIALIZER(&mc_queue);

static struct mc_state *restore = NULL;
static int restore_path_next = 0;

static struct mc_thread *wait_thread = NULL;

static enum mc_fsm_state fsm_state = MC_FSM_PRE_INIT;
static enum mc_search_strategy strategy;
static int max_search_depth = -1; /* < 0 means no bounds on depth */
static bool max_search_depth_reached = false;

static const char *mc_search_strategy_to_string(enum mc_search_strategy status);
static bool mc_search_strategy_from_string(const char *s,
					   enum mc_search_strategy *status);
static void mc_start_process(struct mc_process *new_proc);
static void mc_process_wait_block(struct process *p);
static void mc_process_death(struct mc_process *proc);
static void mc_kill_process(struct mc_process *proc);
static void mc_kill_all_processes(void);
static void mc_get_exit_statuses(struct ds *args);
static void exec_cmd_and_wait(char **cmd, char *name_err_msg);
static void mc_start_all_processes(void);
static bool mc_processes_crashed(void);
static void mc_load_config_run(struct json *config);
static void mc_load_config_processes(struct json *config);
static void mc_load_config(const char *filename);
static struct mc_action *mc_action_alloc(void);
static struct mc_action *mc_action_inc_ref(struct mc_action *action);
static void mc_action_dec_ref(struct mc_action **action);
static void mc_handle_hello_or_bye(struct jsonrpc *js,
				   const union mc_rpc *rpc);
static void mc_handle_choose_req(int p_idx, int t_idx,
				 const struct mc_rpc_choose_req *rq);
static void mc_handle_rpc(struct jsonrpc *js, int p_idx, int t_idx,
			  const union mc_rpc *rpc);
static bool mc_receive_rpc(struct jsonrpc *js, int p_idx,
			   union mc_rpc *rpc);
static void mc_run_conn(struct jsonrpc *js, int p_idx, int t_idx);
static bool mc_all_threads_blocked(void);
static void mc_send_choose_reply(struct mc_action *action,
				 enum mc_rpc_choose_reply_type reply_type);
static void mc_execute_action(struct mc_action *action);
static void mc_dump_state(void);
static void mc_exit_error(void);
static struct ovs_list mc_get_enabled_actions(struct mc_state *cur_state,
					      struct mc_action *cur_action);
static void mc_enqueue_init_state_action_pair(void);
static struct mc_queue_item *new_state_action_pair(struct mc_state *cur_state,
						   struct mc_action *cur_action,
						   const int cur_path_len,
						   struct mc_action *next_action);
static void mc_enqueue_state_action_pairs(struct mc_state *cur_state,
					  struct mc_action *cur_action,
					  const int cur_path_len,
					  struct ovs_list next_actions);
static void mc_explore(void);
static void mc_run(void);

static const char *
mc_search_strategy_to_string(enum mc_search_strategy status)
{
    switch (status) {
#define MC_SEARCH_STRATEGY(ENUM, NAME) case ENUM: return NAME;
        MC_SEARCH_STRATEGY_TYPES
#undef MC_SEARCH_STRATEGY
            }
    return "<unknown>";
}

static bool
mc_search_strategy_from_string(const char *s, enum mc_search_strategy *status)
{
#define MC_SEARCH_STRATEGY(ENUM, NAME)		\
    if (!strcmp(s, NAME)) {                     \
        *status = ENUM;                         \
        return true;                            \
    }
    MC_SEARCH_STRATEGY_TYPES
#undef MC_SEARCH_STRATEGY
    return false;
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
mc_process_wait_block(struct process *p) {
    while (!process_exited(p)) {
	process_run();
	process_wait(p);
	poll_block();
    }
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

/* It is the caller's responsibility to make sure that the
 * process in question is both marked as running in the model
 * checker and also not crashed in reality before calling this */
static void
mc_kill_process(struct mc_process *proc)
{
    ovs_assert(proc->running);
    int err = process_kill(proc->p, SIGKILL);
    if (err != 0) {
	/* Currently assume that a parent can always kill
	   its child that is running */
	ovs_fatal(err, "Cannot kill process %s", proc->name);
    }
    
    /* This might slow things. OTOH not doing it means that you have 
     * lots of zombie processes hanging around. If things are slow 
     * then maybe comment this out */
    mc_process_wait_block(proc->p);
    mc_process_death(proc);
}

/* Assuming that the system is in a state where there are some
 * processes that are running and some that are crashed, kills
 * off the running processes */
static void
mc_kill_all_processes(void)
{
    process_run();
    for (int i= 0; i < num_procs; i++) {	
	if (mc_procs[i].running) {
	    if (process_exited(mc_procs[i].p)) {
		mc_process_death(&mc_procs[i]);
	    } else {
		mc_kill_process(&mc_procs[i]);
	    }
	} 
    }    
}

static void
mc_get_exit_statuses(struct ds *args)
{
    process_run();
    for (int i= 0; i < num_procs; i++) {	
	if (process_exited(mc_procs[i].p)) {
	    char *status =
		process_status_msg(process_status(mc_procs[i].p));
	    ds_put_format(args, "Process %s ", mc_procs[i].name);
	    ds_put_cstr(args, status);
	    ds_put_cstr(args, "\n");
	    free(status);
	}
    }
}

static void
exec_cmd_and_wait(char **cmd, char *name_err_msg)
{
    struct process *p;
    int err = process_start(cmd, &p);
    if (err != 0) {
	ovs_fatal(err, "Cannot start the %s process", name_err_msg);
    }

    mc_process_wait_block(p);
    
    if (process_status(p) != 0) {
	ovs_fatal(process_status(p), "%s process returned error",
		  name_err_msg);
    }
}

static void
mc_start_all_processes(void)
{
    mc_kill_all_processes();
    
    /* Assume that the cleanup command is idempotent.
       It should not fail, even if cleanup is not required */
    exec_cmd_and_wait(cleanup_cmd, "Cleanup");
    exec_cmd_and_wait(setup_cmd, "Setup");
    
    for (int i = 0; i < num_procs; i++) {
	mc_start_process(&mc_procs[i]);
    }
}

/* Checks if all the processes being run by this model checker are alive
 * If there are any processes which the model checker believes to be running
 * but are acually crashed then returns true */
static bool
mc_processes_crashed(void)
{
    process_run();
    for (int i= 0; i < num_procs; i++) {	
	if (mc_procs[i].running && process_exited(mc_procs[i].p)) {
	    return true;
	}
    }

    return false;
}

static void
mc_load_config_run(struct json *config)
{
    const struct json *run_conf = get_member_or_die(config, "run_config", 0,
						    "Cannot find run_config");
    listen_addr = get_str_member_copy_or_die(run_conf, "listen_address",
					     0, "Cannot find listen_address");

    max_threads_per_proc =
	*(int*) get_member_or_die(run_conf,
				  "max_threads_per_proc",
				  0,
				  "Cant find threads_per_proc");
    
    const char *search_strategy =
	get_str_member_copy_or_die(run_conf,
				   "search_strategy",
				   0,
				   "Cant find search strategy");

    if (!mc_search_strategy_from_string(search_strategy, &strategy)) {
	ovs_fatal(0, "Unknown search strategy");
    }
    
    max_search_depth = *(int*) get_member(run_conf, "max_search_depth");
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

static struct mc_action *
mc_action_alloc(void)
{
    struct mc_action *action = xzalloc(sizeof *action);
    action->refcount++;
    return action;
}

static struct mc_action *
mc_action_inc_ref(struct mc_action *action)
{
    action->refcount++;
    return action;
}

static void
mc_action_dec_ref(struct mc_action **action)
{
    if (*action) {
	(*action)->refcount--;
	
	if ((*action)->refcount <= 0) {
	    if ((*action)->where) {
		free((*action)->where);
	    }
	    
	    if ((*action)->data) {
		free((*action)->data);
	    }
	    free(*action);
	}
	
	*action = NULL;
    }
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
mc_handle_choose_req(int p_idx, int t_idx, const struct mc_rpc_choose_req *rq)
{
    struct mc_action *next_action;
    ovs_assert(wait_thread == &mc_procs[p_idx].threads[t_idx]);
    
    if (fsm_state == MC_FSM_RESTORE_ACTION_WAIT) {
	next_action = restore->path[restore_path_next];

	ovs_assert(next_action->choosetype == rq->type);
	ovs_assert(next_action->subtype == rq->subtype);
	
    } else if (fsm_state == MC_FSM_NEW_ACTION_WAIT) {
	next_action = mc_action_alloc();
	next_action->type = MC_ACTION_UNKNOWN;
	next_action->p_idx = p_idx;
	next_action->t_idx = t_idx;
	next_action->where = xmalloc(strlen(rq->common.where) + 1);
	strcpy(next_action->where, rq->common.where);
	next_action->choosetype = rq->type;
	next_action->subtype = rq->subtype;
	next_action->data = rq->data;
    } else {
	/* Should not be getting choose requests if not
	 * in either of the above two states */
	ovs_assert(0);
    }

    wait_thread->blocked = next_action;
}

static void
mc_handle_rpc(struct jsonrpc *js, int p_idx, int t_idx, const union mc_rpc *rpc)
{
    switch (rpc->common.type) {
    case MC_RPC_HELLO:
    case MC_RPC_BYE:
	mc_handle_hello_or_bye(js, rpc);
	break;
	
    case MC_RPC_CHOOSE_REQ:
	mc_handle_choose_req(p_idx, t_idx, &rpc->choose_req);
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
mc_receive_rpc(struct jsonrpc *js, int p_idx, union mc_rpc *rpc)
{
    struct jsonrpc_msg *msg;
    int error = jsonrpc_recv(js, &msg);
    
    if (error != 0) {
	if (error != EAGAIN) {
	    if (error == EOF) {
		ovs_assert(p_idx >= 0);
		VLOG_INFO("End-of-File from %s\n", mc_procs[p_idx].name);
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
mc_run_conn(struct jsonrpc *js, int p_idx, int t_idx)
{
    if (js) {
	jsonrpc_run(js);
	
	union mc_rpc rpc;
	memset(&rpc, 0, sizeof(rpc));
	if (mc_receive_rpc(js, p_idx, &rpc)) {
	    mc_handle_rpc(js, p_idx, t_idx, &rpc);
	}
    }
}

static bool
mc_all_threads_blocked(void)
{
    for (int i = 0; i < num_procs; i++) {
	if (mc_procs[i].running) {
	    for (int j = 0; j < max_threads_per_proc; j++) {
		if (mc_procs[i].threads[j].valid &&
		    mc_procs[i].threads[j].blocked == NULL) {
		    return false;
		}
	    }
	}
    }
    
    return true;
}

static void
mc_send_choose_reply(struct mc_action *action,
		     enum mc_rpc_choose_reply_type reply_type)
{
    struct jsonrpc *js = mc_procs[action->p_idx].threads[action->t_idx].js;
    
    union mc_rpc rpc;
    rpc.common.type = MC_RPC_CHOOSE_REPLY;
    rpc.common.pid = 0;
    rpc.common.tid = 0;
    rpc.choose_reply.reply = reply_type;
        
    int error = jsonrpc_send_block(js, mc_rpc_to_jsonrpc(&rpc));
    
    if (error != 0) {
	ovs_fatal(error, "Cannot send choose reply to %s\n",
		  mc_procs[action->p_idx].name);
    }   
}

static void
mc_execute_action(struct mc_action *action)
{
    switch(action->type) {
    case MC_ACTION_RPC_REPLY_ERROR:
	mc_send_choose_reply(action, MC_RPC_CHOOSE_REPLY_ERROR);
	break;
	
    case MC_ACTION_RPC_REPLY_NORMAL:
	mc_send_choose_reply(action, MC_RPC_CHOOSE_REPLY_NORMAL);
	break;
	
    case MC_ACTION_TIMER_SHORT:
    case MC_ACTION_TIMER_TRIGGER:
    case MC_ACTION_CRASH_PROCESS:
    case MC_ACTION_UNKNOWN:
	ovs_assert(0);
    }
}

static void
mc_dump_state(void)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    /* FILL ME !!!!!!!! */
    /* Add to the string the current state of the state machine 
     * and other statistics */
    /* If restore is non-NULL then add the actions along 
       the path until restore_path_next */
    mc_get_exit_statuses(&ds);
    fprintf(stderr, "%s", ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
mc_exit_error(void)
{
    mc_dump_state();
    mc_kill_all_processes();
    exit(1);
}

struct sync_dep_entry {
    struct ovs_list list_node;
    uint64_t addr;
    int p_idx;
    int t_idx;
};

static struct sync_dep_entry *
find_sync_dep(struct ovs_list dep_list, uint64_t addr, int p_idx)
{
    struct sync_dep_entry *entry;
    LIST_FOR_EACH (entry, list_node, &dep_list) {
	if (entry->addr == addr && entry->p_idx == p_idx) {
	    return entry;
	}
    }

    return NULL;
}

static void
track_sync_dep(struct mc_action *action, uint64_t addr,
	       struct ovs_list cur_locks)
{
    if (action->choosetype == MC_RPC_CHOOSE_REQ_THREAD) {
	int p_idx = action->p_idx;
	int t_idx = action->t_idx;
	struct sync_dep_entry *entry = find_sync_dep(cur_locks, addr, p_idx);
	
	switch(action->subtype) {
	case MC_RPC_SUBTYPE_SEQ_WAIT:
	case MC_RPC_SUBTYPE_UNLOCK:
	    if (entry) {
		ovs_list_remove(&entry->list_node);
		free(entry);
	    }
	    break;
	    
	case MC_RPC_SUBTYPE_LOCK:
	    if (entry != NULL) {
		/* Same lock acquired twice ???? */
		ovs_assert(0);
	    } /* Fall-thru */
	case MC_RPC_SUBTYPE_SEQ_CHANGE:
	    entry = xmalloc(sizeof *entry);
	    entry->addr = addr;
	    entry->p_idx = p_idx;
	    entry->t_idx = t_idx;
	    ovs_list_push_back(&cur_locks, &entry->list_node);
	    break;

	default:
	    ovs_assert(0);
	}
    }
}

static struct ovs_list
mc_filter_disabled_actions(struct mc_state *cur_state,
			   struct mc_action *cur_action,
			   struct ovs_list actions)
{
    struct ovs_list locks = OVS_LIST_INITIALIZER(&locks);

    /* Construct a map of locks held (or seq_change() calls) 
     * by each thread at the end of this path. The seq_change()/seq_wait()
     * logic is somewhat crude. It will identify a pending seq_change()
     * if the number of seq_wait() calls on a thread are > the number
     * of seq_change() calls. It currently does not take the value
     * passed to seq_wait() into account */
    for (int i = 0; i < cur_state->length; i++) {
    	struct mc_action *action = cur_state->path[i];
    	uint64_t addr = *((uint64_t *) cur_state->path[i]->data);
	track_sync_dep(action, addr, locks);			  
    }
    track_sync_dep(cur_action, *((uint64_t *) cur_action->data), locks);
    
    struct ovs_list filtered = OVS_LIST_INITIALIZER(&filtered);
    while (!ovs_list_is_empty(&actions)) {
	struct mc_action *next =
	    CONTAINER_OF(ovs_list_pop_front(&actions),
			 struct mc_action,
			 list_node);

	if (next->choosetype == MC_RPC_CHOOSE_REQ_THREAD &&
	    (next->subtype == MC_RPC_SUBTYPE_LOCK ||
	     next->subtype == MC_RPC_SUBTYPE_SEQ_WAIT) &&
	    find_sync_dep(locks, *((uint64_t *) next->data),
			  next->p_idx) != NULL) {
	    continue;
	}
	ovs_list_push_back(&filtered, &next->list_node);
    }
    
    while (!ovs_list_is_empty(&locks)) {
	struct sync_dep_entry *entry =
	    CONTAINER_OF(ovs_list_pop_front(&locks),
			 struct sync_dep_entry,
			 list_node);
	free(entry);
    }	

    return filtered;
}

static struct mc_action *
mc_action_copy(struct mc_action * action)
{
    struct mc_action *copy = mc_action_alloc();
    copy->type = action->type;
    copy->p_idx = action->p_idx;
    copy->t_idx = action->t_idx;
    copy->where = xmalloc(strlen(action->where) + 1);
    strcpy(copy->where, action->where);
    copy->choosetype = action->choosetype;
    copy->subtype = action->subtype;
    /* If this changes to anything other than uint64_t then 
       this will need replacement */
    copy->data = xmalloc(sizeof(uint64_t));
    *((uint64_t*) copy->data) = *((uint64_t*) action->data);

    return copy;
}

/* Currently assumes that there are at most two options for an
 * action (e.g. error or normal, timer trigger or short). If that
 * changes then this will need to be modified */
static struct mc_action *
mc_action_expand_unknown(struct mc_action *action)
{
    struct mc_action *other = NULL;
    switch(action->choosetype) {
    case MC_RPC_CHOOSE_REQ_LOG:
	action->type = MC_ACTION_RPC_REPLY_NORMAL;
	other = mc_action_copy(action);
	other->type = MC_ACTION_RPC_REPLY_ERROR;
	break;
	
    case MC_RPC_CHOOSE_REQ_TIMER:
	action->type = MC_ACTION_TIMER_SHORT;
	other = mc_action_copy(action);
	other->type = MC_ACTION_TIMER_TRIGGER;
	break;
	
    case MC_RPC_CHOOSE_REQ_NETWORK:
    case MC_RPC_CHOOSE_REQ_UNIXCTL:
    case MC_RPC_CHOOSE_REQ_THREAD:
	action->type = MC_ACTION_RPC_REPLY_NORMAL;
    }

    return other;
}

/* Gets the list of enabled actions, at the current state */
static struct ovs_list
mc_get_enabled_actions(struct mc_state *cur_state,
		       struct mc_action *cur_action)
{
    /* TODO
     * Add other enabled actions not derived from blocked thread actions
     * like crashes. Also check dependencies for other types of calls 
     * wrapped */    
    struct ovs_list actions = OVS_LIST_INITIALIZER(&actions);
    for (int i = 0; i < num_procs; i++) {
	if (mc_procs[i].running) {
	    for (int j = 0; j < max_threads_per_proc; j++) {
		if (mc_procs[i].threads[j].valid) {
		    ovs_assert(mc_procs[i].threads[j].blocked != NULL);
		    /* See comment with mc_action_expand_unknown() definition */
		    struct mc_action *other =
			mc_action_expand_unknown(mc_procs[i].threads[j].blocked);
		    ovs_list_push_back(&actions,
				       &mc_procs[i].threads[j].blocked->list_node);
		    
		    if (other) {
			ovs_list_push_back(&actions,
					   &other->list_node);
		    }
		}
	    }
	}
    }
    
    struct ovs_list retval = mc_filter_disabled_actions(cur_state,
							cur_action,
							actions);        
    return retval;
}

static void
mc_enqueue_init_state_action_pair(void)
{
    struct mc_queue_item *item = xzalloc(sizeof *item) ;
    item->state = xzalloc(sizeof(struct mc_state)); /* Note: zero initialized */
    item->action = NULL;
    ovs_list_push_back(&mc_queue, &item->list_node);   
}

static struct mc_queue_item *
new_state_action_pair(struct mc_state *cur_state,
		      struct mc_action *cur_action,
		      const int cur_path_len,
		      struct mc_action *next_action)
{
    struct mc_queue_item *new_pair = xmalloc(sizeof *new_pair);
    struct mc_state *new_state = xzalloc(sizeof *new_state);

    if (cur_path_len > 0) {
	new_state->path = xmalloc(sizeof(struct mc_action*) * cur_path_len);
	new_state->length = cur_path_len;
	
	for (int i = 0; i < cur_state->length; i++) {
	    new_state->path[i] = mc_action_inc_ref(cur_state->path[i]);
	}

	new_state->path[cur_state->length] = mc_action_inc_ref(cur_action);
    }

    new_pair->state = new_state;
    new_pair->action = mc_action_inc_ref(next_action);
    return new_pair;
}

static void
mc_enqueue_state_action_pairs(struct mc_state *cur_state,
			      struct mc_action *cur_action,
			      const int cur_path_len,
			      struct ovs_list next_actions)
{
    int i = -1, r = 0;

    if (strategy == MC_SEARCH_STRATEGY_RANDOM) {
	r = random_range(ovs_list_size(&next_actions));
    }
    
    while (!ovs_list_is_empty(&next_actions)) {
	struct mc_action *next_action =
	    CONTAINER_OF(ovs_list_pop_front(&next_actions),
			 struct mc_action,
			 list_node);
	
	struct mc_queue_item *pair =
	    new_state_action_pair(cur_state,
				  cur_action,
				  cur_path_len,
				  next_action);

	switch (strategy) {
	case MC_SEARCH_STRATEGY_BREADTH:
	    ovs_list_push_back(&mc_queue, &pair->list_node);
	    break;
	    
	case MC_SEARCH_STRATEGY_DEPTH:
	    ovs_list_push_front(&mc_queue, &pair->list_node);
	    break;
	    
	case MC_SEARCH_STRATEGY_RANDOM:
	    if (++i == r) {
		ovs_list_push_back(&mc_queue, &pair->list_node);
	    }
	    break;
	    
	case MC_SEARCH_STRATEGY_SINGLE:
	    ovs_assert(0);
	}
    }
}

/* Dequeues the current front of the queue and adds the next list of
 * enabled actions to the queue (front or back) based on the search strategy */
static void
mc_explore(void)
{   
    int cur_path_len = 0;
    struct mc_state *cur_state = CONTAINER_OF(ovs_list_front(&mc_queue),
					      struct mc_queue_item,
					      list_node)->state;
    cur_path_len += cur_state->length;

    struct mc_action *cur_action = CONTAINER_OF(ovs_list_front(&mc_queue),
					      struct mc_queue_item,
					      list_node)->action;
    
    if (cur_action) {
	cur_path_len += 1;
    }
    /* If in the initial state cur_path_len should be 0 */
    ovs_assert(cur_path_len == 0 || cur_path_len == cur_state->length + 1);

    /* Pop the front of mc_queue. We pop it here instead of earlier
     * because otherwise the loop in "int main()" which relies on the queue 
     * being non-empty will break incorrectly (e.g. after dequeuing the 
     * initial <state, action> pair and while waiting for a network event) */
    ovs_assert(!ovs_list_is_empty(&mc_queue));
    struct mc_queue_item *front = CONTAINER_OF(ovs_list_pop_front(&mc_queue),
					       struct mc_queue_item,
					       list_node);
    free(front);

    /* Now get more <state,action> pairs and add them to the front or back
     * of the queue based on the search strategy. Important to pop the front
     * of the queue above before this step, since we might add new pairs to
     * the front of the queue (if strategy is DFS) */
    if (max_search_depth < 0 || cur_path_len < max_search_depth) {
	switch (strategy) {
	case MC_SEARCH_STRATEGY_BREADTH:
	case MC_SEARCH_STRATEGY_DEPTH:
	case MC_SEARCH_STRATEGY_RANDOM:
	    mc_enqueue_state_action_pairs(cur_state,
					  cur_action,
					  cur_path_len,
					  mc_get_enabled_actions(cur_state,
								 cur_action));
	    
	    break;
	    
	case MC_SEARCH_STRATEGY_SINGLE:
	    ovs_assert(0);
	}
    } else if (cur_path_len >= max_search_depth) {
	/* Should only trigger when these two are equal */
	ovs_assert(cur_path_len == max_search_depth);
	max_search_depth_reached = true;
	
	if(strategy == MC_SEARCH_STRATEGY_RANDOM) {
	    mc_enqueue_init_state_action_pair();
	}
    } /* FIX ME !!! If max_search_depth == -1 (i.e. disabled) then we
       * need some way of knowing when a termination condition
       * has been reached for DFS or Random Walk */

    /* Now free up any memory for the <state,action> pair we popped earlier */
    for (int i = 0; i < cur_state->length; i++) {
	mc_action_dec_ref(&cur_state->path[i]);
    }
    free(cur_state);

    if (cur_action) {
	mc_action_dec_ref(&cur_action);
    }
}

static void
mc_run(void)
{
    struct mc_action *action = NULL;
    enum mc_fsm_state next_state;
	
    switch(fsm_state) {
    case MC_FSM_PRE_INIT:
	mc_start_all_processes();
	fsm_state = MC_FSM_RESTORE_INIT_WAIT;
	break;

    case MC_FSM_RESTORE_INIT_WAIT:
	if (mc_all_threads_blocked()) {
	    restore = CONTAINER_OF(ovs_list_front(&mc_queue),
				   struct mc_queue_item,
				   list_node)->state;
	    restore_path_next = 0;
	    fsm_state = MC_FSM_RESTORE_MID_STATE;
	}
	break;

    case MC_FSM_RESTORE_MID_STATE:
	if (restore && restore_path_next < restore->length) {
	    action = restore->path[restore_path_next++];
	    next_state = MC_FSM_RESTORE_ACTION_WAIT;
	} else {
	    action = CONTAINER_OF(ovs_list_front(&mc_queue),
				  struct mc_queue_item,
				  list_node)->action;

	    if (action) {
		next_state = MC_FSM_NEW_ACTION_WAIT;
	    } else {
		next_state = MC_FSM_NEW_STATE;
	    } 
	}

	if (action) {
	    wait_thread = &mc_procs[action->p_idx].threads[action->t_idx];
	    mc_action_dec_ref(&wait_thread->blocked);
	    mc_execute_action(action);
	}
	fsm_state = next_state;
	break;

    case MC_FSM_RESTORE_ACTION_WAIT:
	if (wait_thread->blocked != NULL) {
	    fsm_state = MC_FSM_RESTORE_MID_STATE;
	}
	break;

    case MC_FSM_NEW_ACTION_WAIT:
	if (wait_thread->blocked != NULL) {
	    fsm_state = MC_FSM_NEW_STATE;
	}
	break;

    case MC_FSM_NEW_STATE:
	mc_explore();

	if ((strategy == MC_SEARCH_STRATEGY_DEPTH ||
	     strategy == MC_SEARCH_STRATEGY_RANDOM) &&
	    !max_search_depth_reached) {
	    
	    fsm_state = MC_FSM_RESTORE_MID_STATE;
	    restore = NULL;
	} else {
	    fsm_state = MC_FSM_PRE_INIT;

	    if (max_search_depth_reached) {
		max_search_depth_reached = false;
	    }
	} /* If max_search_depth == -1 (i.e. disabled) then we
	   * need some way of knowing when a termination condition
	   * has been reached for DFS or Random Walk */
	break;

    default:
	ovs_assert(0);
    }
    
    if (mc_processes_crashed()) {
	/* otherwise there is some problem with the model checker */
	ovs_assert(fsm_state == MC_FSM_NEW_ACTION_WAIT);
	
	/* FIX ME !!!!!!!!!!!!
	 * Here instead of exiting, decide what to do based on a 
	 * config option which decides if you should either:
	 * 1) error exit after dumping path and killing processes
	 *    (current behavior)
	 * 2) dump the path along with the error and then continue
	 *    without exploring down this path further. This can be
	 *    easily ensured by avoiding the call to mc_explore 
	 *    (by short circuiting the transition to MC_FSM_NEW_STATE) */
	mc_exit_error();
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
	mc_run_conn(conn->js, -1, -1);
    }

    for (int i= 0; i < num_procs; i++) {	
	if (mc_procs[i].running) {
	    for (int j = 0; j < max_threads_per_proc; j++) {
		if (mc_procs[i].threads[j].valid) {
		    mc_run_conn(mc_procs[i].threads[j].js, i, j);
		}
	    }
	}
    }
    
    /* TODO check for timeouts of processes that are believed 
     * to be running but have not contacted the model checker
     * for a decision for TIMEOUT secs. They might be stuck in 
     * an infinite loop */
}

int
main(int argc, char *argv[])
{
    if (argc < 2) {
	ovs_fatal(0, "Usage is ./mc <configfile>. Not enough arguments provided");
    }

    mc_load_config(argv[1]);

    int error = pstream_open(listen_addr, &listener, DSCP_DEFAULT);    
    if (error) {
	ovs_fatal(error, "Cannot open the listening conn due to %s\n",
		  ovs_strerror(error));
    }

    mc_enqueue_init_state_action_pair();
    while(!ovs_list_is_empty(&mc_queue)) {
    	mc_run();
    }
    
    return 0;
}
