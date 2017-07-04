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
    bool running;
};

struct mc_conn {
    struct ovs_list list_node;
    struct jsonrpc_session *js;
    unsigned int js_seqno;
};

static struct ovs_list mc_processes = OVS_LIST_INITIALIZER(&mc_processes);
static struct ovs_list mc_conns = OVS_LIST_INITIALIZER(&mc_conns);
static char* listen_addr = NULL;
static struct pstream *listener = NULL;
static bool all_processes_running = false;

static void
mc_start_process(struct mc_process *new_proc) {
    /* Prepare to redirect stderr and stdout of the process to a file
     * and then start the process */

    int stdout_copy = dup(fileno(stdout));
    int stderr_copy = dup(fileno(stderr));
    
    char path[strlen(new_proc->name) + 4];
    strcpy(path, new_proc->name);
    strcpy(path + strlen(new_proc->name), ".out");
    int fd = open(path, O_CREAT|O_RDWR|O_TRUNC, S_IRWXU);

    if (fd < 0) {
	ovs_fatal(errno, "Cannot open outfile for process %s",
		  new_proc->name);
    }
    
    dup2(fd, fileno(stdout));
    dup2(fd, fileno(stderr));
    
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
    close(fd);
}

static void
mc_start_all_processes(void)
{
    struct mc_process *new_proc;
    LIST_FOR_EACH (new_proc, list_node, &mc_processes) {
	if (!new_proc->running) {
	    mc_start_process(new_proc);
	}
    }
    all_processes_running = true;
}

static void
mc_read_config_run(struct json *config) {
    ovs_assert(config->type == JSON_OBJECT);
    
    struct json *run_conf = shash_find_data(config->u.object,
					     "run_config");    
    if (run_conf == NULL) {
	ovs_fatal(0, "Cannot find the run config");
    }

    struct shash_node *addr = shash_first(run_conf->u.object);
    struct json *listen_conf = addr->data; 
    listen_addr = xmalloc(strlen(listen_conf->u.string) + 1);
    strcpy(listen_addr, listen_conf->u.string);
}

static void
mc_read_config_processes(struct json *config) {

    ovs_assert(config->type == JSON_OBJECT);
    
    struct json *exec_conf = shash_find_data(config->u.object,
					     "model_check_execute");
    
    if (exec_conf == NULL) {
	ovs_fatal(0, "Cannot find the execute config");
    }

    ovs_assert(exec_conf->type == JSON_ARRAY);

    struct mc_process *new_proc;
    for (int i = 0; i < exec_conf->u.array.n; i++) {
	struct shash_node *exe =
	    shash_first(exec_conf->u.array.elems[i]->u.object);
	new_proc = xmalloc(sizeof(struct mc_process));
	new_proc->name = xmalloc(strlen(exe->name) + 1);
	strcpy(new_proc->name, exe->name);

	struct json *exe_data = exe->data;
	exe_data = shash_find_data(exe_data->u.object, "command");

	if (exe_data == NULL) {
	    ovs_fatal(0, "Did not find command for %s\n", exe->name);
	}
	
	char **run_cmd = xmalloc(sizeof(char*) * (exe_data->u.array.n + 1));
	int j = 0;
	for (; j < exe_data->u.array.n; j++) {
	    run_cmd[j] = xmalloc(strlen(exe_data->u.array.elems[j]->u.string)
				 + 1);
	    strcpy(run_cmd[j], exe_data->u.array.elems[j]->u.string);
	}
	run_cmd[j] = NULL;
	new_proc->run_cmd = run_cmd;
	
	/* Should we failure inject this process ? */
	
	exe_data = exe->data;
	exe_data = shash_find_data(exe_data->u.object, "failure_inject");
	if (exe_data == NULL ||
	    !(exe_data->type == JSON_TRUE || exe_data->type == JSON_FALSE)) {

	    ovs_fatal(0,
		      "Did not find failure_inject boolean for %s\n",
		      exe->name);
	} else if (exe_data->type == JSON_TRUE) {
	    new_proc->failure_inject = true;
	} else {
	    new_proc->failure_inject = false;
	}

	new_proc->running = false;
	ovs_list_push_back(&mc_processes, &new_proc->list_node);
    }
}

static void
mc_read_config(struct json *config)
{
    mc_read_config_run(config);
    mc_read_config_processes(config);
}

static void
mc_run(void)
{
    if (!listener) {
	int error = pstream_open(listen_addr, &listener, DSCP_DEFAULT);

	if (error) {
	    ovs_fatal(error, "Cannot open the listening conn");
	}
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
    
    if (!all_processes_running) {
	mc_start_all_processes();
    }
}

int
main(int argc, char *argv[])
{
    if (argc < 2) {
	ovs_fatal(0, "Usage is ./mc <configfile>. Not enough arguments provided");
    }

    struct json *config = json_from_file(argv[1]);

    if (config->type == JSON_STRING) {
	ovs_fatal(0, "Cannot read the json config in %s\n%s", argv[1], config->u.string);
    }

    mc_read_config(config);

    for(;;) {
	mc_run();
    }
    
    return 0;
}
