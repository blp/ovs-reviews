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

/*
 * A raft client which takes a list of commands to send to a raft server
 * driver (the kind in tests/mc/raft-driver.c) and sends them using library 
 * calls interposed on by the model checker
 */

#include <config.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include "command-line.h"
#include "openvswitch/json.h"
#include "ovsdb-error.h"
#include "poll-loop.h"
#include "unixctl.h"
#include "util.h"

#define MAX_LINE_SIZE 50

int
main(int argc, char *argv[])
{
    if (argc < 4) {
	ovs_fatal(0, "Not enough arguments provided to raft-client");
    }

    /*XXX Possibly add usage help and more sophisticated option processing */

    struct jsonrpc *raft_conn;
    unixctl_client_create(argv[1], &raft_conn);

    struct jsonrpc *mc_conn;
    unixctl_client_create(argv[2], &mc_conn);

    FILE *fp = fopen(argv[3], "r");

    if (fp == NULL) {
	ovs_fatal(0, "Client cannot open the command file");
    }

    char* linep = xmalloc(MAX_LINE_SIZE);
    while (fgets(linep, MAX_LINE_SIZE, fp) != NULL) {
	char *result, *err, *cmd, *arg;
	struct json *cmd_json = json_object_create();

	/* Assuming that all the commands will have exactly one argument */
	char *copy_linep = linep;
	cmd = strsep(&copy_linep, " ");
	arg = strsep(&copy_linep, " \n");
	json_object_put_string(cmd_json, cmd, arg);

	char* cmd_str[] = {json_to_string(cmd_json, 0)};
	unixctl_client_transact(raft_conn, "execute", 1, cmd_str, &result, &err);

	if (err == NULL) {
	    /* This could be because the server crashed (including deliberately
	     * by the model checker). Contact some other server ?
	     */
	    printf("Error: raft-client cannot communicate with server");
	} else {
	    /* Again here the server being contacted might not be the leader
	     * in which case, maybe contact another server */
	    printf("Command %s %s resulted in %s", cmd, arg, result);
	}
    }

    return 0;
}

