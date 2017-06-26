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
#include "command-line.h"
#include "openvswitch/json.h"
#include "ovsdb-error.h"
#include "poll-loop.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"

int
main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct jsonrpc *client;
    unixctl_client_create(argv[1], &client);

    char *result, *err;
    unixctl_client_transact(client, "exit", 0, NULL , &result, &err);

    printf("The result was %s and error was %s\n", result, err);
    
    return 0;
}

