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
#include "jsonrpc.h"
#include "mc.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/list.h"
#include "openvswitch/vlog.h"
#include "process.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(mc);

struct mc_process {
    struct ovs_list list_node;
    struct jsonrpc_session *js;
    char* name;
    struct uuid sid;
};

static struct ovs_list
    
int
main(int argc, char *argv[])
{
    if (argc < 2) {
	ovs_fatal(0, "Not enough arguments provided to raft-client");
    }

    struct json *config = json_from_file(argv[1]);

    if (config->type == JSON_STRING) {
	ovs_fatal(0, "Cannot read the json config in %s\n%s", argv[1], config->u.string);
    }

    
    
    return 0;
}
