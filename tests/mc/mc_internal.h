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

const char *mc_rpc_type_to_string(enum mc_rpc_type status);
const void *get_member(const struct json *json, const char *name);
const void *get_first_member(const struct json *json, char **name, bool copy_name);
const void *get_member_or_die(const struct json *json, const char *name, 
			      int err_no, const char *format, ...);
const char *get_str_member_copy(const struct json *json, const char *name);
const char *get_str_member_copy_or_die(const struct json *json, const char *name,
				       int err_no, const char *format, ...);
bool mc_rpc_type_from_string(const char *s, enum mc_rpc_type *status);
