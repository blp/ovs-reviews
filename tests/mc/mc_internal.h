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

#ifndef MC_INTERNAL_H
#define MC_INTERNAL_H 1

#include "mc.h"
#include "openvswitch/json.h"

const void *get_member(const struct json *json, const char *name);
const void *get_first_member(const struct json *json, char **name, bool copy_name);
const void *get_member_or_die(const struct json *json, const char *name, 
			      int err_no, const char *format, ...);
const char *get_str_member_copy(const struct json *json, const char *name);
const char *get_str_member_copy_or_die(const struct json *json, const char *name,
				       int err_no, const char *format, ...);
#endif /* tests/mc/mc_internal.h */
