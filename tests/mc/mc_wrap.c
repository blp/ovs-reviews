/*
 * Copyright (c) 2014, 2016, 2017 Nicira, Inc.
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
#include "mc.h"
#include "mc_wrap.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(mc_wrap);

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_open(const char *name,
		       const char *magic,
		       enum ovsdb_log_open_mode open_mode,
		       int locking, struct ovsdb_log **filep)
{
  return ovsdb_log_open(name, magic, open_mode, locking, filep);
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_read(struct ovsdb_log *file, struct json **jsonp)
{
  return ovsdb_log_read(file, jsonp);
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_write(struct ovsdb_log *file,
			const struct json *json)
{
  return ovsdb_log_write(file, json);
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_commit(struct ovsdb_log *file)
{
  return ovsdb_log_commit(file);
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_replace_start(struct ovsdb_log *old,
				struct ovsdb_log **newp)
{
  return ovsdb_log_replace_start(old, newp);
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
mc_wrap_ovsdb_log_replace_commit(struct ovsdb_log *old,
				 struct ovsdb_log *new)
{
  return ovsdb_log_replace_commit(old, new);
}
