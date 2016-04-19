/*
 * Copyright (c) 2009, 2010, 2014 Nicira, Inc.
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
#include <getopt.h>
#include "ovsdb/raft.h"
#include <stdio.h>
#include "ovsdb-error.h"
#include "poll-loop.h"
#include "util.h"

static void
check_ovsdb_error(struct ovsdb_error *error)
{
    if (error) {
        char *s = ovsdb_error_to_string(error);
        ovsdb_error_destroy(error);
        ovs_fatal(0, "%s", s);
    }
}

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);

    if (argc - optind != 1) {
        ovs_fatal(0, "usage: %s LOG", program_name);
    }

    struct raft *raft;
    check_ovsdb_error(raft_open(argv[optind], &raft));

    for (;;) {
        raft_run(raft);
        raft_wait(raft);
        poll_block();
    }
}
