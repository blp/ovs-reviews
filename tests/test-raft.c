/*
 * Copyright (c) 2016 Nicira, Inc.
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
#include "command-line.h"
#include "daemon.h"
#include "fatal-signal.h"
#include "ovsdb-error.h"
#include "poll-loop.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"

OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[]);

static unixctl_cb_func test_raft_exit;
static unixctl_cb_func test_raft_execute;

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
    service_start(&argc, &argv);
    fatal_signal_init();
    parse_options(argc, argv);

    if (argc - optind != 1) {
        ovs_fatal(0, "exactly one non-option argument required "
                  "(use --help for help)");
    }

    daemonize_start(false);

    struct raft *raft;
    check_ovsdb_error(raft_open(argv[optind], &raft));

    struct unixctl_server *server;
    int error = unixctl_server_create(NULL, &server);
    if (error) {
        ovs_fatal(error, "failed to create unixctl server");
    }

    bool exiting = false;
    unixctl_command_register("exit", "", 0, 0, test_raft_exit, &exiting);
    unixctl_command_register("execute", "DATA", 1, 1, test_raft_execute, raft);

    daemonize_complete();

    for (;;) {
        unixctl_server_run(server);
        raft_run(raft);

        if (exiting) {
            break;
        }

        unixctl_server_wait(server);
        raft_wait(raft);
        poll_block();
    }
    unixctl_server_destroy(server);
    raft_close(raft);

    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        DAEMON_OPTION_HANDLERS
        VLOG_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("%s: Raft implementation test utility\n"
           "usage: %s [OPTIONS] LOG\n"
           "where LOG is the Raft log file.\n",
           program_name, program_name);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help                  display this help message\n");
    exit(EXIT_SUCCESS);
}

static void
test_raft_exit(struct unixctl_conn *conn,
                  int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
                  void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}

static void
test_raft_execute(struct unixctl_conn *conn,
                  int argc OVS_UNUSED, const char *argv[],
                  void *raft_)
{
    struct raft *raft = raft_;
    raft_command_execute(raft, argv[1]);
    unixctl_command_reply(conn, NULL);
}

