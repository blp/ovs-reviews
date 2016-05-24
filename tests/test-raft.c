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
#include "uuid.h"
#include "openvswitch/vlog.h"

struct execute_command {
    struct ovs_list list_node;
    struct raft_command *cmd;
    struct unixctl_conn *conn;
};

struct execute_ctx {
    struct raft *raft;
    struct ovs_list commands;
};

OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[], char **unixctl_pathp);

static unixctl_cb_func test_raft_exit;
static unixctl_cb_func test_raft_execute;
static unixctl_cb_func test_raft_take_leadership;
static unixctl_cb_func test_raft_store_snapshot;

/* --cluster: UUID of cluster to open or join. */
static struct uuid cluster_id;

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
    char *unixctl_pathp = NULL;
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    fatal_signal_init();
    parse_options(argc, argv, &unixctl_pathp);

    argc -= optind;
    argv += optind;
    if (argc == 0 || argc == 2) {
        ovs_fatal(0, "either one or more than two non-option arguments "
                  " required (use --help for help)");
    }

    daemonize_start(false);

    struct raft *raft;
    const char *file_name = argv[0];
    if (argc == 1) {
        check_ovsdb_error(raft_open(file_name, &raft));
    } else {
        const char *local_address = argv[1];
        char **remote_addresses = &argv[2];
        size_t n_remotes = argc - 2;
        const struct uuid *cid = (uuid_is_zero(&cluster_id)
                                  ? NULL : &cluster_id);

        check_ovsdb_error(raft_join(file_name, local_address,
                                    remote_addresses, n_remotes,
                                    cid, &raft));
    }

    struct unixctl_server *server;
    int error = unixctl_server_create(unixctl_pathp, &server);
    if (error) {
        ovs_fatal(error, "failed to create unixctl server");
    }

    bool exiting = false;
    unixctl_command_register("exit", "", 0, 0, test_raft_exit, &exiting);

    struct execute_ctx ec = { raft, OVS_LIST_INITIALIZER(&ec.commands) };
    unixctl_command_register("execute", "DATA", 1, 1, test_raft_execute, &ec);

    unixctl_command_register("take-leadership", "", 0, 0,
                             test_raft_take_leadership, raft);
    unixctl_command_register("store-snapshot", "SNAPSHOT", 1, 1,
                             test_raft_store_snapshot, raft);

    daemonize_complete();

    for (;;) {
        unixctl_server_run(server);

        raft_run(raft);
        while (raft_has_next_entry(raft)) {
            const char *entry;
            bool snapshot;

            entry = raft_next_entry(raft, &snapshot);
            if (snapshot) {
                printf("new snapshot \"%s\"\n", entry);
            } else {
                printf("applying entry \"%s\"\n", entry);
            }
        }

        if (exiting) {
            break;
        }

        struct execute_command *c;
        LIST_FOR_EACH (c, list_node, &ec.commands) {
            enum raft_command_status status = raft_command_get_status(c->cmd);
            if (status != RAFT_CMD_INCOMPLETE) {
                unixctl_command_reply(c->conn,
                                      raft_command_status_to_string(status));
                raft_command_unref(c->cmd);
                ovs_list_remove(&c->list_node);
                free(c);
            }
        }

        unixctl_server_wait(server);
        raft_wait(raft);
        LIST_FOR_EACH (c, list_node, &ec.commands) {
            raft_command_wait(c->cmd);
        }
        poll_block();
    }
    unixctl_server_destroy(server);
    raft_close(raft);

    return 0;
}

static void
parse_options(int argc, char *argv[], char **unixctl_pathp)
{
    enum {
        OPT_CLUSTER = UCHAR_MAX + 1,
        OPT_UNIXCTL,
        DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        {"cluster", required_argument, NULL, OPT_CLUSTER},
        {"unixctl", required_argument, NULL, OPT_UNIXCTL},
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
        case OPT_CLUSTER:
            if (!uuid_from_string(&cluster_id, optarg)) {
                ovs_fatal(0, "\"%s\" is not a valid UUID", optarg);
            }
            break;

        case OPT_UNIXCTL:
            *unixctl_pathp = optarg;
            break;

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
           "  --cluster=UUID          force cluster ID\n"
           "  --unixctl=SOCKET        override default control socket name\n"
           "  -h, --help              display this help message\n");
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
                  void *ctx_)
{
    struct execute_ctx *ctx = ctx_;
    struct execute_command *command = xmalloc(sizeof *command);
    ovs_list_push_back(&ctx->commands, &command->list_node);
    command->cmd = raft_command_execute(ctx->raft, argv[1]);
    command->conn = conn;
}


static void
test_raft_take_leadership(struct unixctl_conn *conn,
                          int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
                          void *raft_)
{
    struct raft *raft = raft_;
    raft_take_leadership(raft);
    unixctl_command_reply(conn, NULL);
}

static void
test_raft_store_snapshot(struct unixctl_conn *conn,
                         int argc OVS_UNUSED, const char *argv[],
                         void *raft_)
{
    struct raft *raft = raft_;
    raft_store_snapshot(raft, argv[1]);
    unixctl_command_reply(conn, NULL);
}
