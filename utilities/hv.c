/*
 * Copyright (c) 2018 Nicira, Inc.
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
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "command-line.h"
#include "process.h"
#include "util.h"

static void usage(void);
static void parse_command_line(int argc, char *argv[]);

static void
read_file(const char *fn)
{
    int fd = open(fn, O_RDONLY);
    if (fd < 0) {
        ovs_fatal(errno, "%s: open failed", fn);
    }

    int size = 4096 * 1024;
    char *buffer = xmalloc(size);
    for (;;) {
        ssize_t n = read(fd, buffer, size);
        if (n < 0) {
            ovs_fatal(errno, "%s: read failed", fn);
        } else if (!n) {
            break;
        }
    }
    free(buffer);

    close(fd);
}

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    parse_command_line (argc, argv);

    for (int i = optind; i < argc; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            ovs_fatal(errno, "fork failed");
        } else if (!pid) {
            /* Child. */
            read_file(argv[i]);
            exit(0);
        }
    }

    for (;;) {
        int status;
        pid_t pid = wait(&status);
        if (pid < 0) {
            break;
        }

        printf ("child %ld exited (%s)\n",
                (long int) pid, process_status_msg (status));
    }
    if (errno != ECHILD) {
        ovs_fatal(errno, "wait failed");
    }

    return 0;
}

static void
usage(void)
{
    printf("\
%s, for querying log files\n\
usage: %s [TARGET] COMMAND [ARG...]\n\
\n\
Common commands:\n\
  list-commands      List commands supported by the target\n\
  version            Print version of the target\n\
  vlog/list          List current logging levels\n\
  vlog/list-pattern  List logging patterns for each destination.\n\
  vlog/set [SPEC]\n\
      Set log levels as detailed in SPEC, which may include:\n\
      A valid module name (all modules, by default)\n\
      'syslog', 'console', 'file' (all destinations, by default))\n\
      'off', 'emer', 'err', 'warn', 'info', or 'dbg' ('dbg', bydefault)\n\
  vlog/reopen        Make the program reopen its log file\n\
Other options:\n\
  -h, --help         Print this helpful information\n\
  -V, --version      Display ovs-appctl version information\n",
           program_name, program_name);
    exit(EXIT_SUCCESS);
}

static void
parse_command_line(int argc, char *argv[])
{
    enum {
        OPT_START = UCHAR_MAX + 1,
    };
    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };
    char *short_options_ = ovs_cmdl_long_options_to_short_options(long_options);
    char *short_options = xasprintf("+%s", short_options_);

    for (;;) {
        int option;

        option = getopt_long(argc, argv, short_options, long_options, NULL);
        if (option == -1) {
            break;
        }
        switch (option) {

        case 'h':
            usage();
            break;

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        case '?':
            exit(EXIT_FAILURE);

        default:
            OVS_NOT_REACHED();
        }
    }
    free(short_options_);
    free(short_options);

    if (optind >= argc) {
        ovs_fatal(0, "at least one non-option argument is required "
                  "(use --help for help)");
    }
}
