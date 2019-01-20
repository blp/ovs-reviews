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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "command-line.h"
#include "ovs-thread.h"
#include "process.h"
#include "random.h"
#include "util.h"

#include "openvswitch/vlog.h"
VLOG_DEFINE_THIS_MODULE(hv);

static const char *grep;

struct substring {
    const char *s;
    size_t length;
};

static bool
ss_equals(struct substring a, struct substring b)
{
    return a.length == b.length && !memcmp(a.s, b.s, a.length);
}

static struct substring
ss_cstr(const char *s)
{
    return (struct substring) { .s = s, .length = strlen(s) };
}

struct log_record {
    bool valid;                 /* Fully parsed record? */
    int facility;               /* 0...23. */
    int priority;               /* 0...7. */
    struct substring timestamp; /* Date and time. */
    struct substring hostname;  /* Hostname. */
    struct substring app_name;  /* Application. */
    struct substring procid;    /* Process ID. */
    struct substring msgid;     /* Message ID. */
    struct substring sdid;      /* Structured data ID. */
    struct substring comp;      /* From structured data. */
    struct substring subcomp;   /* From structured data. */
    struct substring msg;       /* Message content. */
};

enum datum_type {
    DATUM_STRING,
    DATUM_REAL,
    DATUM_INTEGER,
    DATUM_INSTANT,
    DATUM_DURATION,
};

union datum {
    struct {
        char *string;
        size_t length;
    };
    double real;
    int64_t integer;
    long long int instant;      /* Milliseconds since the epoch. */
    long long int duration;     /* Milliseconds. */
};

static void usage(void);
static void parse_command_line(int argc, char *argv[]);

struct parse_ctx {
    const char *fn;
    int ln;

    const char *line_start;
    const char *line_end;
    const char *p;
};

static void OVS_PRINTF_FORMAT(2, 3)
warn(const struct parse_ctx *ctx, const char *format, ...)
{
    fprintf(stderr, "%s:%d.%td: ",
            ctx->fn, ctx->ln, ctx->p - ctx->line_start + 1);

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    putc('\n', stderr);
}

static bool
match(struct parse_ctx *ctx, char c)
{
    if (*ctx->p == c) {
        ctx->p++;
        return true;
    } else {
        return false;
    }
}

static bool
must_match(struct parse_ctx *ctx, char c)
{
    bool matched = match(ctx, c);
    if (!matched) {
        warn(ctx, "expected '%c'", c);
    }
    return matched;
}

static bool
c_isdigit(int c)
{
    return c >= '0' && c <= '9';
}

static bool OVS_UNUSED
c_isalpha(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int
c_tolower(int c)
{
    //return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
    return c;
}

static bool
get_header_token(struct parse_ctx *ctx, struct substring *token)
{
    if (!must_match(ctx, ' ')) {
        return false;
    }

    if (*ctx->p == ' ') {
        warn(ctx, "unexpected space in header");
        return false;
    }

    token->s = ctx->p;
    token->length = 0;
    while (token->s[token->length] != ' ') {
        if (token->s[token->length] == '\n') {
            warn(ctx, "unexpected end of message parsing header");
            return false;
        }
        token->length++;
    }
    ctx->p += token->length;

    /* Turn NILVALUE into empty string. */
    if (token->length == 1 && token->s[0] == '-') {
        token->length = 0;
    }

    return true;
}

static bool
get_sd_name(struct parse_ctx *ctx, struct substring *dst)
{
    dst->s = ctx->p;
    dst->length = strcspn (dst->s, " =]\"\n");
    if (dst->length == 0) {
        warn(ctx, "parse error expecting SDNAME");
        return false;
    }
    ctx->p += dst->length;
    return true;
}

static bool
get_sd_param(struct parse_ctx *ctx, struct log_record *rec)
{
    struct substring name;
    if (!get_sd_name(ctx, &name)) {
        return false;
    }

    if (!must_match(ctx, '=') || !must_match(ctx, '"')) {
        return false;
    }

    struct substring value;
    value.s = ctx->p;
    for (;;) {
        if (*ctx->p == '\\' && ctx->p[1] != '\n') {
            ctx->p++;
        } else if (*ctx->p == '"') {
            break;
        } else if (*ctx->p == '\n') {
            warn(ctx, "unexpected end of line parsing parameter value");
            return false;
        }
        ctx->p++;
    }
    value.length = ctx->p - value.s;
    ctx->p++;                   /* Skip end quote. */

    if (ss_equals(name, ss_cstr("comp"))) {
        rec->comp = value;
    } else if (ss_equals(name, ss_cstr("subcomp"))) {
        rec->subcomp = value;
    }
    return true;
}

static bool
parse_record(struct parse_ctx *ctx, struct log_record *rec)
{
    /* PRI. */
    if (!must_match(ctx, '<')) {
        return false;
    }
    unsigned int pri = 0;
    while (c_isdigit(*ctx->p)) {
        pri = pri * 10 + (*ctx->p++ - '0');
    }
    rec->facility = pri / 8;
    rec->priority = pri % 8;
    if (!must_match(ctx, '>')) {
        return false;
    }

    /* VERSION. */
    if (!must_match(ctx, '1')) {
        return false;
    }

    /* Identifiers. */
    if (!get_header_token(ctx, &rec->timestamp)
        || !get_header_token(ctx, &rec->hostname)
        || !get_header_token(ctx, &rec->app_name)
        || !get_header_token(ctx, &rec->procid)
        || !get_header_token(ctx, &rec->msgid)) {
        return false;
    }

    /* Structured data. */
    if (!must_match(ctx, ' ')) {
        return false;
    }
    if (match(ctx, '[')) {
        if (!get_sd_name(ctx, &rec->sdid)) {
            return false;
        }
        while (match(ctx, ' ')) {
            if (!get_sd_param(ctx, rec)) {
                return false;
            }
        }
        if (!must_match(ctx, ']')) {
            return false;
        }
    } else if (!match(ctx, '-')) {
        warn(ctx, "expected '-' or '['");
        return false;
    }

    if (!match(ctx, ' ')) {
        return must_match(ctx, '\n');
    }

    rec->msg.s = ctx->p;
    rec->msg.length = ctx->line_end - ctx->p;
    return true;
}

#if 0
static int
compare_strings(const void *a_, const void *b_)
{
    const char *const *a = a_;
    const char *const *b = b_;
    return strcmp(*a, *b);
}
#endif

static void
split(const struct substring *msg)
{
    char *tokens[64];
    size_t n_tokens = 0;

    char *s = xmemdup0(msg->s, msg->length);
    char *save_ptr = NULL;
    for (char *token = strtok_r(s, " \t\r\n", &save_ptr); token;
         token = strtok_r(NULL, " \t\r\n", &save_ptr)) {
        char *q = token;
        for (char *p = token; *p; p++) {
            if (c_isdigit(*p)) {
                q = token;
                *q++ = '_';
                break;
            } else {
                *q++ = c_tolower(*p);
            }
        }
        if (q > token) {
            tokens[n_tokens++] = xmemdup0(token, q - token);
            if (n_tokens >= ARRAY_SIZE(tokens)) {
                break;
            }
        }
    }

    if (n_tokens) {
        for (size_t i = 0; i < n_tokens; i++) {
            if (i) {
                putchar(' ');
            }
            fputs(tokens[i], stdout);
            free(tokens[i]);
        }
        putchar('\n');
    }

    free(s);
}

static void *
read_file(const char *fn)
{
    int fd = open(fn, O_RDONLY);
    if (fd < 0) {
        ovs_fatal(errno, "%s: open failed", fn);
    }

    struct stat s;
    if (fstat(fd, &s) < 0) {
        ovs_fatal(errno, "%s; stat failed", fn);
    }

    off_t size = s.st_size;
    char *buffer = mmap (NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    if (buffer == MAP_FAILED) {
        ovs_fatal(errno, "%s: mmap failed", fn);
    }
    char *end = buffer + size;
    close(fd);

    if (madvise(buffer, size, MADV_WILLNEED) < 0) {
        ovs_fatal(errno, "%s: madvise failed", fn);
    }

    struct field {
        const char *s;
        size_t length;
    };

    enum { RESERVOIR_SIZE = 10000 };
    struct log_record reservoir[RESERVOIR_SIZE];
    size_t n_reservoir = 0;

    struct parse_ctx ctx = { .fn = fn, .ln = 1, .line_start = buffer };
    for (; ctx.line_start < end; ctx.line_start = ctx.line_end + 1, ctx.ln++) {
        ctx.line_end = memchr(ctx.line_start, '\n', end - ctx.line_start);
        if (!ctx.line_end) {
            /* Don't bother with lines that lack a new-line. */
            break;
        }
        ctx.p = ctx.line_start;

        if (grep && !memmem (ctx.line_start, ctx.line_end - ctx.line_start,
                             grep, strlen (grep))) {
            continue;
        }

        /* If this record won't be sampled, don't even bother parsing it. */
        if (n_reservoir >= RESERVOIR_SIZE
            && random_range(ctx.ln) >= RESERVOIR_SIZE) {
            continue;
        }

        size_t rec_idx = (n_reservoir < RESERVOIR_SIZE
                          ? n_reservoir++
                          : random_range(RESERVOIR_SIZE));
        struct log_record *rec = &reservoir[rec_idx];
        memset(rec, 0, sizeof *rec);

        parse_record(&ctx, rec);
    }

    for (size_t i = 0; i < n_reservoir; i++) {
        split(&reservoir[i].msg);
    }

    printf("selected %zu records out of %d\n", n_reservoir, ctx.ln - 1);

    return NULL;
}

static void
open_target(const char *name)
{
    struct stat s;
    if (stat(name, &s) < 0) {
        ovs_error(errno, "%s; stat failed", name);
        return;
    }

    if (S_ISREG(s.st_mode)) {
        read_file(name);
        return;
    } else if (!S_ISDIR(s.st_mode)) {
        VLOG_DBG("%s: ignoring special file", name);
        return;
    }

    DIR *dir = opendir(name);
    if (!dir) {
        ovs_error(errno, "%s: open failed", name);
        return;
    }

    for (;;) {
        errno = 0;
        struct dirent *de = readdir(dir);
        if (!de) {
            if (errno) {
                ovs_error(errno, "%s: readdir failed", name);
            }
            break;
        }

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
            continue;
        }

        char *name2 = xasprintf("%s/%s", name, de->d_name);
        open_target(name2);
        free(name2);
    }
    closedir(dir);
}

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    parse_command_line (argc, argv);

    if (optind >= argc) {
        open_target(".");
    } else {
        for (int i = optind; i < argc; i++) {
            open_target(argv[i]);
        }
    }

    for (;;) {
        int status;
        pid_t pid = wait(&status);
        if (pid < 0) {
            break;
        }

        char *status_msg = process_status_msg (status);
        printf ("child %ld exited (%s)\n", (long int) pid, status_msg);
        free(status_msg);
    }
    if (errno != ECHILD) {
        ovs_fatal(errno, "wait failed");
    }

    pthread_exit(NULL);
}

static void
usage(void)
{
    printf("\
%s, for querying log files\n\
usage: %s [TARGET] COMMAND [ARG...]\n\
\n\
Common commands:\n\
  hh   List sampled heavy hitters\n\
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
        {"grep", required_argument, NULL, 'g'},
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
        case 'g':
            grep = optarg;
            break;

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
