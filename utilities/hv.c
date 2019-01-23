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

/* TODO: mode for selecting records in error. */

#include <config.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <getopt.h>
#include <math.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <zlib.h>

#include "command-line.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/poll-loop.h"
#include "ovs-thread.h"
#include "process.h"
#include "random.h"
#include "socket-util.h"
#include "util.h"

#include "openvswitch/vlog.h"
VLOG_DEFINE_THIS_MODULE(hv);

struct task {
    struct ovs_list list_node;
    char *filename;
    off_t size;
    struct ds output;
};
static struct ovs_mutex task_lock = OVS_MUTEX_INITIALIZER;

static struct task **queued_tasks;
static size_t n_queued_tasks, allocated_queued_tasks;

static struct ovs_list running_tasks OVS_GUARDED_BY(task_lock)
    = OVS_LIST_INITIALIZER(&running_tasks);
static struct ovs_list complete_tasks OVS_GUARDED_BY(task_lock)
    = OVS_LIST_INITIALIZER(&complete_tasks);

static const char *grep;
static unsigned int priorities = 0xff;
static unsigned int facilities = (1u << 24) - 1;
static const char *component;
static const char *subcomponent;
static double date_since = -DBL_MAX;
static double date_until = DBL_MAX;

static unsigned long long int total_bytes;
static unsigned long long int total_decompressed;

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

static bool OVS_UNUSED
ss_ends_with(struct substring s, struct substring suffix)
{
    return s.length >= suffix.length && !memcmp(&s.s[s.length - suffix.length],
                                                suffix.s, suffix.length);
}

static bool OVS_UNUSED
ss_contains(struct substring haystack, struct substring needle)
{
    return memmem(haystack.s, haystack.length,
                  needle.s, needle.length) != NULL;
}

struct log_record {
    bool valid;                 /* Fully parsed record? */
    struct substring line;      /* Full log line. */
    int facility;               /* 0...23. */
    int priority;               /* 0...7. */
    struct substring timestamp; /* Date and time. */
    double when;                /* Seconds since the epoch. */
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
    fprintf(stderr, "%s:%d.%"PRIdPTR": ",
            ctx->fn, ctx->ln, ctx->p - ctx->line_start + 1);

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    putc('\n', stderr);
}

static void OVS_PRINTF_FORMAT(2, 3)
debug(const struct parse_ctx *ctx, const char *format, ...)
{
    if (VLOG_IS_DBG_ENABLED()) {
        va_list args;
        va_start(args, format);
        char *msg = xvasprintf(format, args);
        va_end(args);

        VLOG_DBG("%s:%d.%"PRIdPTR": %s",
                 ctx->fn, ctx->ln, ctx->p - ctx->line_start + 1, msg);
        free(msg);
    }
}

static bool
match_spaces(struct parse_ctx *ctx)
{
    if (*ctx->p != ' ') {
        return false;
    }
    do {
        ctx->p++;
    } while (*ctx->p == ' ');
    return true;
}

static bool
must_match_spaces(struct parse_ctx *ctx)
{
    bool matched = match_spaces(ctx);
    if (!matched) {
        warn(ctx, "expected ' '");
    }
    return matched;
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

static bool
get_header_token(struct parse_ctx *ctx, struct substring *token)
{
    if (!must_match_spaces(ctx)) {
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
matches_template(const char *s, const char *template)
{
    size_t i;
    for (i = 0; template[i]; i++) {
        if (!(template[i] == '#' ? c_isdigit(s[i]) : s[i] == template[i])) {
            return false;
        }
    }
    return true;
}

static int
atoi2(const char *s)
{
    int d1 = s[0] - '0';
    int d2 = s[1] - '0';
    return d1 * 10 + d2;
}

static int
atoi4(const char *s)
{
    int d1 = s[0] - '0';
    int d2 = s[1] - '0';
    int d3 = s[2] - '0';
    int d4 = s[3] - '0';
    return d1 * 1000 + d2 * 100 + d3 * 10 + d4;
}

static bool
is_leap_year (int y)
{
  return y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
}

/* Expects y >= 1900, 1 <= m <= 12, 1 <= d <= 31. */
static int
ymd_to_julian(int y, int m, int d)
{
    return (365 * (y - 1)
            + (y - 1) / 4
            - (y - 1) / 100
            + (y - 1) / 400
            + (367 * m - 362) / 12
            + (m <= 2 ? 0 : (m >= 2 && is_leap_year (y) ? -1 : -2))
            + d);
}

static int
epoch(void)
{
    return ymd_to_julian(1970, 1, 1);
}

static double
parse_timestamp(const char *s, size_t len)
{
    if (!len) {
        return 0;
    }

    static const char template[] = "####-##-##T##:##:##";
    if (len < strlen(template + 1) || !matches_template(s, template)) {
        return -1;
    }

    int tz_ofs = strlen(template);
    int numerator = 0;
    int denominator = 1;
    if (s[tz_ofs] == '.') {
        for (tz_ofs++; tz_ofs < len; tz_ofs++) {
            int c = s[tz_ofs];
            if (!c_isdigit(c) || denominator > INT_MAX / 10) {
                break;
            }
            numerator = numerator * 10 + (c - '0');
            denominator *= 10;
        }
    }

    int gmtoff;
    if (tz_ofs >= len) {
        return -1;
    }
    if (len - tz_ofs == 1 && s[tz_ofs] == 'Z') {
        gmtoff = 0;
    } else if (len - tz_ofs == 6
               && (s[tz_ofs] == '+' || s[tz_ofs] == '-')
               && matches_template(&s[tz_ofs + 1], "##:##")) {
        int h_off = atoi2(&s[tz_ofs + 1]);
        int m_off = atoi2(&s[tz_ofs + 4]);
        gmtoff = h_off * 60 + m_off;
        if (s[tz_ofs] == '-') {
            gmtoff = -gmtoff;
        }
    } else {
        return -1;
    }

    int y = atoi4(s);
    int m = atoi2(s + 5);
    int d = atoi2(s + 5);
    int H = atoi2(s + 11);
    int M = atoi2(s + 14);
    int S = atoi2(s + 17);
    int date = ymd_to_julian(y, m, d) - epoch();
    int time = H * 3600 + M * 60 + S - gmtoff * 60;
    double t = date * 86400 + time;
    if (numerator) {
        t += (double) numerator / denominator;
    }
    return t;
}

static void
format_timestamp(double t, struct ds *s)
{
    time_t time = t;
    struct tm tm;
    if (gmtime_r(&time, &tm) != &tm) {
        ds_put_format(s, "<error>");
        return;
    }

    ds_put_format(s, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec,
                  (int) ((t - floor(t)) * 1000 + .5));
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

    rec->when = parse_timestamp(rec->timestamp.s, rec->timestamp.length);
    if (rec->when == -1) {
        return false;
    }

    /* Structured data. */
    if (!must_match_spaces(ctx)) {
        return false;
    }
    if (match(ctx, '[')) {
        if (!get_sd_name(ctx, &rec->sdid)) {
            return false;
        }
        while (match_spaces(ctx)) {
            if (!get_sd_param(ctx, rec)) {
                return false;
            }
        }
        if (!must_match(ctx, ']')) {
            return false;
        }
    } else if (!match(ctx, '-')) {
        /* Some NSX log files have this problem.  Keep going. */
        debug(ctx, "expected '-' or '['");
    }

    match_spaces(ctx);

    rec->msg.s = ctx->p;
    rec->msg.length = ctx->line_end - ctx->p;

    rec->valid = true;

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

static bool
has_digit(const char *s)
{
    for (; *s; s++) {
        if (c_isdigit(*s)) {
            return true;
        }
    }
    return false;
}

static void OVS_UNUSED
split(const struct substring *msg)
{
    char *tokens[64];
    size_t n_tokens = 0;

    char *s = xmemdup0(msg->s, msg->length);
    char *save_ptr = NULL;
    for (char *token = strtok_r(s, " \t\r\n", &save_ptr); token;
         token = strtok_r(NULL, " \t\r\n", &save_ptr)) {
        tokens[n_tokens++] = has_digit(token) ? "_" : token;
        if (n_tokens >= ARRAY_SIZE(tokens)) {
            break;
        }
    }

    if (n_tokens) {
        for (size_t i = 0; i < n_tokens; i++) {
#if 0
            if (i) {
                putchar(' ');
            }
            fputs(tokens[i], stdout);
#endif
        }
        //putchar('\n');
    }

    free(s);
}

static int
compare_log_records(const void *a_, const void *b_)
{
    const struct log_record *a = a_;
    const struct log_record *b = b_;
    return a->when < b->when ? -1 : a->when > b->when;
}

struct state {
    struct log_record *reservoir;
    int allocated;
    int n;
    int population;
};

static void
state_init(struct state *state)
{
    state->allocated = 100;
    state->reservoir = xmalloc(state->allocated * sizeof *state->reservoir);
    state->n = 0;
    state->population = 0;
}

static void
state_add(struct state *state, const struct log_record *rec)
{
    size_t idx = (state->n < state->allocated
                  ? state->n++
                  : random_range(state->population + 1));
    if (idx < state->allocated) {
        state->reservoir[idx] = *rec;
    }
    state->population++;
}

static void
parse_file(const char *fn, const char *buffer, off_t size, struct ds *output OVS_UNUSED)
{
    const char *end = buffer + size;

    if (size < 2 || buffer[0] != '<' || !c_isdigit(buffer[1])) {
        VLOG_DBG("%s: not an RFC 5424 log file", fn);
        return;
    }

    struct state state;
    state_init(&state);

    struct parse_ctx ctx = { .fn = fn, .ln = 1, .line_start = buffer };
    for (; ctx.line_start < end; ctx.line_start = ctx.line_end + 1, ctx.ln++) {
        ctx.line_end = memchr(ctx.line_start, '\n', end - ctx.line_start);
        if (!ctx.line_end) {
            /* Don't bother with lines that lack a new-line. */
            break;
        }
        ctx.p = ctx.line_start;

        struct log_record rec;
        memset(&rec, 0, sizeof rec);
        rec.line.s = ctx.line_start;
        rec.line.length = ctx.line_end - ctx.line_start;

        parse_record(&ctx, &rec);
        if (rec.when < date_since || rec.when > date_until) {
            continue;
        }
        if (!(priorities & (1u << rec.priority))) {
            continue;
        }
        if (!(facilities & (1u << rec.facility))) {
            continue;
        }
        if (component && !ss_contains(rec.comp, ss_cstr(component))) {
            continue;
        }
        if (subcomponent && !ss_contains(rec.subcomp, ss_cstr(subcomponent))) {
            continue;
        }
        if (grep && !ss_contains(rec.msg, ss_cstr(grep))) {
            continue;
        }

        state_add(&state, &rec);
    }

    qsort(state.reservoir, state.n, sizeof *state.reservoir,
          compare_log_records);
#if 1
    for (size_t i = 0; i < state.n; i++) {
        ds_put_buffer(output, state.reservoir[i].line.s,
                      state.reservoir[i].line.length);
        ds_put_char(output, '\n');
    }
#endif
    free(state.reservoir);

    total_bytes += size;
}

static void
read_gzipped(const char *name, const char *in, size_t in_size,
             struct ds *output)
{
    z_stream z = {
        .next_in = (unsigned char *) in,
        .avail_in = in_size,
    };
    int retval = inflateInit2(&z, 15 + 16);
    if (retval != Z_OK) {
        VLOG_WARN("%s: failed to initiate decompression (%s)", name, z.msg);
        return;
    }

    char sample[128];
    z.next_out = (unsigned char *) sample;
    z.avail_out = sizeof sample;
    retval = inflate(&z, Z_SYNC_FLUSH);
    if (retval != Z_OK && retval != Z_STREAM_END) {
        VLOG_WARN("%s: decompression failed (%s)", name, z.msg);
        inflateEnd(&z);
        return;
    }

    if (sample[0] != '<' || !c_isdigit(sample[1])) {
        VLOG_DBG("%s: not a gzipped RFC 5424 log file", name);
        inflateEnd(&z);
        return;
    }

    size_t allocated = in_size * 16;
    char *out = xmalloc(allocated);
    memcpy(out, sample, z.total_out);
    for (;;) {
        if (z.total_out >= allocated) {
            allocated = allocated * 5 / 4;
            out = xrealloc(out, allocated);
            ovs_assert(z.total_out < allocated);
        }
        z.next_out = (unsigned char *) &out[z.total_out];
        z.avail_out = allocated - z.total_out;

        retval = inflate(&z, Z_SYNC_FLUSH);
        if (retval == Z_STREAM_END) {
            break;
        } else if (retval != Z_OK) {
            VLOG_WARN("%s: decompression failed (%s)", name, z.msg);
            inflateEnd(&z);
            free(out);
            return;
        }
    }
    parse_file(name, out, z.total_out, output);
    free(out);

    total_decompressed += z.total_out;
    inflateEnd(&z);
}

static void
read_file__(const char *fn, struct ds *output)
{
    random_init();
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
    close(fd);

    if (size > 2 && !memcmp(buffer, "\x1f\x8b", 2)) {
        read_gzipped(fn, buffer, size, output);
    } else {
        if (madvise(buffer, size, MADV_WILLNEED) < 0) {
            ovs_fatal(errno, "%s: madvise failed", fn);
        }
        parse_file(fn, buffer, size, output);
    }

    if (munmap(buffer, size) < 0) {
        ovs_error(errno, "%s: munmap failed", fn);
    }
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
        if (s.st_size > 0 && !strstr(name, "metrics")) {
            struct task *task = xmalloc(sizeof *task);
            task->filename = xstrdup(name);
            task->size = s.st_size;
            ds_init(&task->output);

            if (n_queued_tasks >= allocated_queued_tasks) {
                queued_tasks = x2nrealloc(queued_tasks,
                                          &allocated_queued_tasks,
                                          sizeof *queued_tasks);
            }
            queued_tasks[n_queued_tasks++] = task;
        }
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

static int
count_cores(void)
{
    cpu_set_t cpus;
    if (sched_getaffinity(0, sizeof cpus, &cpus) < 0) {
        ovs_error(errno, "sched_getaffinity failed");
        return 1;
    } else {
        return CPU_COUNT(&cpus);
    }
}

static void
parse_lines(const char *name, const char *buffer, size_t length,
            struct state *state)
{
    const char *end = buffer + length;
    struct parse_ctx ctx = { .fn = name, .ln = 1, .line_start = buffer };
    for (; ctx.line_start < end; ctx.line_start = ctx.line_end + 1, ctx.ln++) {
        ctx.line_end = memchr(ctx.line_start, '\n', end - ctx.line_start);
        if (!ctx.line_end) {
            /* Don't bother with lines that lack a new-line. */
            break;
        }
        ctx.p = ctx.line_start;

        struct log_record rec;
        memset(&rec, 0, sizeof rec);
        rec.line.s = ctx.line_start;
        rec.line.length = ctx.line_end - ctx.line_start;

        parse_record(&ctx, &rec);
        if (grep && !ss_contains(rec.msg, ss_cstr(grep))) {
            continue;
        }

        state_add(state, &rec);
    }
}

static const char *
priority_to_string(int priority)
{
    const char *levels[] = {
        [0] = "EMER",
        [1] = "ALER",
        [2] = "CRIT",
        [3] = "ERR ",
        [4] = "WARN",
        [5] = "NOTI",
        [6] = "INFO",
        [7] = "DBG ",
    };

    return (priority >= 0 && priority < ARRAY_SIZE(levels)
            ? levels[priority]
            : "****");
}

static const char *
facility_to_string(int facility)
{
    const char *facility_strings[] = {
        [0] = "kern",
        [1] = "user",
        [2] = "mail",
        [3] = "sys ",
        [4] = "auth",
        [5] = "log ",
        [6] = "lpd ",
        [7] = "news",
        [8] = "uucp",
        [9] = "clck",
        [10] = "auth",
        [11] = "ftp ",
        [12] = "ntp ",
        [13] = "audt",
        [14] = "alrt",
        [15] = "clck",
        [16] = "lcl0",
        [17] = "lcl1",
        [18] = "lcl2",
        [19] = "lcl3",
        [20] = "lcl4",
        [21] = "lcl5",
        [22] = "lcl6",
        [23] = "lcl7",
    };

    return (facility >= 0 && facility < ARRAY_SIZE(facility_strings)
            ? facility_strings[facility]
            : "****");
}

static void
put_substring(struct ds *dst, const struct substring *src)
{
    ds_put_char(dst, ' ');
    if (src->length) {
        ds_put_buffer(dst, src->s, src->length);
    } else {
        ds_put_char(dst, '-');
    }
}

static void
parse_results(void)
{
    struct state state;
    state_init(&state);

    struct task *task;
    LIST_FOR_EACH (task, list_node, &complete_tasks) {
        parse_lines("<child process>", task->output.string,
                    task->output.length, &state);
    }

    qsort(state.reservoir, state.n, sizeof *state.reservoir,
          compare_log_records);
    for (size_t i = 0; i < state.n; i++) {
        const struct log_record *rec = &state.reservoir[i];
        if (!rec->valid) {
            fwrite(rec->line.s, rec->line.length, 1, stdout);
            putchar('\n');
            continue;
        }

        struct ds s = DS_EMPTY_INITIALIZER;
        format_timestamp(rec->when, &s);
        ds_put_format(&s, " %s %s", priority_to_string(rec->priority),
                      facility_to_string(rec->facility));
        put_substring(&s, &rec->app_name);
        put_substring(&s, &rec->comp);
        put_substring(&s, &rec->subcomp);
        puts(ds_cstr(&s));
        ds_destroy(&s);
    }
    free(state.reservoir);
}

static int
compare_tasks(const void *a_, const void *b_)
{
    const struct task *const *ap = a_;
    const struct task *const *bp = b_;
    const struct task *a = *ap;
    const struct task *b = *bp;
    return a->size < b->size ? -1 : a->size > b->size;
}

static void *
task_thread(void *unused OVS_UNUSED)
{
    for (;;) {
        ovs_mutex_lock(&task_lock);
        struct task *task = (n_queued_tasks
                             ? queued_tasks[--n_queued_tasks]
                             : NULL);
        ovs_mutex_unlock(&task_lock);

        if (!task) {
            return NULL;
        }

        read_file__(task->filename, &task->output);

        ovs_mutex_lock(&task_lock);
        ovs_list_push_back(&complete_tasks, &task->list_node);
        ovs_mutex_unlock(&task_lock);
    }
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
    qsort(queued_tasks, n_queued_tasks, sizeof *queued_tasks, compare_tasks);

    int cores = count_cores();
    int n_threads = MIN(4 * cores, n_queued_tasks);
    pthread_t *threads = xmalloc(n_threads * sizeof *threads);
    for (int i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("read", task_thread, NULL);
    }
    for (int i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }
    free(queued_tasks);

    parse_results();

    printf("parsed %.1f MB of logs\n", total_bytes / 1024.0 / 1024.0);
    printf("decompressed %.1f MB of gzipped data\n",
           total_decompressed / 1024.0 / 1024.0);
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

static int
level_from_string(const char *s)
{
    const char *levels[] = {
        [0] = "emergency",
        [1] = "alert",
        [2] = "critical",
        [3] = "error",
        [4] = "warning",
        [5] = "notice",
        [6] = "informational",
        [7] = "debug"
    };

    int s_len = strcspn(s, "-+");
    for (size_t i = 0; i < ARRAY_SIZE(levels); i++) {
        if (!strncmp(s, levels[i], s_len)) {
            return i;
        }
    }
    ovs_fatal(0, "%.*s: unknown priority", s_len, s);
}

static void
parse_priorities(char *s)
{
    priorities = 0;

    char *save_ptr = NULL;
    for (char *token = strtok_r(s, ", ", &save_ptr); token;
         token = strtok_r(NULL, ", ", &save_ptr)) {
        int level = level_from_string(s);
        if (strchr(s, '+')) {
            priorities |= (1u << (level + 1)) - 1;
        } else if (strchr(s, '-')) {
            priorities |= ((1u << level) - 1) ^ 0xff;
        } else {
            priorities |= 1u << level;
        }
    }
}

static int
facility_from_string(const char *s)
{
    for (int i = 0; i < 24; i++) {
        if (!strcmp(s, facility_to_string(i))) {
            return i;
        }
    }
    ovs_fatal(0, "%s: unknown facility", s);

}

static void
parse_facilities(char *s)
{
    unsigned int xor = 0;
    if (*s == '^' || *s == '!') {
        s++;
        xor = (1u << 24) - 1;
    }

    facilities = 0;

    char *save_ptr = NULL;
    for (char *token = strtok_r(s, ", ", &save_ptr); token;
         token = strtok_r(NULL, ", ", &save_ptr)) {
        facilities |= 1u << facility_from_string(s);
    }
    facilities ^= xor;
}

static double
parse_date(const char *s)
{
    /* XXX Date parsing is hard.  This might be a cop-out. */
    char *args[] = { "date", "-d", CONST_CAST(char *, s), "+%s", NULL };
    char *command = process_escape_args(args);
    FILE *stream = popen(command, "r");
    if (!stream) {
        ovs_fatal(errno, "%s: popen failed", command);
    }
    double when;
    bool ok = fscanf(stream, "%lf", &when) == 1;
    int status = pclose(stream);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        if (ok) {
            free(command);
            return when;
        } else {
            ovs_fatal(errno, "%s: unexpected output parsing date %s",
                      command, s);
        }
    } else if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
        ovs_fatal(errno, "%s: bad date", s);
    }
    ovs_fatal(errno, "%s: error parsing date (%s)",
              command, process_status_msg(status));
}

static void
parse_command_line(int argc, char *argv[])
{
    enum {
        OPT_SINCE = UCHAR_MAX + 1,
        OPT_UNTIL,
    };
    static const struct option long_options[] = {
        {"grep", required_argument, NULL, 'g'},
        {"priorities", required_argument, NULL, 'p'},
        {"facilities", required_argument, NULL, 'f'},
        {"component", required_argument, NULL, 'c'},
        {"subcomponent", required_argument, NULL, 's'},
        {"since", required_argument, NULL, OPT_SINCE},
        {"after", required_argument, NULL, OPT_SINCE},
        {"until", required_argument, NULL, OPT_UNTIL},
        {"before", required_argument, NULL, OPT_UNTIL},
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

        case 'p':
            parse_priorities(optarg);
            break;

        case 'f':
            parse_facilities(optarg);
            break;

        case OPT_SINCE:
            date_since = parse_date(optarg);
            break;

        case OPT_UNTIL:
            date_until = parse_date(optarg);
            break;

        case 'c':
            component = optarg;
            break;

        case 's':
            subcomponent = optarg;
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
