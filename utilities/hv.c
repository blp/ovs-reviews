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

/* TODO:
 *
 * - mode for selecting records in error.
 * - avoid degzipping whole file at a time.
 * - responsive interface via threading
 * - support tgz or at least tar
 * - bt is slow, use heap+hmap?
 */

#include <config.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <getopt.h>
#include <math.h>
#include <ncurses.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <zlib.h>

#include "bt.h"
#include "command-line.h"
#include "fatal-signal.h"
#include "hash.h"
#include "heap.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/poll-loop.h"
#include "ovs-thread.h"
#include "process.h"
#include "random.h"
#include "sset.h"
#include "socket-util.h"
#include "util.h"

#include "openvswitch/vlog.h"
VLOG_DEFINE_THIS_MODULE(hv);

struct topkapi {
    struct log_record *rec;
    long long int count;
};

struct state {
    struct log_record *reservoir;
    struct bt bt;
    int allocated;
    int n;
    int population;

#define TK_L 4                  /* Number of hashes */
#define TK_B 1024               /* Number of buckets */
    struct topkapi *tk[TK_L];
};

struct task {
    struct ovs_list list_node;
    char *filename;
    off_t size;
    struct ds output;
    struct state state;
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
static struct sset components = SSET_INITIALIZER(&components);
static struct sset subcomponents = SSET_INITIALIZER(&subcomponents);
static double date_since = -DBL_MAX;
static double date_until = DBL_MAX;

static double at = -DBL_MAX;

static enum { SHOW_FIRST, SHOW_LAST, SHOW_SAMPLE, SHOW_TOPK } show
= SHOW_SAMPLE;

#define COLUMNS                                 \
    COLUMN(WHEN, "when")                        \
    COLUMN(FACILITY, "facility")                \
    COLUMN(PRIORITY, "priority")                \
    COLUMN(HOSTNAME, "hostname")                \
    COLUMN(APP_NAME, "app_name")                \
    COLUMN(PROCID, "procid")                    \
    COLUMN(MSGID, "msgid")                      \
    COLUMN(SDID, "sdid")                        \
    COLUMN(COMP, "comp")                        \
    COLUMN(SUBCOMP, "subcomp")                  \
    COLUMN(MSG, "msg")                          \
    COLUMN(VALID, "valid")

enum column {
#define COLUMN(ENUM, NAME) COL_##ENUM,
    COLUMNS
#undef COLUMN
};

#define COLUMN(ENUM, NAME) + 1
enum { N_COLUMNS = 0 COLUMNS };
#undef COLUMN

static enum column *columns;
static size_t n_columns;

static unsigned long long int total_bytes;
static unsigned long long int total_decompressed;
static unsigned long long int total_recs;

struct substring {
    const char *s;
    size_t length;
};

static bool
ss_equals(struct substring a, struct substring b)
{
    return a.length == b.length && !memcmp(a.s, b.s, a.length);
}

static int
ss_compare(struct substring a, struct substring b)
{
    int result = memcmp(a.s, b.s, MIN(a.length, b.length));
    return (result ? result
            : a.length < b.length ? -1
            : a.length > b.length);
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

static uint32_t
ss_hash(struct substring substring, uint32_t basis)
{
    return hash_bytes(substring.s, substring.length, basis);
}

static struct substring
ss_clone(struct substring substring)
{
    return (struct substring) { .s = xmemdup(substring.s, substring.length),
                                .length = substring.length };
}

struct log_record {
    struct bt_node bt_node;
    long long int count;
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
    if (len == 1 && s[0] == '-') {
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

    int msec = (t - floor(t)) * 1000 + .5;
    ds_put_format(s, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec, MIN(999, msec));
}

static bool
parse_record(struct parse_ctx *ctx, struct log_record *rec)
{
    if (match(ctx, '*')) {
        rec->count = 0;
        while (c_isdigit(*ctx->p)) {
            rec->count = rec->count * 10 + (*ctx->p++ - '0');
        }
        if (!must_match(ctx, ' ')) {
            return false;
        }
    } else {
        rec->count = 1;
    }

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

static void
copy_log_record(struct log_record *dst, const struct log_record *src)
{
    dst->count = src->count;
    dst->valid = src->valid;
    dst->line = ss_clone(src->line);
    dst->facility = src->facility;
    dst->priority = src->priority;
    dst->timestamp = ss_clone(src->timestamp);
    dst->when = src->when;
    dst->hostname = ss_clone(src->hostname);
    dst->app_name = ss_clone(src->app_name);
    dst->procid = ss_clone(src->procid);
    dst->msgid = ss_clone(src->msgid);
    dst->sdid = ss_clone(src->sdid);
    dst->comp = ss_clone(src->comp);
    dst->subcomp = ss_clone(src->subcomp);
    dst->msg = ss_clone(src->msg);
}

#if 0
static struct log_record *
clone_log_record(const struct log_record *src)
{
    struct log_record *dst = xmalloc(sizeof *dst);
    copy_log_record(dst, src);
    return dst;
}
#endif

static uint32_t
hash_log_record(const struct log_record *r, uint32_t basis)
{
    uint32_t hash = basis;
    for (size_t i = 0; i < n_columns; i++) {
        switch (columns[i]) {
        case COL_WHEN:
            hash = hash_double(r->when, basis);
            break;
        case COL_FACILITY:
            hash = hash_int(r->facility, basis);
            break;
        case COL_PRIORITY:
            hash = hash_int(r->priority, basis);
            break;
        case COL_HOSTNAME:
            hash = ss_hash(r->hostname, basis);
            break;
        case COL_APP_NAME:
            hash = ss_hash(r->app_name, basis);
            break;
        case COL_PROCID:
            hash = ss_hash(r->procid, basis);
            break;
        case COL_MSGID:
            hash = ss_hash(r->msgid, basis);
            break;
        case COL_SDID:
            hash = ss_hash(r->sdid, basis);
            break;
        case COL_COMP:
            hash = ss_hash(r->comp, basis);
            break;
        case COL_SUBCOMP:
            hash = ss_hash(r->subcomp, basis);
            break;
        case COL_MSG:
            hash = ss_hash(r->msg, basis);
            break;
        case COL_VALID:
            hash = hash_boolean(r->valid, basis);
            break;
        default:
            OVS_NOT_REACHED();
        }
    }
    return hash;
}

static int
compare_double(double a, double b)
{
    return a < b ? -1 : a > b;
}

static int
compare_int(int a, int b)
{
    return a < b ? -1 : a > b;
}

static int
compare_log_records(const struct log_record *a, const struct log_record *b)
{
    for (size_t i = 0; i < n_columns; i++) {
        int cmp;

        switch (columns[i]) {
        case COL_WHEN:
            cmp = compare_double(a->when, b->when);
            break;
        case COL_FACILITY:
            cmp = compare_int(a->facility, b->facility);
            break;
        case COL_PRIORITY:
            cmp = compare_int(a->priority, b->priority);
            break;
        case COL_HOSTNAME:
            cmp = ss_compare(a->hostname, b->hostname);
            break;
        case COL_APP_NAME:
            cmp = ss_compare(a->app_name, b->app_name);
            break;
        case COL_PROCID:
            /* XXX It would be better to compare numerically if possible,
             * e.g. like the GNU function strverscmp(). */
            cmp = ss_compare(a->procid, b->procid);
            break;
        case COL_MSGID:
            cmp = ss_compare(a->msgid, b->msgid);
            break;
        case COL_SDID:
            cmp = ss_compare(a->sdid, b->sdid);
            break;
        case COL_COMP:
            cmp = ss_compare(a->comp, b->comp);
            break;
        case COL_SUBCOMP:
            cmp = ss_compare(a->subcomp, b->subcomp);
            break;
        case COL_MSG:
            cmp = ss_compare(a->msg, b->msg);
            break;
        case COL_VALID:
            cmp = compare_int(a->valid, b->valid);
            break;
        default:
            OVS_NOT_REACHED();
        }
        if (cmp) {
            return show == SHOW_LAST ? -cmp : cmp;
        }
    }
    return 0;
}

static int
compare_log_records_for_qsort(const void *a_, const void *b_)
{
    const struct log_record *a = a_;
    const struct log_record *b = b_;
    return compare_log_records(a, b);
}

static int
compare_log_records_for_bt(const struct bt_node *a_,
                           const struct bt_node *b_,
                           const void *aux OVS_UNUSED)
{
    const struct log_record *a = CONTAINER_OF(a_, struct log_record, bt_node);
    const struct log_record *b = CONTAINER_OF(b_, struct log_record, bt_node);
    return compare_log_records(a, b);
}

static void
state_init(struct state *state)
{
    state->allocated = 10000;
    state->reservoir = xmalloc(state->allocated * sizeof *state->reservoir);
    state->n = 0;
    state->population = 0;
    if (show == SHOW_FIRST || show == SHOW_LAST) {
        bt_init(&state->bt, compare_log_records_for_bt, NULL);
    } else {
        for (int i = 0; i < TK_L; i++) {
            state->tk[i] = xcalloc(TK_B, sizeof *state->tk[i]);
        }
    }
}

static void
state_add(struct state *state, const struct log_record *rec)
{
    if (show == SHOW_SAMPLE) {
        size_t idx = (state->n < state->allocated
                      ? state->n++
                      : random_range(state->population + 1));
        if (idx < state->allocated) {
            state->reservoir[idx] = *rec;
        }
        state->population++;
    } else if (show == SHOW_FIRST || show == SHOW_LAST) {
        state->population++;

        struct bt_node *last = NULL;
        if (state->n >= state->allocated) {
            last = bt_last(&state->bt);
            if (compare_log_records_for_bt(&rec->bt_node, last, NULL) > 0) {
                return;
            }
        }

        struct bt_node *node = bt_find(&state->bt, &rec->bt_node);
        if (node) {
            struct log_record *pos = CONTAINER_OF(node, struct log_record,
                                                  bt_node);
            pos->count += rec->count;
        } else {
            struct log_record *pos;
            if (state->n < state->allocated) {
                pos = &state->reservoir[state->n++];
            } else {
                bt_delete(&state->bt, last);
                pos = CONTAINER_OF(last, struct log_record, bt_node);
            }
            *pos = *rec;
            bt_insert(&state->bt, &pos->bt_node);
        }
    } else if (show == SHOW_TOPK) {
        for (int i = 0; i < TK_L; i++) {
            uint32_t hash = hash_log_record(rec, i);
            struct topkapi *tk = &state->tk[i][hash % TK_B];
            if (!tk->rec) {
                tk->rec = xmemdup(rec, sizeof *rec);
                tk->count = 1;
            } else if (!compare_log_records(rec, tk->rec)) {
                tk->count++;
            } else if (--tk->count < 0) {
                *tk->rec = *rec;
                tk->count = 1;
            }
        }
    }
}

static void
state_uninit(struct state *state)
{
    free(state->reservoir);
}

static void
parse_file(const char *fn, const char *buffer, off_t size, struct task *task)
{
    const char *end = buffer + size;

    if (size < 2 || buffer[0] != '<' || !c_isdigit(buffer[1])) {
        VLOG_DBG("%s: not an RFC 5424 log file", fn);
        return;
    }
    total_bytes += size;

    struct state *state = &task->state;
    state_init(state);

    struct parse_ctx ctx = { .fn = fn, .ln = 1, .line_start = buffer };
    for (; ctx.line_start < end; ctx.line_start = ctx.line_end + 1, ctx.ln++) {
        ctx.line_end = memchr(ctx.line_start, '\n', end - ctx.line_start);
        if (!ctx.line_end) {
            /* Don't bother with lines that lack a new-line. */
            break;
        }
        ctx.p = ctx.line_start;
        total_recs++;
        if (!(total_recs % 1024)) {
            fatal_signal_run();
        }

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
        if (!sset_is_empty(&components)
            && !sset_contains_len(&components, rec.comp.s, rec.comp.length)) {
            continue;
        }
        if (!sset_is_empty(&subcomponents)
            && !sset_contains_len(&components,
                                  rec.subcomp.s, rec.subcomp.length)) {
            continue;
        }
        if (grep && !ss_contains(rec.msg, ss_cstr(grep))) {
            continue;
        }

        state_add(state, &rec);
    }

    if (show != SHOW_TOPK) {
        for (size_t i = 0; i < state->n; i++) {
            ds_put_format(&task->output, "*%lld ", state->reservoir[i].count);
            ds_put_buffer(&task->output, state->reservoir[i].line.s,
                          state->reservoir[i].line.length);
            ds_put_char(&task->output, '\n');
        }
    } else {
        for (int i = 0; i < TK_L; i++) {
            for (int j = 0; j < TK_B; j++) {
                struct log_record *rec = state->tk[i][j].rec;
                if (rec) {
                    copy_log_record(rec, rec);
                }
            }
        }
    }
    state_uninit(state);
}

static void
read_gzipped(const char *name, const char *in, size_t in_size,
             struct task *task)
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

        fatal_signal_run();
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
    parse_file(name, out, z.total_out, task);
    free(out);

    total_decompressed += z.total_out;
    inflateEnd(&z);
}

static void
task_execute(struct task *task)
{
    const char *fn = task->filename;

    int fd = open(fn, O_RDONLY);
    if (fd < 0) {
        ovs_fatal(errno, "%s: open failed", fn);
    }

    struct stat s;
    if (fstat(fd, &s) < 0) {
        ovs_fatal(errno, "%s; stat failed", fn);
    }

    random_set_seed(s.st_size);

    off_t size = s.st_size;
    char *buffer = mmap (NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    if (buffer == MAP_FAILED) {
        ovs_fatal(errno, "%s: mmap failed", fn);
    }
    close(fd);

    if (size > 2 && !memcmp(buffer, "\x1f\x8b", 2)) {
        read_gzipped(fn, buffer, size, task);
    } else {
        if (madvise(buffer, size, MADV_WILLNEED) < 0) {
            ovs_fatal(errno, "%s: madvise failed", fn);
        }
        parse_file(fn, buffer, size, task);
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
            struct task *task = xzalloc(sizeof *task);
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
put_substring(struct ds *dst, const struct substring src)
{
    if (src.length) {
        ds_put_buffer(dst, src.s, src.length);
    } else {
        ds_put_char(dst, '-');
    }
}

static void
format_record(const struct log_record *r, int i, int n, struct ds *s)
{
    ds_put_format(s, "%7lld", r->count);

    if (show == SHOW_SAMPLE && n) {
        ds_put_format(s, "%5.2f%% ", 100.0 * i / n);
    }

    for (size_t j = 0; j < n_columns; j++) {
        ds_put_char(s, ' ');
        switch (columns[j]) {
        case COL_WHEN:
            format_timestamp(r->when, s);
            break;
        case COL_FACILITY:
            ds_put_cstr(s, facility_to_string(r->facility));
            break;
        case COL_PRIORITY:
            ds_put_cstr(s, priority_to_string(r->priority));
            break;
        case COL_HOSTNAME:
            put_substring(s, r->hostname);
            break;
        case COL_APP_NAME:
            put_substring(s, r->app_name);
            break;
        case COL_PROCID:
            put_substring(s, r->procid);
            break;
        case COL_MSGID:
            put_substring(s, r->msgid);
            break;
        case COL_SDID:
            put_substring(s, r->sdid);
            break;
        case COL_COMP:
            put_substring(s, r->comp);
            break;
        case COL_SUBCOMP:
            put_substring(s, r->subcomp);
            break;
        case COL_MSG:
            put_substring(s, r->msg);
            break;
        case COL_VALID:
            ds_put_cstr(s, r->valid ? "ok" : "invalid");
            break;
        default:
            OVS_NOT_REACHED();
        }
    }
}

static int
compare_tk_by_count_desc(const void *a_, const void *b_)
{
    const struct topkapi *a = a_;
    const struct topkapi *b = b_;
    return a->count > b->count ? -1 : a->count < b->count;
}

static void
add_record(struct log_record *record,
           struct log_record ***resultsp, size_t *n_resultsp,
           size_t *allocated_resultsp)
{
    if (*n_resultsp >= *allocated_resultsp) {
        *resultsp = x2nrealloc(*resultsp, allocated_resultsp,
                               sizeof **resultsp);
    }
    (*resultsp)[(*n_resultsp)++] = record;
}

static void
merge_results(struct log_record ***resultsp, size_t *n_resultsp)
{
    struct log_record **results = NULL;
    size_t n_results = 0;
    size_t allocated_results = 0;

    if (show != SHOW_TOPK) {
        struct state state;
        state_init(&state);

        random_set_seed(1);

        struct task *task;
        LIST_FOR_EACH (task, list_node, &complete_tasks) {
            parse_lines("<child process>", task->output.string,
                        task->output.length, &state);
        }

        qsort(state.reservoir, state.n, sizeof *state.reservoir,
              compare_log_records_for_qsort);
        if (!state.n) {
            printf("no data\n");
        } else if (at >= 0 && at <= 100) {
            size_t pos = MIN(at / 100.0 * state.n, state.n - 1);
            add_record(&state.reservoir[pos],
                       &results, &n_results, &allocated_results);
        } else {
            for (size_t i = 0; i < state.n; i++) {
                add_record(&state.reservoir[i],
                           &results, &n_results, &allocated_results);
            }
        }
    } else {
        struct topkapi *tk[TK_L];
        for (int i = 0; i < TK_L; i++) {
            tk[i] = xcalloc(TK_B, sizeof *tk[i]);
        }

        struct task *task;
        LIST_FOR_EACH (task, list_node, &complete_tasks) {
            if (!task->state.tk[0]) {
                continue;
            }
            for (int i = 0; i < TK_L; i++) {
                for (int j = 0; j < TK_B; j++) {
                    struct topkapi *dst = &tk[i][j];
                    struct topkapi *src = &task->state.tk[i][j];

                    if (!src->rec) {
                        /* Nothing to do. */
                    } else if (!dst->rec) {
                        *dst = *src;
                    } else if (!compare_log_records(dst->rec, src->rec)) {
                        dst->count += src->count;
                    } else if (dst->count >= src->count) {
                        dst->count -= src->count;
                    } else {
                        dst->rec = src->rec;
                        dst->count = src->count - dst->count;
                    }
                }
            }
        }

#if 0
        for (int i = 0; i < TK_L; i++) {
            printf("%d:", i);
            for (int j = 0; j < TK_B; j++) {
                printf(" %lld", tk[i][j].count);
            }
            printf("\n");
        }
#endif

        int K = 100;
        int frac_epsilon = 10 * K;
        int threshold = ((double) TK_B / K) - ((double) TK_B / frac_epsilon);
        for (int j = 0; j < TK_B; j++) {
            if (!tk[0][j].rec) {
                tk[0][j].count = 0;
                continue;
            }
            long long int count = tk[0][j].count;
            for (int i = 1; i < TK_L; i++) {
                int idx = hash_log_record(tk[0][j].rec, i) % TK_B;
                if (!tk[i][idx].rec
                    || compare_log_records(tk[0][j].rec, tk[i][idx].rec)) {
                    continue;
                }
                count = MAX(count, tk[i][idx].count);
            }
            tk[0][j].count = count;
        }

        qsort(tk[0], TK_B, sizeof *tk[0], compare_tk_by_count_desc);
        for (int j = 0; j < TK_B; j++) {
            if (tk[0][j].count >= threshold) {
                tk[0][j].rec->count = tk[0][j].count;
                add_record(tk[0][j].rec,
                           &results, &n_results, &allocated_results);
            } else {
                break;
            }
        }
    }

    *resultsp = results;
    *n_resultsp = n_results;
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

        task_execute(task);
        fatal_signal_run();

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

    initscr();
    cbreak();
    noecho();
    nonl();
    intrflush(stdscr, false);
    keypad(stdscr, true);
    mousemask(ALL_MOUSE_EVENTS, NULL);

    fatal_signal_init();

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
    free(threads);
    free(queued_tasks);

    struct log_record **results;
    size_t n_results;
    merge_results(&results, &n_results);

    int y_ofs = 0, x_ofs = 0;
    for (;;) {
        int y_max = getmaxy(stdscr);
        int x_max = getmaxx(stdscr);
        for (size_t i = 0; i < y_max; i++) {
            struct ds s = DS_EMPTY_INITIALIZER;
            if (i + y_ofs < n_results) {
                format_record(results[i + y_ofs], i + y_ofs, n_results, &s);
            } else {
                ds_put_char(&s, '~');
            }
            ds_truncate(&s, x_ofs + x_max - 1);
            mvprintw(i, 0, "%s", ds_cstr(&s) + MIN(x_ofs, s.length));
            clrtoeol();
            ds_destroy(&s);
        }
        refresh();

        switch (getch()) {
        case KEY_UP: case 'k':
            if (y_ofs > 0) {
                y_ofs--;
            }
            break;
        case KEY_DOWN: case 'j':
            if (y_ofs < n_results) {
                y_ofs++;
            }
            break;
        case KEY_LEFT: case 'h':
            if (x_ofs > 0) {
                x_ofs = MAX(x_ofs - 10, 0);
            }
            break;
        case KEY_RIGHT: case 'l':
            x_ofs += 10;
            break;
        case KEY_NPAGE: case ' ':
            y_ofs = MIN(y_ofs + (y_max - 2), n_results);
            break;
        case KEY_PPAGE: case KEY_BACKSPACE:
            y_ofs = MAX(y_ofs - (y_max - 2), 0);
            break;
        case KEY_HOME: case '<':
            y_ofs = 0;
            break;
        case KEY_END: case '>':
            y_ofs = MAX(n_results - (y_max - 2), 0);
            break;
        case KEY_MOUSE:
            for (;;) {
                MEVENT event;
                if (getmouse(&event) != OK) {
                    break;
                }
                if (event.bstate == BUTTON4_PRESSED) {
                    y_ofs = MAX(y_ofs - y_max / 10, 0);
                } else if (event.bstate == BUTTON5_PRESSED) {
                    y_ofs = MIN(y_ofs + y_max / 10, n_results - (y_max - 2));
                }
            }
            break;
        case 'q': case 'Q':
            goto exit;
        }
    }
exit:

#if 0
    printf("parsed %.1f MB of logs containing %llu records\n",
           total_bytes / 1024.0 / 1024.0, total_recs);
    printf("decompressed %.1f MB of gzipped data\n",
           total_decompressed / 1024.0 / 1024.0);
#endif

    endwin();
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
    /* XXX Date parsing is hard.  This is kind of a cop-out. */

    if (!strcmp(s, "-")) {
        return 0;
    }

    double when = parse_timestamp(s, strlen(s));
    if (when > 0) {
        return when;
    }

    char *args[] = { "date", "-d", CONST_CAST(char *, s), "+%s", NULL };
    char *command = process_escape_args(args);
    FILE *stream = popen(command, "r");
    if (!stream) {
        ovs_fatal(errno, "%s: popen failed", command);
    }
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

#if 0
static const char *
column_to_string(enum column c)
{
    switch (c) {
#define COLUMN(ENUM, NAME) case COL_##ENUM: return NAME;
        COLUMNS
#undef COLUMN
    default: return NULL;
    }
}
#endif

static enum column
column_from_string(const char *s)
{
#define COLUMN(ENUM, NAME) if (!strcmp(s, NAME)) return COL_##ENUM;
    COLUMNS
#undef COLUMNS
    ovs_fatal(0, "%s: unknown column", s);
}

static void
parse_columns(const char *s_)
{
    char *s = xstrdup(s_);
    size_t allocated_columns = n_columns;
    char *save_ptr = NULL;
    for (char *token = strtok_r(s, ", ", &save_ptr); token;
         token = strtok_r(NULL, ", ", &save_ptr)) {
        if (n_columns >= allocated_columns) {
            columns = x2nrealloc(columns, &allocated_columns,
                                 sizeof *columns);
        }
        columns[n_columns++] = column_from_string(token);
    }
    free(s);
}

static void
parse_command_line(int argc, char *argv[])
{
    enum {
        OPT_SINCE = UCHAR_MAX + 1,
        OPT_UNTIL,
    };
    static const struct option long_options[] = {
        {"columns", required_argument, NULL, 'c'},
        {"at", required_argument, NULL, 'a'},
        {"show", required_argument, NULL, 's'},
        {"grep", required_argument, NULL, 'g'},
        {"priorities", required_argument, NULL, 'p'},
        {"facilities", required_argument, NULL, 'f'},
        {"component", required_argument, NULL, 'C'},
        {"subcomponent", required_argument, NULL, 'S'},
        {"since", required_argument, NULL, OPT_SINCE},
        {"after", required_argument, NULL, OPT_SINCE},
        {"until", required_argument, NULL, OPT_UNTIL},
        {"before", required_argument, NULL, OPT_UNTIL},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int option;

        option = getopt_long(argc, argv, short_options, long_options, NULL);
        if (option == -1) {
            break;
        }
        switch (option) {
        case 'c':
            parse_columns(optarg);
            break;

        case 'a':
            at = strtod(optarg, NULL);
            break;

        case 's':
            if (!strcmp(optarg, "first")) {
                show = SHOW_FIRST;
            } else if (!strcmp(optarg, "last")) {
                show = SHOW_LAST;
            } else if (!strcmp(optarg, "sample")) {
                show = SHOW_SAMPLE;
            } else if (!strcmp(optarg, "top")) {
                show = SHOW_TOPK;
            } else {
                ovs_fatal(0, "%s: unknown \"show\"", optarg);
            }
            break;

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

        case 'C':
            sset_add_delimited(&components, optarg, " ,");
            break;

        case 'S':
            sset_add_delimited(&subcomponents, optarg, " ,");
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
    free(short_options);

    if (optind >= argc) {
        ovs_fatal(0, "at least one non-option argument is required "
                  "(use --help for help)");
    }

    if (!n_columns) {
        parse_columns("when facility priority comp subcomp msg");
    }
}
