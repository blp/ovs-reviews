/*
 * Copyright (c) 2015 Nicira, Inc.
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
#include "command-line.h"
#include <errno.h>
#include <getopt.h>
#include <sys/wait.h>
#include "dynamic-string.h"
#include "p4-lex.h"
#include "p4-parse.h"
#include "ovstest.h"

static void
compare_token(const struct p4_token *a, const struct p4_token *b)
{
    if (a->type != b->type) {
        fprintf(stderr, "type differs: %d -> %d\n", a->type, b->type);
        return;
    }

    if (!((a->s && b->s && !strcmp(a->s, b->s))
          || (!a->s && !b->s))) {
        fprintf(stderr, "string differs: %s -> %s\n",
                a->s ? a->s : "(null)",
                b->s ? b->s : "(null)");
        return;
    }

    if (a->type == P4_LEX_INTEGER) {
        if (memcmp(&a->value, &b->value, sizeof a->value)) {
            fprintf(stderr, "value differs\n");
            return;
        }

        if (a->radix != b->radix
            && !(b->radix == 10 && is_all_zeros(&b->value, sizeof b->value))
            && !(a->radix == 10 && b->radix == 16 &&
                 !is_all_zeros(&b->value,
                               offsetof(union mf_subvalue, integer)))) {
            fprintf(stderr, "radix differs: %d -> %d\n", a->radix, b->radix);
        }
    }
}

static void
test_lex(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct ds input;
    struct ds output;

    ds_init(&input);
    ds_init(&output);
    while (!ds_get_line(&input, stdin)) {
        struct p4_lexer lexer;

        p4_lexer_init(&lexer, ds_cstr(&input), "-");
        ds_clear(&output);
        while (p4_lexer_get(&lexer) != P4_LEX_END) {
            size_t len = output.length;
            p4_token_format(&lexer.token, &output);

            /* Check that the formatted version can really be parsed back
             * losslessly. */
            if (lexer.token.type != P4_LEX_ERROR) {
                const char *s = ds_cstr(&output) + len;
                struct p4_lexer l2;

                p4_lexer_init(&l2, s, "-");
                p4_lexer_get(&l2);
                compare_token(&lexer.token, &l2.token);
                p4_lexer_destroy(&l2);
                if (lexer.token.type == P4_LEX_INTEGER && !strchr(s, '\'')) {
                    ds_put_format(&output, "(w%d)", lexer.token.width);
                }
            }

            ds_put_char(&output, ' ');
        }
        p4_lexer_destroy(&lexer);

        ds_chomp(&output, ' ');
        puts(ds_cstr(&output));
    }
    ds_destroy(&input);
    ds_destroy(&output);
}

static void
test_parse(struct ovs_cmdl_context *ctx)
{
    const char *file_name = ctx->argv[1];
    struct ds input;
    FILE *stream;

    stream = !strcmp(file_name, "-") ? stdin : fopen(file_name, "r");
    if (stream == NULL) {
        ovs_fatal(errno, "%s: open failed", file_name);
    }

    ds_init(&input);
    for (;;) {
        int c = getc(stream);
        if (c == EOF) {
            break;
        }
        ds_put_char(&input, c);
    }
    if (stream != stdin) {
        fclose(stream);
    }

    struct p4_lexer lexer;
    p4_lexer_init(&lexer, ds_cstr(&input), file_name);
    p4_lexer_get(&lexer);

    struct p4_parser *parser;
    char *diagnostics = p4_parse(&lexer, &parser);
    p4_lexer_destroy(&lexer);

    if (parser) {
        struct ds output;

        if (*diagnostics) {
            puts("/*");
            fputs(diagnostics, stdout);
            puts("*/\n");
        }

        ds_init(&output);
        p4_format(parser, &output);
        fputs(ds_cstr(&output), stdout);
    } else {
        fputs(diagnostics, stderr);
        exit(1);
    }
}

static void
usage(void)
{
    printf("\
%s: P4 test utility\n\
usage: test-p4 %s [OPTIONS] COMMAND [ARG...]\n\
\n\
lex\n\
  Lexically analyzes P4 input from stdin and prints it back on stdout.\n\
\n\
parses\n\
  Parses P4 input from stdin and prints it back on stdout.\n\
",
           program_name, program_name);
    exit(EXIT_SUCCESS);
}

static void
test_p4_main(int argc, char *argv[])
{
    set_program_name(argv[0]);

    for (;;) {
        static const struct option options[] = {
            {"help", no_argument, NULL, 'h'},
            {NULL, 0, NULL, 0},
        };
        int option_index = 0;
        int c = getopt_long (argc, argv, "", options, &option_index);

        if (c == -1) {
            break;
        }
        switch (c) {
        case 'h':
            usage();

        case '?':
            exit(1);

        default:
            abort();
        }
    }

    static const struct ovs_cmdl_command commands[] = {
        /* Lexer. */
        {"lex", NULL, 0, 0, test_lex},

        /* Parser. */
        {"parse", NULL, 1, 1, test_parse},

        {NULL, NULL, 0, 0, NULL},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - optind;
    ctx.argv = argv + optind;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-p4", test_p4_main);
