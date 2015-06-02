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
#include "bpf.h"
#include "dynamic-string.h"
#include "ofpbuf.h"
#include "p4-bpf.h"
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
disassemble(const struct bpf_insn instructions[], size_t n,
            char **notes, size_t n_notes)
{
    struct ds s;

    ds_init(&s);
    bpf_disassemble(instructions, n, notes, n_notes, &s);
    fputs(ds_cstr(&s), stdout);
    ds_destroy(&s);
}

static void
test_parse__(struct ovs_cmdl_context *ctx, int level)
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
        if (*diagnostics) {
            puts("/*");
            fputs(diagnostics, stdout);
            puts("*/\n");
        }

        if (!level) {
            struct ds output;

            ds_init(&output);
            p4_format(parser, &output);
            fputs(ds_cstr(&output), stdout);
        } else {
            struct ofpbuf bpf;
            size_t n_notes;
            char **notes;
            char *error;

            ofpbuf_init(&bpf, 0);
            error = p4_bpf_from_parser(parser, &bpf, &notes, &n_notes);
            disassemble(bpf.data, bpf.size / sizeof(struct bpf_insn),
                        notes, n_notes);
            ofpbuf_uninit(&bpf);
            if (error) {
                ovs_fatal(0, "%s: %s", file_name, error);
            }
        }
    } else {
        fputs(diagnostics, stderr);
        exit(1);
    }
}

static void
test_parse(struct ovs_cmdl_context *ctx)
{
    test_parse__(ctx, 0);
}

static void
test_p4_to_bpf(struct ovs_cmdl_context *ctx)
{
    test_parse__(ctx, 1);
}

static void
test_disassemble(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    static const struct bpf_insn instructions[] = {
        /* Load immediate. */
        { BPF_LD | BPF_IMM | BPF_DW, 1, 0, 0, 0x89abcdef },
        { 0,                         0, 0, 0, 0x76543210 },

        /* Load from memory. */
        { BPF_LDX | BPF_MEM | BPF_DW, 2, 10, 123, 0 },
        { BPF_LDX | BPF_MEM | BPF_W, 3, 9, -1, 0 },
        { BPF_LDX | BPF_MEM | BPF_H, 4, 8, 0, 0 },
        { BPF_LDX | BPF_MEM | BPF_B, 5, 7, 54, 0 },

        /* Store to memory. */
        { BPF_STX | BPF_MEM | BPF_DW, 6, 1, 123, 0 },
        { BPF_STX | BPF_MEM | BPF_W, 8, 5, -127, 0 },
        { BPF_STX | BPF_MEM | BPF_H, 10, 2, 128, 0 },
        { BPF_STX | BPF_MEM | BPF_B, 2, 6, 0, 0 },

        /* Conditional jumps, comparison against immediate. */
        { BPF_JMP | BPF_JEQ | BPF_K, 5, 0, 5, 12345 },
        { BPF_JMP | BPF_JGT | BPF_K, 5, 0, 5, 12345 },
        { BPF_JMP | BPF_JSET | BPF_K, 5, 0, 5, 12345 },
        { BPF_JMP | BPF_JNE | BPF_K, 5, 0, 5, 12345 },
        { BPF_JMP | BPF_JSGT | BPF_K, 5, 0, 5, 12345 },
        { BPF_JMP | BPF_JSGE | BPF_K, 5, 0, 5, 12345 },

        /* Conditional jumps, comparison against register. */
        { BPF_JMP | BPF_JEQ | BPF_X, 5, 2, 0, 0 },
        { BPF_JMP | BPF_JGT | BPF_X, 5, 1, 1, 0 },
        { BPF_JMP | BPF_JSET | BPF_X, 5, 3, 2, 0 },
        { BPF_JMP | BPF_JNE | BPF_X, 5, 5, 3, 0 },
        { BPF_JMP | BPF_JSGT | BPF_X, 5, 4, 4, 0 },
        { BPF_JMP | BPF_JSGE | BPF_X, 5, 6, 5, 0 },

        /* Exit. */
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 },

        /* 32-bit ALU, immediate operand. */
        { BPF_ALU | BPF_ADD | BPF_K, 9, 1, 0, -1 },
        { BPF_ALU | BPF_SUB | BPF_K, 1, 9, 0, 1 },
        { BPF_ALU | BPF_MUL | BPF_K, 8, 1, 0, -2 },
        { BPF_ALU | BPF_DIV | BPF_K, 8, 5, 0, 2 },
        { BPF_ALU | BPF_OR | BPF_K, 1, 4, 0, -3 },
        { BPF_ALU | BPF_AND | BPF_K, 6, 8, 0, 3 },
        { BPF_ALU | BPF_LSH | BPF_K, 1, 2, 0, -4 },
        { BPF_ALU | BPF_RSH | BPF_K, 2, 3, 0, 4 },
        { BPF_ALU | BPF_MOD | BPF_K, 3, 4, 0, -5 },
        { BPF_ALU | BPF_XOR | BPF_K, 4, 5, 0, 5 },
        { BPF_ALU | BPF_MOV | BPF_K, 5, 4, 0, -6 },

        /* 64-bit ALU, immediate operand. */
        { BPF_ALU64 | BPF_ADD | BPF_K, 9, 1, 0, 6 },
        { BPF_ALU64 | BPF_SUB | BPF_K, 1, 9, 0, -7 },
        { BPF_ALU64 | BPF_MUL | BPF_K, 8, 1, 0, 7 },
        { BPF_ALU64 | BPF_DIV | BPF_K, 8, 5, 0, -8 },
        { BPF_ALU64 | BPF_OR | BPF_K, 1, 4, 0, 8 },
        { BPF_ALU64 | BPF_AND | BPF_K, 6, 8, 0, -9 },
        { BPF_ALU64 | BPF_LSH | BPF_K, 1, 2, 0, 9 },
        { BPF_ALU64 | BPF_RSH | BPF_K, 2, 3, 0, -10 },
        { BPF_ALU64 | BPF_MOD | BPF_K, 3, 4, 0, 10 },
        { BPF_ALU64 | BPF_XOR | BPF_K, 4, 5, 0, -11 },
        { BPF_ALU64 | BPF_MOV | BPF_K, 5, 4, 0, 11 },

        /* 32-bit ALU, register operand. */
        { BPF_ALU | BPF_ADD | BPF_X, 9, 1, 0, 0 },
        { BPF_ALU | BPF_SUB | BPF_X, 1, 9, 0, 0 },
        { BPF_ALU | BPF_MUL | BPF_X, 8, 1, 0, 0 },
        { BPF_ALU | BPF_DIV | BPF_X, 8, 5, 0, 0 },
        { BPF_ALU | BPF_OR | BPF_X, 1, 4, 0, 0 },
        { BPF_ALU | BPF_AND | BPF_X, 6, 8, 0, 0 },
        { BPF_ALU | BPF_LSH | BPF_X, 1, 2, 0, 0 },
        { BPF_ALU | BPF_RSH | BPF_X, 2, 3, 0, 0 },
        { BPF_ALU | BPF_MOD | BPF_X, 3, 4, 0, 0 },
        { BPF_ALU | BPF_XOR | BPF_X, 4, 5, 0, 0 },
        { BPF_ALU | BPF_MOV | BPF_X, 5, 4, 0, 0 },

        /* 32-bit ALU64, register operand. */
        { BPF_ALU64 | BPF_ADD | BPF_X, 9, 1, 0, 0 },
        { BPF_ALU64 | BPF_SUB | BPF_X, 1, 9, 0, 0 },
        { BPF_ALU64 | BPF_MUL | BPF_X, 8, 1, 0, 0 },
        { BPF_ALU64 | BPF_DIV | BPF_X, 8, 5, 0, 0 },
        { BPF_ALU64 | BPF_OR | BPF_X, 1, 4, 0, 0 },
        { BPF_ALU64 | BPF_AND | BPF_X, 6, 8, 0, 0 },
        { BPF_ALU64 | BPF_LSH | BPF_X, 1, 2, 0, 0 },
        { BPF_ALU64 | BPF_RSH | BPF_X, 2, 3, 0, 0 },
        { BPF_ALU64 | BPF_MOD | BPF_X, 3, 4, 0, 0 },
        { BPF_ALU64 | BPF_XOR | BPF_X, 4, 5, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_X, 5, 4, 0, 0 },

        /* NEG. */
        { BPF_ALU | BPF_NEG, 1, 0, 0, 0 },
        { BPF_ALU64 | BPF_NEG, 1, 0, 0, 0 },

        /* Byteswapping. */
        { BPF_ALU | BPF_END | BPF_TO_BE, 4, 0, 0, 16 },
        { BPF_ALU | BPF_END | BPF_TO_BE, 3, 0, 0, 32 },
        { BPF_ALU | BPF_END | BPF_TO_BE, 2, 0, 0, 64 },
        { BPF_ALU | BPF_END | BPF_TO_LE, 5, 0, 0, 16 },
        { BPF_ALU | BPF_END | BPF_TO_LE, 1, 0, 0, 32 },
        { BPF_ALU | BPF_END | BPF_TO_LE, 6, 0, 0, 64 },
    };

    disassemble(instructions, ARRAY_SIZE(instructions), NULL, 0);
}

static void
test_flow_extract(struct ovs_cmdl_context *ctx)
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

    if (!init_flow_parser_bpf(ds_cstr(&input))) {
        exit(1);
    }

    for (int i = 2; i < ctx->argc; i++) {
        struct dp_packet *packet;
        const char *error_msg;
        struct flow flow;

        error_msg = eth_from_hex(ctx->argv[i], &packet);
        if (error_msg) {
            ovs_fatal(0, "%s", error_msg);
        }

        flow_extract_bpf(packet, &flow);
        flow_print(stdout, &flow);
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
parse FILE\n\
  Parses P4 input from FILE and prints it back on stdout.\n\
\n\
p4-to-bpf\n\
  Parses P4 input from FILE, converts it to BPF, and prints the BPF\n\
  on stdout.\n\
\n\
disassemble\n\
  Disassembles internally generated BPF and prints it on stdout.\n\
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
        {"p4-to-bpf", NULL, 1, 1, test_p4_to_bpf},

        /* BPF. */
        {"disassemble", NULL, 0, 0, test_disassemble},

        /* Flow extract. */
        {"flow-extract", NULL, 2, INT_MAX, test_flow_extract},

        {NULL, NULL, 0, 0, NULL},
    };
    struct ovs_cmdl_context ctx;
    ctx.argc = argc - optind;
    ctx.argv = argv + optind;
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-p4", test_p4_main);
