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

#ifndef P4_LEXER_H
#define P4_LEXER_H

#include "meta-flow.h"

enum p4_lex_type {
    P4_LEX_END,                 /* End of input. */

    /* Tokens with auxiliary data. */
    P4_LEX_ID,
    P4_LEX_STRING,
    P4_LEX_INTEGER,
    P4_LEX_ERROR,               /* invalid input */

    /* Reserved words. */
    P4_LEX_APPLY,
    P4_LEX_CURRENT,
    P4_LEX_DEFAULT,
    P4_LEX_ELSE,
    P4_LEX_HIT,
    P4_LEX_IF,
    P4_LEX_LAST,
    P4_LEX_LATEST,
    P4_LEX_PARSE_ERROR,
    P4_LEX_PAYLOAD,
    P4_LEX_SELECT,
    P4_LEX_SWITCH,

    /* Operators. */
    P4_LEX_ADD,                 /* + */
    P4_LEX_SUB,                 /* - */
    P4_LEX_MUL,                 /* * */
    P4_LEX_DIV,                 /* / */
    P4_LEX_MOD,                 /* % */
    P4_LEX_LSH,                 /* << */
    P4_LEX_RSH,                 /* >> */
    P4_LEX_BIT_OR,              /* | */
    P4_LEX_BIT_AND,             /* & */
    P4_LEX_BIT_XOR,             /* ^ */
    P4_LEX_BIT_NOT,             /* ~ */

    /* Punctuators. */
    P4_LEX_LPAREN,              /* ( */
    P4_LEX_RPAREN,              /* ) */
    P4_LEX_LCURLY,              /* { */
    P4_LEX_RCURLY,              /* } */
    P4_LEX_LSQUARE,             /* [ */
    P4_LEX_RSQUARE,             /* ] */
    P4_LEX_EQ,                  /* == */
    P4_LEX_NE,                  /* != */
    P4_LEX_LT,                  /* < */
    P4_LEX_LE,                  /* <= */
    P4_LEX_GT,                  /* > */
    P4_LEX_GE,                  /* >= */
    P4_LEX_PERIOD,              /* . */
    P4_LEX_COMMA,               /* , */
    P4_LEX_COLON,               /* : */
    P4_LEX_SEMICOLON,           /* ; */
};

/* A token.
 *
 * 's' is owned by the token. */
struct p4_token {
    enum p4_lex_type type;      /* One of P4_LEX_*. */
    char *s;                    /* P4_LEX_ID, P4_LEX_STRING, P4_LEX_ERROR. */

    /* P4_LEX_INTEGER only. */
    union mf_subvalue value;
    int width;                  /* In bits (implicit or explicit). */
    int radix;                  /* 2 or 10 or 16. */
    bool negative;              /* True if token starts with "-". */
};

void p4_token_init(struct p4_token *);
void p4_token_destroy(struct p4_token *);
void p4_token_swap(struct p4_token *, struct p4_token *);

void p4_token_format(const struct p4_token *, struct ds *);
const char *p4_token_parse(struct p4_token *, const char *input,
                           const char **startp, int *line_number);

bool p4_token_is_small_int(const struct p4_token *);

struct p4_lexer {
    char *file_name;            /* File name. */
    int line_number;            /* Line number within file_name. */
    const char *input;          /* Remaining input (not owned by lexer). */
    const char *start;          /* Start of current token in 'input'. */
    struct p4_token token;      /* Current token (owned by lexer). */
};

void p4_lexer_init(struct p4_lexer *, const char *input,
                   const char *file_name);
void p4_lexer_destroy(struct p4_lexer *);

enum p4_lex_type p4_lexer_get(struct p4_lexer *);
enum p4_lex_type p4_lexer_lookahead(const struct p4_lexer *);
bool p4_lexer_match(struct p4_lexer *, enum p4_lex_type);
bool p4_lexer_match_id(struct p4_lexer *, const char *id);

#endif  /* p4-lexer.h */
