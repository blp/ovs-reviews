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
#include "p4-lex.h"
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include "dynamic-string.h"
#include "json.h"
#include "util.h"

/* Initializes 'token'. */
void
p4_token_init(struct p4_token *token)
{
    token->type = P4_LEX_END;
    token->s = NULL;
}

/* Frees memory owned by 'token'. */
void
p4_token_destroy(struct p4_token *token)
{
    free(token->s);
}

/* Exchanges 'a' and 'b'. */
void
p4_token_swap(struct p4_token *a, struct p4_token *b)
{
    struct p4_token tmp = *a;
    *a = *b;
    *b = tmp;
}

/* p4_token_format(). */

static int
p4_default_width(const union mf_subvalue *value)
{
    /* The P4 spec only defines the width of nonzero values.  Let's assume
     * that zero has a width of 1 bit. */
    int w = mf_subvalue_width(value);
    return MAX(w, 1);
}

static void
p4_token_format_value(const union mf_subvalue *value, int width, int radix,
                      struct ds *s)
{
    int default_width = p4_default_width(value);
    if (width != default_width) {
        ds_put_format(s, "%d'", width);
    }

    if (radix == 10) {
        if (is_all_zeros(value, offsetof(union mf_subvalue, integer))) {
            ds_put_format(s, "%"PRIu64, ntohll(value->integer));
        } else {
            /* Decimal values above 2**64 cannot be parsed back as decimal, so
             * print them as hex */
            mf_format_subvalue(value, 16, s);
        }
    } else {
        mf_format_subvalue(value, radix, s);
    }
}

/* Appends a string representation of 'token' to 's', in a format that can be
 * losslessly parsed back by the lexer.  (P4_LEX_END and P4_LEX_ERROR can't be
 * parsed back.) */
void
p4_token_format(const struct p4_token *token, struct ds *s)
{
    switch (token->type) {
    case P4_LEX_END:
        ds_put_cstr(s, "$");
        break;

    case P4_LEX_ID:
        ds_put_cstr(s, token->s);
        break;

    case P4_LEX_STRING:
        json_string_escape(token->s, s);
        break;

    case P4_LEX_INTEGER:
        p4_token_format_value(&token->value, token->width, token->radix, s);
        break;

    case P4_LEX_ERROR:
        ds_put_cstr(s, "error(");
        json_string_escape(token->s, s);
        ds_put_char(s, ')');
        break;

    case P4_LEX_APPLY:
        ds_put_cstr(s, "apply");
        break;
    case P4_LEX_CURRENT:
        ds_put_cstr(s, "current");
        break;
    case P4_LEX_DEFAULT:
        ds_put_cstr(s, "default");
        break;
    case P4_LEX_ELSE:
        ds_put_cstr(s, "else");
        break;
    case P4_LEX_HIT:
        ds_put_cstr(s, "hit");
        break;
    case P4_LEX_IF:
        ds_put_cstr(s, "if");
        break;
    case P4_LEX_LAST:
        ds_put_cstr(s, "last");
        break;
    case P4_LEX_LATEST:
        ds_put_cstr(s, "latest");
        break;
    case P4_LEX_PARSE_ERROR:
        ds_put_cstr(s, "parse_error");
        break;
    case P4_LEX_PAYLOAD:
        ds_put_cstr(s, "payload");
        break;
    case P4_LEX_SELECT:
        ds_put_cstr(s, "select");
        break;
    case P4_LEX_SWITCH:
        ds_put_cstr(s, "switch");
        break;

    case P4_LEX_ADD:
        ds_put_cstr(s, "+");
        break;
    case P4_LEX_SUB:
        ds_put_cstr(s, "-");
        break;
    case P4_LEX_MUL:
        ds_put_cstr(s, "*");
        break;
    case P4_LEX_DIV:
        ds_put_cstr(s, "/");
        break;
    case P4_LEX_MOD:
        ds_put_cstr(s, "%");
        break;
    case P4_LEX_LSH:
        ds_put_cstr(s, "<<");
        break;
    case P4_LEX_RSH:
        ds_put_cstr(s, ">>");
        break;
    case P4_LEX_BIT_OR:
        ds_put_cstr(s, "|");
        break;
    case P4_LEX_BIT_AND:
        ds_put_cstr(s, "&");
        break;
    case P4_LEX_BIT_XOR:
        ds_put_cstr(s, "^");
        break;
    case P4_LEX_BIT_NOT:
        ds_put_cstr(s, "~");
        break;

    case P4_LEX_LPAREN:
        ds_put_cstr(s, "(");
        break;
    case P4_LEX_RPAREN:
        ds_put_cstr(s, ")");
        break;
    case P4_LEX_LCURLY:
        ds_put_cstr(s, "{");
        break;
    case P4_LEX_RCURLY:
        ds_put_cstr(s, "}");
        break;
    case P4_LEX_LSQUARE:
        ds_put_cstr(s, "[");
        break;
    case P4_LEX_RSQUARE:
        ds_put_cstr(s, "]");
        break;
    case P4_LEX_EQ:
        ds_put_cstr(s, "==");
        break;
    case P4_LEX_NE:
        ds_put_cstr(s, "!=");
        break;
    case P4_LEX_LT:
        ds_put_cstr(s, "<");
        break;
    case P4_LEX_LE:
        ds_put_cstr(s, "<=");
        break;
    case P4_LEX_GT:
        ds_put_cstr(s, ">");
        break;
    case P4_LEX_GE:
        ds_put_cstr(s, ">=");
        break;
    case P4_LEX_PERIOD:
        ds_put_char(s, '.');
        break;
    case P4_LEX_COMMA:
        ds_put_cstr(s, ",");
        break;
    case P4_LEX_COLON:
        ds_put_cstr(s, ":");
        break;
    case P4_LEX_SEMICOLON:
        ds_put_cstr(s, ";");
        break;
    default:
        OVS_NOT_REACHED();
    }
}

/* p4_token_parse(). */

static void OVS_PRINTF_FORMAT(2, 3)
p4_lex_error(struct p4_token *token, const char *message, ...)
{
    ovs_assert(!token->s);
    token->type = P4_LEX_ERROR;

    va_list args;
    va_start(args, message);
    token->s = xvasprintf(message, args);
    va_end(args);
}

static const char *
p4_lex_parse_integer__(const char *p, bool negative, struct p4_token *token)
{
    token->negative = negative;

    int width = 0;
    if (p[strspn(p, "0123456789")] == '\'') {
        /* Divergence from 1.0.2: we do not allow _ in widths. */
        char *tail;

        errno = 0;
        width = strtol(p, &tail, 10);
        if (*tail != '\'' || errno == ERANGE
            || width < 0 || width > 8 * sizeof token->value) {
            p4_lex_error(token, "Width must be between 0 and %"PRIuSIZE".",
                         8 * sizeof token->value);
            return tail;
        }

        p = tail + 1;
    }

    if (*p == '0') {
        /* Parse hex or binary constant. */
        char r = p[1];
        token->radix = (r == 'x' || r == 'X' ? 16
                        : r == 'b' || r == 'B' ? 2
                        : 10);
        if (token->radix == 10) {
            p++;
            if (*p && strchr("0123456789", *p)) {
                /* Divergence from 1.0.2: we disallow constants with leading
                 * zeros because it seems likely that these are intended as
                 * octal constants, which aren't supported.*/
                p4_lex_error(token,
                             "Decimal constants must not have leading zeros.");
            }
        } else {
            p += 2;

            uint8_t buffer[sizeof token->value];
            int ofs = 8 * sizeof buffer;
            int n_digits = 0;
            memset(buffer, 0, sizeof buffer);
            for (;; p++) {
                if (*p == '_') {
                    continue;
                }

                int8_t digit = hexit_value(*p);
                if (digit < 0) {
                    break;
                }
                if (digit >= token->radix) {
                    p4_lex_error(token, "`%c' is not a valid base-%d digit.",
                                 *p, token->radix);
                    return p + 1;
                }

                n_digits++;
                if (!digit && ofs == 8 * sizeof buffer) {
                    continue;
                }

                int bits_per_digit = token->radix == 16 ? 4 : 1;
                if (ofs < bits_per_digit) {
                    p4_lex_error(token,
                                 "Constant exceeds supported %d-bit width.",
                                 8 * sizeof buffer);
                    return p;
                }
                ofs -= bits_per_digit;
                bitwise_copy(&digit, sizeof digit, 0,
                             buffer, sizeof buffer, ofs,
                             bits_per_digit);
            }
            if (!n_digits) {
                /* Ambiguity in 1.0.2: 0x_ appears to be valid according to the
                 * grammar, but it's a likely typo. */
                p4_lex_error(token, "Digits expected following `0%c'.", r);
                return p;
            }

            bitwise_copy(buffer, sizeof buffer, ofs,
                         &token->value, sizeof token->value, 0,
                         (8 * sizeof buffer) - ofs);
        }
    } else {
        /* Parse decimal constant. */
        unsigned long long int integer;

        integer = 0;
        for (; (*p >= '0' && *p <= '9') || *p == '_'; p++) {
            if (*p == '_') {
                continue;
            }

            unsigned long long int next = integer * 10 + (*p - '0');
            if (next < integer) {
                p4_lex_error(token,
                             "Decimal constants must be less than 2**64.");
                return p;
            }
            integer = next;
        }

        token->value.integer = htonll(integer);
        token->radix = 10;
    }

    int default_width = p4_default_width(&token->value);
    if (width == 0) {
        width = default_width + negative;
    }
    if (width < default_width) {
        p4_lex_error(token, "Constant width %d is less than natural width %d.",
                     width, default_width);
    } else if (width > 8 * sizeof token->value) {
        p4_lex_error(token, "Constant width %d bits exceeds supported "
                     "%d-bit width.", width, 8 * sizeof token->value);
    }

    token->width = width;

    if (negative) {
        mf_subvalue_2c_negate(&token->value, width);
    }

    return p;
}

static const char *
p4_lex_parse_integer(const char *p, bool negative, struct p4_token *token)
{
    p4_token_init(token);
    token->type = P4_LEX_INTEGER;
    memset(&token->value, 0, sizeof token->value);

    p = p4_lex_parse_integer__(p, negative, token);

    const char *end = p + strspn(p, "0123456789abcdefABCDEFxX_'");
    if (p != end && token->type != P4_LEX_ERROR) {
        p4_lex_error(token, "Constant followed by unexpected character `%c'.",
                     *p);
    }
    return end;
}

static const char *
p4_lex_parse_string(const char *p, struct p4_token *token)
{
    const char *start = ++p;
    for (;;) {
        switch (*p) {
        case '\0':
            p4_lex_error(token, "Input ends inside quoted string.");
            return p;

        case '"':
            token->type = (json_string_unescape(start, p - start, &token->s)
                           ? P4_LEX_STRING : P4_LEX_ERROR);
            return p + 1;

        case '\\':
            p++;
            if (*p) {
                p++;
            }
            break;

        default:
            p++;
            break;
        }
    }
}

static bool
p4_lex_is_id1(unsigned char c)
{
    return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_');
}

static bool
p4_lex_is_idn(unsigned char c)
{
    return p4_lex_is_id1(c) || (c >= '0' && c <= '9');
}

static const char *
p4_lex_parse_id(const char *p, struct p4_token *token)
{
    const char *start = p;

    do {
        p++;
    } while (p4_lex_is_idn(*p));

    token->type = P4_LEX_ID;
    char *s = xmemdup0(start, p - start);

    if (!strcmp(s, "apply")) {
        token->type = P4_LEX_APPLY;
    } else if (!strcmp(s, "current")) {
        token->type = P4_LEX_CURRENT;
    } else if (!strcmp(s, "default")) {
        token->type = P4_LEX_DEFAULT;
    } else if (!strcmp(s, "else")) {
        token->type = P4_LEX_ELSE;
    } else if (!strcmp(s, "hit")) {
        token->type = P4_LEX_HIT;
    } else if (!strcmp(s, "if")) {
        token->type = P4_LEX_IF;
    } else if (!strcmp(s, "last")) {
        token->type = P4_LEX_LAST;
    } else if (!strcmp(s, "latest")) {
        token->type = P4_LEX_LATEST;
    } else if (!strcmp(s, "parse_error")) {
        token->type = P4_LEX_PARSE_ERROR;
    } else if (!strcmp(s, "payload")) {
        token->type = P4_LEX_PAYLOAD;
    } else if (!strcmp(s, "select")) {
        token->type = P4_LEX_SELECT;
    } else if (!strcmp(s, "switch")) {
        token->type = P4_LEX_SWITCH;
    } else {
        token->type = P4_LEX_ID;
        token->s = s;
        return p;
    }
    free(s);
    return p;
}

/* Initializes 'token' and parses the first token from the beginning of
 * null-terminated string 'p' into 'token'.  Stores a pointer to the start of
 * the token (after skipping white space and comments, if any) into '*startp'.
 * Returns the character position at which to begin parsing the next token.
 * Increments '*line_number' by the number of new-lines skipped during
 * parsing. */
const char *
p4_token_parse(struct p4_token *token, const char *p, const char **startp,
               int *line_number)
{
    p4_token_init(token);

next:
    *startp = p;
    switch (*p) {
    case '\0':
        token->type = P4_LEX_END;
        return p;

    case '\n':
        ++*line_number;
        /* Fall through. */
    case ' ': case '\t': case '\r':
        p++;
        goto next;

    case '/':
        p++;
        if (*p == '/') {
            do {
                p++;
            } while (*p != '\0' && *p != '\n');
            goto next;
        } else if (*p == '*') {
            p++;
            for (;;) {
                if (*p == '*' && p[1] == '/') {
                    p += 2;
                    goto next;
                } else if (*p == '\n') {
                    ++*line_number;
                } else if (*p == '\0') {
                    p4_lex_error(token, "`/*' without matching `*/'.");
                    return p;
                } else {
                    p++;
                }
            }
            goto next;
        } else {
            token->type = P4_LEX_DIV;
        }
        break;

    case '+':
    case '-':
        if (p[1] >= '0' && p[1] <= '9') {
            p = p4_lex_parse_integer(p + 1, *p == '-', token);
        } else {
            token->type = *p == '+' ? P4_LEX_ADD : P4_LEX_SUB;
            p++;
        }
        break;

    case '*':
        token->type = P4_LEX_MUL;
        p++;
        break;

    case '%':
        token->type = P4_LEX_MOD;
        p++;
        break;

    case '(':
        token->type = P4_LEX_LPAREN;
        p++;
        break;

    case ')':
        token->type = P4_LEX_RPAREN;
        p++;
        break;

    case '{':
        token->type = P4_LEX_LCURLY;
        p++;
        break;

    case '}':
        token->type = P4_LEX_RCURLY;
        p++;
        break;

    case '[':
        token->type = P4_LEX_LSQUARE;
        p++;
        break;

    case ']':
        token->type = P4_LEX_RSQUARE;
        p++;
        break;

    case '=':
        p++;
        if (*p == '=') {
            token->type = P4_LEX_EQ;
            p++;
        } else {
            p4_lex_error(token, "`=' is only valid as part of `=='.");
        }
        break;

    case '!':
        p++;
        if (*p == '=') {
            token->type = P4_LEX_NE;
            p++;
        } else {
            p4_lex_error(token, "'!' is only valid as part of `!='.");
        }
        break;

    case '&':
        p++;
        token->type = P4_LEX_BIT_AND;
        break;

    case '|':
        p++;
        token->type = P4_LEX_BIT_OR;
        break;

    case '^':
        p++;
        token->type = P4_LEX_BIT_XOR;
        break;

    case '~':
        p++;
        token->type = P4_LEX_BIT_NOT;
        break;

    case '<':
        p++;
        if (*p == '=') {
            token->type = P4_LEX_LE;
            p++;
        } else if (*p == '<') {
            token->type = P4_LEX_LSH;
            p++;
        } else {
            token->type = P4_LEX_LT;
        }
        break;

    case '>':
        p++;
        if (*p == '=') {
            token->type = P4_LEX_GE;
            p++;
        } else if (*p == '>') {
            token->type = P4_LEX_RSH;
            p++;
        } else {
            token->type = P4_LEX_GT;
        }
        break;

    case '.':
        p++;
        token->type = P4_LEX_PERIOD;
        break;

    case ',':
        p++;
        token->type = P4_LEX_COMMA;
        break;

    case ':':
        p++;
        token->type = P4_LEX_COLON;
        break;

    case ';':
        p++;
        token->type = P4_LEX_SEMICOLON;
        break;

    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        p = p4_lex_parse_integer(p, false, token);
        break;

    case '"':
        p = p4_lex_parse_string(p, token);
        break;

    default:
        if (p4_lex_is_id1(*p)) {
            p = p4_lex_parse_id(p, token);
        } else {
            if (isprint((unsigned char) *p)) {
                p4_lex_error(token, "Invalid character `%c' in input.", *p);
            } else {
                p4_lex_error(token, "Invalid byte 0x%d in input.", *p);
            }
            p++;
        }
        break;
    }

    return p;
}

/* Initializes 'lexer' for parsing 'input', recording 'file_name' as the name
 * of the file being read.
 *
 * While the lexer is in use, 'input' must remain available, but the caller
 * otherwise retains ownership of 'input'.
 *
 * The caller must call p4_lexer_get() to obtain the first token. */
void
p4_lexer_init(struct p4_lexer *lexer, const char *input, const char *file_name)
{
    lexer->file_name = xstrdup(file_name);
    lexer->line_number = 1;
    lexer->input = input;
    lexer->start = NULL;
    p4_token_init(&lexer->token);
}

/* Frees storage associated with 'lexer'. */
void
p4_lexer_destroy(struct p4_lexer *lexer)
{
    free(lexer->file_name);
    p4_token_destroy(&lexer->token);
}

/* Obtains the next token from 'lexer' into 'lexer->token', and returns the
 * token's type.  The caller may examine 'lexer->token' directly to obtain full
 * information about the token. */
enum p4_lex_type
p4_lexer_get(struct p4_lexer *lexer)
{
    p4_token_destroy(&lexer->token);
    lexer->input = p4_token_parse(&lexer->token, lexer->input, &lexer->start,
                                  &lexer->line_number);
    return lexer->token.type;
}

/* Returns the type of the next token that will be fetched by p4_lexer_get(),
 * without advancing 'lexer->token' to that token. */
enum p4_lex_type
p4_lexer_lookahead(const struct p4_lexer *lexer)
{
    struct p4_token next;
    enum p4_lex_type type;
    const char *start;
    int dummy = 0;

    p4_token_parse(&next, lexer->input, &start, &dummy);
    type = next.type;
    p4_token_destroy(&next);
    return type;
}

/* If 'lexer''s current token has the given 'type', advances 'lexer' to the
 * next token and returns true.  Otherwise returns false. */
bool
p4_lexer_match(struct p4_lexer *lexer, enum p4_lex_type type)
{
    if (lexer->token.type == type) {
        p4_lexer_get(lexer);
        return true;
    } else {
        return false;
    }
}

/* If 'lexer''s current token is the identifier given in 'id', advances 'lexer'
 * to the next token and returns true.  Otherwise returns false.  */
bool
p4_lexer_match_id(struct p4_lexer *lexer, const char *id)
{
    if (lexer->token.type == P4_LEX_ID && !strcmp(lexer->token.s, id)) {
        p4_lexer_get(lexer);
        return true;
    } else {
        return false;
    }
}
