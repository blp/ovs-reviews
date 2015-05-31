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
#include "p4-parse.h"
#include <stdarg.h>
#include "p4-lex.h"
#include "dynamic-string.h"
#include "shash.h"
#include "sset.h"
#include "svec.h"

struct p4_context {
    struct p4_lexer *lexer;
    char *error;
    struct ds warnings;
    struct p4_parser *parser;
};

static bool
p4_error_handle_common(struct p4_context *ctx)
{
    if (ctx->error) {
        /* Already have an error, suppress this one since the cascade seems
         * unlikely to be useful. */
        return true;
    } else if (ctx->lexer->token.type == P4_LEX_ERROR) {
        /* The lexer signaled an error.  Nothing in the parser accepts an error
         * token, so we'll inevitably end up here with some meaningless parse
         * error.  Report the lexical error instead. */
        ctx->error = xstrdup(ctx->lexer->token.s);
        return true;
    } else {
        return false;
    }
}

static void OVS_PRINTF_FORMAT(2, 3)
p4_error(struct p4_context *ctx, const char *message, ...)
{
    if (p4_error_handle_common(ctx)) {
        return;
    }

    struct ds s;

    ds_init(&s);
    ds_put_format(&s, "%s:%d: error: ",
                  ctx->lexer->file_name, ctx->lexer->line_number);

    va_list args;
    va_start(args, message);
    ds_put_format_valist(&s, message, args);
    va_end(args);

    ds_put_char(&s, '\n');

    ctx->error = ds_steal_cstr(&s);
}

static void OVS_PRINTF_FORMAT(2, 3)
p4_syntax_error(struct p4_context *ctx, const char *message, ...)
{
    if (p4_error_handle_common(ctx)) {
        return;
    }

    struct ds s;

    ds_init(&s);
    ds_put_format(&s, "%s:%d: syntax error ",
                  ctx->lexer->file_name, ctx->lexer->line_number);
    if (ctx->lexer->token.type == P4_LEX_END) {
        ds_put_cstr(&s, "at end of input ");
    } else if (ctx->lexer->start) {
        ds_put_format(&s, "at `%.*s' ",
                      (int) (ctx->lexer->input - ctx->lexer->start),
                      ctx->lexer->start);
    }

    va_list args;
    va_start(args, message);
    ds_put_format_valist(&s, message, args);
    va_end(args);

    ds_put_char(&s, '\n');

    ctx->error = ds_steal_cstr(&s);
}

static void OVS_PRINTF_FORMAT(2, 3)
p4_warn(struct p4_context *ctx, const char *message, ...)
{
    if (ctx->warnings.length) {
        ds_put_char(&ctx->warnings, '\n');
    }

    ds_put_format(&ctx->warnings, "%s:%d: warning: ",
                  ctx->lexer->file_name, ctx->lexer->line_number);

    va_list args;
    va_start(args, message);
    ds_put_format_valist(&ctx->warnings, message, args);
    va_end(args);

    ds_put_char(&ctx->warnings, '\n');
}

static bool
force_id(struct p4_context *ctx, const char *message)
{
    if (ctx->lexer->token.type != P4_LEX_ID) {
        p4_syntax_error(ctx, "%s", message);
        return false;
    } else {
        return true;
    }
}

static bool
force_match_id(struct p4_context *ctx, const char *id)
{
    if (!p4_lexer_match_id(ctx->lexer, id)) {
        p4_syntax_error(ctx, "expecting `%s'", id);
        return false;
    } else {
        return true;
    }
}

static unsigned int
int_value(const struct p4_context *ctx)
{
    return ntohll(ctx->lexer->token.value.integer);
}

static unsigned int
get_int(struct p4_context *ctx)
{
    unsigned int value = int_value(ctx);
    p4_lexer_get(ctx->lexer);
    return value;
}

static bool
force_int(struct p4_context *ctx, unsigned int min, unsigned int max)
{
    const struct p4_token *token = &ctx->lexer->token;
    if (token->type == P4_LEX_INTEGER
        && token->width <= 32
        && !token->negative
        && int_value(ctx) >= min
        && int_value(ctx) <= max) {
        return true;
    } else {
        p4_syntax_error(ctx, "expecting integer between %u and %u", min, max);
        return false;
    }
}

static bool
force_constant(struct p4_context *ctx)
{
    if (ctx->lexer->token.type != P4_LEX_INTEGER) {
        p4_syntax_error(ctx, "expecting integer constant");
        return false;
    } else {
        return true;
    }
}

static bool
force_match(struct p4_context *ctx, enum p4_lex_type type)
{
    if (!p4_lexer_match(ctx->lexer, type)) {
        struct p4_token token = { .type = type };
        struct ds s = DS_EMPTY_INITIALIZER;
        p4_token_format(&token, &s);

        p4_syntax_error(ctx, "expecting `%s'", ds_cstr(&s));

        ds_destroy(&s);
        return false;
    } else {
        return true;
    }
}

static void
p4_length_expr_destroy(struct p4_length_expr *expr)
{
    if (expr) {
        switch (expr->type) {
        case P4_LEN_CONST:
        case P4_LEN_FIELD:
            break;

        case P4_LEN_ADD:
        case P4_LEN_SUB:
        case P4_LEN_MUL:
        case P4_LEN_LSH:
        case P4_LEN_RSH:
            for (int i = 0; i < 2; i++) {
                p4_length_expr_destroy(expr->subs[i]);
            }
            break;
        }
        free(expr);
    }
}

static struct p4_field *
p4_header_lookup_field(struct p4_header *header, const char *field_name)
{
    for (size_t i = 0; i < header->n_fields; i++) {
        if (!strcmp(header->fields[i]->name, field_name)) {
            return header->fields[i];
        }
    }
    return NULL;
}

static struct p4_field *
p4_parse_field_name(struct p4_context *ctx, struct p4_header *header)
{
    if (!force_id(ctx, "expecting field name")) {
        return NULL;
    }
    struct p4_field *field = p4_header_lookup_field(header,
                                                    ctx->lexer->token.s);
    if (!field) {
        p4_syntax_error(ctx, "expecting field name");
        return NULL;
    }
    p4_lexer_get(ctx->lexer);
    return field;
}

static struct p4_length_expr *
p4_length_expr_new(enum p4_length_expr_type type)
{
    struct p4_length_expr *expr = xzalloc(sizeof *expr);
    expr->type = type;
    return expr;
}

static struct p4_length_expr *
make_binary_expr(enum p4_length_expr_type type, struct p4_length_expr *lhs,
                 struct p4_length_expr *rhs)
{
    struct p4_length_expr *expr = p4_length_expr_new(type);
    expr->subs[0] = lhs;
    expr->subs[1] = rhs;
    return expr;
}

static struct p4_length_expr *p4_parse_length_expr(struct p4_context *,
                                                   struct p4_header *);

static struct p4_length_expr *
p4_parse_primary_length_expr(struct p4_context *ctx, struct p4_header *header)
{
    if (p4_lexer_match(ctx->lexer, P4_LEX_LPAREN)) {
        struct p4_length_expr *expr = p4_parse_length_expr(ctx, header);
        if (expr && !force_match(ctx, P4_LEX_RPAREN)) {
            p4_length_expr_destroy(expr);
            expr = NULL;
        }
        return expr;
    } else if (ctx->lexer->token.type == P4_LEX_INTEGER) {
        if (!force_int(ctx, 1, 65535)) {
            return NULL;
        }

        struct p4_length_expr *expr = p4_length_expr_new(P4_LEN_CONST);
        expr->integer = get_int(ctx);
        return expr;
    } else if (ctx->lexer->token.type == P4_LEX_ID) {
        struct p4_field *field = p4_parse_field_name(ctx, header);
        if (!field) {
            return NULL;
        }

        struct p4_length_expr *expr = p4_length_expr_new(P4_LEN_FIELD);
        expr->field = field;
        return expr;
    } else {
        p4_syntax_error(ctx, "expecting length expression");
        return NULL;
    }
}

static struct p4_length_expr *
p4_parse_multiplicative_length_expr(struct p4_context *ctx,
                                    struct p4_header *header)
{
    struct p4_length_expr *lhs = p4_parse_primary_length_expr(ctx, header);
    if (!lhs) {
        return NULL;
    }

    while (ctx->lexer->token.type == P4_LEX_MUL) {
        p4_lexer_get(ctx->lexer);

        struct p4_length_expr *rhs
            = p4_parse_multiplicative_length_expr(ctx, header);
        if (!rhs) {
            p4_length_expr_destroy(lhs);
            return NULL;
        }
        lhs = make_binary_expr(P4_LEN_MUL, lhs, rhs);
    }

    return lhs;
}

static struct p4_length_expr *
p4_parse_additive_length_expr(struct p4_context *ctx, struct p4_header *header)
{
    struct p4_length_expr *lhs
        = p4_parse_multiplicative_length_expr(ctx, header);
    if (!lhs) {
        return NULL;
    }

    while (ctx->lexer->token.type == P4_LEX_ADD ||
           ctx->lexer->token.type == P4_LEX_SUB) {
        enum p4_lex_type op = ctx->lexer->token.type;
        p4_lexer_get(ctx->lexer);

        struct p4_length_expr *rhs
            = p4_parse_multiplicative_length_expr(ctx, header);
        if (!rhs) {
            p4_length_expr_destroy(lhs);
            return NULL;
        }
        lhs = make_binary_expr(op == P4_LEX_ADD ? P4_LEN_ADD : P4_LEN_SUB,
                               lhs, rhs);
    }

    return lhs;
}

static struct p4_length_expr *
p4_parse_length_expr(struct p4_context *ctx, struct p4_header *header)
{
    struct p4_length_expr *lhs = p4_parse_additive_length_expr(ctx, header);
    if (!lhs) {
        return NULL;
    }

    while (ctx->lexer->token.type == P4_LEX_LSH ||
           ctx->lexer->token.type == P4_LEX_RSH) {
        enum p4_lex_type op = ctx->lexer->token.type;
        p4_lexer_get(ctx->lexer);

        struct p4_length_expr *rhs
            = p4_parse_additive_length_expr(ctx, header);
        if (!rhs) {
            p4_length_expr_destroy(lhs);
            return NULL;
        }
        lhs = make_binary_expr(op == P4_LEX_LSH ? P4_LEN_LSH : P4_LEN_RSH,
                               lhs, rhs);
    }

    return lhs;
}

static void
p4_parse_header_type(struct p4_context *ctx)
{
    /* Parse header_type name and check for duplication.
     *
     * XXX When we support control functions, we need to check for duplication
     * there too. */
    if (!force_id(ctx, "expecting header_type name")) {
        return;
    }
    if (shash_find(&ctx->parser->headers, ctx->lexer->token.s)) {
        p4_error(ctx, "duplicate header_type name `%s'",
                 ctx->lexer->token.s);
        return;
    }

    /* Allocate data structure. */
    struct p4_header *header = xzalloc(sizeof *header);
    header->name = xstrdup(ctx->lexer->token.s);
    shash_add(&ctx->parser->headers, header->name, header);

    /* Parse "{ fields {". */
    p4_lexer_get(ctx->lexer);
    if (!force_match(ctx, P4_LEX_LCURLY)
        || !force_match_id(ctx, "fields")
        || !force_match(ctx, P4_LEX_LCURLY)) {
        return;
    }

    /* Parse fields. */
    bool saw_variable_width = false;
    int offset = 0;
    size_t allocated_fields = 0;
    do {
        if (saw_variable_width) {
            /* XXX I suspect that this isn't the intent of the P4 spec. */
            p4_error(ctx, "variable-width field must be last field");
            return;
        }

        /* Parse field_name. */
        if (!force_id(ctx, "expecting field name")) {
            return;
        }
        const char *field_name = ctx->lexer->token.s;
        if (p4_header_lookup_field(header, field_name)) {
            p4_error(ctx, "duplicate field name `%s'", field_name);
            return;
        }

        struct p4_field *field = xzalloc(sizeof *field);
        field->name = xstrdup(field_name);
        field->offset = offset;

        if (header->n_fields >= allocated_fields) {
            header->fields = x2nrealloc(header->fields, &allocated_fields,
                                        sizeof header->fields);
        }
        header->fields[header->n_fields++] = field;

        /* Parse ":". */
        p4_lexer_get(ctx->lexer);
        if (!force_match(ctx, P4_LEX_COLON)) {
            return;
        }

        /* Parse width. */
        if (p4_lexer_match(ctx->lexer, P4_LEX_MUL)) {
            if (offset % 8) {
                /* P4 1.0.2 doesn't say explicitly that this is an error. */
                p4_error(ctx,
                         "variable-width field must begin on byte boundary");
                return;
            }
            saw_variable_width = true;
            field->width = 0;
        } else if (force_int(ctx, 1, 8 * sizeof(union mf_subvalue))) {
            field->width = get_int(ctx);
        } else {
            return;
        }

        /* Parse modifiers. */
        if (p4_lexer_match(ctx->lexer, P4_LEX_LPAREN)) {
            do {
                if (p4_lexer_match_id(ctx->lexer, "signed")) {
                    field->is_signed = true;
                } else if (p4_lexer_match_id(ctx->lexer, "saturating")) {
                    field->is_saturating = true;
                } else {
                    p4_syntax_error(ctx, "expecting `signed' or `saturating'");
                    return;
                }
            } while (p4_lexer_match(ctx->lexer, P4_LEX_COMMA));
            if (!force_match(ctx, P4_LEX_RPAREN)) {
                return;
            }
        }

        /* Parse ";". */
        if (!force_match(ctx, P4_LEX_SEMICOLON)) {
            return;
        }

        offset += field->width;
    } while (!p4_lexer_match(ctx->lexer, P4_LEX_RCURLY));
    if (offset % 8) {
        /* P4 1.0.2 has conflicting information about this check.  First,
         * it says it's an error:
         *
         *     For header instances, the compiler must produce an error if
         *     the total length of all fields in a header type is not an
         *     integral number of bytes.
         *
         * but then immediately afterward:
         *
         *     The compiler may pad the header to be byte aligned.
         */
        p4_error(ctx, "header_type length must be multiple of 8 bits");
        return;
    }
    header->min_length = offset / 8;

    /* Parse length. */
    if (p4_lexer_match_id(ctx->lexer, "length")) {
        if (!force_match(ctx, P4_LEX_COLON)) {
            return;
        }

        header->length = p4_parse_length_expr(ctx, header);
        if (!header->length || !force_match(ctx, P4_LEX_SEMICOLON)) {
            return;
        }

        if (!saw_variable_width) {
            p4_warn(ctx, "ignoring `length' for fixed-width header_type `%s'",
                    header->name);
            p4_length_expr_destroy(header->length);
            header->length = NULL;
        }
    } else if (saw_variable_width) {
        p4_syntax_error(ctx, "expecting `length'");
        return;
    }

    /* Parse max_length. */
    if (p4_lexer_match_id(ctx->lexer, "max_length")) {
        if (!force_match(ctx, P4_LEX_COLON) || !force_int(ctx, 1, 1500)) {
            return;
        }
        if (saw_variable_width) {
            header->max_length = get_int(ctx);
            if (header->max_length < header->min_length) {
                p4_error(ctx, "max_length %u for header_type %s is less than "
                         "sum of %u bytes for fixed-width fields",
                         header->max_length, header->name, header->min_length);
                return;
            }
        } else {
            p4_warn(ctx, "ignoring `max_length' for fixed-width "
                    "header_type `%s'", header->name);
            p4_lexer_get(ctx->lexer);
        }
        if (!force_match(ctx, P4_LEX_SEMICOLON)) {
            return;
        }
    }
    force_match(ctx, P4_LEX_RCURLY);
}

static void
p4_parse_header_instance(struct p4_context *ctx, bool metadata)
{
    /* Parse header type. */
    if (!force_id(ctx, "expecting header_type name")) {
        return;
    }
    struct p4_header *header = shash_find_data(&ctx->parser->headers,
                                               ctx->lexer->token.s);
    if (!header) {
        p4_syntax_error(ctx, "expecting header_type name");
        return;
    }
    if (metadata && header->length) {
        p4_error(ctx, "metadata instances may not have variable-length "
                 "header types");
        return;
    }
    p4_lexer_get(ctx->lexer);

    /* Parse instance name. */
    if (!force_id(ctx, "expecting instance name")) {
        return;
    }
    if (shash_find(&ctx->parser->instances, ctx->lexer->token.s)) {
        p4_error(ctx, "duplicate instance name `%s'", ctx->lexer->token.s);
        return;
    }

    struct p4_instance *instance = xzalloc(sizeof *instance);
    instance->name = xstrdup(ctx->lexer->token.s);
    instance->header = header;
    shash_add(&ctx->parser->instances, instance->name, instance);
    p4_lexer_get(ctx->lexer);

    /* Parse array size. */
    if (p4_lexer_match(ctx->lexer, P4_LEX_LSQUARE)) {
        if (metadata) {
            p4_error(ctx, "metadata instances may not be arrays");
            return;
        }
        if (!force_int(ctx, 1, 16)) {
            return;
        }
        instance->n = get_int(ctx);
        if (!force_match(ctx, P4_LEX_RSQUARE)) {
            return;
        }
    }

    /* Parse metadata initializer. */
    if (metadata) {
        instance->initializer = xzalloc(instance->header->min_length);
    }
    if (p4_lexer_match(ctx->lexer, P4_LEX_LCURLY)) {
        if (!metadata) {
            p4_error(ctx, "only metadata instances may have initializers");
            return;
        }

        do {
            /* Parse field name. */
            struct p4_field *field = p4_parse_field_name(ctx,
                                                         instance->header);

            /* Parse ":". */
            if (!force_match(ctx, P4_LEX_COLON)) {
                return;
            }

            /* Parse value. */
            if (!force_constant(ctx)) {
                return;
            }
            const struct p4_token *token = &ctx->lexer->token;
            if (token->width > field->width) {
                /* P4 1.0.2 doesn't say this is an error. */
                p4_error(ctx, "can't initialize %d-bit field %s with %d-bit "
                         "constant", field->width, field->name, token->width);
                return;
            }
            bitwise_copy_adapt(&token->value, sizeof token->value, 0,
                               token->width, token->negative,
                               instance->initializer,
                               instance->header->min_length,
                               (8 * instance->header->min_length
                                - field->offset - field->width),
                               field->width);
            p4_lexer_get(ctx->lexer);

            /* Parser ";". */
            if (!force_match(ctx, P4_LEX_SEMICOLON)) {
                return;
            }
        } while (!p4_lexer_match(ctx->lexer, P4_LEX_RCURLY));
    }

    force_match(ctx, P4_LEX_SEMICOLON);
}

static bool
p4_parse_header_ref(struct p4_context *ctx, const char *keyword,
                    struct p4_instance **instancep, int *indexp)
{
    if (!force_id(ctx, "expecting instance name")) {
        return false;
    }

    struct p4_instance *instance
        = shash_find_data(&ctx->parser->instances, ctx->lexer->token.s);
    if (!instance) {
        p4_syntax_error(ctx, "expecting instance name");
        return false;
    }
    p4_lexer_get(ctx->lexer);

    int index = 0;
    if (instance->n) {
        if (!force_match(ctx, P4_LEX_LSQUARE)) {
            return false;
        }

        if (!strcmp(keyword, "last")
            ? p4_lexer_match(ctx->lexer, P4_LEX_LAST)
            : p4_lexer_match_id(ctx->lexer, keyword)) {
            /* WTF is "last" a keyword but not "next"? */
            index = -1;
        } else {
            if (!force_int(ctx, 0, instance->n - 1)) {
                return false;
            }
            index = get_int(ctx);
        }

        if (!force_match(ctx, P4_LEX_RSQUARE)) {
            return false;
        }
    }

    *instancep = instance;
    *indexp = index;
    return true;
}

static bool
p4_parse_field_ref(struct p4_context *ctx,
                   struct p4_instance **instancep, int *indexp,
                   struct p4_field **fieldp)
{
    struct p4_instance *instance;
    int index;
    if (!p4_parse_header_ref(ctx, "last", &instance, &index)
        || !force_match(ctx, P4_LEX_PERIOD)) {
        return false;
    }

    struct p4_field *field = p4_parse_field_name(ctx, instance->header);
    if (!field) {
        return false;
    }

    *instancep = instance;
    *indexp = index;
    *fieldp = field;
    return true;
}

static bool
p4_parse_field_or_data_ref(struct p4_context *ctx, struct p4_instance *latest,
                           bool constant_ok, struct p4_data_ref *ref)
{
    if (p4_lexer_match(ctx->lexer, P4_LEX_LATEST)) {
        if (!latest) {
            p4_error(ctx, "use of `latest' before `extract'");
            return false;
        }
        if (!force_match(ctx, P4_LEX_PERIOD)) {
            return false;
        }

        ref->type = P4_REF_FIELD;
        ref->field.instance = latest;
        ref->field.index = -1;
        ref->field.field = p4_parse_field_name(ctx, latest->header);
        if (!ref->field.field) {
            return false;
        }
        ref->width = ref->field.field->width;
        return true;
    } else if (p4_lexer_match(ctx->lexer, P4_LEX_CURRENT)) {
        if (!force_match(ctx, P4_LEX_LPAREN) || !force_int(ctx, 0, 65535)) {
            return false;
        }
        ref->type = P4_REF_CURRENT;
        ref->current.offset = get_int(ctx);
        if (!force_match(ctx, P4_LEX_COMMA)
            || !force_int(ctx, 0, 8 * sizeof ref->constant)) {
            return false;
        }
        ref->width = get_int(ctx);
        return force_match(ctx, P4_LEX_RPAREN);
    } else if (ctx->lexer->token.type == P4_LEX_INTEGER) {
        if (!constant_ok) {
            p4_error(ctx, "constant value not allowed here");
            return false;
        }
        ref->type = P4_REF_CONSTANT;
        ref->width = ctx->lexer->token.width;
        ref->constant.value = ctx->lexer->token.value;
        ref->constant.negative = ctx->lexer->token.negative;
        p4_lexer_get(ctx->lexer);
        return true;
    } else {
        ref->type = P4_REF_FIELD;
        if (!p4_parse_field_ref(ctx, &ref->field.instance, &ref->field.index,
                                &ref->field.field)) {
            return false;
        }
        ref->width = ref->field.field->width;
        return true;
    }

}

static struct p4_statement *
p4_new_statement(struct p4_state *state, enum p4_statement_type type)
{
    struct p4_statement *statement = xzalloc(sizeof *statement);
    statement->type = type;
    list_push_back(&state->statements, &statement->list_node);
    return statement;
}

static void
p4_parse_extract_statement(struct p4_context *ctx, struct p4_state *state,
                           struct p4_instance **latestp)
{
    struct p4_statement *statement = p4_new_statement(state, P4_STMT_EXTRACT);

    if (force_match(ctx, P4_LEX_LPAREN)
        && p4_parse_header_ref(ctx, "next", &statement->extract.instance,
                               &statement->extract.index)
        && force_match(ctx, P4_LEX_RPAREN)) {
        if (statement->extract.instance->initializer) {
            p4_error(ctx, "cannot extract a metadata instance");
            return;
        }
        *latestp = statement->extract.instance;
    }
}

static void
p4_parse_set_statement(struct p4_context *ctx, struct p4_state *state,
                       struct p4_instance *latest)
{
    struct p4_statement *statement = p4_new_statement(state, P4_STMT_SET);

    int index;
    if (!force_match(ctx, P4_LEX_LPAREN)
        || !p4_parse_field_ref(ctx, &statement->set.instance, &index,
                              &statement->set.field)) {
        return;
    }
    if (!statement->set.instance->initializer) {
        p4_error(ctx, "set_metadata may only be applied to metadata fields");
        return;
    }

    (force_match(ctx, P4_LEX_COMMA)
     && p4_parse_field_or_data_ref(ctx, latest, true,
                                   &statement->set.source)
     && force_match(ctx, P4_LEX_RPAREN));
}

static bool
p4_parse_constant(struct p4_context *ctx,
                  uint8_t *dst, unsigned int dst_len, unsigned int dst_ofs,
                  unsigned int n_bits)
{
    if (!force_constant(ctx)) {
        return false;
    }
    const struct p4_token *token = &ctx->lexer->token;
    if (token->width > n_bits) {
        /* P4 1.0.2 doesn't say this is an error. */
        p4_error(ctx, "can't initialize %d-bit field with %d-bit constant",
                 n_bits, token->width);
        return false;
    }
    bitwise_copy_adapt(&token->value, sizeof token->value, 0,
                       token->width, token->negative,
                       dst, dst_len, dst_ofs, n_bits);
    p4_lexer_get(ctx->lexer);
    return true;
}

static struct p4_state *
p4_new_state(struct p4_context *ctx, const char *name)
{
    struct p4_state *state = xzalloc(sizeof *state);
    state->name = xstrdup(name);
    shash_add(&ctx->parser->states, state->name, state);
    list_init(&state->statements);
    list_init(&state->cases);
    return state;
}

static bool
p4_parse_return_value(struct p4_context *ctx, struct p4_select_case *c)
{
    if (p4_lexer_match(ctx->lexer, P4_LEX_PARSE_ERROR)) {
        /* XXX We should accept a parse_error_name. */
        c->type = P4_RET_EXCEPTION;
        return true;
    } else if (p4_lexer_match_id(ctx->lexer, "ingress")) {
        /* XXX We should accept a control function name. */
        c->type = P4_RET_INGRESS;
        return true;
    } else if (force_id(ctx, "expecting parser state name")) {
        c->type = P4_RET_STATE;
        c->state = shash_find_data(&ctx->parser->states, ctx->lexer->token.s);
        if (!c->state) {
            /* Forward reference to as-yet-undefined parser state. */
            c->state = p4_new_state(ctx, ctx->lexer->token.s);
        }
        p4_lexer_get(ctx->lexer);
        return true;
    } else {
        return false;
    }
}

static void
p4_parse_select(struct p4_context *ctx, struct p4_instance *latest,
                struct p4_state *state)
{
    if (!force_match(ctx, P4_LEX_LPAREN)) {
        return;
    }

    size_t allocated_selects = 0;
    unsigned int total_bits = 0;
    do {
        if (state->n_selects >= allocated_selects) {
            state->selects = x2nrealloc(state->selects, &allocated_selects,
                                        sizeof *state->selects);
        }

        struct p4_data_ref *select = &state->selects[state->n_selects++];
        if (!p4_parse_field_or_data_ref(ctx, latest, false, select)) {
            return;
        }
        total_bits += select->width;
    } while (p4_lexer_match(ctx->lexer, P4_LEX_COMMA));
    if (!force_match(ctx, P4_LEX_RPAREN) || !force_match(ctx, P4_LEX_LCURLY)) {
        return;
    }
    state->select_bytes = DIV_ROUND_UP(total_bits, 8);

    bool saw_default = false;
    do {
        if (saw_default) {
            p4_error(ctx, "default case must be last case");
            break;
        }

        struct p4_select_case *c = xzalloc(sizeof *c);
        list_push_back(&state->cases, &c->list_node);
        if (p4_lexer_match(ctx->lexer, P4_LEX_DEFAULT)) {
            saw_default = true;
        } else {
            c->value = xzalloc(state->select_bytes);
            c->mask = xzalloc(state->select_bytes);

            unsigned int ofs = 0;
            for (size_t i = 0; i < state->n_selects; i++) {
                if (i > 0 && !force_match(ctx, P4_LEX_COMMA)) {
                    return;
                }

                const struct p4_data_ref *select = &state->selects[i];
                if (!p4_parse_constant(ctx, c->value, state->select_bytes, ofs,
                                       select->width)) {
                    return;
                }
                if (p4_lexer_match_id(ctx->lexer, "mask")) {
                    if (!p4_parse_constant(ctx, c->mask, state->select_bytes,
                                           ofs, select->width)) {
                        return;
                    }
                } else {
                    bitwise_one(c->mask, state->select_bytes, ofs,
                                select->width);
                }
                ofs += select->width;
            }

            for (size_t i = 0; i < state->select_bytes; i++) {
                c->value[i] &= c->mask[i];
            }
        }

        if (!force_match(ctx, P4_LEX_COLON)
            || !p4_parse_return_value(ctx, c)
            || !force_match(ctx, P4_LEX_SEMICOLON)) {
            return;
        }
    } while (!p4_lexer_match(ctx->lexer, P4_LEX_RCURLY));
}

static void
p4_parse_state(struct p4_context *ctx)
{
    /* Parse state name. */
    if (!force_id(ctx, "expecting parser name")) {
        return;
    }

    struct p4_state *state = shash_find_data(&ctx->parser->states,
                                             ctx->lexer->token.s);
    if (state) {
        if (!list_is_empty(&state->cases)) {
            p4_error(ctx, "duplicate parser state name `%s'",
                     ctx->lexer->token.s);
            return;
        } else {
            /* We're filling in a forward reference. */
        }
    } else {
        state = p4_new_state(ctx, ctx->lexer->token.s);
    }
    p4_lexer_get(ctx->lexer);

    /* Parse "{". */
    if (!force_match(ctx, P4_LEX_LCURLY)) {
        return;
    }

    /* Parse "extract" and "set_metadata" statements. */
    struct p4_instance *latest = NULL;
    for (;;) {
        if (p4_lexer_match_id(ctx->lexer, "extract")) {
            p4_parse_extract_statement(ctx, state, &latest);
        } else if (p4_lexer_match_id(ctx->lexer, "set_metadata")) {
            p4_parse_set_statement(ctx, state, latest);
        } else {
            break;
        }
        if (ctx->error || !force_match(ctx, P4_LEX_SEMICOLON)) {
            return;
        }
    }

    /* Parse "return" statement. */
    if (ctx->lexer->token.type != P4_LEX_PARSE_ERROR
        && !p4_lexer_match_id(ctx->lexer, "return")) {
        p4_syntax_error(ctx, "expecting statement");
        return;
    }
    if (p4_lexer_match(ctx->lexer, P4_LEX_SELECT)) {
        p4_parse_select(ctx, latest, state);
    } else {
        struct p4_select_case *c = xzalloc(sizeof *c);
        list_push_back(&state->cases, &c->list_node);
        p4_parse_return_value(ctx, c);
        if (!force_match(ctx, P4_LEX_SEMICOLON)) {
            return;
        }
    }
    force_match(ctx, P4_LEX_RCURLY);
}

void
p4_parser_destroy(struct p4_parser *parser OVS_UNUSED)
{
    /* xxx */
}

char *
p4_parse(struct p4_lexer *lexer, struct p4_parser **parserp)
{
    struct p4_context ctx;

    ctx.lexer = lexer;
    ctx.error = NULL;
    ds_init(&ctx.warnings);
    ctx.parser = xmalloc(sizeof *ctx.parser);
    shash_init(&ctx.parser->headers);
    shash_init(&ctx.parser->instances);
    shash_init(&ctx.parser->states);

    while (lexer->token.type != P4_LEX_END && !ctx.error) {
        if (p4_lexer_match_id(lexer, "header_type")) {
            p4_parse_header_type(&ctx);
        } else if (p4_lexer_match_id(lexer, "header")) {
            p4_parse_header_instance(&ctx, false);
        } else if (p4_lexer_match_id(lexer, "metadata")) {
            p4_parse_header_instance(&ctx, true);
        } else if (p4_lexer_match_id(lexer, "parser")) {
            p4_parse_state(&ctx);
        } else {
            p4_syntax_error(&ctx, "expecting top-level declaration");
        }
    }

    if (!ctx.error) {
        struct shash_node *node;
        SHASH_FOR_EACH (node, &ctx.parser->states) {
            struct p4_state *state = node->data;
            if (list_is_empty(&state->cases)) {
                p4_error(&ctx, "parser state %s referenced but never defined",
                         state->name);
                break;
            }
        }
    }

    if (!ctx.error) {
        *parserp = ctx.parser;
        return ds_steal_cstr(&ctx.warnings);
    } else {
        p4_parser_destroy(ctx.parser);
        *parserp = NULL;
        ds_destroy(&ctx.warnings);
        return ctx.error;
    }
}

/* Formatting. */

static void p4_format_length_expr(const struct p4_length_expr *, struct ds *);

static void
p4_format_length_subexpr(const struct p4_length_expr *expr, struct ds *s)
{
    if (expr->type != P4_LEN_CONST && expr->type != P4_LEN_FIELD) {
        ds_put_char(s, '(');
    }
    p4_format_length_expr(expr, s);
    if (expr->type != P4_LEN_CONST && expr->type != P4_LEN_FIELD) {
        ds_put_char(s, ')');
    }
}

static void
p4_format_length_expr_binop(const struct p4_length_expr *expr, const char *op,
                            struct ds *s)
{
    p4_format_length_subexpr(expr->subs[0], s);
    ds_put_format(s, " %s ", op);
    p4_format_length_subexpr(expr->subs[1], s);
}

static void
p4_format_length_expr(const struct p4_length_expr *expr, struct ds *s)
{
    switch (expr->type) {
    case P4_LEN_CONST:
        ds_put_format(s, "%u", expr->integer);
        break;
    case P4_LEN_FIELD:
        ds_put_format(s, "%s", expr->field->name);
        break;
    case P4_LEN_ADD:
        p4_format_length_expr_binop(expr, "+", s);
        break;
    case P4_LEN_SUB:
        p4_format_length_expr_binop(expr, "-", s);
        break;
    case P4_LEN_MUL:
        p4_format_length_expr_binop(expr, "*", s);
        break;
    case P4_LEN_LSH:
        p4_format_length_expr_binop(expr, "<<", s);
        break;
    case P4_LEN_RSH:
        p4_format_length_expr_binop(expr, ">>", s);
        break;
    }
}

static const struct p4_state **
states_bfs(const struct p4_parser *parser)
{
    const struct p4_state **states
        = xmalloc(sizeof *states * shash_count(&parser->states));
    size_t n = 0;
    struct sset used = SSET_INITIALIZER(&used);

    /* Add the start state. */
    const struct p4_state *start = shash_find_data(&parser->states, "start");
    if (start) {
        states[n++] = start;
        sset_add(&used, start->name);
    }

    /* Add all of the states reachable from the start state, in breadth-first
     * order. */
    for (size_t i = 0; i < n; i++) {
        const struct p4_state *state = states[i];
        const struct p4_select_case *c;
        LIST_FOR_EACH (c, list_node, &state->cases) {
            if (c->state && !sset_contains(&used, c->state->name)) {
                states[n++] = c->state;
                sset_add(&used, c->state->name);
            }
        }
    }

    /* Add all of the unreachable states, in alphabetical order. */
    const struct shash_node **states_sorted = shash_sort(&parser->states);
    for (size_t i = 0; i < n; i++) {
        const struct p4_state *state = states_sorted[i]->data;
        if (!sset_contains(&used, state->name)) {
            states[n++] = state;
        }
    }
    free(states_sorted);

    sset_destroy(&used);
    ovs_assert(n == shash_count(&parser->states));

    return states;
}

static void
p4_format_data_ref(const struct p4_data_ref *ref, struct ds *s)
{
    switch (ref->type) {
    case P4_REF_CONSTANT:
        ds_put_hex(s, &ref->constant.value, sizeof ref->constant.value);
        break;

    case P4_REF_FIELD:
        ds_put_cstr(s, ref->field.instance->name);
        if (ref->field.instance->n) {
            if (ref->field.index >= 0) {
                ds_put_format(s, "[%u]", ref->field.index);
            } else {
                ds_put_cstr(s, "[last]");
            }
        }
        ds_put_format(s, ".%s", ref->field.field->name);
        break;

    case P4_REF_CURRENT:
        ds_put_format(s, "current(%u, %u)", ref->current.offset, ref->width);
        break;
    }
}

void
p4_format(const struct p4_parser *parser, struct ds *s)
{
    /* Format headers in alphabetical order. */
    const struct shash_node **headers = shash_sort(&parser->headers);
    for (size_t i = 0; i < shash_count(&parser->headers); i++) {
        const struct p4_header *header = headers[i]->data;

        ds_put_format(s, "header_type %s {\n    fields {\n", header->name);
        for (size_t j = 0; j < header->n_fields; j++) {
            struct p4_field *field = header->fields[j];

            ds_put_format(s, "        %s : ", field->name);
            if (field->width) {
                ds_put_format(s, "%d", field->width);
            } else {
                ds_put_char(s, '*');
            }
            if (field->is_signed) {
                if (field->is_saturating) {
                    ds_put_cstr(s, " (signed, saturating)");
                } else {
                    ds_put_cstr(s, " (signed)");
                }
            } else if (field->is_saturating) {
                ds_put_cstr(s, " (saturating)");
            }
            ds_put_cstr(s, ";\n");
        }
        ds_put_cstr(s, "    }\n");

        if (header->length) {
            ds_put_cstr(s, "    length : ");
            p4_format_length_expr(header->length, s);
            ds_put_cstr(s, ";\n");
        }

        if (header->max_length) {
            ds_put_format(s, "    max_length : %u;\n", header->max_length);
        }
        ds_put_cstr(s, "}\n\n");
    }
    free(headers);

    /* Format instances in alphabetical order. */
    const struct shash_node **instances = shash_sort(&parser->instances);
    for (size_t i = 0; i < shash_count(&parser->instances); i++) {
        const struct p4_instance *instance = instances[i]->data;

        ds_put_format(s, "%s %s %s",
                      instance->initializer ? "metadata" : "header",
                      instance->header->name,
                      instance->name);
        if (instance->n) {
            ds_put_format(s, "[%u]", instance->n);
        }
        if (instance->initializer
            && !is_all_zeros(instance->initializer,
                             instance->header->min_length)) {
            const struct p4_header *header = instance->header;

            ds_put_cstr(s, " {\n");
            for (size_t j = 0; j < header->n_fields; j++) {
                struct p4_field *field = header->fields[j];
                union mf_subvalue value;

                memset(&value, 0, sizeof value);
                bitwise_copy(instance->initializer, header->min_length,
                             (8 * header->min_length
                              - field->offset - field->width),
                             &value, sizeof value, 0,
                             field->width);

                if (!is_all_zeros(&value, sizeof value)) {
                    ds_put_format(s, "    %s : ", field->name);
                    ds_put_hex(s, &value, sizeof value);
                    ds_put_cstr(s, ";\n");
                }
            }
            ds_put_char(s, '}');
        }
        ds_put_cstr(s, ";\n");
    }
    free(instances);

    /* Print parser states. */
    const struct p4_state **states = states_bfs(parser);
    for (size_t i = 0; i < shash_count(&parser->states); i++) {
        const struct p4_state *state = states[i];

        ds_put_format(s, "\nparser %s {\n", state->name);

        const struct p4_statement *statement;
        LIST_FOR_EACH (statement, list_node, &state->statements) {
            if (statement->type == P4_STMT_EXTRACT) {
                const struct p4_instance *instance
                    = statement->extract.instance;

                ds_put_format(s, "    extract(%s", instance->name);
                if (instance->n) {
                    int index = statement->extract.index;
                    if (index >= 0) {
                        ds_put_format(s, "[%u]", index);
                    } else {
                        ds_put_cstr(s, "[next]");
                    }
                }
                ds_put_cstr(s, ");\n");
            } else if (statement->type == P4_STMT_SET) {
                ds_put_format(s, "    set_metadata(%s.%s, ",
                              statement->set.instance->name,
                              statement->set.field->name);
                p4_format_data_ref(&statement->set.source, s);
                ds_put_cstr(s, ");\n");
            } else {
                OVS_NOT_REACHED();
            }
        }

        if (!state->n_selects) {
            /* There's only one case but this is an OK way to find it. */
            struct p4_select_case *c;
            LIST_FOR_EACH (c, list_node, &state->cases) {
                switch (c->type) {
                case P4_RET_STATE:
                    ds_put_format(s, "    return %s;\n", c->state->name);
                    break;
                case P4_RET_INGRESS:
                    ds_put_cstr(s, "    return ingress;\n");
                    break;
                case P4_RET_EXCEPTION:
                    ds_put_cstr(s, "    parse_error;\n");
                    break;
                }
            }
        } else {
            ds_put_cstr(s, "    return select(");
            for (size_t j = 0; j < state->n_selects; j++) {
                if (j > 0) {
                    ds_put_cstr(s, ", ");
                }
                p4_format_data_ref(&state->selects[j], s);
            }
            ds_put_cstr(s, ") {\n");

            struct p4_select_case *c;
            LIST_FOR_EACH (c, list_node, &state->cases) {
                ds_put_cstr(s, "        ");

                unsigned int ofs = 0;
                for (size_t j = 0; j < state->n_selects; j++) {
                    if (j > 0) {
                        ds_put_cstr(s, ", ");
                    }

                    int width = state->selects[j].width;

                    if (c->value) {
                        /* Format value. */
                        union mf_subvalue value;
                        memset(&value, 0, sizeof value);
                        bitwise_copy(c->value, state->select_bytes, ofs,
                                     &value, sizeof value, 0,
                                     width);
                        ds_put_hex(s, &value, sizeof value);

                        /* Format mask. */
                        union mf_subvalue mask;
                        memset(&mask, 0, sizeof mask);
                        bitwise_copy(c->mask, state->select_bytes, ofs,
                                     &mask, sizeof mask, 0,
                                     width);
                        if (!bitwise_is_all_ones(&mask, sizeof mask, 0,
                                                 width)) {
                            ds_put_cstr(s, " mask ");
                            ds_put_hex(s, &mask, sizeof mask);
                        }
                    } else {
                        ds_put_cstr(s, "default");
                    }
                }

                /* Format return value type. */
                ds_put_cstr(s, ": ");
                switch (c->type) {
                case P4_RET_STATE:
                    ds_put_cstr(s, c->state->name);
                    break;
                case P4_RET_INGRESS:
                    ds_put_cstr(s, "ingress");
                    break;
                case P4_RET_EXCEPTION:
                    ds_put_cstr(s, "parse_error");
                    break;
                }
                ds_put_cstr(s, ";\n");
            }
            ds_put_cstr(s, "    }\n");
        }
        ds_put_cstr(s, "}\n");
    }
    free(states);
}
