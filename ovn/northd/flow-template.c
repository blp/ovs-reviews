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

#include "flow-template.h"
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovn/lex.h"
#include "ovn/northd/northd-nb-idl.h"
#include "ovn/northd/ovn-northd.h"
#include "ovsdb-idl-provider.h"
#include "ovsdb-idl.h"
#include "sset.h"
#include "stages.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(flow_template);

struct ftl_context;

struct ftl_variable {
    size_t n_refs;              /* Number of references to this struct. */

    const struct ovsdb_idl_table *table;
    const struct ovsdb_idl_column **columns;
    size_t n_columns;
};

static void ftl_variable_unref(struct ftl_variable *);
static bool ftl_variable_parse(struct ftl_context *, struct ftl_variable **,
                               bool column_required);
static void ftl_variable_format(const struct ftl_variable *, struct ds *);
static const struct ovsdb_type *ftl_variable_type(const struct ftl_variable *);
static const struct ovsdb_idl_table *ftl_variable_table(
    struct ftl_context *ctx, const struct ftl_variable *);

struct ftl_predicate {
    bool eq;
    struct ftl_variable *var;
    struct ovsdb_datum value;
};

static void ftl_predicate_destroy(struct ftl_predicate *);
static void ftl_predicate_clone(struct ftl_predicate *,
                                const struct ftl_predicate *);

struct ftl_item {
    enum ftl_item_type { FTL_LITERAL, FTL_VARIABLE, FTL_QUOTED_VAR } type;
    union {
        char *literal;
        struct ftl_variable *variable;
    };
};

static void ftl_item_destroy(struct ftl_item *);

struct ftl_string {
    struct ftl_item *items;
    size_t n_items;
};

static void ftl_string_destroy(struct ftl_string *);

struct ftl_flow {
    /* for (name in <table>). */
    const struct ovsdb_idl_table **quantifiers;
    size_t n_quantifiers;

    /* if (<var> == <value>) */
    struct ftl_predicate *predicates;
    size_t n_predicates;

    /* Output flow. */
    struct ftl_variable *datapath; /* Logical_Switch or Logical_Router. */
    enum ovn_stage stage;
    int priority;
    struct ftl_string match;
    struct ftl_string actions;
    char *where;
};

static void ftl_flow_destroy(struct ftl_flow *);

struct ftl {
    struct ftl_flow **flows;
    size_t n_flows;
};

struct ftl_context {
    const char *include_path;
    unsigned int include_depth;

    struct lexer *lexer;
    struct ftl *ftl;
    struct ovsdb_idl *db;
    struct shash *quantifiers;   /* Contains "struct ovsdb_idl_table *"s. */
    struct shash *substitutions; /* Contains "struct ftl_variable *"s. */
    struct ftl_predicate *predicates;
    size_t n_predicates, allocated_predicates;
    size_t allocated_flows;
};

static bool ftl_parse(struct ftl_context *ctx);

static char * OVS_WARN_UNUSED_RESULT
read_whole_file(const char *file_name, char **inputp)
{
    *inputp = NULL;

    FILE *stream = fopen(file_name, "r");
    if (!stream) {
        return xasprintf("%s: open failed (%s)",
                         file_name, ovs_strerror(errno));
    }
    struct stat s;
    if (fstat(fileno(stream), &s)) {
        fclose(stream);
        return xasprintf("%s: stat failed (%s)",
                         file_name, ovs_strerror(errno));
    }
    char *input = xmalloc(s.st_size + 1);
    input[s.st_size] = '\0';
    if (fread(input, s.st_size, 1, stream) != 1) {
        char *error = (feof(stream)
                       ? xasprintf("%s: unexpected end of file", file_name)
                       : xasprintf("%s: read error (%s)",
                                   file_name, ovs_strerror(errno)));
        free(input);
        fclose(stream);
        return error;
    }
    fclose(stream);

    *inputp = input;

    return NULL;
}

static bool
ftl_subparse(struct ftl_context *ctx)
{
    if (!lexer_force_match(ctx->lexer, LEX_T_LCURLY)) {
        return false;
    }

    while (!lexer_match(ctx->lexer, LEX_T_RCURLY)) {
        if (!ftl_parse(ctx)) {
            return false;
        }
    }
    return true;
}

static enum ovsdb_atomic_type
ftl_parse_ovsdb_atom(struct ftl_context *ctx, union ovsdb_atom *atom)
{
    if (lexer_get_int(ctx->lexer, &atom->integer)) {
        return OVSDB_TYPE_INTEGER;
    } else if (ctx->lexer->token.type == LEX_T_STRING) {
        atom->string = xstrdup(ctx->lexer->token.s);
        lexer_get(ctx->lexer);
        return OVSDB_TYPE_STRING;
    } else if (lexer_match_id(ctx->lexer, "true")) {
        atom->boolean = true;
        lexer_get(ctx->lexer);
        return OVSDB_TYPE_BOOLEAN;
    } else if (lexer_match_id(ctx->lexer, "false")) {
        atom->boolean = false;
        lexer_get(ctx->lexer);
        return OVSDB_TYPE_BOOLEAN;
    } else {
        lexer_syntax_error(ctx->lexer, "expecting value");
        return OVSDB_TYPE_VOID;
    }
}

static void
add_atom(struct ovsdb_datum *datum, union ovsdb_atom *atom, size_t *allocated)
{
    if (datum->n >= *allocated) {
        datum->keys = x2nrealloc(datum->keys, allocated, sizeof *datum->keys);
    }
    datum->keys[datum->n++] = *atom;
}

static bool
ftl_constant_parse(struct ftl_context *ctx,
                   struct ovsdb_datum *datum,
                   struct ovsdb_type *type)
{
    ovsdb_datum_init_empty(datum);
    *type = (struct ovsdb_type) { OVSDB_BASE_VOID_INIT, OVSDB_BASE_VOID_INIT,
                                  0, UINT_MAX };
    size_t allocated = 0;
    if (lexer_match(ctx->lexer, LEX_T_LSQUARE)) {
        while (!lexer_match(ctx->lexer, LEX_T_RSQUARE)) {
            union ovsdb_atom atom;
            enum ovsdb_atomic_type atom_type
                = ftl_parse_ovsdb_atom(ctx, &atom);
            if (atom_type == OVSDB_TYPE_VOID) {
                goto error;
            } else if (type->key.type == OVSDB_TYPE_VOID) {
                type->key.type = atom_type;
            } else if (type->key.type != atom_type) {
                lexer_error(ctx->lexer,
                            "cannot mix %s and %s values in set",
                            ovsdb_atomic_type_to_string(type->key.type),
                            ovsdb_atomic_type_to_string(atom_type));
                ovsdb_atom_destroy(&atom, atom_type);
                goto error;
            }
            add_atom(datum, &atom, &allocated);

            lexer_match(ctx->lexer, LEX_T_COMMA);
        }
    } else {
        union ovsdb_atom atom;
        type->key.type = ftl_parse_ovsdb_atom(ctx, &atom);
        if (type->key.type == OVSDB_TYPE_VOID) {
            goto error;
        }
        add_atom(datum, &atom, &allocated);
    }
    return true;

error:
    ovsdb_datum_destroy(datum, type);
    ovsdb_datum_init_empty(datum);
    return false;
}

static void
ftl_predicate_destroy(struct ftl_predicate *predicate)
{
    if (predicate) {
        ovsdb_datum_destroy(&predicate->value,
                            ftl_variable_type(predicate->var));
        ftl_variable_unref(predicate->var);
    }
}

static void
ftl_predicate_clone(struct ftl_predicate *dst,
                    const struct ftl_predicate *src)
{
    dst->eq = src->eq;
    dst->var = src->var;
    dst->var->n_refs++;
    ovsdb_datum_clone(&dst->value, &src->value, ftl_variable_type(dst->var));
}

static bool
ftl_predicate_parse_one(struct ftl_context *ctx)
{
    struct ftl_variable *var;
    if (!ftl_variable_parse(ctx, &var, true)) {
        free(var);
        return false;
    }

    struct ovsdb_datum value;
    struct ovsdb_type type;
    bool eq;
    if (ctx->lexer->token.type != LEX_T_EQ &&
        ctx->lexer->token.type != LEX_T_NE) {
        eq = false;
        value.n = 1;
        value.keys = xmalloc(sizeof *value.keys);
        value.keys->boolean = false;
        value.values = NULL;

        type = (struct ovsdb_type) OVSDB_TYPE_SCALAR_INITIALIZER(
            OVSDB_BASE_BOOLEAN_INIT);
    } else {
        if (lexer_match(ctx->lexer, LEX_T_EQ)) {
            eq = true;
        } else if (lexer_match(ctx->lexer, LEX_T_NE)) {
            eq = false;
        } else {
            lexer_syntax_error(ctx->lexer, NULL);
            ftl_variable_unref(var);
            return false;
        }
        if (!ftl_constant_parse(ctx, &value, &type)) {
            ftl_variable_unref(var);
            return false;
        }
    }

    const struct ovsdb_type *var_type
        = &var->columns[var->n_columns - 1]->type;
    if (value.n < var_type->n_min) {
        lexer_error(ctx->lexer,
                    "constant has too few elements for variable");
    } else if (value.n > var_type->n_max) {
        lexer_error(ctx->lexer,
                    "constant has too many elements for variable");
    } else if (type.key.type != OVSDB_TYPE_VOID
               && type.key.type != var_type->key.type) {
        lexer_error(ctx->lexer,
                    "type mismatch between constant and variable");
    }
    if (ctx->lexer->error) {
        ovsdb_datum_destroy(&value, &type);
        ftl_variable_unref(var);
        return false;
    }

    if (ctx->n_predicates >= ctx->allocated_predicates) {
        ctx->predicates = x2nrealloc(ctx->predicates,
                                     &ctx->allocated_predicates,
                                     sizeof *ctx->predicates);
    }
    struct ftl_predicate *predicate = &ctx->predicates[ctx->n_predicates++];
    predicate->eq = eq;
    predicate->var = var;
    predicate->value = value;

    return true;
}

static bool
ftl_predicate_parse__(struct ftl_context *ctx)
{
    do {
        if (!ftl_predicate_parse_one(ctx)) {
            return false;
        }
    } while (lexer_match(ctx->lexer, LEX_T_LOG_AND));
    return true;
}

static void
ftl_pop_predicates(struct ftl_context *ctx, size_t orig_n)
{
    while (ctx->n_predicates > orig_n) {
        /* XXX free memory */
        ctx->n_predicates--;
    }
}

static void
ftl_predicate_parse(struct ftl_context *ctx)
{
    size_t orig_n = ctx->n_predicates;
    lexer_force_match(ctx->lexer, LEX_T_LPAREN)
        && ftl_predicate_parse__(ctx)
        && lexer_force_match(ctx->lexer, LEX_T_RPAREN)
        && ftl_subparse(ctx);
    if (lexer_match_id(ctx->lexer, "else")) {
        if (ctx->n_predicates - orig_n == 1) {
            struct ftl_predicate *p = &ctx->predicates[ctx->n_predicates - 1];
            p->eq = !p->eq;
            ftl_subparse(ctx);
        } else {
            lexer_error(ctx->lexer, "cannot negate conjunction");
        }
    }
    ftl_pop_predicates(ctx, orig_n);
}

static void
ftl_quantifier_parse(struct ftl_context *ctx)
{
    if (!lexer_force_match(ctx->lexer, LEX_T_LPAREN)) {
        return;
    }

    /* Get name. */
    if (ctx->lexer->token.type != LEX_T_ID) {
        lexer_syntax_error(ctx->lexer, "expecting variable name");
        return;
    }
    char *name = xstrdup(ctx->lexer->token.s);
    lexer_get(ctx->lexer);
    if (shash_find(ctx->quantifiers, name)) {
        lexer_error(ctx->lexer, "%s: duplicate variable name", name);
        free(name);
        return;
    }

    /* Get "in" token. */
    if (!lexer_force_match_id(ctx->lexer, "in")) {
        free(name);
        return;
    }

    /* Get table name and ensure that we're not already iterating this
     * table. */
    const struct ovsdb_idl_table *table
        = (ctx->lexer->token.type == LEX_T_ID
           ? ovsdb_idl_lookup_table(ctx->db, ctx->lexer->token.s)
           : NULL);
    if (!table) {
        lexer_syntax_error(ctx->lexer, "expecting table name");
        free(name);
        return;
    }
    const struct shash_node *node;
    SHASH_FOR_EACH (node, ctx->quantifiers) {
        const struct ovsdb_idl_table *t = node->data;
        if (t == table) {
            lexer_error(ctx->lexer,
                        "cannot nest two iterations of table %s",
                        ctx->lexer->token.s);
            free(name);
            return;
        }
    }
    lexer_get(ctx->lexer);

    /* Add the quantifier. */
    struct shash_node *quantifier
        = shash_add_nocopy(ctx->quantifiers, name, table);

    size_t orig_n_predicates = ctx->n_predicates;
    if (lexer_match_id(ctx->lexer, "if")) {
        ftl_predicate_parse__(ctx);
    }
    lexer_force_match(ctx->lexer, LEX_T_RPAREN);
    if (!ctx->lexer->error) {
        ftl_subparse(ctx);
    }

    ftl_pop_predicates(ctx, orig_n_predicates);
    shash_delete(ctx->quantifiers, quantifier);
}

static void
ftl_variable_unref(struct ftl_variable *var)
{
    if (var) {
        ovs_assert(var->n_refs > 0);
        if (--var->n_refs == 0) {
            free(var->columns);
            free(var);
        }
    }
}

static const struct ovsdb_type *
ftl_variable_type(const struct ftl_variable *var)
{
    ovs_assert(var->n_columns > 0);
    return &var->columns[var->n_columns - 1]->type;
}

static const struct ovsdb_idl_table *
ftl_variable_table(struct ftl_context *ctx, const struct ftl_variable *var)
{
    const struct ovsdb_idl_table *table;
    if (var->n_columns) {
        const struct ovsdb_idl_column *column
            = var->columns[var->n_columns - 1];
        table = ovsdb_idl_lookup_table(ctx->db,
                                       column->type.key.u.uuid.refTableName);
        ovs_assert(table);
        return table;
    } else {
        return var->table;
    }
}

static bool
ftl_variable_parse(struct ftl_context *ctx, struct ftl_variable **varp,
                   bool column_required)
{
    struct ftl_variable *var = xmalloc(sizeof *var);
    size_t allocated_columns = 0;
    var->n_refs = 1;
    var->table = NULL;
    var->columns = NULL;
    var->n_columns = 0;

    if (ctx->lexer->token.type != LEX_T_ID) {
        lexer_syntax_error(ctx->lexer, "expecting variable reference");
        goto error;
    }

    char *copy = xstrdup(ctx->lexer->token.s);
    char *p = copy;
    const char *table_name = strsep(&p, ".");
    const struct ovsdb_idl_table *table = shash_find_data(ctx->quantifiers,
                                                          table_name);
    if (!table) {
        lexer_syntax_error(ctx->lexer, "expecting table variable name");
        goto error_free_copy;
    }
    var->table = table;

    for (;;) {
        const char *column_name = strsep(&p, ".");
        if (!column_name) {
            break;
        }
        const struct ovsdb_idl_column *column
            = ovsdb_idl_table_lookup_column(table, column_name);
        if (!column) {
            lexer_syntax_error(ctx->lexer, "because table %s does not have "
                               "a column named %s",
                               table->class->name, column_name);
            goto error_free_copy;
        }

        if (allocated_columns >= var->n_columns) {
            var->columns = x2nrealloc(var->columns, &allocated_columns,
                                      sizeof *var->columns);
        }
        var->columns[var->n_columns++] = column;

        if (ovsdb_type_is_map(&column->type)
            || !ovsdb_base_type_is_ref(&column->type.key)) {
            if (p && *p) {
                lexer_syntax_error(ctx->lexer, "because column %s in table %s "
                                   "does not refer to a row",
                                   column->name, table->class->name);
                goto error_free_copy;
            }
            break;
        }

        table = ovsdb_idl_lookup_table(ctx->db,
                                       column->type.key.u.uuid.refTableName);
        ovs_assert(table);
    }

    if (column_required && !var->n_columns) {
        lexer_syntax_error(ctx->lexer, "expecting column reference");
        goto error_free_copy;
    }

    lexer_get(ctx->lexer);
    free(copy);
    *varp = var;
    return true;

error_free_copy:
    free(copy);
    /* We delay this to here so that the error message refers to the identifier
     * token.  */
    lexer_get(ctx->lexer);
error:
    *varp = NULL;
    free(var->columns);
    free(var);
    return false;
}

static void
ftl_variable_format(const struct ftl_variable *var, struct ds *s)
{
    ds_put_cstr(s, var->table->class->name);
    for (size_t i = 0; i < var->n_columns; i++) {
        ds_put_format(s, ".%s", var->columns[i]->name);
    }
}


static bool
ftl_substitution_parse__(struct ftl_context *ctx,
                         char **namep, struct ftl_variable **varp)
{
    if (ctx->lexer->token.type != LEX_T_ID) {
        lexer_syntax_error(ctx->lexer, "expecting substitution variable name");
        return false;
    }
    if (shash_find_data(ctx->substitutions, ctx->lexer->token.s)) {
        lexer_syntax_error(ctx->lexer, "duplicate substitution variable name");
        return false;
    }
    *namep = xstrdup(ctx->lexer->token.s);
    lexer_get(ctx->lexer);

    if (!lexer_force_match(ctx->lexer, LEX_T_EQUALS)
        || !ftl_variable_parse(ctx, varp, true)) {
        free(*namep);
        return false;
    }

    return true;
}

static void
ftl_substitution_parse(struct ftl_context *ctx)
{
    if (!lexer_force_match(ctx->lexer, LEX_T_LPAREN)) {
        return;
    }

    struct sset substs = SSET_INITIALIZER(&substs);
    do {
        struct ftl_variable *var;
        char *name;
        if (!ftl_substitution_parse__(ctx, &name, &var)) {
            break;
        }

        sset_add(&substs, name);
        shash_add_nocopy(ctx->substitutions, name, var);
    } while (lexer_match(ctx->lexer, LEX_T_COMMA));
    lexer_force_match(ctx->lexer, LEX_T_RPAREN);

    if (!ctx->lexer->error) {
        ftl_subparse(ctx);
    }

    const char *s;
    SSET_FOR_EACH (s, &substs) {
        struct ftl_variable *var;
        var = shash_find_and_delete(ctx->substitutions, s);
        ftl_variable_unref(var);
    }
    sset_destroy(&substs);
}

static void
ftl_item_destroy(struct ftl_item *item)
{
    if (!item) {
        return;
    }

    switch (item->type) {
    case FTL_LITERAL:
        free(item->literal);
        break;

    case FTL_VARIABLE:
    case FTL_QUOTED_VAR:
        ftl_variable_unref(item->variable);
        break;
    }
}

static void
ftl_string_destroy(struct ftl_string *string)
{
    if (!string) {
        return;
    }

    for (size_t i = 0; i < string->n_items; i++) {
        ftl_item_destroy(&string->items[i]);
    }
}

static struct ftl_item *
add_item(struct ftl_string *string, size_t *allocated_itemsp,
         enum ftl_item_type type)
{
    if (string->n_items >= *allocated_itemsp) {
        string->items = x2nrealloc(string->items, allocated_itemsp,
                                   sizeof *string->items);
    }
    struct ftl_item *item = &string->items[string->n_items++];
    item->type = type;
    return item;
}

static bool
is_substitution(const struct lexer *lexer)
{
    bool is_subst = false;
    if (lexer->token.type == LEX_T_LT) {
        struct lexer tmp;
        lexer_clone(&tmp, lexer);
        lexer_get(&tmp);
        if (tmp.token.type == LEX_T_ID) {
            lexer_get(&tmp);
            is_subst = tmp.token.type == LEX_T_GT;
        }
        lexer_destroy(&tmp);
    }
    return is_subst;
}

static void
flush_literal_item(struct ftl_string *string, size_t *allocated_itemsp,
                   struct ds *literal)
{
    if (literal->length) {
        add_item(string, allocated_itemsp, FTL_LITERAL)->literal
            = ds_steal_cstr(literal);
    }
}

static struct ftl_variable *
ftl_expr_parse_subst(struct ftl_context *ctx)
{
    const char *s = ctx->lexer->token.s;
    size_t len = strlen(s);
    if (s[0] == '<' && s[len - 1] == '>') {
        char *name = xmemdup0(s + 1, len - 2);
        struct ftl_variable *var = shash_find_data(ctx->substitutions, name);
        if (!var) {
            lexer_error(ctx->lexer, "unknown substitution <%s>", name);
            free(name);
            return NULL;
        }
        free(name);

        return var;
    }
    return NULL;
}

static bool
ftl_expr_parse(struct ftl_context *ctx, enum lex_type end,
               struct ftl_string *string)
{
    size_t allocated_items = 0;
    string->items = NULL;
    string->n_items = 0;

    struct ds nest = DS_EMPTY_INITIALIZER;
    struct ds literal = DS_EMPTY_INITIALIZER;
    const struct lex_token *token = &ctx->lexer->token;
    do {
        if (is_substitution(ctx->lexer)) {
            flush_literal_item(string, &allocated_items, &literal);

            lexer_get(ctx->lexer); /* Skip '<'. */
            const char *name = ctx->lexer->token.s;
            struct ftl_variable *var = shash_find_data(ctx->substitutions,
                                                       name);
            if (!var) {
                lexer_error(ctx->lexer, "unknown substitution <%s>", name);
                goto exit;
            }
            struct ftl_item *item = add_item(string, &allocated_items,
                                             FTL_VARIABLE);
            item->variable = var;
            var->n_refs++;

            lexer_get(ctx->lexer); /* Skip substitution name */
            lexer_get(ctx->lexer); /* Skip '>'. */
            continue;
        }

        if (token->type == LEX_T_ERROR) {
            goto exit;
        }

        if (token->type == LEX_T_LPAREN) {
            ds_put_char(&nest, ')');
        } else if (token->type == LEX_T_LSQUARE) {
            ds_put_char(&nest, ']');
        } else if (token->type == LEX_T_LCURLY) {
            ds_put_char(&nest, '}');
        } else {
            int closing = (token->type == LEX_T_RPAREN ? ')'
                           : token->type == LEX_T_RSQUARE ? ']'
                           : token->type == LEX_T_RCURLY ? '}'
                           : 0);
            if ((closing && !ds_chomp(&nest, closing))
                || token->type == LEX_T_END) {
                int expected = (nest.length ? ds_last(&nest)
                                : end == LEX_T_RPAREN ? ')'
                                : '}');
                lexer_syntax_error(ctx->lexer, "expecting `%c'", expected);
                goto exit;
            }
        }

        switch (token->type) {
        case LEX_T_ERROR:
        case LEX_T_END:
            OVS_NOT_REACHED();

        case LEX_T_STRING: {
            struct ftl_variable *var = ftl_expr_parse_subst(ctx);
            if (var) {
                flush_literal_item(string, &allocated_items, &literal);
                struct ftl_item *item = add_item(string, &allocated_items,
                                                 FTL_QUOTED_VAR);
                item->variable = var;
                var->n_refs++;
                break;
            }
        }
            /* Fall through. */
        case LEX_T_ID:
        case LEX_T_INTEGER:
        case LEX_T_MASKED_INTEGER:
        case LEX_T_MACRO:
        case LEX_T_LPAREN:
        case LEX_T_RPAREN:
        case LEX_T_LSQUARE:              /* [ */
        case LEX_T_RSQUARE:              /* ] */
        case LEX_T_LOG_NOT:              /* ! */
        case LEX_T_ELLIPSIS:             /* .. */
        case LEX_T_DECREMENT:            /* -- */
        case LEX_T_COLON:                /* : */
            lex_token_format(token, &literal);
            break;

        case LEX_T_LCURLY:               /* { */
        case LEX_T_RCURLY:               /* } */
        case LEX_T_EQ:                   /* == */
        case LEX_T_NE:                   /* != */
        case LEX_T_LT:                   /* < */
        case LEX_T_LE:                   /* <= */
        case LEX_T_GT:                   /* > */
        case LEX_T_GE:                   /* >= */
        case LEX_T_LOG_AND:              /* && */
        case LEX_T_LOG_OR:               /* || */
        case LEX_T_EQUALS:               /* = */
        case LEX_T_EXCHANGE:             /* <-> */
            if (ds_last(&literal) != ' ') {
                ds_put_char(&literal, ' ');
            }
            lex_token_format(token, &literal);
            ds_put_char(&literal, ' ');
            break;

        case LEX_T_COMMA:                /* , */
        case LEX_T_SEMICOLON:            /* ; */
            lex_token_format(token, &literal);
            ds_put_char(&literal, ' ');
            break;
        }
        lexer_get(ctx->lexer);
    } while (!ctx->lexer->error && (token->type != end || nest.length > 0));
    flush_literal_item(string, &allocated_items, &literal);


exit:
    ds_destroy(&nest);
    ds_destroy(&literal);
    return !ctx->lexer->error;
}

static void
ftl_flow_destroy(struct ftl_flow *flow)
{
    if (!flow) {
        return;
    }

    free(flow->quantifiers);

    for (size_t i = 0; i < flow->n_predicates; i++) {
        ftl_predicate_destroy(&flow->predicates[i]);
    }
    free(flow->predicates);

    ftl_variable_unref(flow->datapath);
    ftl_string_destroy(&flow->match);
    ftl_string_destroy(&flow->actions);
    free(flow->where);
    free(flow);
}

static bool
ftl_flow_parse(struct ftl_context *ctx)
{
    struct ftl_flow *flow = xzalloc(sizeof *flow);

    flow->where = xasprintf("%s:%d", ctx->lexer->file_name,
                            ctx->lexer->line_number);

    if (!lexer_force_match(ctx->lexer, LEX_T_LPAREN)
        || !ftl_variable_parse(ctx, &flow->datapath, false)) {
        goto error;
    }

    const struct ovsdb_idl_table *table = ftl_variable_table(ctx,
                                                             flow->datapath);
    enum ovn_datapath_type table_type;
    if (table->class == &nbrec_table_logical_switch) {
        table_type = DP_SWITCH;
    } else if (table->class == &nbrec_table_logical_router) {
        table_type = DP_ROUTER;
    } else {
        lexer_error(ctx->lexer,
                    "only Logical_Switch and Logical_Router (not %s) accept flows %p %p", table->class->name, table->class, &nbrec_table_logical_switch);
        goto error;
    }

    if (!lexer_force_match(ctx->lexer, LEX_T_COMMA)) {
        goto error;
    }
    if (ctx->lexer->token.type != LEX_T_ID
        || !ovn_stage_from_string(ctx->lexer->token.s, &flow->stage)) {
        lexer_syntax_error(ctx->lexer, "expecting stage name");
        goto error;
    }
    lexer_get(ctx->lexer);

    enum ovn_datapath_type dp_type = ovn_stage_to_datapath_type(flow->stage);
    if (dp_type != table_type) {
        if (dp_type == DP_SWITCH) {
            lexer_error(ctx->lexer, "logical router flows must use "
                        "logical router stages");
        } else {
            lexer_error(ctx->lexer, "logical switch flows must use "
                        "logical switch stages");
        }
        goto error;
    }

    int64_t priority;
    if (!lexer_force_match(ctx->lexer, LEX_T_COMMA)
        || !lexer_get_int(ctx->lexer, &priority)) {
        goto error;
    }
    if (priority > UINT16_MAX) {
        lexer_error(ctx->lexer, "priority must be in range 0 to 65535");
        goto error;
    }
    flow->priority = priority;

    if (!lexer_force_match(ctx->lexer, LEX_T_COMMA)
        || !ftl_expr_parse(ctx, LEX_T_RPAREN, &flow->match)
        || !lexer_force_match(ctx->lexer, LEX_T_RPAREN)
        || !lexer_force_match(ctx->lexer, LEX_T_LCURLY)
        || !ftl_expr_parse(ctx, LEX_T_RCURLY, &flow->actions)
        || !lexer_force_match(ctx->lexer, LEX_T_RCURLY)
        || !lexer_force_match(ctx->lexer, LEX_T_SEMICOLON)) {
        goto error;
    }

    size_t n_quantifiers = shash_count(ctx->quantifiers);
    flow->quantifiers = xmalloc(n_quantifiers * sizeof *flow->quantifiers);
    const struct shash_node *node;
    SHASH_FOR_EACH (node, ctx->quantifiers) {
        const struct ovsdb_idl_table *table = node->data;
        flow->quantifiers[flow->n_quantifiers++] = table;
    }
    ovs_assert(flow->n_quantifiers == n_quantifiers);

    flow->predicates = xmalloc(ctx->n_predicates * sizeof *flow->predicates);
    flow->n_predicates = ctx->n_predicates;
    for (size_t i = 0; i < ctx->n_predicates; i++) {
        ftl_predicate_clone(&flow->predicates[i], &ctx->predicates[i]);
    }

    if (ctx->ftl->n_flows >= ctx->allocated_flows) {
        ctx->ftl->flows = x2nrealloc(ctx->ftl->flows, &ctx->allocated_flows,
                                     sizeof *ctx->ftl->flows);
    }
    ctx->ftl->flows[ctx->ftl->n_flows++] = flow;
    return true;

error:
    ftl_flow_destroy(flow);
    return false;
}

static void
ftl_parse_file(struct ftl_context *ctx, const char *file_name)
{
    /* Find input file. */
    char *qualified_fn = search_path(file_name, ctx->include_path);
    if (!qualified_fn) {
        lexer_error(ctx->lexer, "%s: not found in include path (%s)",
                    file_name, ctx->include_path ? ctx->include_path : ".");
        return;
    }

    /* Read input file. */
    char *input;
    char *error = read_whole_file(qualified_fn, &input);
    if (error) {
        lexer_error(ctx->lexer, "%s", error);
        free(qualified_fn);
        return;
    }

    /* Save old lexer and replace it with a new one. */
    struct lexer *old_lexer = ctx->lexer;
    struct lexer new_lexer;
    lexer_init(&new_lexer, input, qualified_fn);
    lexer_get(&new_lexer);
    ctx->lexer = &new_lexer;

    /* Parse file. */
    while (!new_lexer.error && new_lexer.token.type != LEX_T_END) {
        ftl_parse(ctx);
    }

    /* Restore old lexer and propagate error. */
    ctx->lexer = old_lexer;
    if (new_lexer.error && !old_lexer->error) {
        old_lexer->error = lexer_steal_error(&new_lexer);
    }

    /* Free data. */
    lexer_destroy(&new_lexer);
    free(qualified_fn);
    free(input);
}

static void
ftl_include(struct ftl_context *ctx)
{
    if (ctx->include_depth > 100) {
        lexer_syntax_error(ctx->lexer, "include depth exceeds 100");
        return;
    }

    if (!lexer_force_string(ctx->lexer)) {
        return;
    }
    ftl_parse_file(ctx, ctx->lexer->token.s);
    lexer_get(ctx->lexer);
    lexer_force_match(ctx->lexer, LEX_T_SEMICOLON);
}

static bool
ftl_parse(struct ftl_context *ctx)
{
    if (lexer_match_id(ctx->lexer, "for")) {
        ftl_quantifier_parse(ctx);
    } else if (lexer_match_id(ctx->lexer, "if")) {
        ftl_predicate_parse(ctx);
    } else if (lexer_match_id(ctx->lexer, "with")) {
        ftl_substitution_parse(ctx);
    } else if (lexer_match_id(ctx->lexer, "flow")) {
        ftl_flow_parse(ctx);
    } else if (lexer_match_id(ctx->lexer, "include")) {
        ftl_include(ctx);
    } else {
        lexer_syntax_error(ctx->lexer,
                           "expecting `for', `if', `with', or `flow'");
    }
    return !ctx->lexer->error;
}

void
ftl_destroy(struct ftl *ftl)
{
    if (!ftl) {
        return;
    }

    for (size_t i = 0; i < ftl->n_flows; i++) {
        ftl_flow_destroy(ftl->flows[i]);
    }
    free(ftl->flows);
    free(ftl);
}

char * OVS_WARN_UNUSED_RESULT
ftl_read(const char *file_name, const char *include_path,
         struct ovsdb_idl *idl, struct ftl **ftlp)
{

    struct ftl *ftl = xzalloc(sizeof *ftl);
    struct shash quantifiers = SHASH_INITIALIZER(&quantifiers);
    struct shash substitutions = SHASH_INITIALIZER(&substitutions);

    struct lexer lexer;
    lexer_init(&lexer, "", NULL);

    struct ftl_context ctx = {
        .include_path = include_path,
        .lexer = &lexer,
        .ftl = ftl,
        .db = idl,
        .quantifiers = &quantifiers,
        .substitutions = &substitutions,
    };
    ftl_parse_file(&ctx, file_name);

    char *error = lexer_steal_error(&lexer);
    lexer_destroy(&lexer);

    ovs_assert(shash_is_empty(&quantifiers));
    shash_destroy(&quantifiers);
    ovs_assert(shash_is_empty(&substitutions));
    shash_destroy(&substitutions);
    ovs_assert(!ctx.n_predicates);

    if (error) {
        ftl_destroy(ftl);
        ftl = NULL;
    }
    *ftlp = ftl;
    return error;
}

static bool
ftl_flow_first_rows(struct ovsdb_idl *idl,
                    const struct ftl_flow *flow,
                    const struct ovsdb_idl_row **rows)
{
    for (size_t i = 0; i < flow->n_quantifiers; i++) {
        rows[i] = ovsdb_idl_first_row(idl, flow->quantifiers[i]->class);
        if (!rows[i]) {
            return false;
        }
    }
    return true;
}

static bool
ftl_flow_next_rows(struct ovsdb_idl *idl,
                   const struct ftl_flow *flow,
                   const struct ovsdb_idl_row **rows)
{
    for (size_t i = 0; i < flow->n_quantifiers; i++) {
        rows[i] = ovsdb_idl_next_row(rows[i]);
        if (rows[i]) {
            return true;
        }
        rows[i] = ovsdb_idl_first_row(idl, flow->quantifiers[i]->class);
        ovs_assert(rows[i]);
    }
    return false;
}

static const struct ovsdb_idl_row *
row_for_table(const struct ftl_flow *flow, const struct ovsdb_idl_table *table,
              const struct ovsdb_idl_row **rows)
{
    /* XXX this could be O(1) */
    for (size_t i = 0; i < flow->n_quantifiers; i++) {
        if (table == flow->quantifiers[i]) {
            return rows[i];
        }
    }
    OVS_NOT_REACHED();
}

/* Returns the value of 'var'. */
static const struct ovsdb_datum *
ftl_variable_evaluate(const struct ftl_variable *var,
                      const struct ftl_flow *flow,
                      const struct ovsdb_idl_row **rows)
{
    ovs_assert(var->n_columns > 0);
    const struct ovsdb_idl_row *row = row_for_table(flow, var->table, rows);
    if (!row) {
        VLOG_INFO("missing row");
        return NULL;
    }
    /* XXX need ovsdb_idl_read_free() calls */
    VLOG_INFO("n_columns=%"PRIuSIZE, var->n_columns);
    for (size_t i = 0; ; i++) {
        const struct ovsdb_idl_column *c = var->columns[i];
        const struct ovsdb_datum *datum = ovsdb_idl_read(row, c);
        if (i + 1 >= var->n_columns) {
            return datum;
        }

        if (datum->n != 1) {
            VLOG_INFO("empty column %s", var->columns[i]->name);
            return NULL;
        }
        VLOG_INFO("column %s", c->name);
        const struct uuid *uuid = &datum->keys[0].uuid;
        //const struct ovsdb_idl_table_class *class = c->type.key.u.uuid.refTable;
        VLOG_INFO("table '%s'", c->type.key.u.uuid.refTableName);
        row = ovsdb_idl_get_row_for_uuid(row->table->idl,
                                         c->type.key.u.uuid.refTable, uuid);
        if (!row) {
            VLOG_INFO("missing row");
            return NULL;
        }
    }
}

static const struct uuid *
ftl_variable_evaluate_uuid(const struct ftl_variable *var,
                           const struct ftl_flow *flow,
                           const struct ovsdb_idl_row **rows)
{
    if (var->n_columns > 0) {
        const struct ovsdb_datum *d = ftl_variable_evaluate(var, flow, rows);
        return d && d->n ? &d->keys[0].uuid : NULL;
    } else {
        const struct ovsdb_idl_row *row
            = row_for_table(flow, var->table, rows);
        return row ? &row->uuid : NULL;
    }
}

static bool
ftl_predicate_ok(struct ftl_predicate *p, const struct ftl_flow *flow,
                 const struct ovsdb_idl_row **rows)
{
    const struct ovsdb_datum *d = ftl_variable_evaluate(p->var, flow, rows);
    if (!d) {
        return false;
    }
    struct ds s = DS_EMPTY_INITIALIZER;
    ftl_variable_format(p->var, &s);
    ds_put_cstr(&s, "(");
    ovsdb_datum_to_string(d, ftl_variable_type(p->var), &s);
    ds_put_cstr(&s, ") == ");
    ovsdb_datum_to_string(&p->value, ftl_variable_type(p->var), &s);
    ds_put_cstr(&s, "?");
    VLOG_INFO("%s", ds_cstr(&s));
    ds_destroy(&s);
    bool equal = ovsdb_datum_equals(d, &p->value, ftl_variable_type(p->var));
    return p->eq ? equal : !equal;
}

static bool
ftl_predicates_ok(const struct ftl_flow *flow,
                  const struct ovsdb_idl_row **rows)
{
    for (size_t i = 0; i < flow->n_predicates; i++) {
        if (!ftl_predicate_ok(&flow->predicates[i], flow, rows)) {
            return false;
        }
    }
    return true;
}

static char *
ftl_string_evaluate(const struct ftl_string *string,
                    const struct ftl_flow *flow,
                    const struct ovsdb_idl_row **rows)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    for (size_t i = 0; i < string->n_items; i++) {
        const struct ftl_item *item = &string->items[i];
        if (item->type == FTL_LITERAL) {
            ds_put_cstr(&s, item->literal);
        } else {
            const struct ovsdb_datum *datum = ftl_variable_evaluate(
                item->variable, flow, rows);
            if (!datum || datum->n != 1) {
                ds_destroy(&s);
                return NULL;
            }
            const struct ovsdb_type *type = ftl_variable_type(item->variable);
            if (type->key.type == OVSDB_TYPE_STRING) {
                if (item->type == FTL_QUOTED_VAR) {
                    json_string_escape(datum->keys[0].string, &s);
                } else {
                    ds_put_cstr(&s, datum->keys[0].string);
                }
            } else {
                ds_put_cstr(&s, "???");
            }
        }
    }
    ds_chomp(&s, ' ');
    return ds_steal_cstr(&s);
}

static void
ftl_flow_add(const struct ftl_flow *flow, const struct ovsdb_idl_row **rows,
             struct hmap *lflows, struct hmap *datapaths)
{
    /* Find the datapath. */
    const struct uuid *dp_uuid = ftl_variable_evaluate_uuid(flow->datapath,
                                                            flow, rows);
    if (!dp_uuid) {
        VLOG_INFO("no datapath UUID");
        return;
    }
    struct ovn_datapath *od = ovn_datapath_find(datapaths, dp_uuid);
    if (!od) {
        VLOG_INFO("no datapath "UUID_FMT, UUID_ARGS(dp_uuid));
        return;
    }

    char *match = ftl_string_evaluate(&flow->match, flow, rows);
    char *actions = ftl_string_evaluate(&flow->actions, flow, rows);
    if (match && actions) {
        ovn_lflow_add_at(lflows, od, flow->stage, flow->priority,
                         match, actions, flow->where);
    }
    free(actions);
    free(match);
}

static void
ftl_flow_run(struct ftl_flow *flow, struct ovsdb_idl *idl,
             struct hmap *flows, struct hmap *datapaths)
{
    const struct ovsdb_idl_row **rows = xmalloc(flow->n_quantifiers * sizeof *rows);
    for (bool next = ftl_flow_first_rows(idl, flow, rows); next;
         next = ftl_flow_next_rows(idl, flow, rows)) {
        if (ftl_predicates_ok(flow, rows)) {
            VLOG_INFO("row ok...");
            ftl_flow_add(flow, rows, flows, datapaths);
        } else {
            VLOG_INFO("row dropped...");
        }
    }
    free(rows);
}

void
ftl_run(struct ftl *ftl, struct ovsdb_idl *idl,
        struct hmap *flows, struct hmap *datapaths)
{
    VLOG_INFO("ftl_run starting");
    for (size_t i = 0; i < ftl->n_flows; i++) {
        ftl_flow_run(ftl->flows[i], idl, flows, datapaths);
    }
    VLOG_INFO("ftl_run done");
}
