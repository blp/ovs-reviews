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

#ifndef P4_PARSE_H
#define P4_PARSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "list.h"
#include "meta-flow.h"
#include "shash.h"

struct p4_lexer;

struct p4_header {
    char *name;

    struct p4_field **fields;
    size_t n_fields;

    struct p4_length_expr *length; /* Length in bytes. */
    unsigned int min_length;       /* In bytes. */
    unsigned int max_length;       /* In bytes. */
};

struct p4_field {
    char *name;
    int offset;                 /* In bits from beginning of header. */
    int width;                  /* In bits, 0 if variable length. */
    bool is_signed;
    bool is_saturating;
};

enum p4_length_expr_type {
    P4_LEN_CONST,
    P4_LEN_FIELD,
    P4_LEN_ADD,                 /* + */
    P4_LEN_SUB,                 /* - */
    P4_LEN_MUL,                 /* * */
    P4_LEN_LSH,                 /* << */
    P4_LEN_RSH,                 /* >> */
};

struct p4_length_expr {
    enum p4_length_expr_type type;
    union {
        struct p4_field *field;
        unsigned int integer;
        struct p4_length_expr *subs[2];
    };
};

struct p4_instance {
    char *name;
    struct p4_header *header;
    unsigned int n;             /* Number of elems in array, 0 for scalar. */
    uint8_t *initializer;       /* NULL for headers, nonnull for metadata. */
};

enum p4_data_ref_type {
    P4_REF_CONSTANT,            /* Allowed in "set" but not "return". */
    P4_REF_FIELD,               /* An instance of a field. */
    P4_REF_CURRENT              /* Bits extracted relative to current pos. */
};

struct p4_data_ref {
    enum p4_data_ref_type type;

    unsigned int width;
    union {
        struct {
            union mf_subvalue value;
            bool negative;              /* True if token starts with "-". */
        } constant;
        struct {
            struct p4_instance *instance;
            int index;          /* -1 for "last". */
            struct p4_field *field;
        } field;
        struct {
            unsigned int offset;
        } current;
    };
};

enum p4_return_type {
    P4_RET_STATE,           /* To another parser state. */
    P4_RET_INGRESS,         /* To control function "ingress". */
    P4_RET_EXCEPTION,       /* To parser exception. */
};

struct p4_select_case {
    struct ovs_list list_node;  /* In struct p4_state "cases" member. */

    /* Both of these NULL for default case. */
    uint8_t *value;
    uint8_t *mask;

    enum p4_return_type type;
    struct p4_state *state;         /* P4_RET_STATE only. */
};

struct p4_state {
    const char *name;
    struct ovs_list statements; /* Contains "struct p4_statement"s. */

    /* n_selects == 0 for "return" without "select". */
    struct p4_data_ref *selects;
    size_t n_selects;
    unsigned int select_bytes;

    struct ovs_list cases;      /* Contains "struct p4_select_case"s. */
};

enum p4_statement_type {
    P4_STMT_EXTRACT,
    P4_STMT_SET
};

struct p4_statement {
    struct ovs_list list_node;
    enum p4_statement_type type;
    union {
        struct {
            struct p4_instance *instance;
            int index;          /* -1 for "next". */
        } extract;
        struct {
            /* Destination: an instance of a metadata field.  No index because
             * metadata doesn't come in array form. */
            struct p4_instance *instance;
            struct p4_field *field;

            /* Source. */
            struct p4_data_ref source;
        } set;
    };
};

struct p4_parser {
    struct shash headers;       /* Contains "struct p4_header"s. */
    struct shash instances;     /* Contains "struct p4_instance"s. */
    struct shash states;        /* Contains "struct p4_state"s. */
};

char *p4_parse(struct p4_lexer *, struct p4_parser **parserp);
void p4_format(const struct p4_parser *, struct ds *);
void p4_parser_destroy(struct p4_parser *);

#endif  /* p4-parse.h */
