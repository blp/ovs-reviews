/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2016, 2017 Nicira, Inc.
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

#include "file.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "bitmap.h"
#include "column.h"
#include "log.h"
#include "openvswitch/json.h"
#include "lockfile.h"
#include "ovsdb.h"
#include "ovsdb-error.h"
#include "row.h"
#include "socket-util.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "uuid.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ovsdb_file);

/* Minimum number of milliseconds between database compactions. */
#define COMPACT_MIN_MSEC        (10 * 60 * 1000) /* 10 minutes. */

/* Minimum number of milliseconds between trying to compact the database if
 * compacting fails. */
#define COMPACT_RETRY_MSEC      (60 * 1000)      /* 1 minute. */

/* A transaction being converted to JSON for writing to a file. */
struct ovsdb_file_txn {
    struct json *json;          /* JSON for the whole transaction. */
    struct json *table_json;    /* JSON for 'table''s transaction. */
    struct ovsdb_table *table;  /* Table described in 'table_json'.  */
};

static void ovsdb_file_txn_init(struct ovsdb_file_txn *);
static void ovsdb_file_txn_add_row(struct ovsdb_file_txn *,
                                   const struct ovsdb_row *old,
                                   const struct ovsdb_row *new,
                                   const unsigned long int *changed);


static struct ovsdb_error *
ovsdb_file_open_log(const char *file_name, enum ovsdb_log_open_mode open_mode,
                    int locking, struct ovsdb_log **logp,
                    struct ovsdb_schema **schemap)
{
    struct ovsdb_schema *schema = NULL;
    struct ovsdb_log *log = NULL;
    struct ovsdb_error *error;
    struct json *json = NULL;

    ovs_assert(logp || schemap);

    error = ovsdb_log_open(file_name, OVSDB_MAGIC, open_mode, locking, &log);
    if (error) {
        goto error;
    }

    error = ovsdb_log_read(log, &json);
    if (error) {
        goto error;
    } else if (!json) {
        error = ovsdb_io_error(EOF, "%s: database file contains no schema",
                               file_name);
        goto error;
    }

    if (schemap) {
        error = ovsdb_schema_from_json(json, &schema);
        if (error) {
            error = ovsdb_wrap_error(error,
                                     "failed to parse \"%s\" as ovsdb schema",
                                     file_name);
            goto error;
        }
    }
    json_destroy(json);

    if (logp) {
        *logp = log;
    } else {
        ovsdb_log_close(log);
    }
    if (schemap) {
        *schemap = schema;
    }
    return NULL;

error:
    ovsdb_log_close(log);
    json_destroy(json);
    if (logp) {
        *logp = NULL;
    }
    if (schemap) {
        *schemap = NULL;
    }
    return error;
}

static struct ovsdb_error *
ovsdb_file_update_row_from_json(struct ovsdb_row *row, bool converting,
                                const struct json *json)
{
    struct ovsdb_table_schema *schema = row->table->schema;
    struct ovsdb_error *error;
    struct shash_node *node;

    if (json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "row must be JSON object");
    }

    SHASH_FOR_EACH (node, json_object(json)) {
        const char *column_name = node->name;
        const struct ovsdb_column *column;
        struct ovsdb_datum datum;

        column = ovsdb_table_schema_get_column(schema, column_name);
        if (!column) {
            if (converting) {
                continue;
            }
            return ovsdb_syntax_error(json, "unknown column",
                                      "No column %s in table %s.",
                                      column_name, schema->name);
        }

        error = ovsdb_datum_from_json(&datum, &column->type, node->data, NULL);
        if (error) {
            return error;
        }
        ovsdb_datum_swap(&row->fields[column->index], &datum);
        ovsdb_datum_destroy(&datum, &column->type);
    }

    return NULL;
}

static struct ovsdb_error *
ovsdb_file_txn_row_from_json(struct ovsdb_txn *txn, struct ovsdb_table *table,
                             bool converting,
                             const struct uuid *row_uuid, struct json *json)
{
    const struct ovsdb_row *row = ovsdb_table_get_row(table, row_uuid);
    if (json->type == JSON_NULL) {
        if (!row) {
            return ovsdb_syntax_error(NULL, NULL, "transaction deletes "
                                      "row "UUID_FMT" that does not exist",
                                      UUID_ARGS(row_uuid));
        }
        ovsdb_txn_row_delete(txn, row);
        return NULL;
    } else if (row) {
        return ovsdb_file_update_row_from_json(ovsdb_txn_row_modify(txn, row),
                                               converting, json);
    } else {
        struct ovsdb_error *error;
        struct ovsdb_row *new;

        new = ovsdb_row_create(table);
        *ovsdb_row_get_uuid_rw(new) = *row_uuid;
        error = ovsdb_file_update_row_from_json(new, converting, json);
        if (error) {
            ovsdb_row_destroy(new);
        } else {
            ovsdb_txn_row_insert(txn, new);
        }
        return error;
    }
}

static struct ovsdb_error *
ovsdb_file_txn_table_from_json(struct ovsdb_txn *txn,
                               struct ovsdb_table *table,
                               bool converting, struct json *json)
{
    struct shash_node *node;

    if (json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "object expected");
    }

    SHASH_FOR_EACH (node, json->u.object) {
        const char *uuid_string = node->name;
        struct json *txn_row_json = node->data;
        struct ovsdb_error *error;
        struct uuid row_uuid;

        if (!uuid_from_string(&row_uuid, uuid_string)) {
            return ovsdb_syntax_error(json, NULL, "\"%s\" is not a valid UUID",
                                      uuid_string);
        }

        error = ovsdb_file_txn_row_from_json(txn, table, converting,
                                             &row_uuid, txn_row_json);
        if (error) {
            return error;
        }
    }

    return NULL;
}

/* Converts 'json' to an ovsdb_txn for 'db', storing the new transaction in
 * '*txnp'.  Returns NULL if successful, otherwise an error.
 *
 * If 'converting' is true, then unknown table and column names are ignored
 * (which can ease upgrading and downgrading schemas); otherwise, they are
 * treated as errors. */
struct ovsdb_error *
ovsdb_file_txn_from_json(struct ovsdb *db, const struct json *json,
                         bool converting, struct ovsdb_txn **txnp)
{
    struct ovsdb_error *error;
    struct shash_node *node;
    struct ovsdb_txn *txn;

    *txnp = NULL;

    if (json->type != JSON_OBJECT) {
        return ovsdb_syntax_error(json, NULL, "object expected");
    }

    txn = ovsdb_txn_create(db);
    SHASH_FOR_EACH (node, json->u.object) {
        const char *table_name = node->name;
        struct json *node_json = node->data;
        struct ovsdb_table *table;

        table = shash_find_data(&db->tables, table_name);
        if (!table) {
            if (!strcmp(table_name, "_date")
                && node_json->type == JSON_INTEGER) {
                continue;
            } else if (!strcmp(table_name, "_comment") || converting) {
                continue;
            }

            error = ovsdb_syntax_error(json, "unknown table",
                                       "No table named %s.", table_name);
            goto error;
        }

        error = ovsdb_file_txn_table_from_json(txn, table, converting,
                                               node_json);
        if (error) {
            goto error;
        }
    }
    *txnp = txn;
    return NULL;

error:
    ovsdb_txn_abort(txn);
    return error;
}

/* Opens database 'file_name', reads its schema, and closes it.  On success,
 * stores the schema into '*schemap' and returns NULL; the caller then owns the
 * schema.  On failure, returns an ovsdb_error (which the caller must destroy)
 * and sets '*dbp' to NULL. */
struct ovsdb_error *
ovsdb_file_read_schema(const char *file_name, struct ovsdb_schema **schemap)
{
    ovs_assert(schemap != NULL);
    return ovsdb_file_open_log(file_name, OVSDB_LOG_READ_ONLY, false,
                               NULL, schemap);
}

struct ovsdb_file {
    struct ovsdb *db;
    struct ovsdb_log *log;
    long long int last_compact;
    long long int next_compact;
    unsigned int n_transactions;
    off_t snapshot_size;
};

static bool
ovsdb_file_change_cb(const struct ovsdb_row *old,
                     const struct ovsdb_row *new,
                     const unsigned long int *changed,
                     void *ftxn_)
{
    struct ovsdb_file_txn *ftxn = ftxn_;
    ovsdb_file_txn_add_row(ftxn, old, new, changed);
    return true;
}

struct json *
ovsdb_file_txn_to_json(const struct ovsdb_txn *txn)
{
    struct ovsdb_file_txn ftxn;

    ovsdb_file_txn_init(&ftxn);
    ovsdb_txn_for_each_change(txn, ovsdb_file_change_cb, &ftxn);
    return ftxn.json;
}

struct json *
ovsdb_file_txn_annotate(struct json *json, const char *comment)
{
    if (!json) {
        json = json_object_create();
    }
    if (comment) {
        json_object_put_string(json, "_comment", comment);
    }
    json_object_put(json, "_date", json_integer_create(time_wall_msec()));
    return json;
}

void
ovsdb_file_destroy(struct ovsdb_file *file)
{
    ovsdb_log_close(file->log);
    free(file);
}

static void
ovsdb_file_txn_init(struct ovsdb_file_txn *ftxn)
{
    ftxn->json = NULL;
    ftxn->table_json = NULL;
    ftxn->table = NULL;
}

static void
ovsdb_file_txn_add_row(struct ovsdb_file_txn *ftxn,
                       const struct ovsdb_row *old,
                       const struct ovsdb_row *new,
                       const unsigned long int *changed)
{
    struct json *row;

    if (!new) {
        row = json_null_create();
    } else {
        struct shash_node *node;

        row = old ? NULL : json_object_create();
        SHASH_FOR_EACH (node, &new->table->schema->columns) {
            const struct ovsdb_column *column = node->data;
            const struct ovsdb_type *type = &column->type;
            unsigned int idx = column->index;

            if (idx != OVSDB_COL_UUID && column->persistent
                && (old
                    ? bitmap_is_set(changed, idx)
                    : !ovsdb_datum_is_default(&new->fields[idx], type)))
            {
                if (!row) {
                    row = json_object_create();
                }
                json_object_put(row, column->name,
                                ovsdb_datum_to_json(&new->fields[idx], type));
            }
        }
    }

    if (row) {
        struct ovsdb_table *table = new ? new->table : old->table;
        char uuid[UUID_LEN + 1];

        if (table != ftxn->table) {
            /* Create JSON object for transaction overall. */
            if (!ftxn->json) {
                ftxn->json = json_object_create();
            }

            /* Create JSON object for transaction on this table. */
            ftxn->table_json = json_object_create();
            ftxn->table = table;
            json_object_put(ftxn->json, table->schema->name, ftxn->table_json);
        }

        /* Add row to transaction for this table. */
        snprintf(uuid, sizeof uuid,
                 UUID_FMT, UUID_ARGS(ovsdb_row_get_uuid(new ? new : old)));
        json_object_put(ftxn->table_json, uuid, row);
    }
}
