/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2016, 2017 Nicira, Inc.
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
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "column.h"
#include "command-line.h"
#include "compiler.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "file.h"
#include "lockfile.h"
#include "log.h"
#include "openvswitch/json.h"
#include "ovsdb.h"
#include "ovsdb-data.h"
#include "ovsdb-error.h"
#include "ovsdb-parser.h"
#include "raft.h"
#include "raft-private.h"
#include "socket-util.h"
#include "storage.h"
#include "table.h"
#include "timeval.h"
#include "transaction.h"
#include "util.h"
#include "openvswitch/vlog.h"

/* -m, --more: Verbosity level for "show-log" command output. */
static int show_log_verbosity;

/* --role: RBAC role to use for "transact" and "query" commands. */
static const char *rbac_role;

/* --cid: Cluster ID for "join-cluster" command. */
static struct uuid cid;

static const struct ovs_cmdl_command *get_all_commands(void);

OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[]);

static const char *default_db(void);
static const char *default_schema(void);

int
main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = { .argc = 0, };
    set_program_name(argv[0]);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();
    fatal_signal_init();
    ctx.argc = argc - optind;
    ctx.argv = argv + optind;
    ovs_cmdl_run_command(&ctx, get_all_commands());
    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_RBAC_ROLE = UCHAR_MAX + 1,
        OPT_CID
    };
    static const struct option long_options[] = {
        {"more", no_argument, NULL, 'm'},
        {"rbac-role", required_argument, NULL, OPT_RBAC_ROLE},
        {"cid", required_argument, NULL, OPT_CID},
        {"verbose", optional_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {"option", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'm':
            show_log_verbosity++;
            break;

        case OPT_RBAC_ROLE:
            rbac_role = optarg;
            break;

        case OPT_CID:
            if (!uuid_from_string(&cid, optarg) || uuid_is_zero(&cid)) {
                ovs_fatal(0, "%s: not a valid UUID", optarg);
            }
            break;

        case 'h':
            usage();

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("%s: Open vSwitch database management utility\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n"
           "  create [DB [SCHEMA]]    create DB with the given SCHEMA\n"
           "  create-cluster DB CONTENTS LOCAL\n"
           "    create clustered DB with given CONTENTS and LOCAL address\n"
           "  [--cid=UUID] join-cluster DB NAME LOCAL REMOTE...\n"
           "    join clustered DB with given NAME and LOCAL and REMOTE addrs\n"
           "  compact [DB [DST]]      compact DB in-place (or to DST)\n"
           "  convert [DB [SCHEMA [DST]]]   convert DB to SCHEMA (to DST)\n"
           "  db-name [DB]            report name of schema used by DB\n"
           "  db-version [DB]         report version of schema used by DB\n"
           "  db-cksum [DB]           report checksum of schema used by DB\n"
           "  db-cid DB               report cluster ID of clustered DB\n"
           "  db-sid DB               report server ID of clustered DB\n"
           "  db-local-address DB     report local address of clustered DB\n"
           "  schema-name [SCHEMA]    report SCHEMA's name\n"
           "  schema-version [SCHEMA] report SCHEMA's schema version\n"
           "  schema-cksum [SCHEMA]   report SCHEMA's checksum\n"
           "  query [DB] TRNS         execute read-only transaction on DB\n"
           "  transact [DB] TRNS      execute read/write transaction on DB\n"
           "  [-m]... show-log [DB]   print DB's log entries\n"
           "The default DB is %s.\n"
           "The default SCHEMA is %s.\n",
           program_name, program_name, default_db(), default_schema());
    vlog_usage();
    printf("\
\nOther options:\n\
  -m, --more                  increase show-log verbosity\n\
  --rbac-role=ROLE            RBAC role for transact and query commands\n\
  -h, --help                  display this help message\n\
  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}

static const char *
default_db(void)
{
    static char *db;
    if (!db) {
        db = xasprintf("%s/conf.db", ovs_dbdir());
    }
    return db;
}

static const char *
default_schema(void)
{
    static char *schema;
    if (!schema) {
        schema = xasprintf("%s/vswitch.ovsschema", ovs_pkgdatadir());
    }
    return schema;
}

static struct json *
parse_json(const char *s)
{
    struct json *json = json_from_string(s);
    if (json->type == JSON_STRING) {
        ovs_fatal(0, "\"%s\": %s", s, json->u.string);
    }
    return json;
}

static void
print_and_free_json(struct json *json)
{
    char *string = json_to_string(json, JSSF_SORT);
    json_destroy(json);
    puts(string);
    free(string);
}

static void
check_ovsdb_error(struct ovsdb_error *error)
{
    if (error) {
        ovs_fatal(0, "%s", ovsdb_error_to_string(error));
    }
}

static struct ovsdb_schema *
read_schema(const char *filename)
{
    struct ovsdb_storage *storage = ovsdb_storage_open_standalone(filename,
                                                                  false);
    struct ovsdb_schema *schema = ovsdb_storage_read_schema(storage);
    ovsdb_storage_close(storage);
    return schema;
}

static void
do_create(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_db();
    const char *schema_file_name = ctx->argc >= 3 ? ctx->argv[2] : default_schema();
    struct ovsdb_schema *schema;
    struct ovsdb_log *log;
    struct json *json;

    /* Read schema from file and convert to JSON. */
    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema));
    json = ovsdb_schema_to_json(schema);
    ovsdb_schema_destroy(schema);

    /* Create database file. */
    check_ovsdb_error(ovsdb_log_open(db_file_name, OVSDB_MAGIC,
                                     OVSDB_LOG_CREATE_EXCL, -1, &log));
    check_ovsdb_error(ovsdb_log_write(log, json));
    check_ovsdb_error(ovsdb_log_commit_block(log));
    ovsdb_log_close(log);

    json_destroy(json);
}

static void
do_create_cluster(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argv[1];
    const char *src_file_name = ctx->argv[2];
    const char *local = ctx->argv[3];

    struct ovsdb_schema *schema;
    struct json *data;

    struct ovsdb_error *error = ovsdb_schema_from_file(src_file_name, &schema);
    if (!error) {
        /* It's just a schema file. */
        data = json_object_create();
    } else {
        /* Not a schema file.  Try reading it as a standalone database. */
        ovsdb_error_destroy(error);

        struct ovsdb *ovsdb = ovsdb_file_read(src_file_name, false);
        char *comment = xasprintf("created from %s", src_file_name);
        data = ovsdb_to_txn_json(ovsdb, comment);
        free(comment);
        schema = ovsdb_schema_clone(ovsdb->schema);
        ovsdb_destroy(ovsdb);
    }

    ovsdb_schema_persist_ephemeral_columns(schema, src_file_name);

    struct json *schema_json = ovsdb_schema_to_json(schema);

    /* Create database file. */
    struct json *snapshot = json_array_create_2(schema_json, data);
    check_ovsdb_error(raft_create_cluster(db_file_name, schema->name,
                                          local, snapshot));
    ovsdb_schema_destroy(schema);
    json_destroy(snapshot);
}

static void
do_join_cluster(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argv[1];
    const char *name = ctx->argv[2];
    const char *local = ctx->argv[3];

    /* Check for a plausible 'name'. */
    if (!ovsdb_parser_is_id(name)) {
        ovs_fatal(0, "%s: not a valid schema name (use \"schema-name\" "
                  "command to find the correct name)", name);
    }

    /* Create database file. */
    struct sset remote_addrs = SSET_INITIALIZER(&remote_addrs);
    for (size_t i = 4; i < ctx->argc; i++) {
        sset_add(&remote_addrs, ctx->argv[i]);
    }
    check_ovsdb_error(raft_join_cluster(db_file_name, name, local,
                                        &remote_addrs,
                                        uuid_is_zero(&cid) ? NULL : &cid));
    sset_destroy(&remote_addrs);
}

static struct ovsdb_error *
write_and_free_json(struct ovsdb_log *log, struct json *json)
{
    struct ovsdb_error *error = ovsdb_log_write(log, json);
    json_destroy(json);
    return error;
}

static struct ovsdb_error *
write_db(const char *file_name, const char *comment, const struct ovsdb *db)
{
    struct ovsdb_log *log;
    struct ovsdb_error *error = ovsdb_log_open(file_name, OVSDB_MAGIC,
                                               OVSDB_LOG_CREATE, false, &log);
    if (error) {
        return error;
    }

    error = write_and_free_json(log, ovsdb_schema_to_json(db->schema));
    if (!error) {
        error = write_and_free_json(log, ovsdb_to_txn_json(db, comment));
    }
    ovsdb_log_close(log);

    if (error) {
        remove(file_name);
    }
    return error;
}

static void
compact_or_convert(const char *src_name_, const char *dst_name_,
                   struct ovsdb_schema *new_schema, const char *comment)
{
    bool in_place = dst_name_ == NULL;

    /* Dereference symlinks for source and destination names.  In the in-place
     * case this ensures that, if the source name is a symlink, we replace its
     * target instead of replacing the symlink by a regular file.  In the
     * non-in-place, this has the same effect for the destination name. */
    char *src_name = follow_symlinks(src_name_);
    char *dst_name = (in_place
                      ? xasprintf("%s.tmp", src_name)
                      : follow_symlinks(dst_name_));

    /* Lock the source, if we will be replacing it. */
    struct lockfile *src_lock = NULL;
    if (in_place) {
        int retval = lockfile_lock(src_name, &src_lock);
        if (retval) {
            ovs_fatal(retval, "%s: failed to lock lockfile", src_name);
        }
    }

    /* Get (temporary) destination and lock it. */
    struct lockfile *dst_lock = NULL;
    int retval = lockfile_lock(dst_name, &dst_lock);
    if (retval) {
        ovs_fatal(retval, "%s: failed to lock lockfile", dst_name);
    }

    /* Save a copy. */
    struct ovsdb *ovsdb = (new_schema
                           ? ovsdb_file_read_as_schema(src_name, new_schema)
                           : ovsdb_file_read(src_name, false));
    ovsdb_storage_close(ovsdb->storage);
    ovsdb->storage = NULL;
    check_ovsdb_error(write_db(dst_name, comment, ovsdb));
    ovsdb_destroy(ovsdb);

    /* Replace source. */
    if (in_place) {
#ifdef _WIN32
        unlink(src_name);
#endif
        if (rename(dst_name, src_name)) {
            ovs_fatal(errno, "failed to rename \"%s\" to \"%s\"",
                      dst_name, src_name);
        }
        fsync_parent_dir(dst_name);
        lockfile_unlock(src_lock);
    }

    lockfile_unlock(dst_lock);

    free(src_name);
    free(dst_name);
}

static void
do_compact(struct ovs_cmdl_context *ctx)
{
    const char *db = ctx->argc >= 2 ? ctx->argv[1] : default_db();
    const char *target = ctx->argc >= 3 ? ctx->argv[2] : NULL;

    compact_or_convert(db, target, NULL, "compacted by ovsdb-tool "VERSION);
}

static void
do_convert(struct ovs_cmdl_context *ctx)
{
    const char *db = ctx->argc >= 2 ? ctx->argv[1] : default_db();
    const char *schema = ctx->argc >= 3 ? ctx->argv[2] : default_schema();
    const char *target = ctx->argc >= 4 ? ctx->argv[3] : NULL;
    struct ovsdb_schema *new_schema;

    check_ovsdb_error(ovsdb_schema_from_file(schema, &new_schema));
    compact_or_convert(db, target, new_schema,
                       "converted by ovsdb-tool "VERSION);
}

static void
do_needs_conversion(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_db();
    const char *schema_file_name = ctx->argc >= 3 ? ctx->argv[2] : default_schema();
    struct ovsdb_schema *schema1 = read_schema(db_file_name);
    struct ovsdb_schema *schema2;

    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema2));
    puts(ovsdb_schema_equal(schema1, schema2) ? "no" : "yes");
    ovsdb_schema_destroy(schema1);
    ovsdb_schema_destroy(schema2);
}

static void
do_db_name(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_db();

    struct ovsdb_log *log;
    check_ovsdb_error(ovsdb_log_open(db_file_name, OVSDB_MAGIC"|"RAFT_MAGIC,
                                     OVSDB_LOG_READ_ONLY, -1, &log));
    if (!strcmp(ovsdb_log_get_magic(log), OVSDB_MAGIC)) {
        struct json *schema_json;
        check_ovsdb_error(ovsdb_log_read(log, &schema_json));

        struct ovsdb_schema *schema;
        check_ovsdb_error(ovsdb_schema_from_json(schema_json, &schema));

        puts(schema->name);

        ovsdb_schema_destroy(schema);
        json_destroy(schema_json);
    } else if (!strcmp(ovsdb_log_get_magic(log), RAFT_MAGIC)) {
        struct raft_metadata md;
        check_ovsdb_error(raft_read_metadata(log, &md));
        puts(md.name);
        raft_metadata_destroy(&md);
    } else {
        OVS_NOT_REACHED();
    }

    ovsdb_log_close(log);
}

static void
do_db_version(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_db();
    struct ovsdb_schema *schema = read_schema(db_file_name);

    puts(schema->version);
    ovsdb_schema_destroy(schema);
}

static void
do_db_cksum(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_db();
    struct ovsdb_schema *schema = read_schema(db_file_name);
    puts(schema->cksum);
    ovsdb_schema_destroy(schema);
}

static struct raft_metadata
read_cluster_metadata(const char *filename)
{
    struct ovsdb_log *log;
    check_ovsdb_error(ovsdb_log_open(filename, OVSDB_MAGIC"|"RAFT_MAGIC,
                                     OVSDB_LOG_READ_ONLY, -1, &log));
    if (strcmp(ovsdb_log_get_magic(log), RAFT_MAGIC)) {
        ovs_fatal(0, "%s: not a clustered database", filename);
    }

    struct raft_metadata md;
    check_ovsdb_error(raft_read_metadata(log, &md));

    ovsdb_log_close(log);

    return md;
}

static void
do_db_cid(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argv[1];
    struct raft_metadata md = read_cluster_metadata(db_file_name);
    if (uuid_is_zero(&md.cid)) {
        fprintf(stderr, "%s: cluster ID not yet known\n", db_file_name);
        exit(2);
    }
    printf(UUID_FMT"\n", UUID_ARGS(&md.cid));
    raft_metadata_destroy(&md);
}

static void
do_db_sid(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argv[1];
    struct raft_metadata md = read_cluster_metadata(db_file_name);
    printf(UUID_FMT"\n", UUID_ARGS(&md.sid));
    raft_metadata_destroy(&md);
}

static void
do_db_local_address(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argv[1];
    struct raft_metadata md = read_cluster_metadata(db_file_name);
    puts(md.local);
    raft_metadata_destroy(&md);
}

static void
do_schema_name(struct ovs_cmdl_context *ctx)
{
    const char *schema_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_schema();
    struct ovsdb_schema *schema;

    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema));
    puts(schema->name);
    ovsdb_schema_destroy(schema);
}

static void
do_schema_version(struct ovs_cmdl_context *ctx)
{
    const char *schema_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_schema();
    struct ovsdb_schema *schema;

    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema));
    puts(schema->version);
    ovsdb_schema_destroy(schema);
}

static void
do_schema_cksum(struct ovs_cmdl_context *ctx)
{
    const char *schema_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_schema();
    struct ovsdb_schema *schema;

    check_ovsdb_error(ovsdb_schema_from_file(schema_file_name, &schema));
    puts(schema->cksum);
    ovsdb_schema_destroy(schema);
}

static void
transact(struct ovs_cmdl_context *ctx, bool rw)
{
    const char *db_file_name = ctx->argc >= 3 ? ctx->argv[1] : default_db();
    const char *transaction = ctx->argv[ctx->argc - 1];

    struct ovsdb *ovsdb = ovsdb_file_read(db_file_name, rw);
    struct json *request = parse_json(transaction);
    struct json *result = ovsdb_execute(ovsdb, NULL, request, false,
                                        rbac_role, NULL, 0, NULL);
    json_destroy(request);

    print_and_free_json(result);
    ovsdb_destroy(ovsdb);
}

static void
do_query(struct ovs_cmdl_context *ctx)
{
    transact(ctx, false);
}

static void
do_transact(struct ovs_cmdl_context *ctx)
{
    transact(ctx, true);
}

static void
print_db_changes(struct shash *tables, struct shash *names,
                 const struct ovsdb_schema *schema)
{
    struct shash_node *n1;

    int i = 0;
    SHASH_FOR_EACH (n1, tables) {
        const char *table = n1->name;
        struct ovsdb_table_schema *table_schema;
        struct json *rows = n1->data;
        struct shash_node *n2;

        if (n1->name[0] == '_' || rows->type != JSON_OBJECT) {
            continue;
        }

        if (i++ == 0) {
            putchar('\n');
        }

        table_schema = schema ? shash_find_data(&schema->tables, table) : NULL;
        SHASH_FOR_EACH (n2, json_object(rows)) {
            const char *row_uuid = n2->name;
            struct json *columns = n2->data;
            struct shash_node *n3;
            char *old_name, *new_name;
            bool free_new_name = false;

            old_name = new_name = shash_find_data(names, row_uuid);
            if (columns->type == JSON_OBJECT) {
                struct json *new_name_json;

                new_name_json = shash_find_data(json_object(columns), "name");
                if (new_name_json) {
                    new_name = json_to_string(new_name_json, JSSF_SORT);
                    free_new_name = true;
                }
            }

            printf("\ttable %s", table);

            if (!old_name) {
                if (new_name) {
                    printf(" insert row %s (%.8s):\n", new_name, row_uuid);
                } else {
                    printf(" insert row %.8s:\n", row_uuid);
                }
            } else {
                printf(" row %s (%.8s):\n", old_name, row_uuid);
            }

            if (columns->type == JSON_OBJECT) {
                if (show_log_verbosity > 1) {
                    SHASH_FOR_EACH (n3, json_object(columns)) {
                        const char *column = n3->name;
                        const struct ovsdb_column *column_schema;
                        struct json *value = n3->data;
                        char *value_string = NULL;

                        column_schema =
                            (table_schema
                             ? shash_find_data(&table_schema->columns, column)
                             : NULL);
                        if (column_schema) {
                            const struct ovsdb_type *type;
                            struct ovsdb_error *error;
                            struct ovsdb_datum datum;

                            type = &column_schema->type;
                            error = ovsdb_datum_from_json(&datum, type,
                                                          value, NULL);
                            if (!error) {
                                struct ds s;

                                ds_init(&s);
                                ovsdb_datum_to_string(&datum, type, &s);
                                value_string = ds_steal_cstr(&s);
                            } else {
                                ovsdb_error_destroy(error);
                            }
                        }
                        if (!value_string) {
                            value_string = json_to_string(value, JSSF_SORT);
                        }
                        printf("\t\t%s=%s\n", column, value_string);
                        free(value_string);
                    }
                }
                if (!old_name
                    || (new_name != old_name && strcmp(old_name, new_name))) {
                    if (old_name) {
                        shash_delete(names, shash_find(names, row_uuid));
                        free(old_name);
                    }
                    shash_add(names, row_uuid, (new_name
                                                ? xstrdup(new_name)
                                                : xmemdup0(row_uuid, 8)));
                }
            } else if (columns->type == JSON_NULL) {
                struct shash_node *node;

                printf("\t\tdelete row\n");
                node = shash_find(names, row_uuid);
                if (node) {
                    shash_delete(names, node);
                }
                free(old_name);
            }

            if (free_new_name) {
                free(new_name);
            }
        }
    }
}

static void
print_change_record(const struct json *json, const struct ovsdb_schema *schema,
                    struct shash *names)
{
    if (!json || json->type != JSON_OBJECT) {
        return;
    }

    struct json *date, *comment;

    date = shash_find_data(json_object(json), "_date");
    if (date && date->type == JSON_INTEGER) {
        long long int t = json_integer(date);
        char *s;

        if (t < INT32_MAX) {
            /* Older versions of ovsdb wrote timestamps in seconds. */
            t *= 1000;
        }

        s = xastrftime_msec(" %Y-%m-%d %H:%M:%S.###", t, true);
        fputs(s, stdout);
        free(s);
    }

    comment = shash_find_data(json_object(json), "_comment");
    if (comment && comment->type == JSON_STRING) {
        printf(" \"%s\"", json_string(comment));
    }

    if (show_log_verbosity > 0) {
        print_db_changes(json_object(json), names, schema);
    }
}

static void
do_show_log_standalone(struct ovsdb_log *log)
{
    struct shash names = SHASH_INITIALIZER(&names);
    struct ovsdb_schema *schema = NULL;

    for (unsigned int i = 0; ; i++) {
        struct json *json;

        check_ovsdb_error(ovsdb_log_read(log, &json));
        if (!json) {
            break;
        }

        printf("record %u:", i);
        if (i == 0) {
            check_ovsdb_error(ovsdb_schema_from_json(json, &schema));
            printf(" \"%s\" schema, version=\"%s\", cksum=\"%s\"\n",
                   schema->name, schema->version, schema->cksum);
        } else {
            print_change_record(json, schema, &names);
        }
        json_destroy(json);
        putchar('\n');
    }

    ovsdb_schema_destroy(schema);
    /* XXX free 'names'. */
}

static void
print_servers(const char *name, const struct json *servers)
{
    if (!servers) {
        return;
    }

    printf(" %s: ", name);

    const struct shash_node **nodes = shash_sort(json_object(servers));
    size_t n = shash_count(json_object(servers));
    for (size_t i = 0; i < n; i++) {
        if (i > 0) {
            printf(", ");
        }

        const struct shash_node *node = nodes[i];
        printf("%.4s(", node->name);

        const struct json *address = node->data;
        char *s = json_to_string(address, JSSF_SORT);
        fputs(s, stdout);
        free(s);

        putchar(')');
    }
    free(nodes);
    putchar('\n');
}

static void
print_data(const char *prefix, const struct json *data,
           struct ovsdb_schema **schemap, struct shash *names)
{
    if (!data) {
        return;
    }

    if (json_array(data)->n != 2) {
        printf(" ***invalid data***\n");
        return;
    }

    const struct json *schema_json = json_array(data)->elems[0];
    if (schema_json->type != JSON_NULL) {
        struct ovsdb_schema *schema;

        check_ovsdb_error(ovsdb_schema_from_json(schema_json, &schema));
        printf(" %sschema: \"%s\", version=\"%s\", cksum=\"%s\"\n",
               prefix, schema->name, schema->version, schema->cksum);

        ovsdb_schema_destroy(*schemap);
        *schemap = schema;
    }

    print_change_record(json_array(data)->elems[1], *schemap, names);
}

static void
print_raft_header(const struct raft_header *h,
                  struct ovsdb_schema **schemap, struct shash *names)
{
    printf(" name: \"%s\'\n", h->name);
    printf(" local address: \"%s\"\n", h->local_address);
    printf(" server_id: "SID_FMT"\n", SID_ARGS(&h->sid));
    if (!uuid_is_zero(&h->cid)) {
        printf(" cluster_id: "CID_FMT"\n", CID_ARGS(&h->cid));
    }
    if (!sset_is_empty(&h->remote_addresses)) {
        printf(" remote_addresses:");

        const char *s;
        SSET_FOR_EACH (s, &h->remote_addresses) {
            printf(" %s", s);
        }
        putchar('\n');
    }
    if (h->snap_index) {
        printf(" prev_index: %"PRIu64"\n", h->snap_index);
        printf(" prev_term: %"PRIu64"\n", h->snap.term);
        print_servers("prev_servers", h->snap.servers);
        if (!uuid_is_zero(&h->snap.eid)) {
            printf(" prev_eid: %04x\n", uuid_prefix(&h->snap.eid, 4));
        }
        print_data("prev_", h->snap.data, schemap, names);
    }
}

static void
print_raft_record(const struct raft_record *r,
                  struct ovsdb_schema **schemap, struct shash *names)
{
    if (r->term) {
        printf(" term: %"PRIu64"\n", r->term);
    }

    switch (r->type) {
    case RAFT_REC_ENTRY:
        printf(" index: %"PRIu64"\n", r->entry.index);
        print_servers("servers", r->entry.servers);
        if (!uuid_is_zero(&r->entry.eid)) {
            printf(" eid: %04x\n", uuid_prefix(&r->entry.eid, 4));
        }
        print_data("", r->entry.data, schemap, names);
        break;

    case RAFT_REC_TERM:
        break;

    case RAFT_REC_VOTE:
        printf(" vote: "SID_FMT"\n", SID_ARGS(&r->vote));
        break;

    case RAFT_REC_COMMIT_INDEX:
        printf(" commit_index: %"PRIu64"\n", r->commit_index);
        break;

    case RAFT_REC_LEADER:
        printf(" leader: true\n");
        break;

    case RAFT_REC_LEFT:
        printf(" left: true\n");
        break;

    default:
        OVS_NOT_REACHED();
    }
}

static void
do_show_log_cluster(struct ovsdb_log *log)
{
    struct shash names = SHASH_INITIALIZER(&names);
    struct ovsdb_schema *schema = NULL;
    unsigned int i;

    shash_init(&names);
    schema = NULL;
    for (i = 0; ; i++) {
        struct json *json;
        check_ovsdb_error(ovsdb_log_read(log, &json));
        if (!json) {
            break;
        }

        printf("record %u:\n", i);
        struct ovsdb_error *error;
        if (i == 0) {
            struct raft_header h;
            error = raft_header_from_json(&h, json);
            if (!error) {
                print_raft_header(&h, &schema, &names);
                raft_header_uninit(&h);
            }
        } else {
            struct raft_record r;
            error = raft_record_from_json(&r, json);
            if (!error) {
                print_raft_record(&r, &schema, &names);
                raft_record_uninit(&r);
            }
        }
        if (error) {
            char *s = ovsdb_error_to_string_free(error);
            puts(s);
            free(s);
        }

        putchar('\n');
    }

    ovsdb_schema_destroy(schema);
    /* XXX free 'names'. */
}

static void
do_show_log(struct ovs_cmdl_context *ctx)
{
    const char *db_file_name = ctx->argc >= 2 ? ctx->argv[1] : default_db();
    struct ovsdb_log *log;

    check_ovsdb_error(ovsdb_log_open(db_file_name, OVSDB_MAGIC"|"RAFT_MAGIC,
                                     OVSDB_LOG_READ_ONLY, -1, &log));
    if (!strcmp(ovsdb_log_get_magic(log), OVSDB_MAGIC)) {
        do_show_log_standalone(log);
    } else {
        do_show_log_cluster(log);
    }
    ovsdb_log_close(log);
}

struct server {
    const char *filename;

    struct raft_header header;

    struct raft_record *records;
    size_t n_records;

    struct raft_entry *snap;
    struct raft_entry *entries;
    uint64_t log_start, log_end;
};

static void
do_check_cluster(struct ovs_cmdl_context *ctx)
{
    struct server *servers = xzalloc((ctx->argc - 1) * sizeof *servers);
    size_t n_servers = 0;

    uint64_t max_term = 0;

    for (int i = 1; i < ctx->argc; i++) {
        struct server *s = &servers[n_servers];
        s->filename = ctx->argv[i];

        struct ovsdb_log *log;
        check_ovsdb_error(ovsdb_log_open(s->filename, RAFT_MAGIC,
                                         OVSDB_LOG_READ_ONLY, -1, &log));

        struct json *json;
        check_ovsdb_error(ovsdb_log_read(log, &json));
        check_ovsdb_error(raft_header_from_json(&s->header, json));
        json_destroy(json);

        if (s->header.joining) {
            printf("%s has not joined the cluster, omitting\n", s->filename);
            continue;
        }
        if (n_servers > 0) {
            struct server *s0 = &servers[0];
            if (!uuid_equals(&s0->header.cid, &s->header.cid)) {
                ovs_fatal(0, "%s has cluster ID "CID_FMT" but %s "
                          "has cluster ID "CID_FMT,
                          s0->filename, CID_ARGS(&s0->header.cid),
                          s->filename, CID_ARGS(&s->header.cid));
            }
            if (strcmp(s0->header.name, s->header.name)) {
                ovs_fatal(0, "%s is named \"%s\" but %s is named \"%s\"",
                          s0->filename, s0->header.name,
                          s->filename, s->header.name);
            }
        }
        s->snap = &s->header.snap;
        s->log_start = s->log_end = s->header.snap_index + 1;

        size_t allocated_records = 0;
        size_t allocated_entries = 0;
        uint64_t term = 0;
        struct uuid vote = UUID_ZERO;
        uint64_t commit_index = s->header.snap_index;
        for (unsigned long long int rec_idx = 1; ; rec_idx++) {
            if (s->n_records >= allocated_records) {
                s->records = x2nrealloc(s->records, &allocated_records,
                                        sizeof *s->records);
            }
            check_ovsdb_error(ovsdb_log_read(log, &json));
            if (!json) {
                break;
            }
            struct raft_record *r = &s->records[s->n_records++];
            check_ovsdb_error(raft_record_from_json(r, json));
            json_destroy(json);

            if (r->term > term) {
                term = r->term;
                vote = UUID_ZERO;
            }

            switch (r->type) {
            case RAFT_REC_ENTRY:
                if (r->entry.index < commit_index) {
                    ovs_fatal(0, "%s: record %llu  attempts to truncate log "
                              "from %"PRIu64" to %"PRIu64" entries, but "
                              "commit index is already %"PRIu64,
                              s->filename, rec_idx,
                              s->log_end, r->entry.index,
                              commit_index);
                } else if (r->entry.index > s->log_end) {
                    ovs_fatal(0, "%s: record %llu with index %"PRIu64" skips "
                              "past expected index %"PRIu64, s->filename,
                              rec_idx, r->entry.index, s->log_end);
                }

                if (r->entry.index < s->log_end) {
                    /* This can happen, but it is unusual. */
                    printf("%s: record %llu truncates log from %"PRIu64" to "
                           "%"PRIu64" entries", s->filename, rec_idx,
                           s->log_end, r->entry.index);
                    s->log_end = r->entry.index;
                }

                uint64_t prev_term = (s->log_end > s->log_start
                                      ? s->entries[s->log_end
                                                   - s->log_start - 1].term
                                      : s->snap->term);
                if (r->term < prev_term) {
                    ovs_fatal(0, "%s: record %llu with index %"PRIu64" term "
                              "%"PRIu64" precedes previous entry's term "
                              "%"PRIu64, s->filename, rec_idx,
                              r->entry.index, r->term, prev_term);
                }

                uint64_t log_idx = s->log_end++ - s->log_start;
                if (log_idx >= allocated_entries) {
                    s->entries = x2nrealloc(s->entries, &allocated_entries,
                                            sizeof *s->entries);
                }
                struct raft_entry *e = &s->entries[log_idx];
                e->term = r->term;
                e->data = r->entry.data;
                e->eid = r->entry.eid;
                e->servers = r->entry.servers;
                break;

            case RAFT_REC_TERM:
                break;

            case RAFT_REC_VOTE:
                if (r->term < term) {
                    ovs_fatal(0, "%s: record %llu votes for term %"PRIu64" "
                              "but current term is %"PRIu64, s->filename,
                              rec_idx, r->term, term);
                } else if (!uuid_is_zero(&vote)
                           && !uuid_equals(&vote, &r->vote)) {
                    ovs_fatal(0, "%s: record %llu votes for "SID_FMT" in term "
                              "%"PRIu64" but a previous record for the "
                              "same term voted for "SID_FMT, s->filename,
                              rec_idx, SID_ARGS(&vote), r->term,
                              SID_ARGS(&r->vote));
                } else {
                    vote = r->vote;
                }
                break;


            case RAFT_REC_COMMIT_INDEX:
                if (r->commit_index < commit_index) {
                    ovs_fatal(0, "%s: record %llu regresses commit index "
                              "from %"PRIu64 " to %"PRIu64, s->filename,
                              rec_idx, commit_index, r->commit_index);
                } else if (r->commit_index >= s->log_end) {
                    ovs_fatal(0, "%s: record %llu advances commit index to "
                              "%"PRIu64 " but last log index is %"PRIu64,
                              s->filename, rec_idx, r->commit_index,
                              s->log_end - 1);
                } else {
                    commit_index = r->commit_index;
                }
                break;

            case RAFT_REC_LEADER:
                break;

            case RAFT_REC_LEFT:
                printf("%s: record %llu shows that the server left the "
                       "cluster\n", s->filename, rec_idx);
                break;
            }
        }

        if (term > max_term) {
            max_term = term;
        }

        n_servers++;
    }

    /* Check election safety property.
     *
     * This could use O(n_servers) memory but it currently uses O(max_term). */
    struct server **leaders = xzalloc((max_term + 1) * sizeof *leaders);
    for (size_t server_idx = 0; server_idx < n_servers; server_idx++) {
        struct server *s = &servers[server_idx];

        for (size_t i = 0; i < s->n_records; i++) {
            const struct raft_record *r = &s->records[i];
            ovs_assert(r->term <= max_term);

            if (r->type == RAFT_REC_LEADER) {
                struct server **leader = &leaders[r->term];
                if (!*leader) {
                    *leader = s;
                } else if (*leader != s) {
                    ovs_fatal(0, "term %"PRIu64" has two different leaders: "
                              SID_FMT" and "SID_FMT,
                              r->term, SID_ARGS(&(*leader)->header.sid),
                              SID_ARGS(&s->header.sid));
                }
            }
        }
    }
    free(leaders);
}

static void
do_help(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    usage();
}

static void
do_list_commands(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
     ovs_cmdl_print_commands(get_all_commands());
}

static const struct ovs_cmdl_command all_commands[] = {
    { "create", "[db [schema]]", 0, 2, do_create, OVS_RW },
    { "create-cluster", "db contents local", 3, 3, do_create_cluster, OVS_RW },
    { "join-cluster", "db name local remote...", 4, INT_MAX, do_join_cluster,
      OVS_RW },
    { "compact", "[db [dst]]", 0, 2, do_compact, OVS_RW },
    { "convert", "[db [schema [dst]]]", 0, 3, do_convert, OVS_RW },
    { "needs-conversion", NULL, 0, 2, do_needs_conversion, OVS_RO },
    { "db-name", "[db]",  0, 1, do_db_name, OVS_RO },
    { "db-version", "[db]",  0, 1, do_db_version, OVS_RO },
    { "db-cksum", "[db]", 0, 1, do_db_cksum, OVS_RO },
    { "db-cid", "db", 1, 1, do_db_cid, OVS_RO },
    { "db-sid", "db", 1, 1, do_db_sid, OVS_RO },
    { "db-local-address", "db", 1, 1, do_db_local_address, OVS_RO },
    { "schema-name", "[schema]", 0, 1, do_schema_name, OVS_RO },
    { "schema-version", "[schema]", 0, 1, do_schema_version, OVS_RO },
    { "schema-cksum", "[schema]", 0, 1, do_schema_cksum, OVS_RO },
    { "query", "[db] trns", 1, 2, do_query, OVS_RO },
    { "transact", "[db] trns", 1, 2, do_transact, OVS_RO },
    { "show-log", "[db]", 0, 1, do_show_log, OVS_RO },
    { "check-cluster", "db...", 1, INT_MAX, do_check_cluster, OVS_RO },
    { "help", NULL, 0, INT_MAX, do_help, OVS_RO },
    { "list-commands", NULL, 0, INT_MAX, do_list_commands, OVS_RO },
    { NULL, NULL, 0, 0, NULL, OVS_RO },
};

static const struct ovs_cmdl_command *get_all_commands(void)
{
    return all_commands;
}
