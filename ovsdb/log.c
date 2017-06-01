/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2017 Nicira, Inc.
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

#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "openvswitch/json.h"
#include "lockfile.h"
#include "ovsdb.h"
#include "ovsdb-error.h"
#include "sha1.h"
#include "socket-util.h"
#include "transaction.h"
#include "util.h"

enum ovsdb_log_mode {
    OVSDB_LOG_READ,
    OVSDB_LOG_WRITE
};

struct ovsdb_log {
    off_t prev_offset;
    off_t offset;
    char *rel_name;
    char *name;
    char *magic;
    struct lockfile *lockfile;
    FILE *stream;
    struct ovsdb_error *read_error;
    bool write_error;
    enum ovsdb_log_mode mode;
};

static bool parse_header(char *header, const char **magicp,
                         unsigned long int *length,
                         uint8_t sha1[SHA1_DIGEST_SIZE]);
static bool is_magic_ok(const char *needle, const char *haystack);

/* Attempts to open 'name' with the specified 'open_mode'.  On success, stores
 * the new log into '*filep' and returns NULL; otherwise returns NULL and
 * stores NULL into '*filep'.
 *
 * 'magic' is a short text string put at the beginning of every record and used
 * to distinguish one kind of log file from another.  For a conventional OVSDB
 * log file, use OVSDB_MAGIC.  To accept more than one magic string, separate
 * them with "|", e.g. "MAGIC 1|MAGIC 2".
 *
 * Whether the file will be locked using lockfile_lock() depends on 'locking':
 * use true to lock it, false not to lock it, or -1 to lock it only if
 * 'open_mode' is a mode that allows writing.
 */
struct ovsdb_error *
ovsdb_log_open(const char *name, const char *magic,
               enum ovsdb_log_open_mode open_mode,
               int locking, struct ovsdb_log **filep)
{
    struct lockfile *lockfile;
    struct ovsdb_error *error;
    char *abs_name;
    FILE *stream;
    int flags;
    int fd;

    /* If we can create a new file, we need to know what kind of magic to
     * use, so there must be only one kind. */
    if (open_mode == OVSDB_LOG_CREATE_EXCL || open_mode == OVSDB_LOG_CREATE) {
        ovs_assert(!strchr(magic, '|'));
    }

    *filep = NULL;

    /* Use the absolute name of the file because ovsdb-server opens its
     * database before daemonize() chdirs to "/". */
    char *deref_name = follow_symlinks(name);
    abs_name = abs_file_name(NULL, deref_name);
    free(deref_name);
    if (!name) {
        error = ovsdb_io_error(0, "could not determine current "
                              "working directory");
        goto error;
    }

    ovs_assert(locking == -1 || locking == false || locking == true);
    if (locking < 0) {
        locking = open_mode != OVSDB_LOG_READ_ONLY;
    }
    if (locking) {
        int retval = lockfile_lock(abs_name, &lockfile);
        if (retval) {
            error = ovsdb_io_error(retval, "%s: failed to lock lockfile",
                                   name);
            goto error;
        }
    } else {
        lockfile = NULL;
    }

    switch (open_mode) {
    case OVSDB_LOG_READ_ONLY:
        flags = O_RDONLY;
        break;

    case OVSDB_LOG_READ_WRITE:
        flags = O_RDWR;
        break;

    case OVSDB_LOG_CREATE_EXCL:
        flags = O_RDWR | O_CREAT | O_EXCL;
        break;

    case OVSDB_LOG_CREATE:
        flags = O_RDWR | O_CREAT;
        break;

    default:
        OVS_NOT_REACHED();
    }
#ifdef _WIN32
    flags = flags | O_BINARY;
#endif
    fd = open(abs_name, flags, 0666);
    if (fd < 0) {
        const char *op = (open_mode == OVSDB_LOG_CREATE_EXCL ? "create"
            : open_mode == OVSDB_LOG_CREATE ? "create or open"
            : "open");
        error = ovsdb_io_error(errno, "%s: %s failed", name, op);
        goto error_unlock;
    }

    stream = fdopen(fd, open_mode == OVSDB_LOG_READ_ONLY ? "rb" : "w+b");
    if (!stream) {
        error = ovsdb_io_error(errno, "%s: fdopen failed", name);
        close(fd);
        goto error_unlock;
    }

    /* Read the magic from the first log record. */
    char header[128];
    const char *actual_magic;
    if (!fgets(header, sizeof header, stream)) {
        if (ferror(stream)) {
            error = ovsdb_io_error(errno, "%s: read error", name);
            goto error_fclose;
        }

        /* We need to be able to report what kind of file this is but we can't
         * if it's empty and we accept more than one. */
        if (strchr(magic, '|')) {
            error = ovsdb_error(NULL, "%s: unexpected end of file", name);
            goto error_fclose;
        }
        actual_magic = magic;

        /* It's an empty file and therefore probably a new file, so fsync()
         * its parent directory to ensure that its directory entry is
         * committed to disk. */
        fsync_parent_dir(abs_name);
    } else {
        unsigned long int length;
        uint8_t sha1[SHA1_DIGEST_SIZE];
        if (!parse_header(header, &actual_magic, &length, sha1)
            || !is_magic_ok(actual_magic, magic)) {
            error = ovsdb_error(NULL, "%s: unexpected file format", name);
            goto error_fclose;
        }
    }

    if (fseek(stream, 0, SEEK_SET)) {
        error = ovsdb_io_error(errno, "%s: seek failed", name);
        goto error_fclose;
    }

    struct ovsdb_log *file = xmalloc(sizeof *file);
    file->name = abs_name;
    file->rel_name = xstrdup(name);
    file->magic = xstrdup(actual_magic);
    file->lockfile = lockfile;
    file->stream = stream;
    file->prev_offset = 0;
    file->offset = 0;
    file->read_error = NULL;
    file->write_error = false;
    file->mode = OVSDB_LOG_READ;
    *filep = file;
    return NULL;

error_fclose:
    fclose(stream);
error_unlock:
    lockfile_unlock(lockfile);
error:
    free(abs_name);
    return error;
}

/* Returns true if 'needle' is one of the |-delimited words in 'haystack'. */
static bool
is_magic_ok(const char *needle, const char *haystack)
{
    /* 'needle' can't be multiple words. */
    if (strchr(needle, '|')) {
        return false;
    }

    size_t n = strlen(needle);
    for (;;) {
        if (!strncmp(needle, haystack, n) && strchr("|", haystack[n])) {
            return true;
        }
        haystack = strchr(haystack, '|');
        if (!haystack) {
            return false;
        }
        haystack++;
    }
}

void
ovsdb_log_close(struct ovsdb_log *file)
{
    if (file) {
        free(file->name);
        free(file->rel_name);
        free(file->magic);
        if (file->stream) {
            fclose(file->stream);
        }
        lockfile_unlock(file->lockfile);
        ovsdb_error_destroy(file->read_error);
        free(file);
    }
}

const char *
ovsdb_log_get_name(const struct ovsdb_log *log)
{
    return log->rel_name;
}

const char *
ovsdb_log_get_magic(const struct ovsdb_log *log)
{
    return log->magic;
}

static bool
parse_header(char *header, const char **magicp,
             unsigned long int *length, uint8_t sha1[SHA1_DIGEST_SIZE])
{
    /* 'header' must consist of "OVSDB "... */
    const char lead[] = "OVSDB ";
    if (strncmp(lead, header, strlen(lead))) {
        return false;
    }

    /* ...followed by a magic string... */
    char *magic = header + strlen(lead);
    size_t magic_len = strcspn(magic, " ");
    if (magic[magic_len] != ' ') {
        return false;
    }
    magic[magic_len] = '\0';
    *magicp = magic;

    /* ...followed by a length in bytes... */
    char *p;
    *length = strtoul(magic + magic_len + 1, &p, 10);
    if (!*length || *length == ULONG_MAX || *p != ' ') {
        return false;
    }
    p++;

    /* ...followed by a SHA-1 hash... */
    if (!sha1_from_hex(sha1, p)) {
        return false;
    }
    p += SHA1_HEX_DIGEST_LEN;

    /* ...and ended by a new-line. */
    if (*p != '\n') {
        return false;
    }

    return true;
}

static struct ovsdb_error *
parse_body(struct ovsdb_log *file, off_t offset, unsigned long int length,
           uint8_t sha1[SHA1_DIGEST_SIZE], struct json **jsonp)
{
    struct json_parser *parser;
    struct sha1_ctx ctx;

    sha1_init(&ctx);
    parser = json_parser_create(JSPF_TRAILER);

    while (length > 0) {
        char input[BUFSIZ];
        int chunk;

        chunk = MIN(length, sizeof input);
        if (fread(input, 1, chunk, file->stream) != chunk) {
            json_parser_abort(parser);
            return ovsdb_io_error(ferror(file->stream) ? errno : EOF,
                                  "%s: error reading %lu bytes "
                                  "starting at offset %lld", file->rel_name,
                                  length, (long long int) offset);
        }
        sha1_update(&ctx, input, chunk);
        json_parser_feed(parser, input, chunk);
        length -= chunk;
    }

    sha1_final(&ctx, sha1);
    *jsonp = json_parser_finish(parser);
    return NULL;
}

/* Attempts to read a log record from 'file'.
 *
 * If successful, returns NULL and stores in '*jsonp' the JSON object that the
 * record contains.  The caller owns the data and must eventually free it (with
 * json_destroy()).
 *
 * If a read error occurs, returns the error and stores NULL in '*jsonp'.
 *
 * If the read reaches end of file, returns NULL and stores NULL in
 * '*jsonp'. */
struct ovsdb_error *
ovsdb_log_read(struct ovsdb_log *file, struct json **jsonp)
{
    uint8_t expected_sha1[SHA1_DIGEST_SIZE];
    uint8_t actual_sha1[SHA1_DIGEST_SIZE];
    struct ovsdb_error *error;
    unsigned long data_length;
    struct json *json;
    char header[128];

    *jsonp = json = NULL;

    if (file->read_error) {
        return ovsdb_error_clone(file->read_error);
    } else if (file->mode == OVSDB_LOG_WRITE) {
        return OVSDB_BUG("reading file in write mode");
    }

    if (!fgets(header, sizeof header, file->stream)) {
        if (feof(file->stream)) {
            error = NULL;
        } else {
            error = ovsdb_io_error(errno, "%s: read failed", file->rel_name);
        }
        goto error;
    }
    off_t data_offset = file->offset + strlen(header);

    const char *magic;
    if (!parse_header(header, &magic, &data_length, expected_sha1)
        || strcmp(magic, file->magic)) {
        error = ovsdb_syntax_error(NULL, NULL, "%s: parse error at offset "
                                   "%lld in header line \"%.*s\"",
                                   file->rel_name,
                                   (long long int) file->offset,
                                   (int) strcspn(header, "\n"), header);
        goto error;
    }

    error = parse_body(file, data_offset, data_length, actual_sha1, &json);
    if (error) {
        goto error;
    }

    if (memcmp(expected_sha1, actual_sha1, SHA1_DIGEST_SIZE)) {
        error = ovsdb_syntax_error(NULL, NULL, "%s: %lu bytes starting at "
                                   "offset %lld have SHA-1 hash "SHA1_FMT" "
                                   "but should have hash "SHA1_FMT,
                                   file->rel_name, data_length,
                                   (long long int) data_offset,
                                   SHA1_ARGS(actual_sha1),
                                   SHA1_ARGS(expected_sha1));
        goto error;
    }

    if (json->type == JSON_STRING) {
        error = ovsdb_syntax_error(NULL, NULL, "%s: %lu bytes starting at "
                                   "offset %lld are not valid JSON (%s)",
                                   file->rel_name, data_length,
                                   (long long int) data_offset,
                                   json->u.string);
        goto error;
    }
    if (json->type != JSON_OBJECT) {
        error = ovsdb_syntax_error(NULL, NULL, "%s: %lu bytes starting at "
                                   "offset %lld are not a JSON object",
                                   file->rel_name, data_length,
                                   (long long int) data_offset);
        goto error;
    }

    file->prev_offset = file->offset;
    file->offset = data_offset + data_length;
    *jsonp = json;
    return NULL;

error:
    file->read_error = ovsdb_error_clone(error);
    json_destroy(json);
    return error;
}

/* Causes the log record read by the previous call to ovsdb_log_read() to be
 * effectively discarded.  The next call to ovsdb_log_write() will overwrite
 * that previously read record.
 *
 * Calling this function more than once has no additional effect.
 *
 * This function is useful when ovsdb_log_read() successfully reads a record
 * but that record does not make sense at a higher level (e.g. it specifies an
 * invalid transaction). */
void
ovsdb_log_unread(struct ovsdb_log *file)
{
    ovs_assert(file->mode == OVSDB_LOG_READ);
    file->offset = file->prev_offset;
}

static struct ovsdb_error *
ovsdb_log_truncate(struct ovsdb_log *file)
{
    file->mode = OVSDB_LOG_WRITE;

    struct ovsdb_error *error = NULL;
    if (fseeko(file->stream, file->offset, SEEK_SET)) {
        error = ovsdb_io_error(errno, "%s: cannot seek to offset %lld",
                               file->rel_name, (long long int) file->offset);
    } else if (ftruncate(fileno(file->stream), file->offset)) {
        error = ovsdb_io_error(errno, "%s: cannot truncate to length %lld",
                               file->rel_name, (long long int) file->offset);
    }
    file->write_error = error != NULL;
    return error;
}

struct ovsdb_error *
ovsdb_log_write(struct ovsdb_log *file, const struct json *json)
{
    uint8_t sha1[SHA1_DIGEST_SIZE];
    struct ovsdb_error *error;
    char *json_string;
    char header[128];
    size_t length;

    json_string = NULL;

    if (file->mode == OVSDB_LOG_READ || file->write_error) {
        error = ovsdb_log_truncate(file);
        if (error) {
            goto error;
        }
    }

    if (json->type != JSON_OBJECT && json->type != JSON_ARRAY) {
        error = OVSDB_BUG("bad JSON type");
        goto error;
    }

    /* Compose content.  Add a new-line (replacing the null terminator) to make
     * the file easier to read, even though it has no semantic value.  */
    json_string = json_to_string(json, 0);
    length = strlen(json_string) + 1;
    json_string[length - 1] = '\n';

    /* Compose header. */
    sha1_bytes(json_string, length, sha1);
    snprintf(header, sizeof header, "OVSDB %s %"PRIuSIZE" "SHA1_FMT"\n",
             file->magic, length, SHA1_ARGS(sha1));

    /* Write. */
    if (fwrite(header, strlen(header), 1, file->stream) != 1
        || fwrite(json_string, length, 1, file->stream) != 1
        || fflush(file->stream))
    {
        error = ovsdb_io_error(errno, "%s: write failed", file->rel_name);

        /* Remove any partially written data, ignoring errors since there is
         * nothing further we can do. */
        ignore(ftruncate(fileno(file->stream), file->offset));

        goto error;
    }

    file->offset += strlen(header) + length;
    free(json_string);
    return NULL;

error:
    file->write_error = true;
    free(json_string);
    return error;
}

struct ovsdb_error *
ovsdb_log_commit(struct ovsdb_log *file)
{
    if (fsync(fileno(file->stream))) {
        return ovsdb_io_error(errno, "%s: fsync failed", file->rel_name);
    }
    return NULL;
}

/* Returns the current offset into the file backing 'log', in bytes.  This
 * reflects the number of bytes that have been read or written in the file.  If
 * the whole file has been read, this is the file size. */
off_t
ovsdb_log_get_offset(const struct ovsdb_log *log)
{
    return log->offset;
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_log_replace_start(struct ovsdb_log *old,
                        struct ovsdb_log **newp)
{
    char *tmp_name = xasprintf("%s.tmp", old->rel_name);
    struct ovsdb_error *error;

    ovs_assert(old->lockfile);

    /* Remove temporary file.  (It might not exist.) */
    if (unlink(tmp_name) < 0 && errno != ENOENT) {
        error = ovsdb_io_error(errno, "failed to remove %s", tmp_name);
        free(tmp_name);
        *newp = NULL;
        return error;
    }

    /* Create temporary file. */
    error = ovsdb_log_open(tmp_name, old->magic, OVSDB_LOG_CREATE_EXCL,
                           false, newp);
    if (error) {
        free(tmp_name);
        *newp = NULL;
    }
    return error;
}

struct ovsdb_error * OVS_WARN_UNUSED_RESULT
ovsdb_log_replace_commit(struct ovsdb_log *old, struct ovsdb_log *new)
{
    struct ovsdb_error *error = ovsdb_log_commit(new);
    if (error) {
        ovsdb_log_close(new);
        return error;
    }

    /* Replace old file by new file on-disk. */
    if (rename(new->name, old->name)) {
        error = ovsdb_io_error(errno, "failed to rename \"%s\" to \"%s\"",
                               new->name, old->name);
        ovsdb_log_close(new);
        return error;
    }
    fsync_parent_dir(old->name);

    /* Replace 'old' by 'new' in memory.
     *
     * 'old' transitions to OVSDB_LOG_WRITE (it was probably in that mode
     * anyway). */
    /* prev_offset only matters for OVSDB_LOG_READ. */
    old->offset = new->offset;
    /* Keep old->name and old->rel_name. */
    free(old->magic);
    old->magic = new->magic;
    new->magic = NULL;
    /* Keep old->lockfile. */
    fclose(old->stream);
    old->stream = new->stream;
    new->stream = NULL;
    /* read_error only matters for OVSDB_LOG_READ. */
    old->write_error = new->write_error;
    old->mode = OVSDB_LOG_WRITE;

    /* Free 'new'. */
    ovsdb_log_close(new);

    return NULL;
}

void
ovsdb_log_replace_abort(struct ovsdb_log *new)
{
    if (new) {
        /* Unlink the new file, but only after we close it (for Windows
         * compatibility). */
        char *name = xstrdup(new->name);
        ovsdb_log_close(new);
        unlink(name);
        free(name);
    }
}
