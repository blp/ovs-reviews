#include <config.h>

#include "openvswitch/vlog.h"
#include "ddlog.h"

VLOG_DEFINE_THIS_MODULE(controller_ddlog);

bool print_records_callback(uintptr_t arg, const ddlog_record *rec, ssize_t weight)
{
    (void) arg;
    (void) weight;

    char *record_as_string = ddlog_dump_record(rec);
    if (record_as_string == NULL) {
        VLOG_INFO("failed to dump record");
    }
    VLOG_INFO("DDlog record: %s", record_as_string);
    ddlog_string_free(record_as_string);

    return true;
}

void print_deltas_callback(uintptr_t arg, table_id table, const ddlog_record *rec, ssize_t weight)
{
    (void) arg;
    (void) weight;
    (void) table;

    char *record_as_string = ddlog_dump_record(rec);
    if (record_as_string == NULL) {
        VLOG_INFO("failed to dump delta");
    }
    VLOG_INFO("DDlog delta: %s", record_as_string);
    ddlog_string_free(record_as_string);
}

void init_ddlog(void) {
    ddlog_prog_global = ddlog_run(1, true, NULL, NULL);
    if (!ddlog_prog_global) {
        ovs_fatal(0, "Ddlog instance could not be created");
    }
}

void stop_ddlog(void) {
    ddlog_stop(ddlog_prog_global);
}
