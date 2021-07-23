#ifndef OVN_DDLOG_H
#define OVN_DDLOG_H 1

#include <stddef.h>

#include "util.h"
#include "controller/ovn_controller_ddlog/ddlog.h"

#define DDLOG_PROG  (ddlog_prog_global)

// the ddlog instance for ovn-controller, initialized in ovn-controller main()
ddlog_prog ddlog_prog_global;

void init_ddlog(void);
void stop_ddlog(void);

bool print_records_callback(uintptr_t arg, const ddlog_record *rec, ssize_t weight);
void print_deltas_callback(uintptr_t arg, table_id table, const ddlog_record *rec, ssize_t weight);

#endif
