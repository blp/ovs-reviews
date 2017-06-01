#! /bin/sh -ex
rm -f s1.db s2.db s3.db
export OVS_RUNDIR=$PWD
schema=../ovn/ovn-sb.ovsschema
schema_name=`ovsdb/ovsdb-tool schema-name $schema`
ovsdb/ovsdb-tool create-cluster s1.db $schema tcp:127.0.0.1:6641
ovsdb/ovsdb-tool join-cluster s2.db $schema_name tcp:127.0.0.1:6642 tcp:127.0.0.1:6641
ovsdb/ovsdb-tool join-cluster s3.db $schema_name tcp:127.0.0.1:6643 tcp:127.0.0.1:6642

xterm -geometry 132x25-0+0 -T 1 -e valgrind ovsdb/ovsdb-server s1.db --remote=punix:db1.sock &
xterm -geometry 132x25-0+350 -T 2 -e valgrind ovsdb/ovsdb-server s2.db --remote=punix:db2.sock &
xterm -geometry 132x25-0+700 -T 3 -e valgrind ovsdb/ovsdb-server s3.db --remote=punix:db3.sock &
wait
