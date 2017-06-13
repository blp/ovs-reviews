#! /bin/sh -ex
rm -f s1.db s2.db s3.db
export OVS_RUNDIR=$PWD
schema=ovn/ovn-sb.ovsschema
schema_name=`ovsdb/ovsdb-tool schema-name $schema`
ovsdb/ovsdb-tool create-cluster s1.db $schema tcp:127.0.0.1:6641
valgrind ovsdb/ovsdb-server s1.db --remote=punix:db.sock &
read line
kill $!
wait
valgrind ovsdb/ovsdb-server s1.db --remote=punix:db.sock

