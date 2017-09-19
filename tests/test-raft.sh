#! /bin/sh -ex
rm -f s1.db s2.db s3.db
export OVS_RUNDIR=$PWD
schema=../ovn/ovn-sb.ovsschema
schema_name=`ovsdb/ovsdb-tool schema-name $schema`
ovsdb/ovsdb-tool create-cluster s1.db $schema unix:s1.sock
ovsdb/ovsdb-tool join-cluster s2.db $schema_name unix:s2.sock unix:s1.sock
ovsdb/ovsdb-tool join-cluster s3.db $schema_name unix:s3.sock unix:s1.sock

xterm -geometry 132x25-0+0 -T 1 -e tests/test-raft s1.db &
xterm -geometry 132x25-0+350 -T 2 -e tests/test-raft s2.db &
xterm -geometry 132x25-0+700 -T 3 -e tests/test-raft s3.db &
wait
