#! /bin/sh -x
rm -f s?.db
rm -f s?.log
export OVS_RUNDIR=$PWD
schema=ovn/ovn-sb.ovsschema
schema_name=`ovsdb/ovsdb-tool schema-name $schema`

ovsdb/ovsdb-tool create-cluster s1.db $schema unix:s1.raft
ovsdb/ovsdb-tool join-cluster s2.db $schema_name unix:s2.raft unix:s1.raft
ovsdb/ovsdb-tool join-cluster s3.db $schema_name unix:s3.raft unix:s1.raft
ovsdb/ovsdb-tool join-cluster s4.db $schema_name unix:s3.raft unix:s1.raft

xterm -geometry 80x25-0+0 -T 1 -e ovsdb/ovsdb-server --log-file=s1.log --pidfile=s1.pid --unixctl=s1 --remote=punix:s1.ovsdb s1.db &
xterm -geometry 80x25-0+350 -T 2 -e ovsdb/ovsdb-server --log-file=s2.log --pidfile=s2.pid --unixctl=s2 --remote=punix:s2.ovsdb s2.db &
xterm -geometry 80x25-0+700 -T 3 -e ovsdb/ovsdb-server --log-file=s3.log --pidfile=s3.pid --unixctl=s3 --remote=punix:s3.ovsdb s3.db &

read line

xterm -geometry 80x25-490+0 -T 4 -e ovsdb/ovsdb-server --log-file=s4.log --pidfile=s4.pid --unixctl=s4 --remote=punix:s4.ovsdb s4.db &

wait
