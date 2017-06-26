#! /bin/sh -ex
rm -f s1.db s2.db s3.db
export OVS_RUNDIR=$PWD
schema=../../ovn/ovn-sb.ovsschema
schema_name=`../../ovsdb/ovsdb-tool schema-name $schema`
../../ovsdb/ovsdb-tool create-cluster s1.db $schema tcp:127.0.0.1:6641
../../ovsdb/ovsdb-tool join-cluster s2.db $schema_name tcp:127.0.0.1:6642 tcp:127.0.0.1:6641
../../ovsdb/ovsdb-tool join-cluster s3.db $schema_name tcp:127.0.0.1:6643 tcp:127.0.0.1:6642

xterm -geometry 132x25-0+0 -T 1 -e ./raft-driver --unixctl=raft1.ctl s1.db &
xterm -geometry 132x25-0+350 -T 2 -e ./raft-driver --unixctl=raft2.ctl s2.db &
xterm -geometry 132x25-0+700 -T 3 -e ./raft-driver --unixctl=raft3.ctl s3.db &
sleep 2

./raft-client raft1.ctl &
./raft-client raft2.ctl &
wait
