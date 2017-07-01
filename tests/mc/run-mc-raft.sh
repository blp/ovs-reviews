#!/bin/bash

export OVS_RUNDIR=$PWD
export PATH=$PATH:$PWD
kill-mc-raft.sh
schema=../../ovn/ovn-sb.ovsschema
schema_name=`../../ovsdb/ovsdb-tool schema-name $schema`
../../ovsdb/ovsdb-tool create-cluster s1.db $schema tcp:127.0.0.1:6641
../../ovsdb/ovsdb-tool join-cluster s2.db $schema_name tcp:127.0.0.1:6642 tcp:127.0.0.1:6641
../../ovsdb/ovsdb-tool join-cluster s3.db $schema_name tcp:127.0.0.1:6643 tcp:127.0.0.1:6642

./mc raft-config.json
