#! /bin/sh -ex

export OVS_RUNDIR=$PWD
export OVN_SB_DB=unix:s1.ovsdb,unix:s2.ovsdb,unix:s3.ovsdb
PATH=$PATH:$PWD/ovn/utilities
#ovn-sbctl init
for i in `seq 10`; do
    (for j in `seq 5`; do
	 ovn-sbctl -voff add SB_Global . external_ids $i-$j=$i-$j
    done)&
done
wait
ovn-sbctl list sb_global
