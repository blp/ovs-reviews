#! /bin/sh -ex

export OVS_RUNDIR=$PWD
export OVN_SB_DB=unix:s1.ovsdb,unix:s2.ovsdb,unix:s3.ovsdb
PATH=$PATH:$PWD/ovn/utilities
for i in `seq 0 9`; do
    for j in `seq 5`; do
	echo "$i-$j=$i-$j" >> expected
    done
done > expected
for i in `seq 0 9`; do
    (for j in `seq 5`; do
	 ovn-sbctl -voff add SB_Global . external_ids $i-$j=$i-$j
     done)&
done
sleep 5
kill `cat s3.pid` || true
wait
ovn-sbctl --bare get SB_Global . external-ids | sed 's/, /\n/g; s/[{}"]//g;' > output
if diff -u expected output; then
    echo "success"
fi
