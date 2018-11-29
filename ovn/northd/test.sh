#!/bin/sh

ovn_northd_ddlog/target/debug/ovn_northd_cli < ovn_northd.dat > ovn_northd.dump 2> ovn_northd.err
echo Running diff
diff ovn_northd.dump.expected ovn_northd.dump
