#!/bin/bash

export OVS_RUNDIR=$PWD
export PATH=$PATH:$PWD

./mc raft-config.json
