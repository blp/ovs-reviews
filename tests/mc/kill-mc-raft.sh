#!/bin/bash
ps aux | grep 'raft-driver\|raft-client\|mc' | grep $(whoami) | grep -v 'emacs\|grep\|sh' | awk '{print $2}' | xargs kill -9 
rm -f *.db *.out *.ctl
