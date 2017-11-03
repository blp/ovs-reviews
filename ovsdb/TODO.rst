..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

===========================
OVSDB Clustering To-do List
===========================

* Minimal requirements for features and bug fixes:

  * Locks.

  * Investigate 100% CPU for long-running triggers

  * Tons of unit tests.

  * Increase exponential backoff cap.  Introduce randomization.

  * Include index with monitor update?

  * Back off when transaction fails to commit?  Definitely back off until
    the eid changes for prereq failures

  * Testing with replication.

  * Handling bad transactions in read_db().  (Kill the database?)

* Documentation:

  * ACID (and CAP?) explanation.

  * Upgrading OVN to a clustered database

  * Installing OVN with a clustered database

  * Overall diagram explaining the cluster and ovsdb protocol pieces

  * commit_index and leader in disk format

* Future work:

  * File format with diff support. 

  * Future work: DNS or directory support

From Numan Siddique::

  1) As I had mentioned in the IRC meeting yesterday, when I pass the options
  "--remote=db:OVN_Northbound,NB_Global,connections" to ovsdb-server, it is
  failing with the error
  "ovsdb-server: "db:OVN_Northbound,NB_Global,connections": no table named
  NB_Global".

  I see this issue when I freshly create the database file (ovsdb-tool
  create-cluster ovnnb.db OVN_Northbound local_addr remote_addr" and start
  ovsdb-server) and start the ovsdb-server.

  This issue is not seen if the ovsdb-server has already connected to the
  remote and the above option is passed in subsequent runs.


  b) I am seeing an issue when I run  "ovn-nbctl ls-add sw2". It hangs.

  I created a 2 node cluster - node 1 and node 2
   When I run "ovn-nbctl ls-add sw2" it hangs. Here are the steps
     1. On node 1 created a clustered db and started ovsdb-server
       (/usr/share/openvswitch/scripts/ovn-ctl start_ovsdb
  --db-nb-cluster-local-addr=tcp:192.168.121.91:6643
  --db-sb-cluster-local-addr=tcp:192.168.121.91:6644)
     2. Created a logical switch "ovn-nbctl ls-add sw0"

     3. On node 2, started ovsdb-servers as
       /usr/share/openvswitch/scripts/ovn-ctl start_ovsdb
  --db-nb-cluster-local-addr=tcp:192.168.121.87:6643
  --db-sb-cluster-local-addr=tcp:192.168.121.87:6644
  --db-nb-cluster-remote-addr=tcp:192.168.121.91:6643
  --db-sb-cluster-remote-addr=tcp:192.168.121.91:6644

    4. "ovn-nbctl show" works fine. Ran "ovn-nbctl ls-add sw1" and it worked
  fine.

    5. Stop ovsdb-server - /usr/share/openvswitch/scripts/ovn-ctl stop_ovsdb

    6. Start again and when I run "ovn-nbctl ls-add sw2" it hangs.
     You can find the logs of ovsdb-server for node 2 here -
  https://paste.fedoraproject.org/paste/xp~8lxdoq52TO28NbGoQbg

     and node 1 here -
  https://paste.fedoraproject.org/paste/~J4rG9H36GWWWav98N5KaQ


