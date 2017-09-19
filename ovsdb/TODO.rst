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

  * Figure out how ephemeral columns should be handled.

  * Anti-rollback: client won't accept an older version.

  * Causality: server receives data update and sends monitor update before it
    responds to an RPC.

  * Security for "convert".

  * ovsdb-client handling of clusters

  * Locks.

  * ovsdb-idl should listen for monitor_canceled and restart monitoring,
  or at least transition to S_ERROR, reconnect, etc.

  * Investigate 100% CPU for long-running triggers

  * Tons of unit tests.

* Documentation:

  * Upgrading OVN to a clustered database

  * Installing OVN with a clustered database

  * Overall diagram explaining the cluster and ovsdb protocol pieces

  * Move OVSDB protocol stuff to ovsdb-server.7?

* Future work:

  * File format with diff support. 

  * Future work: DNS or directory support
