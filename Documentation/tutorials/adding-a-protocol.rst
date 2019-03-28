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

=======================
Adding Protocol Support
=======================

Researchers and others frequently want to make Open vSwitch support a new
protocol (either a standard protocol or one that they have invented for an
experiment) or to make Open vSwitch support matching or updating some new field
in an existing protocol.  This tutorial gives an example of adding a new
fictitious protocol.  By the time you try to follow along, it's possible that
these instructions will not be exactly correct, but they are still likely to
give you the core information you need to succeed.

The Open vSwitch FAQ, in :doc:`/faq/contributing`, also has some information on
how to add support for a new field or protocol.  This tutorial is much more
detailed.

To get the most out of this document, you should understand basic OpenFlow
concepts, have spent a little time reading up on Open vSwitch and playing with
it, and be comfortable with C programming.

Here is an outline of how we will proceed:

1. Describe "dLAN", the protocol that we will implement.

2. Add support for matching on dLAN and modifying the dLAN ID to OVS userspace.
   As a side effect, this adds support for these features in the OVS userspace
   datapath (aka the DPDK datapath).

3. Add dLAN support to the OVS Linux kernel module.  If you do not plan to use
   the OVS Linux kernel datapath, you can skip this step in your own work.

4. Add OpenFlow actions for pushing and popping dLAN headers to OVS userspace
   and the userspace datapath.

5. Add dLAN push and pop support to the OVS Linux kernel module.  Again, you
   can skip this in your own work if you do not plan to use the OVS Linux
   kernel datapath.

Before You Start
----------------

Refer to :doc:`/intro/install/general` for the basics of retrieving and
building OVS.  The following is a brief summary.

Install the required build tools.  GCC, OpenSSL and its development libraries,
Autoconf, Automake, libtool, and sparse are a good place to start.  For
example, on Debian and its derived distributions::

  $ sudo apt-get install gcc openssl libssl-dev autoconf automake libtool

Then clone the Open vSwitch Git repository::

  $ git clone https://github.com/openvswitch/ovs.git
  $ cd ovs

The Git master branch is usually stable.  Alternatively, you may choose to work
from a release branch, e.g.::

  $ git checkout origin/branch-2.11

Then run ``boot.sh`` to create the ``configure`` script::

  $ ./boot.sh

Configure the build tree appropriately.  For developers, ``--enable-Werror``
and ``--enable-sparse`` are a good way to ensure that you're not missing
important problems (use ``--enable-sparse`` only if you installed ``sparse``).
You can add any other options that are suitable for your environment or your
preferences::

  $ ./configure --enable-Werror --enable-sparse.

Our Protocol
------------

The protocol that we will make OVS support is called "dLAN".  A dLAN header, if
it is present, has the following form::

    0           16          32
    +------------+-----------+
    |  dLAN ID   | Ethertype |
    +------------+-----------+

That is, a dLAN header consists of a 16-bit dLAN ID followed by a 16-bit
Ethernet type.  The dLAN ID is arbitrary.  The Ethertype specifies the protocol
that follows the dLAN header; for example, it might be 0x86dd if IPv6 follows
the dLAN header.

dLAN itself uses Ethertype 0xdddd.

dLAN goes after the Ethernet header and, if present, the VLAN headers.  We will
implement support for only a single dLAN header, although in theory one could
stack them.

There is another way that one can look at the dLAN header that in some cases
makes it easier to think about (the same thing goes for VLAN headers).  This
way looks at it in terms of what must be inserted into an existing packet to
add a dLAN to it.  One inserts, following the source and destination Ethernet
addresses, the following::

    0          16          32
    +-----------+-----------+
    | Ethertype |  dLAN ID  |
    +-----------+-----------+
        0xdddd

We will make a simplifying assumption that a dLAN ID of 0 is invalid and must
not appear on the wire.

Adding dLAN ID to ``struct flow``
---------------------------------

Packet processing in Open vSwitch has the following steps:

1. Extract all the fields understood by OVS into a "flow" structure.
2. Look up the flow in the flow table, yielding a flow entry.
3. Execute the flow entry's actions.

Thus, for a protocol or a header to have any bearing on packet processing, OVS
must be able to understand and extract it in step 1.  Our first step is to add
the field to the data structure that represents a (micro)flow, which is
``struct flow``, defined in ``include/openvswitch/flow.h``.  (There is also a
file named ``flow.h`` in the ``lib`` directory, but it is not relevant here.)

``struct flow`` is divided in sections for metadata fields, L2 fields, L3
fields, and L4 fields.  A new field should ordinarily go in the section
corresponding to its type.  This is not a correctness issue--OVS will still
function regardless of where it is put--but it can be a performance issue due
to "staged lookup", which is a classifier optimization described in the large
comment in ``lib/classifier.h`` and in [OVS-DESIGN]_.

.. [OVS-DESIGN] B. Pfaff, J. Pettit, T. Koponen, E. J. Jackson, A. Zhou,
   J. Rajahalme, J. Gross, A. Wang, J. Stringer, P. Shelar, K. Amidon,
   M. Casado, “The Design and Implementation of Open vSwitch.”  In USENIX
   NSDI. 2015. `PDF
   <https://www.usenix.org/system/files/conference/nsdi15/nsdi15-paper-pfaff.pdf>`_.

dLAN is an L2 header, so we should insert it in the L2 section of ``struct
flow``.  Initially, that section looks like this::

    /* L2, Order the same as in the Ethernet header! (64-bit aligned) */
    struct eth_addr dl_dst;     /* Ethernet destination address. */
    struct eth_addr dl_src;     /* Ethernet source address. */
    ovs_be16 dl_type;           /* Ethernet frame type.
                                   Note: This also holds the Ethertype for L3
                                   packets of type PACKET_TYPE(1, Ethertype) */
    uint8_t pad1[2];            /* Pad to 64 bits. */
    union flow_vlan_hdr vlans[FLOW_MAX_VLAN_HEADERS]; /* VLANs */
    ovs_be32 mpls_lse[ROUND_UP(FLOW_MAX_MPLS_LABELS, 2)]; /* MPLS label stack
                                                             (with padding). */

Inserting our field has at least the following considerations:

* We need to ensure that code examining the flow structure can tell whether the
  field is present.  In our case, a dLAN ID of 0 is invalid, so we can use that
  value to mean "no dLAN header present".  If every dLAN ID were possible, then
  we would have to introduce an extra flag to indicate whether a header was
  present.

* It is easier to write the code to parse flows if the structure members are
  ordered in the structure the same way as in a packet.  In this case, this
  means that the dLAN ID should go after ``dl_type`` and before ``vlans``.

* Each section of ``struct flow`` must be a multiple of 64 bits in length.  If
  the changes you make increase the length of the section, be sure to add or
  adjust padding to maintain its length as a 64-bit multiple.

We are very lucky: we need 16 bits right after ``dl_type``, and there happens
to be a 16-bit padding field there already.  We can replace it by our dLAN ID,
removing ``pad1`` and replacing it by this::

    ovs_be16 dlan_id;           /* dLAN ID (zero if no dLAN present). */

.. note::

   We used ``ovs_be16`` because we plan to process the dLAN ID in network byte
   order.  OVS uses ``ovs_be<N>`` as big-endian types.  Each of these types is
   a ``typedef`` to ``uint<N>_t``.  If you install ``sparse``, as recommended
   in `Before You Start`_, it will report many kinds of byte-order errors at
   compile time,

Finding Places to Fix
---------------------

If you run ``make`` now, most of OVS will be rebuilt, but since we just
replaced a padding field by our new field, nothing functional will change.  The
way to proceed in most software would be to laboriously chase down all of the
places we need to update.  Open vSwitch has some features in the code to make
this easier, the ``FLOW_WC_SEQ`` macro in ``include/openvswitch/flow.h``.  It's
defined like this::

    /* This sequence number should be incremented whenever anything involving
     * flows or the wildcarding of flows changes.  This will cause build
     * assertion failures in places which likely need to be updated. */
    #define FLOW_WC_SEQ 41

Since we modified the flow structure, we should change ``FLOW_WC_SEQ``.  The
particular value doesn't matter, so long as it's different, but it's customary
to increment it, like this::

    #define FLOW_WC_SEQ 42 /* The Answer to the Ultimate Question of Life,
                            * the Universe, and Networking. */

Now, if we run ``make``, we'll get a slew of compiler errors.  Each of these
points to a place where the code might need to be changed to make OVS work
properly with our new field.

Updating ``flow.h``
-------------------

Two of the compiler errors are in ``flow.h`` itself, which means that these get
reported for every single ``.c`` file that ``make`` rebuilds.  That's super
annoying, so we should address these first.

The first of them is for the following code::

    /* Remember to update FLOW_WC_SEQ when changing 'struct flow'. */
    BUILD_ASSERT_DECL(offsetof(struct flow, igmp_group_ip4) + sizeof(uint32_t)
                      == sizeof(struct flow_tnl) + sizeof(struct ovs_key_nsh) + 300
                      && FLOW_WC_SEQ == 41);

This is just a way to remind the programmer to update ``FLOW_WC_SEQ`` when
changing ``struct flow``.  If we had changed the size of ``struct flow``, then
it would have triggered as soon as we had done that.  It doesn't otherwise
point to anything we need to update, so we can just change the assertion to use
our new value of ``FLOW_WC_SEQ``::

    ...
                      && FLOW_WC_SEQ == 42);

The second is in the inline function ``pkt_metadata_from_flow()``.  This
function copies metadata (such as the OpenFlow input port ``in_port``) from a
flow into a structure that only carries metadata.  It checks ``FLOW_WC_SEQ`` in
a way that will soon seem familiar::

    /* Update this function whenever struct flow changes. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 41);

Our new field ``dlan_id`` is an L2 data field, not metadata, so we do not need
to update anything in this function other than the assertion itself::

    /* Update this function whenever struct flow changes. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

(Not) Updating ``odp-util.h``
-----------------------------

The header ``odp-util.h``, which is also widely used, has a compiler error too
by the definition of ``ODPUTIL_FLOW_KEY_BYTES``.  To update this definition
properly, we need some concepts we haven't learned yet and that are not quite
ripe.  For now, Let's just update its assertion from::

    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 41);

to::

    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42); /* XXX */

This will suppress the widespread errors, and we can plan to come back to it
later.

(It's not that important to update ``ODPUTIL_FLOW_KEY_BYTES`` anyhow: it just
needs to be big enough, and for adding a single small field it will be big
enough already.)

Updating ``flow.c``
-------------------

The file ``lib/flow.c``, as one might guess, has lots of functions for dealing
with flows, and some of those are flagged for updates.  Before we can do an
effective job updating them, we need to understand a few more concepts.

Flow Matches: ``struct match``
++++++++++++++++++++++++++++++

First is the concept of a "match", represented by ``struct match``.  Whereas
``struct flow`` represents the fields in a microflow (or a packet), ``struct
match`` represents the match part of an OpenFlow flow.  It does this by pairing
two ``struct flow`` data structures, one of which is the microflow and the
other is a bitwise mask in which a 1-bit indicates that the corresponding
microflow bit is to be matched and a 0-bit indicates a "don't-care".

For example:

* If ``nw_dst`` is 0x0a000000 (10.0.0.0) in the microflow and 0xffffffff
  (255.255.255.255) in the mask, then the ``struct match`` matches on exact IP
  destination 10.0.0.0.

* If ``nw_dst`` is 0x0a000000 (10.0.0.0) in the microflow and 0xff000000
  (255.0.0.0) in the mask, then the ``struct match`` matches on IP subnet
  destination 10.0.0.0/255.0.0.0.

``struct match`` is actually defined as follows, where ``flow`` is the
microflow and ``wc``, which stands for "wildcards", is the mask.  The
``tun_md`` member is only relevant if you are working with Geneve or NSH TLVs::

    struct match {
        struct flow flow;
        struct flow_wildcards wc;
        struct tun_metadata_allocation tun_md;
    };

Possibly you noticed that ``wc`` is not a plain ``struct flow`` but instead a
``struct flow_wildcards``.  This structure, in turn, is just a wrapper around
``struct flow``.  It exists only for documentation purposes, so that when a
struct of this type is used in an interface or a structure it is clear that it
is being used as a mask rather than as a microflow::

    struct flow_wildcards {
        struct flow masks;
    };

Compressed Flows: ``struct miniflow``
+++++++++++++++++++++++++++++++++++++

The other relevant concept is ``struct miniflow``.  This need for this
structure arises because ``struct flow`` is relatively large (672 bytes, as of
this writing) and thus ``struct match`` over twice as large.  In contexts where
we might need many flows or matches, such as for representing an OpenFlow flow
table that can have millions of flows, the size itself is limiting.  Also, for
``struct match``, it is expensive to figure out whether a given packet matches
the structure because that requires looking at every byte in the mask.

``struct miniflow`` (and ``struct minimatch``) exists to solve these problems.
It is a kind of compressed version of ``struct flow`` (and ``struct match``)
that omits all-zero doublewords.  Most flow and match structures are very
sparse, so this is effective compression.  It is not necessary to understand
all the details of the compression, but you can look up its definition in
``lib/flow.h`` if you want to know more.

Despite their advantages, it is less convenient to work with the
mini-structures, so the full-size versions remain in use for many purposes.

miniflow_extract()
++++++++++++++++++



flow_get_metadata()
+++++++++++++++++++

flow_get_metadata(): "match" concept, metadata only

flow_wildcards_init_for_packet(): "match" concept

flow_wc_map(): "flowmap" (and "miniflow"?) concept

flow_wildcards_clear_non_packet_fields(): metadata only

miniflow_hash_5tuple(): "miniflow" concept

flow_hash_5tuple()

flow_push_mpls()

ofp-match.c
-----------

ofputil_wildcard_from_ofpfw10(): OpenFlow 1.0

ofproto-dpif-rid.h
------------------

frozen_metadata: metadata only

ofproto-dpif-xlate.c
--------------------

compose_output_action__(): metadata only

match.c
-------

match_format()

nx-match.c
----------

nx_put_raw(): NXM/OXM



notes:

* Two ways to think about VLAN/dLAN headers.

* Meaning of dl_type in OpenFlow.

* Take full advantage of existing similar code

:doc:`/topics/datapath`

TODO: kernel module
