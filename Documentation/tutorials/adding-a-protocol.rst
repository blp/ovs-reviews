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

The dLAN Protocol
-----------------

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

Introduction to Open vSwitch Packet Processing
----------------------------------------------

Open vSwitch divides packet processing into two parts.  The first of these is
called a "datapath".  OVS includes multiple datapath implementations: the
"userspace datapath" that is integrated into ``ovs-vswitchd`` (this is used
with DPDK and so sometimes it is called the "DPDK datapath"), the Linux kernel
datapath, and the Windows kernel datapath.  All of these use the same
interface.

The datapath is where a packet to be processed by Open vSwitch starts out.
It processes the packet in the following way:

1. Extracts the fields understood by the datapath into a datapath "(micro)flow"
   structure.
2. Looks up the flow in the flow table, yielding a datapath flow entry.
3. Executes the datapath flow entry's datapath "actions".

The flow table in step 2 is a cache.  The first time a particular kind of
packet arrives in the datapath, no flow entry will be populated for it, so the
lookup in step 2 fails.  In such a case, the datapath passes the packet and its
flow to the second part, the "slow path"[#]_, which resides in ``ovs-vswitchd``
and has a common implementation regardless of the datapath.  It goes through a
similar process there:

1. Extracts the fields understood by the slow path into a slow path "flow"
   structure (``struct flow``) and compares it against the datapath flow.

2. Passes the packet through the series of OpenFlow flow tables, using the
   OpenFlow action to determine what datapath actions should be executed and
   otherwise what the datapath flow entry should look like.  We often call this
   "flow translation".

3. Sends the packet back to the datapath, which executes the actions and adds
   a new flow entry.

Step 1 might be surprising.  Why would the slow path need to redo the work of
the datapath by extracting all the fields again?  And why would the result
possibly differ?  This is because of inter-version compatibility between the
datapaths and the slow path.  Any version of any Open vSwitch datapath is
intended to be compatible with any version of the Open vSwitch slow path,
regardless of what protocols and fields they respectively support.  The slow
path can figure out the capabilities of the datapath, and compensate for
missing features, on a flow-by-flow basis by comparing its own idea of a
(micro)flow against the one provided by the datapath.  Implementing this
comparison correctly is tricky and error-prone, and we'll see more on it later.

There is also a difference between OpenFlow actions and datapath actions (aka
"ODP actions"[#]_).  ODP actions tend to be, functionally, a subset of OpenFlow
actions, but their format is unrelated.

.. [#] Sometimes the "slow path" is just called "userspace".  There is also a
       userspace datapath, so this can be terribly confusing.  Sorry about
       that.

.. [#] ODP is short for Open vSwitch Datapath.

Outline
-------

To add a new field, we need to do some work across both parts of the system.
We proceed in roughly the following steps:

1. Add a bunch of declarations, without actually implementing the guts of any
   of them.  The following section covers this step.

2. Recompile.  This will cause a pile of new warnings and errors.  If you
   configured with ``--enable-Werror``, as recommended, all of them will be
   errors.  (You want them to be errors, to make them impossible to miss.)

   Each of these warnings (or errors) represents a place that an update might
   be required to support your new field.  We will fix up the code in all of
   these places.

   After this step, the OVS slow path and the userspace datapath support the
   new field, and all that's left for them is testing.

3. Optionally, add support for the remaining datapaths, such as the Linux
   kernel datapath.  We will not do this in this tutorial.

   .. note::
      
      Even without doing this work, the inter-version compatibility support in
      the slow path/datapath protocol means that the new field will still
      function properly.  This comes at a very large performance cost for the
      protocol--every packet with the protocol will go through the slow
      path--so this is likely to be acceptable only if the protocol is rarely
      used (e.g. some ARP features are implemented this way).

The following sections go through each of these steps.

1. Add Declarations for dLAN
----------------------------

We need to add various declarations to the source code for various features of
our new field:

A. Add dLAN ID to the slow path's (micro)flow structure, called ``struct
   flow``, so that the slow path knows how to deal with the field.

B. Add dLAN ID to the interface that sits between the slow path and the
   datapaths, so that the slow path and datapaths have a way to refer to it.

C. Declare an OpenFlow "OXM" name for a dLAN ID, so that OpenFlow controllers
   can match and modify it.

D. Declare OpenFlow actions for dLAN IDs.

E. Declare ODP actions for actions on dLAN IDs.  (These might be necessary even
   if there are no OpenFlow actions, as we'll explain later.)

F. Declare helper functions for working with matching on dLAN ID.

G. Declare helper functions for pushing and popping dLAN headers and modifying
   a dLAN ID in a packet.

The sections below go through the details.

A. Add dLAN ID to Slow Path Microflow Strcture (``struct flow``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For a protocol or a header to have any bearing on packet processing, OVS
userspace must be able to understand and extract it into the slow path
(micro)flow structure, which is ``struct flow``, defined in
``include/openvswitch/flow.h``.  (There is also a file named ``flow.h`` in the
``lib`` directory, but it is not relevant here.)

What Members Does the dLAN Need?
++++++++++++++++++++++++++++++++

Before we consider modifying this structure, we need to decide what we want to
add to it.  We at least need the dLAN ID, for which the natural type in Open
vSwitch is ``ovs_be16``.  This is a ``typedef`` for ``uint16_t`` that is
specially tagged so that the ``sparse`` semantic analyzer reports common
byte-order errors, such as forgetting to use ``htons`` or ``ntohs``.  If you
install ``sparse``, as recommended in `Before You Start`_, then you will
automatically get these error reports during your build.

Another important consideration is that we need to ensure that code examining
the flow structure can tell whether the field is present.  For L3 and L4
fields, this is often implicit in the Ethernet type or IP protocol type,
respectively.  For example, an IPv4 source address is present if the Ethertype
indicates IPv4.  For better or worse, OpenFlow and OVS have not traditionally
indicated the presence of L2 protocols in the same way.  That is, the Ethernet
type member in ``struct flow``, called ``dl_type``, is not 0x8100 if the packet
has a VLAN header; instead, it is whatever protocol is inside the Ethernet
header, such as 0x0800 if the packet is an IPv4 packet.

For VLAN headers, OVS takes advantage of some natural redundancy to indicate
whether the header is actually present, using the TPID and the CFI bit.  For
dLAN, we can take advantage of how we defined a dLAN ID of 0 to be invalid,
using that special value as an indication that the header is not present.

Putting this together, dLAN needs only a single member in ``struct flow``, like
this::

      ovs_be16 dlan_id;           /* dLAN ID (zero if no dLAN present). */

Where Should the dLAN Members Go?
+++++++++++++++++++++++++++++++++

``struct flow`` is divided in sections for metadata fields, L2 fields, L3
fields, and L4 fields.  A new field should ordinarily go in the section
corresponding to its type.  This is not a correctness issue, because OVS will
still function regardless.  It can be a performance issue due to "staged
lookup", which is a classifier optimization described in the large comment in
``lib/classifier.h`` and in [OVS-DESIGN]_.

The L2 section in ``struct flow`` initially looks like this::

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

We are strongly motivated to order the structure members the same way they
appear in a packet.  Later, that will make it much easier to write the code to
extract the fields.  In this case, this means that the dLAN ID should go after
``vlans``.

It's not as simple as just adding an dLAN ID just after ``vlans'', though,
because we also need to keep member alignment into account.  Each section of
``struct flow`` must be a multiple of 64 bits in length; the L2 section above
starts and ends on a 64-bit boundary.  If we just add a 16-bit member after
``vlans``, the compiler would put 16 bits of padding before ``mpls_lse``, which
in turn would end 32 bits into a 64-bit unit.

``FLOW_MAX_MPLS_LABELS`` is currently 3, so there's 32 bits of padding built
into ``mpls_lse``.  Therefore, we can reuse part of the extra space for the
dLAN ID, changing the definition of ``mpls_lse`` to::

    ovs_be32 mpls_lse[FLOW_MAX_MPLS_LABELS];          /* MPLS label stack. */
    ovs_be16 dlan_id;           /* dLAN ID (zero if no dLAN present). */
    uint8_t pad4[2];            /* Pad to 64 bits. */

.. [OVS-DESIGN] B. Pfaff, J. Pettit, T. Koponen, E. J. Jackson, A. Zhou,
   J. Rajahalme, J. Gross, A. Wang, J. Stringer, P. Shelar, K. Amidon,
   M. Casado, “The Design and Implementation of Open vSwitch.”  In USENIX
   NSDI. 2015. `PDF
   <https://www.usenix.org/system/files/conference/nsdi15/nsdi15-paper-pfaff.pdf>`_.

B. Add dLAN ID to Datapath Interface
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The datapath and the slow path communicate microflows and flow matches to each
other using a specialized type-length-value (TLV) protocol that is defined in
``datapath/linux/compat/include/linux/openvswitch.h``.  This file defines a
contract between Open vSwitch userspace and its Linux kernel module, which
means that it must maintain a stable ABI: nothing that it defines may be
changed in a backward-incompatible way.  In practice, this means that we may
add new definitions but not change existing ones.

A key for each protocol is defined in this file in the ``enum
ovs_key_attr`` enumeration:[#]_

::

    enum ovs_key_attr {
        OVS_KEY_ATTR_UNSPEC,
        OVS_KEY_ATTR_ENCAP,     /* Nested set of encapsulated attributes. */
        OVS_KEY_ATTR_PRIORITY,  /* u32 skb->priority */
        OVS_KEY_ATTR_IN_PORT,   /* u32 OVS dp port number */
        OVS_KEY_ATTR_ETHERNET,  /* struct ovs_key_ethernet */
        OVS_KEY_ATTR_VLAN,      /* be16 VLAN TCI */
        OVS_KEY_ATTR_ETHERTYPE, /* be16 Ethernet type */
        OVS_KEY_ATTR_IPV4,      /* struct ovs_key_ipv4 */
   ...

    #ifdef __KERNEL__
        /* Only used within kernel data path. */
        OVS_KEY_ATTR_TUNNEL_INFO,  /* struct ovs_tunnel_info */
    #endif

    #ifndef __KERNEL__
        /* Only used within userspace data path. */
        OVS_KEY_ATTR_PACKET_TYPE,  /* be32 packet type */
        OVS_KEY_ATTR_ND_EXTENSIONS, /* struct ovs_key_nd_extensions */
    #endif

        __OVS_KEY_ATTR_MAX
    };

We need to add an attribute type for a dLAN header.  If we planned to implement
this feature in the Linux kernel datapath, we would add it at the end of the
first group, before the first ``#ifdef``.  However, this tutorial will only
cover adding dLAN support to the userspace datapath, which means that we should
add it to the group that is only included when not building the kernel,
i.e. the ``#ifndef __KERNEL__`` group.

The attribute needs to have a name; ``OVS_KEY_ATTR_DLAN`` is appropriate.  We
also need to define the attribute's contents.  In this case, a single be16 is
appropriate.  So we add such a definition in the ``#ifndef __KERNEL__`` group,
which ends up looking like this::

    #ifndef __KERNEL__
        /* Only used within userspace data path. */
        OVS_KEY_ATTR_PACKET_TYPE,  /* be32 packet type */
        OVS_KEY_ATTR_ND_EXTENSIONS, /* struct ovs_key_nd_extensions */
        OVS_KEY_ATTR_DLAN,          /* be16 dLAN ID */
    #endif

There's more to understand about the datapath interface, but we'll save that
for later.

.. [#] Indentation has been adjusted slightly to make this example fit in the
       margins.

C. Declare an OpenFlow OXM Name for the dLAN ID
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

OpenFlow 1.2 and later use a flexible type-length-value format, called OXM, to
describe packet fields.  (OXM was adapted from a very similar earlier design in
Open vSwitch called NXM, so the terms OXM and NXM are used almost
interchangeably with OVS.)  For an OpenFlow controller to be able to work with
our new dLAN header, we need to define a OXM code point for the dLAN ID.

There is no standardized code point for this field, of course.  We can define
our own nonstandard NXM/OXM code point.  A code point consists of a "class" and
a "type".  A class identifies an organization that is entitled to assign types
within the class.  In this case, we can use the ``NXM_NX`` class, a class
assigned to Open vSwitch itself for its extensions.  We choose the first
available type within the class; as of this writing, that is 126.

We also need to know what kind of value the OXM/NXM field takes; in this case,
it is ``be16``, a 16-bit big-endian number.

To declare this NXM/OXM code point with the properties described above, we add
the following to ``include/openvswitch/meta-flow.h`` among all the other field
declarations::

    /* "dlan_id".
     *
     * dLAN ID.
     *
     * For a packet with a valid dLAN header, this is the dLAN ID field.  For a
     * packet with no dLAN header, this has value 0 (this is unambiguous
     * because a dLAN ID of 0 is invalid).
     *
     * Type: be16.
     * Maskable: bitwise.
     * Formatting: decimal.
     * Prerequisites: Ethernet.
     * Access: read/write.
     * NXM: NXM_NX_DLAN_ID(126) since v2.12.
     * OXM: none.
     */
    MFF_DLAN_ID,

Most of the above is a C comment that ordinarily would have no effect, but as
part of the build process Open vSwitch runs a script that parses the comment
and uses it to implement the features that it describes.  Thus, the line that
begins ``NXM:`` actually associates our new field, which OVS internally calls
``MFF_DLAN_ID``, with the specified NXM/OXM class and type.

The other key-value pair lines in the above comment are also significant.
Their meanings are described in a large comment at the top of
``include/openvswitch/meta-flow.h``.

D. Declare OpenFlow Actions for the dLAN ID
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Our dLAN ID field does not need any new OpenFlow actions.  One might think that
these would be needed to support a few behaviors we obviously want from dLANs,
but it's not true:

* Modifying a dLAN ID: OpenFlow 1.2+ has a standard action called Set-Field
  that can modify any writable field that has an NXM/OXM code point, so we
  don't need a special action for that.

* Pushing a dLAN: We only support a single dLAN header, so a Set-Field that
  changes the dLAN ID from zero to nonzero can implicitly push a dLAN header.

* Popping a dLAN: A Set-Field that changes the dLAN to zero can implicitly pop
  a dLAN header.

Thus, we won't add any OpenFlow actions in this tutorial.

If you're still interested, the FAQ has some information on adding an OpenFlow
action in :doc:`/faq/contributing` under "Q: How do I add support for a new
OpenFlow action?".

E. Declare ODP Actions for dLAN ID
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

dLAN could be treated the same way in the lower-level datapath or ODP actions
as in OpenFlow.  Like OpenFlow, ODP has a generic "set-field" action, so we'll
use that for setting the dLAN ID.  However, it is conventional in ODP to use
explicit actions for pushing and popping headers, so we will follow precedent
and introduce a pair of new actions.

The ODP actions are declared as ``enum ovs_action_attr`` in
``datapath/linux/compat/include/linux/openvswitch.h``, like so:[#]_

::

    enum ovs_action_attr {
        OVS_ACTION_ATTR_UNSPEC,
        OVS_ACTION_ATTR_OUTPUT,       /* u32 port number. */
        OVS_ACTION_ATTR_USERSPACE,    /* Nested OVS_USERSPACE_ATTR_*. */
    ...

    #ifndef __KERNEL__
        OVS_ACTION_ATTR_TUNNEL_PUSH,   /* struct ovs_action_push_tnl*/
        OVS_ACTION_ATTR_TUNNEL_POP,    /* u32 port number. */
    #endif
        __OVS_ACTION_ATTR_MAX,        /* Nothing past this will be accepted
                                       * from userspace. */
    ...
    };

This tutorial is not adding support to the Linux kernel module for the dLAN
header, so we add our new actions to the ``#ifndef __KERNEL__`` block, like
this::

    #ifndef __KERNEL__
        OVS_ACTION_ATTR_TUNNEL_PUSH,   /* struct ovs_action_push_tnl*/
        OVS_ACTION_ATTR_TUNNEL_POP,    /* u32 port number. */
        OVS_ACTION_ATTR_PUSH_DLAN,     /* __be16 dLAN ID. */
        OVS_ACTION_ATTR_POP_DLAN,      /* No argument. */
    #endif
  
.. [#] Again, indentation has been adjusted slightly to make this example fit
       in the margins.

F. Declare Helpers for Matching on dLAN ID
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We've already met ``struct flow`` above.  Now it's time to introduce ``struct
match``.  Whereas ``struct flow`` represents the fields in a microflow (or a
packet), ``struct match`` represents the match part of an OpenFlow flow.  It
can represent an exact or bitwise match on any supported fields.  For the
moment, the details are not important.

It's customary in OVS to have a pair of functions to make a match structure
match exactly or in a bitwise-masked way on a field.  We can declare these for
our new dLAN ID in ``include/openvswitch/match.h`` by adding the following
prototypes::

    void match_set_dlan_id(struct match *, ovs_be16);
    void match_set_dlan_id_masked(struct match *, ovs_be16 id, ovs_be16 mask);

We'll implement them later.

G. Declare Helpers for Manipulating dLAN in Packets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The header ``lib/packets.h`` contains definitions for network protocols.  We
will need to manipulate dLAN packets, so we should add some definitions here.

We add prototypes for functions to operate on dLAN headers.  A ``struct
dp_packet`` is the structure used to hold network packets in OVS::

    void eth_push_dlan(struct dp_packet *, ovs_be16 dlan_id);
    void eth_pop_dlan(struct dp_packet *);
    void eth_set_dlan(struct dp_packet *, ovs_be16 dlan_id, ovs_be16 mask);

We define the Ethernet type for dLAN::

    #define ETH_TYPE_DLAN          0xdddd

Finally, we define a data structure for a dLAN header::

    #define DLAN_HEADER_LEN 4
    struct dlan_header {
        ovs_be16 dlan_id;
        ovs_be16 dlan_next_type;
    };
    BUILD_ASSERT_DECL(DLAN_HEADER_LEN == sizeof(struct dlan_header));

Pitfalls
++++++++

Two pitfalls, both related to alignment, sometimes arise in defining data
structures for network data.  The first issue comes up with network protocols
that contain misaligned fields.  For example, a SNAP header consists of a
3-byte field followed by a 16-bit field.  The 16-bit field is therefore not
naturally aligned for its size, and if a structure is defined naively
consisting of a ``uint8_t[3]`` member followed by a ``ovs_be16`` member, the
compiler will insert a pad byte between the members, which breaks the code.

The second issue comes up because, even when the headers themselves do not pose
their own internal alignment problems, network headers are not always stored in
memory starting at aligned addresses.  In some cases, it is not even possible
for all the fields in a packet to be aligned.  For example, VXLAN's design
means that either the inner or the outer headers can be properly aligned, but
not both.

   

2. Fixing Compiler Errors
-------------------------

By design, when you add the kinds of declarations we did above, compiler
warnings and errors kick in to point out the important places that OVS needs to
be changed to fully implement the new field.




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
------------------------------

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
-------------------------------------

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
------------------



flow_get_metadata()
-------------------

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

* Meaning of dl_type in OpenFlow.

* Take full advantage of existing similar code

* 16aligned types

:doc:`/topics/datapath`

TODO: kernel module
