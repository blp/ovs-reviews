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
   "flow translation", thinking of an analogy between packet processing and a
   compiler for OpenFlow.

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

Incrementing ``FLOW_WC_SEQ``
++++++++++++++++++++++++++++

OVS has a mechanism to make it easier to find the bits of code that need to be
updated when ``struct flow`` changes.  This mechanism kicks in automatically
if we change the size of ``struct flow``.  We didn't do that, since we put our
new field in a hole in the structure, so we need to invoke it ourselves.

This mechanism is the macro ``FLOW_WC_SEQ`` in ``include/openvswitch/flow.h``.
It is defined this way::

    /* This sequence number should be incremented whenever anything involving
     * flows or the wildcarding of flows changes.  This will cause build
     * assertion failures in places which likely need to be updated. */
    #define FLOW_WC_SEQ 41

To invoke it, we just modify the macro's value.  The particular value doesn't
matter, so long as it's different, but it's customary to increment it, like
this::

    #define FLOW_WC_SEQ 42 /* The Answer to the Ultimate Question of Life,
                            * the Universe, and Networking. */

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

Aside: Alignment Pitfalls in Protocol Definitions
+++++++++++++++++++++++++++++++++++++++++++++++++

Two data alignment pitfalls sometimes arise in defining data structures for
network data.  First, some network protocols contain misaligned fields.  For
example, a SNAP header consists of a 3-byte field followed by a 16-bit field.
The 16-bit field is therefore not naturally aligned for its size, and if a
structure is defined naively consisting of a ``uint8_t[3]`` member followed by
a ``ovs_be16`` member, the compiler will insert a pad byte between the members,
which breaks the code.

A similar problem arises if the fields in a network header are naturally
aligned but the header ends in a misaligned way.  For example, a LACP
information structure (``struct lacp_info`` in OVS) contains 16-bit members,
but its length is not a multiple of 16 bits, so a compiler would normally
append a padding byte to the structure.

Both forms of this problems can be solved by marking the data structure as
"packed", which keeps the compiler from inserting pad bytes and makes it emit
code that does not assume that instances of the structure are aligned on any
particular boundary.  The ``OVS_PACKED`` macro, which is defined to work with
all the compilers that OVS supports, is available for this purpose.  Here is
how ``lib/packets.h`` uses it to define the SNAP header structure::

    #define SNAP_HEADER_LEN 5
    OVS_PACKED(
    struct snap_header {
        uint8_t snap_org[3];
        ovs_be16 snap_type;
    });
    BUILD_ASSERT_DECL(SNAP_HEADER_LEN == sizeof(struct snap_header));

Second, even when the headers themselves do not pose their own internal
alignment problems, network headers are not always stored in memory starting at
aligned addresses.  In some cases, it is not even possible for all the fields
in a packet to be aligned.  For example, VXLAN's design means that either the
inner or the outer headers can be properly aligned, but not both.  Given all
the protocols that OVS supports, only 16-bit alignment can be guaranteed for
any given field.

This second problem could also be solved with ``OVS_PACKED``, but OVS usually
takes a different approach, by declaring variants of many 32-bit and larger
types that require only 16-bit alignment.  For example, ``ovs_16aligned_be32``
is a ``typedef`` for a structure with two 16-bit members, which therefore only
requires 16-bit alignment.  Most of the OVS protocol definitions use these
types, which come with helpers for reading and writing them,
e.g. ``get_16aligned_be32`` and ``put_16aligned_be32``.

The dLAN header doesn't have either of these problems.

2. Fixing Compiler Errors
-------------------------

By design, when you add the kinds of declarations we did above, and run
``make``, then compiler and linker diagnostics, and eventually unit test
failures, kick in to point out the important places that OVS needs to be
changed to fully implement the new field.

The fixes we need to implement relate to the following changes we've already
made:

A. New ``dlan_id`` member in ``struct flow``.

B. New ``OVS_KEY_ATTR_DLAN`` member in ``enum ovs_key_attr``.

C. New ``OVS_ACTION_ATTR_*_DLAN`` members in ``enum ovs_action_attr``.

D. New ``MFF_DLAN_ID`` member in ``enum mf_field_id``.

E. New function prototypes we added.

The following sections cover each of these categories.

A. New ``dlan_id`` Member in ``struct flow``.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The change we made to ``FLOW_WC_SEQ`` in ``include/openvswitch/flow.h`` causes
many diagnostics in build assertions.  Each of the build assertions is intended
to draw our attention to some code that might need to change when ``struct
flow`` changes.  Many of these locations only require something new for
particular kinds of changes; for example, some of them only require our
attention if we added (or removed) a metadata field or a tunnel field.  We will
look at each of these in turn.

We will skip a few of them and come back in a later section where they fit
better.

Build Assertions in Header Files
++++++++++++++++++++++++++++++++

Some of the build assertions are in header files that are widely included and
thus account for most of the compiler diagnostics.  These are worth looking at
first since fixing them cleans up so much of the build.

Two of these are in ``include/openvswitch/flow.h``. The first of these is for
the following code::

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

The header file ``ofproto/ofproto-dpif-rid.h`` has another build assertion that
is just for metadata fields::

    /* Metadata for restoring pipeline context after recirculation.  Helpers
     * are inlined below to keep them together with the definition for easier
     * updates. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 41);

We can safely update this one, too, without further changes::

    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

Flow Extraction
+++++++++++++++

A build assertion will alert us to ``miniflow_extract()`` in ``lib/flow.c``.
This function extracts the fields in a packet in the slow path into a ``struct
flow``, as described back in `Introduction to Open vSwitch Packet Processing`_,
We need to make it look for a dLAN ID and copy that into the ``dlan_id`` field.

The ``miniflow_extract()`` function does not work directly with a ``struct
flow``.  Instead, it works with ``struct miniflow``, which is a compressed
version of ``struct flow`` .  Miniflows exist because ``struct flow`` is
relatively large (672 bytes, as of this writing).  In contexts where we might
need many flows, such as for representing an OpenFlow flow table that can have
millions of flows, the size itself is limiting.

``struct miniflow`` compresses ``struct flow`` by omitting all-zero 64-bit
doublewords.  Most flow and match structures are very sparse, so this is
effective compression.  It is not necessary to understand all the details of
the compression, but you can look up its definition in ``lib/flow.h`` if you
want to know more.

Despite this advantages, it is less convenient to work with the mini-structure,
so the full-size version remain in use for many purposes.

The ``miniflow_extract()`` function is a fast-path in the OVS userspace
datapath, which means that it is written to be as fast as possible.  This means
that its code is not necessarily as easy to read as it otherwise could be.  In
particular, it uses somewhat awkward techniques to construct the miniflow that
it outputs.  The programmer has to have some knowledge of the layout of the
flow structure, the order of fields within it, and which fields occupy which
64-bit doublewords.  The source file includes various functions and macros,
named ``miniflow_push_*()``, for appending a field to the extracted miniflow,
which has to happen in the same order as the ``struct flow`` members.  (This is
why it was important earlier to put the ``dlan_id`` member in ``struct flow``
just after the VLAN fields.)

The existing code in ``miniflow_extract()`` to extract the VLAN headers looks
like this::

            /* VLAN */
            union flow_vlan_hdr vlans[FLOW_MAX_VLAN_HEADERS];
            size_t num_vlans = parse_vlan(&data, &size, vlans);

            dl_type = parse_ethertype(&data, &size);
            miniflow_push_be16(mf, dl_type, dl_type);
            miniflow_pad_to_64(mf, dl_type);
            if (num_vlans > 0) {
                miniflow_push_words_32(mf, vlans, vlans, num_vlans);
            }

We can add dLAN parsing just after this as::

            /* dLAN */
            ovs_be16 did = parse_dlan(&data, &size);
            if (did) {
                miniflow_push_be16(mf, dlan_id, did);
            }

We also add a helper to do the actual parsing and return the dLAN ID, like
this::

    /* Attempts to parse a dLAN header at the current position in the packet
     * (which points to an Ethertype).  '*datap' and '*sizep' are the remaining
     * data in the packet; the function updates them.
     *
     * On entry, '*sizep' is at least 2.  On exit, it will also be at least 2.
     *
     * Returns 0 if no valid dLAN header was parsed, otherwise the dLAN ID. */
    static ovs_be16
    parse_dlan(const void **datap, size_t *sizep)
    {
        /* If a dLAN header is present, then data[0] == ETH_TYPE_DLAN and
         * data[1] is the dLAN ID.  We also ensure that there are at least 2
         * additional bytes beyond the dLAN ID (for the Ethertype of the next
         * protocol). */
        const ovs_be16 *data = *datap;
        if (*data != htons(ETH_TYPE_DLAN) || *sizep < 6) {
            return 0;
        }

        ovs_be16 dlan_id = data[1];
        if (!dlan_id) {
            /* dLAN ID of zero is invalid. */
            return 0;
        }

        *datap = data + 2;
        *sizep -= 4;
        return dlan_id;
    }

Of course we also need to update the build assertion from::

    /* Add code to this function (or its callees) to extract new fields. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 41);

to::

    /* Add code to this function (or its callees) to extract new fields. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 42);

Updating build assertions should be routine at this point, so it won't be
mentioned explicitly from now on.

Flow Composition
++++++++++++++++

The ``flow_compose()`` function in ``lib/flow.c`` is something like this
opposite of ``flow_extract()``.  Whereas ``flow_extract()`` takes a packet as
input and yields a microflow as output, ``flow_compose()`` takes a microflow as
input and produces a packet as output.  Obviously, a single microflow
corresponds to a very large number of possible packets, so this is only useful
for debugging situations where one wants to be able to test code with *some*
packet of a given microflow.

We can add support for dLAN IDs in ``flow_compose()`` by adding the following
after its code for VLANs::

    if (flow->dlan_id) {
        eth_push_dlan(p, flow->dlan_id);
    }

Committing Changes
++++++++++++++++++

``lib/odp-util.c`` has a function ``commit_odp_actions()`` that implements
OpenFlow actions that change fields.  Open vSwitch implements such actions in
what at first might seem a surprising way.  Ultimately, OVS has to implement an
OpenFlow action that, say, modifies the IP destination or pushes a VLAN by
translating it into an equivalent datapath (ODP) action that does the same
thing.  For example, given that a flow initially had no VLAN tag, it might
ultimately translate the OpenFlow action::

    set_field:1234->vlan_vid

into the ODP action::

    push_vlan(tpid=0x8100, tci=1234)

However, OVS doesn't do that translation immediately when it encounters the
``set_field`` action as part of processing a packet through OpenFlow.  That is
because it is common for controllers to include redundant, unneeded, or
mutually offsetting actions in the programs that they pass to Open vSwitch.
For example, the controller might push a VLAN on a packet when it enters the
switch through an access port, then pop that VLAN off before it exits the
switch through an access port, so that the net effect is that no change is
needed.  In that case, if OVS emitted a ``push_vlan`` action followed by
``pop_vlan``, the datapath would waste time processing every packet uselessly
pushing and then popping a VLAN.

Instead, OVS only bothers to emit ODP actions to update fields when their side
effects would be visible, for example, just before an ``output`` action that
transmits a packet to a physical or virtual port.  The ``commit_odp_actions()``
function implements that feature.  Its primary arguments are a pair of ``struct
flow`` structures: ``flow`` that represents the desired field values and
``base`` that represents the actual current field values.  The function
compares all of the values and, for the ones that differ, emits actions that
update them to match ``flow`` (and changes ``base`` to match ``flow``).

We need to add functionality to update the dLAN header.  The logic is simple:
if the dLAN ID differs between ``flow`` and ``base``, then pop off the dLAN
header (if there was one) and push on a new dLAN header (if there should be
one), and in any case update ``base`` to match ``flow``::

    static void
    commit_dlan_action(const struct flow *flow, struct flow *base,
                       struct ofpbuf *odp_actions, struct flow_wildcards *wc)
    {
        if (base->dlan_id != flow->dlan_id) {
            wc->masks.dlan_id = OVS_BE16_MAX;

            if (base->dlan_id) {
                nl_msg_put_flag(odp_actions, OVS_ACTION_ATTR_POP_DLAN);
            }
            if (flow->dlan_id) {
                nl_msg_put_be16(odp_actions, OVS_ACTION_ATTR_PUSH_DLAN,
                                flow->dlan_id);
            }
            base->dlan_id = flow->dlan_id;
        }
    }

We also add a call to our new function in an appropriate place in
``commit_odp_actions()``::

    ...
    commit_vlan_action(flow, base, odp_actions, wc);
    commit_dlan_action(flow, base, odp_actions, wc);
    commit_set_priority_action(flow, base, odp_actions, wc, use_masked);
    ...

Marking Significant Fields
++++++++++++++++++++++++++

``lib/flow.c`` has a couple of functions that, for a given ``struct flow`` that
represents a microflow, mark the members that are significant for it.  For
example, if a microflow represents an ARP packet, then they would mark
``arp_sha`` and ``arp_tha``, but they would not do so for other kinds of
packets.

In this case, the ``dlan_id`` member is significant for all Ethernet packets.
This might not be obvious at first, because most packets will not have a dLAN
header.  However, the ``dlan_id`` member is what tells us that the packet does
not have a dLAN header, so its value is still significant, and that is what
these functions are attempting to determine.

There are two functions that do this kind of thing.  The first one is
``flow_wildcards_init_for_packet()``.  For this one, the relevant section of
code is this::

    if (flow->packet_type == htonl(PT_ETH)) {
        WC_MASK_FIELD(wc, dl_dst);
        WC_MASK_FIELD(wc, dl_src);
        WC_MASK_FIELD(wc, dl_type);
        /* No need to set mask of inner VLANs that don't exist. */
        for (int i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
            /* Always show the first zero VLAN. */
            WC_MASK_FIELD(wc, vlans[i]);
            if (flow->vlans[i].tci == htons(0)) {
                break;
            }
        }
        dl_type = flow->dl_type;
    } else {

As you can see, each significant field is marked using ``WC_MASK_FIELD``.  To
mark ``dlan_id``, we just add the following someplace.  The particular spot
does not matter, although just after the VLANs maintains the logical ordering::

        WC_MASK_FIELD(wc, dlan_id);

The ``flow_wc_map()`` function does something similar.  In this case the
relevant stanza is::

    /* Metadata fields that can appear on packet input. */
    FLOWMAP_SET(map, skb_priority);
    FLOWMAP_SET(map, pkt_mark);
    FLOWMAP_SET(map, recirc_id);
    FLOWMAP_SET(map, dp_hash);
    FLOWMAP_SET(map, in_port);
    FLOWMAP_SET(map, dl_dst);
    FLOWMAP_SET(map, dl_src);
    FLOWMAP_SET(map, dl_type);
    FLOWMAP_SET(map, vlans);
    FLOWMAP_SET(map, ct_state);
    FLOWMAP_SET(map, ct_zone);
    FLOWMAP_SET(map, ct_mark);
    FLOWMAP_SET(map, ct_label);
    FLOWMAP_SET(map, packet_type);

and we can just add ``dlan_id`` to it somewhere, like this::

    FLOWMAP_SET(map, dlan_id);

Functions That Don't Need to Change
+++++++++++++++++++++++++++++++++++

``lib/flow.c`` has a bunch of functions that trigger build assertions that we
don't actually need to update (besides the build assertions themselves).  These
are:

* ``flow_get_metadata()`` and ``flow_wildcards_clear_non_packet_fields()``: The
  dLAN ID is a data field, not a metadata field.

* ``miniflow_hash_5tuple()`` and ``flow_hash_5tuple()``: The dLAN ID is not
  part of the 5-tuple.

* ``flow_push_mpls()``: This function has an internal need to clear all the L3
  and L4 fields in a flow, but the dLAN ID is an L2 field.

This is also true for ``ofputil_wildcard_from_ofpfw10()`` in
``lib/ofp-match.c``.  This function works with OpenFlow 1.0 flows.  OpenFlow
1.0 supported a fixed set of packet headers, which OVS has fully supported for
a long time.  OpenFlow 1.0 did not support dLAN and never will, and dLAN has no
effect on OpenFlow 1.0, so nothing needs to change there.

Finally, ``compose_output_action__()`` in ``ofproto/ofproto-dpif-xlate.c`` has
some code that needs to change if we introduce a new metadata field.  Since the
dLAN ID is not metadata, nothing needs to change here either.

B. New ``OVS_KEY_ATTR_DLAN`` Member in ``enum ovs_key_attr``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Now we have to implement userspace code related to the dLAN ID field, which we
previously added as ``OVS_KEY_ATTR_DLAN``.  We will implement the interface
between the slow path and the datapath, which also makes the dLAN ID work in
the userspace datapath.

The compiler tells us about most of the places we have to update by reporting
missing cases for ``OVS_KEY_ATTR_DLAN`` in ``switch`` statements.  The fix for
these messages is always to add a case for the new attribute, and sometimes no
more work than that is needed.  (In a few cases where there is no relevant
``switch`` statement, build assertions on ``FLOW_WC_SEQ`` let us know about the
problem instead.)

Datapath Field Modification
+++++++++++++++++++++++++++

The file ``lib/odp-execute.c`` has two functions that allow datapath actions to
modify fields.  In both cases we just follow the pattern set by existing code.
We need to add code to ``odp_execute_set_action()`` to modify the whole dLAN ID
field.  This is easy::

    case OVS_KEY_ATTR_DLAN:
        eth_set_dlan(packet, nl_attr_get_be16(a), OVS_BE16_MAX);
        break;

We also need to add code to ``odp_execute_masked_set_action()`` to modify part
of the dLAN ID field based on a mask provided by the caller, which is just as
easy::

    case OVS_KEY_ATTR_DLAN:
        eth_set_dlan(packet, nl_attr_get_be16(a), *get_mask(a, ovs_be16));
        break;

Easy Changes
++++++++++++

There are a few related changes in ``lib/odp-util.c`` that are easy.  We need
to add a case to ``ovs_key_attr_to_string()`` to return the name of the field::

    case OVS_KEY_ATTR_DLAN: return "dlan";

The function ``odp_mask_is_constant__()`` needs to be able to identify when a
mask for a field is all-0-bits or all-1-bits.  For dLAN, like most fields, we
can use the "default" implementation that just checks whether all the bytes are
0x00 or 0xff::

    ...
    case OVS_KEY_ATTR_CT_ZONE:
    case OVS_KEY_ATTR_CT_MARK:
    case OVS_KEY_ATTR_CT_LABELS:
    case OVS_KEY_ATTR_PACKET_TYPE:
    case OVS_KEY_ATTR_NSH:
    case OVS_KEY_ATTR_DLAN:
        return is_all_byte(mask, size, u8);

And the function ``format_odp_key_attr__()`` needs to be able to print a match
against the field, possibly with a mask.  It's easy to follow the same pattern
as other fields here, too::

    case OVS_KEY_ATTR_DLAN:
        ds_put_format(ds, "0x%04"PRIx16, ntohs(nl_attr_get_be16(a)));
        if (!is_exact) {
            ds_put_format(ds, "/0x%04"PRIx16, ntohs(nl_attr_get_be16(ma)));
        }
        break;

The sFlow code in ``sflow_read_set_action()`` in
``ofproto/ofproto-dpif-sflow.c`` has a switch statement that treats a few kinds
of datapath fields specially.  Like most fields, though, dLAN needs no special
treatment, so we can just make ``OVS_KEY_ATTR_DLAN`` do nothing::

    case OVS_KEY_ATTR_IN_PORT:
    case OVS_KEY_ATTR_ETHERNET:
    case OVS_KEY_ATTR_VLAN:
    case OVS_KEY_ATTR_DLAN:
        break;

Translating Datapath Microflows into Slow Path Microflows
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++

The hardest part of implementing a new field is dealing with the differences
between microflows in the slow path and microflows in the datapath.  This is
difficult because of the need for version compatibility: the OVS slow path is
supposed to work properly with any version of an OVS datapath, and vice versa.
As mentioned previously in `Introduction to Open vSwitch Packet Processing`_,
this is done





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
