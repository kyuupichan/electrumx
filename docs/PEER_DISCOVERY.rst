Peer Discovery
==============

This is a suggestion of a peer discovery prtocol as a way to gradually
move off depending on IRC.

It will be implemented in ElectrumX from version 0.11.0
onwards.


Peer Database
-------------

A persistent store of peers with at least the following information
about a peer so that state persists across server restarts.  This
information is required for a response to the **server.peers.subscribe**
RPC call:

* host name
* ip address
* TCP and SSL port numbers
* protocol version
* pruning limit, if any

At present ElectrumX uses a flat file for this DB in the main database
directory.  It retains additional per-peer metadata including:

* time of last successful connection
* time of last connection attempt
* count of unsuccessful attempts since last successful one
* source of the information stored about this peer


Default Peers
-------------

This is a list of hard-coded, well-known peers to seed the peer
discovery process if the peer database is empty or corrupt.  If the
peer database is available it is not used.  Ideally it should hold up
to 10 servers that have shown commitment to reliable service.

In ElectrumX this is a per-coin property in `lib/coins.py`.


Response to server.peers.subscribe RPC call
-------------------------------------------

This RPC call is used by Electrum clients to get a list of peer
servers, in preference to a hard-coded list of peer servers in the
client, which it will fall back to if necessary.

The server should craft its response in a way that reduces the
effectiveness of sybil attacks and peer spamming.

The response should only include peers it has successfully connected
to recently.  If Tor routing is not available, so their existence
cannot be verified, the response should include some hard-coded onion
peers so that clients always have a choice of onion servers.

Only reporting recent good peers ensures that those that have gone
offline will not be passed around for long (ignoring for hard-coded
onion peer exception).

In ElectrumX, "recently" is taken to be the last 24 hours.  Only one
peer from each IPv4/16 netmask is returned, and the number of onion
peers is limited.


Maintaining the Peer Database
-----------------------------

In order to keep its peer database up-to-date and fresh, if some time
has passed since the last successful connection to a peer, an Electrum
server should make an attempt to connect, choosing either the TCP or
SSL port.  On connecting it should issue **server.peers.subscribe**
and **server.features** RPC calls to collect information about the
server and its peers, and if it is the first time connecting to this
peer, a **server.add_peer** call to advertise itself.  Once this is
done and replies received it should terminate the connection.

The peer database should view information obtained from an outgoing
connection as authoritative, and prefer it to information obtained
from any other source.

On connecting, a server should confirm the peer is serving the same
network, ideally via the genesis block hash of the **server.features**
RPC call below.  If the peer does not implement that call, perhaps
instead check the **blockchain.headers.subscribe** RPC call returns a
peer block height within a small number of the expected value.  If a
peer is on the wrong network it should never be advertised to clients
or other peers.  Such invalid peers should perhaps be remembered for a
short time to prevent redundant revalidation if other peers persist in
advertising them, and later forgotten.

If a connection attempt fails, subsequent reconnection attempts should
follow some kind of exponential backoff.

If a long period of time has elapsed since the last successful
connection attempt, the peer entry should be removed from the
database.  This ensures that all peers that have gone offline will
eventually be forgotten by the network entirely.

ElectrumX will connect to the SSL port if both ports are available.
If that fails it will fall back to the TCP port.  It tries to
reconnect to a good peer at least once every 24 hours, and a failing
after 5 minutes but with exponential backoff.  It forgets a peer
entirely if two weeks have passed since a successful connection.
ElectrumX attempts to connect to onion peers through a Tor proxy that
can be configured or that it will try to autodetect.


server.features RPC call
------------------------

This is a new RPC call that a server can use to advertise what
services and features it offers.  It is intended for eventual use by
Electrum clients as well as other peers.  Peers will use it to gather
peer information from the peer itself.

The call takes no arguments and returns a dictionary keyed by feature
name whose value gives details about the feature where appropriate.
If a key is missing the feature is presumed not to be offered.

Currently ElectrumX understands and returns the following keys.
Unknown keys should be silently ignored.

* **hosts**

  An dictionary, keyed by host name, that this server can be reached
  at.  Normally this will only have a single entry; other entries can
  be used in case there are other connection routes (e.g. Tor).

  The value for a host is itself a dictionary, with the following
  optional keys:

  * **ssl_port**

    An integer.  Omit or set to *null* if SSL connectivity is not
    provided.

  * **tcp_port**

    An integer.  Omit or set to *null* if TCP connectivity is not
    provided.

  A server should ignore information provided about any host other
  than the one it connected to.

* **genesis_hash**

  The hash of the genesis block.  This is used to detect if a peer is
  connected to one serving a different network.

* **server_version**

  A string that identifies the server software.  Should be the same as
  the response to **server.version** RPC call.

* **protocol_max**
* **protocol_min**

  Strings that are the minimum and maximum Electrum protcol versions
  this server speaks.  The maximum value should be the same as what
  would suffix the letter **v** in the IRC real name.  Example: "1.1".

* **pruning**

  An integer, the pruning limit.  Omit or set to *null* if there is no
  pruning limit.  Should be the same as what would suffix the letter
  **p** in the IRC real name.


server.add_peer RPC call
------------------------

This call is intended for a new server to get itself in the connected
set.

It takes a single parameter (named **features** if JSON RPCv2 named
parameters are being used) which contains the same information as the
**server.features** RPC call would return.

A server receiving a **server.add_peer** call should not replace
existing information about the host(s) given, but instead schedule a
separate connection to verify the information for itself.

To prevent abuse a server may do nothing with second and subsequent
calls to this method from a single connection.

The result should be True if accepted and False otherwise.


IRC
---

Other server implementations may not have implemented the peer
discovery protocol yet.  Whilst we transition away from IRC, in order
to keep these servers in the connected peer set, having one or two in
the hard-coded peer list used to seed this process should suffice.
Any peer on IRC will report other peers on IRC, and so if any one of
them is known to any single peer implementing this protocol, they will
all become known to all peers quite rapidly.
