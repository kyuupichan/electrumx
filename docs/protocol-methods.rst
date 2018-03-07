Protocol Methods
================

mempool.get_fee_histogram
-------------------------

  Return a histogram of the fee rates paid by transactions in the
  memory pool, weighted by transaction size.

**Signature**

  .. function:: mempool.get_fee_histogram()

  .. versionadded:: 1.2

**Result**

  The histogram is an array of [*fee*, *vsize*] pairs, where |vsize_n|
  is the cumulative virtual size of mempool transactions with a fee rate
  in the interval [|fee_n1|, |fee_n|], and |fee_n1| > |fee_n|.

  .. |vsize_n| replace:: vsize\ :sub:`n`
  .. |fee_n| replace:: fee\ :sub:`n`
  .. |fee_n1| replace:: fee\ :sub:`n-1`

  Fee intervals may have variable size.  The choice of appropriate
  intervals is currently not part of the protocol.

**Example Result**

  ::

    [[12, 128812], [4, 92524], [2, 6478638], [1, 22890421]]


server.add_peer
---------------

  This call is intended for a new server to get itself into a server's
  peers list, and should not be used by wallet clients.

**Signature**

  .. function:: server.add_peer(features)

  .. versionadded:: 1.1

  * **features**

    The same information that a call to the sender's
    :func:`server.features` RPC call would return.

**Result**

  A boolean indicating whether the request was tentatively accepted.
  The requesting server will appear in :func:`server.peers.subscribe`
  when further sanity checks complete successfully.


server.banner
-------------

  Return a banner to be shown in the Electrum console.

**Signature**

  .. function:: server.banner()

**Result**

  A string.

**Example Result**

  ::

     "Welcome to Electrum!"


server.donation_address
-----------------------

  Return a server donation address.

**Signature**

  .. function:: server.donation_address()

**Result**

  A string.

**Example Result**

  ::

     "1BWwXJH3q6PRsizBkSGm2Uw4Sz1urZ5sCj"


server.features
---------------

  Return a list of features and services supported by the server.

**Signature**

  .. function:: server.features()

**Result**

  A dictionary of keys and values.  Each key represents a feature or
  service of the server, and the value gives additional information.

  The following features MUST be reported by the server.  Additional
  key-value pairs may be returned.

  * **hosts**

    A dictionary, keyed by host name, that this server can be reached
    at.  Normally this will only have a single entry; other entries
    can be used in case there are other connection routes (e.g. Tor).

    The value for a host is itself a dictionary, with the following
    optional keys:

    * **ssl_port**

      An integer.  Omit or set to **null** if SSL connectivity is not
      provided.

    * **tcp_port**

      An integer.  Omit or set to **null** if TCP connectivity is not
      provided.

    A server should ignore information provided about any host other
    than the one it connected to.

  * **genesis_hash**

    The hash of the genesis block.  This is used to detect if a peer
    is connected to one serving a different network.

  * **hash_function**

    The hash function the server uses for :ref:`script hashing
    <script hashes>`.  The client must use this function to hash
    pay-to-scripts to produce script hashes to send to the server.
    The default is "sha256".  "sha256" is currently the only
    acceptable value.

  * **server_version**

    A string that identifies the server software.  Should be the same
    as the response to :func:`server.version` RPC call.

  * **protocol_max**
  * **protocol_min**

    Strings that are the minimum and maximum Electrum protocol
    versions this server speaks.  Example: "1.1".

  * **pruning**

    An integer, the pruning limit.  Omit or set to **null** if there is
    no pruning limit.  Should be the same as what would suffix the
    letter **p** in the IRC real name.

**Example Result**

::

  {
      "genesis_hash": "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
      "hosts": {"14.3.140.101": {"tcp_port": 51001, "ssl_port": 51002}},
      "protocol_max": "1.0",
      "protocol_min": "1.0",
      "pruning": null,
      "server_version": "ElectrumX 1.0.17",
      "hash_function": "sha256"
  }


server.peers.subscribe
----------------------

  Return a list of peer servers.  Despite the name this is not a
  subscription and the server must send no notifications.

**Signature**

  .. function:: server.peers.subscribe()

**Result**

  An array of peer servers, each returned as a 3-element array.  For
  example::

    ["107.150.45.210",
     "e.anonyhost.org",
     ["v1.0", "p10000", "t", "s995"]]

  The first element is the IP address, the second is the host name
  (which might also be an IP address), and the third is a list of
  server features.  Each feature and starts with a letter.  'v'
  indicates the server maximum protocol version, 'p' its pruning limit
  and is omitted if it does not prune, 't' is the TCP port number, and
  's' is the SSL port number.  If a port is not given for 's' or 't'
  the default port for the coin network is implied.  If 's' or 't' is
  missing then the server does not support that transport.


server.version
--------------

  Identify the client to the server and negotiate the protocol version.


**Signature**

  .. function:: server.version(client_name="", protocol_version="1.1")

  * **client_name**

    A string identifying the connecting client software.

  * **protocol_version**

    An array [`protocol_min`, `protocol_max`], each of which is a
    string.  If `protocol_min` and `protocol_max` are the same, they
    can be passed as a single string rather than as an array of two
    strings, as for the default value.

    .. versionadded:: 1.1
       **protocol_version** is not ignored.

  The server should use the highest protocol version both support::

    version = min(client.protocol_max, server.protocol_max)

  If this is below the value::

    max(client.protocol_min, server.protocol_min)

  then there is no protocol version in common and the server must
  close the connection.  Otherwise it should send a response
  appropriate for that protocol version.

**Result**

  An array of 2 strings:

     [`server software version`, `protocol version`]

  identifying the server and the protocol version that will be used
  for future communication.

  *Protocol version 1.0*: A string identifying the server software.

**Examples**::

  server.version("Electrum 3.0.6", ["1.1", "1.2"])
  server.version("2.7.1", "1.0")

**Example Results**::

  ["ElectrumX 1.2.1", "1.2"]
  "ElectrumX 1.2.1"
