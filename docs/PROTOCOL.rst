=================
Electrum Protocol
=================

This is intended to be a reference for client and server authors
alike.

I have attempted to ensure what is written is correct for the three
known server implementations: electrum-server, jelectrum and
ElectrumX, and also for Electrum clients of the 2.x series.  We know
other clients exist but I am not aware of the source of any being
publicly available.


Message Stream
--------------

Clients and servers communicate using JSON RPC over an unspecified
underlying stream transport protocol, typically TCP or SSL.

`JSON RPC 1.0`_ and `JSON RPC 2.0`_ are specified; use of version 2.0
is encouraged but not required.  Server support of batch requests is
encouraged for version 1.0 but not required.  Clients making batch
requests should limit their size depending on the nature of their
query, because servers will limit response size as an anti-DoS
mechanism.

RPC calls and responses are separated by newlines in the stream.  The
JSON specification does not permit control characters within strings,
so no confusion is possible there.  However it does permit newlines as
extraneous whitespace between elements; client and server MUST NOT use
newlines in such a way.

If using JSON RPC 2.0's feature of parameter passing by name, the
names shown in the protocol versions's description MUST be used.

A server advertising support for a particular protocol version MUST
support each method documented for that protocol version, unless the
method is explicitly marked optional.  It may support other methods or
additional parameters with unspecified behaviour.  Use of additional
parameters is discouraged as it may conflict with future versions of
the protocol.

Notifications
-------------

Some methods are subscriptions, which will respond with notifications
when the thing subscribed to changes.  The `method` of the
notification is the same as the method of the subscription, and the
`params` of the notification (and their names) are given in the
documentation of the method.


Protocol Negotiation
--------------------

It is desirable to have a way to enhance and improve the protocol
without forcing servers and clients to upgrade at the same time.
Protocol negotiation is not implemented in any client or server at
present to the best of my knowledge, so care is needed to ensure
current clients and servers continue to operate as expected.

Protocol versions are denoted by "m.n" strings, where *m* is the major
version number and *n* the minor version number.  For example: "1.5".

A party to a connection will speak all protocol versions in a range,
say from `protocol_min` to `protocol_max`.  This min and max may be
the same.  When a connection is made, both client and server must
initially assume the protocol to use is their own `protocol_min`.

The client should send a `server.version` RPC call as early as
possible in order to negotiate the precise protocol version; see its
description for more detail.  All responses received in the stream
from and including the server's response to this call will use the
negotiated protocol version.


Protocol Version 1.0
--------------------

server.version
==============

Identifies the client to the server.

  server.version(**client_name**, **protocol_version**)

  **client_name**

    An optional string identifying the connecting client software.

  **protocol_verion**

    Optional.  The value passed is ignored.

**Response**

  A string identifying the server software.

**Example**::

  server.version("2.7.11", "1.0")


blockchain.address.get_balance
==============================

Return the confirmed and unconfirmed balances of a bitcoin address.

  blockchain.address.get_balance(**address**)

  **address**

    The address as a Base58 string.

**Response**

  A dictionary with keys *confirmed* and *unconfirmed*.  The value of
  each is the appropriate balance in coin units as a string.

**Response Example**::

  {
    "confirmed": "1.03873966",
    "unconfirmed": "0.236844"
  }


blockchain.address.get_history
==============================

Return the confirmed and unconfirmed history of a bitcoin address.

  blockchain.address.get_history(**address**)

  **address**

    The address as a Base58 string.

**Response**

    A list of confirmed transactions in blockchain order, with the
    output of *blockchain.address.get_mempool* appended to the list.
    Each transaction is a dictionary with keys *height* and *tx_hash*.
    *height* is the integer height of the block the transaction was
    confirmed in; if unconfirmed then *height* is 0 if all inputs are
    confirmed, and -1 otherwise.  *tx_hash* the transaction hash in
    hexadecimal.

**Response Examples**

::

    [
      {
        "height": 200004,
        "tx_hash": "acc3758bd2a26f869fcc67d48ff30b96464d476bca82c1cd6656e7d506816412"
      },
      {
        "height": 215008,
        "tx_hash": "f3e1bf48975b8d6060a9de8884296abb80be618dc00ae3cb2f6cee3085e09403"
      }
    ]

::

    [
      {
        "fee": 20000,
        "height": 0,
        "tx_hash": "9fbed79a1e970343fcd39f4a2d830a6bde6de0754ed2da70f489d0303ed558ec"
      }
    ]


blockchain.address.get_mempool
==============================

Return the unconfirmed transactions of a bitcoin address.

  blockchain.address.get_mempool(**address**)

  **address**

    The address as a Base58 string.

**Response**

    A list of mempool transactions in arbitrary order.  Each
    transaction is a dictionary with keys *height* , *tx_hash* and
    *fee*.  *tx_hash* the transaction hash in hexadecimal, *height* is
    `0` if all inputs are confirmed, and `-1` otherwise, and *fee* is
    the transaction fee in minimum coin units as an integer.

**Response Examples**

::

  [
    {
      "tx_hash": "45381031132c57b2ff1cbe8d8d3920cf9ed25efd9a0beb764bdb2f24c7d1c7e3",
      "height": 0,
      "fee": 24310
    }
  ]


blockchain.address.get_proof
============================

This method is optional and deprecated, and hence its response will
not be described here.

  blockchain.address.get_proof(**address**)

  **address**

    The address as a Base58 string.


blockchain.address.listunspent
==============================

Return an ordered list of UTXOs sent to a bitcoin address.

  blockchain.address.listunspent(**address**)

  **address**

    The address as a Base58 string.

**Response**

    A list of unspent outputs in blockchain order.  Each transaction
    is a dictionary with keys *height* , *tx_pos*, *tx_height* and
    *value* keys.  *height* is the integer height of the block the
    transaction was confirmed in; if unconfirmed then *height* is 0 if
    all inputs are confirmed, and -1 otherwise.  *tx_hash* the
    transaction hash in hexadecimal, *tx_pos* the zero-based index of
    the output in the transaction's list of outputs, and *value* its
    integer value in minimum coin units (satoshis in the case of
    Bitcoin).

**Response Example**

::

  [
    {
      "tx_pos": 0,
      "value": 45318048,
      "tx_hash": "9f2c45a12db0144909b5db269415f7319179105982ac70ed80d76ea79d923ebf",
      "height": 437146
    },
    {
      "tx_pos": 0,
      "value": 919195,
      "tx_hash": "3d2290c93436a3e964cfc2f0950174d8847b1fbe3946432c4784e168da0f019f",
      "height": 441696
    }
  ]


blockchain.address.subscribe
============================

Subscribe to a bitcoin address.

  blockchain.address.subscribe(**address**)

  **address**

    The address as a Base58 string.

**Response**

  The *status* [1]_ of the address.

**Notifications**

  As this is a subcription, the client will receive a notification
  when the status of the address changes.  The parameters are:

    [**address**, **status**]

.. [1] To calculate the *status* of an address, order confirmed
       transactions touching the address by height (and position in
       the block if there are more than one in a block).  Form a
       string that is the concatenation of strings 'tx_hash:height:'
       for each transaction in order.  *tx_hash* is the transaction
       hash in hexadecimal, *height* the height of the block it is in.
       Next, with mempool transactions in any order, append a string
       that is the same, but where *height* is `-1` if the transaction
       has at least one unconfirmed input, and `0` if all inputs are
       confirmed.  The *status* is the **sha256** hash of this string
       expressed as a hexadecimal string.


blockchain.block.get_header
===========================

Return the *deserialized header* [2]_ of the block at the given height.

  blockchain.block.get_header(**height**)

  **height**

    The height of the block, an integer.

**Response**

.. [2] The *deserialized header* of a block is a dictionary like
       so::

        {
            "block_height": <integer>,
            'version': <integer>,
            'prev_block_hash': <hexadecimal string>,
            'merkle_root':  <hexadecimal string>,
            'timestamp': <integer>,
            'bits': <integer>,
            'nonce': <integer>
        }


blockchain.block.get_chunk
==========================

Return a concatenated chunk of block headers.  A chunk consists of a
fixed number of block headers over which difficulty is constant, and
at the end of which difficulty is retargeted.

In the case of Bitcoin a chunk is 2,016 headers, each of 80 bytes,
and chunk 5 is the block headers from height 10,080 to 12,095
inclusive.  When encoded as hexadecimal, the response string is twice
as long, so for Bitcoin it is 322,560 bytes long, making this a
bandwidth-intensive request.

  blockchain.block.get_chunk(**index**)

  **index**

    The zero-based index of the chunk, an integer.

**Response**

    The binary block headers, as hexadecimal strings, in order
    concatenated together.


blockchain.estimatefee
======================

Return the estimated transaction fee per kilobyte for a transaction to
be confirmed within a certain number of blocks.

  blockchain.block.get_chunk(**number**)

  **number**

    The number of blocks to target for confirmation.

**Response**

  The estimated transaction fee in coin units per kilobyte, as a
  floating point number.  If the daemon does not have enough
  information to make an estimate, the integer `-1` is returned.

**Example Response**

::

  0.00101079


blockchain.headers.subscribe
============================

Subscribe to receive block headers when a new block is found.

  blockchain.headers.subscribe()

**Response**

  The *deserialized header* [2]_ of the current block.

**Notification Parameters**

  As this is a subcription, the client will receive a notification
  when a new block is found.  The parameters are:

    [**header**]


blockchain.numblocks.subscribe
==============================

Subscribe to receive the block height when a new block is found.  This
subscription is deprecated in favour of *blockchain.headers.subscribe*
which provides more detailed information.

  blockchain.numblocks.subscribe()

**Response**

  The height of the current block, an integer

**Notification Parameters**

  As this is a subcription, the client will receive a notification
  when a new block is found.  The parameters are:

    [**height**]


blockchain.relayfee
===================

Return the minimum fee a low-priority tx must pay in order to be accepted
to the daemon's memory pool.

  blockchain.relayfee()

**Response**

  The fee in coin units as a floating point number.

**Example Responses**

::

   1e-05

::

   0.0

blockchain.transaction.broadcast
================================

Broadcast a transaction to the network.

  blockchain.transaction.broadcast(**raw_tx**)

  **raw_tx**

    The raw transaction as a hexadecimal string.

**Response**

  Unfortunately the protocol version 1.0 API does not obey the JSON
  specification for the response; this will be fixed in a future
  version of the protocol.

  If the daemon accepts the transaction, return the transaction hash
  as a hexadecimal string.  If the daemon rejects the transaction, the
  server must not return an error, but instead return the error
  message string as the result.  The client needs to determine if an
  error occurred by comparing the result to the expected transaction
  hash.

**Response Examples**

::

   'a76242fce5753b4212f903ff33ac6fe66f2780f34bdb4b33b175a7815a11a98e'

::

  '258: txn-mempool-conflict'


blockchain.transaction.get
==========================

Return a raw transaction.

  blockchain.transaction.get(**tx_hash**, **height**)

  **tx_hash**

    The transaction hash as a hexadecimal string.

  **height**

    The height at which it was confirmed, an integer.  This parameter
    is optional and ignored; it is recommended that clients do not
    send it as it will be removed in a future protocol version.

**Response**

    The raw transaction as a hexadecimal string.


blockchain.transaction.get_merkle
=================================

Return the markle branch to a confirmed transaction given its hash
and height.

  blockchain.transaction.get(**tx_hash**, **height**)

  **tx_hash**

    The transaction hash as a hexadecimal string.

  **height**

    The height at which it was confirmed, an integer.

**Response**

  A dictionary with keys *block_height*, *merkle* and *pos*.
  *block_height* is the height of the block the transaction was
  confirmed in.  *merkle* is a list of transaction hashes the current
  hash is paired with, recursively, in order to trace up to obtain
  merkle root of the block, deepest pairing first.  *pos* is the
  0-based index of the position of the transaction in the ordered list
  of transactions in the block.

**Response Examples**

::

  {
    "merkle":
    [
      "713d6c7e6ce7bbea708d61162231eaa8ecb31c4c5dd84f81c20409a90069cb24",
      "03dbaec78d4a52fbaf3c7aa5d3fccd9d8654f323940716ddf5ee2e4bda458fde",
      "e670224b23f156c27993ac3071940c0ff865b812e21e0a162fe7a005d6e57851",
      "369a1619a67c3108a8850118602e3669455c70cdcdb89248b64cc6325575b885",
      "4756688678644dcb27d62931f04013254a62aeee5dec139d1aac9f7b1f318112",
      "7b97e73abc043836fd890555bfce54757d387943a6860e5450525e8e9ab46be5",
      "61505055e8b639b7c64fd58bce6fc5c2378b92e025a02583303f69930091b1c3",
      "27a654ff1895385ac14a574a0415d3bbba9ec23a8774f22ec20d53dd0b5386ff",
      "5312ed87933075e60a9511857d23d460a085f3b6e9e5e565ad2443d223cfccdc",
      "94f60b14a9f106440a197054936e6fb92abbd69d6059b38fdf79b33fc864fca0",
      "2d64851151550e8c4d337f335ee28874401d55b358a66f1bafab2c3e9f48773d"
    ],
    "block_height": 450538,
    "pos": 710
  }


blockchain.utxo.get_address
===========================

Return the address paid to by a UTXO.  This method is optional and
deprecated.

  blockchain.utxo.get_address(**tx_hash**, **index**)

  **tx_hash**

    The transaction hash as a hexadecimal string.

  **index**

    The zero-based index of the UTXO in the transaction.

**Response**

  A Base58 address string, or *null*.  If the transaction doesn't
  exist, the index is out of range, or the output is not paid to an
  address, *null* must be returned.  If the output is spent *null* may
  be returned.


server.banner
=============

Return a banner to be shown in the Electrum console.

  server.banner()

The return value is a string.


server.donation_address
=======================

Return a server donation address.

  server.donation_address()

The return value is a string.


server.peers.subscribe
======================

Return a list of peer servers.  Despite the name this is not a
subscription and the server must send no notifications.

  server.peers.subscribe()

**Response**

  An array of peer servers.  Each entry is a triple like

  ["107.150.45.210", "e.anonyhost.org", ["v1.0", "p10000", "t", "s995"]]

  The first element is the IP address, the second is the host name
  (which might also be an IP address), and the third is a list of
  server features.  Each feature and starts with a letter.  'v'
  indicates the server maximum protocol version, 'p' its pruning limit
  and is omitted if it does not prune, 't' is the TCP port number, and
  's' is the SSL port number.  If a port is not given for 's' or 't'
  the default port for the coin network is implied.  If 's' or 't' is
  missing then the server does not support that transport.


Version 1.1
-----------

This protocol version is the same as version `1.0` except for the
following changes:

* improved semantics of `server.version` to aid protocol negotiation,
  and a changed return value.
* version 1.0 methods `blockchain.address.get_proof`,
  `blockchain.utxo.get_address` and `blockchain.numblocks.subscribe`
  have been removed.
* method `blockchain.transaction.get` no longer takes the *height*
  argument that was ignored in 1.0, providing one will return an
  error.
* method `blockchain.transaction.broadcast` returns errors like any
  other JSON RPC call.  A *tx_hash* result is only returned on
  success.
* new methods `blockchain.scripthash.get_balance`,
  `blockchain.scripthash.get_history`,
  `blockchain.scripthash.get_mempool`,
  `blockchain.scripthash.listunspent`,
  `blockchain.scripthash.subscribe`,
  `server.features` and `server.add_peer`.


server.version
==============

Identify the client and inform the server the range of understood
protocol versions.

  server.version(**client_name**, **protocol_version** = ["1.1", "1.1"])

**client_name**

  An optional string identifying the connecting client software.

**protocol_verion**

  Optional with default value ["1.1", "1.1"].

  It must be a pair [`protocol_min`, `protocol_max`], each of which is
  a string.  If `protocol_min` and `protocol_max` are the same, they
  can be passed as a single string rather than as a pair of strings.

The server should use the highest protocol version both support:

  protocol_version_to_use = min(client.protocol_max, server.protocol_max)

If this is below the value

  max(client.protocol_min, server.protocol_min)

then there is no protocol version in common and the server must close
the connection.  Otherwise it should send a response appropriate for
that protocol version.

**Response**

  An array of length 2

     [<software version string>, <protocol version string>]

  identifying the server and the protocol version that will be used
  for future communication.

**Example**

::

  server.version('2.7.11', ["0.10", "1.1"])

**Example Response**

  ["ElectrumX 1.0.18", "1.1"]


blockchain.scripthash.get_balance
=================================

Return the confirmed and unconfirmed balances of a script hash.

  blockchain.scripthash.get_balance(**scripthash**)

  **scripthash**

    The script hash as a hexadecimal string.

**Response**

  As for `blockchain.address.get_balance`.


blockchain.scripthash.get_history
=================================

Return the confirmed and unconfirmed history of a script hash.

  blockchain.scripthash.get_history(**scripthash**)

  **scripthash**

    The script hash as a hexadecimal string.

**Response**

  As for `blockchain.address.get_history`.


blockchain.scripthash.get_mempool
=================================

Return the unconfirmed transactions of a script hash.

  blockchain.scripthash.get_mempool(**scripthash**)

  **scripthash**

    The script hash as a hexadecimal string.

**Response**

  As for `blockchain.address.get_mempool`.


blockchain.scripthash.listunspent
=================================

Return an ordered list of UTXOs sent to a script hash.

  blockchain.scripthash.listunspent(**scripthash**)

  **scripthash**

    The script hash as a hexadecimal string.

**Response**

  As for `blockchain.address.listunspent`.


blockchain.scripthash.subscribe
===============================

Subscribe to a script hash.

  blockchain.scripthash.subscribe(**scripthash**)

  **scripthash**

    The script hash as a hexadecimal string.

**Response**

  The *status* [1]_ of the script hash.

**Notifications**

  As this is a subcription, the client will receive a notification
  when the status of the script hash changes.  The parameters are:

    [**scripthash**, **status**]


server.add_peer
===============

This call is intended for a new server to get itself into the server's
peers list.

  server.add_peer(**features**)

  * **features**

    The same information as a call to the client server's
    **server.features** RPC call would return.


server.features
===============

Get a list of features and services supported by the server.

  server.features()

**Response**

  A dictionary of keys and values.  Each key represents a feature or
  service of the server, and the value gives additional information.

  The following features MUST be reported by the server.  Additional
  key-value pairs may be returned.

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

* **hash_function**

  The hash function the server uses for script hashing.  The client
  must use this function to hash pay-to-scripts to produce script
  hashes to send to the server.  The default is "sha256".  "sha256" is
  currently the only acceptable value.

* **server_version**

  A string that identifies the server software.  Should be the same as
  the response to **server.version** RPC call.

* **protocol_max**
* **protocol_min**

  Strings that are the minimum and maximum Electrum protocol versions
  this server speaks.  Example: "1.1".

* **pruning**

  An integer, the pruning limit.  Omit or set to *null* if there is no
  pruning limit.  Should be the same as what would suffix the letter
  **p** in the IRC real name.

**Example Response**

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

.. _JSON RPC 1.0: http://json-rpc.org/wiki/specification
.. _JSON RPC 2.0: http://json-rpc.org/specification
