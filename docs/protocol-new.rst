Electrum Protocol
=================

This is intended to be a reference for client and server authors
alike.


Message Stream
--------------

Clients and servers communicate using **JSON RPC** over an unspecified
underlying stream transport protocol, typically TCP or SSL.

`JSON RPC 1.0 <http://www.jsonrpc.org/specification_v1>` and `JSON RPC
2.0 <http://www.jsonrpc.org/specification>` are specified; use of
version 2.0 is encouraged but not required.  Server support of batch
requests is encouraged for version 1.0 but not required.  Clients
making batch requests should limit their size depending on the nature
of their query, because servers will limit response size as an
anti-DoS mechanism.

Eeach RPC call, and each response, is separated by a single newline in
their respective streams.  The JSON specification does not permit
control characters within strings, so no confusion is possible there.
However it does permit newlines as extraneous whitespace between
elements; client and server MUST NOT use newlines in such a way.

If using JSON RPC 2.0's feature of parameter passing by name, the
names shown in the description of the method in question MUST be used.

A server advertising support for a particular protocol version MUST
support each method documented for that protocol version, unless the
method is explicitly marked optional.  It may support other methods or
additional parameters with unspecified behaviour.  Use of additional
parameters is discouraged as it may conflict with future versions of
the protocol.


Notifications
-------------

Some RPC calls are subscriptions, which, after the initial response,
will send a :dfn:`notification` each time the thing subscribed to
changes.  The `method` of the notification is the same as the method
of the subscription, and the `params` of the notification (and their
names) are given in the documentation of the method.


Protocol Negotiation
--------------------

It is desirable to have a way to enhance and improve the protocol
without forcing servers and clients to upgrade at the same time.
Protocol negotiation is not implemented in any client or server at
present to the best of my knowledge, so care is needed to ensure
current clients and servers continue to operate as expected.

Protocol versions are denoted by dotted "a.b" strings, where *m* is
the major version number and *n* the minor version number.  For
example: "1.5".

A party to a connection will speak all protocol versions in a range,
say from `protocol_min` to `protocol_max`, which may be the same.
When a connection is made, both client and server must initially
assume the protocol to use is their own `protocol_min`.

The client should send a :func:`server.version` RPC call as early as
possible in order to negotiate the precise protocol version; see its
description for more detail.  All responses received in the stream
from and including the server's response to this call will use the
negotiated protocol version.


Script Hashes
-------------

A :defn:`script hash` is the hash of the binary bytes of the locking
script (ScriptPubKey), expressed as a hexadecimal string.  The hash
function to use is given by the "hash_function" member of
:func:`server.features` (currently "sha256" only).  Like for block and
transaction hashes, when converting the big-endian binary hash to a
hexadecimal string the least-significant byte appears first, and the
most-significant byte last.

For example, the legacy Bitcoin address from the genesis block::

    1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

has P2PKH script::

    76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac

with SHA256 hash::

    6191c3b590bfcfa0475e877c302da1e323497acf3b42c08d8fa28e364edf018b

which is sent to the server reversed as::

    8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161

By subscribing to this hash you can find P2PKH payments to that address.

One public key for that address (the genesis block public key) is::

    04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb
    649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f

which has P2PK script::

    4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb
    649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac

with SHA256 hash::

    3318537dfb3135df9f3d950dbdf8a7ae68dd7c7dfef61ed17963ff80f3850474

which is sent to the server reversed as::

    740485f380ff6379d11ef6fe7d7cdd68aea7f8bd0d953d9fdf3531fb7d531833

By subscribing to this hash you can find P2PK payments to that public
key.

.. note:: The Genesis block coinbase is unspendable and therefore not
indexed.  It will not show with the above P2PK script hash subscription.


.. toctree::
   :maxdepth: 1
   :caption: Methods:

   mempool_fee_get_histogram
