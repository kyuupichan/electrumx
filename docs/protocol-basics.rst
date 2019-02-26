Protocol Basics
===============

Message Stream
--------------

Clients and servers communicate using **JSON RPC** over an unspecified
underlying stream transport protocol, typically TCP or SSL.

Two standards `JSON RPC 1.0
<http://www.jsonrpc.org/specification_v1>`_ and `JSON RPC 2.0
<http://www.jsonrpc.org/specification>`_ are specified; use of version
2.0 is encouraged but not required.  Server support of batch requests
is encouraged for version 1.0 but not required.

.. note:: A client or server should only indicate JSON RPC 2.0 by
  setting the `jsonrpc
  <http://www.jsonrpc.org/specification#request_object>`_ member of
  its messages to ``"2.0"`` if it supports the version 2.0 protocol in
  its entirety.  ElectrumX does and will expect clients advertizing so
  to function correctly.  Those that do not will be disconnected and
  possibly blacklisted.

Clients making batch requests should limit their size depending on the
nature of their query, because servers will limit response size as an
anti-DoS mechanism.

Each RPC call, and each response, is separated by a single newline in
their respective streams.  The JSON specification does not permit
control characters within strings, so no confusion is possible there.
However it does permit newlines as extraneous whitespace between
elements; client and server MUST NOT use newlines in such a way.

If using JSON RPC 2.0's feature of parameter passing by name, the
names shown in the description of the method or notification in
question MUST be used.

A server advertising support for a particular protocol version MUST
support each method documented for that protocol version, unless the
method is explicitly marked optional.  It may support other methods or
additional parameters with unspecified behaviour.  Use of additional
parameters is discouraged as it may conflict with future versions of
the protocol.


Notifications
-------------

Some RPC calls are subscriptions which, after the initial response,
will send a JSON RPC :dfn:`notification` each time the thing
subscribed to changes.  The `method` of the notification is the same
as the method of the subscription, and the `params` of the
notification (and their names) are given in the documentation of the
method.


Version Negotiation
-------------------

It is desirable to have a way to enhance and improve the protocol
without forcing servers and clients to upgrade at the same time.

Protocol versions are denoted by dotted number strings with at least
one dot.  Examples: "1.5", "1.4.1", "2.0".  In "a.b.c" *a* is the
major version number, *b* the minor version number, and *c* the
revision number.

A party to a connection will speak all protocol versions in a range,
say from `protocol_min` to `protocol_max`, which may be the same.
When a connection is made, both client and server must initially
assume the protocol to use is their own `protocol_min`.

The client should send a :func:`server.version` RPC call as early as
possible in order to negotiate the precise protocol version; see its
description for more detail.  All responses received in the stream
from and including the server's response to this call will use its
negotiated protocol version.


.. _script hashes:

Script Hashes
-------------

A :dfn:`script hash` is the hash of the binary bytes of the locking
script (ScriptPubKey), expressed as a hexadecimal string.  The hash
function to use is given by the "hash_function" member of
:func:`server.features` (currently :func:`sha256` only).  Like for
block and transaction hashes, when converting the big-endian binary
hash to a hexadecimal string the least-significant byte appears first,
and the most-significant byte last.

For example, the legacy Bitcoin address from the genesis block::

    1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

has P2PKH script::

    76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac

with SHA256 hash::

    6191c3b590bfcfa0475e877c302da1e323497acf3b42c08d8fa28e364edf018b

which is sent to the server reversed as::

    8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161

By subscribing to this hash you can find P2PKH payments to that address.

One public key, the genesis block public key, among the trillions for
that address is::

    04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb
    649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f

which has P2PK script::

    4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb
    649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac

with SHA256 hash::

    3318537dfb3135df9f3d950dbdf8a7ae68dd7c7dfef61ed17963ff80f3850474

which is sent to the server reversed as::

    740485f380ff6379d11ef6fe7d7cdd68aea7f8bd0d953d9fdf3531fb7d531833

By subscribing to this hash you can find P2PK payments to the genesis
block public key.

.. note:: The Genesis block coinbase is uniquely unspendable and
   therefore not indexed.  It will not show with the above P2PK script
   hash subscription.


.. _status:

Status
------

To calculate the `status` of a :ref:`script hash <script hashes>` (or
address):

1. order confirmed transactions to the script hash by increasing
height (and position in the block if there are more than one in a
block)

2. form a string that is the concatenation of strings
``"tx_hash:height:"`` for each transaction in order, where:

  * ``tx_hash`` is the transaction hash in hexadecimal

  * ``height`` is the height of the block it is in.

3. Next, with mempool transactions in any order, append a similar
string for those transactions, but where **height** is ``-1`` if the
transaction has at least one unconfirmed input, and ``0`` if all
inputs are confirmed.

4. The :dfn:`status` of the script hash is the :func:`sha256` hash of the
full string expressed as a hexadecimal string, or :const:`null` if the
string is empty because there are no transactions.


Block Headers
-------------

Originally Electrum clients would download all block headers and
verify the chain of hashes and header difficulty in order to confirm
the merkle roots with which to check transaction inclusion.

With the BTC and BCH chains now past height 500,000, the headers form
over 40MB of raw data which becomes 80MB if downloaded as text from
Electrum servers.  The situation is worse for testnet and coins with
more frequent blocks.  Downloading and verifying all this data on
initial use would take several minutes, during which Electrum was
non-responsive.

To facilitate a better experience for SPV clients, particularly on
mobile, protocol :ref:`version 1.4 <version 1.4>` introduces an
optional *cp_height* argument to the :func:`blockchain.block.header`
and :func:`blockchain.block.headers` RPC calls.

This requests the server provide a merkle proof, to a single 32-byte
checkpoint hard-coded in the client, that the header(s) provided are
valid in the same way the server proves a transaction is included in a
block.  If several consecutive headers are requested, the proof is
provided for the final header - the *prev_hash* links in the headers
are sufficient to prove the others valid.

Using this feature client software only needs to download the headers
it is interested in up to the checkpoint.  Headers after the
checkpoint must all be downloaded and validated as before.  The RPC
calls return the merkle root, so to embed a checkpoint in a client
simply make an RPC request to a couple of trusted servers for the
greatest height to which a reorganisation of the chain is infeasible,
and confirm the returned roots match.

.. note:: with 500,000 headers of 80 bytes each, a naïve server
  implementation would require hashing approximately 88MB of data to
  provide a single merkle proof.  ElectrumX implements an optimization
  such that it hashes only approximately 180KB of data per proof.
