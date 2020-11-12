Protocol Changes
================

This documents lists changes made by protocol version.

Version 1.0
===========

Deprecated methods
------------------

  * `blockchain.utxo.get_address`
  * `blockchain.numblocks.subscribe`

Version 1.1
===========

Changes
-------

  * improved semantics of `server.version` to aid protocol
    negotiation, and a changed return value.
  * `blockchain.transaction.get` no longer takes the *height*
    argument that was ignored anyway.
  * `blockchain.transaction.broadcast` returns errors like any
    other JSON RPC call.  A transaction hash result is only returned on
    success.

New methods
-----------

  * `blockchain.scripthash.get_balance`
  * `blockchain.scripthash.get_history`
  * `blockchain.scripthash.get_mempool`
  * `blockchain.scripthash.listunspent`
  * `blockchain.scripthash.subscribe`
  * `server.features`
  * `server.add_peer`

Removed methods
---------------

  * `blockchain.utxo.get_address`
  * `blockchain.numblocks.subscribe`

Version 1.2
===========

Changes
-------

  * `blockchain.transaction.get` now has an optional parameter
    *verbose*.
  * `blockchain.headers.subscribe` now has an optional parameter
    *raw*.
  * `server.version` should not be used for "ping" functionality;
    use the new `server.ping` method instead.

New methods
-----------

  * `blockchain.block.headers`
  * `mempool.get_fee_histogram`
  * `server.ping`

Deprecated methods
------------------

  * `blockchain.block.get_chunk`.  Switch to
    `blockchain.block.headers`
  * `blockchain.address.get_balance`.  Switch to
    `blockchain.scripthash.get_balance`.
  * `blockchain.address.get_history`.  Switch to
    `blockchain.scripthash.get_history`.
  * `blockchain.address.get_mempool`.  Switch to
    `blockchain.scripthash.get_mempool`.
  * `blockchain.address.listunspent`.  Switch to
    `blockchain.scripthash.listunspent`.
  * `blockchain.address.subscribe`.  Switch to
    `blockchain.scripthash.subscribe`.
  * `blockchain.headers.subscribe` with *raw* other than `True`.

Version 1.3
===========

Changes
-------

  * `blockchain.headers.subscribe` argument *raw* switches default to
    `True`

New methods
-----------

  * `blockchain.block.header`

Removed methods
---------------

  * `blockchain.address.get_balance`
  * `blockchain.address.get_history`
  * `blockchain.address.get_mempool`
  * `blockchain.address.listunspent`
  * `blockchain.address.subscribe`

Deprecated methods
------------------

  * `blockchain.block.get_header`.  Switch to
    `blockchain.block.header`.

Version 1.4
===========

This version removes all support for deserialized headers.

Changes
-------

  * Deserialized headers are no longer available, so removed argument
    *raw* from `blockchain.headers.subscribe`.
  * Only the first `server.version` message is accepted.
  * Optional *cp_height* argument added to
    `blockchain.block.header` and `blockchain.block.headers`
    to return merkle proofs of the header to a given checkpoint.

New methods
-----------

  * `blockchain.transaction.id_from_pos` to return a transaction
    hash, and optionally a merkle proof, given a block height and
    position in the block.

Removed methods
---------------

  * `blockchain.block.get_header`
  * `blockchain.block.get_chunk`

Version 1.4.1
=============

Changes
-------

  * `blockchain.block.header` and `blockchain.block.headers` now
    truncate AuxPoW data (if using an AuxPoW chain) when *cp_height* is
    nonzero.  AuxPoW data is still present when *cp_height* is zero.
    Non-AuxPoW chains are unaffected.


Version 1.4.1
=============

New methods
-----------

  * `blockchain.scipthash.unsubscribe` to unsubscribe from a script hash.


Version 2.0
=============

Changes
-------

  * `blockchain.scripthash.get_balance` -
    added `alert_incoming` and `alert_outgoing` balances
  * `blockchain.scripthash.get_history` - added `tx_type` to each transaction
  * `blockchain.scripthash.get_mempool` - added `tx_type` to each transaction
  * `blockchain.scripthash.listunspent` - added `spend_tx_num`
