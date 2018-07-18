================
Protocol Changes
================

This documents lists changes made by protocol version.

Version 1.0
===========

Deprecated methods
------------------

  * :func:`blockchain.utxo.get_address`
  * :func:`blockchain.numblocks.subscribe`

.. _version 1.1:

Version 1.1
===========

Changes
-------

  * improved semantics of :func:`server.version` to aid protocol
    negotiation, and a changed return value.
  * :func:`blockchain.transaction.get` no longer takes the *height*
    argument that was ignored anyway.
  * :func:`blockchain.transaction.broadcast` returns errors like any
    other JSON RPC call.  A transaction hash result is only returned on
    success.

New methods
-----------

  * :func:`blockchain.scripthash.get_balance`
  * :func:`blockchain.scripthash.get_history`
  * :func:`blockchain.scripthash.get_mempool`
  * :func:`blockchain.scripthash.listunspent`
  * :func:`blockchain.scripthash.subscribe`
  * :func:`server.features`
  * :func:`server.add_peer`

Removed methods
---------------

  * :func:`blockchain.utxo.get_address`
  * :func:`blockchain.numblocks.subscribe`

.. _version 1.2:

Version 1.2
===========

Changes
-------

  * :func:`blockchain.transaction.get` now has an optional parameter
    *verbose*.
  * :func:`blockchain.headers.subscribe` now has an optional parameter
    *raw*.
  * :func:`server.version` should not be used for "ping" functionality;
    use the new :func:`server.ping` method instead.

New methods
-----------

  * :func:`blockchain.block.headers`
  * :func:`mempool.get_fee_histogram`
  * :func:`server.ping`

Deprecated methods
------------------

  * :func:`blockchain.block.get_chunk`.  Switch to
    :func:`blockchain.block.headers`
  * :func:`blockchain.address.get_balance`.  Switch to
    :func:`blockchain.scripthash.get_balance`.
  * :func:`blockchain.address.get_history`.  Switch to
    :func:`blockchain.scripthash.get_history`.
  * :func:`blockchain.address.get_mempool`.  Switch to
    :func:`blockchain.scripthash.get_mempool`.
  * :func:`blockchain.address.listunspent`.  Switch to
    :func:`blockchain.scripthash.listunspent`.
  * :func:`blockchain.address.subscribe`.  Switch to
    :func:`blockchain.scripthash.subscribe`.
  * :func:`blockchain.headers.subscribe` with *raw* other than :const:`True`.

.. _version 1.3:

Version 1.3
===========

Changes
-------

  * :func:`blockchain.headers.subscribe` argument *raw* switches default to
    :const:`True`

New methods
-----------

  * :func:`blockchain.block.header`

Removed methods
---------------

  * :func:`blockchain.address.get_balance`
  * :func:`blockchain.address.get_history`
  * :func:`blockchain.address.get_mempool`
  * :func:`blockchain.address.listunspent`
  * :func:`blockchain.address.subscribe`

Deprecated methods
------------------

  * :func:`blockchain.block.get_header`.  Switch to
    :func:`blockchain.block.header`.

.. _version 1.4:

Version 1.4
===========

This version removes all support for :ref:`deserialized headers
<deserialized header>`.

Changes
-------

  * The argument *raw* removed from :func:`blockchain.headers.subscribe`,
    only raw headers can be subscribed to.
  * Only the first :func:`server.version` message is accepted.
  * Optional *cp_height* argument added to
    :func:`blockchain.block.header` and :func:`blockchain.block.headers`

New methods
-----------

  * :func:`blockchain.transaction.id_from_pos`

Removed methods
---------------

  * :func:`blockchain.block.get_header`
  * :func:`blockchain.block.get_chunk`
