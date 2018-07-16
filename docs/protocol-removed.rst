========================
Removed Protocol Methods
========================

This documents protocol methods that are still supported in some protocol
versions, but not the most recent one.

blockchain.address.get_balance
==============================

Return the confirmed and unconfirmed balances of a bitcoin address.

**Signature**

  .. function:: blockchain.address.get_balance(address)
  .. deprecated:: 1.2 removed in version 1.3

  * *address*

    The address as a Base58 string.

**Result**

  See :func:`blockchain.scripthash.get_balance`.

blockchain.address.get_history
==============================

Return the confirmed and unconfirmed history of a bitcoin address.

**Signature**

  .. function:: blockchain.address.get_history(address)
  .. deprecated:: 1.2 removed in version 1.3

  * *address*

    The address as a Base58 string.

**Result**

  As for :func:`blockchain.scripthash.get_history`.

blockchain.address.get_mempool
==============================

Return the unconfirmed transactions of a bitcoin address.

**Signature**

  .. function:: blockchain.address.get_mempool(address)
  .. deprecated:: 1.2 removed in version 1.3

  * *address*

    The address as a Base58 string.

**Result**

  As for :func:`blockchain.scripthash.get_mempool`.

blockchain.address.listunspent
==============================

Return an ordered list of UTXOs sent to a bitcoin address.

**Signature**

  .. function:: blockchain.address.listunspent(address)
  .. deprecated:: 1.2 removed in version 1.3

  * *address*

    The address as a Base58 string.

**Result**

  As for :func:`blockchain.scripthash.listunspent`.

blockchain.address.subscribe
============================

Subscribe to a bitcoin address.

**Signature**

  .. function:: blockchain.address.subscribe(address)
  .. deprecated:: 1.2 removed in version 1.3

  *address*

    The address as a Base58 string.

**Result**

  The :ref:`status <status>` of the address.

**Notifications**

  As this is a subcription, the client will receive a notification
  when the :ref:`status <status>` of the address changes.  Its
  signature is

  .. function:: blockchain.address.subscribe(address, status)

blockchain.numblocks.subscribe
==============================

Subscribe to receive the block height when a new block is found.

**Signature**

  .. function:: blockchain.numblocks.subscribe()
  .. deprecated:: 1.0 removed in version 1.1

**Result**

  The height of the current block, an integer.

**Notifications**

  As this is a subcription, the client will receive a notification
  when a new block is found.  The notification's signature is:

    .. function:: blockchain.numblocks.subscribe(height)

blockchain.utxo.get_address
===========================

Return the address paid to by a UTXO.

**Signature**

  .. function:: blockchain.utxo.get_address(tx_hash, index)

    *Optional in version 1.0, removed in version 1.1*

  *tx_hash*

    The transaction hash as a hexadecimal string.

  *index*

    The zero-based index of the UTXO in the transaction.

**Result**

  A Base58 address string, or :const:`null`.  If the transaction
  doesn't exist, the index is out of range, or the output is not paid
  to an address, :const:`null` must be returned.  If the output is
  spent :const:`null` *may* be returned.

blockchain.block.get_header
===========================

Return the :ref:`deserialized header <deserialized header>` of the
block at the given height.

**Signature**

  .. function:: blockchain.block.get_header(height)
  .. deprecated:: 1.3 removed in version 1.4

  *height*

    The height of the block, an integer.

**Result**

  The coin-specific :ref:`deserialized header <deserialized header>`.

**Example Result**

::

  {
    "bits": 392292856,
    "block_height": 510000,
    "merkle_root": "297cfcc6a66e063692b20650d21cc0ac7a2a80f7277ebd7c5d6c7010a070d25c",
    "nonce": 3347656422,
    "prev_block_hash": "0000000000000000002292de0d9f03dfa15a04dbf09102d5d4552117b717fa86",
    "timestamp": 1519083654,
    "version": 536870912
  }

blockchain.block.get_chunk
==========================

Return a concatenated chunk of block headers from the main chain.
Typically, a chunk consists of a fixed number of block headers over
which difficulty is constant, and at the end of which difficulty is
retargeted.

In the case of Bitcoin a chunk is 2,016 headers, each of 80 bytes, so
chunk 5 consists of the block headers from height 10,080 to 12,095
inclusive.  When encoded as hexadecimal, the result string is twice as
long, so for Bitcoin it takes 322,560 bytes, making this a
bandwidth-intensive request.

**Signature**

  .. function:: blockchain.block.get_chunk(index)
  .. deprecated:: 1.2 removed in version 1.4

  *index*

    The zero-based index of the chunk, an integer.

**Result**

    The binary block headers as hexadecimal strings, in-order and
    concatenated together.  As many as headers as are available at the
    implied starting height will be returned; this may range from zero
    to the coin-specific chunk size.
