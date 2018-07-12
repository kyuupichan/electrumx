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
  .. deprecated:: 1.2
     *Removed in version 1.3.*

  * *address*

    The address as a Base58 string.

**Result**

  See :func:`blockchain.scripthash.get_balance`.

blockchain.address.get_history
==============================

Return the confirmed and unconfirmed history of a bitcoin address.

**Signature**

  .. function:: blockchain.address.get_history(address)
  .. deprecated:: 1.2
     *Removed in version 1.3.*

  * *address*

    The address as a Base58 string.

**Result**

  As for :func:`blockchain.scripthash.get_history`.

blockchain.address.get_mempool
==============================

Return the unconfirmed transactions of a bitcoin address.

**Signature**

  .. function:: blockchain.address.get_mempool(address)
  .. deprecated:: 1.2
     *Removed in version 1.3.*

  * *address*

    The address as a Base58 string.

**Result**

  As for :func:`blockchain.scripthash.get_mempool`.

blockchain.address.listunspent
==============================

Return an ordered list of UTXOs sent to a bitcoin address.

**Signature**

  .. function:: blockchain.address.listunspent(address)
  .. deprecated:: 1.2
     *Removed in version 1.3.*

  * *address*

    The address as a Base58 string.

**Result**

  As for :func:`blockchain.scripthash.listunspent`.

blockchain.address.subscribe
============================

Subscribe to a bitcoin address.

**Signature**

  .. function:: blockchain.address.subscribe(address)
  .. deprecated:: 1.2
     *Removed in version 1.3.*

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
  .. deprecated:: 1.0
     *Removed in version 1.1.*

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

  *Optional in version 1.0.  Removed in version 1.1.*

  *tx_hash*

    The transaction hash as a hexadecimal string.

  *index*

    The zero-based index of the UTXO in the transaction.

**Result**

  A Base58 address string, or :const:`null`.  If the transaction
  doesn't exist, the index is out of range, or the output is not paid
  to an address, :const:`null` must be returned.  If the output is
  spent :const:`null` *may* be returned.
