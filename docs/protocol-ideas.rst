==============
Protocol Ideas
==============

.. note:: This is a draft of ideas for a future protocol tentatively called 2.0; they are
          not implemented and it is likely they will change and that protocol 2.0 will be
          quite different.

This protocol version makes changes intended to allow clients and servers to more easily
scale to support queries about busy addresses.  It has changes to reduce the amount of
round-trip queries made in common usage, and to make results more compact to reduce
bandwidth consumption.

RPC calls with potentially large responses have pagination support, and the return value
of :func:`blockchain.scripthash.subscribe` changes.  Script hash :ref:`status <status>`
had to be recalculated with each new transaction and was undefined if it included more
than one mempool transaction.  Its calculation is linear in history length resulting in
quadratic complexity as history grows.  Its calculation for large histories was demanding
for both the server to compute and the client to check.

RPC calls and notifications that combined the effects of the mempool and confirmed history
are removed.

The changes are beneficial to clients and servers alike, but will require changes to both
client-side and server-side logic.  In particular, the client should track what block (by
hash and height) wallet data is synchronized to, and if that hash is no longer part of the
main chain, it will need to remove wallet data for blocks that were reorganized away and
get updated information as of the first reorganized block.  The effects are limited to
script hashes potentially affected by the reorg, and for most clients this will be the
empty set.


blockchain.scripthash.subscribe
===============================

Subscribe to a script hash.

**Signature**

  .. function:: blockchain_.scripthash.subscribe(scripthash)

  *scripthash*

    The script hash as a hexadecimal string.

**Result**

  .. versionchanged:: 2.0

  As of protocol 2.0, the transaction hash of the last confirmed
  transaction in blockchain order, or :const:`null` if there are none.

  For protocol versions 1.4 and below, the :ref:`status <status>` of
  the script hash.

**Notifications**

  .. versionchanged:: 2.0

  As this is a subscription, the client receives notifications when
  the confirmed transaction history and/or associated mempool
  transactions change.

  As of protocol 2.0, the initial mempool and subsequent changes to it
  are sent with :func:`mempool.changes` notifications.  When confirmed
  history changes, a notification with signature

    .. function:: blockchain_.scripthash.subscribe(scripthash, tx_hash)

  is sent, where *tx_hash* is the hash of the last confirmed
  transaction in blockchain order.


blockchain.scripthash.history
=============================

Return part of the confirmed history of a :ref:`script hash <script
hashes>`.

**Signature**

  .. function:: blockchain.scripthash.history(scripthash, start_height)

  *scripthash*

    The script hash as a hexadecimal string.

  *start_height*

    History will be returned starting from this height, a non-negative
    integer.  If there are several matching transactions in a block,
    the server will return *all* of them -- partial results from a
    block are not permitted.  The client can start subsequent requests
    at one above the greatest returned height and avoid repeats.

**Result**

  A dictionary with the following keys.

  * *more*

    :const:`true` indicates that there *may* be more history
    available.  A follow-up request is required to obtain any.
    :const:`false` means all history to blockchain's tip has been
    returned.

  * *history*

    A list ot transactions.  Each transaction is itself a list of
    two elements:

      1. The block height
      2. The transaction hash

**Result Examples**

::

  {
    "more": false,
    "history": [
      [
        200004,
        "acc3758bd2a26f869fcc67d48ff30b96464d476bca82c1cd6656e7d506816412"
      ],
      [
        215008,
        "f3e1bf48975b8d6060a9de8884296abb80be618dc00ae3cb2f6cee3085e09403"
      ]
    ]
  }


blockchain.scripthash.utxos
===========================

Return some confirmed UTXOs sent to a script hash.

**Signature**

  .. function:: blockchain.scripthash.utxos(scripthash, start_height)
  .. versionadded:: 2.0

  *scripthash*

    The script hash as a hexadecimal string.

  *start_height*

    UTXOs will be returned starting from this height, a non-negative
    integer.  If there are several UTXOs in one block, the server will
    return *all* of them -- partial results from a block are not
    permitted.  The client can start subsequent requests at one above
    the greatest returned height and avoid repeats.

.. note:: To get the effects of transactions in the mempool adding or
   removing UTXOs, a client must
   :func:`blockchain.scripthash.subscribe` and track mempool
   transactions sent via :func:`mempool.changes` notifications.

**Result**

  A dictionary with the following keys.

  * *more*

    :const:`true` indicates that there *may* be more UTXOs available.
    A follow-up request is required to obtain any.  :const:`false`
    means all UTXOs to the blockchain's tip have been returned.

  * *utxos*

    A list of UTXOs.  Each UTXO is itself a list with the following
    elements:

    1. The height of the block the transaction is in
    2. The transaction hash as a hexadecimal string
    3. The zero-based index of the output in the transaction's outputs
    4. The output value, an integer in minimum coin units (satoshis)

**Result Example**

::
  **TODO**


blockchain.transaction.get
==========================

Return a raw transaction.

**Signature**

  .. function:: blockchain_.transaction.get(tx_hash, verbose=false, merkle=false)
  .. versionchanged:: 1.1
     ignored argument *height* removed
  .. versionchanged:: 1.2
     *verbose* argument added
  .. versionchanged:: 2.0
     *merkle* argument added

  *tx_hash*

    The transaction hash as a hexadecimal string.

  *verbose*

    Whether a verbose coin-specific response is required.

  *merkle*

    Whether a merkle branch proof should be returned as well.

**Result**

    If *verbose* is :const:`false`:

       If *merkle* is :const:`false`, the raw transaction as a
       hexadecimal string.  If :const:`true`, the dictionary returned
       by :func:`blockchain.transaction.get_merkle` with an additional
       key:

       *hex*

          The raw transaction as a hexadecimal string.

    If *verbose* is :const:`true`:

       The result is a coin-specific dictionary -- whatever the coin
       daemon returns when asked for a verbose form of the raw
       transaction.  If *merkle* is :const:`true` it will have an
       additional key:

       *merkle*

          The dictionary returned by
          :func:`blockchain.transaction.get_merkle`.


mempool.changes
===============

A notification that indicates changes to unconfirmed transactions of a
:ref:`subscribed <subscribed>` :ref:`script hash <script hashes>`.  As
its name suggests the notification is stateful; its contents are a
function of what was sent previously.

**Signature**

  .. function:: mempool.changes(scripthash, new, gone)
  .. versionadded:: 2.0

  The parameters are as follows:

  * *scripthash*

    The script hash the notification is for, a hexadecimal string.

  * *new*

    A list of transactions in the mempool that have not previously
    been sent to the client, or whose *confirmed input* status
    has changed.  Each transaction is an ordered list of 3 items:

    1. The raw transaction or its hash as a hexadecimal string.  The
       first time the server sends a transaction it sends it raw.
       Subsequent references in the same *new* list or in later
       notifications will send the hash only.  Transactions cannot be
       32 bytes in size so length can be used to distinguish.
    2. The transaction fee, an integer in minimum coin units (satoshis)
    3. :const:`true` if all inputs are confirmed otherwise :const:`false`

  * *gone*

    A list of hashes of transactions that were previously sent to the
    client as being in the mempool but no longer are.  Those
    transactions presumably were confirmed in a block or were evicted
    from the mempool.

**Notification Example**

::
  **TODO**
