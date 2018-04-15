Architecture
============

.. image:: https://docs.google.com/drawings/d/1Su_DR2c8__-4phm12hAzV65fL2tNm_1IhKr4XivkW6Q/pub?w=720&h=540
    :target: https://docs.google.com/drawings/d/1Su_DR2c8__-4phm12hAzV65fL2tNm_1IhKr4XivkW6Q/pub?w=960&h=720

Env
---

Holds configuration taken from the environment, with apprioriate
defaulting appropriately.  Generally passed to the constructor of
other components which take their settings from it.

Controller
----------

The central part of the server process initialising and coordinating
all the others.  Manages resource usage.


LocalRPC
--------

Handles local JSON RPC connections querying ElectrumX server state.
Started when the ElectrumX process starts.

ElectrumX
---------

Handles JSON Electrum client connections over TCP or SSL.  One
instance per client session.  Should be the only component concerned
with the details of the Electrum wire protocol.

Not started until the Block Processor has caught up with bitcoind.

Daemon
------

Encapsulates the RPC wire protocol with bitcoind for the whole server.
Transparently handles temporary bitcoind connection errors, and fails
over if necessary.

Notifies the Mempool when the list of mempool transaction hashes is
updated.


Block Processor
---------------

Responsible for managing block chain state (UTXO set, history,
transaction and undo information) and for handling block chain
reorganisations.

When caught up, processes new blocks as they are found, and flushes
the updates to the Database immediately.

When syncing uses caches for in-memory state updates since the prior
flush.  Occasionally flushes state to the storage layer when caches
get large.

Prefetcher
----------

Cooperates with the Block Processor to asynchronously prefetch blocks
from bitcoind.  Once it has caught up it additionally asks the Daemon
to refresh its view of bitcoind's mempool transaction hashes.  Serves
blocks to the Block Processor via a queue.

Mempool
-------

Handles all the details of maintaining a representation of bitcoind's
mempool state.  Obtains the list of current mempool transaction hashes
from the Daemon when notified by the Prefetcher.

Notifies the Controller that addresses have been touched when the
mempool refreshes (or implicitly when a new block is found).

Database
--------

The underlying data store, made up of the DB backend (such as
`leveldb`) and the host filesystem.
