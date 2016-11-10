Components
==========

The components of the server are roughly like this::

   -------
   - Env -
   -------

     -------
     - IRC -
     -------
            <
             -------------     ------------
             - ElectrumX -<<<<<- LocalRPC -
             -------------     ------------
              <      >
    ----------        -------------------
    - Daemon -<<<<<<<<- Block processor -
    ----------        -------------------
        <              <               >
         --------------                 -----------
         - Prefetcher -                 - FS + DB -
         --------------                 -----------


Env
---

Holds configuration taken from the environment.  Handles defaults
appropriately.  Generally passed to the constructor of other
components which take their settings from it.


LocalRPC
--------

Handles local JSON RPC connections querying ElectrumX server state.
Not started until the block processor has caught up with the daemon.

ElectrumX
---------

Handles JSON Electrum client connections over TCP or SSL.  One
instance per client session.  Should be the only component concerned
with the details of the Electrum wire protocol.  Responsible for
caching of client responses.  Not started until the block processor
has caught up with the daemon.  Logically, if not yet in practice, a
coin-specific class.

Daemon
------

Used by the block processor, ElectrumX servers and prefetcher.
Encapsulates daemon RPC wire protcol.  Logically, if not yet in
practice, a coin-specific class.

Block Processor
---------------

Responsible for managing block chain state (UTXO set, history,
transaction and undo information) and processing towards the chain
tip.  Uses the caches for in-memory state updates since the last
flush.  Flushes state to the storage layer.  Reponsible for handling
block chain reorganisations.  Once caught up maintains a
representation of daemon mempool state.

Database
--------

The database.  Along with the host filesystem stores flushed chain state.

Prefetcher
----------

Used by the block processor to asynchronously prefetch blocks from the
daemon.  Holds fetched block height.  Once it has caught up
additionally obtains daemon mempool tx hashes.  Serves blocks and
mempool hashes to the block processor via a queue.

IRC
---

Not currently imlpemented; will handle IRC communication for the
ElectrumX servers.
