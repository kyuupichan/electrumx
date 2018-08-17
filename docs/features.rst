Features
========

- Efficient, lightweight reimplementation of electrum-server
- Fast synchronization of bitcoin mainnet from Genesis.  Recent
  hardware should synchronize in well under 24 hours.  The fastest
  time to height 448k (mid January 2017) reported is under 4h 30m.  On
  the same hardware JElectrum would take around 4 days and
  electrum-server probably around 1 month.
- Various configurable means of controlling resource consumption and
  handling bad clients and denial of service attacks.  These include
  maximum connection counts, subscription limits per-connection and
  across all connections, maximum response size, per-session bandwidth
  limits, and session timeouts.
- Minimal resource usage once caught up and serving clients; tracking the
  transaction mempool appears to be the most expensive part.
- Mostly asynchronous processing of new blocks, mempool updates, and
  client requests.  Busy clients should not noticeably impede other
  clients' requests and notifications, nor the processing of incoming
  blocks and mempool updates.
- Daemon failover.  More than one daemon can be specified, and
  ElectrumX will failover round-robin style if the current one fails
  for any reason.
- Peer discovery protocol removes need for IRC
- Coin abstraction makes compatible altcoin and testnet support easy.

Implementation
==============

ElectrumX does not do any pruning or throwing away of history.  I want
to retain this property for as long as it is feasible, and it appears
efficiently achievable for the forseeable future with plain Python.

The following all play a part in making it efficient as a Python
blockchain indexer:

- aggressive caching and batching of DB writes
- more compact and efficient representation of UTXOs, address index,
  and history.  Electrum Server stores full transaction hash and
  height for each UTXO, and does the same in its pruned history.  In
  contrast ElectrumX just stores the transaction number in the linear
  history of transactions.  For at least another 5 years this
  transaction number will fit in a 4-byte integer, and when necessary
  expanding to 5 or 6 bytes is trivial.  ElectrumX can determine block
  height from a simple binary search of tx counts stored on disk.
  ElectrumX stores historical transaction hashes in a linear array on
  disk.
- placing static append-only metadata indexable by position on disk
  rather than in levelDB.  It would be nice to do this for histories
  but I cannot think of a way.
- avoiding unnecessary or redundant computations, such as converting
  address hashes to human-readable ASCII strings with expensive bignum
  arithmetic, and then back again.
- better choice of Python data structures giving lower memory usage as
  well as faster traversal
- leveraging asyncio for asynchronous prefetch of blocks to mostly
  eliminate CPU idling.  As a Python program ElectrumX is unavoidably
  single-threaded in its essence; we must keep that CPU core busy.

Python's :mod:`asyncio` means ElectrumX has no (direct) use for threads
and associated complications.

Roadmap
=======

* break ElectrumX up into simple services that initially can be run in
  separate processes on a single host.  Then support running them on
  different hosts, and finally support sharding.  With this we can
  take advantage of multiple cores and hosts, and scale to much larger
  block sizes.  This should solve several issues with the current
  history storage mechanism.
* fully asynchronous operation.  At present too much is synchronous, such
  as file system access.
* protocol improvements targeting better client and server scalability
  to large wallets (100k addresses) and address histories.  Some
  aspects of the current protocol are very inefficient.
* investigate speaking the Bitcoin protocol and connecting to the
  Bitcoin network directly for some queries.  This could lead to
  ElectrumX being runnable with a node without a tx index, or a
  pruning node, or not needing to run a node at all.  ElectrumX would
  store all blocks itself and index the transactions therein.
* lifting internal limits such as maximum 4 billion transactions
* supporting better user privacy.  I believe significantly improved
  user address privacy might be possible with a simple addition to the
  protocol, and assuming a server network of which a reasonable
  fraction (40%?) are cooperative and non-colluding
* new features such as possibly adding label or wallet server
  functionality
