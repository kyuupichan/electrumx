.. image:: https://travis-ci.org/kyuupichan/electrumx.svg?branch=master
    :target: https://travis-ci.org/kyuupichan/electrumx
.. image:: https://coveralls.io/repos/github/kyuupichan/electrumx/badge.svg
    :target: https://coveralls.io/github/kyuupichan/electrumx

===============================================
ElectrumX - Reimplementation of electrum-server
===============================================

  :Licence: MIT
  :Language: Python (>= 3.5)
  :Author: Neil Booth

Getting Started
===============

See `docs/HOWTO.rst`_.

Motivation
==========

Mainly for privacy reasons, I have long wanted to run my own Electrum
server, but I struggled to set it up or get it to work on my
DragonFlyBSD system and lost interest for over a year.

In September 2015 I heard that electrum-server databases were getting
large (35-45GB when gzipped), and it would take several weeks to sync
from Genesis (and was sufficiently painful that no one seems to have
done it for about a year).  This made me curious about improvements
and after taking a look at the code I decided to try a different
approach.

I prefer Python3 over Python2, and the fact that Electrum is stuck on
Python2 has been frustrating for a while.  It's easier to change the
server to Python3 than the client, so I decided to write my effort in
Python3.

It also seemed like a good opportunity to learn about asyncio, a
wonderful and powerful feature introduced in Python 3.4.
Incidentally, asyncio would also make a much better way to implement
the Electrum client.

Finally though no fan of most altcoins I wanted to write a codebase
that could easily be reused for those alts that are reasonably
compatible with Bitcoin.  Such an abstraction is also useful for
testnets.

Features
========

- The full Electrum protocol is implemented.  The only exception is
  the blockchain.address.get_proof RPC call, which is not used by
  Electrum GUI clients, and can only be invoked from the command line.
- Efficient synchronization from Genesis.  Recent hardware should
  synchronize in well under 24 hours, possibly much faster for recent
  CPUs or if you have an SSD.  The fastest time to height 439k (mid
  November 2016) reported is under 5 hours.  For comparison, JElectrum
  would take around 4 days, and electrum-server probably around 1
  month, on the same hardware.
- Various configurable means of controlling resource consumption and
  handling denial of service attacks.  These include maximum
  connection counts, subscription limits per-connection and across all
  connections, maximum response size, per-session bandwidth limits,
  and session timeouts.
- Minimal resource usage once caught up and serving clients; tracking the
  transaction mempool appears to be the most expensive part.
- Fully asynchronous processing of new blocks, mempool updates, and
  client requests.  Busy clients should not noticeably impede other
  clients' requests and notifications, nor the processing of incoming
  blocks and mempool updates.
- Daemon failover.  More than one daemon can be specified, and
  ElectrumX will failover round-robin style if the current one fails
  for any reason.
- Coin abstraction makes compatible altcoin and testnet support easy.

Implementation
==============

ElectrumX does not do any pruning or throwing away of history.  I want
to retain this property for as long as it is feasible, and it appears
efficiently achievable for the forseeable future with plain Python.

The following all play a part in making ElectrumX very efficient as a
Python blockchain indexer:

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

Python's ``asyncio`` means ElectrumX has no (direct) use for threads
and associated complications.


Roadmap Pre-1.0
===============

- minor code cleanups.
- implement simple protocol to discover peers without resorting to IRC.

Roadmap Post-1.0
================

- Python 3.6, which has several performance improvements relevant to
  ElectrumX
- UTXO root logic and implementation
- potentially move some functionality to C or C++


Database Format
===============

The database format of ElectrumX is unlikely to change from the 0.10.0
version prior to the release of 1.0.


ChangeLog
=========

Version 0.10.16
---------------

* disable batch notifications; unintentionally enabled in a prior version

Version 0.10.15
---------------

* Force JSONRPCv2 for backwards compat with Coinomi wallets that don't
  speak JSON RPCv1 properly.  This will only be forced for a few
  months to give Coinomi users a chance to upgrade.
* Basic sanity check on IRC reported settings (closes `#110`_)
* Add an RPC interface to set **DAEMON_URL** at run-time and switch back
  to the primary daemon (closes `#111`_)

Version 0.10.14
---------------

* misc cleanups and code changes to prepare for peer discovery in 0.11.0
* add `docs/PEER_DISCOVERY.rst`_

Version 0.10.13
---------------

* worked around asyncio issue to suppress the annoying log spew on shutdown
  that makes it look like a bomb hit
* implement peer subscriptions as real subscriptions with incremental updates
* misc cleanups

Version 0.10.12
---------------

* fixed a bug in 0.10.11 where a dict changed whilst iterating it

Version 0.10.11
---------------

* rewrite of JSON RPC layer to improve usability for clients.
  Includes support of JSON RPC v1, v2 and a compat layer that tries to
  detect the peer's version.

Version 0.10.10
---------------

* move peer management from irc.py to peers.py.  This is preparataion
  for peer discovery without IRC.
* misc cleanups
* fix Litecoin genesis hash (petrkr)

Version 0.10.9
--------------

* restore client to sessions output
* cleanup shutdown process; hopefully this resolves the log spew for good

Version 0.10.8
--------------

* fix import for reverse iterator for RocksDB
* fix tests

Version 0.10.7
--------------

* remove LMDB
* turn on snappy compression for LevelDB and RocksDB; gives smaller DBs and
  faster sync
* fix and speed up RocksDB iterator slightly
* expect JSON with bitcoind HTTP status code 500

Version 0.10.6
--------------

* fix for rest of second part of issue `#100`_
* check HTTP error codes from bitcoind and log appropriately
* don't error opening a new DB that has nothing written yet

Version 0.10.5
--------------

* fix for some of second part of issue `#100`_ where the ElectrumX was not
  killable if bitcoind was unavailable


Version 0.10.4
--------------

* Named argument handling as per JSON RPC 2.0 (issue `#99`_).  This
  takes argument names from the Python RPC handlers, and paves the way
  for creating help output automatically from the handler docstrings
* Write reorg undo info with the UTXO flushes (issue `#101`_)

Version 0.10.3
--------------

* Add an RPC call to force a reorg at run-time, issue `#103`_
* Make flushes and reorgs async, issue `#102`_
* add Argentum and Digibyte support to coins.py (protonn)

Version 0.10.2
--------------

* The **NETWORK** environment variable was renamed **NET** to bring it
  into line with lib/coins.py.
* The genesis hash is now compared with the genesis hash expected by
  **COIN** and **NET**.  This sanity check was not done previously, so
  you could easily be syncing to a network daemon different to what
  you thought.
* SegWit-compatible testnet support for bitcoin core versions 0.13.1
  or higher.  Resolves issue `#92`_.  Testnet worked with prior
  versions of ElectrumX as long as you used an older bitcoind too,
  such as 0.13.0 or Bitcoin Unlimited.

  **Note**: for testnet, you need to set **NET** to *testnet-segwit*
  if using a recent Core bitcoind that broke RPC compatibility, or
  *testnet* if using a bitcoind that maintains RPC compatibility.
  Changing **NET** for Bitcoin testnet can be done dynamically; it is
  not necessary to resync from scratch.

Version 0.10.1
--------------

* Includes what should be a fix for issue `#94`_ - stale references to
  old sessions.  This would effectively memory and network handles.

Version 0.10.0
--------------

* Major rewrite of DB layer as per issue `#72`_.  UTXOs and history
  are now indexed by the hash of the pay to script, making the index
  independent of the address scheme.
* The history and UTXO DBs are also now separate.

Together these changes reduce the size of the DB by approximately 15%
and the time taken to sync from genesis by about 20%.

Note the **UTXO_MB** and **HIST_MB** environment variables have been
removed and replaced with the single environment variable
**CACHE_MB**.  I suggest you set this to 90% of the sum of the old
variables to use roughly the same amount of memory.

For now this code should be considered experimental; if you want
stability please stick with the 0.9 series.


**Neil Booth**  kyuupichan@gmail.com  https://github.com/kyuupichan

1BWwXJH3q6PRsizBkSGm2Uw4Sz1urZ5sCj


.. _#72: https://github.com/kyuupichan/electrumx/issues/72
.. _#92: https://github.com/kyuupichan/electrumx/issues/92
.. _#94: https://github.com/kyuupichan/electrumx/issues/94
.. _#99: https://github.com/kyuupichan/electrumx/issues/99
.. _#100: https://github.com/kyuupichan/electrumx/issues/100
.. _#101: https://github.com/kyuupichan/electrumx/issues/101
.. _#102: https://github.com/kyuupichan/electrumx/issues/102
.. _#103: https://github.com/kyuupichan/electrumx/issues/103
.. _#110: https://github.com/kyuupichan/electrumx/issues/110
.. _#111: https://github.com/kyuupichan/electrumx/issues/111
.. _docs/HOWTO.rst: https://github.com/kyuupichan/electrumx/blob/master/docs/HOWTO.rst
.. _docs/PEER_DISCOVERY.rst: https://github.com/kyuupichan/electrumx/blob/master/docs/PEER_DISCOVERY.rst
