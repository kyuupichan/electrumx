.. image:: https://travis-ci.org/kyuupichan/electrumx.svg?branch=master
    :target: https://travis-ci.org/kyuupichan/electrumx
.. image:: https://coveralls.io/repos/github/kyuupichan/electrumx/badge.svg
    :target: https://coveralls.io/github/kyuupichan/electrumx

===============================================
ElectrumX - Reimplementation of electrum-server
===============================================
::

  Licence: MIT
  Author: Neil Booth
  Language: Python (>=3.5)

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
- support bitcoin testnet with Satoshi bitcoind 0.13.1
- implement simple protocol to discover peers without resorting to IRC.
  This may slip to post 1.0


Roadmap Post-1.0
================

- Python 3.6, which has several performance improvements relevant to
  ElectrumX
- UTXO root logic and implementation
- improve DB abstraction so LMDB is not penalized
- investigate effects of cache defaults and DB configuration defaults
  on sync time and simplify / optimize the default config accordingly
- potentially move some functionality to C or C++


Database Format
===============

The database format of ElectrumX is unlikely to change from the 0.10.0
version prior to the release of 1.0.


ChangeLog
=========

Version 0.10.0
--------------

Major rewrite of DB layer as per issue `#72`_.  UTXOs and history are
now indexed by the hash of the pay to script, making the index
independent of the address scheme.  The history and UTXO DBs are also
now separate.

Together these changes reduce the size of the DB by approximately 15%
and the time taken to sync from genesis by about 20%.

Note the **UTXO_MB** and **HIST_MB** environment variables have been
removed and replaced with the single environment variable
**CACHE_MB**.  I suggest you set this to 90% of the sum of the old
variables to use roughly the same amount of memory.

For now this code should be considered experimental; if you want
stability please stick with the 0.9 series.

Version 0.9.22
--------------

* documentation updates (ARCHITECTURE.rst, ENVIRONMENT.rst) only.

Version 0.9.21
--------------

* moved RELEASE-NOTES into this README
* document the RPC interface in docs/RPC-INTERFACE.rst
* clean up open DB handling, issue `#89`_

Version 0.9.20
--------------

* fix for IRC flood issue `#93`_

Version 0.9.19
--------------

* move sleep outside semaphore (issue `#88`_)

Version 0.9.18
--------------

* last release of 2016.  Just a couple of minor tweaks to logging.

Version 0.9.17
--------------

* have all the DBs use fsync on write; hopefully means DB won't corrupt in
  case of a kernel panic (issue `#75`_)
* replace $DONATION_ADDRESS in banner file

Version 0.9.16
--------------

* logging improvements, including throttling of abusive logs
* permit large RPC requests (issue 85)

Version 0.9.15
--------------

* fix crash on reorg, issue #84

Version 0.9.14
--------------

* don't start processing mempool until block processor has caught up.
  Print server settings when servers start, not at startup.

Version 0.9.13
--------------

* fix to reduce verbosity of logging of deprioritised sessions.  Sessions
  are deprioritised if they are using high bandwidth, or if they are part
  of a group using high bandwidth.  Previously each delayed request scheduling
  would be logged, now only changes in the delay (up or down) are logged.

Version 0.9.12
--------------

* enchancements to RPC and logging.  getinfo output has changed, a couple
  of fields renamed.
  issue 77: add PID to getinfo
  issue 78: start RPC immediately, don't wait for catch-up
  issue 79: show IPv6 address-port combinations properly in []
  issue 80: show DB and daemon heights in getinfo

Version 0.9.11
--------------

* rework the fetch-and-process blocks loop.  This regains some of the
  sync efficiency we lost during 0.8.x and that was poorly hacked
  around earlier in 0.9.x.  Continuing to investigate where the rest
  went.
* logging of block processing times fixes #58
* moved the peer column to the end of the sessions RPC so that IPv6 addrs
  don't mess up the formatting

Version 0.9.10
--------------

* logging improvements
* fixed issue #76 (RPCError namespace)

Version 0.9.9
-------------

* prioritize mempool processing of sent txs.  Closes issue 73.
* mempool tx processing needs to handle DBError exceptions.  Fixes issue 74.

Version 0.9.8
-------------

* cleanup up mempool handling, notify of addresses only once when a new block
  comes in.  Fixes issue 70.

Version 0.9.7
-------------

* history and UTXO requests are now processed by the executor, i.e.,
  properly asynchronously.  This was the last of the potential latency
  bottlenecks.

Version 0.9.6
-------------

* fix it properly this time

Version 0.9.5
-------------

* fix issue introduced in 0.9.4 with paused connections

Version 0.9.4
-------------

* new env var MAX_SESSIONS, see docs/ENV-NOTES.  The default limit is
  1,000 sessions so raise this if you want to be able to take more.
* a couple of minor bug fixes relating to paused connections
* removed RPC calls numsessions and numpeers.  They're not very interesting
  and all that and more is in getinfo.

Version 0.9.3
-------------

* unconfirmed flag indicating whether mempool txs have unconfirmed inputs
  was inverted

Version 0.9.2
-------------

* fix mempool busy waiting

Version 0.9.1
-------------

* fix another couple of issues introduced in 0.9.0

Version 0.9.0a
--------------

* fix typo in 0.9.0

Version 0.9.0
-------------

* complete rewrite of mempool code to have minimal latency and fix a
  couple of minor bugs.  When a new block is found, ideally this
  should be communicated to clients who addresses are affected with a
  single notification.  Previously this would happen with two
  notifications: one because the TX got in the block, and one because
  that TX was no longer in the mempool.  Fundamentally this a race
  condition that cannot be eliminated but its occurrence should be
  minimized.


**Neil Booth**  kyuupichan@gmail.com  https://github.com/kyuupichan

1BWwXJH3q6PRsizBkSGm2Uw4Sz1urZ5sCj


.. _#72: https://github.com/kyuupichan/electrumx/issues/72
.. _#75: https://github.com/kyuupichan/electrumx/issues/75
.. _#88: https://github.com/kyuupichan/electrumx/issues/88
.. _#89: https://github.com/kyuupichan/electrumx/issues/89
.. _#93: https://github.com/kyuupichan/electrumx/issues/93
.. _docs/HOWTO.rst: https://github.com/kyuupichan/electrumx/blob/master/docs/HOWTO.rst
