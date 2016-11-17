.. image:: https://travis-ci.org/kyuupichan/electrumx.svg?branch=master
    :target: https://travis-ci.org/kyuupichan/electrumx
.. image:: https://coveralls.io/repos/github/kyuupichan/electrumx/badge.svg
    :target: https://coveralls.io/github/kyuupichan/electrumx


ElectrumX - Reimplementation of Electrum-server
===============================================
::

  Licence: MIT Licence
  Author: Neil Booth
  Language: Python (>=3.5)


Getting Started
===============

See :code:`docs/HOWTO.rst`.

Motivation
==========

For privacy and other reasons, I have long wanted to run my own
Electrum server, but for reasons I cannot remember I struggled to set
it up or get it to work on my DragonFlyBSD system, and I lost interest
for over a year.

More recently I heard that Electrum server databases were around 35GB
in size when gzipped, and had sync times from Genesis of over a week
(and sufficiently painful that no one seems to have done one for a
long time) and got curious about improvements.  After taking a look at
the existing server code I decided to try a different approach.

I prefer Python3 over Python2, and the fact that Electrum is stuck on
Python2 has been frustrating for a while.  It's easier to change the
server to Python3 than the client.

It also seemed like a good way to learn about asyncio, which is a
wonderful and powerful feature of Python from 3.4 onwards.
Incidentally asyncio would also make a much better way to implement
the Electrum client.

Finally though no fan of most altcoins I wanted to write a codebase
that could easily be reused for those alts that are reasonably
compatible with Bitcoin.  Such an abstraction is also useful for
testnets, of course.


Implementation
==============

ElectrumX does not do any pruning or throwing away of history.  It
will retain this property for as long as feasible, and I believe it is
efficiently achievable for the forseeable future with plain Python.

So how does it achieve a much more compact database than Electrum
server, which is forced to prune hisory for busy addresses, and yet
sync roughly 2 orders of magnitude faster?

I believe all of the following play a part:

- aggressive caching and batching of DB writes
- more compact and efficient representation of UTXOs, address index,
  and history.  Electrum-Server stores full transaction hash and
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

Python's asyncio means ElectrumX has no (direct) use for threads and
associated complications.  I cannot foresee any case where they might
be necessary.


Roadmap Pre-1.0
===============

- minor code cleanups
- minor additions of missing functionality
- logging improvements, mostly post-sync.  Pre-sync logs seem decent.
- at most 1 more DB format change; I will make a weak attempt to
  retain 0.6 release's DB format if possible
- provision of configurable ways to limit client connections so as to
  mitigate intentional or unintentional degradation of server response
  time to other clients.  Based on IRC discussion this will likely be a
  combination of address subscription and bandwidth limits.


Roadmap Post-1.0
================

- UTXO root logic and implementation
- improve DB abstraction so LMDB is not penalized
- investigate effects of cache defaults and DB configuration defaults
  on sync time and simplify / optimize the default config accordingly
- potentially move some functionality to C or C++


Database Format
===============

The database and metadata formats of ElectrumX are likely to change.
Such changes will render old DBs unusable.  At least until 1.0 I do
not intend to provide converters; moreover from-genesis sync time to
create a pristine database is quite tolerable.


Miscellany
==========

As I've been researching where the time is going during block chain
indexing and how various cache sizes and hardware choices affect it,
I'd appreciate it if anyone trying to synchronize could tell me::

  - the version of ElectrumX
  - their O/S and filesystem
  - their hardware (CPU name and speed, RAM, and disk kind)
  - whether their daemon was on the same host or not
  - whatever stats about sync height vs time they can provide (the
    logs give it all in wall time)
  - the network (e.g. bitcoin mainnet) they synced


Neil Booth
kyuupichan@gmail.com
https://github.com/kyuupichan
1BWwXJH3q6PRsizBkSGm2Uw4Sz1urZ5sCj
