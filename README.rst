.. image:: https://travis-ci.org/kyuupichan/electrumx.svg?branch=master
    :target: https://travis-ci.org/kyuupichan/electrumx

ElectrumX - Reimplementation of Electrum-server
===============================================
::

  Licence: MIT Licence
  Author: Neil Booth
  Language: Python (>=3.5)


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

ElectrumX does not currently do any pruning.  With luck it may never
become necessary.  So how does it achieve a much more compact database
than Electrum server, which prunes a lot of hisory, and also sync
faster?

All of the following likely play a part:

- aggressive caching and batching of DB writes
- more compact representation of UTXOs, the address index, and
  history.  Electrum server stores full transaction hash and height
  for all UTXOs.  In its pruned history it does the same.  ElectrumX
  just stores the transaction number in the linear history of
  transactions.  For at least another 5 years the transaction number
  will fit in a 4-byte integer.  ElectrumX calculates the height from
  a simple lookup in a linear array which is stored on disk.
  ElectrumX also stores transaction hashes in a linear array on disk.
- storing static append-only metadata which is indexed by position on
  disk rather than in levelDB.  It would be nice to do this for histories
  but I cannot think how they could be easily indexable on a filesystem.
- avoiding unnecessary or redundant computations
- more efficient memory usage
- asyncio and asynchronous prefetch of blocks.  ElectrumX should not
  have any need of threads.


Roadmap
=======

- test a few more performance improvement ideas
- implement light caching of client responses
- yield during expensive requests and/or penalize the connection
- improve DB abstraction so LMDB is not penalized
- continue to clean up the code and remove layering violations
- store all UTXOs, not just those with addresses
- implement IRC connectivity
- potentially move some functionality to C or C++

The above are in no particular order.


Database Format
===============

The database and metadata formats of ElectrumX are certain to change
in the future.  Such a change will render old DBs unusable.  For now I
do not intend to provide converters as this is still non-production
software.  Moreover from-genesis sync time is quite bearable.


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
