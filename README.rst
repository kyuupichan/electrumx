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
than Electrum server, which throws away a lot of information?  And
sync faster to boot?

All of the following likely play a part:

- more compact representation of UTXOs, the mp address index, and
  history.  Electrum server stores full transaction hash and height
  for all UTXOs.  In its pruned history it does the same.  ElectrumX
  just stores the transaction number in the linear history of
  transactions, and it looks like that for at least 5 years that will
  fit in a 4-byte integer.  ElectrumX calculates the height from a
  simple lookup in a linear array which is stored on disk.  ElectrumX
  also stores transaction hashes in a linear array on disk.
- storing static append-only metadata which is indexed by position on
  disk rather than in levelDB.  It would be nice to do this for histories
  but I cannot think how they could be easily indexable on a filesystem.
- avoiding unnecessary or redundant computations
- more efficient memory usage - through more compact data structures and
  and judicious use of memoryviews
- big caches (controlled via FLUSH_SIZE)
- asyncio and asynchronous prefetch of blocks.  With luck ElectrumX
  will have no need of threads or locking primitives
- because it prunes electrum-server needs to store undo information,
  ElectrumX should does not need to store undo information for
  blockchain reorganisations (note blockchain reorgs are not yet
  implemented in ElectrumX)
- finally electrum-server maintains a patricia tree of UTXOs.  My
  understanding is this is for future features and not currently
  required.  It's unclear precisely how this will be used or what
  could replace or duplicate its functionality in ElectrumX.  Since
  ElectrumX stores all necessary blockchain metadata some solution
  should exist.


Future/TODO
===========

- handling blockchain reorgs
- handling client connections (heh!)
- investigating leveldb space / speed tradeoffs
- seeking out further efficiencies.  ElectrumX is CPU bound; it would not
  surprise me if there is a way to cut CPU load by 10-20% more.  To squeeze
  more out would probably require some things to move to C or C++.

Once I get round to writing the server part, I will add DoS
protections if necessary to defend against requests for large
histories.  However with asyncio it would not surprise me if ElectrumX
could smoothly serve the whole history of the biggest Satoshi dice
address with minimal negative impact on other connections; we shall
have to see.  If the requestor is running Electrum client I am
confident that it would collapse under the load far more quickly that
the server would; it is very inefficeint at handling large wallets
and histories.


Database Format
===============

The database and metadata formats of ElectrumX are very likely to
change in the future.  If so old DBs would not be usable.  However it
should be easy to write short Python script to do any necessary
conversions in-place without having to start afresh.


Miscellany
==========

As I've been researching where the time is going during block chain
indexing and how various cache sizes and hardware choices affect it,
I'd appreciate it if anyone trying to synchronize could tell me their::

  - their O/S and filesystem
  - their hardware (CPU name and speed, RAM, and disk kind)
  - whether their daemon was on the same host or not
  - whatever stats about sync height vs time they can provide (the
    logs give it all in wall time)
  - the network they synced


Neil Booth
kyuupichan@gmail.com
https://github.com/kyuupichan
1BWwXJH3q6PRsizBkSGm2Uw4Sz1urZ5sCj
