.. image:: https://travis-ci.org/kyuupichan/electrumx.svg?branch=master
    :target: https://travis-ci.org/kyuupichan/electrumx
.. image:: https://coveralls.io/repos/github/kyuupichan/electrumx/badge.svg
    :target: https://coveralls.io/github/kyuupichan/electrumx

===============================================
ElectrumX - Reimplementation of electrum-server
===============================================

For a future network with bigger blocks.

  :Licence: MIT
  :Language: Python (>= 3.6)
  :Author: Neil Booth

Getting Started
===============

See `docs/HOWTO.rst`_.
There is also an `installer`_ available that simplifies the installation on various Linux-based distributions.
There is also an `Dockerfile`_ available .

.. _installer: https://github.com/bauerj/electrumx-installer

.. _Dockerfile: https://github.com/followtheart/electrumx-docker

Features
========

- Efficient, lightweight reimplementation of electrum-server
- Fast synchronization of bitcoin mainnet from Genesis.  Recent
  hardware should synchronize in well under 24 hours.  The fastest
  time to height 448k (mid January 2017) reported is under 4h 30m.  On
  the same hardware JElectrum would take around 4 days and
  electrum-server probably around 1 month.
- The full Electrum protocol is implemented.  The only exception is
  the blockchain.address.get_proof RPC call, which is not used by
  Electrum GUI clients, and can only be invoked from the command line.
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
- Peer discovery protocol removes need for IRC
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


Roadmap
=======

- offloading more work of wallet synchronization to the client
- supporting better client privacy
- wallet server engine
- new features such as possibly adding label server functionality
- potentially move some functionality to C or C++


ChangeLog
=========

IMPORTANT: version 1.2 changes script hash indexing in the database,
so you will need to rebuild your databases from scratch.  Running this
version will refuse to open the DB and not corrupt it, so you can
revert to 1.1.x if you wish.  The initial synchronisation process
should be around 10-15% faster than 1.1, owing to this change and
Justin Arthur's optimisations from 1.1.1.

Version 1.2.1
-------------

- remove IRC support.  Most coins had empty IRC channels.  Those that
  don't have peers populated.
- use estimatesmartfee RPC call if available (SomberNight)
- new/updated coins: Emercoin (Sergii Vakula), Bitcoin Gold (erasmospunk),
  Monacoin testnet (Wakiyama P), sibcoin (53r63rn4r), Komodo and Monaize
  (cipig), Hush (Duke Leto)
- doc updates (fr3aker)
- issues fixed: `#302`_

Version 1.2
-----------

- separate P2PKH from P2PK entries in the history and UTXO databases.
  These were previously amalgamated by address as that is what
  electrum-server used to do.  However Electrum didn't handle P2PK
  spends correctly and now the protocol admits subscriptions by script
  hash there is no need to have these merged any more.

For Bitcoin (BitcoinSegwit/mainnet) you can download a leveldb database
synced up to block 490153 using this bittorrent magnet link (~24GB):
    magnet:?xt=urn:btih:caa804f48a319b061be3884ac011656c27121a6f&dn=electrumx_1.2_btc_leveldb_490153

Version 1.1.2
-------------

- PEER_DISCOVERY environment variable is now tri-state (fixes
  `#287`_).  Please check your setting as its meaning has changed
  slightly.
- fix listunspent protocol methods to remove in-mempool spends (fixes
  `#277`_).
- improved environment variable handling
- EMC2 update (cipig), Monacoin update (cryptocoin-junkey),
  Canada Ecoin (koad)
- typo fixes, Bitcoin testnet peers updates (SomberNight)

Version 1.1.1
-------------

- various refactorings, improvement of env var handling
- update docs to match
- various optimizations mainly affecting initial sync (Justin Arthur)
- Dash fixes (cipig)
- Add ALLOW_ROOT option (Luke Childs)
- Add BitZeny support, update Monacoin (cryptocoin-junkey)

Version 1.1
-----------

See the changelogs below for recent changes.  The most important is
that for mainnet bitcoin **NET** must now be *mainnet* and you must
choose a **COIN** from *BitcoinCash* and *BitcoinSegwit*.  Similarly
for testnets.  These coins will likely diverge further in future so
it's best they become separate coins now.

- no longer persist peers, rediscover on restart
- onion peers only reported if can connect; hard-coded exception removed
- small fix for blockchain.transaction.broadcast

Version 1.1pre2
---------------

- peerdisc: handle protocol 1.1 server replies
- issue `#251`_: fix protocol version reported in server.peers.subscribe
- fix handling of failed transaction broadcast
- fix typos (SomberNight)
- doc and test updates
- dash: return errors in JSON error field for protocol 1.1

Version 1.1pre1
---------------

Many changes, mostly to prepare for support of Electrum protocol 1.1
which the next Electrum client release will use.

*NOTE*: the **COIN** environment variable is now mandatory, and if you
were running for any bitcoin flavour (Cash, Segwit, mainnet or
testnet) you will need to update your **COIN** and **NET** environment
variable settings as the old ones will no longer work.

- implement protocol version 1.1 and update protocol documentation
- rework lib/coins.py for the various bitcoin flavours
- show protocol version in "sessions" ElectrumX RPC call
- permit **HOST** envvar to be a comma-separated list
- daemon abstraction refactoring (erasmospunk)
- permit alternative event loop policies (based on suggestion / work
  of JustinTArthur)
- misc configuration updates (SubPar)
- add Neblio support (neblioteam) and Bitbay (anoxxxy)
- HOWTO.rst update for running on privileged port (EagleTM)
- issues closed: exclude test dirs from installation (`#223`_).

Version 1.0.17
--------------

- fix #227 introduced in 1.0.16

Version 1.0.16
--------------

- updated server lists for post-fork.  If you are on the Segwit chain
  you should have NET be "bitcoin-segwit", and if on the Bitcoin Cash chain
  continue to use "mainnet".
- binding address fix for multi-homed machines (mmouse)
- listen to IPv4 and IPv6 local interfaces
- add Fujicoin (fujicoin), Crown (Extreemist), RegTest (RCasatta),
  Monacoin (cryptocoin-junkey)
- bug fixes and updates (Kefkius, mmouse, thesamesam, cryptocoin-junkey,
  jtarthur)

Version 1.0.15
--------------

- split server networks faster if a fork is detected
- minor speedup
- add Vertcoin support (erasmospunk)
- update Faircoin (thokon00)


**Neil Booth**  kyuupichan@gmail.com  https://github.com/kyuupichan

1BWwXJH3q6PRsizBkSGm2Uw4Sz1urZ5sCj


.. _#223: https://github.com/kyuupichan/electrumx/issues/223
.. _#251: https://github.com/kyuupichan/electrumx/issues/251
.. _#277: https://github.com/kyuupichan/electrumx/issues/277
.. _#287: https://github.com/kyuupichan/electrumx/issues/287
.. _#302: https://github.com/kyuupichan/electrumx/issues/287
.. _docs/HOWTO.rst: https://github.com/kyuupichan/electrumx/blob/master/docs/HOWTO.rst
.. _docs/ENVIRONMENT.rst: https://github.com/kyuupichan/electrumx/blob/master/docs/ENVIRONMENT.rst
.. _docs/PROTOCOL.rst: https://github.com/kyuupichan/electrumx/blob/master/docs/PROTOCOL.rst
