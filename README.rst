.. image:: https://travis-ci.org/kyuupichan/electrumx.svg?branch=master
    :target: https://travis-ci.org/kyuupichan/electrumx
.. image:: https://coveralls.io/repos/github/kyuupichan/electrumx/badge.svg
    :target: https://coveralls.io/github/kyuupichan/electrumx

===============================================
ElectrumX - Reimplementation of electrum-server
===============================================

For a future network with bigger blocks.

  :Licence: MIT
  :Language: Python (>= 3.5.3)
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

Motivation
==========

Mainly for privacy reasons, I have long wanted to run my own Electrum
server, but I struggled to set it up or get it to work on my
DragonFlyBSD system and lost interest for over a year.

In September 2016 I heard that electrum-server databases were getting
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

- Python 3.6, which has several performance improvements relevant to
  ElectrumX
- UTXO root logic and implementation
- incremental history serving / pruning
- new features such as possibly adding label server functionality
- potentially move some functionality to C or C++


ChangeLog
=========

Version 1.0.14
--------------

- revert the changes to mempool handling of 1.0.13; I think they introduced
  a notification bug

Version 1.0.13
--------------

- improve mempool handling and height notifications
- add bitcoin-segwit as a new COIN

Version 1.0.12
--------------

- handle legacy daemons, add support for Blackcoin and Peercoin (erasmospunk)
- implement history compression; can currently only be done from a script
  with the server down
- Add dockerfile reference (followtheart)
- doc, runfile fixes (Henry, emilrus)
- add bip32 implementation, currently unused
- daemon compatibility improvements (erasmospunk)
- permit underscores in hostnames, updated Bitcoin server list

Version 1.0.11
--------------

- disable IRC for bitcoin mainnet
- remove dead code, allow custom Daemon & BlockProcessor classes (erasmospunk)
- add SERVER_(SUB)VERSION to banner metavariables (LaoDC)
- masternode methods for Dash (TheLazier)
- allow multiple P2SH address versions, implement for Litecoin (pooler)
- update Bitcoin's TX_COUNT and block height (JWU42)
- update BU nolnet parameters
- fix diagnostic typo (anduck)
- Issues fixed: `#180`_

Version 1.0.10
--------------

- add bauerj's installer docs
- segwit has activated on Litecoin.  Make segwit deserialization the
  default.  Also as the first Segwit block probably will break old
  electrum-server implementation servers, disable IRC and make
  Litecoin mainnet and testnet use the peer-discovery protocol.  If
  you previously used "testnet-segwit" as your NET you should instead
  use "testnet".

Version 1.0.9
-------------

- ignore peers not appearing in their features list
- validate hostnames in Env object
- added tests for env.py
- Einsteinium support and contrib script shebang fix (erasmospunk)
- set last_good only if successfully verified

Version 1.0.8
-------------

Minor peer-discovery tweaks:

* I intended that if a host and its IP address were both registered as
  peers, that the real hostname replace the IP address.  That wasn't
  working properly and is fixed now.
* 1.0.6 no longer required a clearnet identity but part of the peer
  discovery logic assumed one existed.  That is now fixed.

Version 1.0.7
-------------

Improvements to proxy handling and peer discovery

* background async proxy detection loop.  Removes responsibility for
  proxy detection and maintenance from the peer manager.
* peer discovery waits for an initial proxy detection attempt to complete
  before starting
* new feature: flag to force peer discovery to happen via the proxy.
  This might be useful for someone exlusively running a Tor service
  that doesn't want to reveal its IP address.  See **FORCE_PROXY** in
  `docs/ENVIRONMENT.rst`_ for details and caveats.
* other minor fixes and tweaks

Version 1.0.6
-------------

* updated to handle incompatibilities between aiohttp 1.0 and 2.0.
  ElexctrumX should work with either for now; I will drop support for
  1.0 in a few months.  Fixes `#163`_.
* relax get_chunk restrictions for clients 1.8.3 and higher.  Closes
  `#162`_.
* **REPORT_HOST** no longer defaults to **HOST**.  If not set, no
  clearnet identity will be advertised.
* Add Viacoin support (romanornr)

Version 1.0.5
-------------

* the peer looping was actually just looping of logging output, not
  connections.  Hopefully fixed for good in this release.  Closes `#160`_.

Version 1.0.4
-------------

* fix another unwanted loop in peer discovery, tweak diagnostics

Version 1.0.3
-------------

* fix a verification loop that happened occasionally with bad peers

Version 1.0.2
-------------

* stricter acceptance of add_peer requests: rate-limit onion peers,
  and require incoming requests to resolve to the requesting IP address
* validate peer hostnames (closes `#157`_)
* verify height for all peers (closes `#152`_)
* various improvements to peer handling
* various documentation tweaks
* limit the maximum number of sessions based on the process's
  open file soft limit (closes `#158`_)
* improved altcoin support for variable-length block headers and AuxPoW
  (erasmospunk) (closes `#128`_ and `#83`_)

Version 1.0.1
-------------

* Rate-limit add_peer calls in a random way
* Fix discovery of base height in reorgs
* Don't permit common but invalid REPORT_HOST values
* Set reorg limit to 8000 blocks on testnet
* dogecoin / litecoin parameter fixes (erasmospunk, pooler)
* minor doc tweaks

Version 1.0
-----------

* Minor doc tweaks only


**Neil Booth**  kyuupichan@gmail.com  https://github.com/kyuupichan

1BWwXJH3q6PRsizBkSGm2Uw4Sz1urZ5sCj


.. _#83: https://github.com/kyuupichan/electrumx/issues/83
.. _#128: https://github.com/kyuupichan/electrumx/issues/128
.. _#152: https://github.com/kyuupichan/electrumx/issues/152
.. _#157: https://github.com/kyuupichan/electrumx/issues/157
.. _#158: https://github.com/kyuupichan/electrumx/issues/158
.. _#160: https://github.com/kyuupichan/electrumx/issues/160
.. _#162: https://github.com/kyuupichan/electrumx/issues/162
.. _#163: https://github.com/kyuupichan/electrumx/issues/163
.. _#180: https://github.com/kyuupichan/electrumx/issues/180
.. _docs/HOWTO.rst: https://github.com/kyuupichan/electrumx/blob/master/docs/HOWTO.rst
.. _docs/ENVIRONMENT.rst: https://github.com/kyuupichan/electrumx/blob/master/docs/ENVIRONMENT.rst
.. _docs/PEER_DISCOVERY.rst: https://github.com/kyuupichan/electrumx/blob/master/docs/PEER_DISCOVERY.rst
