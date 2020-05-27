===========
 ChangeLog
===========

.. note:: Version 1.15.0 will be the final ElectrumX release with altcoin support, future
   releases will be Bitcoin-only.  ElectrumX needs to scale quickly and support for
   various other coins and their idiosyncracies is distracting and unhelpful.  Anyone
   wishing to maintain an ElectrumX repository with altcoin support is free to do so as
   explained in the licence.

.. note:: It is strongly recommended you upgrade to Python 3.7, which
   fixes bugs in asyncio that caused an ever-growing open file count
   and memory consumption whilst serving clients.  Those problems
   should not occur with Python 3.7.


Version 1.15.0 (27 May 2020)
============================

* switch to 5-byte txnums to handle larger blockchains.  Upgrade DBs during restart.
* accurate clearing of stale caches
* coin additions / updates: NavCoin + Hush + VersusCoin + Zero (cipig), DashRegtest (colmenero),
  Quebecoin (morinpa), Primecoin (Sunny King), multiple (Panagiotis David), RVN (standard-error),
  Sumcoin
* other: Jeremy Rand, Jin Eguchi, ddude, Jonathan Cross, Carsen Klock, cipig


Version 1.14.0 (19 Jan 2020)
============================

* require Python 3.7
* support for Bitcoin SV Genesis activation
* DB upgrade to allow for larger transactions.  Your DB will automatically upgrade when
  starting, the upgrade should take approximately 15 mintues.
* fix server shutdown process
* fix cache race condition (issue `#909`_)
* faster initial sync
* coin additions / updates: Emercoin (yakimka), Feathercoin (wellenreiter01),
  Peercoin (peerchemist), Namecoin (JeremyRand), Zcoin (a-bezrukov), Simplicity,
  Mice (ComputerCraftr), Sibcoin testnet (TriKriSta), Odin (Manbearpixel),
* other: h2o10, osagga, Sombernight, breign, pedr0-fr, wingsuit

Version 1.13.0 (26 Sep 2019)
============================

* daemon: use a single connection for all requests rather than a connection per request.
  Distinguish handling of JSON and HTTP errors
* recognise OP_FALSE OP_RETURN scripts as unspendable
* peers - attempt to bind to correct local IP address
* improve name support (domob1812)
* coin additions / updates: BitZeny (y-chan), ZCoin (a-bezrukov), Emercoin (yakimka),
  BSV (Roger Taylor), Bellcoin (streetcrypto7), Ritocoin (traysi), BTC (Sombernight),
  PIVX (mrcarlanthony), Monacoin (wakiyamap)), NamecoinRegtest (JeremyRand), Axe (ddude1),
  Xaya (domob1812), GZRO (MrNaif2018), Ravencoin (standard-error)
* other: gits7r

Version 1.12.0 (13 May 2019)
============================

* require aiorpcX 0.18.1.  This introduces websocket support.  The environment variables
  changed accordingly; see :envvar:`SERVICES` and :envvar:`REPORT_SERVICES`.
* work around bug in recent versions of uvloop
* aiorpcX upgrade fixes from Shane M
* coin additions / updates: BitcoinSV, Bolivarcoin (Jose Luis Estevez), BTC Testnet (ghost43),
  Odin (Pixxl)

Version 1.11.0 (18 Apr 2019)
============================

* require aiorpcX 0.15.x
* require aiohttp 3.3 or higher; earlier versions had a problematic bug
* add :envvar:`REQUEST_TIMEOUT` and :envvar:`LOG_LEVEL` environment variables
* mark 4 old environment variables obsolete.  ElectrumX won't start until they are removed
* getinfo local RPC cleaned up and shows more stats
* miscellaneous fixes and improvements
* more efficient handling of some RPC methods, particularly
  :func:`blockchain.transaction.get_merkle`
* coin additions / updates: BitcoinSV scaling testnet (Roger Taylor), Dash (zebra lucky),
* issues resolved: `#566`_, `#731`_, `#795`_

Version 1.10.1 (13 Apr 2019)
============================

* introduce per-request costing.  See environment variables documentation for new
  variables :envvar:`COST_SOFT_LIMIT`, :envvar:`COST_HARD_LIMIT`, :envvar:`REQUEST_SLEEP`,
  :envvar:`INITIAL_CONCURRENT`, :envvar:`BANDWIDTH_UNIT_COST`.  Sessions are placed in groups
  with which they share some of their costs.  Prior cost is remembered across reconnects.
* require aiorpcX 0.13.5 for better concurrency handling
* require clients use protocol 1.4 or higher
* handle transaction.get_merkle requests more efficiently (ghost43)
* Windows support (sancoder)
* peers improvements (ghost43)
* report mempool and block sizes in logs
* electrumx_rpc: timeout raised to 30s, fix session request counts
* other tweaks and improvements by Bjorge Dijkstra, ghost43, peleion,
* coin additions / updates: ECA (Jenova7), ECCoin (smogm), GXX (DEVCØN), BZX (2INFINITY),
  DeepOnion (Liam Alford), CivX / EXOS (turcol)

Version 1.10.0 (15 Mar 2019)
============================

* extra countermeasures to limit BTC phishing effectiveness (ghost43)
* peers: mark blacklisted peers bad; force retry blacklisted peers (ghost43)
* coin additions / updates: Monacoin (wakiyamap), Sparks (Mircea Rila), ColossusXT,
  Polis, MNPCoin, Zcoin, GINCoin (cronos), Grosetlcoin (gruve-p), Dash (konez2k),
  Bitsend (David), Ravencoin (standard-error), Onixcoin (Jose Estevez), SnowGem
* coin removals: Gobyte, Moneci (cronos)
* minor tweaks by d42
* issues fixed `#660`_ - unclean shutdowns during initial sync

Version 1.9.5 (08 Feb 2019)
===========================

* server blacklist logic (ecdsa)
* require aiorpcX 0.10.4
* remove dead wallet code
* fix `#727`_ - not listing same peer twice

Version 1.9.4 (07 Feb 2019)
===========================

* require aiorpcX 0.10.3
* fix `#713`_

Version 1.9.3 (05 Feb 2019)
===========================

* ignore potential sybil peers
* coin additions / updates: BitcoinCashABC (cculianu), Monacoin (wakiyamap)

Version 1.9.2 (03 Feb 2019)
===========================

* restore protocol version 1.2 and send a warning for old BTC Electrum clients that they
  need to upgrade.  This is an attempt to protect users of old versions of Electrum from
  the ongoing phishing attacks
* increase default MAX_SEND for AuxPow Chains.  Truncate AuxPow for block heights covered
  by a checkpoint.  (jeremyrand)
* coin additions / updates: NMC (jeremyrand), Dash (zebra-lucky), PeerCoin (peerchemist),
  BCH testnet (Mark Lundeberg), Unitus (ChekaZ)
* tighter RPC param checking (ghost43)

Version 1.9.1 (11 Jan 2019)
===========================

* fix `#684`_

Version 1.9.0 (10 Jan 2019)
===========================

* minimum protocol version is now 1.4
* coin additions / updates: BitcoinSV, SmartCash (rc125), NIX (phamels), Minexcoin (joesixpack),
  BitcoinABC (mblunderburg), Dash (zebra-lucky), BitcoinABCRegtest (ezegom), AXE (slowdive),
  NOR (flo071), BitcoinPlus (bushsolo), Myriadcoin (cryptapus), Trezarcoin (ChekaZ),
  Bitcoin Diamond (John Shine),
* close `#554`_, `#653`_, `#655`_
* other minor tweaks (Michael Schmoock, Michael Taborsky)


**Neil Booth**  kyuupichan@gmail.com  https://github.com/kyuupichan

.. _#554: https://github.com/kyuupichan/electrumx/issues/554
.. _#566: https://github.com/kyuupichan/electrumx/issues/566
.. _#653: https://github.com/kyuupichan/electrumx/issues/653
.. _#655: https://github.com/kyuupichan/electrumx/issues/655
.. _#660: https://github.com/kyuupichan/electrumx/issues/660
.. _#684: https://github.com/kyuupichan/electrumx/issues/684
.. _#713: https://github.com/kyuupichan/electrumx/issues/713
.. _#727: https://github.com/kyuupichan/electrumx/issues/727
.. _#731: https://github.com/kyuupichan/electrumx/issues/731
.. _#795: https://github.com/kyuupichan/electrumx/issues/795
.. _#909: https://github.com/kyuupichan/electrumx/issues/909
