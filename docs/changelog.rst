===========
 ChangeLog
===========

.. note:: It is strongly recommended you upgrade to Python 3.7, which
   fixes bugs in asyncio that caused an ever-growing open file count
   and memory consumption whilst serving clients.  Those problems
   should not occur with Python 3.7.


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


Version 1.8.12 (10 Nov 2018)
============================

* bug fix

Version 1.8.11 (07 Nov 2018)
============================

* require aiorpcX 0.10.1

Version 1.8.10 (05 Nov 2018)
============================

* require aiorpcX 0.10.0
* fix `#632`_
* coin additions / updates: ZelCash (TheTrunk)

Version 1.8.9 (02 Nov 2018)
===========================

* fix `#630`_

Version 1.8.8 (01 Nov 2018)
===========================

* require aiorpcX 0.9.0
* coin additions / updates: decred (dajohi, bolapara), zcash (erasmospunk),
  namecoin (JeremyRand),CivX (turcol), NewYorkCoin (erasmospunk)
* fix `#603`_, `#608`_
* other minor fixes and changes: FMCorz

Version 1.8.7 (13 Sep 2018)
===========================

* require aiorpcX 0.8.1
* fix reorg bug loading blocks from disk (erasmospunk)

Version 1.8.6 (12 Sep 2018)
===========================

* require aiorpcX 0.8.0
* suppress socket.send() errors
* new coin TokenPay (samfiragabriel)
* minor fix: wakiyamap

Version 1.8.5 (18 Aug 2018)
===========================

* require aiorpcX 0.7.3 which contains a couple of bugfixes
* fix `#552`_, `#577`_
* fixed a session limiting bug reported by ghost43
* coin additions / updates: PIVX and Decred Testnets, BitcoinGreen (cunhasb)
  Monacoin (wakayamap)
* proper generation input handling for various altcoins (erasmospunk) fixing
  `#570`_

Version 1.8.4 (14 Aug 2018)
===========================

* improved notification handling and efficiency
* improved daemon handling with minor fixes; full tests for Daemon class
* remove chain_state class
* various internal cleanups and improvements (erasmospunk)
* add PIVX support (erasmospunk) - mempool handling WIP
* fix protocol 1.3 handling of blockchain.block.header RPC (ghost43)

Version 1.8.3 (11 Aug 2018)
===========================

* separate the DB and the BlockProcessor objects
* comprehensive mempool tests
* fix `#521`_, `#565`_, `#567`_

Version 1.8.2 (09 Aug 2018)
===========================

* require aiorpcX 0.7.1 which along with an ElectrumX change restores clean
  shutdown and flush functionality, particularly during initial sync
* fix `#564`_

Version 1.8.1 (08 Aug 2018)
===========================

* require aiorpcX 0.7.0 which fixes a bug causing silent shutdown of ElectrumX
* fix `#557`_, `#559`_
* tweaks related to log spew (I think mostly occurring with old versions
  of Python)

Version 1.8  (06 Aug 2018)
==========================

* require aiorpcX 0.6.2
* fix query.py; move to contrib.  Add :ref:`query <query>` function to RPC
* rewrite :command:`electrumx_rpc` so that proper command-line help is provided
* per-coin tx hash functions (erasmospunk)
* coin additions / updates: Groestlcoin (Kefkius, erasmospunk),
  Decred (erasmonpsunk)
* other minor (smmalis37)


**Neil Booth**  kyuupichan@gmail.com  https://github.com/kyuupichan

1BWwXJH3q6PRsizBkSGm2Uw4Sz1urZ5sCj

.. _#521: https://github.com/kyuupichan/electrumx/issues/521
.. _#552: https://github.com/kyuupichan/electrumx/issues/552
.. _#554: https://github.com/kyuupichan/electrumx/issues/554
.. _#557: https://github.com/kyuupichan/electrumx/issues/557
.. _#559: https://github.com/kyuupichan/electrumx/issues/559
.. _#564: https://github.com/kyuupichan/electrumx/issues/564
.. _#565: https://github.com/kyuupichan/electrumx/issues/565
.. _#566: https://github.com/kyuupichan/electrumx/issues/566
.. _#567: https://github.com/kyuupichan/electrumx/issues/567
.. _#570: https://github.com/kyuupichan/electrumx/issues/570
.. _#577: https://github.com/kyuupichan/electrumx/issues/577
.. _#603: https://github.com/kyuupichan/electrumx/issues/603
.. _#608: https://github.com/kyuupichan/electrumx/issues/608
.. _#630: https://github.com/kyuupichan/electrumx/issues/630
.. _#632: https://github.com/kyuupichan/electrumx/issues/630
.. _#653: https://github.com/kyuupichan/electrumx/issues/653
.. _#655: https://github.com/kyuupichan/electrumx/issues/655
.. _#660: https://github.com/kyuupichan/electrumx/issues/660
.. _#684: https://github.com/kyuupichan/electrumx/issues/684
.. _#713: https://github.com/kyuupichan/electrumx/issues/713
.. _#727: https://github.com/kyuupichan/electrumx/issues/727
.. _#731: https://github.com/kyuupichan/electrumx/issues/731
.. _#795: https://github.com/kyuupichan/electrumx/issues/795
