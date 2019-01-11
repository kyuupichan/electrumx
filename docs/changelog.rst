===========
 ChangeLog
===========

.. note:: It is strongly recommended you upgrade to Python 3.7, which
   fixes bugs in asyncio that caused an ever-growing open file count
   and memory consumption whilst serving clients.  Those problems
   should not occur with Python 3.7.


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

Version 1.7.3  (01 Aug 2018)
============================

* fix `#538`_

Version 1.7.2  (29 Jul 2018)
============================

* require aiorpcX 0.5.9; 0.5.8 didn't work on Python 3.7

Version 1.7.1  (28 Jul 2018)
============================

* switch to aiorpcX 0.5.8 which implements some curio task management
  primitives on top of asyncio that make writing correct async code
  much easier, as well as making it simpler to reason about
* use those primitives to restructure the peer manager, which is now
  fully concurrent again, as well as the block processor and
  controller
* fix `#534`_ introduced in 1.7
* minor coin tweaks (ghost43, cipig)

Version 1.7  (25 Jul 2018)
==========================

* completely overhauled mempool and address notifications
  implementation.  Cleaner and a lot more efficient, especially for
  initial synchronization of the mempool.  Mempool handling is fully
  asynchronous and doesn't hinder client responses or block
  processing.
* peer discovery cleaned up, more work remains
* cleaner shutdown process with clear guarantees
* aiohttp min version requirement raised to 2.0
* onion peers are ignored if no tor proxy is available
* add Motion coin (ocruzv), MinexCoin (joesixpack)

Version 1.6  (19 July 2018)
===========================

* implement :ref:`version 1.4` of the protocol, with benefit for light
  clients, particularly mobile
* implement header proofs and merkle caches
* implement :func:`blockchain.transaction.id_from_pos` (ghost43)
* large refactoring of session and controller classes
* recent blocks are now stored on disk.  When backing up in a reorg
  ElectrumX uses these rather than asking the daemon for the blocks --
  some daemons cannot correctly handle orphaned block requests after
  a reorg.  Fixes `#258`_, `#315`_, `#479`_
* minor fixes: nijel


**Neil Booth**  kyuupichan@gmail.com  https://github.com/kyuupichan

1BWwXJH3q6PRsizBkSGm2Uw4Sz1urZ5sCj

.. _#258: https://github.com/kyuupichan/electrumx/issues/258
.. _#315: https://github.com/kyuupichan/electrumx/issues/315
.. _#479: https://github.com/kyuupichan/electrumx/issues/479
.. _#521: https://github.com/kyuupichan/electrumx/issues/521
.. _#534: https://github.com/kyuupichan/electrumx/issues/534
.. _#538: https://github.com/kyuupichan/electrumx/issues/538
.. _#552: https://github.com/kyuupichan/electrumx/issues/552
.. _#554: https://github.com/kyuupichan/electrumx/issues/554
.. _#557: https://github.com/kyuupichan/electrumx/issues/557
.. _#559: https://github.com/kyuupichan/electrumx/issues/559
.. _#564: https://github.com/kyuupichan/electrumx/issues/564
.. _#565: https://github.com/kyuupichan/electrumx/issues/565
.. _#567: https://github.com/kyuupichan/electrumx/issues/567
.. _#570: https://github.com/kyuupichan/electrumx/issues/570
.. _#577: https://github.com/kyuupichan/electrumx/issues/577
.. _#603: https://github.com/kyuupichan/electrumx/issues/603
.. _#608: https://github.com/kyuupichan/electrumx/issues/608
.. _#630: https://github.com/kyuupichan/electrumx/issues/630
.. _#632: https://github.com/kyuupichan/electrumx/issues/630
.. _#653: https://github.com/kyuupichan/electrumx/issues/653
.. _#655: https://github.com/kyuupichan/electrumx/issues/655
.. _#684: https://github.com/kyuupichan/electrumx/issues/684
