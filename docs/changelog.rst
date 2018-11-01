===========
 ChangeLog
===========

.. note:: It is strongly recommended you upgrade to Python 3.7, which
   fixes bugs in asyncio that caused an ever-growing open file count
   and memory consumption whilst serving clients.  Those problems
   should not occur with Python 3.7.

.. note:: Bitcoin ABC developers have hastily introduced controversial
   changes that break ElectrumX's block processing by requiring it to
   be non-sequential.  Unlike others with unique requirements they
   refused to make their code coin-specific.  ElectrumX continues to
   require blocks be naturally ordered, and is compatible with any
   non-CToR daemon, such as Bitcoin SV, and Bitcoin Unlimited /
   Bitcoin XT with CToR disabled.


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

Version 1.5.2
=============

* package renamed from elctrumX-kyuupichan to electrumX
* split merkle logic out into lib/merkle.py
* fix `#523`_ for daemons based on older releases of core

Version 1.5.1
=============

Fixes a couple of issues found in 1.5 after release:

* update peer discovery code for :ref:`version 1.3` of the protocol
* setup.py would not run in a clean environment (e.g. virtualenv)
* logging via aiorpcX didn't work with the logging hierarchy updates
* log Python interpreter version on startup

Version 1.5
===========

.. note:: The two main scripts, :file:`electrumx_server` and
   :file:`electrumx_rpc` were renamed to drop the `.py` suffix.  You
   will probably need to update your run script accordingly.

* support :ref:`version 1.3` of the protocol
* increase minimum supported protocol version to :ref:`version 1.1`
* split out history handling in preparation for new DB format
* force close stubborn connections that refuse to close gracefully
* RPC getinfo returns server version (erasmospunk)
* add new masternode methods; document them all (elmora-do)
* make electrumx a Python package (eukreign)
* hierarchical logging, Env to take a coin class directly,
  server_listening event (eukreign)
* decred coin removed as mainnet does not sync
* issues fixed: `#414`_, `#443`_, `#455`_, `#480`_, `#485`_, `#502`_,
  `#506`_, `#519`_ (wakiyamap)
* new or updated coins: Feathercoin (lclc), NewYorkCoin Testnet(nicovs),
  BitZeny (wakiyamap), UFO (bushstar), GAME (cipig), MAC (nico205),
  Xuez (ddude), ZCash (wo01), PAC (elmora-do), Koto Testnet (wo01),
  Dash Testnet (ser), BTG all nets (wilsonmeier), Polis + ColossusXT +
  GoByte + Monoeci (cronos-polis), BitcoinCash Regtest (eukreign)
* minor tweaks: romanz, you21979, SuBPaR42, sangaman, wakiyamap, DaShak


Version 1.4.3
=============

* Fix `#442`_.

Version 1.4.2
=============

* proxy remote IP reported properly if :envvar:`FORCE_PROXY` is set.
  Fixes `#301`_.
* requires aiorpcx 0.5.5

Version 1.4.1
=============

* minor bugfixes - cleaner shutdown; group handling
* set PROTOCOL_MIN to 1.0; this will prevent 2.9.x clients from connecting
  and encourage upgrades to more recent clients without the security hole
* requires aiorpcx 0.5.4

Version 1.4
===========

* switch to `aiorpcX <https://github.com/kyuupichan/aiorpcX>`_ for all
  networking, ``JSON RPC`` and proxy handling
* proxy detection improvements
* `documentation <https://electrumx.readthedocs.io/>`_ rewrite
* new environment variable :envvar:`LOG_FORMAT` to control logging format
* new environment variable :envvar:`DROP_CLIENT` to cut off unsupported
     client software
* coin updates: Litecoin (pooler), bitbayd (kongeo), BTG (wilsonmeier),
     danny91, wakiyamap, snowgem, Dash (theLazier), fujicoin
* new coins: Decred (cipherzzz), axe (-k),
* typo fixes (dax, romanz)

.. note:: the Dash-specific undocumented ``masternode.subscribe()``
   RPC call was not following the JSON RPC spec; this was shown up by
   the switch to aiorpcX.  I had to modify the code but it may break
   Dash clients.

   The Decred implementation doesn't work on mainnet; I will remove it
   if this remains unfixed.

**Neil Booth**  kyuupichan@gmail.com  https://github.com/kyuupichan

bitcoincash:qzxpdlt8ehu9ehftw6rqsy2jgfq4nsltxvhrdmdfpn

.. _#258: https://github.com/kyuupichan/electrumx/issues/258
.. _#301: https://github.com/kyuupichan/electrumx/issues/301
.. _#315: https://github.com/kyuupichan/electrumx/issues/315
.. _#414: https://github.com/kyuupichan/electrumx/issues/414
.. _#442: https://github.com/kyuupichan/electrumx/issues/442
.. _#443: https://github.com/kyuupichan/electrumx/issues/443
.. _#455: https://github.com/kyuupichan/electrumx/issues/455
.. _#479: https://github.com/kyuupichan/electrumx/issues/479
.. _#480: https://github.com/kyuupichan/electrumx/issues/480
.. _#485: https://github.com/kyuupichan/electrumx/issues/485
.. _#502: https://github.com/kyuupichan/electrumx/issues/50
.. _#506: https://github.com/kyuupichan/electrumx/issues/506
.. _#519: https://github.com/kyuupichan/electrumx/issues/519
.. _#521: https://github.com/kyuupichan/electrumx/issues/521
.. _#523: https://github.com/kyuupichan/electrumx/issues/523
.. _#534: https://github.com/kyuupichan/electrumx/issues/534
.. _#538: https://github.com/kyuupichan/electrumx/issues/538
.. _#552: https://github.com/kyuupichan/electrumx/issues/552
.. _#557: https://github.com/kyuupichan/electrumx/issues/557
.. _#559: https://github.com/kyuupichan/electrumx/issues/559
.. _#564: https://github.com/kyuupichan/electrumx/issues/564
.. _#565: https://github.com/kyuupichan/electrumx/issues/565
.. _#567: https://github.com/kyuupichan/electrumx/issues/567
.. _#570: https://github.com/kyuupichan/electrumx/issues/570
.. _#577: https://github.com/kyuupichan/electrumx/issues/577
.. _#603: https://github.com/kyuupichan/electrumx/issues/603
.. _#608: https://github.com/kyuupichan/electrumx/issues/608
