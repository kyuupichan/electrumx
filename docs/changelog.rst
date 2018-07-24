===========
 ChangeLog
===========

.. note:: It is strongly recommended you upgrade to Python 3.7, which
   fixes bugs in asyncio that caused an ever-growing open file count
   and memory consumption whilst serving clients.  Those problems
   should not occur with Python 3.7.

Version 1.7  (in progress)
==========================

Version 1.6.1  (in progress)
============================

* cleaner shutdown process with clear guarantees
* cleaner mempool and notification handling
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

Version 1.3
===========

* Switch to :ref:`version 1.2` of the protocol.
  :func:`mempool.get_fee_histogram` implementation contributed by ecdsa,
  verbose mode of :func:`blockchain.transaction.get` by gdassori.
* :func:`blockchain.scripthash.listunspent` now takes into account mempool
  spends and receipts.
* Improved client notification handling.
* Wait for mempool to fully sync before serving.
* Documentation moved to `readthedocs.io
  <https://electrumx.readthedocs.io/>`_.  Rewritten and improved
  protocol documentation.
* new/updated coins: Chips (cipig), Feathercoin (lclc), Zclassic(heyrhett),
  Dash (thelazier), NYC (xarakas), Koto (wo01), BitcoinZ (cipig), BitCore
  (cipig), Fujicoin (fujicoin), Bitcoin Atom (erasmospunk), Deanrius (carsenk),
  SNG (blackjok3rtt).
* Minor fixes and improvements: duckartes, blin00, bauerj,
  erasmospunk, SomberNight, romanz.

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
.. _#523: https://github.com/kyuupichan/electrumx/issues/523
