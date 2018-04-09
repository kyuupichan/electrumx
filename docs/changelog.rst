ChangeLog
=========

Version 1.4.3
-------------

* Fix `#442`_.

Version 1.4.2
-------------

* proxy remote IP reported properly if :envvar:`FORCE_PROXY` is set.
  Fixes `#301`_.
* requires aiorpcx 0.5.5

Version 1.4.1
-------------

* minor bugfixes - cleaner shutdown; group handling
* set PROTOCOL_MIN to 1.0; this will prevent 2.9.x clients from connecting
  and encourage upgrades to more recent clients without the security hole
* requires aiorpcx 0.5.4

Version 1.4
-----------

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
-----------

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

.. note:: version 1.2 changes script hash indexing in the database, so
  you will need to rebuild your databases from scratch.  Running this
  version will refuse to open the DB and not corrupt it, so you can
  revert to 1.1.x if you wish.  The initial synchronisation process
  should be around 10-15% faster than 1.1, owing to this change and
  Justin Arthur's optimisations from 1.1.1.

- separate P2PKH from P2PK entries in the history and UTXO databases.
  These were previously amalgamated by address as that is what
  electrum-server used to do.  However Electrum didn't handle P2PK
  spends correctly and now the protocol admits subscriptions by script
  hash there is no need to have these merged any more.

For Bitcoin (BitcoinSegwit/mainnet) you can download a leveldb database
synced up to block 490153 using this bittorrent magnet
`link (~24GB) <magnet:?xt=urn:btih:caa804f48a319b061be3884ac011656c27121a6f&dn=electrumx_1.2_btc_leveldb_490153>`_.

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

**Neil Booth**  kyuupichan@gmail.com  https://github.com/kyuupichan

1BWwXJH3q6PRsizBkSGm2Uw4Sz1urZ5sCj

LKaFk4KkVpw9pYoUpbckQSKKgCVC4oj78b

.. _#277: https://github.com/kyuupichan/electrumx/issues/277
.. _#287: https://github.com/kyuupichan/electrumx/issues/287
.. _#301: https://github.com/kyuupichan/electrumx/issues/301
.. _#302: https://github.com/kyuupichan/electrumx/issues/302
.. _#442: https://github.com/kyuupichan/electrumx/issues/442
