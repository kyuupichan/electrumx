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

LKaFk4KkVpw9pYoUpbckQSKKgCVC4oj78b

.. _#223: https://github.com/kyuupichan/electrumx/issues/223
.. _#251: https://github.com/kyuupichan/electrumx/issues/251
.. _#277: https://github.com/kyuupichan/electrumx/issues/277
.. _#287: https://github.com/kyuupichan/electrumx/issues/287
.. _#302: https://github.com/kyuupichan/electrumx/issues/287
