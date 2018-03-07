.. ElectrumX documentation master file, created by
   sphinx-quickstart on Mon Mar  5 22:39:16 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. image:: https://travis-ci.org/kyuupichan/electrumx.svg?branch=master
    :target: https://travis-ci.org/kyuupichan/electrumx
.. image:: https://coveralls.io/repos/github/kyuupichan/electrumx/badge.svg
    :target: https://coveralls.io/github/kyuupichan/electrumx

=========
ElectrumX
=========

A reimplementation of Electrum-Server for a future with bigger blocks.

  :Licence: MIT
  :Language: Python (>= 3.6)
  :Author: Neil Booth


Getting Started
===============

See :ref:`HOWTO`.

There is also an `installer`_ available that simplifies the
installation on various Linux-based distributions, and a `Dockerfile`_
available .

.. _installer: https://github.com/bauerj/electrumx-installer
.. _Dockerfile: https://github.com/lukechilds/docker-electrumx


Features
========

- Efficient, lightweight reimplementation of electrum-server
- Fast synchronization of bitcoin mainnet from Genesis.  Recent
  hardware should synchronize in well under 24 hours.  The fastest
  time to height 448k (mid January 2017) reported is under 4h 30m.  On
  the same hardware JElectrum would take around 4 days and
  electrum-server probably around 1 month.
- The full current Electrum protocol is implemented.
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


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   ENVIRONMENT
   HOWTO
   PEER_DISCOVERY
   RPC-INTERFACE
   protocol-new
   ARCHITECTURE


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
