.. _environment:

=====================
Environment Variables
=====================

ElectrumX takes no command line arguments, instead its behaviour is
controlled by environment variables.  Only a few are required to be
given, the rest will have sensible defaults if not specified.  Many of
the defaults around resource usage are conservative; I encourage you
to review them.

Note: by default the server will only serve to connections from the
same machine.  To be accessible to other users across the internet you
must set **HOST** appropriately; see below.


Required
========

These environment variables are always required:

.. envvar:: COIN

  Must be a :attr:`NAME` from one of the :class:`Coin` classes in
  `lib/coins.py`_.

.. envvar:: DB_DIRECTORY

  The path to the database directory.  Relative paths should be
  relative to the parent process working directory.  This is the
  directory of the `run` script if you use it.

.. envvar:: DAEMON_URL

  A comma-separated list of daemon URLs.  If more than one is provided
  ElectrumX will initially connect to the first, and failover to
  subsequent ones round-robin style if one stops working.

  The generic form of a daemon URL is::

     http://username:password@hostname:port/

  The leading ``http://`` is optional, as is the trailing slash.  The
  ``:port`` part is also optional and will default to the standard RPC
  port for :envvar:`COIN` and :envvar:`NET` if omitted.


For the ``run`` script
======================

The following are required if you use the ``run`` script:

.. envvar:: ELECTRUMX

  The path to the electrumx_server script.  Relative paths should
  be relative to the directory of the ``run`` script.

.. envvar:: USERNAME

  The username the server will run as.


Services
========

These two environment variables are comma-separated lists of individual *services*.

A **service** has the general form::

  protocol://host:port

*protocol* is case-insensitive.  A protocol can be specified multiple times, with
different hosts or ports.  This might be useful for multi-homed hosts, or if you offer
both Tor and clearnet services.  The recognised protocols are::

   tcp    Plaintext TCP sockets
   ssl    SSL-encrypted TCP sockets
   ws     Plaintext websockets
   wss    SSL-encrypted websockets
   rpc    Plaintext RPC

*host* can be a hostname, an IPv4 address, or an IPv6 address enclosed in square brackets.

*port* is an integer from :const:`1` to :const:`65535` inclusive.

Where documented, one or more of *protocol*, *host* and *port* can be omitted, in which
case a default value will be assumed.

Here are some examples of valid services::

  tcp://host.domain.tld:50001           # Hostname, lowercase protocol, port
  SSL://23.45.67.78:50002               # An IPv4 address, upper-case protocol, port
  rpC://localhost                       # Host as a string, mixed-case protocol, default port
  ws://[1234:5678:abcd::5601]:8000      # Host as an IPv6 address
  wss://h3ubaasdlkheryasd.onion:50001   # Host as a Tor ".onion" address
  rpc://:8000                           # Default host, port given
  host.domain.tld:5151                  # Default protocol, hostname, port
  rpc://                                # RPC protocol, default host and port

.. note:: ElectrumX will not serve any incoming connections until it has fully caught up
          with your bitcoin daemon.  The only exception is local **RPC** connections,
          which are served at any time after the server has initialized.

.. envvar:: SERVICES

  A comma-separated list of services ElectrumX will accept incoming connections for.

  This environment variable determines what interfaces and ports the server listens on, so
  must be set correctly for any connection to the server to succeed.

  *protocol* can be any recognised protocol.

  *host* defaults to all of the machine's interfaces, except if the protocol is **rpc**,
  when it defaults to :const:`localhost`.

  *port* can only be defaulted for **rpc** where the default is :const:`8000`.

  If any listed service has protocol **ssl** or **wss** then :envvar:`SSL_CERTFILE` and
  :envvar:`SSL_KEYFILE` must be defined.

  Tor **onion** addresses are invalid in :envvar:`SERVICES`.

  Here is an example value of this environment variable::

    tcp://:50001,ssl://:50002,wss://:50004,rpc://

  This serves **tcp**, **ssl**, **wss** on all interfaces on ports 50001, 50002 and 50004
  respectively.  **rpc** is served on :const:`localhost` port :const:`8000`.

.. envvar:: REPORT_SERVICES

  A comma-separated list of services ElectrumX will advertise and other servers in the
  server network (if peer discovery is enabled), and any successful connection.

  This environment variable must be set correctly, taking account of your network,
  firewall and router setup, for clients and other servers to see how to connect to your
  server.

  The **rpc** protocol, special IP addresses (inlcuding private ones if peer discovery is
  enabled), and :const:`localhost` are invalid in :envvar:`REPORT_SERVICES`.

  Here is an example value of this environment variable::

    tcp://sv.usebsv.com:50001,ssl://sv.usebsv.com:50002,wss://sv.usebsv.com:50004

  This advertizes **tcp**, **ssl**, **wss** services at :const:`sv.usebsv.com` on ports
  50001, 50002 and 50004 respectively.

.. note:: Certificate Authority-signed certificates don't work over Tor, so you should
          only have Tor services` in :envvar:`REPORT_SERVICES` if yours is self-signed.

.. envvar:: SSL_CERTFILE

  The filesystem path to your SSL certificate file.

  :ref:`SSL certificates`

.. envvar:: SSL_KEYFILE

  The filesystem path to your SSL key file.

  :ref:`SSL certificates`


Miscellaneous
=============

These environment variables are optional:

.. envvar:: LOG_FORMAT

  The Python logging `format string
  <https://docs.python.org/3/library/logging.html#logrecord-attributes>`_
  to use.  Defaults to ``%(levelname)s:%(name)s:%(message)s``.

.. envvar:: LOG_LEVEL

  The default Python logging level, a case-insensitive string.  Useful values
  are 'debug', 'info', 'warning' and 'error'.

.. envvar:: ALLOW_ROOT

  Set this environment variable to anything non-empty to allow running
  ElectrumX as root.

.. envvar:: NET

  Must be a :envvar:`NET` from one of the **Coin** classes in
  `lib/coins.py`_.  Defaults to ``mainnet``.

.. envvar:: DB_ENGINE

  Database engine for the UTXO and history database.  The default is
  ``leveldb``.  The other alternative is ``rocksdb``.  You will need
  to install the appropriate python package for your engine.  The
  value is not case sensitive.

.. envvar:: DONATION_ADDRESS

  The server donation address reported to Electrum clients.  Defaults
  to empty, which Electrum interprets as meaning there is none.

.. envvar:: BANNER_FILE

  The path to a banner file to serve to clients in Electrum's
  "Console" tab.  Relative file paths must be relative to
  :envvar:`DB_DIRECTORY`.  The banner file is re-read for each new
  client.

  You can place several meta-variables in your banner file, which will be
  replaced before serving to a client.

  + ``$SERVER_VERSION`` is replaced with the ElectrumX version you are
    running, such as ``1.0.10``.
  + ``$SERVER_SUBVERSION`` is replaced with the ElectrumX user agent
    string.  For example, ``ElectrumX 1.0.10``.
  + ``$DAEMON_VERSION`` is replaced with the daemon's version as a
    dot-separated string. For example ``0.12.1``.
  + ``$DAEMON_SUBVERSION`` is replaced with the daemon's user agent
    string.  For example, ``/BitcoinUnlimited:0.12.1(EB16; AD4)/``.
  + ``$DONATION_ADDRESS`` is replaced with the address from the
    :envvar:`DONATION_ADDRESS` environment variable.

  See `here <https://github.com/shsmith/electrumx-banner-updater>`_
  for a script that updates a banner file periodically with useful
  statistics about fees, last block time and height, etc.

.. envvar:: TOR_BANNER_FILE

  As for :envvar:`BANNER_FILE` (which is also the default) but shown
  to incoming connections believed to be to your Tor hidden service.

.. envvar:: ANON_LOGS

  Set to anything non-empty to replace IP addresses in logs with
  redacted text like ``xx.xx.xx.xx:xxx``.  By default IP addresses
  will be written to logs.

.. envvar:: LOG_SESSIONS

  The number of seconds between printing session statistics to the
  log.  The output is identical to the :ref:`sessions` RPC command
  except that :envvar:`ANON_LOGS` is honoured.  Defaults to 3600.  Set
  to zero to suppress this logging.

.. envvar:: REORG_LIMIT

  The maximum number of blocks to be able to handle in a chain
  reorganisation.  ElectrumX retains some fairly compact undo
  information for this many blocks in levelDB.  The default is a
  function of :envvar:`COIN` and :envvar:`NET`; for Bitcoin mainnet it
  is 200.

.. envvar:: EVENT_LOOP_POLICY

  The name of an event loop policy to replace the default asyncio
  policy, if any.  At present only ``uvloop`` is accepted, in which
  case you must have installed the `uvloop`_ Python package.

  If you are not sure what this means leave it unset.

.. envvar:: DROP_CLIENT

  Set a regular expression to disconnect any client based on their
  version string. For example to drop versions from 1.0 to 1.2 use
  the regex ``1\.[0-2]\.\d+``.


Resource Usage Limits
=====================

The following environment variables are all optional and help to limit
server resource consumption and prevent simple DoS.

Address subscriptions in ElectrumX are very cheap - they consume about
160 bytes of memory each and are processed efficiently.  I feel the
two subscription-related defaults below are low and encourage you to
raise them.

.. envvar:: MAX_SESSIONS

  The maximum number of incoming connections.  Once reached, TCP and
  SSL listening sockets are closed until the session count drops
  naturally to 95% of the limit.  Defaults to 1,000.

.. envvar:: MAX_SEND

  The maximum size of a response message to send over the wire, in
  bytes.  Defaults to 1,000,000 (except for AuxPoW coins, which default
  to 10,000,000).  Values smaller than 350,000 are taken as 350,000
  because standard Electrum protocol header "chunk" requests are almost
  that large.

  The Electrum protocol has a flaw in that address histories must be
  served all at once or not at all, an obvious avenue for abuse.
  :envvar:`MAX_SEND` is a stop-gap until the protocol is improved to
  admit incremental history requests.  Each history entry is
  approximately 100 bytes so the default is equivalent to a history
  limit of around 10,000 entries, which should be ample for most
  legitimate users.  If you use a higher default bear in mind one
  client can request history for multiple addresses.  Also note that
  the largest raw transaction you will be able to serve to a client is
  just under half of :envvar:`MAX_SEND`, as each raw byte becomes 2
  hexadecimal ASCII characters on the wire.  Very few transactions on
  Bitcoin mainnet are over 500KB in size.

.. envvar:: COST_SOFT_LIMIT
.. envvar:: COST_HARD_LIMIT
.. envvar:: REQUEST_SLEEP
.. envvar:: INITIAL_CONCURRENT

  All values are integers. :envvar:`COST_SOFT_LIMIT` defaults to :const:`1,000`,
  :envvar:`COST_HARD_LIMIT` to :const:`10,000`, :envvar:`REQUEST_SLEEP` to :const:`2,500`
  milliseconds, and :envvar:`INITIAL_CONCURRENT` to :const:`10` concurrent requests.

  The server prices each request made to it based upon an estimate of the resources needed
  to process it.  Factors include whether the request uses bitcoind, how much bandwidth
  it uses, and how hard it hits the databases.

  To set a base for the units, a :func:`blockchain.scripthash.subscribe` subscription to
  an address with a history of 2 or fewer transactions is costed at :const:`1.0` before
  considering the bandwidth consumed.  :func:`server.ping` is costed at :const:`0.1`.

  As the total cost of a session goes over the soft limit, its requests start to be
  throttled in two ways.  First, the number of requests for that session that the server
  will process concurrently is reduced.  Second, each request starts to sleep a little
  before being handled.

  Before throttling starts, the server will process up to :envvar:`INITIAL_CONCURRENT`
  requests concurrently without sleeping.  As the session cost ranges from
  :envvar:`COST_SOFT_LIMIT` to :envvar:`COST_HARD_LIMIT`, concurrency drops linearly to
  zero and each request's sleep time increases linearly up to :envvar:`REQUEST_SLEEP`
  milliseconds.  Once the hard limit is reached, the session is disconnected.

  In order that non-abusive sessions can continue to be served, a session's cost gradually
  decays over time.  Subscriptions have an ongoing servicing cost, so the decay is slower
  as the number of subscriptions increases.

  If a session disconnects, ElectrumX continues to associate its cost with its IP address,
  so if it immediately reconnects it will re-acquire its previous cost allocation.

  A server operator should experiment with different values according to server loads.  It
  is not necessarily true that e.g. having a low soft limit, decreasing concurrency and
  increasing sleep will help handling heavy loads, as it will also increase the backlog of
  requests the server has to manage in memory.  It will also give a much worse experience
  for genuine connections.

.. envvar:: BANDWIDTH_UNIT_COST

  The number of bytes, sent and received, by a session that is deemed to cost :const:`1.0`.

  The default value :const:`5,000` bytes, meaning the bandwidth cost assigned to a response
  of 100KB is 20.  If your bandwidth is cheap you should probably raise this.

.. envvar:: REQUEST_TIMEOUT

  An integer number of seconds defaulting to :const:`30`.  If a request takes longer than
  this to respond to, either because of request limiting or because the request is
  expensive, the server rejects it and returns a timeout error to the client indicating
  that the server is busy.

  This can help prevent large backlogs of unprocessed requests building up under heavy load.

.. envvar:: SESSION_TIMEOUT

  An integer number of seconds defaulting to :const:`600`.  Sessions that have not sent a
  request for longer than this are disconnected.  Properly functioning clients should send
  a :func:`server.ping` request once roughly 450 seconds have passed since the previous
  request, in order to avoid disconnection.


Peer Discovery
==============

In response to the :func:`server.peers.subscribe` RPC call, ElectrumX
will only return peer servers that it has recently connected to and
verified basic functionality.

If you are not running a Tor proxy ElectrumX will be unable to connect
to onion server peers, in which case rather than returning no onion
peers it will fall back to a hard-coded list.

To give incoming clients a full range of onion servers you will need
to be running a Tor proxy for ElectrumX to use.

ElectrumX will perform peer-discovery by default and announce itself
to other peers.  If your server is private you may wish to disable
some of this.

.. envvar:: PEER_DISCOVERY

  This environment variable is case-insensitive and defaults to
  ``on``.

  If ``on``, ElectrumX will occasionally connect to and verify its
  network of peer servers.

  If ``off``, peer discovery is disabled and a hard-coded default list
  of servers will be read in and served.  If set to ``self`` then peer
  discovery is disabled and the server will only return itself in the
  peers list.

.. envvar:: PEER_ANNOUNCE

  Set this environment variable to empty to disable announcing itself.
  If not defined, or non-empty, ElectrumX will announce itself to
  peers.

  If peer discovery is disabled this environment variable has no
  effect, because ElectrumX only announces itself to peers when doing
  peer discovery if it notices it is not present in the peer's
  returned list.

.. envvar:: FORCE_PROXY

  By default peer discovery happens over the clear internet.  Set this
  to non-empty to force peer discovery to be done via the proxy.  This
  might be useful if you are running a Tor service exclusively and
  wish to keep your IP address private.

.. envvar:: TOR_PROXY_HOST

  The host where your Tor proxy is running.  Defaults to
  ``localhost``.

  If you are not running a Tor proxy just leave this environment
  variable undefined.

.. envvar:: TOR_PROXY_PORT

  The port on which the Tor proxy is running.  If not set, ElectrumX
  will autodetect any proxy running on the usual ports 9050 (Tor),
  9150 (Tor browser bundle) and 1080 (socks).

.. envvar:: BLACKLIST_URL

  URL to retrieve a list of blacklisted peers.  If not set, a coin-
  specific default is used.


Cache
=====

If synchronizing from the Genesis block your performance might change
by tweaking the cache size.  Cache size is only checked roughly every
minute, so the cache can grow beyond the specified size.  Moreover,
the Python process is often quite a bit fatter than the cache size,
because of Python overhead and also because leveldb consumes a lot of
memory when flushing.  So I recommend you do not set this over 60% of
your available physical RAM:

.. _CACHE:

.. envvar:: CACHE_MB

  The amount of cache, in MB, to use.  The default is 1,200.

  A portion of the cache is reserved for unflushed history, which is
  written out frequently.  The bulk is used to cache UTXOs.

  Larger caches probably increase performance a little as there is
  significant searching of the UTXO cache during indexing.  However, I
  don't see much benefit in my tests pushing this too high, and in
  fact performance begins to fall, probably because LevelDB already
  caches, and also because of Python GC.

  I do not recommend raising this above 2000.

.. _lib/coins.py: https://github.com/kyuupichan/electrumx/blob/master/electrumx/lib/coins.py
.. _uvloop: https://pypi.python.org/pypi/uvloop
