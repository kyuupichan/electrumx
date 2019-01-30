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


Miscellaneous
=============

These environment variables are optional:

.. envvar:: LOG_FORMAT

  The Python logging `format string
  <https://docs.python.org/3/library/logging.html#logrecord-attributes>`_
  to use.  Defaults to ``%(levelname)s:%(name)s:%(message)s``.

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

.. envvar:: HOST

  The host or IP address that the TCP and SSL servers will use when
  binding listening sockets.  Defaults to ``localhost``.  To listen on
  multiple specific addresses specify a comma-separated list.  Set to
  an empty string to listen on all available interfaces (likely both
  IPv4 and IPv6).

.. envvar:: TCP_PORT

  If set ElectrumX will serve TCP clients on
  :envvar:`HOST`\::envvar:`TCP_PORT`.

  .. note:: ElectrumX will not serve TCP connections until it has
            fully caught up with your daemon.

.. envvar:: SSL_PORT

  If set ElectrumX will serve SSL clients on
  :envvar:`HOST`\::envvar:`SSL_PORT`.  If set then
  :envvar:`SSL_CERTFILE` and :envvar:`SSL_KEYFILE` must be defined
  environment variables with values the filesystem paths to those SSL
  files.

  .. note:: ElectrumX will not serve SSL connections until it has
            fully caught up with your daemon.

.. envvar:: RPC_HOST

  The host or IP address that the RPC server will listen on and
  defaults to ``localhost``.  To listen on multiple specific addresses
  specify a comma-separated list.  Servers with unusual networking
  setups might want to specify e.g. ``::1`` or ``127.0.0.1``
  explicitly rather than defaulting to ``localhost``.

  An empty string (normally indicating all interfaces) is interpreted
  as ``localhost``, because allowing access to the server's RPC
  interface to arbitrary connections across the internet is not a good
  idea.

.. envvar:: RPC_PORT

  ElectrumX will listen on this port for local RPC connections.
  ElectrumX listens for RPC connections unless this is explicitly set
  to blank.  The default depends on :envvar:`COIN` and :envvar:`NET`
  (e.g., 8000 for Bitcoin mainnet) if not set, as indicated in
  `lib/coins.py`_.

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

.. envvar:: MAX_SUBS

  The maximum number of address subscriptions across all sessions.
  Defaults to 250,000.

.. envvar:: MAX_SESSION_SUBS

  The maximum number of address subscriptions permitted to a single
  session.  Defaults to 50,000.

.. envvar:: BANDWIDTH_LIMIT

  Per-session periodic bandwidth usage limit in bytes.  This is a soft,
  not hard, limit.  Currently the period is hard-coded to be one hour.
  The default limit value is 2 million bytes.

  Bandwidth usage over each period is totalled, and when this limit is
  exceeded each subsequent request is stalled by sleeping before
  handling it, effectively giving higher processing priority to other
  sessions.

  The more bandwidth usage exceeds this soft limit the longer the next
  request will sleep.  Sleep times are a round number of seconds with
  a minimum of 1.  Each time the delay changes the event is logged.

  Bandwidth usage is gradually reduced over time by "refunding" a
  proportional part of the limit every now and then.

.. envvar:: SESSION_TIMEOUT

  An integer number of seconds defaulting to 600.  Sessions with no
  activity for longer than this are disconnected.  Properly
  functioning Electrum clients by default will send pings roughly
  every 60 seconds.


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


Server Advertising
==================

These environment variables affect how your server is advertised
by peer discovery (if enabled).

.. envvar:: REPORT_HOST

  The clearnet host to advertise.  If not set, no clearnet host is
  advertised.

.. envvar:: REPORT_TCP_PORT

  The clearnet TCP port to advertise if :envvar:`REPORT_HOST` is set.
  Defaults to :envvar:`TCP_PORT`.  ``0`` disables publishing a TCP
  port.

.. envvar:: REPORT_SSL_PORT

  The clearnet SSL port to advertise if :envvar:`REPORT_HOST` is set.
  Defaults to :envvar:`SSL_PORT`.  ``0`` disables publishing an SSL
  port.

.. envvar:: REPORT_HOST_TOR

  If you wish run a Tor service, this is the Tor host name to
  advertise and must end with ``.onion``.

.. envvar:: REPORT_TCP_PORT_TOR

  The Tor TCP port to advertise.  The default is the clearnet
  :envvar:`REPORT_TCP_PORT`, unless disabled or it is ``0``, otherwise
  :envvar:`TCP_PORT`.  ``0`` disables publishing a Tor TCP port.

.. envvar:: REPORT_SSL_PORT_TOR

  The Tor SSL port to advertise.  The default is the clearnet
  :envvar:`REPORT_SSL_PORT`, unless disabled or it is ``0``, otherwise
  :envvar:`SSL_PORT`.  ``0`` disables publishing a Tor SSL port.

  .. note:: Certificate-Authority signed certificates don't work over
            Tor, so you should set :envvar:`REPORT_SSL_PORT_TOR` to
            ``0`` if yours is not self-signed.


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
