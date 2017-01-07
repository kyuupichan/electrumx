=====================
Environment Variables
=====================

ElectrumX takes no command line arguments, instead its behaviour is
controlled by environment variables.  Only a few are required to be
given, the rest will have sensible defaults if not specified.  Many of
the defaults around resource usage are conservative; I encourage you
to review them.

Required
--------

These environment variables are always required:

* **DB_DIRECTORY**

  The path to the database directory.  Relative paths should be
  relative to the parent process working directory.  This is the
  directory of the `run` script if you use it.

* **DAEMON_URL**

  A comma-separated list of daemon URLs.  If more than one is provided
  ElectrumX will initially connect to the first, and failover to
  subsequent ones round-robin style if one stops working.

  The generic form of a daemon URL is:

     `http://username:password@hostname:port/`

  The leading `http://` is optional, as is the trailing slash.  The
  `:port` part is also optional and will default to the standard RPC
  port for **COIN** and **NET** if omitted.


For the `run` script
--------------------

The following are required if you use the `run` script:

* **ELECTRUMX**

  The path to the electrumx_server.py script.  Relative paths should
  be relative to the directory of the `run` script.

* **USERNAME**

  The username the server will run as.

Miscellaneous
-------------

These environment variables are optional:

* **COIN**

  Must be a *NAME* from one of the **Coin** classes in
  `lib/coins.py`_.  Defaults to `Bitcoin`.

* **NET**

  Must be a *NET* from one of the **Coin** classes in `lib/coins.py`_.
  Defaults to `mainnet`.

* **DB_ENGINE**

  Database engine for the UTXO and history database.  The default is
  `leveldb`.  Supported alternatives are `rocksdb` and `lmdb`.  You
  will need to install the appropriate python package for your engine.
  The value is not case sensitive.  Note that the current way
  ElectrumX uses LMDB results in poor performance.  I intend to improve
  this.

* **REORG_LIMIT**

  The maximum number of blocks to be able to handle in a chain
  reorganisation.  ElectrumX retains some fairly compact undo
  information for this many blocks in levelDB.  The default is a
  function of **COIN** and **NET**; for Bitcoin mainnet it is 200.

* **HOST**

  The host that the TCP and SSL servers will use.  Defaults to
  `localhost`.  Set to blank to listen on all addresses (IPv4 and IPv6).

* **TCP_PORT**

  If set ElectrumX will serve TCP clients on **HOST**:**TCP_PORT**.

* **SSL_PORT**

  If set ElectrumX will serve SSL clients on **HOST**:**SSL_PORT**.
  If set SSL_CERTFILE and SSL_KEYFILE must be defined and be
  filesystem paths to those SSL files.

* **RPC_PORT**

  ElectrumX will listen on this port for local RPC connections.
  ElectrumX listens for RPC connections unless this is explicitly set
  to blank.  The default is appropriate for **COIN** and **NET**
  (e.g., 8000 for Bitcoin mainnet) if not set.

* **DONATION_ADDRESS**

  The server donation address reported to Electrum clients.  Defaults
  to empty, which Electrum interprets as meaning there is none.

* **BANNER_FILE**

  The path to a banner file to serve to clients in Electrum's
  "Console" tab.  Relative file paths must be relative to
  **DB_DIRECTORY**.  The banner file is re-read for each new client.

  You can place several meta-variables in your banner file, which will be
  replaced before serving to a client.

  + **$VERSION** is replaced with the ElectrumX version you are
    runnning, such as *ElectrumX 0.9.22*.
  + **$DAEMON_VERSION** is replaced with the daemon's version as a
    dot-separated string. For example *0.12.1*.
  + **$DAEMON_SUBVERSION** is replaced with the daemon's user agent
    string.  For example, `/BitcoinUnlimited:0.12.1(EB16; AD4)/`.
  + **$DONATION_ADDRESS** is replaced with the address from the
    **DONATION_ADDRESS** environment variable.

* **ANON_LOGS**

  Set to anything non-empty to replace IP addresses in logs with
  redacted text like 'xx.xx.xx.xx:xxx'.  By default IP addresses will
  be written to logs.

* **LOG_SESSIONS**

  The number of seconds between printing session statistics to the
  log.  The output is identical to the **sessions** RPC command except
  that **ANON_LOGS** is honoured.  Defaults to 3600.  Set to zero to
  suppress this logging.

Resource Usage Limits
---------------------

The following environment variables are all optional and help to limit
server resource consumption and prevent simple DoS.

Address subscriptions in ElectrumX are very cheap - they consume about
100 bytes of memory each (160 bytes from version 0.10.0) and are
processed efficiently.  I feel the two subscription-related defaults
below are low and encourage you to raise them.

* **MAX_SESSIONS**

  The maximum number of incoming connections.  Once reached, TCP and
  SSL listening sockets are closed until the session count drops
  naturally to 95% of the limit.  Defaults to 1,000.

* **MAX_SEND**

  The maximum size of a response message to send over the wire, in
  bytes.  Defaults to 1,000,000.  Values smaller than 350,000 are
  taken as 350,000 because standard Electrum protocol header "chunk"
  requests are almost that large.

  The Electrum protocol has a flaw in that address histories must be
  served all at once or not at all, an obvious avenue for abuse.
  **MAX_SEND** is a stop-gap until the protocol is improved to admit
  incremental history requests.  Each history entry is appoximately
  100 bytes so the default is equivalent to a history limit of around
  10,000 entries, which should be ample for most legitimate users.  If
  you use a higher default bear in mind one client can request history
  for multiple addresses.  Also note that the largest raw transaction
  you will be able to serve to a client is just under half of
  MAX_SEND, as each raw byte becomes 2 hexadecimal ASCII characters on
  the wire.  Very few transactions on Bitcoin mainnet are over 500KB
  in size.

* **MAX_SUBS**

  The maximum number of address subscriptions across all sessions.
  Defaults to 250,000.

* **MAX_SESSION_SUBS**

  The maximum number of address subscriptions permitted to a single
  session.  Defaults to 50,000.

* **BANDWIDTH_LIMIT**

  Per-session periodic bandwith usage limit in bytes.  This is a soft,
  not hard, limit.  Currently the period is hard-coded to be one hour.
  The default limit value is 2 million bytes.

  Bandwidth usage over each period is totalled, and when this limit is
  exceeded each subsequent request is stalled by sleeping before
  handling it, effectively giving higher processing priority to other
  sessions.  Each time this happens the event is logged.

  The more bandwidth usage exceeds this soft limit the longer the next
  request will sleep.  Sleep times are a round number of seconds with
  a minimum of 1.

  Bandwidth usage is gradually reduced over time by "refunding" a
  proportional part of the limit every now and then.

* **SESSION_TIMEOUT**

  An integer number of seconds defaulting to 600.  Sessions with no
  activity for longer than this are disconnected.  Properly
  functioning Electrum clients by default will send pings roughly
  every 60 seconds.

IRC
---

Use the following environment variables if you want to advertise
connectivity on IRC:

* **IRC**

  Set to anything non-empty to advertise on IRC

* **IRC_NICK**

  The nick to use when connecting to IRC.  The default is a hash of
  **REPORT_HOST**.  Either way a prefix will be prepended depending on
  **COIN** and **NET**.

* **REPORT_HOST**

  The host to advertise.  Defaults to **HOST**.

* **REPORT_TCP_PORT**

  The TCP port to advertise.  Defaults to **TCP_PORT**.  '0' disables
  publishing the port.

* **REPORT_SSL_PORT**

  The SSL port to advertise.  Defaults to **SSL_PORT**.  '0' disables
  publishing the port.

* **REPORT_HOST_TOR**

  The tor .onion address to advertise.  If set, an additional
  connection to IRC happens with '_tor" appended to **IRC_NICK**.

* **REPORT_TCP_PORT_TOR**

  The TCP port to advertise for Tor.  Defaults to **REPORT_TCP_PORT**,
  unless it is '0', otherwise **TCP_PORT**.  '0' disables publishing
  the port.

* **REPORT_SSL_PORT_TOR**

  The SSL port to advertise for Tor.  Defaults to **REPORT_SSL_PORT**,
  unless it is '0', otherwise **SSL_PORT**.  '0' disables publishing
  the port.

Cache
-----

If synchronizing from the Genesis block your performance might change
by tweaking the cache size.  Cache size is only checked roughly every
minute, so the cache can grow beyond the specified size.  Moreover,
the Python process is often quite a bit fatter than the cache size,
because of Python overhead and also because leveldb consumes a lot of
memory when flushing.  So I recommend you do not set this over 60% of
your available physical RAM:

* **CACHE_MB**

  The amount of cache, in MB, to use.  The default is 1,200.

  A portion of the cache is reserved for unflushed history, which is
  written out frequently.  The bulk is used to cache UTXOs.

  Larger caches probably increase performance a little as there is
  significant searching of the UTXO cache during indexing.  However, I
  don't see much benefit in my tests pushing this too high, and in
  fact performance begins to fall, probably because LevelDB already
  caches, and also because of Python GC.

  I do not recommend raising this above 2000.  If upgrading from prior
  versions, a value of 90% of the sum of the old UTXO_MB and HIST_MB
  variables is roughly equivalent.

Debugging
---------

The following are for debugging purposes:

* **FORCE_REORG**

  If set to a positive integer, it will simulate a reorg of the
  blockchain for that number of blocks on startup.  You must have
  synced before using this, otherwise there will be no undo
  information.

  Although it should fail gracefully if set to a value greater than
  **REORG_LIMIT**, I do not recommend it as I have not tried it and
  there is a chance your DB might corrupt.

.. _lib/coins.py: https://github.com/kyuupichan/electrumx/blob/master/lib/coins.py
