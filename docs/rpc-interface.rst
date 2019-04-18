RPC Interface
=============

You can query the status of a running server, and affect its behaviour
by sending **JSON RPC** commands to the LocalRPC port it is listening
on.  This is best done using the :file:`electrumx_rpc` script
provided.

The general form of invocation is::

  electrumx_rpc [-p PORT] <command> [arg1 [arg2...]]

The port to send the commands to can be specified on the command line,
otherwise the environment variable :envvar:`RPC_PORT` is used, and if
that is not set then **8000** is assumed.

The following commands are available:

add_peer
--------

Add a peer to the peers list.  ElectrumX will schdule an immediate
connection attempt.  This command takes a single argument: the peer's
"real name" as it used to advertise itself on IRC::

  $ electrumx_rpc add_peer "ecdsa.net v1.0 s110 t"
  "peer 'ecdsa.net v1.0 s110 t' added"

daemon_url
----------

This command takes an optional argument that is interpreted
identically to the :envvar:`DAEMON_URL` environment variable.  If
omitted, the default argument value is the process's existing
:envvar:`DAEMON_URL` environment variable.

This command replaces the daemon's URL at run-time, and also
forecefully rotates to the first URL in the list.

For example, in case ElectrumX has previously failed over to a
secondary daemon and you want to revert to the primary having resolved
the connectivity issue, invoking this command without an argument will
have that effect.

disconnect
----------

Disonnect the given session IDs or group names.

Session IDs can be obtained in the logs or with the `sessions`_ RPC command.  Group
names can be optained with the `groups`_ RPC command.

The special string :const:`all` disconnects all sessions.

Example::

  $ electrumx_rpc disconnect 209.59.102 34 2
  [
      "disconnecting session 34",
      "disconnecting group 209.59.102"
      "unknown: 2",
  ]

getinfo
-------

Return a summary of server state.  This command takes no arguments.
A typical result is as follows (with annotated comments)::

  $ electrumx_rpc getinfo
  {
      "coin": "BitcoinSegwit",
      "daemon": "127.0.0.1:9334/",
      "daemon height": 572154,         # The daemon's height when last queried
      "db height": 572154,             # The height to which the DB is flushed
      "groups": 586,                   # The number of session groups
      "history cache": "185,014 lookups 9,756 hits 1,000 entries",
      "merkle cache": "280 lookups 54 hits 213 entries",
      "peers": {                       # Peer information
          "bad": 1,
          "good": 51,
          "never": 2,
          "stale": 0,
          "total": 54
      },
      "pid": 11804,                    # Process ID
      "request counts": {              # Count of RPC requests by method name
          "blockchain.block.header": 245,
          "blockchain.block.headers": 70,
          "blockchain.estimatefee": 12776,
          "blockchain.headers.subscribe": 2825,
          "blockchain.relayfee": 740,
          "blockchain.scripthash.get_history": 196,
          "blockchain.scripthash.subscribe": 184626,
          "blockchain.transaction.broadcast": 19,
          "blockchain.transaction.get": 213,
          "blockchain.transaction.get_merkle": 289,
          "getinfo": 3,
          "groups": 1,
          "mempool.get_fee_histogram": 3194,
          "server.add_peer": 9,
          "server.banner": 740,
          "server.donation_address": 754,
          "server.features": 50,
          "server.peers.subscribe": 792,
          "server.ping": 6412,
          "server.version": 2866
      },
      "request total": 216820,         # Total requests served
      "sessions": {                    # Live session stats
          "count": 670,
          "count with subs": 45,
          "errors": 0,
          "logged": 0,
          "paused": 0,
          "pending requests": 79,      # Number of requests currently being processed
          "subs": 36292                # Total subscriptions
      },
      "tx hashes cache": "289 lookups 38 hits 213 entries",
      "txs sent": 19,                  # Transactions broadcast
      "uptime": "01h 39m 04s",
      "version": "ElectrumX 1.10.1"
  }

Each ill-formed request, or one that does not follow the Electrum
protocol, increments the error count of the session that sent it.

:ref:`logging <session logging>` of sessions can be enabled by RPC.

For more information on peers see :ref:`here <peers>`.

Clients that are slow to consume data sent to them are :dfn:`paused` until their socket
buffer drains sufficiently, at which point processing of requests resumes.

Apart from very short intervals, typically after a new block or when a client has just
connected, the number of unprocessed requests should be low, say 250 or fewer.  If it is
over 1,000 the server is overloaded.

Sessions are put into groups, primarily as an anti-DoS measure.  Currently each session
goes into two groups: one for an IP subnet, and one based on the timeslice it connected
in.  Each member of a group incurs a fraction of the costs of the other group members.
This appears in the `sessions_` list under the column XCost.

groups
------

Return a list of all current session groups.  Takes no arguments.

The output is quite similar to the `sessions`_ command.

log
---

Toggle logging of the given session IDs or group names.  All incoming requests for a
logged session are written to the server log.  The arguments are case-insensitive.

When a group is specified, logging is toggled for its current members only; there is no
effect on future group members.

Session IDs can be obtained in the logs or with the `sessions`_ RPC command.  Group
names can be optained with the `groups`_ RPC command.

The special string :const:`all` turns on logging of all current and future sessions,
:const:`none` turns off logging of all current and future sessions, and :const:`new`
toggles logging of future sessions.

Example::

  $ electrumx_rpc log new 6 t0 z
  [
    "logging new sessions",
    "logging session 6",
    "logging session 3",
    "logging session 57",
    "logging session 12"
    "unknown: z",
  ]

In the above command sessions 3, 12 and 57 were in group `t0` (in fact, session 6 was
too).

.. _peers:

peers
-----

Return a list of peer Electrum servers serving the same coin network.
This command takes no arguments.

Peer data is obtained via a peer discovery protocol documented
:ref:`here <Peer Discovery>`::

  $ electrumx_rpc peers
  Host                           Status   TCP   SSL Server             Min  Max  Pruning   Last Good    Last Try Tries               Source IP Address
  bch.tedy.pw                    good   50001 50002 ElectrumX 1.2.1    0.9  1.2          07h 29m 23s 07h 30m 40s     0                 peer 185.215.224.26
  shsmithgoggryfbx.onion         good   60001 60002 ElectrumX 1.2.1    0.9  1.2          07h 30m 34s 07h 30m 38s     0                 peer
  bccarihace4jdcnt.onion         good   52001 52002 ElectrumX 1.2.1    0.9  1.2          07h 30m 34s 07h 30m 39s     0                 peer
  [...]
  electroncash.checksum0.com     good   50001 50002 ElectrumX 1.2.1    0.9  1.1          07h 30m 40s 07h 30m 41s     0                 peer 149.56.198.233

.. _query:

query
-----

Run a query of the UTXO and history databases against one or more
addresses or hex scripts.  `--limit <N>` or `-l <N>` limits the output
for each kind to that many entries.  History is printed in blockchain
order; UTXOs in an arbitrary order.

For example::

  $ electrumx_rpc query --limit 5 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac
  Script: 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac
  History #1: height 123,723 tx_hash 3387418aaddb4927209c5032f515aa442a6587d6e54677f08a03b8fa7789e688
  History #2: height 127,280 tx_hash 4574958d135e66a53abf9c61950aba340e9e140be50efeea9456aa9f92bf40b5
  History #3: height 127,909 tx_hash 8b960c87f9f1a6e6910e214fcf5f9c69b60319ba58a39c61f299548412f5a1c6
  History #4: height 127,943 tx_hash 8f6b63012753005236b1b76e4884e4dee7415e05ab96604d353001662cde6b53
  History #5: height 127,943 tx_hash 60ff2dfdf67917040139903a0141f7525a7d152365b371b35fd1cf83f1d7f704
  UTXO #1: tx_hash 9aa497bf000b20f5ec5dc512bb6c1b60b68fc584d38b292b434e839ea8807bf0 tx_pos 0 height 254,148 value 5,500
  UTXO #2: tx_hash 1c998142a5a5aae6f8c1eab245351413fe8d4032a3f14345f9943a0d0bc90ec0 tx_pos 0 height 254,161 value 5,500
  UTXO #3: tx_hash 53345491b4829140be53f30079c6e4556a18545343b122900ebbfa158f9ca97a tx_pos 0 height 254,163 value 5,500
  UTXO #4: tx_hash c71ad947ac46af217da3cd5521113cbd03e36ddada2b4452afe6c15f944d2529 tx_pos 0 height 372,916 value 1,000
  UTXO #5: tx_hash c944a6acac054275a5e294e746d9ce79f6dcae91f3b4f5a84561aee6404a55b3 tx_pos 0 height 254,148 value 5,500
  Balance: 17.8983303 BCH

reorg
-----

Force a block chain reorganisation, primarily for debugging purposes.
This command takes an optional argument - the number of blocks to
reorg - which defaults to 3.

That number of blocks will be backed up - using undo information
stored in ElectrumX's database - and then ElectrumX will move forwards
on the daemon's main chain to its current height.

.. _sessions:

sessions
--------

Return a list of all current sessions.  Takes no arguments::

  ID     Flags            Client Proto    Cost   XCost  Reqs   Txs    Subs    Recv Recv KB    Sent Sent KB      Time                  Peer
  1      S6                1.1.1   1.4       0      16     0     0       0       3       0       3       0    05m42s 165.255.191.213:22349
  2      S6       all_seeing_eye   1.4       0      16     0     0       0       2       0       2       0    05m40s   67.170.52.226:24995
  4      S6                3.3.2   1.4       0      16     0     0      34      45       5      45       3    05m40s 185.220.100.252:40463
  3      S6                1.1.2   1.4       0      16     0     0       0       3       0       3       0    05m40s    89.17.142.28:59241

The columns show information by session: the session ID, flags (see below), how the client
identifies itself - typically the Electrum client version, the protocol version
negotiated, the session cost, the additional session cost accrued from its groups, the
number of unprocessed requests, the number of transactions sent, the number of address
subscriptions, the number of requests received and their total size, the number of
messages sent and their size, how long the client has been connected, and the client's IP
address (if anonymous logging is disabled).

The flags are:

 * ``S`` an SSL connection
 * ``T`` a TCP connection
 * ``R`` a local RPC connection
 * ``L`` a logged session
 * ``C`` a connection that is being closed
 * the non-negative number is the connection "cost", with lower
   numbers having higher priority.  RPC connections have cost ``0``,
   normal connections have cost at least ``1``.

stop
----

Flush all cached data to disk and shut down the server cleanly, as if
sending the `KILL` signal.  Be patient - during initial sync flushing
all cached data to disk can take several minutes.  This command takes
no arguments.

.. _session logging:
