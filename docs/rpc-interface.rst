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

  $ ./electrumx_rpc add_peer "ecdsa.net v1.0 s110 t"
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

Disconnect the given session IDs.  Session IDs can be seen in the logs
or with the `sessions`_ RPC command::

  $ ./electrumx_rpc disconnect 2 3
  [
      "disconnected 2",
      "disconnected 3"
  ]

ElectrumX initiates the socket close process for the passed sessions.
Whilst most connections close quickly, it can take several minutes for
Python to shut some SSL connections down.

getinfo
-------

Return a summary of server state.  This command takes no arguments.
A typical result is as follows (with annotated comments)::

  $ electrumx_rpc getinfo
  {
    "closing": 1,                  # The number of sessions being closed down
    "daemon": "192.168.0.2:8332/", # The daemon URL without auth info
    "daemon_height": 520527,       # The daemon's height when last queried
    "db_height": 520527,           # The height to which the DB is flushed
    "errors": 0,                   # Errors across current sessions
    "groups": 7,                   # The number of session groups
    "logged": 0,                   # The number of sessions being logged
    "paused": 0,                   # The number of paused sessions
    "peers": {                     # Various categories of server peers
        "bad": 0,                  # Not responding or invalid height etc.
        "good": 28,                # Responding with good data
        "never": 0,                # Never managed to connect
        "stale": 0,                # Was "good" but not recently connected
        "total": 28                # Sum of the above
    },
    "pid": 85861,                  # Server's process ID
    "requests": 0,                 # Unprocessed requests across all sessions
    "sessions": 43,                # Total number of sessions
    "subs": 84,                    # Script hash subscriptions across all sessions
    "txs_sent": 4,                 # Transactions sent since server started
    "uptime": "06h 48m 00s"        # Time since server started
  }

Each ill-formed request, or one that does not follow the Electrum
protocol, increments the error count of the session that sent it.  If
the error count reaches a certain level (currently ``10``) that client
is disconnected.

:ref:`logging <session logging>` of sessions can be enabled by RPC.

For more information on peers see :ref:`here <peers>`.

Clients that are slow to consume data sent to them are :dfn:`paused`
until their socket buffer drains sufficiently, at which point
processing of requests resumes.

Apart from very short intervals, typically after a new block or when
a client has just connected, the number of unprocessed requests
should normally be zero.

Sessions are put into groups, primarily as an anti-DoS measure.
Initially all connections made within a period of time are put in the
same group.  High bandwidth usage by a member of a group deprioritizes
that session, and all members of its group to a lesser extent.
Low-priority sessions have their requests served after higher priority
sessions.  ElectrumX will start delaying responses to a session if it
becomes sufficiently deprioritized.

groups
------

Return a list of all current session groups.  Takes no arguments.

The output is quite similar to the `sessions`_ command.

log
---

Toggle logging of the given session IDs.  All incoming requests for a
logged session are written to the server log.  Session IDs can be seen
in the logs or with the `sessions`_ RPC command::

  $ electrumx_rpc log 0 1 2 3 4 5
  [
      "log 0: False",
      "log 1: False",
      "log 2: False",
      "log 3: True",
      "log 4: True",
      "unknown session: 5"
  ]

The return value shows this command turned off logging for sesssions
0, 1 and 2.  It was turned on for sessions 3 and 4, and there was no
session 5.

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

  ID     Flags            Client Proto  Reqs   Txs    Subs    Recv Recv KB    Sent Sent KB      Time                Peer
  110    S1                2.9.4  0.10     0     0       0     403      28     442      37 06h41m41s  xxx.xxx.xxx.xxx:xx
  282    S1                3.1.5   1.1     0     0       0     380      25     417      40 06h21m38s  xxx.xxx.xxx.xxx:xx
  300    S1                2.9.4  0.10     0     0       0     381      25     418      34 06h19m35s  xxx.xxx.xxx.xxx:xx
  [...]
  3313   S1                2.9.3  0.10     0     0       0      22       1      22       6       07s  xxx.xxx.xxx.xxx:xx
  4      R0                  RPC   RPC     0     0       0       1       0       0       0       00s         [::1]:62479

The columns show information by session: the session ID, flags (see
below), how the client identifies itself - typically the Electrum
client version, the protocol version negotiated, the number of
unprocessed requests, the number of transactions sent, the number of
address subscriptions, the number of requests received and their total
size, the number of messages sent and their size, how long the client
has been connected, and the client's IP address (if anonymous logging
is disabled).

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
