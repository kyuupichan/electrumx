The ElectrumX RPC Interface
===========================

You can query the status of a running server, and affect its behaviour
using the RPC interface.

The general form of invocation is:

    ``electrumx_rpc.py <command> [arg1 [arg2...]``

The following commands are available:

* **getinfo**

  Returns a summary of server state.  This command takes no arguments.
  A typical result is as follows (with annotated comments):

  .. code::

     $ electrumx_rpc.py getinfo
     {
         "closing": 1,              # The number of sessions being closed down
         "daemon_height": 446231,   # The daemon's height when last queried
         "db_height": 446231,       # The height to which the DB is processed
         "errors": 1,               # Errors across current sessions
         "groups": 2,               # The number of session groups
         "logged": 0,               # The number of sessions being logged
         "paused": 0,               # The number of paused sessions.
         "peers": 62,               # Number of peer servers (from IRC)
         "pid": 126275,             # The server's process ID
         "requests": 0,             # Number of unprocessed requests
         "sessions": 85,            # Number of current sessions (connections)
         "subs": 6235,              # Number of current address subscriptions
         "txs_sent": 2              # Total transactions sent by ElectrumX
     }

  Clients that are slow to consume data sent to them are *paused*
  until their socket buffer drains sufficiently, at which point
  processing of requests resumes.

  Each ill-formed request, or one that does not follow the Electrum
  protocol, increments the error count of the session that sent it.
  If the error count reaches a certain level (currently 10) that
  client is disconnected.

  Apart from very short intervals, typically after a new block or when
  a client has just connected, the number of unprocessed requests
  should normally be zero.

  Sessions are put into groups, primarily as an anti-DoS measure.
  Initially all connections made within a period of time are put in
  the same group.  High bandwidth usage by a member of a group
  deprioritizes itself, and all members of its group to a lesser
  extent.  Low-priority sessions have their requests served after
  higher priority sessions.  ElectrumX will start delaying responses
  to a sessions if it becomes sufficiently deprioritized.

* **sessions**

  Returns a list of all current sessions.  Takes no arguments.

  .. code::

    $ electrumx_rpc.py sessions

    ID     Flags          Client  Reqs   Txs    Subs    Recv Recv KB    Sent Sent KB      Time                  Peer
    0      S1             2.7.12     0     0     293     352      34     355      35   0:49:27      192.168.0.1:4093
    1      T1              2.5.2     0     0      87     141      12     144      13   0:49:25     xxx.xx.xx.x:39272
    2      T1     all_seeing_eye     0     0       0      10       0      13       2   0:49:25   xxx.xx.xxx.xx:57862
    3      S1     all_seeing_eye     0     0       0      10       0      13       2   0:49:25   xxx.xx.xxx.xx:41315
    4      S1              2.6.4     0     0   2,048   2,104     215   2,108     122   0:49:25   xxx.xx.xxx.xx:35287
    ...
    435    R0                RPC     0     0       0       1       0       0       0   0:00:00            [::1]:1484


  The columns show the session ID, flags (see below), how the client
  identifies itself - typically the Electrum client version, the
  number of unprocessed requests, the number of transactions sent, the
  number of address subscriptions, the number of requests received and
  the bandwidth used, the number of messages sent and the bandwidth
  used, how long the client has been connected, and the client's IP
  address.

  The flags are:

     * S an SSL connection
     * T a TCP connection
     * R a local RPC connection
     * L a logged session
     * C a connection that is being closed
     * the non-negative number is the connection priority, with lower
       numbers having higher priority.  RPC connections have priority
       0, normal connections have priority at least 1.

* **groups**

  Returns a list of all current groups.  Takes no arguments.

  The output is quite similar to the **sessions** command.

* **disconnect**

  Disconnects the given session IDs.  Session IDs can be seen in the
  logs or with the **sessions** RPC command.

  .. code::

    $ ./electrumx_rpc.py disconnect 2 3
    [
        "disconnected 2",
        "disconnected 3"
    ]

  ElectrumX initiates the socket close process for the passed
  sessions.  Whilst most connections close quickly, it can take
  several minutes for Python to close some SSL connections down.

* **log**

  Toggles logging of the given session IDs.  All incoming requests for
  a logged session are written to the server log.  Session IDs can be
  seen in the logs or with the **sessions** RPC command.

  .. code::

    $ electrumx_rpc.py log 0 1 2 3 4 5
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

* **peers**

  Returns a list of peer electrum servers.  This command takes no arguments.

  Currently this is data gleaned from an IRC session.
