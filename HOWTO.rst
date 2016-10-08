Prerequisites
=============

ElectrumX should run on any flavour of unix.  I have run it
successfully on MaxOSX and DragonFlyBSD.  It won't run out-of-the-box
on Windows, but the changes required to make it do so should be
small - patches welcome.

+ Python3  ElectrumX makes heavy use of asyncio so version >=3.5 is required
+ plyvel   Python interface to LevelDB.  I am using plyvel-0.9.
+ aiohttp  Python library for asynchronous HTTP.  ElectrumX uses it for
           communication with the daemon.  I am using aiohttp-0.21.

While not requirements for running ElectrumX, it is intended to be run
with supervisor software such as Daniel Bernstein's daemontools, or
Gerald Pape's runit package.  These make administration of secure
unix servers very easy, and I strongly recommend you install one of these
and familiarise yourself with them.  The instructions below and sample
run scripts assume daemontools; adapting to runit should be trivial
for someone used to either.

When building the database form the genesis block, ElectrumX has to
flush large quantities of data to disk and to leveldb.  You will have
a much nicer experience if the database directory is on an SSD than on
an HDD.  Currently to around height 430,000 of the Bitcoin blockchain
the final size of the leveldb database, and other ElectrumX file
metadata comes to around 15GB.  Leveldb needs a bit more for brief
periods, and the block chain is only getting longer, so I would
recommend having at least 30-40GB free space.


Running
=======

Install the prerequisites above.

Check out the code from Github::

    git clone https://github.com/kyuupichan/electrumx.git
    cd electrumx

I have not yet created a setup.py, so for now I suggest you run
the code from the source tree or a copy of it.

You should create a standard user account to run the server under;
your own is probably adequate unless paranoid.  The paranoid might
also want to create another user account for the daemontools logging
process.  The sample scripts and these instructions assume it is all
under one account which I have called 'electrumx'.

Next create a directory where the database will be stored and make it
writeable by the electrumx account.  I recommend this directory live
on an SSD::

    mkdir /path/to/db_directory
    chown electrumx /path/to/db_directory

Next create a daemontools service directory; this only holds symlinks
(see daemontools documentation).  The 'svscan' program will ensure the
servers in the directory are running by launching a 'supervise'
supervisor for the server and another for its logging process.  You
can run 'svscan' under the electrumx account if that is the only one
involved (server and logger) otherwise it will need to run as root so
that the user can be switched to electrumx.

Assuming this directory is called service, you would do one of::

    mkdir /service       # If running svscan as root
    mkdir ~/service      # As electrumx if running svscan as that a/c

Next create a directory to hold the scripts that the 'supervise'
process spawned by 'svscan' will run - this directory must be readable
by the 'svscan' process.  Suppose this directory is called scripts, you
might do::

    mkdir -p ~/scripts/electrumx

Then copy the all sample scripts from the ElectrumX source tree there::

    cp -R /path/to/repo/electrumx/samples/scripts ~/scripts/electrumx

This copies 4 things: the top level server run script, a log/ directory
with the logger run script, an env/ directory, and a NOTES file.

You need to configure the environment variables under env/ to your
setup, as explained in NOTES.  ElectrumX server currently takes no
command line arguments; all of its configuration is taken from its
environment which is set up according to env/ directory (see 'envdir'
man page).  Finally you need to change the log/run script to use the
directory where you want the logs to be written by multilog.  The
directory need not exist as multilog will create it, but its parent
directory must exist.

Now start the 'svscan' process.  This will not do much as the service
directory is still empty::

    svscan ~/service & disown

svscan is now waiting for services to be added to the directory::

    cd ~/service
    ln -s ~/scripts/electrumx electrumx

Creating the symlink will kick off the server process almost immediately.
You can see its logs with::

    tail -F /path/to/log/dir/current | tai64nlocal


Progress
========

Speed indexing the blockchain depends on your hardware of course.  As
Python is single-threaded most of the time only 1 core is kept busy.
ElectrumX uses Python's asyncio to prefill a cache of future blocks
asynchronously; this keeps the CPU busy processing the chain and not
waiting for blocks to be delivered.  I therefore doubt there will be
much boost in performance if the daemon is on the same host: indeed it
may even be beneficial to have the daemon on a separate machine so the
machine doing the indexing is focussing on the one task and not the
wider network.

The FLUSH_SIZE environment variable is an upper bound on how much
unflushed data is cached before writing to disk + leveldb.  The
default is 4 million items, which is probably fine unless your
hardware is quite poor.  If you've got a really fat machine with lots
of RAM, 10 million or even higher is likely good (I used 10 million on
Machine B below without issue so far).  A higher number will have
fewer flushes and save your disk thrashing, but you don't want it so
high your machine is swapping.  If your machine loses power all
synchronization since the previous flush is lost.

When syncing, ElectrumX is CPU bound over 70% of the time, with the
rest being bursts of disk activity whilst flushing.  Here is my
experience with the current codebase, to given heights and rough
wall-time::

                 Machine A     Machine B    DB + Metadata
  100,000        2m            30s          0  (unflushed)
  150,000        35m           4m 30s       0.2 GB
  180,000        1h 5m         9m           0.4 GB
  245,800        3h            1h 30m       2.7 GB
  290,000        13h 15m       3h 5m        3.3 GB

Machine A: a low-spec 2011 1.6GHz AMD E-350 dual-core fanless CPU, 8GB
RAM and a DragonFlyBSD HAMMER fileystem on an SSD.  It requests blocks
over the LAN from a bitcoind on machine B.  FLUSH_SIZE: I changed it
several times between 1 and 5 million during the sync which causes the
above stats to be a little approximate.  Initial FLUSH_SIZE was 1
million and first flush at height 126,538.

Machine B: a late 2012 iMac running El-Capitan 10.11.6, 2.9GHz
quad-core Intel i5 CPU with an HDD and 24GB RAM.  Running bitcoind on
the same machine.  FLUSH_SIZE of 10 million.  First flush at height
195,146.

Transactions processed per second seems to gradually decrease over
time but this statistic is not currently logged and I've not looked
closely.

For chains other than bitcoin-mainnet sychronization should be much
faster.


Terminating ElectrumX
=====================

The preferred way to terminate the server process is to send it the
TERM signal.  For a daemontools supervised process this is best done
by bringing it down like so::

    svc -d ~/service/electrumx

If processing the blockchain the server will start the process of
flushing to disk.  Once that is complete the server will exit.  Be
patient as disk flushing can take a while.

ElectrumX flushes to leveldb using its transaction functionality.  The
plyvel documentation claims this is atomic.  I have written ElectrumX
with the intent that, to the extent this atomicity guarantee holds,
the database should not get corrupted even if the ElectrumX process if
forcibly killed or there is loss of power.  The worst case is losing
unflushed in-memory blockchain processing and having to restart from
the state as of the prior successfully completed flush.

During development I have terminated ElectrumX processes in various
ways and at random times, and not once have I had any corruption as a
result of doing so.  Mmy only DB corruption has been through buggy
code.  If you do have any database corruption as a result of
terminating the process without modifying the code I would be very
interested in hearing details.

I have heard about corruption issues with electrum-server.  I cannot
be sure but with a brief look at the code it does seem that if
interrupted at the wrong time the databases it uses could become
inconsistent.

Once the process has terminated, you can start it up again with::

    svc -u ~/service/electrumx

You can see the status of a running service with::

    svstat ~/service/electrumx

Of course, svscan can handle multiple services simultaneously from the
same service directory, such as a testnet or altcoin server.  See the
man pages of these various commands for more information.



Understanding the Logs
======================

You can see the logs usefully like so::

    tail -F /path/to/log/dir/current | tai64nlocal

Here is typical log output on startup::


  2016-10-08 14:46:48.088516500 Launching ElectrumX server...
  2016-10-08 14:46:49.145281500 INFO:root:ElectrumX server starting
  2016-10-08 14:46:49.147215500 INFO:root:switching current directory to /var/nohist/server-test
  2016-10-08 14:46:49.150765500 INFO:DB:using flush size of 1,000,000 entries
  2016-10-08 14:46:49.156489500 INFO:DB:created new database Bitcoin-mainnet
  2016-10-08 14:46:49.157531500 INFO:DB:flushing to levelDB 0 txs and 0 blocks to height -1 tx count: 0
  2016-10-08 14:46:49.158640500 INFO:DB:flushed. Cache hits: 0/0 writes: 5 deletes: 0 elided: 0 sync: 0d 00h 00m 00s
  2016-10-08 14:46:49.159508500 INFO:RPC:using RPC URL http://user:pass@192.168.0.2:8332/
  2016-10-08 14:46:49.167352500 INFO:BlockCache:catching up, block cache limit 10MB...
  2016-10-08 14:46:49.318374500 INFO:BlockCache:prefilled 10 blocks to height 10 daemon height: 433,401 block cache size: 2,150
  2016-10-08 14:46:50.193962500 INFO:BlockCache:prefilled 4,000 blocks to height 4,010 daemon height: 433,401 block cache size: 900,043
  2016-10-08 14:46:51.253644500 INFO:BlockCache:prefilled 4,000 blocks to height 8,010 daemon height: 433,401 block cache size: 1,600,613
  2016-10-08 14:46:52.195633500 INFO:BlockCache:prefilled 4,000 blocks to height 12,010 daemon height: 433,401 block cache size: 2,329,325

Under normal operation these prefill messages repeat fairly regularly.
Occasionally (depending on how big your FLUSH_SIZE environment
variable was set, and your hardware, this could be anything from every
5 minutes to every hour) you will get a flush to disk that begins with:

    2016-10-08 06:34:20.841563500 INFO:DB:flushing to levelDB 828,190 txs and 3,067 blocks to height 243,982 tx count: 20,119,669

During the flush, which can take many minutes, you may see logs like
this:

    2016-10-08 12:20:08.558750500 INFO:DB:address 1dice7W2AicHosf5EL3GFDUVga7TgtPFn hist moving to idx 3000

These are just informational messages about addresses that have very
large histories that are generated as those histories are being
written out.  After the flush has completed a few stats are printed
about cache hits, the number of writes and deletes, and the number of
writes that were elided by the cache::

    2016-10-08 06:37:41.035139500 INFO:DB:flushed. Cache hits: 3,185,958/192,336 writes: 781,526 deletes: 465,236 elided: 3,185,958 sync: 0d 06h 57m 03s

After flush-to-disk you may see an aiohttp error; this is the daemon
timing out the connection while the disk flush was in progress.  This
is harmless; I intend to fix this soon by yielding whilst flushing.

You may see one or two logs about ambiguous UTXOs or hash160s::

    2016-10-08 07:24:34.068609500 INFO:DB:UTXO compressed key collision at height 252943 utxo 115cc1408e5321636675a8fcecd204661a6f27b4b7482b1b7c4402ca4b94b72f / 1

These are informational messages about an artefact of the compression
scheme ElectrumX uses and are harmless.  However, if you see more than
a handful of these, particularly close together, something is very
wrong and your DB is probably corrupt.
