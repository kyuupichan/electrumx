Prerequisites
=============

ElectrumX should run on any flavour of unix.  I have run it
successfully on MaxOSX and DragonFlyBSD.  It won't run out-of-the-box
on Windows, but the changes required to make it do so should be
small - patches welcome.

+ Python3:  ElectrumX uses asyncio.  Python version >=3.5 is required.
+ plyvel:   Python interface to LevelDB.  I am using plyvel-0.9.
+ aiohttp:  Python library for asynchronous HTTP.  ElectrumX uses it for
            communication with the daemon.  Version >= 1.0 required; I am
            using 1.0.5.
+ irc:      Python IRC package.  Only required if you enable IRC; ElectrumX
            will happily serve clients that try to connect directly.
            I use 15.0.4 but older versions likely are fine.
+ x11_hash: Python X11 Hash package. Only required if you use ElectrumX
            with Dash Mainnet or Testnet.  Version 1.4 tested.

While not requirements for running ElectrumX, it is intended to be run
with supervisor software such as Daniel Bernstein's daemontools,
Gerald Pape's runit package or systemd.  These make administration of secure
unix servers very easy, and I strongly recommend you install one of these
and familiarise yourself with them.  The instructions below and sample
run scripts assume daemontools; adapting to runit should be trivial
for someone used to either.

When building the database form the genesis block, ElectrumX has to
flush large quantities of data to disk and to leveldb.  You will have
a much nicer experience if the database directory is on an SSD than on
an HDD.  Currently to around height 434,000 of the Bitcoin blockchain
the final size of the leveldb database, and other ElectrumX file
metadata comes to just over 17GB.  Leveldb needs a bit more for brief
periods, and the block chain is only getting longer, so I would
recommend having at least 30-40GB free space.

Database Engine
===============

You can choose from RocksDB, LevelDB or LMDB to store transaction
information on disk. Currently, the fastest seems to be RocksDB with
LevelDB being about 10% slower. LMDB is slowest but that is because it
is not yet efficiently abstracted.

You will need to install one of:

+ `plyvel <https://plyvel.readthedocs.io/en/latest/installation.html>`_ for LevelDB
+ `pyrocksdb <http://pyrocksdb.readthedocs.io/en/v0.4/installation.html>`_ for RocksDB
+ `lmdb <https://lmdb.readthedocs.io/en/release/#installation-unix>`_ for LMDB

Running
=======

Install the prerequisites above.

Check out the code from Github::

    git clone https://github.com/kyuupichan/electrumx.git
    cd electrumx

You can install with setup.py, or run the code from the source tree or
a copy of it.

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


Using daemontools
-----------------

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


Using systemd
-------------

This repository contains a sample systemd unit file that you can use to
setup ElectrumX with systemd. Simply copy it to :code:`/etc/systemd/system`::

    cp samples/systemd-unit /etc/systemd/system/electrumx.service

The sample unit file assumes that the repository is located at
:code:`/home/electrumx/electrumx`. If that differs on your system, you need to
change the unit file accordingly.

You need to set a few configuration variables in :code:`/etc/electrumx.conf`,
see `samples/NOTES` for the list of required variables.

Now you can start ElectrumX using :code:`systemctl`::

    systemctl start electrumx

You can use :code:`journalctl` to check the log output::

    journalctl -u electrumx -f

Once configured, you may want to start ElectrumX at boot::

    systemctl enable electrumx


Sync Progress
=============

Speed indexing the blockchain depends on your hardware of course.  As
Python is single-threaded most of the time only 1 core is kept busy.
ElectrumX uses Python's asyncio to prefill a cache of future blocks
asynchronously; this keeps the CPU busy processing the chain and not
waiting for blocks to be delivered.  I therefore doubt there will be
much boost in performance if the daemon is on the same host: indeed it
may even be beneficial to have the daemon on a separate machine so the
machine doing the indexing is focussing on the one task and not the
wider network.

The HIST_MB and CACHE_MB environment variables control cache sizes
before they spill to disk; see the NOTES file under samples/scripts.

Here is my experience with the current codebase, to given heights and
rough wall-time::

                 Machine A     Machine B    DB + Metadata
  181,000                       7m 09s       0.4 GiB
  255,000                       1h 02m       2.7 GiB
  289,000                       1h 46m       3.3 GiB
  317,000                       2h 33m
  351,000                       3h 58m
  377,000                       6h 06m       6.5 GiB
  403,400                       8h 51m
  436,196                      14h 03m      17.3 GiB

Machine A: a low-spec 2011 1.6GHz AMD E-350 dual-core fanless CPU, 8GB
RAM and a DragonFlyBSD HAMMER fileystem on an SSD.  It requests blocks
over the LAN from a bitcoind on machine B.

Machine B: a late 2012 iMac running El-Capitan 10.11.6, 2.9GHz
quad-core Intel i5 CPU with an HDD and 24GB RAM.  Running bitcoind on
the same machine.  HIST_MB of 350, UTXO_MB of 1,600.  LevelDB.

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
patient as disk flushing can take many minutes.

ElectrumX flushes to leveldb using its transaction functionality.  The
plyvel documentation claims this is atomic.  I have written ElectrumX
with the intent that, to the extent this atomicity guarantee holds,
the database should not get corrupted even if the ElectrumX process if
forcibly killed or there is loss of power.  The worst case is losing
unflushed in-memory blockchain processing and having to restart from
the state as of the prior successfully completed UTXO flush.

If you do have any database corruption as a result of terminating the
process (without modifying the code) I would be interested in the
details.

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

  2016-10-14 20:22:10.747808500 Launching ElectrumX server...
  2016-10-14 20:22:13.032415500 INFO:root:ElectrumX server starting
  2016-10-14 20:22:13.032633500 INFO:root:switching current directory to /Users/neil/server-btc
  2016-10-14 20:22:13.038495500 INFO:DB:created new database Bitcoin-mainnet
  2016-10-14 20:22:13.038892500 INFO:DB:Bitcoin/mainnet height: -1 tx count: 0 flush count: 0 utxo flush count: 0 sync time: 0d 00h 00m 00s
  2016-10-14 20:22:13.038935500 INFO:DB:flushing all after cache reaches 2,000 MB
  2016-10-14 20:22:13.038978500 INFO:DB:flushing history cache at 400 MB
  2016-10-14 20:22:13.039076500 INFO:BlockCache:using RPC URL http://user:password@192.168.0.2:8332/
  2016-10-14 20:22:13.039796500 INFO:BlockCache:catching up, block cache limit 10MB...
  2016-10-14 20:22:14.092192500 INFO:DB:cache stats at height 0  daemon height: 434,293
  2016-10-14 20:22:14.092243500 INFO:DB:  entries: UTXO: 1  DB: 0  hist count: 1  hist size: 1
  2016-10-14 20:22:14.092288500 INFO:DB:  size: 0MB  (UTXOs 0MB hist 0MB)
  2016-10-14 20:22:32.302394500 INFO:UTXO:duplicate tx hash d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599
  2016-10-14 20:22:32.310441500 INFO:UTXO:duplicate tx hash e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468
  2016-10-14 20:23:14.094855500 INFO:DB:cache stats at height 125,278  daemon height: 434,293
  2016-10-14 20:23:14.095026500 INFO:DB:  entries: UTXO: 191,155  DB: 0  hist count: 543,455  hist size: 1,394,187
  2016-10-14 20:23:14.095028500 INFO:DB:  size: 172MB  (UTXOs 44MB hist 128MB)

Under normal operation these cache stats repeat roughly every minute.
Flushes can take many minutes and look like this::

  2016-10-14 21:30:29.085479500 INFO:DB:flushing UTXOs: 22,910,848 txs and 254,753 blocks
  2016-10-14 21:32:05.383413500 INFO:UTXO:UTXO cache adds: 55,647,862 spends: 48,751,219
  2016-10-14 21:32:05.383460500 INFO:UTXO:UTXO DB adds: 6,875,315 spends: 0. Collisions: hash168: 268 UTXO: 0
  2016-10-14 21:32:07.056008500 INFO:DB:6,982,386 history entries in 1,708,991 addrs
  2016-10-14 21:32:08.169468500 INFO:DB:committing transaction...
  2016-10-14 21:33:17.644296500 INFO:DB:flush #11 to height 254,752 took 168s
  2016-10-14 21:33:17.644357500 INFO:DB:txs: 22,910,848  tx/sec since genesis: 5,372, since last flush: 3,447
  2016-10-14 21:33:17.644536500 INFO:DB:sync time: 0d 01h 11m 04s  ETA: 0d 11h 22m 42s

After flush-to-disk you may see an aiohttp error; this is the daemon
timing out the connection while the disk flush was in progress.  This
is harmless.

The ETA is just a guide and can be quite volatile around flushes.
