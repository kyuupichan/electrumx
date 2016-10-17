# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import asyncio
import signal
import traceback
from functools import partial

from server.daemon import Daemon, DaemonError
from server.db import DB
from server.protocol import ElectrumX, LocalRPC
from lib.hash import (sha256, double_sha256, hash_to_str,
                      Base58, hex_str_to_hash)
from lib.util import LoggedClass


class Controller(LoggedClass):

    def __init__(self, env):
        '''Create up the controller.

        Creates DB, Daemon and BlockCache instances.
        '''
        super().__init__()
        self.env = env
        self.db = DB(env)
        self.daemon = Daemon(env.daemon_url)
        self.block_cache = BlockCache(self.db, self.daemon)
        self.servers = []
        self.sessions = set()
        self.addresses = {}
        self.jobs = set()
        self.peers = {}

    def start(self, loop):
        '''Prime the event loop with asynchronous servers and jobs.'''
        env = self.env

        if False:
            protocol = partial(LocalRPC, self)
            if env.rpc_port is not None:
                host = 'localhost'
                rpc_server = loop.create_server(protocol, host, env.rpc_port)
                self.servers.append(loop.run_until_complete(rpc_server))
                self.logger.info('RPC server listening on {}:{:d}'
                                 .format(host, env.rpc_port))

            protocol = partial(ElectrumX, self, self.db, self.daemon, env)
            if env.tcp_port is not None:
                tcp_server = loop.create_server(protocol, env.host, env.tcp_port)
                self.servers.append(loop.run_until_complete(tcp_server))
                self.logger.info('TCP server listening on {}:{:d}'
                                 .format(env.host, env.tcp_port))

            if env.ssl_port is not None:
                ssl_server = loop.create_server(protocol, env.host, env.ssl_port)
                self.servers.append(loop.run_until_complete(ssl_server))
                self.logger.info('SSL server listening on {}:{:d}'
                                 .format(env.host, env.ssl_port))

        coros = [
            self.block_cache.prefetcher(),
            self.block_cache.process_blocks(),
        ]

        for coro in coros:
            asyncio.ensure_future(coro)

        # Signal handlers
        for signame in ('SIGINT', 'SIGTERM'):
            loop.add_signal_handler(getattr(signal, signame),
                                    partial(self.on_signal, loop, signame))

    def stop(self):
        '''Close the listening servers.'''
        for server in self.servers:
            server.close()

    def on_signal(self, loop, signame):
        '''Call on receipt of a signal to cleanly shutdown.'''
        self.logger.warning('received {} signal, preparing to shut down'
                            .format(signame))
        for task in asyncio.Task.all_tasks(loop):
            task.cancel()

    def add_session(self, session):
        self.sessions.add(session)

    def remove_session(self, session):
        self.sessions.remove(session)

    def add_job(self, coro):
        '''Queue a job for asynchronous processing.'''
        self.jobs.add(asyncio.ensure_future(coro))

    async def reap_jobs(self):
        while True:
            jobs = set()
            for job in self.jobs:
                if job.done():
                    try:
                        job.result()
                    except Exception as e:
                        traceback.print_exc()
                else:
                    jobs.add(job)
            self.logger.info('reaped {:d} jobs, {:d} jobs pending'
                             .format(len(self.jobs) - len(jobs), len(jobs)))
            self.jobs = jobs
            await asyncio.sleep(5)

    def address_status(self, hash168):
        '''Returns status as 32 bytes.'''
        status = self.addresses.get(hash168)
        if status is None:
            status = ''.join(
                '{}:{:d}:'.format(hash_to_str(tx_hash), height)
                for tx_hash, height in self.db.get_history(hash168)
            )
            if status:
                status = sha256(status.encode())
            self.addresses[hash168] = status

        return status

    async def get_merkle(self, tx_hash, height):
        '''tx_hash is a hex string.'''
        block_hash = await self.daemon.send_single('getblockhash', (height,))
        block = await self.daemon.send_single('getblock', (block_hash, True))
        tx_hashes = block['tx']
        # This will throw if the tx_hash is bad
        pos = tx_hashes.index(tx_hash)

        idx = pos
        hashes = [hex_str_to_hash(txh) for txh in tx_hashes]
        merkle_branch = []
        while len(hashes) > 1:
            if len(hashes) & 1:
                hashes.append(hashes[-1])
            idx = idx - 1 if (idx & 1) else idx + 1
            merkle_branch.append(hash_to_str(hashes[idx]))
            idx //= 2
            hashes = [double_sha256(hashes[n] + hashes[n + 1])
                      for n in range(0, len(hashes), 2)]

        return {"block_height": height, "merkle": merkle_branch, "pos": pos}

    def get_peers(self):
        '''Returns a dictionary of IRC nick to (ip, host, ports) tuples, one
        per peer.'''
        return self.peers

class BlockCache(LoggedClass):
    '''Requests and caches blocks ahead of time from the daemon.  Serves
    them to the blockchain processor.  Coordinates backing up in case of
    block chain reorganisations.
    '''

    def __init__(self, db, daemon):
        super().__init__()
        self.db = db
        self.daemon = daemon
        # Target cache size.  Has little effect on sync time.
        self.target_cache_size = 10 * 1024 * 1024
        self.daemon_height = 0
        self.fetched_height = db.height
        self.queue = asyncio.Queue()
        self.queue_size = 0
        self.recent_sizes = [0]

    def flush_db(self):
        self.db.flush(self.daemon_height, True)

    async def process_blocks(self):
        try:
            while True:
                blocks, total_size = await self.queue.get()
                self.queue_size -= total_size
                for block in blocks:
                    self.db.process_block(block, self.daemon_height)
                    # Release asynchronous block fetching
                    await asyncio.sleep(0)

                if self.db.height == self.daemon_height:
                    self.logger.info('caught up to height {:d}'
                                     .format(self.daemon_height))
                    self.flush_db()
        finally:
            self.flush_db()

    async def prefetcher(self):
        '''Loops forever polling for more blocks.'''
        self.logger.info('prefetching blocks...')
        while True:
            try:
                await self.maybe_prefetch()
            except DaemonError as e:
                self.logger.info('ignoring daemon errors: {}'.format(e))
            await asyncio.sleep(2)

    def cache_used(self):
        return sum(len(block) for block in self.blocks)

    def prefill_count(self, room):
        ave_size = sum(self.recent_sizes) // len(self.recent_sizes)
        count = room // ave_size if ave_size else 0
        return max(count, 10)

    async def maybe_prefetch(self):
        '''Prefetch blocks if there are any to prefetch.'''
        daemon = self.daemon
        while self.queue_size < self.target_cache_size:
            # Keep going by getting a whole new cache_limit of blocks
            self.daemon_height = await daemon.send_single('getblockcount')
            max_count = min(self.daemon_height - self.fetched_height, 4000)
            count = min(max_count, self.prefill_count(self.target_cache_size))
            if not count:
                break

            first = self.fetched_height + 1
            param_lists = [[height] for height in range(first, first + count)]
            hashes = await daemon.send_vector('getblockhash', param_lists)

            # Hashes is an array of hex strings
            param_lists = [(h, False) for h in hashes]
            blocks = await daemon.send_vector('getblock', param_lists)
            self.fetched_height += count

            # Convert hex string to bytes
            blocks = [bytes.fromhex(block) for block in blocks]
            sizes = [len(block) for block in blocks]
            total_size = sum(sizes)
            self.queue.put_nowait((blocks, total_size))
            self.queue_size += total_size

            # Keep 50 most recent block sizes for fetch count estimation
            self.recent_sizes.extend(sizes)
            excess = len(self.recent_sizes) - 50
            if excess > 0:
                self.recent_sizes = self.recent_sizes[excess:]
