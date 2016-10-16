# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import asyncio
import json
import signal
import traceback
from functools import partial

import aiohttp

from server.db import DB
from server.protocol import ElectrumX, LocalRPC
from lib.hash import sha256, hash_to_str, Base58
from lib.util import LoggedClass


class Controller(LoggedClass):

    def __init__(self, env):
        super().__init__()
        self.env = env
        self.db = DB(env)
        self.block_cache = BlockCache(env, self.db)
        self.servers = []
        self.sessions = set()
        self.addresses = {}
        self.jobs = set()
        self.peers = {}

    def start(self, loop):
        env = self.env

        protocol = partial(LocalRPC, self)
        if env.rpc_port is not None:
            host = 'localhost'
            rpc_server = loop.create_server(protocol, host, env.rpc_port)
            self.servers.append(loop.run_until_complete(rpc_server))
            self.logger.info('RPC server listening on {}:{:d}'
                             .format(host, env.rpc_port))

        protocol = partial(ElectrumX, self, env)
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
            self.reap_jobs(),
            self.block_cache.catch_up(),
            self.block_cache.process_cache()
        ]

        self.tasks = [asyncio.ensure_future(coro) for coro in coros]

        # Signal handlers
        for signame in ('SIGINT', 'SIGTERM'):
            loop.add_signal_handler(getattr(signal, signame),
                                    partial(self.on_signal, signame))

        return self.tasks

    def stop(self):
        for server in self.servers:
            server.close()

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

    def on_signal(self, signame):
        self.logger.warning('received {} signal, preparing to shut down'
                            .format(signame))
        for task in self.tasks:
            task.cancel()

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

    def get_peers(self):
        '''Returns a dictionary of IRC nick to (ip, host, ports) tuples, one
        per peer.'''
        return self.peers


class BlockCache(LoggedClass):
    '''Requests blocks ahead of time from the daemon.  Serves them
    to the blockchain processor.'''

    def __init__(self, env, db):
        super().__init__()
        self.db = db
        self.daemon_url = env.daemon_url
        # Cache target size is in MB.  Has little effect on sync time.
        self.cache_limit = 10
        self.daemon_height = 0
        self.fetched_height = db.height
        # Blocks stored in reverse order.  Next block is at end of list.
        self.blocks = []
        self.recent_sizes = []
        self.ave_size = 0

        self.logger.info('using daemon URL {}'.format(self.daemon_url))

    async def process_cache(self):
        while True:
            await asyncio.sleep(1)
            while self.blocks:
                self.db.process_block(self.blocks.pop(), self.daemon_height)
                # Release asynchronous block fetching
                await asyncio.sleep(0)

    async def catch_up(self):
        self.logger.info('catching up, block cache limit {:d}MB...'
                         .format(self.cache_limit))

        try:
            while await self.maybe_prefill():
                await asyncio.sleep(1)
            self.logger.info('caught up to height {:d}'
                             .format(self.daemon_height))
        finally:
            self.db.flush(self.daemon_height, True)

    def cache_used(self):
        return sum(len(block) for block in self.blocks)

    def prefill_count(self, room):
        count = 0
        if self.ave_size:
            count = room // self.ave_size
        return max(count, 10)

    async def maybe_prefill(self):
        '''Returns False to stop.  True to sleep a while for asynchronous
        processing.'''
        cache_limit = self.cache_limit * 1024 * 1024
        while True:
            cache_used = self.cache_used()
            if cache_used > cache_limit:
                return True

            # Keep going by getting a whole new cache_limit of blocks
            self.daemon_height = await self.send_single('getblockcount')
            max_count = min(self.daemon_height - self.fetched_height, 4000)
            count = min(max_count, self.prefill_count(cache_limit))
            if not count:
                return False  # Done catching up

            first = self.fetched_height + 1
            param_lists = [[height] for height in range(first, first + count)]
            hashes = await self.send_vector('getblockhash', param_lists)

            # Hashes is an array of hex strings
            param_lists = [(h, False) for h in hashes]
            blocks = await self.send_vector('getblock', param_lists)
            self.fetched_height += count

            # Convert hex string to bytes
            blocks = [bytes.fromhex(block) for block in blocks]
            # Reverse order and place at front of list
            self.blocks = list(reversed(blocks)) + self.blocks

            # Keep 50 most recent block sizes for fetch count estimation
            sizes = [len(block) for block in blocks]
            self.recent_sizes.extend(sizes)
            excess = len(self.recent_sizes) - 50
            if excess > 0:
                self.recent_sizes = self.recent_sizes[excess:]
            self.ave_size = sum(self.recent_sizes) // len(self.recent_sizes)

    async def send_single(self, method, params=None):
        payload = {'method': method}
        if params:
            payload['params'] = params
        result, = await self.send((payload, ))
        return result

    async def send_many(self, mp_pairs):
        payload = [{'method': method, 'params': params}
                   for method, params in mp_pairs]
        return await self.send(payload)

    async def send_vector(self, method, params_list):
        payload = [{'method': method, 'params': params}
                   for params in params_list]
        return await self.send(payload)

    async def send(self, payload):
        assert isinstance(payload, (tuple, list))
        data = json.dumps(payload)
        while True:
            try:
                async with aiohttp.post(self.daemon_url, data = data) as resp:
                    result = await resp.json()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                msg = 'aiohttp error: {}'.format(e)
                secs = 3
            else:
                errs = tuple(item['error'] for item in result)
                if not any(errs):
                    return tuple(item['result'] for item in result)
                if any(err.get('code') == -28 for err in errs):
                    msg = 'daemon still warming up.'
                    secs = 30
                else:
                    msg = 'daemon errors: {}'.format(errs)
                    secs = 3

            self.logger.error('{}.  Sleeping {:d}s and trying again...'
                              .format(msg, secs))
            await asyncio.sleep(secs)
