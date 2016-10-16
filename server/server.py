# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import asyncio
import json
import logging
import signal
from functools import partial

import aiohttp

from server.db import DB
from server.rpc import ElectrumRPCServer


class Server(object):

    def __init__(self, env):
        self.env = env
        self.db = DB(env)
        self.block_cache = BlockCache(env, self.db)
        self.rpc_server = ElectrumRPCServer(self)

        # Signal handlers
        loop = asyncio.get_event_loop()
        for signame in ('SIGINT', 'SIGTERM'):
            loop.add_signal_handler(getattr(signal, signame),
                                    partial(self.on_signal, signame))

        coros = self.rpc_server.tasks(env.electrumx_rpc_port)
        coros += [self.block_cache.catch_up(),
                  self.block_cache.process_cache()]
        self.tasks = [asyncio.ensure_future(coro) for coro in coros]

    async def handle_rpc_getinfo(self, params):
        return None, {
            'blocks': self.db.height,
            'peers': 0,
            'sessions': 0,
            'watched': 0,
            'cached': 0,
        }

    async def handle_rpc_sessions(self, params):
        return None, []

    async def handle_rpc_numsessions(self, params):
        return None, 0

    async def handle_rpc_peers(self, params):
        return None, []

    async def handle_rpc_banner_update(self, params):
        return None, 'FIXME'

    def on_signal(self, signame):
        logging.warning('received {} signal, preparing to shut down'
                        .format(signame))
        for task in self.tasks:
            task.cancel()

    def async_tasks(self):
        return self.tasks


class BlockCache(object):
    '''Requests blocks ahead of time from the daemon.  Serves them
    to the blockchain processor.'''

    def __init__(self, env, db):
        self.logger = logging.getLogger('BlockCache')
        self.logger.setLevel(logging.INFO)

        self.db = db
        self.rpc_url = env.rpc_url
        # Cache target size is in MB.  Has little effect on sync time.
        self.cache_limit = 10
        self.daemon_height = 0
        self.fetched_height = db.height
        # Blocks stored in reverse order.  Next block is at end of list.
        self.blocks = []
        self.recent_sizes = []
        self.ave_size = 0

        self.logger.info('using RPC URL {}'.format(self.rpc_url))

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
                async with aiohttp.post(self.rpc_url, data = data) as resp:
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
