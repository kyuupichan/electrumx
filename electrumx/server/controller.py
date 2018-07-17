# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

import asyncio
import traceback
from concurrent.futures import ThreadPoolExecutor

import pylru

from aiorpcx import RPCError, TaskSet, _version as aiorpcx_version
import electrumx
from electrumx.lib.hash import hash_to_hex_str, hex_str_to_hash
from electrumx.lib.server_base import ServerBase
import electrumx.lib.util as util
from electrumx.server.daemon import DaemonError
from electrumx.server.mempool import MemPool
from electrumx.server.peers import PeerManager
from electrumx.server.session import (BAD_REQUEST, DAEMON_ERROR,
                                      SessionManager, non_negative_integer)


class Controller(ServerBase):
    '''Manages the client servers, a mempool, and a block processor.

    Servers are started immediately the block processor first catches
    up with the daemon.
    '''

    AIORPCX_MIN = (0, 5, 6)

    def __init__(self, env):
        '''Initialize everything that doesn't require the event loop.'''
        super().__init__(env)

        version_string = util.version_string
        if aiorpcx_version < self.AIORPCX_MIN:
            raise RuntimeError('ElectrumX requires aiorpcX >= '
                               f'{version_string(self.AIORPCX_MIN)}')

        min_str, max_str = env.coin.SESSIONCLS.protocol_min_max_strings()
        self.logger.info(f'software version: {electrumx.version}')
        self.logger.info(f'aiorpcX version: {version_string(aiorpcx_version)}')
        self.logger.info(f'supported protocol versions: {min_str}-{max_str}')
        self.logger.info(f'event loop policy: {env.loop_policy}')

        self.coin = env.coin
        self.tasks = TaskSet()
        self.history_cache = pylru.lrucache(256)
        self.header_cache = pylru.lrucache(8)
        self.cache_height = 0
        self.cache_mn_height = 0
        self.mn_cache = pylru.lrucache(256)
        env.max_send = max(350000, env.max_send)

        self.loop = asyncio.get_event_loop()
        self.executor = ThreadPoolExecutor()
        self.loop.set_default_executor(self.executor)

        # The complex objects.  Note PeerManager references self.loop (ugh)
        self.session_mgr = SessionManager(env, self)
        self.daemon = self.coin.DAEMON(env)
        self.bp = self.coin.BLOCK_PROCESSOR(env, self, self.daemon)
        self.mempool = MemPool(self.bp, self)
        self.peer_mgr = PeerManager(env, self)

    async def start_servers(self):
        '''Start the RPC server and schedule the external servers to be
        started once the block processor has caught up.
        '''
        await self.session_mgr.start_rpc_server()
        self.create_task(self.bp.main_loop())
        self.create_task(self.wait_for_bp_catchup())

    async def shutdown(self):
        '''Perform the shutdown sequence.'''
        # Not certain of ordering here
        self.tasks.cancel_all()
        await self.session_mgr.shutdown()
        await self.tasks.wait()
        # Finally shut down the block processor and executor
        self.bp.shutdown(self.executor)

    async def mempool_transactions(self, hashX):
        '''Generate (hex_hash, tx_fee, unconfirmed) tuples for mempool
        entries for the hashX.

        unconfirmed is True if any txin is unconfirmed.
        '''
        return await self.mempool.transactions(hashX)

    def mempool_value(self, hashX):
        '''Return the unconfirmed amount in the mempool for hashX.

        Can be positive or negative.
        '''
        return self.mempool.value(hashX)

    async def run_in_executor(self, func, *args):
        '''Wait whilst running func in the executor.'''
        return await self.loop.run_in_executor(None, func, *args)

    def schedule_executor(self, func, *args):
        '''Schedule running func in the executor, return a task.'''
        return self.create_task(self.run_in_executor(func, *args))

    def create_task(self, coro, callback=None):
        '''Schedule the coro to be run.'''
        task = self.tasks.create_task(coro)
        task.add_done_callback(callback or self.check_task_exception)
        return task

    def check_task_exception(self, task):
        '''Check a task for exceptions.'''
        try:
            if not task.cancelled():
                task.result()
        except Exception as e:
            self.logger.exception(f'uncaught task exception: {e}')

    async def wait_for_bp_catchup(self):
        '''Wait for the block processor to catch up, and for the mempool to
        synchronize, then kick off server background processes.'''
        await self.bp.caught_up_event.wait()
        self.create_task(self.mempool.main_loop())
        await self.mempool.synchronized_event.wait()
        self.create_task(self.peer_mgr.main_loop())
        self.create_task(self.session_mgr.start_serving())
        self.create_task(self.session_mgr.housekeeping())

    def notify_sessions(self, touched):
        '''Notify sessions about height changes and touched addresses.'''
        # Invalidate caches
        hc = self.history_cache
        for hashX in set(hc).intersection(touched):
            del hc[hashX]

        height = self.bp.db_height
        if height != self.cache_height:
            self.cache_height = height
            self.header_cache.clear()

        self.session_mgr.notify(height, touched)

    def raw_header(self, height):
        '''Return the binary header at the given height.'''
        header, n = self.bp.read_headers(height, 1)
        if n != 1:
            raise RPCError(BAD_REQUEST, f'height {height:,d} out of range')
        return header

    def electrum_header(self, height):
        '''Return the deserialized header at the given height.'''
        if height not in self.header_cache:
            raw_header = self.raw_header(height)
            self.header_cache[height] = self.coin.electrum_header(raw_header,
                                                                  height)
        return self.header_cache[height]

    # Helpers for RPC "blockchain" command handlers

    def assert_tx_hash(self, value):
        '''Raise an RPCError if the value is not a valid transaction
        hash.'''
        try:
            if len(util.hex_to_bytes(value)) == 32:
                return
        except Exception:
            pass
        raise RPCError(BAD_REQUEST, f'{value} should be a transaction hash')

    async def daemon_request(self, method, *args):
        '''Catch a DaemonError and convert it to an RPCError.'''
        try:
            return await getattr(self.daemon, method)(*args)
        except DaemonError as e:
            raise RPCError(DAEMON_ERROR, f'daemon error: {e}')

    async def get_history(self, hashX):
        '''Get history asynchronously to reduce latency.'''
        if hashX in self.history_cache:
            return self.history_cache[hashX]

        def job():
            # History DoS limit.  Each element of history is about 99
            # bytes when encoded as JSON.  This limits resource usage
            # on bloated history requests, and uses a smaller divisor
            # so large requests are logged before refusing them.
            limit = self.env.max_send // 97
            return list(self.bp.get_history(hashX, limit=limit))

        history = await self.run_in_executor(job)
        self.history_cache[hashX] = history
        return history

    async def get_utxos(self, hashX):
        '''Get UTXOs asynchronously to reduce latency.'''
        def job():
            return list(self.bp.get_utxos(hashX, limit=None))

        return await self.run_in_executor(job)

    async def transaction_get(self, tx_hash, verbose=False):
        '''Return the serialized raw transaction given its hash

        tx_hash: the transaction hash as a hexadecimal string
        verbose: passed on to the daemon
        '''
        self.assert_tx_hash(tx_hash)
        if verbose not in (True, False):
            raise RPCError(BAD_REQUEST, f'"verbose" must be a boolean')

        return await self.daemon_request('getrawtransaction', tx_hash, verbose)

    async def transaction_get_merkle(self, tx_hash, height):
        '''Return the markle tree to a confirmed transaction given its hash
        and height.

        tx_hash: the transaction hash as a hexadecimal string
        height: the height of the block it is in
        '''
        self.assert_tx_hash(tx_hash)
        height = non_negative_integer(height)

        hex_hashes = await self.daemon_request('block_hex_hashes', height, 1)
        block_hash = hex_hashes[0]
        block = await self.daemon_request('deserialised_block', block_hash)
        tx_hashes = block['tx']
        try:
            pos = tx_hashes.index(tx_hash)
        except ValueError:
            raise RPCError(BAD_REQUEST, f'tx hash {tx_hash} not in '
                           f'block {block_hash} at height {height:,d}')

        hashes = [hex_str_to_hash(hash) for hash in tx_hashes]
        branch, root = self.bp.merkle.branch_and_root(hashes, pos)
        branch = [hash_to_hex_str(hash) for hash in branch]

        return {"block_height": height, "merkle": branch, "pos": pos}
