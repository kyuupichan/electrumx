# Copyright (c) 2016-2018, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.


import pylru

from electrumx.server.mempool import MemPool


class ChainState(object):
    '''Used as an interface by servers to request information about
    blocks, transaction history, UTXOs and the mempool.
    '''

    def __init__(self, env, tasks, shutdown_event):
        self.env = env
        self.tasks = tasks
        self.shutdown_event = shutdown_event
        self.daemon = env.coin.DAEMON(env)
        BlockProcessor = env.coin.BLOCK_PROCESSOR
        self.bp = BlockProcessor(env, tasks, self.daemon)
        self.mempool = MemPool(env.coin, self, self.tasks,
                               self.bp.add_new_block_callback)
        self.history_cache = pylru.lrucache(256)
        # External interface: pass-throughs for mempool.py
        self.cached_mempool_hashes = self.daemon.cached_mempool_hashes
        self.mempool_refresh_event = self.daemon.mempool_refresh_event
        self.getrawtransactions = self.daemon.getrawtransactions
        self.utxo_lookup = self.bp.db_utxo_lookup
        # External interface pass-throughs for session.py
        self.force_chain_reorg = self.bp.force_chain_reorg
        self.mempool_fee_histogram = self.mempool.get_fee_histogram
        self.mempool_get_utxos = self.mempool.get_utxos
        self.mempool_potential_spends = self.mempool.potential_spends
        self.mempool_transactions = self.mempool.transactions
        self.mempool_value = self.mempool.value
        self.tx_branch_and_root = self.bp.merkle.branch_and_root
        self.read_headers = self.bp.read_headers

    async def broadcast_transaction(self, raw_tx):
        return await self.daemon.sendrawtransaction([raw_tx])

    async def daemon_request(self, method, args):
        return await getattr(self.daemon, method)(*args)

    def db_height(self):
        return self.bp.db_height

    def get_info(self):
        '''Chain state info for LocalRPC and logs.'''
        return {
            'daemon': self.daemon.logged_url(),
            'daemon_height': self.daemon.cached_height(),
            'db_height': self.db_height(),
        }

    async def get_history(self, hashX):
        '''Get history asynchronously to reduce latency.'''
        def job():
            # History DoS limit.  Each element of history is about 99
            # bytes when encoded as JSON.  This limits resource usage
            # on bloated history requests, and uses a smaller divisor
            # so large requests are logged before refusing them.
            limit = self.env.max_send // 97
            return list(self.bp.get_history(hashX, limit=limit))

        hc = self.history_cache
        if hashX not in hc:
            hc[hashX] = await self.tasks.run_in_thread(job)
        return hc[hashX]

    async def get_utxos(self, hashX):
        '''Get UTXOs asynchronously to reduce latency.'''
        def job():
            return list(self.bp.get_utxos(hashX, limit=None))

        return await self.tasks.run_in_thread(job)

    def header_branch_and_root(self, length, height):
        return self.bp.header_mc.branch_and_root(length, height)

    def invalidate_history_cache(self, touched):
        hc = self.history_cache
        for hashX in set(hc).intersection(touched):
            del hc[hashX]

    def processing_new_block(self):
        '''Return True if we're processing a new block.'''
        return self.daemon.cached_height() > self.db_height()

    def raw_header(self, height):
        '''Return the binary header at the given height.'''
        header, n = self.bp.read_headers(height, 1)
        if n != 1:
            raise IndexError(f'height {height:,d} out of range')
        return header

    def set_daemon_url(self, daemon_url):
        self.daemon.set_urls(self.env.coin.daemon_urls(daemon_url))
        return self.daemon.logged_url()

    def shutdown(self):
        self.tasks.loop.call_soon(self.shutdown_event.set)

    async def wait_for_mempool(self):
        await self.bp.catch_up_to_daemon()
        self.tasks.create_task(self.mempool.main_loop())
        await self.mempool.synchronized_event.wait()
