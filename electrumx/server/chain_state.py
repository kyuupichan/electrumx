# Copyright (c) 2016-2018, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.


import asyncio

from aiorpcx import run_in_thread

from electrumx.lib.hash import hash_to_hex_str, Base58Error


class ChainState(object):
    '''Used as an interface by servers to request information about
    blocks, transaction history, UTXOs and the mempool.
    '''

    def __init__(self, env, daemon, bp):
        self._env = env
        self._daemon = daemon
        self._bp = bp

        # External interface pass-throughs for session.py
        self.force_chain_reorg = self._bp.force_chain_reorg
        self.tx_branch_and_root = self._bp.merkle.branch_and_root
        self.read_headers = self._bp.read_headers

    async def broadcast_transaction(self, raw_tx):
        return await self._daemon.sendrawtransaction([raw_tx])

    async def daemon_request(self, method, args=()):
        return await getattr(self._daemon, method)(*args)

    def db_height(self):
        return self._bp.db_height

    def get_info(self):
        '''Chain state info for LocalRPC and logs.'''
        return {
            'daemon': self._daemon.logged_url(),
            'daemon_height': self._daemon.cached_height(),
            'db_height': self.db_height(),
        }

    async def get_history(self, hashX):
        '''Get history asynchronously to reduce latency.'''
        def job():
            # History DoS limit.  Each element of history is about 99
            # bytes when encoded as JSON.  This limits resource usage
            # on bloated history requests, and uses a smaller divisor
            # so large requests are logged before refusing them.
            limit = self._env.max_send // 97
            return list(self._bp.get_history(hashX, limit=limit))

        return await run_in_thread(job)

    async def get_utxos(self, hashX):
        '''Get UTXOs asynchronously to reduce latency.'''
        def job():
            return list(self._bp.get_utxos(hashX, limit=None))

        return await run_in_thread(job)

    def header_branch_and_root(self, length, height):
        return self._bp.header_mc.branch_and_root(length, height)

    def processing_new_block(self):
        '''Return True if we're processing a new block.'''
        return self._daemon.cached_height() > self.db_height()

    def raw_header(self, height):
        '''Return the binary header at the given height.'''
        header, n = self._bp.read_headers(height, 1)
        if n != 1:
            raise IndexError(f'height {height:,d} out of range')
        return header

    def set_daemon_url(self, daemon_url):
        self._daemon.set_urls(self._env.coin.daemon_urls(daemon_url))
        return self._daemon.logged_url()

    async def query(self, args, limit):
        coin = self._env.coin
        db = self._bp
        lines = []

        def arg_to_hashX(arg):
            try:
                script = bytes.fromhex(arg)
                lines.append(f'Script: {arg}')
                return coin.hashX_from_script(script)
            except ValueError:
                pass

            try:
                hashX = coin.address_to_hashX(arg)
                lines.append(f'Address: {arg}')
                return hashX
            except Base58Error:
                print(f'Ingoring unknown arg: {arg}')
                return None

        for arg in args:
            hashX = arg_to_hashX(arg)
            if not hashX:
                continue
            n = None
            for n, (tx_hash, height) in enumerate(
                    db.get_history(hashX, limit), start=1):
                lines.append(f'History #{n:,d}: height {height:,d} '
                             f'tx_hash {hash_to_hex_str(tx_hash)}')
            if n is None:
                lines.append('No history found')
            n = None
            for n, utxo in enumerate(db.get_utxos(hashX, limit), start=1):
                lines.append(f'UTXO #{n:,d}: tx_hash '
                             f'{hash_to_hex_str(utxo.tx_hash)} '
                             f'tx_pos {utxo.tx_pos:,d} height '
                             f'{utxo.height:,d} value {utxo.value:,d}')
            if n is None:
                lines.append('No UTXOs found')

            balance = db.get_balance(hashX)
            lines.append(f'Balance: {coin.decimal_value(balance):,f} '
                         f'{coin.SHORTNAME}')

        return lines
