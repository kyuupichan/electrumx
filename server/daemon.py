# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Class for handling asynchronous connections to a blockchain
daemon.'''

import asyncio
import json

import aiohttp

import lib.util as util


class DaemonError(Exception):
    '''Raised when the daemon returns an error in its results that
    cannot be remedied by retrying.'''


class Daemon(util.LoggedClass):
    '''Handles connections to a daemon at the given URL.'''

    WARMING_UP = -28

    def __init__(self, url, debug):
        super().__init__()
        self.url = url
        self._height = None
        self.logger.info('connecting to daemon at URL {}'.format(url))
        self.debug_caught_up = 'caught_up' in debug

    def debug_set_height(self, height):
        if self.debug_caught_up:
            self.logger.info('pretending to have caught up to height {}'
                             .format(height))
            self._height = height

    @classmethod
    def is_warming_up(cls, err):
        if not isinstance(err, list):
            err = [err]
        return any(elt.get('code') == cls.WARMING_UP for elt in err)

    async def send(self, payload):
        '''Send a payload to be converted to JSON.'''
        data = json.dumps(payload)
        secs = 1
        while True:
            try:
                async with aiohttp.post(self.url, data=data) as resp:
                    result = await resp.json()
                if not self.is_warming_up(result):
                    return result
                msg = 'daemon is still warming up'
            except asyncio.TimeoutError:
                msg = 'timeout error'
            except aiohttp.DisconnectedError as e:
                msg = '{}: {}'.format(e.__class__.__name__, e)

            secs = min(180, secs * 2)
            self.logger.error('{}.  Sleeping {:d}s and trying again...'
                              .format(msg, secs))
            await asyncio.sleep(secs)

    async def send_single(self, method, params=None):
        '''Send a single request to the daemon.'''
        payload = {'method': method}
        if params:
            payload['params'] = params
        item = await self.send(payload)
        if item['error']:
            raise DaemonError(item['error'])
        return item['result']

    async def send_many(self, mp_iterable):
        '''Send several requests at once.

        The results are returned as a tuple.'''
        payload = tuple({'method': m, 'params': p} for m, p in mp_iterable)
        if payload:
            items = await self.send(payload)
            errs = tuple(item['error'] for item in items)
            if any(errs):
                raise DaemonError(errs)
            return tuple(item['result'] for item in items)
        return ()

    async def send_vector(self, method, params_iterable):
        '''Send several requests of the same method.

        The results are returned as a tuple.'''
        return await self.send_many((method, params)
                                    for params in params_iterable)

    async def block_hex_hashes(self, first, count):
        '''Return the hex hashes of count block starting at height first.'''
        params_iterable = ((h, ) for h in range(first, first + count))
        return await self.send_vector('getblockhash', params_iterable)

    async def raw_blocks(self, hex_hashes):
        '''Return the raw binary blocks with the given hex hashes.'''
        params_iterable = ((h, False) for h in hex_hashes)
        blocks = await self.send_vector('getblock', params_iterable)
        # Convert hex string to bytes
        return tuple(bytes.fromhex(block) for block in blocks)

    async def mempool_hashes(self):
        '''Return the hashes of the txs in the daemon's mempool.'''
        if self.debug_caught_up:
            return []
        return await self.send_single('getrawmempool')

    async def estimatefee(self, params):
        '''Return the fee estimate for the given parameters.'''
        return await self.send_single('estimatefee', params)

    async def relayfee(self):
        '''The minimum fee a low-priority tx must pay in order to be accepted
        to the daemon's memory pool.'''
        net_info = await self.send_single('getnetworkinfo')
        return net_info['relayfee']

    async def getrawtransaction(self, hex_hash):
        '''Return the serialized raw transaction with the given hash.'''
        return await self.send_single('getrawtransaction', (hex_hash, 0))

    async def getrawtransactions(self, hex_hashes):
        '''Return the serialized raw transactions with the given hashes.

        Breaks large requests up.  Yields after each sub request.'''
        param_lists = tuple((hex_hash, 0) for hex_hash in hex_hashes)
        raw_txs = []
        for chunk in util.chunks(param_lists, 10000):
            txs = await self.send_vector('getrawtransaction', chunk)
            # Convert hex strings to bytes
            raw_txs.append(tuple(bytes.fromhex(tx) for tx in txs))
            await asyncio.sleep(0)
        return sum(raw_txs, ())

    async def sendrawtransaction(self, params):
        '''Broadcast a transaction to the network.'''
        return await self.send_single('sendrawtransaction', params)

    async def height(self):
        '''Query the daemon for its current height.'''
        if not self.debug_caught_up:
            self._height = await self.send_single('getblockcount')
        return self._height

    def cached_height(self):
        '''Return the cached daemon height.

        If the daemon has not been queried yet this returns None.'''
        return self._height
