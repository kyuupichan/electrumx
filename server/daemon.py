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

from lib.util import LoggedClass


class DaemonError(Exception):
    '''Raised when the daemon returns an error in its results that
    cannot be remedied by retrying.'''


class Daemon(LoggedClass):
    '''Handles connections to a daemon at the given URL.'''

    def __init__(self, url):
        super().__init__()
        self.url = url
        self._height = None
        self.logger.info('connecting to daemon at URL {}'.format(url))

    async def send_single(self, method, params=None):
        payload = {'method': method}
        if params:
            payload['params'] = params
        result, = await self.send((payload, ))
        return result

    async def send_many(self, mp_pairs):
        if mp_pairs:
            payload = [{'method': method, 'params': params}
                       for method, params in mp_pairs]
            return await self.send(payload)
        return []

    async def send_vector(self, method, params_list):
        if params_list:
            payload = [{'method': method, 'params': params}
                       for params in params_list]
            return await self.send(payload)
        return []

    async def send(self, payload):
        assert isinstance(payload, (tuple, list))
        data = json.dumps(payload)
        while True:
            try:
                async with aiohttp.post(self.url, data=data) as resp:
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
                    raise DaemonError(errs)

            self.logger.error('{}.  Sleeping {:d}s and trying again...'
                              .format(msg, secs))
            await asyncio.sleep(secs)

    async def block_hex_hashes(self, first, count):
        '''Return the hex hashes of count block starting at height first.'''
        param_lists = [[height] for height in range(first, first + count)]
        return await self.send_vector('getblockhash', param_lists)

    async def raw_blocks(self, hex_hashes):
        '''Return the raw binary blocks with the given hex hashes.'''
        param_lists = [(h, False) for h in hex_hashes]
        blocks = await self.send_vector('getblock', param_lists)
        # Convert hex string to bytes
        return [bytes.fromhex(block) for block in blocks]

    async def mempool_hashes(self):
        '''Return the hashes of the txs in the daemon's mempool.'''
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

    async def sendrawtransaction(self, params):
        '''Broadcast a transaction to the network.'''
        return await self.send_single('sendrawtransaction', params)

    async def height(self):
        '''Query the daemon for its current height.'''
        self._height = await self.send_single('getblockcount')
        return self._height

    def cached_height(self):
        '''Return the cached daemon height.

        If the daemon has not been queried yet this returns None.'''
        return self._height
