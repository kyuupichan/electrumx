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
    '''Raised when the daemon returns an error in its results.'''


class DaemonWarmingUpError(DaemonError):
    '''Raised when the daemon returns an error in its results.'''


class Daemon(util.LoggedClass):
    '''Handles connections to a daemon at the given URL.'''

    WARMING_UP = -28

    def __init__(self, url, debug):
        super().__init__()
        self.url = url
        self._height = None
        self.logger.info('connecting to daemon at URL {}'.format(url))
        self.debug_caught_up = 'caught_up' in debug
        # Limit concurrent RPC calls to this number.
        # See DEFAULT_HTTP_WORKQUEUE in bitcoind, which is typically 16
        self.workqueue_semaphore = asyncio.Semaphore(value=10)

    def debug_set_height(self, height):
        if self.debug_caught_up:
            self.logger.info('pretending to have caught up to height {}'
                             .format(height))
            self._height = height

    async def post(self, data):
        '''Send data to the daemon and handle the response.'''
        async with self.workqueue_semaphore:
            async with aiohttp.post(self.url, data=data) as resp:
                result = await resp.json()

        if isinstance(result, list):
            errs = [item['error'] for item in result]
            if not any(errs):
                return [item['result'] for item in result]
            if any(err.get('code') == self.WARMING_UP for err in errs if err):
                raise DaemonWarmingUpError
            raise DaemonError(errs)
        else:
            err = result['error']
            if not err:
                return result['result']
            if err.get('code') == self.WARMING_UP:
                raise DaemonWarmingUpError
            raise DaemonError(err)

    async def send(self, payload):
        '''Send a payload to be converted to JSON.

        Handles temporary connection issues.  Daemon reponse errors
        are raise through DaemonError.
        '''
        data = json.dumps(payload)
        secs = 1
        prior_msg = None
        while True:
            try:
                result = await self.post(data)
                if prior_msg:
                    self.logger.info('connection successfully restored')
                return result
            except asyncio.TimeoutError:
                msg = 'timeout error'
            except aiohttp.ClientHttpProcessingError:
                msg = 'HTTP error'
            except aiohttp.ServerDisconnectedError:
                msg = 'disconnected'
            except aiohttp.ClientConnectionError:
                msg = 'connection problem - is your daemon running?'
            except DaemonWarmingUpError:
                msg = 'still starting up checking blocks...'
            except (asyncio.CancelledError, DaemonError):
                raise
            except Exception as e:
                msg = ('request gave unexpected error: {}'.format(e))

            if msg != prior_msg or count == 10:
                self.logger.error('{}.  Retrying between sleeps...'
                                  .format(msg))
                prior_msg = msg
                count = 0
            await asyncio.sleep(secs)
            count += 1
            secs = min(16, secs * 2)

    async def send_single(self, method, params=None):
        '''Send a single request to the daemon.'''
        payload = {'method': method}
        if params:
            payload['params'] = params
        return await self.send(payload)

    async def send_many(self, mp_iterable):
        '''Send several requests at once.'''
        payload = [{'method': m, 'params': p} for m, p in mp_iterable]
        if payload:
            return await self.send(payload)
        return []

    async def send_vector(self, method, params_iterable):
        '''Send several requests of the same method.'''
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
        return [bytes.fromhex(block) for block in blocks]

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
        params_iterable = ((hex_hash, 0) for hex_hash in hex_hashes)
        txs = await self.send_vector('getrawtransaction', params_iterable)
        # Convert hex strings to bytes
        return [bytes.fromhex(tx) for tx in txs]

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
