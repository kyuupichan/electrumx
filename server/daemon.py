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

class Daemon(util.LoggedClass):
    '''Handles connections to a daemon at the given URL.'''

    WARMING_UP = -28

    class DaemonWarmingUpError(Exception):
        '''Raised when the daemon returns an error in its results.'''

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

    async def _send(self, payload, processor):
        '''Send a payload to be converted to JSON.

        Handles temporary connection issues.  Daemon reponse errors
        are raise through DaemonError.
        '''
        self.prior_msg = None
        self.skip_count = None

        def log_error(msg, skip_once=False):
            if skip_once and self.skip_count is None:
                self.skip_count = 1
            if msg != self.prior_msg or self.skip_count == 0:
                self.skip_count = 10
                self.prior_msg = msg
                self.logger.error('{}  Retrying between sleeps...'
                                  .format(msg))
            self.skip_count -= 1

        data = json.dumps(payload)
        secs = 1
        while True:
            try:
                async with self.workqueue_semaphore:
                    async with aiohttp.post(self.url, data=data) as resp:
                        result = processor(await resp.json())
                        if self.prior_msg:
                            self.logger.info('connection restored')
                        return result
            except asyncio.TimeoutError:
                log_error('timeout error.', skip_once=True)
            except aiohttp.ClientHttpProcessingError:
                log_error('HTTP error.', skip_once=True)
            except aiohttp.ServerDisconnectedError:
                log_error('disconnected.', skip_once=True)
            except aiohttp.ClientConnectionError:
                log_error('connection problem - is your daemon running?')
            except self.DaemonWarmingUpError:
                log_error('still starting up checking blocks.')
            except (asyncio.CancelledError, DaemonError):
                raise
            except Exception as e:
                log_error('request gave unexpected error: {}.'.format(e))
            await asyncio.sleep(secs)
            secs = min(16, secs * 2)

    async def _send_single(self, method, params=None):
        '''Send a single request to the daemon.'''
        def processor(result):
            err = result['error']
            if not err:
                return result['result']
            if err.get('code') == self.WARMING_UP:
                raise self.DaemonWarmingUpError
            raise DaemonError(err)

        payload = {'method': method}
        if params:
            payload['params'] = params
        return await self._send(payload, processor)

    async def _send_vector(self, method, params_iterable, replace_errs=False):
        '''Send several requests of the same method.

        The result will be an array of the same length as params_iterable.
        If replace_errs is true, any item with an error is returned as None,
        othewise an exception is raised.'''
        def processor(result):
            errs = [item['error'] for item in result if item['error']]
            if not errs or replace_errs:
                return [item['result'] for item in result]
            if any(err.get('code') == self.WARMING_UP for err in errs):
                raise self.DaemonWarmingUpError
            raise DaemonError(errs)

        payload = [{'method': method, 'params': p} for p in params_iterable]
        if payload:
            return await self._send(payload, processor)
        return []

    async def block_hex_hashes(self, first, count):
        '''Return the hex hashes of count block starting at height first.'''
        params_iterable = ((h, ) for h in range(first, first + count))
        return await self._send_vector('getblockhash', params_iterable)

    async def deserialised_block(self, hex_hash):
        '''Return the deserialised block with the given hex hash.'''
        return await self._send_single('getblock', (hex_hash, True))

    async def raw_blocks(self, hex_hashes):
        '''Return the raw binary blocks with the given hex hashes.'''
        params_iterable = ((h, False) for h in hex_hashes)
        blocks = await self._send_vector('getblock', params_iterable)
        # Convert hex string to bytes
        return [bytes.fromhex(block) for block in blocks]

    async def mempool_hashes(self):
        '''Return the hashes of the txs in the daemon's mempool.'''
        if self.debug_caught_up:
            return []
        return await self._send_single('getrawmempool')

    async def estimatefee(self, params):
        '''Return the fee estimate for the given parameters.'''
        return await self._send_single('estimatefee', params)

    async def relayfee(self):
        '''The minimum fee a low-priority tx must pay in order to be accepted
        to the daemon's memory pool.'''
        net_info = await self._send_single('getnetworkinfo')
        return net_info['relayfee']

    async def getrawtransaction(self, hex_hash):
        '''Return the serialized raw transaction with the given hash.'''
        return await self._send_single('getrawtransaction', (hex_hash, 0))

    async def getrawtransactions(self, hex_hashes, replace_errs=True):
        '''Return the serialized raw transactions with the given hashes.

        Replaces errors with None by default.'''
        params_iterable = ((hex_hash, 0) for hex_hash in hex_hashes)
        txs = await self._send_vector('getrawtransaction', params_iterable,
                                      replace_errs=replace_errs)
        # Convert hex strings to bytes
        return [bytes.fromhex(tx) if tx else None for tx in txs]

    async def sendrawtransaction(self, params):
        '''Broadcast a transaction to the network.'''
        return await self._send_single('sendrawtransaction', params)

    async def height(self):
        '''Query the daemon for its current height.'''
        if not self.debug_caught_up:
            self._height = await self._send_single('getblockcount')
        return self._height

    def cached_height(self):
        '''Return the cached daemon height.

        If the daemon has not been queried yet this returns None.'''
        return self._height
