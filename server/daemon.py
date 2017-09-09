# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Class for handling asynchronous connections to a blockchain
daemon.'''

import asyncio
import json
import time
import traceback
from calendar import timegm
from struct import pack
from time import strptime

import aiohttp

from lib.util import LoggedClass, int_to_varint, hex_to_bytes
from lib.hash import hex_str_to_hash


class DaemonError(Exception):
    '''Raised when the daemon returns an error in its results.'''


class Daemon(LoggedClass):
    '''Handles connections to a daemon at the given URL.'''

    WARMING_UP = -28

    class DaemonWarmingUpError(Exception):
        '''Raised when the daemon returns an error in its results.'''

    def __init__(self, env):
        super().__init__()
        self.coin = env.coin
        self.set_urls(env.coin.daemon_urls(env.daemon_url))
        self._height = None
        self._mempool_hashes = set()
        self.mempool_refresh_event = asyncio.Event()
        # Limit concurrent RPC calls to this number.
        # See DEFAULT_HTTP_WORKQUEUE in bitcoind, which is typically 16
        self.workqueue_semaphore = asyncio.Semaphore(value=10)
        self.down = False
        self.last_error_time = 0
        self.req_id = 0
        # assignment of asyncio.TimeoutError are essentially ignored
        if aiohttp.__version__.startswith('1.'):
            self.ClientHttpProcessingError = aiohttp.ClientHttpProcessingError
            self.ClientPayloadError = asyncio.TimeoutError
        else:
            self.ClientHttpProcessingError = asyncio.TimeoutError
            self.ClientPayloadError = aiohttp.ClientPayloadError

    def next_req_id(self):
        '''Retrns the next request ID.'''
        self.req_id += 1
        return self.req_id

    def set_urls(self, urls):
        '''Set the URLS to the given list, and switch to the first one.'''
        if not urls:
            raise DaemonError('no daemon URLs provided')
        self.urls = urls
        self.url_index = 0
        for n, url in enumerate(urls):
            self.logger.info('daemon #{:d} at {}{}'
                             .format(n + 1, self.logged_url(url),
                                     '' if n else ' (current)'))

    def url(self):
        '''Returns the current daemon URL.'''
        return self.urls[self.url_index]

    def failover(self):
        '''Call to fail-over to the next daemon URL.

        Returns False if there is only one, otherwise True.
        '''
        if len(self.urls) > 1:
            self.url_index = (self.url_index + 1) % len(self.urls)
            self.logger.info('failing over to {}'.format(self.logged_url()))
            return True
        return False

    def client_session(self):
        '''An aiohttp client session.'''
        return aiohttp.ClientSession()

    async def _send_data(self, data):
        async with self.workqueue_semaphore:
            async with self.client_session() as session:
                async with session.post(self.url(), data=data) as resp:
                    # If bitcoind can't find a tx, for some reason
                    # it returns 500 but fills out the JSON.
                    # Should still return 200 IMO.
                    if resp.status in (200, 500):
                        return await resp.json()
                    return (resp.status, resp.reason)

    async def _send(self, payload, processor):
        '''Send a payload to be converted to JSON.

        Handles temporary connection issues.  Daemon reponse errors
        are raise through DaemonError.
        '''
        def log_error(error):
            self.down = True
            now = time.time()
            prior_time = self.last_error_time
            if now - prior_time > 60:
                self.last_error_time = now
                if prior_time and self.failover():
                    secs = 0
                else:
                    self.logger.error('{}  Retrying occasionally...'
                                      .format(error))

        data = json.dumps(payload)
        secs = 1
        max_secs = 4
        while True:
            try:
                result = await self._send_data(data)
                if not isinstance(result, tuple):
                    result = processor(result)
                    if self.down:
                        self.down = False
                        self.last_error_time = 0
                        self.logger.info('connection restored')
                    return result
                log_error('HTTP error code {:d}: {}'
                          .format(result[0], result[1]))
            except asyncio.TimeoutError:
                log_error('timeout error.')
            except aiohttp.ServerDisconnectedError:
                log_error('disconnected.')
            except self.ClientHttpProcessingError:
                log_error('HTTP error.')
            except self.ClientPayloadError:
                log_error('payload encoding error.')
            except aiohttp.ClientConnectionError:
                log_error('connection problem - is your daemon running?')
            except self.DaemonWarmingUpError:
                log_error('starting up checking blocks.')
            except (asyncio.CancelledError, DaemonError):
                raise
            except Exception:
                self.log_error(traceback.format_exc())

            await asyncio.sleep(secs)
            secs = min(max_secs, secs * 2, 1)

    def logged_url(self, url=None):
        '''The host and port part, for logging.'''
        url = url or self.url()
        return url[url.rindex('@') + 1:]

    async def _send_single(self, method, params=None):
        '''Send a single request to the daemon.'''
        def processor(result):
            err = result['error']
            if not err:
                return result['result']
            if err.get('code') == self.WARMING_UP:
                raise self.DaemonWarmingUpError
            raise DaemonError(err)

        payload = {'method': method, 'id': self.next_req_id()}
        if params:
            payload['params'] = params
        return await self._send(payload, processor)

    async def _send_vector(self, method, params_iterable, replace_errs=False):
        '''Send several requests of the same method.

        The result will be an array of the same length as params_iterable.
        If replace_errs is true, any item with an error is returned as None,
        otherwise an exception is raised.'''
        def processor(result):
            errs = [item['error'] for item in result if item['error']]
            if any(err.get('code') == self.WARMING_UP for err in errs):
                raise self.DaemonWarmingUpError
            if not errs or replace_errs:
                return [item['result'] for item in result]
            raise DaemonError(errs)

        payload = [{'method': method, 'params': p, 'id': self.next_req_id()}
                   for p in params_iterable]
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
        return [hex_to_bytes(block) for block in blocks]

    async def mempool_hashes(self):
        '''Update our record of the daemon's mempool hashes.'''
        return await self._send_single('getrawmempool')

    async def estimatefee(self, params):
        '''Return the fee estimate for the given parameters.'''
        return await self._send_single('estimatefee', params)

    async def getnetworkinfo(self):
        '''Return the result of the 'getnetworkinfo' RPC call.'''
        return await self._send_single('getnetworkinfo')

    async def relayfee(self):
        '''The minimum fee a low-priority tx must pay in order to be accepted
        to the daemon's memory pool.'''
        network_info = await self.getnetworkinfo()
        return network_info['relayfee']

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
        return [hex_to_bytes(tx) if tx else None for tx in txs]

    async def sendrawtransaction(self, params):
        '''Broadcast a transaction to the network.'''
        return await self._send_single('sendrawtransaction', params)

    async def height(self, mempool=False):
        '''Query the daemon for its current height.'''
        self._height = await self._send_single('getblockcount')
        if mempool:
            self._mempool_hashes = set(await self.mempool_hashes())
            self.mempool_refresh_event.set()
        return self._height

    def cached_mempool_hashes(self):
        '''Return the cached mempool hashes.'''
        return self._mempool_hashes

    def cached_height(self):
        '''Return the cached daemon height.

        If the daemon has not been queried yet this returns None.'''
        return self._height


class DashDaemon(Daemon):

    async def masternode_broadcast(self, params):
        '''Broadcast a transaction to the network.'''
        return await self._send_single('masternodebroadcast', params)

    async def masternode_list(self, params ):
        '''Return the masternode status.'''
        return await self._send_single('masternodelist', params)


class FakeEstimateFeeDaemon(Daemon):
    '''Daemon that simulates estimatefee and relayfee RPC calls. Coin that
    wants to use this daemon must define ESTIMATE_FEE & RELAY_FEE'''

    async def estimatefee(self, params):
        '''Return the fee estimate for the given parameters.'''
        return self.coin.ESTIMATE_FEE

    async def relayfee(self):
        '''The minimum fee a low-priority tx must pay in order to be accepted
        to the daemon's memory pool.'''
        return self.coin.RELAY_FEE


class LegacyRPCDaemon(Daemon):
    '''Handles connections to a daemon at the given URL.

    This class is useful for daemons that don't have the new 'getblock'
    RPC call that returns the block in hex, the workaround is to manually
    recreate the block bytes. The recreated block bytes may not be the exact
    as in the underlying blockchain but it is good enough for our indexing
    purposes.'''

    async def raw_blocks(self, hex_hashes):
        '''Return the raw binary blocks with the given hex hashes.'''
        params_iterable = ((h, ) for h in hex_hashes)
        block_info = await self._send_vector('getblock', params_iterable)

        blocks = []
        for i in block_info:
            raw_block = await self.make_raw_block(i)
            blocks.append(raw_block)

        # Convert hex string to bytes
        return blocks

    async def make_raw_header(self, b):
        pbh = b.get('previousblockhash')
        if pbh is None:
            pbh = '0' * 64
        header = pack('<L', b.get('version')) \
                 + hex_str_to_hash(pbh) \
                 + hex_str_to_hash(b.get('merkleroot')) \
                 + pack('<L', self.timestamp_safe(b['time'])) \
                 + pack('<L', int(b.get('bits'), 16)) \
                 + pack('<L', int(b.get('nonce')))
        return header

    async def make_raw_block(self, b):
        '''Construct a raw block'''

        header = await self.make_raw_header(b)

        transactions = []
        if b.get('height') > 0:
            transactions = await self.getrawtransactions(b.get('tx'), False)

        raw_block = header
        num_txs = len(transactions)
        if num_txs > 0:
            raw_block += int_to_varint(num_txs)
            raw_block += b''.join(transactions)
        else:
            raw_block += b'\x00'

        return raw_block

    def timestamp_safe(self, t):
        if isinstance(t, int):
            return t
        return timegm(strptime(t, "%Y-%m-%d %H:%M:%S %Z"))
