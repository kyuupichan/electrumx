# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Class for handling asynchronous connections to a blockchain
daemon.'''

import asyncio
import itertools
import json
import time
from calendar import timegm
from struct import pack
from time import strptime

import aiohttp

from electrumx.lib.util import int_to_varint, hex_to_bytes, class_logger, \
    unpack_uint16_from
from electrumx.lib.hash import hex_str_to_hash, hash_to_hex_str
from electrumx.lib.tx import DeserializerDecred
from aiorpcx import JSONRPC


class DaemonError(Exception):
    '''Raised when the daemon returns an error in its results.'''


class Daemon(object):
    '''Handles connections to a daemon at the given URL.'''

    WARMING_UP = -28
    id_counter = itertools.count()

    class DaemonWarmingUpError(Exception):
        '''Raised when the daemon returns an error in its results.'''

    def __init__(self, coin, url, max_workqueue=10):
        self.coin = coin
        self.logger = class_logger(__name__, self.__class__.__name__)
        self.set_url(url)
        self._height = None
        # Limit concurrent RPC calls to this number.
        # See DEFAULT_HTTP_WORKQUEUE in bitcoind, which is typically 16
        self.workqueue_semaphore = asyncio.Semaphore(value=max_workqueue)
        self.available_rpcs = {}

    def set_url(self, url):
        '''Set the URLS to the given list, and switch to the first one.'''
        urls = url.split(',')
        urls = [self.coin.sanitize_url(url) for url in urls]
        for n, url in enumerate(urls):
            status = '' if n else ' (current)'
            logged_url = self.logged_url(url)
            self.logger.info(f'daemon #{n + 1} at {logged_url}{status}')
        self.url_index = 0
        self.urls = urls

    def current_url(self):
        '''Returns the current daemon URL.'''
        return self.urls[self.url_index]

    def logged_url(self, url=None):
        '''The host and port part, for logging.'''
        url = url or self.current_url()
        return url[url.rindex('@') + 1:]

    def failover(self):
        '''Call to fail-over to the next daemon URL.

        Returns False if there is only one, otherwise True.
        '''
        if len(self.urls) > 1:
            self.url_index = (self.url_index + 1) % len(self.urls)
            self.logger.info(f'failing over to {self.logged_url()}')
            return True
        return False

    def client_session(self):
        '''An aiohttp client session.'''
        return aiohttp.ClientSession()

    async def _send_data(self, data):
        async with self.workqueue_semaphore:
            async with self.client_session() as session:
                async with session.post(self.current_url(), data=data) as resp:
                    # If bitcoind can't find a tx, for some reason
                    # it returns 500 but fills out the JSON.
                    # Should still return 200 IMO.
                    if resp.status in (200, 404, 500):
                        return await resp.json()
                    return (resp.status, resp.reason)

    async def _send(self, payload, processor):
        '''Send a payload to be converted to JSON.

        Handles temporary connection issues.  Daemon reponse errors
        are raise through DaemonError.
        '''
        def log_error(error):
            nonlocal down, last_error_time
            down = True
            now = time.time()
            prior_time = last_error_time
            if now - prior_time > 60:
                last_error_time = now
                if prior_time and self.failover():
                    secs = 0
                else:
                    self.logger.error(f'{error}  Retrying occasionally...')

        down = False
        last_error_time = 0
        data = json.dumps(payload)
        secs = 1
        max_secs = 4
        while True:
            try:
                result = await self._send_data(data)
                if not isinstance(result, tuple):
                    result = processor(result)
                    if down:
                        self.logger.info('connection restored')
                    return result
                log_error(f'HTTP error code {result[0]}: {result[1]}')
            except asyncio.TimeoutError:
                log_error('timeout error.')
            except aiohttp.ServerDisconnectedError:
                log_error('disconnected.')
            except aiohttp.ClientPayloadError:
                log_error('payload encoding error.')
            except aiohttp.ClientConnectionError:
                log_error('connection problem - is your daemon running?')
            except self.DaemonWarmingUpError:
                log_error('starting up checking blocks.')
            except (asyncio.CancelledError, DaemonError):
                raise
            except Exception as e:
                self.logger.exception(f'uncaught exception: {e}')

            await asyncio.sleep(secs)
            secs = min(max_secs, secs * 2, 1)

    async def _send_single(self, method, params=None):
        '''Send a single request to the daemon.'''
        def processor(result):
            err = result['error']
            if not err:
                return result['result']
            if err.get('code') == self.WARMING_UP:
                raise self.DaemonWarmingUpError
            raise DaemonError(err)

        payload = {'method': method, 'id': next(self.id_counter)}
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

        payload = [{'method': method, 'params': p, 'id': next(self.id_counter)}
                   for p in params_iterable]
        if payload:
            return await self._send(payload, processor)
        return []

    async def _is_rpc_available(self, method):
        '''Return whether given RPC method is available in the daemon.

        Results are cached and the daemon will generally not be queried with
        the same method more than once.'''
        available = self.available_rpcs.get(method)
        if available is None:
            available = True
            try:
                await self._send_single(method)
            except DaemonError as e:
                err = e.args[0]
                error_code = err.get("code")
                available = error_code != JSONRPC.METHOD_NOT_FOUND
            self.available_rpcs[method] = available
        return available

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
        if await self._is_rpc_available('estimatesmartfee'):
            estimate = await self._send_single('estimatesmartfee', params)
            return estimate.get('feerate', -1)
        return await self._send_single('estimatefee', params)

    async def getnetworkinfo(self):
        '''Return the result of the 'getnetworkinfo' RPC call.'''
        return await self._send_single('getnetworkinfo')

    async def relayfee(self):
        '''The minimum fee a low-priority tx must pay in order to be accepted
        to the daemon's memory pool.'''
        network_info = await self.getnetworkinfo()
        return network_info['relayfee']

    async def getrawtransaction(self, hex_hash, verbose=False):
        '''Return the serialized raw transaction with the given hash.'''
        # Cast to int because some coin daemons are old and require it
        return await self._send_single('getrawtransaction',
                                       (hex_hash, int(verbose)))

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

    async def height(self):
        '''Query the daemon for its current height.'''
        self._height = await self._send_single('getblockcount')
        return self._height

    def cached_height(self):
        '''Return the cached daemon height.

        If the daemon has not been queried yet this returns None.'''
        return self._height


class DashDaemon(Daemon):

    async def masternode_broadcast(self, params):
        '''Broadcast a transaction to the network.'''
        return await self._send_single('masternodebroadcast', params)

    async def masternode_list(self, params):
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
        return b''.join([
            pack('<L', b.get('version')),
            hex_str_to_hash(pbh),
            hex_str_to_hash(b.get('merkleroot')),
            pack('<L', self.timestamp_safe(b['time'])),
            pack('<L', int(b.get('bits'), 16)),
            pack('<L', int(b.get('nonce')))
        ])

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


class DecredDaemon(Daemon):
    async def raw_blocks(self, hex_hashes):
        '''Return the raw binary blocks with the given hex hashes.'''

        params_iterable = ((h, False) for h in hex_hashes)
        blocks = await self._send_vector('getblock', params_iterable)

        raw_blocks = []
        valid_tx_tree = {}
        for block in blocks:
            # Convert to bytes from hex
            raw_block = hex_to_bytes(block)
            raw_blocks.append(raw_block)
            # Check if previous block is valid
            prev = self.prev_hex_hash(raw_block)
            votebits = unpack_uint16_from(raw_block[100:102])[0]
            valid_tx_tree[prev] = self.is_valid_tx_tree(votebits)

        processed_raw_blocks = []
        for hash, raw_block in zip(hex_hashes, raw_blocks):
            if hash in valid_tx_tree:
                is_valid = valid_tx_tree[hash]
            else:
                # Do something complicated to figure out if this block is valid
                header = await self._send_single('getblockheader', (hash, ))
                if 'nextblockhash' not in header:
                    raise DaemonError(f'Could not find next block for {hash}')
                next_hash = header['nextblockhash']
                next_header = await self._send_single('getblockheader',
                                                      (next_hash, ))
                is_valid = self.is_valid_tx_tree(next_header['votebits'])

            if is_valid:
                processed_raw_blocks.append(raw_block)
            else:
                # If this block is invalid remove the normal transactions
                self.logger.info(f'block {hash} is invalidated')
                processed_raw_blocks.append(self.strip_tx_tree(raw_block))

        return processed_raw_blocks

    @staticmethod
    def prev_hex_hash(raw_block):
        return hash_to_hex_str(raw_block[4:36])

    @staticmethod
    def is_valid_tx_tree(votebits):
        # Check if previous block was invalidated.
        return bool(votebits & (1 << 0) != 0)

    def strip_tx_tree(self, raw_block):
        c = self.coin
        assert issubclass(c.DESERIALIZER, DeserializerDecred)
        d = c.DESERIALIZER(raw_block, start=c.BASIC_HEADER_SIZE)
        d.read_tx_tree()  # Skip normal transactions
        # Create a fake block without any normal transactions
        return raw_block[:c.BASIC_HEADER_SIZE] + b'\x00' + raw_block[d.cursor:]

    async def height(self):
        height = await super().height()
        if height > 0:
            # Lie about the daemon height as the current tip can be invalidated
            height -= 1
            self._height = height
        return height

    async def mempool_hashes(self):
        mempool = await super().mempool_hashes()
        # Add current tip transactions to the 'fake' mempool.
        real_height = await self._send_single('getblockcount')
        tip_hash = await self._send_single('getblockhash', (real_height,))
        tip = await self.deserialised_block(tip_hash)
        # Add normal transactions except coinbase
        mempool += tip['tx'][1:]
        # Add stake transactions if applicable
        mempool += tip.get('stx', [])
        return mempool

    def client_session(self):
        # FIXME allow self signed certificates
        connector = aiohttp.TCPConnector(verify_ssl=False)
        return aiohttp.ClientSession(connector=connector)
