# Copyright (c) 2016-2021, Neil Booth
#
# All rights reserved.
#
# This file is licensed under the Open BSV License version 3, see LICENCE for details.

'''Class for handling asynchronous connections to a blockchain
daemon.'''

import asyncio
import itertools
import json
import time

import aiohttp
from aiorpcx import run_in_thread

from electrumx.lib.util import hex_to_bytes, open_truncate, class_logger


class DaemonError(Exception):
    '''Raised when the daemon returns an error in its results.'''


class WarmingUpError(Exception):
    '''Internal - when the daemon is warming up.'''


class ServiceRefusedError(Exception):
    '''Internal - when the daemon doesn't provide a JSON response, only an HTTP error, for
    some reason.'''


class Daemon(object):
    '''Handles connections to a daemon at the given URL.'''

    WARMING_UP = -28
    id_counter = itertools.count()

    def __init__(self, coin, url, *, init_retry=0.25, max_retry=4.0):
        self.coin = coin
        self.logger = class_logger(__name__, self.__class__.__name__)
        self.url_index = None
        self.urls = []
        self.set_url(url)
        # Limit concurrent RPC calls to this number.
        # See DEFAULT_HTTP_WORKQUEUE in bitcoind, which is typically 16
        self.workqueue_semaphore = asyncio.Semaphore(value=10)
        self.block_semaphore = asyncio.Semaphore(value=6)
        self.init_retry = init_retry
        self.max_retry = max_retry
        self._height = None
        self.available_rpcs = {}
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(connector=self.connector())
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.session.close()
        self.session = None

    def connector(self):
        return None

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

    async def _post_json(self, payload, processor):
        data = json.dumps(payload)
        async with self.workqueue_semaphore:
            async with self.session.post(self.current_url(), data=data) as resp:
                kind = resp.headers.get('Content-Type', None)
                if kind == 'application/json':
                    return processor(await resp.json())
                text = await resp.text()
                text = text.strip() or resp.reason
                raise ServiceRefusedError(text)

    async def _get_to_file(self, rest_url, filename):
        full_url = self.current_url() + rest_url
        async with self.block_semaphore:
            with open_truncate(filename) as file:
                async with self.session.get(full_url) as resp:
                    kind = resp.headers.get('Content-Type', None)
                    if kind != 'application/octet-stream':
                        text = await resp.text()
                        text = text.strip() or resp.reason
                        raise ServiceRefusedError(text)
                    size = 0
                    async for part, _ in resp.content.iter_chunks():
                        size += await run_in_thread(file.write, part)
                    return size

    async def _send(self, func, *args):
        '''Send a payload to be converted to JSON.

        Handles temporary connection issues.  Daemon reponse errors
        are raise through DaemonError.
        '''
        def log_error(error):
            nonlocal last_error_log, retry
            now = time.monotonic()
            if now - last_error_log > 60:
                last_error_log = now
                self.logger.error(f'{error}.  Retrying occasionally...')
            if retry == self.max_retry and self.failover():
                retry = 0

        on_good_message = None
        last_error_log = -1000   # Monotonic time starts at 0
        retry = self.init_retry
        while True:
            try:
                result = await func(*args)
                if on_good_message:
                    self.logger.info(on_good_message)
                return result
            except asyncio.TimeoutError:
                log_error('timeout error')
            except aiohttp.ServerDisconnectedError:
                log_error('disconnected')
                on_good_message = 'connection restored'
            except ConnectionResetError:
                log_error('connection reset')
                on_good_message = 'connection restored'
            except aiohttp.ClientConnectionError:
                log_error('connection problem - check your daemon is running')
                on_good_message = 'connection restored'
            except aiohttp.ClientError as e:
                log_error(f'request failed: {e} {args[0]}')
                on_good_message = None
            except ServiceRefusedError as e:
                log_error(f'daemon service refused: {e}')
                on_good_message = 'running normally'
            except WarmingUpError:
                log_error('starting up checking blocks')
                on_good_message = 'running normally'

            await asyncio.sleep(retry)
            retry = max(min(self.max_retry, retry * 2), self.init_retry)

    async def _send_single(self, method, params=None):
        '''Send a single request to the daemon.'''
        def processor(result):
            err = result['error']
            if not err:
                return result['result']
            if err.get('code') == self.WARMING_UP:
                raise WarmingUpError
            raise DaemonError(err)

        payload = {'method': method, 'id': next(self.id_counter)}
        if params:
            payload['params'] = params
        return await self._send(self._post_json, payload, processor)

    async def _send_vector(self, method, params_iterable, replace_errs=False):
        '''Send several requests of the same method.

        The result will be an array of the same length as params_iterable.
        If replace_errs is true, any item with an error is returned as None,
        otherwise an exception is raised.'''
        def processor(result):
            errs = [item['error'] for item in result if item['error']]
            if any(err.get('code') == self.WARMING_UP for err in errs):
                raise WarmingUpError
            if not errs or replace_errs:
                return [item['result'] for item in result]
            raise DaemonError(errs)

        payload = [{'method': method, 'params': p, 'id': next(self.id_counter)}
                   for p in params_iterable]
        if payload:
            return await self._send(self._post_json, payload, processor)
        return []

    async def block_hex_hashes(self, first, count):
        '''Return the hex hashes of count block starting at height first.'''
        params_iterable = ((h, ) for h in range(first, first + count))
        return await self._send_vector('getblockhash', params_iterable)

    async def get_block(self, hex_hash, filename):
        rest_url = f'rest/block/{hex_hash}.bin'
        return await self._send(self._get_to_file, rest_url, filename)

    async def mempool_hashes(self):
        '''Update our record of the daemon's mempool hashes.'''
        return await self._send_single('getrawmempool')

    async def getnetworkinfo(self):
        '''Return the result of the 'getnetworkinfo' RPC call.'''
        return await self._send_single('getnetworkinfo')

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

    async def broadcast_transaction(self, raw_tx):
        '''Broadcast a transaction to the network.'''
        return await self._send_single('sendrawtransaction', (raw_tx, ))

    async def height(self):
        '''Query the daemon for its current height.'''
        self._height = await self._send_single('getblockcount')
        return self._height

    def cached_height(self):
        '''Return the cached daemon height.

        If the daemon has not been queried yet this returns None.'''
        return self._height
