import aiohttp
import asyncio
import json
import logging

import pytest

from aiorpcx import (
    JSONRPCv1, JSONRPCLoose, RPCError, ignore_after,
    Request, Batch,
)
from electrumx.lib.coins import BitcoinCash, CoinError, Bitzeny, Dash
from electrumx.server.daemon import (
    Daemon, FakeEstimateFeeDaemon, DaemonError
)


coin = BitcoinCash

# These should be full, canonical URLs
urls = ['http://rpc_user:rpc_pass@127.0.0.1:8332/',
        'http://rpc_user:rpc_pass@192.168.0.1:8332/']


@pytest.fixture(params=[BitcoinCash, Bitzeny])
def daemon(request):
    coin = request.param
    return coin.DAEMON(coin, ','.join(urls))


@pytest.fixture(params=[Dash])
def dash_daemon(request):
    coin = request.param
    return coin.DAEMON(coin, ','.join(urls))


class ResponseBase(object):

    def __init__(self, headers, status):
        self.headers = headers
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        pass


class JSONResponse(ResponseBase):

    def __init__(self, result, msg_id, status=200):
        super().__init__({'Content-Type': 'application/json'}, status)
        self.result = result
        self.msg_id = msg_id

    async def json(self):
        if isinstance(self.msg_id, int):
            message = JSONRPCv1.response_message(self.result, self.msg_id)
        else:
            parts = [JSONRPCv1.response_message(item, msg_id)
                     for item, msg_id in zip(self.result, self.msg_id)]
            message = JSONRPCv1.batch_message_from_parts(parts)
        return json.loads(message.decode())


class HTMLResponse(ResponseBase):

    def __init__(self, text, reason, status):
        super().__init__({'Content-Type': 'text/html; charset=ISO-8859-1'},
                         status)
        self._text = text
        self.reason = reason

    async def text(self):
        return self._text


class ClientSessionBase(object):

    def __enter__(self):
        self.prior_class = aiohttp.ClientSession
        aiohttp.ClientSession = lambda: self

    def __exit__(self, exc_type, exc_value, traceback):
        aiohttp.ClientSession = self.prior_class

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        pass


class ClientSessionGood(ClientSessionBase):
    '''Imitate aiohttp for testing purposes.'''

    def __init__(self, *triples):
        self.triples = triples  # each a (method, args, result)
        self.count = 0
        self.expected_url = urls[0]

    def post(self, url, data=""):
        assert url == self.expected_url
        request, request_id = JSONRPCLoose.message_to_item(data.encode())
        method, args, result = self.triples[self.count]
        self.count += 1
        if isinstance(request, Request):
            assert request.method == method
            assert request.args == args
            return JSONResponse(result, request_id)
        else:
            batch = request
            assert isinstance(batch, list)
            request_ids = []
            for payload, args in zip(batch, args):
                assert payload['method'] == method
                assert payload['params'] == args
                request_ids.append(payload['id'])
            return JSONResponse(result, request_ids)


class ClientSessionBadAuth(ClientSessionBase):

    def post(self, url, data=""):
         return HTMLResponse('', 'Unauthorized', 401)


class ClientSessionWorkQueueFull(ClientSessionGood):

    def post(self, url, data=""):
        self.post = super().post
        return HTMLResponse('Work queue depth exceeded',
                            'Internal server error', 500)


class ClientSessionNoConnection(ClientSessionGood):

    def __init__(self, *args):
        self.args = args

    async def __aenter__(self):
        aiohttp.ClientSession = lambda: ClientSessionGood(*self.args)
        raise aiohttp.ClientConnectionError


class ClientSessionPostError(ClientSessionGood):

    def __init__(self, exception, *args):
        self.exception = exception
        self.args = args

    def post(self, url, data=""):
        aiohttp.ClientSession = lambda: ClientSessionGood(*self.args)
        raise self.exception


class ClientSessionFailover(ClientSessionGood):

    def post(self, url, data=""):
        # If not failed over; simulate disconnecting
        if url == self.expected_url:
            raise aiohttp.ServerDisconnectedError
        else:
            self.expected_url = urls[1]
            return super().post(url, data)


def in_caplog(caplog, message, count=1):
    return sum(message in record.message
               for record in caplog.records) == count

#
# Tests
#

def test_set_urls_bad():
    with pytest.raises(CoinError):
        Daemon(coin, '')
    with pytest.raises(CoinError):
        Daemon(coin, 'a')


def test_set_urls_one(caplog):
    with caplog.at_level(logging.INFO):
        daemon = Daemon(coin, urls[0])
    assert daemon.current_url() == urls[0]
    assert len(daemon.urls) == 1
    logged_url = daemon.logged_url()
    assert logged_url == '127.0.0.1:8332/'
    assert in_caplog(caplog, f'daemon #1 at {logged_url} (current)')


def test_set_urls_two(caplog):
    with caplog.at_level(logging.INFO):
        daemon = Daemon(coin, ','.join(urls))
    assert daemon.current_url() == urls[0]
    assert len(daemon.urls) == 2
    logged_url = daemon.logged_url()
    assert logged_url == '127.0.0.1:8332/'
    assert in_caplog(caplog, f'daemon #1 at {logged_url} (current)')
    assert in_caplog(caplog, 'daemon #2 at 192.168.0.1:8332')


def test_set_urls_short():
    no_prefix_urls = ['/'.join(part for part in url.split('/')[2:])
                      for url in urls]
    daemon = Daemon(coin, ','.join(no_prefix_urls))
    assert daemon.current_url() == urls[0]
    assert len(daemon.urls) == 2

    no_slash_urls = [url[:-1] for url in urls]
    daemon = Daemon(coin, ','.join(no_slash_urls))
    assert daemon.current_url() == urls[0]
    assert len(daemon.urls) == 2

    no_port_urls = [url[:url.rfind(':')] for url in urls]
    daemon = Daemon(coin, ','.join(no_port_urls))
    assert daemon.current_url() == urls[0]
    assert len(daemon.urls) == 2


def test_failover_good(caplog):
    daemon = Daemon(coin, ','.join(urls))
    with caplog.at_level(logging.INFO):
        result = daemon.failover()
    assert result is True
    assert daemon.current_url() == urls[1]
    logged_url = daemon.logged_url()
    assert in_caplog(caplog, f'failing over to {logged_url}')
    # And again
    result = daemon.failover()
    assert result is True
    assert daemon.current_url() == urls[0]


def test_failover_fail(caplog):
    daemon = Daemon(coin, urls[0])
    with caplog.at_level(logging.INFO):
        result = daemon.failover()
    assert result is False
    assert daemon.current_url() == urls[0]
    assert not in_caplog(caplog, f'failing over')


@pytest.mark.asyncio
async def test_height(daemon):
    assert daemon.cached_height() is None
    height = 300
    with ClientSessionGood(('getblockcount', [], height)):
        assert await daemon.height() == height
    assert daemon.cached_height() == height


@pytest.mark.asyncio
async def test_broadcast_transaction(daemon):
    raw_tx = 'deadbeef'
    tx_hash = 'hash'
    with ClientSessionGood(('sendrawtransaction', [raw_tx], tx_hash)):
        assert await daemon.broadcast_transaction(raw_tx) == tx_hash


@pytest.mark.asyncio
async def test_relayfee(daemon):
    response = {"relayfee": sats, "other:": "cruft"}
    with ClientSessionGood(('getnetworkinfo', [], response)):
        assert await daemon.getnetworkinfo() == response


@pytest.mark.asyncio
async def test_relayfee(daemon):
    if isinstance(daemon, FakeEstimateFeeDaemon):
        sats = daemon.coin.ESTIMATE_FEE
    else:
        sats = 2
    response = {"relayfee": sats, "other:": "cruft"}
    with ClientSessionGood(('getnetworkinfo', [], response)):
        assert await daemon.relayfee() == sats


@pytest.mark.asyncio
async def test_mempool_hashes(daemon):
    hashes = ['hex_hash1', 'hex_hash2']
    with ClientSessionGood(('getrawmempool', [], hashes)):
        assert await daemon.mempool_hashes() == hashes


@pytest.mark.asyncio
async def test_deserialised_block(daemon):
    block_hash = 'block_hash'
    result = {'some': 'mess'}
    with ClientSessionGood(('getblock', [block_hash, True], result)):
        assert await daemon.deserialised_block(block_hash) == result


@pytest.mark.asyncio
async def test_estimatefee(daemon):
    method_not_found = RPCError(JSONRPCv1.METHOD_NOT_FOUND, 'nope')
    if isinstance(daemon, FakeEstimateFeeDaemon):
        result = daemon.coin.ESTIMATE_FEE
    else:
        result = -1
    with ClientSessionGood(
            ('estimatesmartfee', [], method_not_found),
            ('estimatefee', [2], result)
    ):
        assert await daemon.estimatefee(2) == result


@pytest.mark.asyncio
async def test_estimatefee_smart(daemon):
    bad_args = RPCError(JSONRPCv1.INVALID_ARGS, 'bad args')
    if isinstance(daemon, FakeEstimateFeeDaemon):
        return
    rate = 0.0002
    result = {'feerate': rate}
    with ClientSessionGood(
            ('estimatesmartfee', [], bad_args),
            ('estimatesmartfee', [2], result)
    ):
        assert await daemon.estimatefee(2) == rate

    # Test the rpc_available_cache is used
    with ClientSessionGood(('estimatesmartfee', [2], result)):
        assert await daemon.estimatefee(2) == rate


@pytest.mark.asyncio
async def test_getrawtransaction(daemon):
    hex_hash = 'deadbeef'
    simple = 'tx_in_hex'
    verbose = {'hex': hex_hash, 'other': 'cruft'}
    # Test False is converted to 0 - old daemon's reject False
    with ClientSessionGood(('getrawtransaction', [hex_hash, 0], simple)):
        assert await daemon.getrawtransaction(hex_hash) == simple

    # Test True is converted to 1
    with ClientSessionGood(('getrawtransaction', [hex_hash, 1], verbose)):
        assert await daemon.getrawtransaction(
            hex_hash, True) == verbose


@pytest.mark.asyncio
async def test_protx(dash_daemon):
    protx_hash = 'deadbeaf'
    with ClientSessionGood(('protx', ['info', protx_hash], {})):
        assert await dash_daemon.protx(['info', protx_hash]) == {}


# Batch tests

@pytest.mark.asyncio
async def test_empty_send(daemon):
    first = 5
    count = 0
    with ClientSessionGood(('getblockhash', [], [])):
        assert await daemon.block_hex_hashes(first, count) == []


@pytest.mark.asyncio
async def test_block_hex_hashes(daemon):
    first = 5
    count = 3
    hashes = [f'hex_hash{n}' for n in range(count)]
    with ClientSessionGood(('getblockhash',
                            [[n] for n in range(first, first + count)],
                            hashes)):
        assert await daemon.block_hex_hashes(first, count) == hashes


@pytest.mark.asyncio
async def test_raw_blocks(daemon):
    count = 3
    hex_hashes = [f'hex_hash{n}' for n in range(count)]
    args_list = [[hex_hash, False] for hex_hash in hex_hashes]
    iterable = (hex_hash for hex_hash in hex_hashes)
    blocks = ["00", "019a", "02fe"]
    blocks_raw = [bytes.fromhex(block) for block in blocks]
    with ClientSessionGood(('getblock', args_list, blocks)):
        assert await daemon.raw_blocks(iterable) == blocks_raw


@pytest.mark.asyncio
async def test_get_raw_transactions(daemon):
    hex_hashes = ['deadbeef0', 'deadbeef1']
    args_list = [[hex_hash, 0] for hex_hash in hex_hashes]
    raw_txs_hex = ['fffefdfc', '0a0b0c0d']
    raw_txs = [bytes.fromhex(raw_tx) for raw_tx in raw_txs_hex]
    # Test 0 - old daemon's reject False
    with ClientSessionGood(('getrawtransaction', args_list, raw_txs_hex)):
        assert await daemon.getrawtransactions(hex_hashes) == raw_txs

    # Test one error
    tx_not_found = RPCError(-1, 'some error message')
    results = ['ff0b7d', tx_not_found]
    raw_txs = [bytes.fromhex(results[0]), None]
    with ClientSessionGood(('getrawtransaction', args_list, results)):
        assert await daemon.getrawtransactions(hex_hashes) == raw_txs


# Other tests

@pytest.mark.asyncio
async def test_bad_auth(daemon, caplog):
    with pytest.raises(DaemonError) as e:
        with ClientSessionBadAuth():
            await daemon.height()

    assert "Unauthorized" in e.value.args[0]
    assert in_caplog(caplog, "Unauthorized")


@pytest.mark.asyncio
async def test_workqueue_depth(daemon, caplog):
    daemon.init_retry = 0.01
    height = 125
    with caplog.at_level(logging.INFO):
        with ClientSessionWorkQueueFull(('getblockcount', [], height)):
            await daemon.height() == height

    assert in_caplog(caplog, "work queue full")
    assert in_caplog(caplog, "running normally")


@pytest.mark.asyncio
async def test_connection_error(daemon, caplog):
    height = 100
    daemon.init_retry = 0.01
    with caplog.at_level(logging.INFO):
        with ClientSessionNoConnection(('getblockcount', [], height)):
            await daemon.height() == height

    assert in_caplog(caplog, "connection problem - is your daemon running?")
    assert in_caplog(caplog, "connection restored")


@pytest.mark.asyncio
async def test_timeout_error(daemon, caplog):
    height = 100
    daemon.init_retry = 0.01
    with caplog.at_level(logging.INFO):
        with ClientSessionPostError(asyncio.TimeoutError,
                                    ('getblockcount', [], height)):
            await daemon.height() == height

    assert in_caplog(caplog, "timeout error")


@pytest.mark.asyncio
async def test_disconnected(daemon, caplog):
    height = 100
    daemon.init_retry = 0.01
    with caplog.at_level(logging.INFO):
        with ClientSessionPostError(aiohttp.ServerDisconnectedError,
                                    ('getblockcount', [], height)):
            await daemon.height() == height

    assert in_caplog(caplog, "disconnected")
    assert in_caplog(caplog, "connection restored")


@pytest.mark.asyncio
async def test_warming_up(daemon, caplog):
    warming_up = RPCError(-28, 'reading block index')
    height = 100
    daemon.init_retry = 0.01
    with caplog.at_level(logging.INFO):
        with ClientSessionGood(
                ('getblockcount', [], warming_up),
                ('getblockcount', [], height)
        ):
            assert await daemon.height() == height

    assert in_caplog(caplog, "starting up checking blocks")
    assert in_caplog(caplog, "running normally")


@pytest.mark.asyncio
async def test_warming_up_batch(daemon, caplog):
    warming_up = RPCError(-28, 'reading block index')
    first = 5
    count = 1
    daemon.init_retry = 0.01
    hashes = ['hex_hash5']
    with caplog.at_level(logging.INFO):
        with ClientSessionGood(('getblockhash', [[first]], [warming_up]),
                               ('getblockhash', [[first]], hashes)):
            assert await daemon.block_hex_hashes(first, count) == hashes

    assert in_caplog(caplog, "starting up checking blocks")
    assert in_caplog(caplog, "running normally")


@pytest.mark.asyncio
async def test_failover(daemon, caplog):
    height = 100
    daemon.init_retry = 0.01
    daemon.max_retry = 0.04
    with caplog.at_level(logging.INFO):
        with ClientSessionFailover(('getblockcount', [], height)):
            await daemon.height() == height

    assert in_caplog(caplog, "disconnected", 1)
    assert in_caplog(caplog, "failing over")
    assert in_caplog(caplog, "connection restored")
