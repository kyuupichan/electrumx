import asyncio
from unittest import mock

from aiorpcx import RPCError
from electrumx import Controller, Env

loop = asyncio.get_event_loop()


def set_env():
    env = mock.create_autospec(Env)
    env.coin = mock.Mock()
    env.coin.SESSIONCLS.protocol_min_max_strings = lambda : ["1.1", "1.4"]
    env.loop_policy = None
    env.max_sessions = 0
    env.max_subs = 0
    env.max_send = 0
    env.bandwidth_limit = 0
    env.identities = ''
    env.tor_proxy_host = env.tor_proxy_port = None
    env.peer_discovery = env.PD_SELF = False
    env.daemon_url = 'http://localhost:8000/'
    return env


async def coro(res):
    return res


def raise_exception(msg):
    raise RPCError(1, msg)


def ensure_text_exception(test, exception):
    res = err = None
    try:
        res = loop.run_until_complete(test)
    except Exception as e:
        err = e
    assert isinstance(err, exception), (res, err)


def test_dummy():
    assert True

def _test_transaction_get():
    async def test_verbose_ignore_by_backend():
        env = set_env()
        sut = Controller(env)
        sut.daemon_request = mock.Mock()
        sut.daemon_request.return_value = coro('11'*32)
        res = await sut.transaction_get('ff'*32, True)
        assert res == '11'*32

    async def test_verbose_ok():
        env = set_env()
        sut = Controller(env)
        sut.daemon_request = mock.Mock()
        response = {
            "hex": "00"*32,
            "blockhash": "ff"*32
        }
        sut.daemon_request.return_value = coro(response)
        res = await sut.transaction_get('ff'*32, True)
        assert res == response

        response = {
            "hex": "00"*32,
            "blockhash": None
        }
        sut.daemon_request.return_value = coro(response)
        res = await sut.transaction_get('ff'*32, True)
        assert res == response

    async def test_no_verbose():
        env = set_env()
        sut = Controller(env)
        sut.daemon_request = mock.Mock()
        response = 'cafebabe'*64
        sut.daemon_request.return_value = coro(response)
        res = await sut.transaction_get('ff'*32)
        assert res == response

    async def test_verbose_failure():
        env = set_env()
        sut = Controller(env)
        sut.daemon_request = mock.Mock()
        sut.daemon_request.return_value = coro(
            raise_exception('some unhandled error'))
        await sut.transaction_get('ff' * 32, True)

    async def test_wrong_txhash():
        env = set_env()
        sut = Controller(env)
        sut.daemon_request = mock.Mock()
        await sut.transaction_get('cafe')
        sut.daemon_request.assert_not_called()

    loop.run_until_complete(asyncio.gather(
        *[
            test_verbose_ignore_by_backend(),
            test_verbose_ok(),
            test_no_verbose()
        ]
    ))

    for error_test in [test_verbose_failure, test_wrong_txhash]:
        ensure_text_exception(error_test(), RPCError)
