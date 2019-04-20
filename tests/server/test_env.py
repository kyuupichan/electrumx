# Tests of server/env.py

import os
import random
import re

import pytest

from electrumx.server.env import Env, NetIdentity
import electrumx.lib.coins as lib_coins


BASE_DAEMON_URL = 'http://username:password@hostname:321/'
BASE_DB_DIR = '/some/dir'

base_environ = {
    'DB_DIRECTORY': BASE_DB_DIR,
    'DAEMON_URL': BASE_DAEMON_URL,
    'COIN': 'BitcoinSV',
}


def setup_base_env():
    os.environ.clear()
    os.environ.update(base_environ)


def assert_required(env_var):
    setup_base_env()
    os.environ.pop(env_var, None)
    with pytest.raises(Env.Error):
        Env()


def assert_default(env_var, attr, default):
    setup_base_env()
    e = Env()
    assert getattr(e, attr) == default
    os.environ[env_var] = 'foo'
    e = Env()
    assert getattr(e, attr) == 'foo'


def assert_integer(env_var, attr, default=''):
    if default != '':
        e = Env()
        assert getattr(e, attr) == default
    value = random.randrange(5, 2000)
    os.environ[env_var] = str(value) + '.1'
    with pytest.raises(Env.Error):
        Env()
    os.environ[env_var] = str(value)
    e = Env()
    assert getattr(e, attr) == value


def assert_boolean(env_var, attr, default):
    e = Env()
    assert getattr(e, attr) == default
    os.environ[env_var] = 'foo'
    e = Env()
    assert getattr(e, attr) == True
    os.environ[env_var] = ''
    e = Env()
    assert getattr(e, attr) == False


def test_minimal():
    setup_base_env()
    Env()


def test_DB_DIRECTORY():
    assert_required('DB_DIRECTORY')
    setup_base_env()
    e = Env()
    assert e.db_dir == BASE_DB_DIR


def test_DAEMON_URL():
    assert_required('DAEMON_URL')
    setup_base_env()
    e = Env()
    assert e.daemon_url == BASE_DAEMON_URL


def test_COIN_NET():
    '''Test COIN and NET defaults and redirection.'''
    setup_base_env()
    e = Env()
    assert e.coin == lib_coins.BitcoinSV
    os.environ['NET'] = 'testnet'
    e = Env()
    assert e.coin == lib_coins.BitcoinSVTestnet
    os.environ['NET'] = ' testnet '
    e = Env()
    assert e.coin == lib_coins.BitcoinSVTestnet
    os.environ.pop('NET')
    os.environ['COIN'] = ' Litecoin '
    e = Env()
    assert e.coin == lib_coins.Litecoin
    os.environ['NET'] = 'testnet'
    e = Env()
    assert e.coin == lib_coins.LitecoinTestnet
    os.environ.pop('NET')
    os.environ['COIN'] = ' BitcoinGold '
    e = Env()
    assert e.coin == lib_coins.BitcoinGold
    os.environ['NET'] = 'testnet'
    e = Env()
    assert e.coin == lib_coins.BitcoinGoldTestnet
    os.environ['NET'] = 'regtest'
    e = Env()
    assert e.coin == lib_coins.BitcoinGoldRegtest
    os.environ.pop('NET')
    os.environ['COIN'] = ' Decred '
    e = Env()
    assert e.coin == lib_coins.Decred
    os.environ['NET'] = 'testnet'
    e = Env()
    assert e.coin == lib_coins.DecredTestnet
    os.environ.pop('NET')
    os.environ['COIN'] = ' BitcoinGreen '
    e = Env()
    assert e.coin == lib_coins.Bitg
    os.environ['NET'] = 'mainnet'
    e = Env()
    os.environ.pop('NET')
    os.environ['COIN'] = ' Pivx '
    os.environ['NET'] = 'mainnet'
    e = Env()
    assert e.coin == lib_coins.Pivx
    os.environ['NET'] = 'testnet'
    e = Env()
    assert e.coin == lib_coins.PivxTestnet
    os.environ.pop('NET')
    os.environ['NET'] = 'mainnet'
    os.environ['COIN'] = ' TokenPay '
    e = Env()
    assert e.coin == lib_coins.TokenPay

def test_CACHE_MB():
    assert_integer('CACHE_MB', 'cache_MB', 1200)


def test_HOST():
    assert_default('HOST', 'host', 'localhost')
    os.environ['HOST'] = ''
    e = Env()
    assert e.cs_host(for_rpc=False) == ''
    os.environ['HOST'] = '192.168.0.1,23.45.67.89'
    e = Env()
    assert e.cs_host(for_rpc=False) == ['192.168.0.1', '23.45.67.89']
    os.environ['HOST'] = '192.168.0.1 , 23.45.67.89 '
    e = Env()
    assert e.cs_host(for_rpc=False) == ['192.168.0.1', '23.45.67.89']


def test_RPC_HOST():
    assert_default('RPC_HOST', 'rpc_host', 'localhost')
    os.environ['RPC_HOST'] = ''
    e = Env()
    # Blank reverts to localhost
    assert e.cs_host(for_rpc=True) == 'localhost'
    os.environ['RPC_HOST'] = '127.0.0.1, ::1'
    e = Env()
    assert e.cs_host(for_rpc=True) == ['127.0.0.1', '::1']


def test_REORG_LIMIT():
    assert_integer('REORG_LIMIT', 'reorg_limit',
                   lib_coins.BitcoinSV.REORG_LIMIT)


def test_TCP_PORT():
    assert_integer('TCP_PORT', 'tcp_port', None)


def test_SSL_PORT():
    # Requires both SSL_CERTFILE and SSL_KEYFILE to be set
    os.environ['SSL_PORT'] = '50002'
    os.environ['SSL_CERTFILE'] = 'certfile'
    with pytest.raises(Env.Error):
        Env()
    os.environ.pop('SSL_CERTFILE')
    os.environ['SSL_KEYFILE'] = 'keyfile'
    with pytest.raises(Env.Error):
        Env()
    os.environ['SSL_CERTFILE'] = 'certfile'
    Env()
    os.environ.pop('SSL_PORT')
    assert_integer('SSL_PORT', 'ssl_port', None)


def test_RPC_PORT():
    assert_integer('RPC_PORT', 'rpc_port', 8000)


def test_COST_HARD_LIMIT():
    assert_integer('COST_HARD_LIMIT', 'cost_hard_limit', 10000)


def test_COST_SOFT_LIMIT():
    assert_integer('COST_SOFT_LIMIT', 'cost_soft_limit', 1000)


def test_INITIAL_CONCURRENT():
    assert_integer('INITIAL_CONCURRENT', 'initial_concurrent', 10)


def test_REQUEST_SLEEP():
    assert_integer('REQUEST_SLEEP', 'request_sleep', 2500)


def test_BANDWIDTH_UNIT_COST():
    assert_integer('BANDWIDTH_UNIT_COST', 'bw_unit_cost', 5000)


def test_DONATION_ADDRESS():
    assert_default('DONATION_ADDRESS', 'donation_address', '')


def test_DB_ENGINE():
    assert_default('DB_ENGINE', 'db_engine', 'leveldb')


def test_MAX_SEND():
    assert_integer('MAX_SEND', 'max_send', 1000000)


def test_LOG_LEVEL():
    setup_base_env()
    e = Env()
    assert e.log_level == 'INFO'
    os.environ['LOG_LEVEL'] = 'warning'
    e = Env()
    assert e.log_level == 'WARNING'


def test_MAX_SESSIONS():
    too_big = 1000000
    os.environ['MAX_SESSIONS'] = str(too_big)
    e = Env()
    assert e.max_sessions < too_big
    # Cannot test default as it may be lowered by the open file limit cap


def test_REQUEST_TIMEOUT():
    assert_integer('REQUEST_TIMEOUT', 'request_timeout', 30)


def test_SESSION_TIMEOUT():
    assert_integer('SESSION_TIMEOUT', 'session_timeout', 600)


def test_BANNER_FILE():
    e = Env()
    assert e.banner_file is None
    assert e.tor_banner_file is None
    os.environ['BANNER_FILE'] = 'banner_file'
    e = Env()
    assert e.banner_file == 'banner_file'
    assert e.tor_banner_file == 'banner_file'
    os.environ['TOR_BANNER_FILE'] = 'tor_banner_file'
    e = Env()
    assert e.banner_file == 'banner_file'
    assert e.tor_banner_file == 'tor_banner_file'


def test_EVENT_LOOP_POLICY():
    e = Env()
    assert e.loop_policy is None
    os.environ['EVENT_LOOP_POLICY'] = 'foo'
    with pytest.raises(Env.Error):
        Env()
    os.environ['EVENT_LOOP_POLICY'] = 'uvloop'
    try:
        Env()
    except ImportError:
        pass
    del os.environ['EVENT_LOOP_POLICY']


def test_ANON_LOGS():
    assert_boolean('ANON_LOGS', 'anon_logs', False)


def test_PEER_DISCOVERY():
    e = Env()
    assert e.peer_discovery == Env.PD_ON
    os.environ['PEER_DISCOVERY'] = ' '
    e = Env()
    assert e.peer_discovery == Env.PD_OFF
    os.environ['PEER_DISCOVERY'] = 'ON'
    e = Env()
    assert e.peer_discovery == Env.PD_ON
    os.environ['PEER_DISCOVERY'] = 'self'
    e = Env()
    assert e.peer_discovery == Env.PD_SELF


def test_PEER_ANNOUNCE():
    assert_boolean('PEER_ANNOUNCE', 'peer_announce', True)


def test_FORCE_PROXY():
    assert_boolean('FORCE_PROXY', 'force_proxy', False)


def test_TOR_PROXY_HOST():
    assert_default('TOR_PROXY_HOST', 'tor_proxy_host', 'localhost')


def test_TOR_PROXY_PORT():
    assert_integer('TOR_PROXY_PORT', 'tor_proxy_port', None)


def test_clearnet_identity():
    os.environ['REPORT_TCP_PORT'] = '456'
    e = Env()
    assert len(e.identities) == 0
    os.environ['REPORT_HOST'] = '8.8.8.8'
    e = Env()
    assert len(e.identities) == 1
    assert e.identities[0].host == '8.8.8.8'
    os.environ['REPORT_HOST'] = 'localhost'
    with pytest.raises(Env.Error):
        Env()
    os.environ['REPORT_HOST'] = ''
    with pytest.raises(Env.Error):
        Env()
    os.environ['REPORT_HOST'] = '127.0.0.1'
    with pytest.raises(Env.Error):
        Env()
    os.environ['REPORT_HOST'] = '0.0.0.0'
    with pytest.raises(Env.Error):
        Env()
    os.environ['REPORT_HOST'] = '224.0.0.2'
    with pytest.raises(Env.Error):
        Env()
    os.environ['REPORT_HOST'] = '$HOST'
    with pytest.raises(Env.Error):
        Env()
    # Accept private IP, unless PEER_ANNOUNCE
    os.environ['PEER_ANNOUNCE'] = ''
    os.environ['REPORT_HOST'] = '192.168.0.1'
    os.environ['SSL_CERTFILE'] = 'certfile'
    os.environ['SSL_KEYFILE'] = 'keyfile'
    Env()
    os.environ['PEER_ANNOUNCE'] = 'OK'
    with pytest.raises(Env.Error) as err:
        Env()
    os.environ.pop('PEER_ANNOUNCE', None)
    assert 'not a valid REPORT_HOST' in str(err)

    os.environ['REPORT_HOST'] = '1.2.3.4'
    os.environ['REPORT_SSL_PORT'] = os.environ['REPORT_TCP_PORT']
    with pytest.raises(Env.Error) as err:
        Env()
    assert 'both resolve' in str(err)

    os.environ['REPORT_SSL_PORT'] = '457'
    os.environ['REPORT_HOST'] = 'foo.com'
    e = Env()
    assert len(e.identities) == 1
    ident = e.identities[0]
    assert ident.host == 'foo.com'
    assert ident.tcp_port == 456
    assert ident.ssl_port == 457


def test_tor_identity():
    tor_host = 'something.onion'
    os.environ.pop('REPORT_HOST', None)
    os.environ.pop('REPORT_HOST_TOR', None)
    e = Env()
    assert len(e.identities) == 0
    os.environ['REPORT_HOST_TOR'] = 'foo'
    os.environ['REPORT_SSL_PORT_TOR'] = '123'
    os.environ['TCP_PORT'] = '456'
    with pytest.raises(Env.Error):
        Env()
    os.environ['REPORT_HOST_TOR'] = tor_host
    e = Env()
    assert len(e.identities) == 1
    ident = e.identities[0]
    assert ident.host == tor_host
    assert ident.tcp_port == 456
    assert ident.ssl_port == 123
    os.environ['REPORT_TCP_PORT_TOR'] = os.environ['REPORT_SSL_PORT_TOR']
    with pytest.raises(Env.Error):
        Env()
    os.environ['REPORT_HOST'] = 'foo.com'
    os.environ['TCP_PORT'] = '456'
    os.environ['SSL_PORT'] = '789'
    os.environ['REPORT_TCP_PORT'] = '654'
    os.environ['REPORT_SSL_PORT'] = '987'
    os.environ['SSL_CERTFILE'] = 'certfile'
    os.environ['SSL_KEYFILE'] = 'keyfile'
    os.environ.pop('REPORT_TCP_PORT_TOR', None)
    os.environ.pop('REPORT_SSL_PORT_TOR', None)
    e = Env()
    assert len(e.identities) == 2
    ident = e.identities[1]
    assert ident.host == tor_host
    assert ident.tcp_port == 654
    assert ident.ssl_port == 987
    os.environ['REPORT_TCP_PORT_TOR'] = '234'
    os.environ['REPORT_SSL_PORT_TOR'] = '432'
    e = Env()
    assert len(e.identities) == 2
    ident = e.identities[1]
    assert ident.host == tor_host
    assert ident.tcp_port == 234
    assert ident.ssl_port == 432


def test_ban_versions():
    e = Env()
    assert e.drop_client is None
    ban_re = r'1\.[0-2]\.\d+?[_\w]*'
    os.environ['DROP_CLIENT'] = ban_re
    e = Env()
    assert e.drop_client == re.compile(ban_re)
    assert e.drop_client.match("1.2.3_buggy_client")
    assert e.drop_client.match("1.3.0_good_client") is None


def test_coin_class_provided():
    e = Env(lib_coins.BitcoinSV)
    assert e.coin == lib_coins.BitcoinSV
