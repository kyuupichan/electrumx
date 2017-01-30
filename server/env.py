# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Class for handling environment configuration and defaults.'''


from collections import namedtuple
from os import environ

from lib.coins import Coin
from lib.util import LoggedClass


NetIdentity = namedtuple('NetIdentity', 'host tcp_port ssl_port nick_suffix')


class Env(LoggedClass):
    '''Wraps environment configuration.'''

    class Error(Exception):
        pass

    def __init__(self):
        super().__init__()
        self.obsolete(['UTXO_MB', 'HIST_MB', 'NETWORK'])
        coin_name = self.default('COIN', 'Bitcoin')
        network = self.default('NET', 'mainnet')
        self.coin = Coin.lookup_coin_class(coin_name, network)
        self.db_dir = self.required('DB_DIRECTORY')
        self.cache_MB = self.integer('CACHE_MB', 1200)
        self.host = self.default('HOST', 'localhost')
        self.reorg_limit = self.integer('REORG_LIMIT', self.coin.REORG_LIMIT)
        self.daemon_url = self.required('DAEMON_URL')
        # Server stuff
        self.tcp_port = self.integer('TCP_PORT', None)
        self.ssl_port = self.integer('SSL_PORT', None)
        if self.ssl_port:
            self.ssl_certfile = self.required('SSL_CERTFILE')
            self.ssl_keyfile = self.required('SSL_KEYFILE')
        self.rpc_port = self.integer('RPC_PORT', 8000)
        self.max_subscriptions = self.integer('MAX_SUBSCRIPTIONS', 10000)
        self.banner_file = self.default('BANNER_FILE', None)
        self.anon_logs = self.default('ANON_LOGS', False)
        self.log_sessions = self.integer('LOG_SESSIONS', 3600)
        # The electrum client takes the empty string as unspecified
        self.donation_address = self.default('DONATION_ADDRESS', '')
        self.db_engine = self.default('DB_ENGINE', 'leveldb')
        # Server limits to help prevent DoS
        self.max_send = self.integer('MAX_SEND', 1000000)
        self.max_subs = self.integer('MAX_SUBS', 250000)
        self.max_sessions = self.integer('MAX_SESSIONS', 1000)
        self.max_session_subs = self.integer('MAX_SESSION_SUBS', 50000)
        self.bandwidth_limit = self.integer('BANDWIDTH_LIMIT', 2000000)
        self.session_timeout = self.integer('SESSION_TIMEOUT', 600)
        # IRC
        self.irc = self.default('IRC', False)
        self.irc_nick = self.default('IRC_NICK', None)

        self.identity = NetIdentity(
            self.default('REPORT_HOST', self.host),
            self.integer('REPORT_TCP_PORT', self.tcp_port) or None,
            self.integer('REPORT_SSL_PORT', self.ssl_port) or None,
            ''
        )
        self.tor_identity = NetIdentity(
            self.default('REPORT_HOST_TOR', ''), # must be a string
            self.integer('REPORT_TCP_PORT_TOR',
                         self.identity.tcp_port
                         if self.identity.tcp_port else
                         self.tcp_port) or None,
            self.integer('REPORT_SSL_PORT_TOR',
                         self.identity.ssl_port
                         if self.identity.ssl_port else
                         self.ssl_port) or None,
            '_tor'
        )

        if self.irc:
            if not self.identity.host.strip():
                raise self.Error('IRC host is empty')
            if self.identity.tcp_port == self.identity.ssl_port:
                raise self.Error('IRC TCP and SSL ports are the same')


    def default(self, envvar, default):
        return environ.get(envvar, default)

    def required(self, envvar):
        value = environ.get(envvar)
        if value is None:
            raise self.Error('required envvar {} not set'.format(envvar))
        return value

    def integer(self, envvar, default):
        value = environ.get(envvar)
        if value is None:
            return default
        try:
            return int(value)
        except Exception:
            raise self.Error('cannot convert envvar {} value {} to an integer'
                             .format(envvar, value))

    def obsolete(self, envvars):
        bad = [envvar for envvar in envvars if environ.get(envvar)]
        if bad:
            raise self.Error('remove obsolete environment variables {}'
                             .format(bad))
