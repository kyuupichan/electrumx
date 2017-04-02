# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Class for handling environment configuration and defaults.'''


import resource
from collections import namedtuple
from ipaddress import ip_address
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
        self.tor_banner_file = self.default('TOR_BANNER_FILE',
                                            self.banner_file)
        self.anon_logs = self.default('ANON_LOGS', False)
        self.log_sessions = self.integer('LOG_SESSIONS', 3600)
        # Peer discovery
        self.peer_discovery = bool(self.default('PEER_DISCOVERY', True))
        self.peer_announce = bool(self.default('PEER_ANNOUNCE', True))
        self.tor_proxy_host = self.default('TOR_PROXY_HOST', 'localhost')
        self.tor_proxy_port = self.integer('TOR_PROXY_PORT', None)
        # The electrum client takes the empty string as unspecified
        self.donation_address = self.default('DONATION_ADDRESS', '')
        self.db_engine = self.default('DB_ENGINE', 'leveldb')
        # Server limits to help prevent DoS
        self.max_send = self.integer('MAX_SEND', 1000000)
        self.max_subs = self.integer('MAX_SUBS', 250000)
        self.max_sessions = self.sane_max_sessions()
        self.max_session_subs = self.integer('MAX_SESSION_SUBS', 50000)
        self.bandwidth_limit = self.integer('BANDWIDTH_LIMIT', 2000000)
        self.session_timeout = self.integer('SESSION_TIMEOUT', 600)
        # IRC
        self.irc = self.default('IRC', False)
        self.irc_nick = self.default('IRC_NICK', None)

        # Identities
        clearnet_identity = self.clearnet_identity()
        tor_identity = self.tor_identity(clearnet_identity)
        self.identities = [identity
                           for identity in (clearnet_identity, tor_identity)
                           if identity is not None]

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

    def sane_max_sessions(self):
        '''Return the maximum number of sessions to permit.  Normally this
        is MAX_SESSIONS.  However, to prevent open file exhaustion, ajdust
        downwards if running with a small open file rlimit.'''
        env_value = self.integer('MAX_SESSIONS', 1000)
        nofile_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        # We give the DB 250 files; allow ElectrumX 100 for itself
        value = max(0, min(env_value, nofile_limit - 350))
        if value < env_value:
            self.log_warning('lowered maximum seessions from {:,d} to {:,d} '
                             'because your open file limit is {:,d}'
                             .format(env_value, value, nofile_limit))
        return value

    def obsolete(self, envvars):
        bad = [envvar for envvar in envvars if environ.get(envvar)]
        if bad:
            raise self.Error('remove obsolete environment variables {}'
                             .format(bad))

    def clearnet_identity(self):
        host = self.default('REPORT_HOST', None)
        if host is None:
            return None
        try:
            ip = ip_address(host)
        except ValueError:
            bad = host.lower().strip() in ('', 'localhost')
        else:
            bad = (ip.is_multicast or ip.is_unspecified
                   or (ip.is_private and (self.irc or self.peer_announce)))
        if bad:
            raise self.Error('"{}" is not a valid REPORT_HOST'.format(host))
        tcp_port = self.integer('REPORT_TCP_PORT', self.tcp_port) or None
        ssl_port = self.integer('REPORT_SSL_PORT', self.ssl_port) or None
        if tcp_port == ssl_port:
            raise self.Error('REPORT_TCP_PORT and REPORT_SSL_PORT '
                             'both resolve to {}'.format(tcp_port))
        return NetIdentity(
            host,
            tcp_port,
            ssl_port,
            ''
        )

    def tor_identity(self, clearnet):
        host = self.default('REPORT_HOST_TOR', None)
        if host is None:
            return None
        if not host.endswith('.onion'):
            raise self.Error('tor host "{}" must end with ".onion"'
                             .format(host))

        def port(port_kind):
            '''Returns the clearnet identity port, if any and not zero,
            otherwise the listening port.'''
            result = 0
            if clearnet:
                result = getattr(clearnet, port_kind)
            return result or getattr(self, port_kind)

        tcp_port = self.integer('REPORT_TCP_PORT_TOR', port('tcp_port')) or None
        ssl_port = self.integer('REPORT_SSL_PORT_TOR', port('ssl_port')) or None
        if tcp_port == ssl_port:
            raise self.Error('REPORT_TCP_PORT_TOR and REPORT_SSL_PORT_TOR '
                             'both resolve to {}'.format(tcp_port))

        return NetIdentity(
            host,
            tcp_port,
            ssl_port,
            '_tor',
        )
