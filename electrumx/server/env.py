# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Class for handling environment configuration and defaults.'''


import re
from collections import namedtuple
from ipaddress import IPv4Address, IPv6Address

from aiorpcx import classify_host
from electrumx.lib.coins import Coin
from electrumx.lib.env_base import EnvBase
import electrumx.lib.util as lib_util


NetIdentity = namedtuple('NetIdentity', 'host tcp_port ssl_port')


class Env(EnvBase):
    '''Wraps environment configuration. Optionally, accepts a Coin class
       as first argument to have ElectrumX serve custom coins not part of
       the standard distribution.
    '''

    # Peer discovery
    PD_OFF, PD_SELF, PD_ON = ('OFF', 'SELF', 'ON')

    def __init__(self, coin=None):
        super().__init__()
        self.obsolete(["MAX_SUBSCRIPTIONS", "MAX_SUBS", "MAX_SESSION_SUBS", "BANDWIDTH_LIMIT"])
        self.db_dir = self.required('DB_DIRECTORY')
        self.db_engine = self.default('DB_ENGINE', 'leveldb')
        self.daemon_url = self.required('DAEMON_URL')
        if coin is not None:
            assert issubclass(coin, Coin)
            self.coin = coin
        else:
            coin_name = self.required('COIN').strip()
            network = self.default('NET', 'mainnet').strip()
            self.coin = Coin.lookup_coin_class(coin_name, network)
        self.cache_MB = self.integer('CACHE_MB', 1200)
        self.host = self.default('HOST', 'localhost')
        self.reorg_limit = self.integer('REORG_LIMIT', self.coin.REORG_LIMIT)
        # Server stuff
        self.tcp_port = self.integer('TCP_PORT', None)
        self.ssl_port = self.integer('SSL_PORT', None)
        if self.ssl_port:
            self.ssl_certfile = self.required('SSL_CERTFILE')
            self.ssl_keyfile = self.required('SSL_KEYFILE')
        self.rpc_port = self.integer('RPC_PORT', 8000)
        self.banner_file = self.default('BANNER_FILE', None)
        self.tor_banner_file = self.default('TOR_BANNER_FILE',
                                            self.banner_file)
        self.anon_logs = self.boolean('ANON_LOGS', False)
        self.log_sessions = self.integer('LOG_SESSIONS', 3600)
        self.log_level = self.default('LOG_LEVEL', 'info').upper()
        # Peer discovery
        self.peer_discovery = self.peer_discovery_enum()
        self.peer_announce = self.boolean('PEER_ANNOUNCE', True)
        self.force_proxy = self.boolean('FORCE_PROXY', False)
        self.tor_proxy_host = self.default('TOR_PROXY_HOST', 'localhost')
        self.tor_proxy_port = self.integer('TOR_PROXY_PORT', None)
        # The electrum client takes the empty string as unspecified
        self.donation_address = self.default('DONATION_ADDRESS', '')
        # Server limits to help prevent DoS
        self.max_send = self.integer('MAX_SEND', self.coin.DEFAULT_MAX_SEND)
        self.max_sessions = self.sane_max_sessions()
        self.cost_soft_limit = self.integer('COST_SOFT_LIMIT', 1000)
        self.cost_hard_limit = self.integer('COST_HARD_LIMIT', 10000)
        self.bw_unit_cost = self.integer('BANDWIDTH_UNIT_COST', 5000)
        self.initial_concurrent = self.integer('INITIAL_CONCURRENT', 10)
        self.request_sleep = self.integer('REQUEST_SLEEP', 2500)
        self.request_timeout = self.integer('REQUEST_TIMEOUT', 30)
        self.session_timeout = self.integer('SESSION_TIMEOUT', 600)
        self.drop_client = self.custom("DROP_CLIENT", None, re.compile)
        self.blacklist_url = self.default('BLACKLIST_URL', self.coin.BLACKLIST_URL)

        # Identities
        clearnet_identity = self.clearnet_identity()
        tor_identity = self.tor_identity(clearnet_identity)
        self.identities = [identity
                           for identity in (clearnet_identity, tor_identity)
                           if identity is not None]

    def sane_max_sessions(self):
        '''Return the maximum number of sessions to permit.  Normally this
        is MAX_SESSIONS.  However, to prevent open file exhaustion, ajdust
        downwards if running with a small open file rlimit.'''
        env_value = self.integer('MAX_SESSIONS', 1000)
        # No resource module on Windows
        try:
            import resource
            nofile_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            # We give the DB 250 files; allow ElectrumX 100 for itself
            value = max(0, min(env_value, nofile_limit - 350))
            if value < env_value:
                self.logger.warning('lowered maximum sessions from {:,d} to {:,d} '
                                    'because your open file limit is {:,d}'
                                    .format(env_value, value, nofile_limit))
        except ImportError:
            value = 512  # that is what returned by stdio's _getmaxstdio()
        return value

    def clearnet_identity(self):
        host = self.default('REPORT_HOST', None)
        if host is None:
            return None
        try:
            host = classify_host(host)
        except ValueError:
            bad = True
        else:
            if isinstance(host, (IPv4Address, IPv6Address)):
                bad = (host.is_multicast or host.is_unspecified
                       or (host.is_private and self.peer_announce))
            else:
                bad = host.lower() == 'localhost'
        if bad:
            raise self.Error('"{}" is not a valid REPORT_HOST'.format(host))
        tcp_port = self.integer('REPORT_TCP_PORT', self.tcp_port) or None
        ssl_port = self.integer('REPORT_SSL_PORT', self.ssl_port) or None
        if tcp_port == ssl_port:
            raise self.Error('REPORT_TCP_PORT and REPORT_SSL_PORT '
                             'both resolve to {}'.format(tcp_port))
        return NetIdentity(
            str(host),
            tcp_port,
            ssl_port,
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

        tcp_port = self.integer('REPORT_TCP_PORT_TOR',
                                port('tcp_port')) or None
        ssl_port = self.integer('REPORT_SSL_PORT_TOR',
                                port('ssl_port')) or None
        if tcp_port == ssl_port:
            raise self.Error('REPORT_TCP_PORT_TOR and REPORT_SSL_PORT_TOR '
                             'both resolve to {}'.format(tcp_port))

        return NetIdentity(
            host,
            tcp_port,
            ssl_port,
        )

    def hosts_dict(self):
        return {identity.host: {'tcp_port': identity.tcp_port,
                                'ssl_port': identity.ssl_port}
                for identity in self.identities}

    def peer_discovery_enum(self):
        pd = self.default('PEER_DISCOVERY', 'on').strip().lower()
        if pd in ('off', ''):
            return self.PD_OFF
        elif pd == 'self':
            return self.PD_SELF
        else:
            return self.PD_ON
