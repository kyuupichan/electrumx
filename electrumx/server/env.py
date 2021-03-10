# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Class for handling environment configuration and defaults.'''


import re
from ipaddress import IPv4Address, IPv6Address

from aiorpcx import Service, ServicePart
from electrumx.lib.coins import Coin
from electrumx.lib.env_base import EnvBase


class ServiceError(Exception):
    pass


class Env(EnvBase):
    '''Wraps environment configuration. Optionally, accepts a Coin class
       as first argument to have ElectrumX serve custom coins not part of
       the standard distribution.
    '''

    # Peer discovery
    PD_OFF, PD_SELF, PD_ON = ('OFF', 'SELF', 'ON')
    SSL_PROTOCOLS = {'ssl', 'wss'}
    KNOWN_PROTOCOLS = {'ssl', 'tcp', 'ws', 'wss', 'rpc'}

    def __init__(self, coin=None):
        super().__init__()
        self.obsolete(["MAX_SUBSCRIPTIONS", "MAX_SUBS", "MAX_SESSION_SUBS", "BANDWIDTH_LIMIT",
                       "HOST", "TCP_PORT", "SSL_PORT", "RPC_HOST", "RPC_PORT", "REPORT_HOST",
                       "REPORT_TCP_PORT", "REPORT_SSL_PORT", "REPORT_HOST_TOR",
                       "REPORT_TCP_PORT_TOR", "REPORT_SSL_PORT_TOR"])

        # Core items

        self.db_dir = self.required('DB_DIRECTORY')
        self.daemon_url = self.required('DAEMON_URL')
        if coin is not None:
            assert issubclass(coin, Coin)
            self.coin = coin
        else:
            coin_name = self.required('COIN').strip()
            network = self.default('NET', 'mainnet').strip()
            self.coin = Coin.lookup_coin_class(coin_name, network)

        # Peer discovery

        self.peer_discovery = self.peer_discovery_enum()
        self.peer_announce = self.boolean('PEER_ANNOUNCE', True)
        self.force_proxy = self.boolean('FORCE_PROXY', False)
        self.tor_proxy_host = self.default('TOR_PROXY_HOST', 'localhost')
        self.tor_proxy_port = self.integer('TOR_PROXY_PORT', None)

        # Misc

        self.db_engine = self.default('DB_ENGINE', 'leveldb')
        self.banner_file = self.default('BANNER_FILE', None)
        self.tor_banner_file = self.default('TOR_BANNER_FILE',
                                            self.banner_file)
        self.anon_logs = self.boolean('ANON_LOGS', False)
        self.log_sessions = self.integer('LOG_SESSIONS', 3600)
        self.log_level = self.default('LOG_LEVEL', 'info').upper()
        self.donation_address = self.default('DONATION_ADDRESS', '')
        self.drop_client = self.custom("DROP_CLIENT", None, re.compile)
        self.blacklist_url = self.default('BLACKLIST_URL', self.coin.BLACKLIST_URL)
        self.cache_MB = self.integer('CACHE_MB', 1200)
        self.reorg_limit = self.integer('REORG_LIMIT', self.coin.REORG_LIMIT)

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

        # Services last - uses some env vars above

        self.services = self.services_to_run()
        if {service.protocol for service in self.services}.intersection(self.SSL_PROTOCOLS):
            self.ssl_certfile = self.required('SSL_CERTFILE')
            self.ssl_keyfile = self.required('SSL_KEYFILE')
        self.report_services = self.services_to_report()

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

    def _parse_services(self, services_str, default_func):
        result = []
        for service_str in services_str.split(','):
            if not service_str:
                continue
            try:
                service = Service.from_string(service_str, default_func=default_func)
            except Exception as e:
                raise ServiceError(f'"{service_str}" invalid: {e}') from None
            if service.protocol not in self.KNOWN_PROTOCOLS:
                raise ServiceError(f'"{service_str}" invalid: unknown protocol')
            result.append(service)

        # Find duplicate addresses
        service_map = {service.address: [] for service in result}
        for service in result:
            service_map[service.address].append(service)
        for address, services in service_map.items():
            if len(services) > 1:
                raise ServiceError(f'address {address} has multiple services')

        return result

    def services_to_run(self):
        def default_part(protocol, part):
            return default_services.get(protocol, {}).get(part)

        default_services = {protocol: {ServicePart.HOST: 'all_interfaces'}
                            for protocol in self.KNOWN_PROTOCOLS}
        default_services['rpc'] = {ServicePart.HOST: 'localhost', ServicePart.PORT: 8000}
        services = self._parse_services(self.default('SERVICES', ''), default_part)

        # Find onion hosts
        for service in services:
            if str(service.host).endswith('.onion'):
                raise ServiceError(f'bad host for SERVICES: {service}')

        return services

    def services_to_report(self):
        services = self._parse_services(self.default('REPORT_SERVICES', ''), None)

        for service in services:
            if service.protocol == 'rpc':
                raise ServiceError(f'bad protocol for REPORT_SERVICES: {service.protocol}')
            if isinstance(service.host, (IPv4Address, IPv6Address)):
                ip_addr = service.host
                if (ip_addr.is_multicast or ip_addr.is_unspecified or
                        (ip_addr.is_private and self.peer_announce)):
                    raise ServiceError(f'bad IP address for REPORT_SERVICES: {ip_addr}')
            elif service.host.lower() == 'localhost':
                raise ServiceError(f'bad host for REPORT_SERVICES: {service.host}')

        return services

    def peer_discovery_enum(self):
        pd = self.default('PEER_DISCOVERY', 'on').strip().lower()
        if pd in ('off', ''):
            return self.PD_OFF
        elif pd == 'self':
            return self.PD_SELF
        else:
            return self.PD_ON
