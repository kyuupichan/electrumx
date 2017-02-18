# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

'''Representation of a peer server.'''

import re
from ipaddress import ip_address

from lib.util import cachedproperty


class Peer(object):

    # Protocol version
    VERSION_REGEX = re.compile('[0-9]+(\.[0-9]+)?$')
    ATTRS = ('host', 'features',
             # metadata
             'source', 'ip_addr', 'good_ports',
             'last_connect', 'last_try', 'try_count')
    PORTS = ('ssl_port', 'tcp_port')
    FEATURES = PORTS + ('pruning', 'server_version',
                        'protocol_min', 'protocol_max')
    # This should be set by the application
    DEFAULT_PORTS = {}

    def __init__(self, host, features, source='unknown', ip_addr=None,
                 good_ports=[], last_connect=0, last_try=0, try_count=0):
        '''Create a peer given a host name (or IP address as a string),
        a dictionary of features, and a record of the source.'''
        assert isinstance(host, str)
        assert isinstance(features, dict)
        self.host = host
        self.features = features.copy()
        # Canonicalize / clean-up
        for feature in self.FEATURES:
            self.features[feature] = getattr(self, feature)
        # Metadata
        self.source = source
        self.ip_addr = ip_addr
        self.good_ports = good_ports.copy()
        self.last_connect = last_connect
        self.last_try = last_try
        self.try_count = try_count
        # Transient, non-persisted metadata
        self.bad = False
        self.other_port_pairs = set()

    @classmethod
    def peers_from_features(cls, features, source):
        peers = []
        if isinstance(features, dict):
            hosts = features.get('hosts')
            if isinstance(hosts, dict):
                peers = [Peer(host, features, source=source)
                         for host in hosts if isinstance(host, str)]
        return peers

    @classmethod
    def deserialize(cls, item):
        '''Deserialize from a dictionary.'''
        return cls(**item)

    @classmethod
    def version_tuple(cls, vstr):
        '''Convert a version string, such as "1.2", to a (major_version,
        minor_version) pair.
        '''
        if isinstance(vstr, str) and VERSION_REGEX.match(vstr):
            if '.' not in vstr:
                vstr += '.0'
        else:
            vstr = '1.0'
        return tuple(int(part) for part in vstr.split('.'))

    def matches(self, peers):
        '''Return peers whose host matches the given peer's host or IP
        address.  This results in our favouring host names over IP
        addresses.
        '''
        candidates = (self.host.lower(), self.ip_addr)
        return [peer for peer in peers if peer.host.lower() in candidates]

    def __str__(self):
        return self.host

    def update_features(self, features):
        '''Update features in-place.'''
        tmp = Peer(self.host, features)
        self.features = tmp.features
        for feature in self.FEATURES:
            setattr(self, feature, getattr(tmp, feature))

    def connection_port_pairs(self):
        '''Return a list of (kind, port) pairs to try when making a
        connection.'''
        # Use a list not a set - it's important to try the registered
        # ports first.
        pairs = [('SSL', self.ssl_port), ('TCP', self.tcp_port)]
        while self.other_port_pairs:
            pairs.append(other_port_pairs.pop())
        return [pair for pair in pairs if pair[1]]

    def mark_bad(self):
        '''Mark as bad to avoid reconnects but also to remember for a
        while.'''
        self.bad = True

    def check_ports(self, other):
        '''Remember differing ports in case server operator changed them
        or removed one.'''
        if other.ssl_port != self.ssl_port:
            self.other_port_pairs.add(('SSL', other.ssl_port))
        if other.tcp_port != self.tcp_port:
            self.other_port_pairs.add(('TCP', other.tcp_port))
        return bool(self.other_port_pairs)

    @cachedproperty
    def is_tor(self):
        return self.host.endswith('.onion')

    @cachedproperty
    def is_valid(self):
        ip = self.ip_address
        if not ip:
            return True
        return not ip.is_multicast and (ip.is_global or ip.is_private)

    @cachedproperty
    def is_public(self):
        ip = self.ip_address
        return self.is_valid and not (ip and ip.is_private)

    @cachedproperty
    def ip_address(self):
        '''The host as a python ip_address object, or None.'''
        try:
            return ip_address(self.host)
        except ValueError:
            return None

    def bucket(self):
        if self.is_tor:
            return 'onion'
        if not self.ip_addr:
            return ''
        return tuple(self.ip_addr.split('.')[:2])

    def serialize(self):
        '''Serialize to a dictionary.'''
        return {attr: getattr(self, attr) for attr in self.ATTRS}

    def _port(self, key):
        hosts = self.features.get('hosts')
        if isinstance(hosts, dict):
            host = hosts.get(self.host)
            port = self._integer(key, host)
            if port and 0 < port < 65536:
                return port
        return None

    def _integer(self, key, d=None):
        d = d or self.features
        result = d.get(key) if isinstance(d, dict) else None
        if isinstance(result, str):
            try:
                result = int(result)
            except ValueError:
                pass
        return result if isinstance(result, int) else None

    def _string(self, key):
        result = self.features.get(key)
        return result if isinstance(result, str) else None

    def _version_string(self, key):
        version = self.features.get(key)
        return '{:d}.{:d}'.format(*self.version_tuple(version))

    @cachedproperty
    def genesis_hash(self):
        '''Returns None if no SSL port, otherwise the port as an integer.'''
        return self._string('genesis_hash')

    @cachedproperty
    def ssl_port(self):
        '''Returns None if no SSL port, otherwise the port as an integer.'''
        return self._port('ssl_port')

    @cachedproperty
    def tcp_port(self):
        '''Returns None if no TCP port, otherwise the port as an integer.'''
        return self._port('tcp_port')

    @cachedproperty
    def server_version(self):
        '''Returns the server version as a string if known, otherwise None.'''
        return self._string('server_version')

    @cachedproperty
    def pruning(self):
        '''Returns the pruning level as an integer.  None indicates no
        pruning.'''
        pruning = self._integer('pruning')
        if pruning and pruning > 0:
            return pruning
        return None

    @cachedproperty
    def protocol_min(self):
        '''Minimum protocol version as a string, e.g., 1.0'''
        return self._version_string('protcol_min')

    @cachedproperty
    def protocol_max(self):
        '''Maximum protocol version as a string, e.g., 1.1'''
        return self._version_string('protcol_max')

    def to_tuple(self):
        '''The tuple ((ip, host, details) expected in response
        to a peers subscription.'''
        details = self.real_name().split()[1:]
        return (self.ip_addr or self.host, self.host, details)

    def real_name(self, host_override=None):
        '''Real name of this peer as used on IRC.'''
        def port_text(letter, port):
            if port == self.DEFAULT_PORTS.get(letter):
                return letter
            else:
                return letter + str(port)

        parts = [host_override or self.host, 'v' + self.protocol_max]
        if self.pruning:
            parts.append('p{:d}'.format(self.pruning))
        for letter, port in (('s', self.ssl_port), ('t', self.tcp_port)):
            if port:
                parts.append(port_text(letter, port))
        return ' '.join(parts)

    @classmethod
    def from_real_name(cls, real_name, source):
        '''Real name is a real name as on IRC, such as

            "erbium1.sytes.net v1.0 s t"

        Returns an instance of this Peer class.
        '''
        host = 'nohost'
        features = {}
        ports = {}
        for n, part in enumerate(real_name.split()):
            if n == 0:
                host = part
                continue
            if part[0] in ('s', 't'):
                if len(part) == 1:
                    port = cls.DEFAULT_PORTS[part[0]]
                else:
                    port = part[1:]
                if part[0] == 's':
                    ports['ssl_port'] = port
                else:
                    ports['tcp_port'] = port
            elif part[0] == 'v':
                features['protocol_max'] = features['protocol_min'] = part[1:]
            elif part[0] == 'p':
                features['pruning'] = part[1:]

        features.update(ports)
        features['hosts'] = {host: ports}

        return cls(host, features, source)
