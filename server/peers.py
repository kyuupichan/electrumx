# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Peer management.'''

import asyncio
import socket
from collections import namedtuple

import lib.util as util
from server.irc import IRC


IRCPeer = namedtuple('IRCPeer', 'ip_addr host details')


class PeerManager(util.LoggedClass):
    '''Looks after the DB of peer network servers.

    Attempts to maintain a connection with up to 8 peers.
    Issues a 'peers.subscribe' RPC to them and tells them our data.
    '''
    PROTOCOL_VERSION = '1.0'

    def __init__(self, env, controller):
        super().__init__()
        self.env = env
        self.controller = controller
        if self.env.irc:
            self.irc = IRC(env, self)
        self.pruning = None
        self._identities = []
        # Keyed by nick
        self.irc_peers = {}
        self._identities.append(env.identity)
        if env.tor_identity.host.endswith('.onion'):
            self._identities.append(env.tor_identity)

    def real_name(self, host, protocol_version, tcp_port, ssl_port):
        '''Real name as used on IRC.'''
        default_ports = self.env.coin.PEER_DEFAULT_PORTS

        def port_text(letter, port):
            if port == default_ports.get(letter):
                return letter
            else:
                return letter + str(port)

        parts = [host, 'v' + protocol_version]
        for letter, port in (('s', ssl_port), ('t', tcp_port)):
            if port:
                parts.append(port_text(letter, port))
        return ' '.join(parts)

    def irc_name_pairs(self):
        return [(self.real_name(identity.host, self.PROTOCOL_VERSION,
                                identity.tcp_port, identity.ssl_port),
                 identity.nick_suffix)
                for identity in self._identities]

    def identities(self):
        '''Return a list of network identities of this server.'''
        return self._identities

    def ensure_future(self, coro, callback=None):
        '''Schedule the coro to be run.'''
        return self.controller.ensure_future(coro, callback=callback)

    async def main_loop(self):
        '''Not a loop for now...'''
        if self.irc:
            self.ensure_future(self.irc.start(self.irc_name_pairs()))
        else:
            self.logger.info('IRC is disabled')

    def dns_lookup_peer(self, nick, hostname, details):
        try:
            ip_addr = None
            try:
                ip_addr = socket.gethostbyname(hostname)
            except socket.error:
                pass  # IPv6?
            ip_addr = ip_addr or hostname
            self.irc_peers[nick] = IRCPeer(ip_addr, hostname, details)
            self.logger.info('new IRC peer {} at {} ({})'
                             .format(nick, hostname, details))
        except UnicodeError:
            # UnicodeError comes from invalid domains (issue #68)
            self.logger.info('IRC peer domain {} invalid'.format(hostname))

    def add_irc_peer(self, *args):
        '''Schedule DNS lookup of peer.'''
        self.controller.schedule_executor(self.dns_lookup_peer, *args)

    def remove_irc_peer(self, nick):
        '''Remove a peer from our IRC peers map.'''
        self.logger.info('removing IRC peer {}'.format(nick))
        self.irc_peers.pop(nick, None)

    def count(self):
        return len(self.irc_peers)

    def rpc_data(self):
        return self.irc_peers

    def on_peers_subscribe(self):
        '''Returns the server peers as a list of (ip, host, details) tuples.'''
        return list(self.irc_peers.values())
