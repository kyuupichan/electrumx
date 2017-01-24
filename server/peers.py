# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Peer management.'''

import socket
from collections import namedtuple

import lib.util as util
from server.irc import IRC


NetIdentity = namedtuple('NetIdentity', 'host tcp_port ssl_port nick_suffix')
IRCPeer = namedtuple('IRCPeer', 'ip_addr host details')


class PeerManager(util.LoggedClass):
    '''Looks after the DB of peer network servers.

    Attempts to maintain a connection with up to 8 peers.
    Issues a 'peers.subscribe' RPC to them and tells them our data.
    '''
    VERSION = '1.0'
    DEFAULT_PORTS = {'t': 50001, 's': 50002}

    def __init__(self, env, controller):
        super().__init__()
        self.env = env
        self.controller = controller
        self.irc = IRC(env, self)
        self.identities = []
        # Keyed by nick
        self.irc_peers = {}

        # We can have a Tor identity inaddition to a normal one
        self.identities.append(NetIdentity(env.report_host,
                                           env.report_tcp_port,
                                           env.report_ssl_port,
                                           ''))
        if env.report_host_tor.endswith('.onion'):
            self.identities.append(NetIdentity(env.report_host_tor,
                                               env.report_tcp_port_tor,
                                               env.report_ssl_port_tor,
                                               '_tor'))

    @classmethod
    def real_name(cls, identity):
        '''Real name as used on IRC.'''
        def port_text(letter, port):
            if not port:
                return ''
            if port == cls.DEFAULT_PORTS.get(letter):
                return ' ' + letter
            else:
                return ' ' + letter + str(port)

        tcp = port_text('t', identity.tcp_port)
        ssl = port_text('s', identity.ssl_port)
        return '{} v{}{}{}'.format(identity.host, cls.VERSION, tcp, ssl)

    def start_irc(self):
        '''Start up the IRC connections if enabled.'''
        if self.env.irc:
            name_pairs = [(self.real_name(identity), identity.nick_suffix)
                          for identity in self.identities]
            self.controller.ensure_future(self.irc.start(name_pairs))
        else:
            self.logger.info('IRC is disabled')

    async def main_loop(self):
        '''Main loop.  No loop for now.'''
        self.start_irc()

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

    def peer_list(self):
        return self.irc_peers

    def subscribe(self):
        '''Returns the server peers as a list of (ip, host, details) tuples.

        Despite the name this is not currently treated as a subscription.'''
        return list(self.irc_peers.values())
