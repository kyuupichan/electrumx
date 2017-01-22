# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Peer management.'''

import asyncio
import socket
import traceback
from collections import namedtuple
from functools import partial

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

    def __init__(self, env):
        super().__init__()
        self.env = env
        self.loop = asyncio.get_event_loop()
        self.irc = IRC(env, self)
        self.futures = set()
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

    async def executor(self, func, *args, **kwargs):
        '''Run func taking args in the executor.'''
        await self.loop.run_in_executor(None, partial(func, *args, **kwargs))

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

    def ensure_future(self, coro):
        '''Convert a coro into a future and add it to our pending list
        to be waited for.'''
        self.futures.add(asyncio.ensure_future(coro))

    def start_irc(self):
        '''Start up the IRC connections if enabled.'''
        if self.env.irc:
            name_pairs = [(self.real_name(identity), identity.nick_suffix)
                          for identity in self.identities]
            self.ensure_future(self.irc.start(name_pairs))
        else:
            self.logger.info('IRC is disabled')

    async def main_loop(self):
        '''Start and then enter the main loop.'''
        self.start_irc()

        try:
            while True:
                await asyncio.sleep(10)
                done = [future for future in self.futures if future.done()]
                self.futures.difference_update(done)
                for future in done:
                    try:
                        future.result()
                    except:
                        self.log_error(traceback.format_exc())
        finally:
            for future in self.futures:
                future.cancel()

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
        self.ensure_future(self.executor(self.dns_lookup_peer, *args))

    def remove_irc_peer(self, nick):
        '''Remove a peer from our IRC peers map.'''
        self.logger.info('removing IRC peer {}'.format(nick))
        self.irc_peers.pop(nick, None)

    def count(self):
        return len(self.irc_peers)

    def peer_list(self):
        return self.irc_peers

    async def subscribe(self):
        '''Returns the server peers as a list of (ip, host, details) tuples.

        Despite the name this is not currently treated as a subscription.'''
        return list(self.irc_peers.values())
