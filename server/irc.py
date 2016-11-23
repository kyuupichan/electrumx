# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''IRC connectivity to discover peers.

Only calling start() requires the IRC Python module.
'''

import asyncio
import re
import socket

from collections import namedtuple

from lib.hash import double_sha256
from lib.util import LoggedClass


def port_text(letter, port, default):
    if not port:
        return ''
    if port == default:
        return letter
    return letter + str(port)


class IRC(LoggedClass):

    Peer = namedtuple('Peer', 'ip_addr host ports')

    class DisconnectedError(Exception):
        pass

    def __init__(self, env):
        super().__init__()
        tcp_text = port_text('t', env.report_tcp_port, 50001)
        ssl_text = port_text('s', env.report_ssl_port, 50002)
        # If this isn't something the client expects you won't appear
        # in the client's network dialog box
        version = '1.0'
        self.real_name = '{} v{} {} {}'.format(env.report_host, version,
                                               tcp_text, ssl_text)
        self.prefix = env.coin.IRC_PREFIX
        self.nick = '{}{}'.format(self.prefix,
                                  env.irc_nick if env.irc_nick else
                                  double_sha256(env.report_host.encode())
                                  [:5].hex())
        self.channel = env.coin.IRC_CHANNEL
        self.irc_server = env.coin.IRC_SERVER
        self.irc_port = env.coin.IRC_PORT
        self.peer_regexp = re.compile('({}[^!]*)!'.format(self.prefix))
        self.peers = {}
        self.disabled = env.irc is None

    async def start(self, caught_up):
        '''Start IRC connections once caught up if enabled in environment.'''
        await caught_up.wait()
        try:
            if self.disabled:
                self.logger.info('IRC is disabled')
            else:
                await self.join()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(str(e))

    async def join(self):
        import irc.client as irc_client

        self.logger.info('joining IRC with nick "{}" and real name "{}"'
                         .format(self.nick, self.real_name))

        reactor = irc_client.Reactor()
        for event in ['welcome', 'join', 'quit', 'kick', 'whoreply',
                      'namreply', 'disconnect']:
            reactor.add_global_handler(event, getattr(self, 'on_' + event))

        while True:
            try:
                connection = reactor.server()
                connection.connect(self.irc_server, self.irc_port,
                                   self.nick, ircname=self.real_name)
                connection.set_keepalive(60)
                while True:
                    reactor.process_once()
                    await asyncio.sleep(2)
            except irc_client.ServerConnectionError as e:
                self.logger.error('connection error: {}'.format(e))
            except self.DisconnectedError:
                self.logger.error('disconnected')
            await asyncio.sleep(10)

    def log_event(self, event):
        self.logger.info('IRC event type {} source {}  args {}'
                         .format(event.type, event.source, event.arguments))

    def on_welcome(self, connection, event):
        '''Called when we connect to irc server.'''
        connection.join(self.channel)

    def on_disconnect(self, connection, event):
        '''Called if we are disconnected.'''
        self.log_event(event)
        raise self.DisconnectedError

    def on_join(self, connection, event):
        '''Called when someone new connects to our channel, including us.'''
        match = self.peer_regexp.match(event.source)
        if match:
            connection.who(match.group(1))

    def on_quit(self, connection, event):
        '''Called when someone leaves our channel.'''
        match = self.peer_regexp.match(event.source)
        if match:
            self.peers.pop(match.group(1), None)

    def on_kick(self, connection, event):
        '''Called when someone is kicked from our channel.'''
        self.log_event(event)
        match = self.peer_regexp.match(event.arguments[0])
        if match:
            self.peers.pop(match.group(1), None)

    def on_namreply(self, connection, event):
        '''Called repeatedly when we first connect to inform us of all users
        in the channel.

        The users are space-separated in the 2nd argument.
        '''
        for peer in event.arguments[2].split():
            if peer.startswith(self.prefix):
                connection.who(peer)

    def on_whoreply(self, connection, event):
        '''Called when a response to our who requests arrives.

        The nick is the 4th argument, and real name is in the 6th
        argument preceeded by '0 ' for some reason.
        '''
        try:
            nick = event.arguments[4]
            line = event.arguments[6].split()
            try:
                ip_addr = socket.gethostbyname(line[1])
            except socket.error:
                # No IPv4 address could be resolved. Could be .onion or IPv6.
                ip_addr = line[1]
            peer = self.Peer(ip_addr, line[1], line[2:])
            self.peers[nick] = peer
        except IndexError:
            pass
