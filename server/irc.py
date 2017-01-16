# Copyright (c) 2016-2017, Neil Booth
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


class IRC(LoggedClass):

    Peer = namedtuple('Peer', 'ip_addr host ports')

    class DisconnectedError(Exception):
        pass

    def __init__(self, env):
        super().__init__()
        self.env = env

        # If this isn't something a peer or client expects
        # then you won't appear in the client's network dialog box
        irc_address = (env.coin.IRC_SERVER, env.coin.IRC_PORT)
        self.channel = env.coin.IRC_CHANNEL
        self.prefix = env.coin.IRC_PREFIX

        self.clients = []
        self.nick = '{}{}'.format(self.prefix,
                                  env.irc_nick if env.irc_nick else
                                  double_sha256(env.report_host.encode())
                                  [:5].hex())
        self.clients.append(IrcClient(irc_address, self.nick,
                                      env.report_host,
                                      env.report_tcp_port,
                                      env.report_ssl_port))
        if env.report_host_tor:
            self.clients.append(IrcClient(irc_address, self.nick + '_tor',
                                          env.report_host_tor,
                                          env.report_tcp_port_tor,
                                          env.report_ssl_port_tor))

        self.peer_regexp = re.compile('({}[^!]*)!'.format(self.prefix))
        self.peers = {}

    async def start(self):
        '''Start IRC connections if enabled in environment.'''
        try:
            if self.env.irc:
                await self.join()
            else:
                self.logger.info('IRC is disabled')
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(str(e))

    async def join(self):
        import irc.client as irc_client
        from jaraco.stream import buffer

        # see https://pypi.python.org/pypi/irc under DecodingInput
        irc_client.ServerConnection.buffer_class = \
            buffer.LenientDecodingLineBuffer

        # Register handlers for events we're interested in
        reactor = irc_client.Reactor()
        for event in 'welcome join quit kick whoreply disconnect'.split():
            reactor.add_global_handler(event, getattr(self, 'on_' + event))

        # Note: Multiple nicks in same channel will trigger duplicate events
        for client in self.clients:
            client.connection = reactor.server()

        while True:
            try:
                for client in self.clients:
                    self.logger.info('Joining IRC in {} as "{}" with '
                                     'real name "{}"'
                                     .format(self.channel, client.nick,
                                             client.realname))
                    client.connect()
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
        # /who the channel when we join.  We used to /who on each
        # namreply event, but the IRC server would frequently kick us
        # for flooding.  This requests only once including the tor case.
        if event.source.startswith(self.nick + '!'):
            connection.who(self.channel)
        else:
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

    def on_whoreply(self, connection, event):
        '''Called when a response to our who requests arrives.

        The nick is the 4th argument, and real name is in the 6th
        argument preceeded by '0 ' for some reason.
        '''
        try:
            nick = event.arguments[4]
            if nick.startswith(self.prefix):
                line = event.arguments[6].split()
                try:
                    ip_addr = socket.gethostbyname(line[1])
                except socket.error:
                    # Could be .onion or IPv6.
                    ip_addr = line[1]
                peer = self.Peer(ip_addr, line[1], line[2:])
                self.peers[nick] = peer
        except (IndexError, UnicodeError):
            # UnicodeError comes from invalid domains (issue #68)
            pass


class IrcClient(LoggedClass):

    VERSION = '1.0'
    DEFAULT_PORTS = {'t': 50001, 's': 50002}

    def __init__(self, irc_address, nick, host, tcp_port, ssl_port):
        super().__init__()
        self.irc_host, self.irc_port = irc_address
        self.nick = nick
        self.realname = self.create_realname(host, tcp_port, ssl_port)
        self.connection = None

    def connect(self, keepalive=60):
        '''Connect this client to its IRC server'''
        self.connection.connect(self.irc_host, self.irc_port, self.nick,
                                ircname=self.realname)
        self.connection.set_keepalive(keepalive)

    @classmethod
    def create_realname(cls, host, tcp_port, ssl_port):
        def port_text(letter, port):
            if not port:
                return ''
            if port == cls.DEFAULT_PORTS.get(letter):
                return ' ' + letter
            else:
                return ' ' + letter + str(port)

        tcp = port_text('t', tcp_port)
        ssl = port_text('s', ssl_port)
        return '{} v{}{}{}'.format(host, cls.VERSION, tcp, ssl)
