# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.
"""
IRC connectivity to discover peers.
Only calling start() requires the IRC Python module.
"""

import asyncio
import re

from lib.hash import double_sha256
from lib.util import LoggedClass


class IRC(LoggedClass):
    class DisconnectedError(Exception):
        pass

    def __init__(self, env, peer_mgr):
        super().__init__()
        self.coin = env.coin
        self.peer_mgr = peer_mgr

        # If this isn't something a peer or client expects
        # then you won't appear in the client's network dialog box
        self.channel = env.coin.IRC_CHANNEL
        self.prefix = env.coin.IRC_PREFIX
        self.nick = '{}{}'.format(self.prefix,
                                  env.irc_nick if env.irc_nick else
                                  double_sha256(env.host.encode())
                                  [:5].hex())
        self.peer_regexp = re.compile('({}[^!]*)!'.format(self.prefix))

    async def start(self, name_pairs):
        """Start IRC connections if enabled in environment."""
        import irc.client as irc_client
        from jaraco.stream import buffer

        # see https://pypi.python.org/pypi/irc under DecodingInput
        irc_client.ServerConnection.buffer_class = \
            buffer.LenientDecodingLineBuffer

        # Register handlers for events we're interested in
        reactor = irc_client.Reactor()
        for event in 'welcome join whoreply disconnect'.split():
            reactor.add_global_handler(event, getattr(self, 'on_' + event))

        # Note: Multiple nicks in same channel will trigger duplicate events
        clients = [IrcClient(self.coin, real_name, self.nick + suffix,
                             reactor.server())
                   for (real_name, suffix) in name_pairs]

        while True:
            try:
                for client in clients:
                    client.connect(self)
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
        """Called when we connect to irc server."""
        connection.join(self.channel)

    def on_disconnect(self, connection, event):
        """Called if we are disconnected."""
        self.log_event(event)
        raise self.DisconnectedError

    def on_join(self, connection, event):
        """Called when someone new connects to our channel, including us."""
        # /who the channel when we join.  We used to /who on each
        # namreply event, but the IRC server would frequently kick us
        # for flooding.  This requests only once including the tor case.
        if event.source.startswith(self.nick + '!'):
            connection.who(self.channel)
        else:
            match = self.peer_regexp.match(event.source)
            if match:
                connection.who(match.group(1))

    def on_whoreply(self, connection, event):
        """Called when a response to our who requests arrives.

        The nick is the 4th argument, and real name is in the 6th
        argument preceeded by '0 ' for some reason.
        """
        nick = event.arguments[4]
        if nick.startswith(self.prefix):
            line = event.arguments[6].split()
            hp_string = ' '.join(line[1:])  # hostname, ports, version etc.
            self.peer_mgr.add_irc_peer(nick, hp_string)


class IrcClient(object):
    def __init__(self, coin, real_name, nick, server):
        self.irc_host = coin.IRC_SERVER
        self.irc_port = coin.IRC_PORT
        self.nick = nick
        self.real_name = real_name
        self.server = server

    def connect(self, irc):
        """Connect this client to its IRC server"""
        irc.logger.info('joining {} as "{}" with real name "{}"'
                        .format(irc.channel, self.nick, self.real_name))
        self.server.connect(self.irc_host, self.irc_port, self.nick,
                            ircname=self.real_name)
