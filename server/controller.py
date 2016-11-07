# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Server controller.

Coordinates the parts of the server.  Serves as a cache for
client-serving data such as histories.
'''

import asyncio

from server.daemon import Daemon
from server.block_processor import BlockServer
from lib.util import LoggedClass


class Controller(LoggedClass):

    def __init__(self, loop, env):
        '''Create up the controller.

        Creates DB, Daemon and BlockProcessor instances.
        '''
        super().__init__()
        self.loop = loop
        self.env = env
        self.coin = env.coin
        self.daemon = Daemon(env.daemon_url, env.debug)
        self.block_processor = BlockServer(env, self.daemon)

    def start(self):
        '''Prime the event loop with asynchronous jobs.'''
        coros = self.block_processor.coros()

        for coro in coros:
            asyncio.ensure_future(coro)

    def stop(self):
        '''Close the listening servers.'''
        self.block_processor.stop()
