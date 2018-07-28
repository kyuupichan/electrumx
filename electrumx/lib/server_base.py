# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

import asyncio
import os
import signal
import sys
import time
from functools import partial

from aiorpcx import TaskGroup

from electrumx.lib.util import class_logger


class ServerBase(object):
    '''Base class server implementation.

    Derived classes are expected to:

    - set PYTHON_MIN_VERSION and SUPPRESS_MESSAGES as appropriate
    - implement the serve() coroutine, called from the run() method.
      Upon return the event loop runs until the shutdown signal is received.
    '''

    SUPPRESS_MESSAGES = [
        'Fatal read error on socket transport',
        'Fatal write error on socket transport',
    ]

    PYTHON_MIN_VERSION = (3, 6)

    def __init__(self, env):
        '''Save the environment, perform basic sanity checks, and set the
        event loop policy.
        '''
        # First asyncio operation must be to set the event loop policy
        # as this replaces the event loop
        asyncio.set_event_loop_policy(env.loop_policy)

        self.logger = class_logger(__name__, self.__class__.__name__)
        self.logger.info(f'Python version: {sys.version}')
        self.env = env

        # Sanity checks
        if sys.version_info < self.PYTHON_MIN_VERSION:
            mvs = '.'.join(str(part) for part in self.PYTHON_MIN_VERSION)
            raise RuntimeError('Python version >= {} is required'.format(mvs))

        if os.geteuid() == 0 and not env.allow_root:
            raise RuntimeError('RUNNING AS ROOT IS STRONGLY DISCOURAGED!\n'
                               'You shoud create an unprivileged user account '
                               'and use that.\n'
                               'To continue as root anyway, restart with '
                               'environment variable ALLOW_ROOT non-empty')

    async def serve(self, shutdown_event):
        '''Override to provide the main server functionality.
        Run as a task that will be cancelled to request shutdown.

        Setting the event also shuts down the server.
        '''
        shutdown_event.set()

    def on_exception(self, loop, context):
        '''Suppress spurious messages it appears we cannot control.'''
        message = context.get('message')
        if message in self.SUPPRESS_MESSAGES:
            return
        if 'accept_connection2()' in repr(context.get('task')):
            return
        loop.default_exception_handler(context)

    async def _main(self, loop):
        '''Run the server application:

        - record start time
        - install SIGINT and SIGTERM handlers to trigger shutdown_event
        - set loop's exception handler to suppress unwanted messages
        - run the event loop until serve() completes
        '''
        def on_signal(signame):
            shutdown_event.set()
            self.logger.warning(f'received {signame} signal, '
                                f'initiating shutdown')

        self.start_time = time.time()
        for signame in ('SIGINT', 'SIGTERM'):
            loop.add_signal_handler(getattr(signal, signame),
                                    partial(on_signal, signame))
        loop.set_exception_handler(self.on_exception)

        shutdown_event = asyncio.Event()
        try:
            async with TaskGroup() as group:
                server_task = await group.spawn(self.serve(shutdown_event))
                # Wait for shutdown, log on receipt of the event
                await shutdown_event.wait()
                self.logger.info('shutting down')
                server_task.cancel()
        finally:
            await loop.shutdown_asyncgens()

        # Prevent some silly logs
        await asyncio.sleep(0.001)
        # Finally, work around an apparent asyncio bug that causes log
        # spew on shutdown for partially opened SSL sockets
        try:
            del asyncio.sslproto._SSLProtocolTransport.__del__
        except Exception:
            pass

        self.logger.info('shutdown complete')

    def run(self):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self._main(loop))
        loop.close()
