# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Base class of servers'''

import asyncio
import os
import platform
import re
import signal
import sys
import time
from contextlib import suppress
from functools import partial

from aiorpcx import spawn

from electrumx.lib.util import class_logger


class ServerBase:
    '''Base class server implementation.

    Derived classes are expected to:

    - set PYTHON_MIN_VERSION and SUPPRESS_MESSAGE_REGEX as appropriate
    - implement the serve() coroutine, called from the run() method.
      Upon return the event loop runs until the shutdown signal is received.
    '''
    SUPPRESS_MESSAGE_REGEX = re.compile('SSL handshake|Fatal read error on|'
                                        'SSL error in data received|'
                                        'socket.send() raised exception')
    SUPPRESS_TASK_REGEX = re.compile('accept_connection2')
    PYTHON_MIN_VERSION = (3, 6)

    def __init__(self, env):
        '''Save the environment, perform basic sanity checks, and set the
        event loop policy.
        '''
        # First asyncio operation must be to set the event loop policy
        # as this replaces the event loop
        asyncio.set_event_loop_policy(env.loop_policy)

        self.logger = class_logger(__name__, self.__class__.__name__)
        version_str = ' '.join(sys.version.splitlines())
        self.logger.info(f'Python version: {version_str}')
        self.env = env
        self.start_time = 0

        # Sanity checks
        if sys.version_info < self.PYTHON_MIN_VERSION:
            mvs = '.'.join(str(part) for part in self.PYTHON_MIN_VERSION)
            raise RuntimeError('Python version >= {} is required'.format(mvs))

        if platform.system() == 'Windows':
            pass
        elif os.geteuid() == 0 and not env.allow_root:
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
        if message and self.SUPPRESS_MESSAGE_REGEX.match(message):
            return
        if self.SUPPRESS_TASK_REGEX.match(repr(context.get('task'))):
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
            self.logger.warning(f'received {signame} signal, initiating shutdown')

        self.start_time = time.time()
        if platform.system() != 'Windows':
            # No signals on Windows
            for signame in ('SIGINT', 'SIGTERM'):
                loop.add_signal_handler(getattr(signal, signame),
                                        partial(on_signal, signame))
        loop.set_exception_handler(self.on_exception)

        shutdown_event = asyncio.Event()
        server_task = await spawn(self.serve(shutdown_event))

        # Wait for shutdown, log on receipt of the event
        try:
            await shutdown_event.wait()
        except KeyboardInterrupt:
            self.logger.warning(f'received keyboard interrupt, initiating shutdown')
        finally:
            self.logger.info('shutting down')

            server_task.cancel()
            with suppress(Exception):
                await server_task
            self.logger.info('shutdown complete')

    def run(self):
        '''Start the event loop.'''
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(self._main(loop))
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
