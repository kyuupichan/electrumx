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
import signal
import ssl
import traceback
from functools import partial

from server.daemon import Daemon
from server.block_processor import BlockProcessor
from server.protocol import ElectrumX, LocalRPC, JSONRPC
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
        self.daemon = Daemon(env.daemon_url)
        self.block_processor = BlockProcessor(env, self.daemon,
                                              on_update=self.on_update)
        JSONRPC.init(self.block_processor, self.daemon, self.coin,
                     self.add_job)
        self.servers = []
        self.jobs = asyncio.Queue()

    def start(self):
        '''Prime the event loop with asynchronous jobs.'''
        coros = self.block_processor.coros()
        coros.append(self.run_jobs())

        for coro in coros:
            asyncio.ensure_future(coro)

        # Signal handlers
        for signame in ('SIGINT', 'SIGTERM'):
            self.loop.add_signal_handler(getattr(signal, signame),
                                         partial(self.on_signal, signame))

    async def on_update(self, height, touched):
        if not self.servers:
            self.servers = await self.start_servers()
        ElectrumX.notify(height, touched)

    async def start_servers(self):
        '''Start listening on RPC, TCP and SSL ports.

        Does not start a server if the port wasn't specified.  Does
        nothing if servers are already running.
        '''
        servers = []
        env = self.env
        loop = self.loop

        protocol = LocalRPC
        if env.rpc_port is not None:
            host = 'localhost'
            rpc_server = loop.create_server(protocol, host, env.rpc_port)
            servers.append(await rpc_server)
            self.logger.info('RPC server listening on {}:{:d}'
                             .format(host, env.rpc_port))

        protocol = partial(ElectrumX, env)
        if env.tcp_port is not None:
            tcp_server = loop.create_server(protocol, env.host, env.tcp_port)
            servers.append(await tcp_server)
            self.logger.info('TCP server listening on {}:{:d}'
                             .format(env.host, env.tcp_port))

        if env.ssl_port is not None:
            # FIXME: update if we want to require Python >= 3.5.3
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            ssl_context.load_cert_chain(env.ssl_certfile,
                                        keyfile=env.ssl_keyfile)
            ssl_server = loop.create_server(protocol, env.host, env.ssl_port,
                                            ssl=ssl_context)
            servers.append(await ssl_server)
            self.logger.info('SSL server listening on {}:{:d}'
                             .format(env.host, env.ssl_port))

        return servers

    def stop(self):
        '''Close the listening servers.'''
        for server in self.servers:
            server.close()

    def on_signal(self, signame):
        '''Call on receipt of a signal to cleanly shutdown.'''
        self.logger.warning('received {} signal, preparing to shut down'
                            .format(signame))
        for task in asyncio.Task.all_tasks(self.loop):
            task.cancel()

    def add_job(self, coro):
        '''Queue a job for asynchronous processing.'''
        self.jobs.put_nowait(coro)

    async def run_jobs(self):
        '''Asynchronously run through the job queue.'''
        while True:
            job = await self.jobs.get()
            try:
                await job
            except asyncio.CancelledError:
                raise
            except Exception:
                # Getting here should probably be considered a bug and fixed
                traceback.print_exc()
