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

from server.daemon import Daemon, DaemonError
from server.block_processor import BlockProcessor
from server.protocol import ElectrumX, LocalRPC
from lib.hash import (sha256, double_sha256, hash_to_str,
                      Base58, hex_str_to_hash)
from lib.util import LoggedClass


class Controller(LoggedClass):

    def __init__(self, loop, env):
        '''Create up the controller.

        Creates DB, Daemon and BlockProcessor instances.
        '''
        super().__init__()
        self.loop = loop
        self.env = env
        self.daemon = Daemon(env.daemon_url)
        self.block_processor = BlockProcessor(env, self.daemon,
                                              on_catchup=self.start_servers)
        self.servers = []
        self.sessions = set()
        self.addresses = {}
        self.jobs = asyncio.Queue()
        self.peers = {}

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

    async def start_servers(self):
        '''Start listening on RPC, TCP and SSL ports.

        Does not start a server if the port wasn't specified.  Does
        nothing if servers are already running.
        '''
        if self.servers:
            return

        env = self.env
        loop = self.loop

        protocol = partial(LocalRPC, self)
        if env.rpc_port is not None:
            host = 'localhost'
            rpc_server = loop.create_server(protocol, host, env.rpc_port)
            self.servers.append(await rpc_server)
            self.logger.info('RPC server listening on {}:{:d}'
                             .format(host, env.rpc_port))

        protocol = partial(ElectrumX, self, self.daemon, env)
        if env.tcp_port is not None:
            tcp_server = loop.create_server(protocol, env.host, env.tcp_port)
            self.servers.append(await tcp_server)
            self.logger.info('TCP server listening on {}:{:d}'
                             .format(env.host, env.tcp_port))

        if env.ssl_port is not None:
            # FIXME: update if we want to require Python >= 3.5.3
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            ssl_context.load_cert_chain(env.ssl_certfile,
                                        keyfile=env.ssl_keyfile)
            ssl_server = loop.create_server(protocol, env.host, env.ssl_port,
                                            ssl=ssl_context)
            self.servers.append(await ssl_server)
            self.logger.info('SSL server listening on {}:{:d}'
                             .format(env.host, env.ssl_port))

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

    def add_session(self, session):
        '''Add a session representing one incoming connection.'''
        self.sessions.add(session)

    def remove_session(self, session):
        '''Remove a session.'''
        self.sessions.remove(session)

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

    def address_status(self, hash168):
        '''Returns status as 32 bytes.'''
        status = self.addresses.get(hash168)
        if status is None:
            history = self.block_processor.get_history(hash168)
            status = ''.join('{}:{:d}:'.format(hash_to_str(tx_hash), height)
                             for tx_hash, height in history)
            if status:
                status = sha256(status.encode())
            self.addresses[hash168] = status

        return status

    async def get_merkle(self, tx_hash, height):
        '''tx_hash is a hex string.'''
        block_hash = await self.daemon.send_single('getblockhash', (height,))
        block = await self.daemon.send_single('getblock', (block_hash, True))
        tx_hashes = block['tx']
        # This will throw if the tx_hash is bad
        pos = tx_hashes.index(tx_hash)

        idx = pos
        hashes = [hex_str_to_hash(txh) for txh in tx_hashes]
        merkle_branch = []
        while len(hashes) > 1:
            if len(hashes) & 1:
                hashes.append(hashes[-1])
            idx = idx - 1 if (idx & 1) else idx + 1
            merkle_branch.append(hash_to_str(hashes[idx]))
            idx //= 2
            hashes = [double_sha256(hashes[n] + hashes[n + 1])
                      for n in range(0, len(hashes), 2)]

        return {"block_height": height, "merkle": merkle_branch, "pos": pos}

    def get_peers(self):
        '''Returns a dictionary of IRC nick to (ip, host, ports) tuples, one
        per peer.'''
        return self.peers

    def height(self):
        return self.block_processor.height

    def get_current_header(self):
        return self.block_processor.get_current_header()

    def get_history(self, hash168):
        history = self.block_processor.get_history(hash168, limit=None)
        return [
            {'tx_hash': hash_to_str(tx_hash), 'height': height}
            for tx_hash, height in history
        ]
