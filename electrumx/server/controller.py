# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

from aiorpcx import _version as aiorpcx_version

import electrumx
from electrumx.lib.server_base import ServerBase
from electrumx.lib.util import version_string
from electrumx.server.chain_state import ChainState
from electrumx.server.peers import PeerManager
from electrumx.server.session import SessionManager


class Controller(ServerBase):
    '''Manages server initialisation and stutdown.

    Servers are started once the mempool is synced after the block
    processor first catches up with the daemon.
    '''

    AIORPCX_MIN = (0, 5, 6)

    def __init__(self, env):
        '''Initialize everything that doesn't require the event loop.'''
        super().__init__(env)

        if aiorpcx_version < self.AIORPCX_MIN:
            raise RuntimeError('ElectrumX requires aiorpcX >= '
                               f'{version_string(self.AIORPCX_MIN)}')

        min_str, max_str = env.coin.SESSIONCLS.protocol_min_max_strings()
        self.logger.info(f'software version: {electrumx.version}')
        self.logger.info(f'aiorpcX version: {version_string(aiorpcx_version)}')
        self.logger.info(f'supported protocol versions: {min_str}-{max_str}')
        self.logger.info(f'event loop policy: {env.loop_policy}')

        self.chain_state = ChainState(env, self.tasks)
        self.peer_mgr = PeerManager(env, self.tasks, self.chain_state)
        self.session_mgr = SessionManager(env, self.tasks, self.chain_state,
                                          self.peer_mgr, self.shutdown_event)

    async def start_servers(self):
        '''Start the RPC server and wait for the mempool to synchronize.  Then
        start the peer manager and serving external clients.
        '''
        self.session_mgr.start_rpc_server()
        await self.chain_state.wait_for_mempool()
        self.peer_mgr.start_peer_discovery()
        self.session_mgr.start_serving()

    async def shutdown(self):
        '''Perform the shutdown sequence.'''
        # Close servers and connections - main source of new task creation
        await self.session_mgr.shutdown()
        # Flush chain state to disk
        await self.chain_state.shutdown()
        # Cancel all tasks; this shuts down the peer manager and prefetcher
        await self.tasks.cancel_all(wait=True)
