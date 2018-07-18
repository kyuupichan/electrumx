# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

from aiorpcx import _version as aiorpcx_version

import electrumx
from electrumx.lib.server_base import ServerBase
from electrumx.lib.tasks import Tasks
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

        self.tasks = Tasks()
        self.chain_state = ChainState(env, self.tasks, self.shutdown_event)
        self.peer_mgr = PeerManager(env, self.tasks, self.chain_state)
        self.session_mgr = SessionManager(env, self.tasks, self.chain_state,
                                          self.peer_mgr)

    async def start_servers(self):
        '''Start the RPC server and wait for the mempool to synchronize.  Then
        start the peer manager and serving external clients.
        '''
        await self.session_mgr.start_rpc_server()
        await self.chain_state.wait_for_mempool()
        self.tasks.create_task(self.peer_mgr.main_loop())
        self.tasks.create_task(self.session_mgr.start_serving())
        self.tasks.create_task(self.session_mgr.housekeeping())

    async def shutdown(self):
        '''Perform the shutdown sequence.'''
        # Not certain of ordering here
        self.tasks.cancel_all()
        await self.session_mgr.shutdown()
        await self.tasks.wait()
        # Finally shut down the block processor and executor (FIXME)
        self.chain_state.bp.shutdown(self.tasks.executor)
