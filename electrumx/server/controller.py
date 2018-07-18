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
from electrumx.server.mempool import MemPool
from electrumx.server.peers import PeerManager
from electrumx.server.session import SessionManager


class Controller(ServerBase):
    '''Manages the client servers, a mempool, and a block processor.

    Servers are started immediately the block processor first catches
    up with the daemon.
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

        env.max_send = max(350000, env.max_send)

        self.tasks = Tasks()
        self.session_mgr = SessionManager(env, self.tasks, self)
        self.daemon = env.coin.DAEMON(env)
        self.bp = env.coin.BLOCK_PROCESSOR(env, self.tasks, self.daemon)
        self.mempool = MemPool(self.bp, self.daemon, self.tasks,
                               self.session_mgr.notify_sessions)
        self.peer_mgr = PeerManager(env, self.tasks, self.session_mgr, self.bp)

    async def start_servers(self):
        '''Start the RPC server and schedule the external servers to be
        started once the block processor has caught up.
        '''
        await self.session_mgr.start_rpc_server()
        self.tasks.create_task(self.bp.main_loop())
        self.tasks.create_task(self.wait_for_bp_catchup())

    async def shutdown(self):
        '''Perform the shutdown sequence.'''
        # Not certain of ordering here
        self.tasks.cancel_all()
        await self.session_mgr.shutdown()
        await self.tasks.wait()
        # Finally shut down the block processor and executor (FIXME)
        self.bp.shutdown(self.tasks.executor)

    async def mempool_transactions(self, hashX):
        '''Generate (hex_hash, tx_fee, unconfirmed) tuples for mempool
        entries for the hashX.

        unconfirmed is True if any txin is unconfirmed.
        '''
        return await self.mempool.transactions(hashX)

    def mempool_value(self, hashX):
        '''Return the unconfirmed amount in the mempool for hashX.

        Can be positive or negative.
        '''
        return self.mempool.value(hashX)

    async def wait_for_bp_catchup(self):
        '''Wait for the block processor to catch up, and for the mempool to
        synchronize, then kick off server background processes.'''
        await self.bp.caught_up_event.wait()
        self.tasks.create_task(self.mempool.main_loop())
        await self.mempool.synchronized_event.wait()
        self.tasks.create_task(self.peer_mgr.main_loop())
        self.tasks.create_task(self.session_mgr.start_serving())
        self.tasks.create_task(self.session_mgr.housekeeping())
