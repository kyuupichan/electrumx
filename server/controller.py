# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

import asyncio
import itertools
import json
import os
import ssl
import time
import traceback
from bisect import bisect_left
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from functools import partial

import pylru

from aiorpcx import RPCError, TaskSet, _version
from lib.hash import double_sha256, hash_to_str, hex_str_to_hash, HASHX_LEN
from lib.peer import Peer
from lib.server_base import ServerBase
import lib.util as util
from server.daemon import DaemonError
from server.mempool import MemPool
from server.peers import PeerManager
from server.session import LocalRPC, BAD_REQUEST, DAEMON_ERROR
from server.version import VERSION


class SessionGroup(object):

    def __init__(self, gid):
        self.gid = gid
        # Concurrency per group
        self.semaphore = asyncio.Semaphore(20)


class Controller(ServerBase):
    '''Manages the client servers, a mempool, and a block processor.

    Servers are started immediately the block processor first catches
    up with the daemon.
    '''

    CATCHING_UP, LISTENING, PAUSED, SHUTTING_DOWN = range(4)
    PROTOCOL_MIN = '1.1'
    PROTOCOL_MAX = '1.2'
    VERSION = VERSION

    def __init__(self, env):
        '''Initialize everything that doesn't require the event loop.'''
        super().__init__(env)
        if _version < (0, 5, 5):
            raise RuntimeError('ElectrumX requires aiorpcX 0.5.5')

        self.logger.info(f'software version: {self.VERSION}')
        self.logger.info(f'supported protocol versions: '
                         f'{self.PROTOCOL_MIN}-{self.PROTOCOL_MAX}')
        self.logger.info(f'event loop policy: {env.loop_policy}')

        self.coin = env.coin
        self.servers = {}
        self.tasks = TaskSet()
        self.sessions = set()
        self.cur_group = SessionGroup(0)
        self.txs_sent = 0
        self.next_log_sessions = 0
        self.state = self.CATCHING_UP
        self.max_sessions = env.max_sessions
        self.low_watermark = self.max_sessions * 19 // 20
        self.max_subs = env.max_subs
        # Cache some idea of room to avoid recounting on each subscription
        self.subs_room = 0
        self.next_stale_check = 0
        self.history_cache = pylru.lrucache(256)
        self.header_cache = pylru.lrucache(8)
        self.cache_height = 0
        env.max_send = max(350000, env.max_send)
        # Set up the RPC request handlers
        cmds = ('add_peer daemon_url disconnect getinfo groups log peers reorg '
                'sessions stop'.split())
        self.rpc_handlers = {cmd: getattr(self, 'rpc_' + cmd) for cmd in cmds}

        self.loop = asyncio.get_event_loop()
        self.executor = ThreadPoolExecutor()
        self.loop.set_default_executor(self.executor)

        # The complex objects.  Note PeerManager references self.loop (ugh)
        self.daemon = self.coin.DAEMON(env)
        self.bp = self.coin.BLOCK_PROCESSOR(env, self, self.daemon)
        self.mempool = MemPool(self.bp, self)
        self.peer_mgr = PeerManager(env, self)

    @classmethod
    def short_version(cls):
        '''Return e.g. "1.2" for ElectrumX 1.2'''
        return cls.VERSION.split()[-1]

    def server_features(self):
        '''Return the server features dictionary.'''
        return {
            'hosts': self.env.hosts_dict(),
            'pruning': None,
            'server_version': self.VERSION,
            'protocol_min': self.PROTOCOL_MIN,
            'protocol_max': self.PROTOCOL_MAX,
            'genesis_hash': self.coin.GENESIS_HASH,
            'hash_function': 'sha256',
        }

    def server_version_args(self):
        '''The arguments to a server.version RPC call to a peer.'''
        return [self.VERSION, [self.PROTOCOL_MIN, self.PROTOCOL_MAX]]

    def protocol_tuple(self, client_protocol_str):
        '''Given a client's protocol version string, return the negotiated
        protocol version tuple, or None if unsupported.
        '''
        return util.protocol_version(client_protocol_str,
                                     self.PROTOCOL_MIN, self.PROTOCOL_MAX)

    async def start_servers(self):
        '''Start the RPC server and schedule the external servers to be
        started once the block processor has caught up.
        '''
        if self.env.rpc_port is not None:
            await self.start_server('RPC', self.env.cs_host(for_rpc=True),
                                    self.env.rpc_port)

        self.create_task(self.bp.main_loop())
        self.create_task(self.wait_for_bp_catchup())

    async def shutdown(self):
        '''Perform the shutdown sequence.'''
        self.state = self.SHUTTING_DOWN

        # Close servers and sessions, and cancel all tasks
        self.close_servers(list(self.servers.keys()))
        for session in self.sessions:
            session.abort()
        self.tasks.cancel_all()

        # Wait for the above to take effect
        await self.tasks.wait()
        for session in list(self.sessions):
            await session.wait_closed()

        # Finally shut down the block processor and executor
        self.bp.shutdown(self.executor)

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

    def sent_tx(self, tx_hash):
        '''Call when a TX is sent.'''
        self.txs_sent += 1

    async def run_in_executor(self, func, *args):
        '''Wait whilst running func in the executor.'''
        return await self.loop.run_in_executor(None, func, *args)

    def schedule_executor(self, func, *args):
        '''Schedule running func in the executor, return a task.'''
        return self.create_task(self.run_in_executor(func, *args))

    def create_task(self, coro, callback=None):
        '''Schedule the coro to be run.'''
        task = self.tasks.create_task(coro)
        task.add_done_callback(callback or self.check_task_exception)
        return task

    def check_task_exception(self, task):
        '''Check a task for exceptions.'''
        try:
            if not task.cancelled():
                task.result()
        except Exception as e:
            self.logger.exception(f'uncaught task exception: {e}')

    async def housekeeping(self):
        '''Regular housekeeping checks.'''
        n = 0
        while True:
            n += 1
            await asyncio.sleep(15)
            if n % 10 == 0:
                self.clear_stale_sessions()

            # Start listening for incoming connections if paused and
            # session count has fallen
            if (self.state == self.PAUSED and
                    len(self.sessions) <= self.low_watermark):
                await self.start_external_servers()

            # Periodically log sessions
            if self.env.log_sessions and time.time() > self.next_log_sessions:
                if self.next_log_sessions:
                    data = self.session_data(for_log=True)
                    for line in Controller.sessions_text_lines(data):
                        self.logger.info(line)
                    self.logger.info(json.dumps(self.getinfo()))
                self.next_log_sessions = time.time() + self.env.log_sessions

    async def wait_for_bp_catchup(self):
        '''Wait for the block processor to catch up, and for the mempool to
        synchronize, then kick off server background processes.'''
        await self.bp.caught_up_event.wait()
        self.logger.info('block processor has caught up')
        self.create_task(self.mempool.main_loop())
        await self.mempool.synchronized_event.wait()
        self.create_task(self.peer_mgr.main_loop())
        self.create_task(self.log_start_external_servers())
        self.create_task(self.housekeeping())

    def close_servers(self, kinds):
        '''Close the servers of the given kinds (TCP etc.).'''
        if kinds:
            self.logger.info('closing down {} listening servers'
                             .format(', '.join(kinds)))
        for kind in kinds:
            server = self.servers.pop(kind, None)
            if server:
                server.close()

    async def start_server(self, kind, *args, **kw_args):
        protocol_class = LocalRPC if kind == 'RPC' else self.coin.SESSIONCLS
        protocol_factory = partial(protocol_class, self, kind)
        server = self.loop.create_server(protocol_factory, *args, **kw_args)

        host, port = args[:2]
        try:
            self.servers[kind] = await server
        except Exception as e:
            self.logger.error('{} server failed to listen on {}:{:d} :{}'
                              .format(kind, host, port, e))
        else:
            self.logger.info('{} server listening on {}:{:d}'
                             .format(kind, host, port))

    async def log_start_external_servers(self):
        '''Start TCP and SSL servers.'''
        self.logger.info('max session count: {:,d}'.format(self.max_sessions))
        self.logger.info('session timeout: {:,d} seconds'
                         .format(self.env.session_timeout))
        self.logger.info('session bandwidth limit {:,d} bytes'
                         .format(self.env.bandwidth_limit))
        self.logger.info('max response size {:,d} bytes'
                         .format(self.env.max_send))
        self.logger.info('max subscriptions across all sessions: {:,d}'
                         .format(self.max_subs))
        self.logger.info('max subscriptions per session: {:,d}'
                         .format(self.env.max_session_subs))
        if self.env.drop_client is not None:
            self.logger.info('drop clients matching: {}'
                             .format(self.env.drop_client.pattern))
        await self.start_external_servers()

    async def start_external_servers(self):
        '''Start listening on TCP and SSL ports, but only if the respective
        port was given in the environment.
        '''
        self.state = self.LISTENING

        env = self.env
        host = env.cs_host(for_rpc=False)
        if env.tcp_port is not None:
            await self.start_server('TCP', host, env.tcp_port)
        if env.ssl_port is not None:
            sslc = ssl.SSLContext(ssl.PROTOCOL_TLS)
            sslc.load_cert_chain(env.ssl_certfile, keyfile=env.ssl_keyfile)
            await self.start_server('SSL', host, env.ssl_port, ssl=sslc)

    def notify_sessions(self, touched):
        '''Notify sessions about height changes and touched addresses.'''
        # Invalidate caches
        hc = self.history_cache
        for hashX in set(hc).intersection(touched):
            del hc[hashX]

        height = self.bp.db_height
        if height != self.cache_height:
            self.cache_height = height
            self.header_cache.clear()

        # Height notifications are synchronous.  Those sessions with
        # touched addresses are scheduled for asynchronous completion
        for session in self.sessions:
            if isinstance(session, LocalRPC):
                continue
            session_touched = session.notify(height, touched)
            if session_touched is not None:
                self.create_task(session.notify_async(session_touched))

    def notify_peers(self, updates):
        '''Notify of peer updates.'''
        for session in self.sessions:
            session.notify_peers(updates)

    def raw_header(self, height):
        '''Return the binary header at the given height.'''
        header, n = self.bp.read_headers(height, 1)
        if n != 1:
            raise RPCError(BAD_REQUEST, f'height {height:,d} out of range')
        return header

    def electrum_header(self, height):
        '''Return the deserialized header at the given height.'''
        if height not in self.header_cache:
            raw_header = self.raw_header(height)
            self.header_cache[height] = self.coin.electrum_header(raw_header,
                                                                  height)
        return self.header_cache[height]

    def add_session(self, session):
        self.sessions.add(session)
        if (len(self.sessions) >= self.max_sessions
                and self.state == self.LISTENING):
            self.state = self.PAUSED
            session.logger.info('maximum sessions {:,d} reached, stopping new '
                                'connections until count drops to {:,d}'
                                .format(self.max_sessions, self.low_watermark))
            self.close_servers(['TCP', 'SSL'])
        gid = int(session.start_time - self.start_time) // 900
        if self.cur_group.gid != gid:
            self.cur_group = SessionGroup(gid)
        return self.cur_group

    def remove_session(self, session):
        '''Remove a session from our sessions list if there.'''
        self.sessions.remove(session)

    def close_session(self, session):
        '''Close the session's transport.'''
        session.close()
        return 'disconnected {:d}'.format(session.session_id)

    def toggle_logging(self, session):
        '''Toggle logging of the session.'''
        session.toggle_logging()
        return 'log {:d}: {}'.format(session.session_id, session.log_me)

    def _group_map(self):
        group_map = defaultdict(list)
        for session in self.sessions:
            group_map[session.group].append(session)
        return group_map

    def clear_stale_sessions(self):
        '''Cut off sessions that haven't done anything for 10 minutes.'''
        now = time.time()
        stale_cutoff = now - self.env.session_timeout

        stale = []
        for session in self.sessions:
            if session.is_closing():
                session.abort()
            elif session.last_recv < stale_cutoff:
                self.close_session(session)
                stale.append(session.session_id)
        if stale:
            self.logger.info('closing stale connections {}'.format(stale))

        # Consolidate small groups
        bw_limit = self.env.bandwidth_limit
        group_map = self._group_map()
        groups = [group for group, sessions in group_map.items()
                  if len(sessions) <= 5 and
                  sum(s.bw_charge for s in sessions) < bw_limit]
        if len(groups) > 1:
            new_group = groups[-1]
            for group in groups:
                for session in group_map[group]:
                    session.group = new_group

    def session_count(self):
        '''The number of connections that we've sent something to.'''
        return len(self.sessions)

    def getinfo(self):
        '''A one-line summary of server state.'''
        group_map = self._group_map()
        return {
            'version': VERSION,
            'daemon': self.daemon.logged_url(),
            'daemon_height': self.daemon.cached_height(),
            'db_height': self.bp.db_height,
            'closing': len([s for s in self.sessions if s.is_closing()]),
            'errors': sum(s.rpc.errors for s in self.sessions),
            'groups': len(group_map),
            'logged': len([s for s in self.sessions if s.log_me]),
            'paused': sum(s.paused for s in self.sessions),
            'pid': os.getpid(),
            'peers': self.peer_mgr.info(),
            'requests': sum(s.count_pending_items() for s in self.sessions),
            'sessions': self.session_count(),
            'subs': self.sub_count(),
            'txs_sent': self.txs_sent,
            'uptime': util.formatted_time(time.time() - self.start_time),
        }

    def sub_count(self):
        return sum(s.sub_count() for s in self.sessions)

    @staticmethod
    def groups_text_lines(data):
        '''A generator returning lines for a list of groups.

        data is the return value of rpc_groups().'''

        fmt = ('{:<6} {:>9} {:>9} {:>6} {:>6} {:>8}'
               '{:>7} {:>9} {:>7} {:>9}')
        yield fmt.format('ID', 'Sessions', 'Bwidth KB', 'Reqs', 'Txs', 'Subs',
                         'Recv', 'Recv KB', 'Sent', 'Sent KB')
        for (id_, session_count, bandwidth, reqs, txs_sent, subs,
             recv_count, recv_size, send_count, send_size) in data:
            yield fmt.format(id_,
                             '{:,d}'.format(session_count),
                             '{:,d}'.format(bandwidth // 1024),
                             '{:,d}'.format(reqs),
                             '{:,d}'.format(txs_sent),
                             '{:,d}'.format(subs),
                             '{:,d}'.format(recv_count),
                             '{:,d}'.format(recv_size // 1024),
                             '{:,d}'.format(send_count),
                             '{:,d}'.format(send_size // 1024))

    def group_data(self):
        '''Returned to the RPC 'groups' call.'''
        result = []
        group_map = self._group_map()
        for group, sessions in group_map.items():
            result.append([group.gid,
                           len(sessions),
                           sum(s.bw_charge for s in sessions),
                           sum(s.count_pending_items() for s in sessions),
                           sum(s.txs_sent for s in sessions),
                           sum(s.sub_count() for s in sessions),
                           sum(s.recv_count for s in sessions),
                           sum(s.recv_size for s in sessions),
                           sum(s.send_count for s in sessions),
                           sum(s.send_size for s in sessions),
                           ])
        return result

    @staticmethod
    def peers_text_lines(data):
        '''A generator returning lines for a list of peers.

        data is the return value of rpc_peers().'''
        def time_fmt(t):
            if not t:
                return 'Never'
            return util.formatted_time(now - t)

        now = time.time()
        fmt = ('{:<30} {:<6} {:>5} {:>5} {:<17} {:>4} '
               '{:>4} {:>8} {:>11} {:>11} {:>5} {:>20} {:<15}')
        yield fmt.format('Host', 'Status', 'TCP', 'SSL', 'Server', 'Min',
                         'Max', 'Pruning', 'Last Good', 'Last Try',
                         'Tries', 'Source', 'IP Address')
        for item in data:
            features = item['features']
            hostname = item['host']
            host = features['hosts'][hostname]
            yield fmt.format(hostname[:30],
                             item['status'],
                             host.get('tcp_port') or '',
                             host.get('ssl_port') or '',
                             features['server_version'] or 'unknown',
                             features['protocol_min'],
                             features['protocol_max'],
                             features['pruning'] or '',
                             time_fmt(item['last_good']),
                             time_fmt(item['last_try']),
                             item['try_count'],
                             item['source'][:20],
                             item['ip_addr'] or '')

    @staticmethod
    def sessions_text_lines(data):
        '''A generator returning lines for a list of sessions.

        data is the return value of rpc_sessions().'''
        fmt = ('{:<6} {:<5} {:>17} {:>5} {:>5} {:>5} '
               '{:>7} {:>7} {:>7} {:>7} {:>7} {:>9} {:>21}')
        yield fmt.format('ID', 'Flags', 'Client', 'Proto',
                         'Reqs', 'Txs', 'Subs',
                         'Recv', 'Recv KB', 'Sent', 'Sent KB', 'Time', 'Peer')
        for (id_, flags, peer, client, proto, reqs, txs_sent, subs,
             recv_count, recv_size, send_count, send_size, time) in data:
            yield fmt.format(id_, flags, client, proto,
                             '{:,d}'.format(reqs),
                             '{:,d}'.format(txs_sent),
                             '{:,d}'.format(subs),
                             '{:,d}'.format(recv_count),
                             '{:,d}'.format(recv_size // 1024),
                             '{:,d}'.format(send_count),
                             '{:,d}'.format(send_size // 1024),
                             util.formatted_time(time, sep=''), peer)

    def session_data(self, for_log):
        '''Returned to the RPC 'sessions' call.'''
        now = time.time()
        sessions = sorted(self.sessions, key=lambda s: s.start_time)
        return [(session.session_id,
                 session.flags(),
                 session.peer_address_str(for_log=for_log),
                 session.client,
                 session.protocol_version,
                 session.count_pending_items(),
                 session.txs_sent,
                 session.sub_count(),
                 session.recv_count, session.recv_size,
                 session.send_count, session.send_size,
                 now - session.start_time)
                for session in sessions]

    def lookup_session(self, session_id):
        try:
            session_id = int(session_id)
        except Exception:
            pass
        else:
            for session in self.sessions:
                if session.session_id == session_id:
                    return session
        return None

    def for_each_session(self, session_ids, operation):
        if not isinstance(session_ids, list):
            raise RPCError(BAD_REQUEST, 'expected a list of session IDs')

        result = []
        for session_id in session_ids:
            session = self.lookup_session(session_id)
            if session:
                result.append(operation(session))
            else:
                result.append('unknown session: {}'.format(session_id))
        return result

    # Local RPC command handlers

    def rpc_add_peer(self, real_name):
        '''Add a peer.

        real_name: a real name, as would appear on IRC
        '''
        peer = Peer.from_real_name(real_name, 'RPC')
        self.peer_mgr.add_peers([peer])
        return "peer '{}' added".format(real_name)

    def rpc_disconnect(self, session_ids):
        '''Disconnect sesssions.

        session_ids: array of session IDs
        '''
        return self.for_each_session(session_ids, self.close_session)

    def rpc_log(self, session_ids):
        '''Toggle logging of sesssions.

        session_ids: array of session IDs
        '''
        return self.for_each_session(session_ids, self.toggle_logging)

    def rpc_daemon_url(self, daemon_url=None):
        '''Replace the daemon URL.'''
        daemon_url = daemon_url or self.env.daemon_url
        try:
            self.daemon.set_urls(self.env.coin.daemon_urls(daemon_url))
        except Exception as e:
            raise RPCError(BAD_REQUEST, f'an error occured: {e}')
        return 'now using daemon at {}'.format(self.daemon.logged_url())

    def rpc_stop(self):
        '''Shut down the server cleanly.'''
        self.shutdown_event.set()
        return 'stopping'

    def rpc_getinfo(self):
        '''Return summary information about the server process.'''
        return self.getinfo()

    def rpc_groups(self):
        '''Return statistics about the session groups.'''
        return self.group_data()

    def rpc_peers(self):
        '''Return a list of data about server peers.'''
        return self.peer_mgr.rpc_data()

    def rpc_sessions(self):
        '''Return statistics about connected sessions.'''
        return self.session_data(for_log=False)

    def rpc_reorg(self, count=3):
        '''Force a reorg of the given number of blocks.

        count: number of blocks to reorg (default 3)
        '''
        count = self.non_negative_integer(count)
        if not self.bp.force_chain_reorg(count):
            raise RPCError(BAD_REQUEST, 'still catching up with daemon')
        return 'scheduled a reorg of {:,d} blocks'.format(count)

    # Helpers for RPC "blockchain" command handlers

    def address_to_hashX(self, address):
        try:
            return self.coin.address_to_hashX(address)
        except Exception:
            pass
        raise RPCError(BAD_REQUEST, f'{address} is not a valid address')

    def scripthash_to_hashX(self, scripthash):
        try:
            bin_hash = hex_str_to_hash(scripthash)
            if len(bin_hash) == 32:
                return bin_hash[:HASHX_LEN]
        except Exception:
            pass
        raise RPCError(BAD_REQUEST, f'{scripthash} is not a valid script hash')

    def assert_tx_hash(self, value):
        '''Raise an RPCError if the value is not a valid transaction
        hash.'''
        try:
            if len(util.hex_to_bytes(value)) == 32:
                return
        except Exception:
            pass
        raise RPCError(BAD_REQUEST, f'{value} should be a transaction hash')

    def non_negative_integer(self, value):
        '''Return param value it is or can be converted to a non-negative
        integer, otherwise raise an RPCError.'''
        try:
            value = int(value)
            if value >= 0:
                return value
        except ValueError:
            pass
        raise RPCError(BAD_REQUEST,
                       f'{value} should be a non-negative integer')

    async def daemon_request(self, method, *args):
        '''Catch a DaemonError and convert it to an RPCError.'''
        try:
            return await getattr(self.daemon, method)(*args)
        except DaemonError as e:
            raise RPCError(DAEMON_ERROR, f'daemon error: {e}')

    def new_subscription(self):
        if self.subs_room <= 0:
            self.subs_room = self.max_subs - self.sub_count()
            if self.subs_room <= 0:
                raise RPCError(BAD_REQUEST, f'server subscription limit '
                               f'{self.max_subs:,d} reached')
        self.subs_room -= 1

    async def tx_merkle(self, tx_hash, height):
        '''tx_hash is a hex string.'''
        hex_hashes = await self.daemon_request('block_hex_hashes', height, 1)
        block = await self.daemon_request('deserialised_block', hex_hashes[0])
        tx_hashes = block['tx']
        try:
            pos = tx_hashes.index(tx_hash)
        except ValueError:
            raise RPCError(BAD_REQUEST, f'tx hash {tx_hash} not in '
                           f'block {hex_hashes[0]} at height {height:,d}')

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

    async def get_balance(self, hashX):
        utxos = await self.get_utxos(hashX)
        confirmed = sum(utxo.value for utxo in utxos)
        unconfirmed = self.mempool_value(hashX)
        return {'confirmed': confirmed, 'unconfirmed': unconfirmed}

    async def unconfirmed_history(self, hashX):
        # Note unconfirmed history is unordered in electrum-server
        # Height is -1 if unconfirmed txins, otherwise 0
        mempool = await self.mempool_transactions(hashX)
        return [{'tx_hash': tx_hash, 'height': -unconfirmed, 'fee': fee}
                for tx_hash, fee, unconfirmed in mempool]

    async def get_history(self, hashX):
        '''Get history asynchronously to reduce latency.'''
        if hashX in self.history_cache:
            return self.history_cache[hashX]

        def job():
            # History DoS limit.  Each element of history is about 99
            # bytes when encoded as JSON.  This limits resource usage
            # on bloated history requests, and uses a smaller divisor
            # so large requests are logged before refusing them.
            limit = self.env.max_send // 97
            return list(self.bp.get_history(hashX, limit=limit))

        history = await self.run_in_executor(job)
        self.history_cache[hashX] = history
        return history

    async def confirmed_and_unconfirmed_history(self, hashX):
        # Note history is ordered but unconfirmed is unordered in e-s
        history = await self.get_history(hashX)
        conf = [{'tx_hash': hash_to_str(tx_hash), 'height': height}
                for tx_hash, height in history]
        return conf + await self.unconfirmed_history(hashX)

    async def get_utxos(self, hashX):
        '''Get UTXOs asynchronously to reduce latency.'''
        def job():
            return list(self.bp.get_utxos(hashX, limit=None))

        return await self.run_in_executor(job)

    def block_headers(self, start_height, count):
        '''Read count block headers starting at start_height; both
        must be non-negative.

        The return value is (hex, n), where hex is the hex encoding of
        the concatenated headers, and n is the number of headers read
        (0 <= n <= count).
        '''
        headers, n = self.bp.read_headers(start_height, count)
        return headers.hex(), n

    # Client RPC "blockchain" command handlers

    async def address_get_balance(self, address):
        '''Return the confirmed and unconfirmed balance of an address.'''
        hashX = self.address_to_hashX(address)
        return await self.get_balance(hashX)

    async def scripthash_get_balance(self, scripthash):
        '''Return the confirmed and unconfirmed balance of a scripthash.'''
        hashX = self.scripthash_to_hashX(scripthash)
        return await self.get_balance(hashX)

    async def address_get_history(self, address):
        '''Return the confirmed and unconfirmed history of an address.'''
        hashX = self.address_to_hashX(address)
        return await self.confirmed_and_unconfirmed_history(hashX)

    async def scripthash_get_history(self, scripthash):
        '''Return the confirmed and unconfirmed history of a scripthash.'''
        hashX = self.scripthash_to_hashX(scripthash)
        return await self.confirmed_and_unconfirmed_history(hashX)

    async def address_get_mempool(self, address):
        '''Return the mempool transactions touching an address.'''
        hashX = self.address_to_hashX(address)
        return await self.unconfirmed_history(hashX)

    async def scripthash_get_mempool(self, scripthash):
        '''Return the mempool transactions touching a scripthash.'''
        hashX = self.scripthash_to_hashX(scripthash)
        return await self.unconfirmed_history(hashX)

    async def hashX_listunspent(self, hashX):
        '''Return the list of UTXOs of a script hash, including mempool
        effects.'''
        utxos = await self.get_utxos(hashX)
        utxos = sorted(utxos)
        utxos.extend(self.mempool.get_utxos(hashX))
        spends = await self.mempool.potential_spends(hashX)

        return [{'tx_hash': hash_to_str(utxo.tx_hash), 'tx_pos': utxo.tx_pos,
                 'height': utxo.height, 'value': utxo.value}
                for utxo in utxos
                if (utxo.tx_hash, utxo.tx_pos) not in spends]

    async def address_listunspent(self, address):
        '''Return the list of UTXOs of an address.'''
        hashX = self.address_to_hashX(address)
        return await self.hashX_listunspent(hashX)

    async def scripthash_listunspent(self, scripthash):
        '''Return the list of UTXOs of a scripthash.'''
        hashX = self.scripthash_to_hashX(scripthash)
        return await self.hashX_listunspent(hashX)

    def block_get_header(self, height):
        '''The deserialized header at a given height.

        height: the header's height'''
        height = self.non_negative_integer(height)
        return self.electrum_header(height)

    async def estimatefee(self, number):
        '''The estimated transaction fee per kilobyte to be paid for a
        transaction to be included within a certain number of blocks.

        number: the number of blocks
        '''
        number = self.non_negative_integer(number)
        return await self.daemon_request('estimatefee', [number])

    def mempool_get_fee_histogram(self):
        '''Memory pool fee histogram.

        TODO: The server should detect and discount transactions that
        never get mined when they should.
        '''
        return self.mempool.get_fee_histogram()

    async def relayfee(self):
        '''The minimum fee a low-priority tx must pay in order to be accepted
        to the daemon's memory pool.'''
        return await self.daemon_request('relayfee')

    async def transaction_get(self, tx_hash, verbose=False):
        '''Return the serialized raw transaction given its hash

        tx_hash: the transaction hash as a hexadecimal string
        verbose: passed on to the daemon
        '''
        self.assert_tx_hash(tx_hash)
        return await self.daemon_request('getrawtransaction', tx_hash, verbose)

    async def transaction_get_merkle(self, tx_hash, height):
        '''Return the markle tree to a confirmed transaction given its hash
        and height.

        tx_hash: the transaction hash as a hexadecimal string
        height: the height of the block it is in
        '''
        self.assert_tx_hash(tx_hash)
        height = self.non_negative_integer(height)
        return await self.tx_merkle(tx_hash, height)
