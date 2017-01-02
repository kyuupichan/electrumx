# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

import asyncio
import json
import os
import ssl
import time
from bisect import bisect_left
from collections import defaultdict
from functools import partial

import pylru

from lib.jsonrpc import JSONRPC, RequestBase
import lib.util as util
from server.block_processor import BlockProcessor
from server.irc import IRC
from server.protocol import LocalRPC, ElectrumX
from server.mempool import MemPool


class Controller(util.LoggedClass):
    '''Manages the client servers, a mempool, and a block processor.

    Servers are started immediately the block processor first catches
    up with the daemon.
    '''

    BANDS = 5
    CATCHING_UP, LISTENING, PAUSED, SHUTTING_DOWN = range(4)

    class NotificationRequest(RequestBase):
        def __init__(self, height, touched):
            super().__init__(1)
            self.height = height
            self.touched = touched

        async def process(self, session):
            self.remaining = 0
            await session.notify(self.height, self.touched)

    def __init__(self, env):
        super().__init__()
        self.loop = asyncio.get_event_loop()
        self.start = time.time()
        self.bp = BlockProcessor(env)
        self.mempool = MemPool(self.bp.daemon, env.coin, self.bp)
        self.irc = IRC(env)
        self.env = env
        self.servers = {}
        self.sessions = {}
        self.groups = defaultdict(set)
        self.txs_sent = 0
        self.next_log_sessions = 0
        self.state = self.CATCHING_UP
        self.max_sessions = env.max_sessions
        self.low_watermark = self.max_sessions * 19 // 20
        self.max_subs = env.max_subs
        self.subscription_count = 0
        self.next_stale_check = 0
        self.history_cache = pylru.lrucache(256)
        self.header_cache = pylru.lrucache(8)
        self.queue = asyncio.PriorityQueue()
        self.delayed_sessions = []
        self.next_queue_id = 0
        self.height = 0
        self.futures = []
        env.max_send = max(350000, env.max_send)
        self.setup_bands()

    async def mempool_transactions(self, hash168):
        '''Generate (hex_hash, tx_fee, unconfirmed) tuples for mempool
        entries for the hash168.

        unconfirmed is True if any txin is unconfirmed.
        '''
        return await self.mempool.transactions(hash168)

    def mempool_value(self, hash168):
        '''Return the unconfirmed amount in the mempool for hash168.

        Can be positive or negative.
        '''
        return self.mempool.value(hash168)

    def sent_tx(self, tx_hash):
        '''Call when a TX is sent.  Tells mempool to prioritize it.'''
        self.txs_sent += 1
        self.mempool.prioritize(tx_hash)

    def setup_bands(self):
        bands = []
        limit = self.env.bandwidth_limit
        for n in range(self.BANDS):
            bands.append(limit)
            limit //= 4
        limit = self.env.bandwidth_limit
        for n in range(self.BANDS):
            limit += limit // 2
            bands.append(limit)
        self.bands = sorted(bands)

    def session_priority(self, session):
        if isinstance(session, LocalRPC):
            return 0
        group_bandwidth = sum(s.bandwidth_used for s in self.sessions[session])
        return 1 + (bisect_left(self.bands, session.bandwidth_used)
                    + bisect_left(self.bands, group_bandwidth) + 1) // 2

    def is_deprioritized(self, session):
        return self.session_priority(session) > self.BANDS

    async def enqueue_delayed_sessions(self):
        while True:
            now = time.time()
            keep = []
            for pair in self.delayed_sessions:
                timeout, item = pair
                priority, queue_id, session = item
                if not session.pause and timeout <= now:
                    self.queue.put_nowait(item)
                else:
                    keep.append(pair)
            self.delayed_sessions = keep

            # If paused and session count has fallen, start listening again
            if (len(self.sessions) <= self.low_watermark
                    and self.state == self.PAUSED):
                await self.start_external_servers()

            await asyncio.sleep(1)

    def enqueue_session(self, session):
        # Might have disconnected whilst waiting
        if not session in self.sessions:
            return
        priority = self.session_priority(session)
        item = (priority, self.next_queue_id, session)
        self.next_queue_id += 1

        excess = max(0, priority - self.BANDS)
        if excess != session.last_delay:
            session.last_delay = excess
            if excess:
                session.log_info('high bandwidth use, deprioritizing by '
                                 'delaying responses {:d}s'.format(excess))
            else:
                session.log_info('stopped delaying responses')
        delay = max(int(session.pause), excess)
        if delay:
            self.delayed_sessions.append((time.time() + delay, item))
        else:
            self.queue.put_nowait(item)

    async def serve_requests(self):
        '''Asynchronously run through the task queue.'''
        while True:
            priority_, id_, session = await self.queue.get()
            if session in self.sessions:
                await session.serve_requests()

    async def main_loop(self):
        '''Server manager main loop.'''
        def add_future(coro):
            self.futures.append(asyncio.ensure_future(coro))

        # shutdown() assumes bp.main_loop() is first
        add_future(self.bp.main_loop(self.mempool.touched))
        add_future(self.bp.prefetcher.main_loop(self.bp.caught_up_event))
        add_future(self.irc.start(self.bp.caught_up_event))
        add_future(self.start_servers(self.bp.caught_up_event))
        add_future(self.mempool.main_loop())
        add_future(self.enqueue_delayed_sessions())
        add_future(self.notify())
        for n in range(4):
            add_future(self.serve_requests())

        for future in asyncio.as_completed(self.futures):
            try:
                await future  # Note: future is not one of self.futures
            except asyncio.CancelledError:
                break
        await self.shutdown()
        await asyncio.sleep(1)

    def close_servers(self, kinds):
        '''Close the servers of the given kinds (TCP etc.).'''
        for kind in kinds:
            server = self.servers.pop(kind, None)
            if server:
                server.close()
                # Don't bother awaiting the close - we're not async

    async def start_server(self, kind, *args, **kw_args):
        protocol_class = LocalRPC if kind == 'RPC' else ElectrumX
        protocol = partial(protocol_class, self, self.bp, self.env, kind)
        server = self.loop.create_server(protocol, *args, **kw_args)

        host, port = args[:2]
        try:
            self.servers[kind] = await server
        except Exception as e:
            self.logger.error('{} server failed to listen on {}:{:d} :{}'
                              .format(kind, host, port, e))
        else:
            self.logger.info('{} server listening on {}:{:d}'
                             .format(kind, host, port))

    async def start_servers(self, caught_up):
        '''Start RPC, TCP and SSL servers once caught up.'''
        if self.env.rpc_port is not None:
            await self.start_server('RPC', 'localhost', self.env.rpc_port)
        await caught_up.wait()
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
        self.logger.info('bands: {}'.format(self.bands))
        await self.start_external_servers()

    async def start_external_servers(self):
        '''Start listening on TCP and SSL ports, but only if the respective
        port was given in the environment.
        '''
        self.state = self.LISTENING

        env= self.env
        if env.tcp_port is not None:
            await self.start_server('TCP', env.host, env.tcp_port)
        if env.ssl_port is not None:
            # Python 3.5.3: use PROTOCOL_TLS
            sslc = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            sslc.load_cert_chain(env.ssl_certfile, keyfile=env.ssl_keyfile)
            await self.start_server('SSL', env.host, env.ssl_port, ssl=sslc)

    async def notify(self):
        '''Notify sessions about height changes and touched addresses.'''
        while True:
            await self.mempool.touched_event.wait()
            touched = self.mempool.touched.copy()
            self.mempool.touched.clear()
            self.mempool.touched_event.clear()

            # Invalidate caches
            hc = self.history_cache
            for hash168 in set(hc).intersection(touched):
                del hc[hash168]
            if self.bp.db_height != self.height:
                self.height = self.bp.db_height
                self.header_cache.clear()

            for session in self.sessions:
                if isinstance(session, ElectrumX):
                    request = self.NotificationRequest(self.bp.db_height,
                                                       touched)
                    session.enqueue_request(request)
            # Periodically log sessions
            if self.env.log_sessions and time.time() > self.next_log_sessions:
                if self.next_log_sessions:
                    data = self.session_data(for_log=True)
                    for line in Controller.sessions_text_lines(data):
                        self.logger.info(line)
                    self.logger.info(json.dumps(self.server_summary()))
                self.next_log_sessions = time.time() + self.env.log_sessions

    def electrum_header(self, height):
        '''Return the binary header at the given height.'''
        if not 0 <= height <= self.bp.db_height:
            raise JSONRPC.RPCError('height {:,d} out of range'.format(height))
        if height in self.header_cache:
            return self.header_cache[height]
        header = self.bp.read_headers(height, 1)
        header = self.env.coin.electrum_header(header, height)
        self.header_cache[height] = header
        return header

    async def async_get_history(self, hash168):
        '''Get history asynchronously to reduce latency.'''
        if hash168 in self.history_cache:
            return self.history_cache[hash168]

        def job():
            # History DoS limit.  Each element of history is about 99
            # bytes when encoded as JSON.  This limits resource usage
            # on bloated history requests, and uses a smaller divisor
            # so large requests are logged before refusing them.
            limit = self.env.max_send // 97
            return list(self.bp.get_history(hash168, limit=limit))

        loop = asyncio.get_event_loop()
        history = await loop.run_in_executor(None, job)
        self.history_cache[hash168] = history
        return history

    async def shutdown(self):
        '''Call to shutdown everything.  Returns when done.'''
        self.state = self.SHUTTING_DOWN
        self.close_servers(list(self.servers.keys()))
        # Don't cancel the block processor main loop - let it close itself
        for future in self.futures[1:]:
            future.cancel()
        if self.sessions:
            await self.close_sessions()
        await self.futures[0]

    async def close_sessions(self, secs=30):
        self.logger.info('cleanly closing client sessions, please wait...')
        for session in self.sessions:
            self.close_session(session)
        self.logger.info('listening sockets closed, waiting up to '
                         '{:d} seconds for socket cleanup'.format(secs))
        limit = time.time() + secs
        while self.sessions and time.time() < limit:
            self.clear_stale_sessions(grace=secs//2)
            await asyncio.sleep(2)
            self.logger.info('{:,d} sessions remaining'
                             .format(len(self.sessions)))

    def add_session(self, session):
        now = time.time()
        if now > self.next_stale_check:
            self.next_stale_check = now + 300
            self.clear_stale_sessions()
        group = self.groups[int(session.start - self.start) // 900]
        group.add(session)
        self.sessions[session] = group
        session.log_info('{} {}, {:,d} total'
                         .format(session.kind, session.peername(),
                                 len(self.sessions)))
        if (len(self.sessions) >= self.max_sessions
               and self.state == self.LISTENING):
            self.state = self.PAUSED
            session.log_info('maximum sessions {:,d} reached, stopping new '
                             'connections until count drops to {:,d}'
                             .format(self.max_sessions, self.low_watermark))
            self.close_servers(['TCP', 'SSL'])

    def remove_session(self, session):
        '''Remove a session from our sessions list if there.'''
        if session in self.sessions:
            group = self.sessions.pop(session)
            group.remove(session)
            self.subscription_count -= session.sub_count()

    def close_session(self, session):
        '''Close the session's transport and cancel its future.'''
        session.close_connection()
        return 'disconnected {:d}'.format(session.id_)

    def toggle_logging(self, session):
        '''Toggle logging of the session.'''
        session.log_me = not session.log_me
        return 'log {:d}: {}'.format(session.id_, session.log_me)

    def clear_stale_sessions(self, grace=15):
        '''Cut off sessions that haven't done anything for 10 minutes.  Force
        close stubborn connections that won't close cleanly after a
        short grace period.
        '''
        now = time.time()
        shutdown_cutoff = now - grace
        stale_cutoff = now - self.env.session_timeout

        stale = []
        for session in self.sessions:
            if session.is_closing():
                if session.stop <= shutdown_cutoff:
                    session.transport.abort()
            elif session.last_recv < stale_cutoff:
                self.close_session(session)
                stale.append(session.id_)
        if stale:
            self.logger.info('closing stale connections {}'.format(stale))

        # Consolidate small groups
        keys = [k for k, v in self.groups.items() if len(v) <= 4
                and sum(session.bandwidth_used for session in v) < 10000]
        if len(keys) > 1:
            group = set.union(*(self.groups[key] for key in keys))
            for key in keys:
                del self.groups[key]
            self.groups[max(keys)] = group

    def new_subscription(self):
        if self.subscription_count >= self.max_subs:
            raise JSONRPC.RPCError('server subscription limit {:,d} reached'
                                   .format(self.max_subs))
        self.subscription_count += 1

    def irc_peers(self):
        return self.irc.peers

    def session_count(self):
        '''The number of connections that we've sent something to.'''
        return len(self.sessions)

    def server_summary(self):
        '''A one-line summary of server state.'''
        return {
            'daemon_height': self.bp.daemon.cached_height(),
            'db_height': self.bp.db_height,
            'closing': len([s for s in self.sessions if s.is_closing()]),
            'errors': sum(s.error_count for s in self.sessions),
            'groups': len(self.groups),
            'logged': len([s for s in self.sessions if s.log_me]),
            'paused': sum(s.pause for s in self.sessions),
            'pid': os.getpid(),
            'peers': len(self.irc.peers),
            'requests': sum(s.requests_remaining() for s in self.sessions),
            'sessions': self.session_count(),
            'subs': self.subscription_count,
            'txs_sent': self.txs_sent,
        }

    @staticmethod
    def text_lines(method, data):
        if method == 'sessions':
            return Controller.sessions_text_lines(data)
        else:
            return Controller.groups_text_lines(data)

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
        for group_id in sorted(self.groups.keys()):
            sessions = self.groups[group_id]
            result.append([group_id,
                           len(sessions),
                           sum(s.bandwidth_used for s in sessions),
                           sum(s.requests_remaining() for s in sessions),
                           sum(s.txs_sent for s in sessions),
                           sum(s.sub_count() for s in sessions),
                           sum(s.recv_count for s in sessions),
                           sum(s.recv_size for s in sessions),
                           sum(s.send_count for s in sessions),
                           sum(s.send_size for s in sessions),
                           ])
        return result

    @staticmethod
    def sessions_text_lines(data):
        '''A generator returning lines for a list of sessions.

        data is the return value of rpc_sessions().'''

        def time_fmt(t):
            t = int(t)
            return ('{:3d}:{:02d}:{:02d}'
                    .format(t // 3600, (t % 3600) // 60, t % 60))

        fmt = ('{:<6} {:<5} {:>15} {:>5} {:>5} '
               '{:>7} {:>7} {:>7} {:>7} {:>7} {:>9} {:>21}')
        yield fmt.format('ID', 'Flags', 'Client', 'Reqs', 'Txs', 'Subs',
                         'Recv', 'Recv KB', 'Sent', 'Sent KB', 'Time', 'Peer')
        for (id_, flags, peer, client, reqs, txs_sent, subs,
             recv_count, recv_size, send_count, send_size, time) in data:
            yield fmt.format(id_, flags, client,
                             '{:,d}'.format(reqs),
                             '{:,d}'.format(txs_sent),
                             '{:,d}'.format(subs),
                             '{:,d}'.format(recv_count),
                             '{:,d}'.format(recv_size // 1024),
                             '{:,d}'.format(send_count),
                             '{:,d}'.format(send_size // 1024),
                             time_fmt(time), peer)

    def session_data(self, for_log):
        '''Returned to the RPC 'sessions' call.'''
        now = time.time()
        sessions = sorted(self.sessions, key=lambda s: s.start)
        return [(session.id_,
                 session.flags(),
                 session.peername(for_log=for_log),
                 session.client,
                 session.requests_remaining(),
                 session.txs_sent,
                 session.sub_count(),
                 session.recv_count, session.recv_size,
                 session.send_count, session.send_size,
                 now - session.start)
                for session in sessions]

    def lookup_session(self, param):
        try:
            id_ = int(param)
        except:
            pass
        else:
            for session in self.sessions:
                if session.id_ == id_:
                    return session
        return None

    def for_each_session(self, params, operation):
        result = []
        for param in params:
            session = self.lookup_session(param)
            if session:
                result.append(operation(session))
            else:
                result.append('unknown session: {}'.format(param))
        return result

    async def rpc_disconnect(self, params):
        return self.for_each_session(params, self.close_session)

    async def rpc_log(self, params):
        return self.for_each_session(params, self.toggle_logging)

    async def rpc_getinfo(self, params):
        return self.server_summary()

    async def rpc_groups(self, params):
        return self.group_data()

    async def rpc_sessions(self, params):
        return self.session_data(for_log=False)

    async def rpc_peers(self, params):
        return self.irc.peers
