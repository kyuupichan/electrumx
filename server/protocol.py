# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Classes for local RPC server and remote client TCP/SSL servers.'''


import asyncio
import codecs
import json
import ssl
import time
import traceback
from bisect import bisect_left
from collections import defaultdict, namedtuple
from functools import partial

import pylru

from lib.hash import sha256, double_sha256, hash_to_str, hex_str_to_hash
from lib.jsonrpc import JSONRPC, RequestBase
import lib.util as util
from server.block_processor import BlockProcessor
from server.daemon import DaemonError
from server.irc import IRC
from server.mempool import MemPool
from server.version import VERSION


class ServerManager(util.LoggedClass):
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
        self.logger.info('max session count: {:,d}'.format(self.max_sessions))
        self.logger.info('session timeout: {:,d} seconds'
                         .format(env.session_timeout))
        self.logger.info('session bandwidth limit {:,d} bytes'
                         .format(env.bandwidth_limit))
        self.logger.info('max response size {:,d} bytes'.format(env.max_send))
        self.logger.info('max subscriptions across all sessions: {:,d}'
                         .format(self.max_subs))
        self.logger.info('max subscriptions per session: {:,d}'
                         .format(env.max_session_subs))

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
        self.logger.info('bands: {}'.format(self.bands))

    def session_priority(self, session):
        if isinstance(session, LocalRPC):
            return 0
        group_bandwidth = sum(s.bandwidth_used for s in self.sessions[session])
        return 1 + (bisect_left(self.bands, session.bandwidth_used)
                    + bisect_left(self.bands, group_bandwidth) + 1) // 2

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

        secs = int(session.pause)
        excess = priority - self.BANDS
        if excess > 0:
            secs = excess
            session.log_info('delaying response to low-priority session {:d}s'
                             .format(secs))
        if secs:
            self.delayed_sessions.append((time.time() + secs, item))
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
        add_future(self.bp.prefetcher.main_loop())
        add_future(self.irc.start(self.bp.event))
        add_future(self.start_servers(self.bp.event))
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
        await caught_up.wait()

        if self.env.rpc_port is not None:
            await self.start_server('RPC', 'localhost', self.env.rpc_port)
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
                data = self.session_data(for_log=True)
                for line in ServerManager.sessions_text_lines(data):
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
        self.bp.shutdown()
        # Don't cancel the block processor main loop - let it close itself
        for future in self.futures[1:]:
            future.cancel()
        if self.sessions:
            await self.close_sessions()

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
        session.log_info('{} from {}, {:,d} total'
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
            'blocks': self.bp.db_height,
            'closing': len([s for s in self.sessions if s.is_closing()]),
            'errors': sum(s.error_count for s in self.sessions),
            'groups': len(self.groups),
            'logged': len([s for s in self.sessions if s.log_me]),
            'peers': len(self.irc.peers),
            'requests': sum(s.requests_remaining() for s in self.sessions),
            'sessions': self.session_count(),
            'txs_sent': self.txs_sent,
            'watched': self.subscription_count,
        }

    @staticmethod
    def text_lines(method, data):
        if method == 'sessions':
            return ServerManager.sessions_text_lines(data)
        else:
            return ServerManager.groups_text_lines(data)

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

        fmt = ('{:<6} {:<5} {:>23} {:>15} {:>5} {:>5} '
               '{:>7} {:>7} {:>7} {:>7} {:>7} {:>9}')
        yield fmt.format('ID', 'Flags', 'Peer', 'Client', 'Reqs', 'Txs',
                         'Subs', 'Recv', 'Recv KB', 'Sent', 'Sent KB', 'Time')
        for (id_, flags, peer, client, reqs, txs_sent, subs,
             recv_count, recv_size, send_count, send_size, time) in data:
            yield fmt.format(id_, flags, peer, client,
                             '{:,d}'.format(reqs),
                             '{:,d}'.format(txs_sent),
                             '{:,d}'.format(subs),
                             '{:,d}'.format(recv_count),
                             '{:,d}'.format(recv_size // 1024),
                             '{:,d}'.format(send_count),
                             '{:,d}'.format(send_size // 1024),
                             time_fmt(time))

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


class Session(JSONRPC):
    '''Base class of ElectrumX JSON session protocols.

    Each session runs its tasks in asynchronous parallelism with other
    sessions.  To prevent some sessions blocking others, potentially
    long-running requests should yield.
    '''

    def __init__(self, manager, bp, env, kind):
        super().__init__()
        self.manager = manager
        self.bp = bp
        self.env = env
        self.daemon = bp.daemon
        self.coin = bp.coin
        self.kind = kind
        self.client = 'unknown'
        self.anon_logs = env.anon_logs
        self.max_send = env.max_send
        self.bandwidth_limit = env.bandwidth_limit
        self.txs_sent = 0
        self.requests = []

    def is_closing(self):
        '''True if this session is closing.'''
        return self.transport and self.transport.is_closing()

    def flags(self):
        '''Status flags.'''
        status = self.kind[0]
        if self.is_closing():
            status += 'C'
        if self.log_me:
            status += 'L'
        status += str(self.manager.session_priority(self))
        return status

    def requests_remaining(self):
        return sum(request.remaining for request in self.requests)

    def enqueue_request(self, request):
        '''Add a request to the session's list.'''
        self.requests.append(request)
        if len(self.requests) == 1:
            self.manager.enqueue_session(self)

    async def serve_requests(self):
        '''Serve requests in batches.'''
        total = 0
        errs = []
        # Process 8 items at a time
        for request in self.requests:
            try:
                initial = request.remaining
                await request.process(self)
                total += initial - request.remaining
            except asyncio.CancelledError:
                raise
            except Exception:
                # Should probably be considered a bug and fixed
                self.log_error('error handling request {}'.format(request))
                traceback.print_exc()
                errs.append(request)
            await asyncio.sleep(0)
            if total >= 8:
                break

        # Remove completed requests and re-enqueue ourself if any remain.
        self.requests = [req for req in self.requests
                         if req.remaining and not req in errs]
        if self.requests:
            self.manager.enqueue_session(self)

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        super().connection_made(transport)
        self.manager.add_session(self)

    def connection_lost(self, exc):
        '''Handle client disconnection.'''
        super().connection_lost(exc)
        if self.error_count or self.send_size >= 1024*1024:
            self.log_info('disconnected.  Sent {:,d} bytes in {:,d} messages '
                          '{:,d} errors'
                          .format(self.send_size, self.send_count,
                                  self.error_count))
        self.manager.remove_session(self)

    async def handle_request(self, method, params):
        '''Handle a request.'''
        handler = self.handlers.get(method)
        if not handler:
            self.raise_unknown_method(method)

        return await handler(params)

    def sub_count(self):
        return 0

    async def daemon_request(self, method, *args):
        '''Catch a DaemonError and convert it to an RPCError.'''
        try:
            return await getattr(self.daemon, method)(*args)
        except DaemonError as e:
            raise self.RPCError('daemon error: {}'.format(e))

    def param_to_tx_hash(self, param):
        '''Raise an RPCError if the parameter is not a valid transaction
        hash.'''
        if isinstance(param, str) and len(param) == 64:
            try:
                bytes.fromhex(param)
                return param
            except ValueError:
                pass
        raise self.RPCError('parameter should be a transaction hash: {}'
                            .format(param))

    def param_to_hash168(self, param):
        if isinstance(param, str):
            try:
                return self.coin.address_to_hash168(param)
            except:
                pass
        raise self.RPCError('param {} is not a valid address'.format(param))

    def params_to_hash168(self, params):
        if len(params) == 1:
            return self.param_to_hash168(params[0])
        raise self.RPCError('params {} should contain a single address'
                            .format(params))


class ElectrumX(Session):
    '''A TCP server that handles incoming Electrum connections.'''

    def __init__(self, *args):
        super().__init__(*args)
        self.subscribe_headers = False
        self.subscribe_height = False
        self.notified_height = None
        self.max_subs = self.env.max_session_subs
        self.hash168s = set()
        rpcs = [
            ('blockchain',
             'address.get_balance address.get_history address.get_mempool '
             'address.get_proof address.listunspent address.subscribe '
             'block.get_header block.get_chunk estimatefee headers.subscribe '
             'numblocks.subscribe relayfee transaction.broadcast '
             'transaction.get transaction.get_merkle utxo.get_address'),
            ('server',
             'banner donation_address peers.subscribe version'),
        ]
        self.handlers = {'.'.join([prefix, suffix]):
                         getattr(self, suffix.replace('.', '_'))
                         for prefix, suffixes in rpcs
                         for suffix in suffixes.split()}

    def sub_count(self):
        return len(self.hash168s)

    async def notify(self, height, touched):
        '''Notify the client about changes in height and touched addresses.

        Cache is a shared cache for this update.
        '''
        if height != self.notified_height:
            self.notified_height = height
            if self.subscribe_headers:
                payload = self.notification_payload(
                    'blockchain.headers.subscribe',
                    (self.manager.electrum_header(height), ),
                )
                self.encode_and_send_payload(payload)

            if self.subscribe_height:
                payload = self.notification_payload(
                    'blockchain.numblocks.subscribe',
                    (height, ),
                )
                self.encode_and_send_payload(payload)

        hash168_to_address = self.coin.hash168_to_address
        matches = self.hash168s.intersection(touched)
        for hash168 in matches:
            address = hash168_to_address(hash168)
            status = await self.address_status(hash168)
            payload = self.notification_payload(
                'blockchain.address.subscribe', (address, status))
            self.encode_and_send_payload(payload)

        if matches:
            self.log_info('notified of {:,d} addresses'.format(len(matches)))

    def height(self):
        '''Return the current flushed database height.'''
        return self.bp.db_height

    def current_electrum_header(self):
        '''Used as response to a headers subscription request.'''
        return self.manager.electrum_header(self.height())

    async def address_status(self, hash168):
        '''Returns status as 32 bytes.'''
        # Note history is ordered and mempool unordered in electrum-server
        # For mempool, height is -1 if unconfirmed txins, otherwise 0
        history = await self.manager.async_get_history(hash168)
        mempool = await self.manager.mempool_transactions(hash168)

        status = ''.join('{}:{:d}:'.format(hash_to_str(tx_hash), height)
                         for tx_hash, height in history)
        status += ''.join('{}:{:d}:'.format(hex_hash, -unconfirmed)
                          for hex_hash, tx_fee, unconfirmed in mempool)
        if status:
            return sha256(status.encode()).hex()
        return None

    async def tx_merkle(self, tx_hash, height):
        '''tx_hash is a hex string.'''
        hex_hashes = await self.daemon_request('block_hex_hashes', height, 1)
        block = await self.daemon_request('deserialised_block', hex_hashes[0])
        tx_hashes = block['tx']
        try:
            pos = tx_hashes.index(tx_hash)
        except ValueError:
            raise self.RPCError('tx hash {} not in block {} at height {:,d}'
                                .format(tx_hash, hex_hashes[0], height))

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

    async def unconfirmed_history(self, hash168):
        # Note unconfirmed history is unordered in electrum-server
        # Height is -1 if unconfirmed txins, otherwise 0
        mempool = await self.manager.mempool_transactions(hash168)
        return [{'tx_hash': tx_hash, 'height': -unconfirmed, 'fee': fee}
                for tx_hash, fee, unconfirmed in mempool]

    async def get_history(self, hash168):
        # Note history is ordered but unconfirmed is unordered in e-s
        history = await self.manager.async_get_history(hash168)
        conf = [{'tx_hash': hash_to_str(tx_hash), 'height': height}
                for tx_hash, height in history]

        return conf + await self.unconfirmed_history(hash168)

    def get_chunk(self, index):
        '''Return header chunk as hex.  Index is a non-negative integer.'''
        chunk_size = self.coin.CHUNK_SIZE
        next_height = self.height() + 1
        start_height = min(index * chunk_size, next_height)
        count = min(next_height - start_height, chunk_size)
        return self.bp.read_headers(start_height, count).hex()

    async def get_utxos(self, hash168):
        '''Get UTXOs asynchronously to reduce latency.'''
        def job():
            return list(self.bp.get_utxos(hash168, limit=None))
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, job)

    async def get_balance(self, hash168):
        utxos = await self.get_utxos(hash168)
        confirmed = sum(utxo.value for utxo in utxos)
        unconfirmed = self.manager.mempool_value(hash168)
        return {'confirmed': confirmed, 'unconfirmed': unconfirmed}

    async def list_unspent(self, hash168):
        return [{'tx_hash': hash_to_str(utxo.tx_hash), 'tx_pos': utxo.tx_pos,
                 'height': utxo.height, 'value': utxo.value}
                for utxo in sorted(await self.get_utxos(hash168))]

    # --- blockchain commands

    async def address_get_balance(self, params):
        hash168 = self.params_to_hash168(params)
        return await self.get_balance(hash168)

    async def address_get_history(self, params):
        hash168 = self.params_to_hash168(params)
        return await self.get_history(hash168)

    async def address_get_mempool(self, params):
        hash168 = self.params_to_hash168(params)
        return await self.unconfirmed_history(hash168)

    async def address_get_proof(self, params):
        hash168 = self.params_to_hash168(params)
        raise self.RPCError('get_proof is not yet implemented')

    async def address_listunspent(self, params):
        hash168 = self.params_to_hash168(params)
        return await self.list_unspent(hash168)

    async def address_subscribe(self, params):
        hash168 = self.params_to_hash168(params)
        if len(self.hash168s) >= self.max_subs:
            raise self.RPCError('your address subscription limit {:,d} reached'
                                .format(self.max_subs))
        result = await self.address_status(hash168)
        # add_subscription can raise so call it before adding
        self.manager.new_subscription()
        self.hash168s.add(hash168)
        return result

    async def block_get_chunk(self, params):
        index = self.params_to_non_negative_integer(params)
        return self.get_chunk(index)

    async def block_get_header(self, params):
        height = self.params_to_non_negative_integer(params)
        return self.manager.electrum_header(height)

    async def estimatefee(self, params):
        return await self.daemon_request('estimatefee', params)

    async def headers_subscribe(self, params):
        self.require_empty_params(params)
        self.subscribe_headers = True
        return self.current_electrum_header()

    async def numblocks_subscribe(self, params):
        self.require_empty_params(params)
        self.subscribe_height = True
        return self.height()

    async def relayfee(self, params):
        '''The minimum fee a low-priority tx must pay in order to be accepted
        to the daemon's memory pool.'''
        self.require_empty_params(params)
        return await self.daemon_request('relayfee')

    async def transaction_broadcast(self, params):
        '''Pass through the parameters to the daemon.

        An ugly API: current Electrum clients only pass the raw
        transaction in hex and expect error messages to be returned in
        the result field.  And the server shouldn't be doing the client's
        user interface job here.
        '''
        try:
            tx_hash = await self.daemon.sendrawtransaction(params)
            self.txs_sent += 1
            self.log_info('sent tx: {}'.format(tx_hash))
            self.manager.sent_tx(tx_hash)
            return tx_hash
        except DaemonError as e:
            error = e.args[0]
            message = error['message']
            self.log_info('sendrawtransaction: {}'.format(message))
            if 'non-mandatory-script-verify-flag' in message:
                return (
                    'Your client produced a transaction that is not accepted '
                    'by the network any more.  Please upgrade to Electrum '
                    '2.5.1 or newer.'
                )

            return (
                'The transaction was rejected by network rules.  ({})\n[{}]'
                .format(message, params[0])
            )

    async def transaction_get(self, params):
        '''Return the serialized raw transaction.'''
        # For some reason Electrum passes a height.  Don't require it
        # in anticipation it might be dropped in the future.
        if 1 <= len(params) <= 2:
            tx_hash = self.param_to_tx_hash(params[0])
            return await self.daemon_request('getrawtransaction', tx_hash)

        raise self.RPCError('params wrong length: {}'.format(params))

    async def transaction_get_merkle(self, params):
        if len(params) == 2:
            tx_hash = self.param_to_tx_hash(params[0])
            height = self.param_to_non_negative_integer(params[1])
            return await self.tx_merkle(tx_hash, height)

        raise self.RPCError('params should contain a transaction hash '
                            'and height')

    async def utxo_get_address(self, params):
        if len(params) == 2:
            tx_hash = self.param_to_tx_hash(params[0])
            index = self.param_to_non_negative_integer(params[1])
            tx_hash = hex_str_to_hash(tx_hash)
            hash168 = self.bp.get_utxo_hash168(tx_hash, index)
            if hash168:
                return self.coin.hash168_to_address(hash168)
            return None

        raise self.RPCError('params should contain a transaction hash '
                            'and index')

    # --- server commands

    async def banner(self, params):
        '''Return the server banner.'''
        self.require_empty_params(params)
        banner = 'Welcome to Electrum!'
        if self.env.banner_file:
            try:
                with codecs.open(self.env.banner_file, 'r', 'utf-8') as f:
                    banner = f.read()
            except Exception as e:
                self.log_error('reading banner file {}: {}'
                               .format(self.env.banner_file, e))
            else:
                network_info = await self.daemon.getnetworkinfo()
                version = network_info['version']
                major, minor = divmod(version, 1000000)
                minor, revision = divmod(minor, 10000)
                revision //= 100
                version = '{:d}.{:d}.{:d}'.format(major, minor, revision)
                subversion = network_info['subversion']
                banner = (banner.replace('$VERSION', VERSION)
                          .replace('$DAEMON_VERSION', version)
                          .replace('$DAEMON_SUBVERSION', subversion))

        return banner

    async def donation_address(self, params):
        '''Return the donation address as a string.

        If none is specified return the empty string.
        '''
        self.require_empty_params(params)
        return self.env.donation_address

    async def peers_subscribe(self, params):
        '''Returns the peer (ip, host, ports) tuples.

        Despite the name electrum-server does not treat this as a
        subscription.
        '''
        self.require_empty_params(params)
        return list(self.manager.irc_peers().values())

    async def version(self, params):
        '''Return the server version as a string.'''
        if params:
            self.client = str(params[0])[:15]
        if len(params) > 1:
            self.protocol_version = params[1]
        return VERSION


class LocalRPC(Session):
    '''A local TCP RPC server for querying status.'''

    def __init__(self, *args):
        super().__init__(*args)
        cmds = 'disconnect getinfo groups log peers sessions'.split()
        self.handlers = {cmd: getattr(self.manager, 'rpc_{}'.format(cmd))
                         for cmd in cmds}
        self.client = 'RPC'
        self.max_send = 5000000
