# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

import asyncio
import codecs
import json
import os
import _socket
import ssl
import time
from bisect import bisect_left
from collections import defaultdict
from functools import partial

import pylru

from lib.jsonrpc import JSONRPC, RPCError, RequestBase
from lib.hash import sha256, double_sha256, hash_to_str, hex_str_to_hash
import lib.util as util
from server.block_processor import BlockProcessor
from server.irc import IRC
from server.session import LocalRPC, ElectrumX
from server.mempool import MemPool
from server.version import VERSION


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
        self.coin = env.coin
        self.bp = BlockProcessor(env)
        self.daemon = self.bp.daemon
        self.mempool = MemPool(self.bp)
        self.irc = IRC(env)
        self.env = env
        self.servers = {}
        # Map of session to the key of its list in self.groups
        self.sessions = {}
        self.groups = defaultdict(list)
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
        self.cache_height = 0
        self.futures = []
        env.max_send = max(350000, env.max_send)
        self.setup_bands()
        # Set up the RPC request handlers
        cmds = 'disconnect getinfo groups log peers reorg sessions'.split()
        self.rpc_handlers = {cmd: getattr(self, 'rpc_' + cmd) for cmd in cmds}
        # Set up the ElectrumX request handlers
        rpcs = [
            ('blockchain',
             'address.get_balance address.get_history address.get_mempool '
             'address.get_proof address.listunspent '
             'block.get_header block.get_chunk estimatefee relayfee '
             'transaction.get transaction.get_merkle utxo.get_address'),
            ('server',
             'banner donation_address peers.subscribe version'),
        ]
        self.electrumx_handlers = {'.'.join([prefix, suffix]):
                                   getattr(self, suffix.replace('.', '_'))
                                   for prefix, suffixes in rpcs
                                   for suffix in suffixes.split()}

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
        gid = self.sessions[session]
        group_bandwidth = sum(s.bandwidth_used for s in self.groups[gid])
        return 1 + (bisect_left(self.bands, session.bandwidth_used)
                    + bisect_left(self.bands, group_bandwidth)) // 2

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
        '''Controller main loop.'''
        def add_future(coro):
            self.futures.append(asyncio.ensure_future(coro))

        # shutdown() assumes bp.main_loop() is first
        add_future(self.bp.main_loop())
        add_future(self.bp.prefetcher.main_loop())
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
        _socket.setdefaulttimeout(5)
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
            for hashX in set(hc).intersection(touched):
                del hc[hashX]
            if self.bp.db_height != self.cache_height:
                self.cache_height = self.bp.db_height
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
            raise RPCError('height {:,d} out of range'.format(height))
        if height in self.header_cache:
            return self.header_cache[height]
        header = self.bp.read_headers(height, 1)
        header = self.coin.electrum_header(header, height)
        self.header_cache[height] = header
        return header

    async def shutdown(self):
        '''Call to shutdown everything.  Returns when done.'''
        self.state = self.SHUTTING_DOWN
        self.bp.on_shutdown()
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
        gid = int(session.start - self.start) // 900
        self.groups[gid].append(session)
        self.sessions[session] = gid
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
            gid = self.sessions.pop(session)
            assert gid in self.groups
            self.groups[gid].remove(session)
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
        gids = [gid for gid, l in self.groups.items() if len(l) <= 4
                and sum(session.bandwidth_used for session in l) < 10000]
        if len(gids) > 1:
            sessions = sum([self.groups[gid] for gid in gids], [])
            new_gid = max(gids)
            for gid in gids:
                del self.groups[gid]
            for session in sessions:
                self.sessions[session] = new_gid
            self.groups[new_gid] = sessions

    def session_count(self):
        '''The number of connections that we've sent something to.'''
        return len(self.sessions)

    def server_summary(self):
        '''A one-line summary of server state.'''
        return {
            'daemon_height': self.daemon.cached_height(),
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
        for gid in sorted(self.groups.keys()):
            sessions = self.groups[gid]
            result.append([gid,
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

    def lookup_session(self, session_id):
        try:
            session_id = int(session_id)
        except:
            pass
        else:
            for session in self.sessions:
                if session.id_ == session_id:
                    return session
        return None

    def for_each_session(self, session_ids, operation):
        if not isinstance(session_ids, list):
            raise RPCError('expected a list of session IDs')

        result = []
        for session_id in session_ids:
            session = self.lookup_session(session_id)
            if session:
                result.append(operation(session))
            else:
                result.append('unknown session: {}'.format(session_id))
        return result

    # Local RPC command handlers

    async def rpc_disconnect(self, session_ids):
        '''Disconnect sesssions.

        session_ids: array of session IDs
        '''
        return self.for_each_session(session_ids, self.close_session)

    async def rpc_log(self, session_ids):
        '''Toggle logging of sesssions.

        session_ids: array of session IDs
        '''
        return self.for_each_session(session_ids, self.toggle_logging)

    async def rpc_getinfo(self):
        '''Return summary information about the server process.'''
        return self.server_summary()

    async def rpc_groups(self):
        '''Return statistics about the session groups.'''
        return self.group_data()

    async def rpc_sessions(self):
        '''Return statistics about connected sessions.'''
        return self.session_data(for_log=False)

    async def rpc_peers(self):
        '''Return a list of server peers, currently taken from IRC.'''
        return self.irc.peers

    async def rpc_reorg(self, count=3):
        '''Force a reorg of the given number of blocks.

        count: number of blocks to reorg (default 3)
        '''
        count = self.non_negative_integer(count)
        if not self.bp.force_chain_reorg(count):
            raise RPCError('still catching up with daemon')
        return 'scheduled a reorg of {:,d} blocks'.format(count)

    # Helpers for RPC "blockchain" command handlers

    def address_to_hashX(self, address):
        if isinstance(address, str):
            try:
                return self.coin.address_to_hashX(address)
            except:
                pass
        raise RPCError('{} is not a valid address'.format(address))

    def to_tx_hash(self, value):
        '''Raise an RPCError if the value is not a valid transaction
        hash.'''
        if isinstance(value, str) and len(value) == 64:
            try:
                bytes.fromhex(value)
                return value
            except ValueError:
                pass
        raise RPCError('{} should be a transaction hash'.format(value))

    def non_negative_integer(self, value):
        '''Return param value it is or can be converted to a non-negative
        integer, otherwise raise an RPCError.'''
        try:
            value = int(value)
            if value >= 0:
                return value
        except ValueError:
            pass
        raise RPCError('{} should be a non-negative integer'.format(value))

    async def daemon_request(self, method, *args):
        '''Catch a DaemonError and convert it to an RPCError.'''
        try:
            return await getattr(self.daemon, method)(*args)
        except DaemonError as e:
            raise RPCError('daemon error: {}'.format(e))

    async def new_subscription(self, address):
        if self.subscription_count >= self.max_subs:
            raise RPCError('server subscription limit {:,d} reached'
                           .format(self.max_subs))
        self.subscription_count += 1
        hashX = self.address_to_hashX(address)
        status = await self.address_status(hashX)
        return hashX, status

    async def tx_merkle(self, tx_hash, height):
        '''tx_hash is a hex string.'''
        hex_hashes = await self.daemon_request('block_hex_hashes', height, 1)
        block = await self.daemon_request('deserialised_block', hex_hashes[0])
        tx_hashes = block['tx']
        try:
            pos = tx_hashes.index(tx_hash)
        except ValueError:
            raise RPCError('tx hash {} not in block {} at height {:,d}'
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

        loop = asyncio.get_event_loop()
        history = await loop.run_in_executor(None, job)
        self.history_cache[hashX] = history
        return history

    async def confirmed_and_unconfirmed_history(self, hashX):
        # Note history is ordered but unconfirmed is unordered in e-s
        history = await self.get_history(hashX)
        conf = [{'tx_hash': hash_to_str(tx_hash), 'height': height}
                for tx_hash, height in history]
        return conf + await self.unconfirmed_history(hashX)

    async def address_status(self, hashX):
        '''Returns status as 32 bytes.'''
        # Note history is ordered and mempool unordered in electrum-server
        # For mempool, height is -1 if unconfirmed txins, otherwise 0
        history = await self.get_history(hashX)
        mempool = await self.mempool_transactions(hashX)

        status = ''.join('{}:{:d}:'.format(hash_to_str(tx_hash), height)
                         for tx_hash, height in history)
        status += ''.join('{}:{:d}:'.format(hex_hash, -unconfirmed)
                          for hex_hash, tx_fee, unconfirmed in mempool)
        if status:
            return sha256(status.encode()).hex()
        return None

    async def get_utxos(self, hashX):
        '''Get UTXOs asynchronously to reduce latency.'''
        def job():
            return list(self.bp.get_utxos(hashX, limit=None))
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, job)

    def get_chunk(self, index):
        '''Return header chunk as hex.  Index is a non-negative integer.'''
        chunk_size = self.coin.CHUNK_SIZE
        next_height = self.bp.db_height + 1
        start_height = min(index * chunk_size, next_height)
        count = min(next_height - start_height, chunk_size)
        return self.bp.read_headers(start_height, count).hex()

    # Client RPC "blockchain" command handlers

    async def address_get_balance(self, address):
        '''Return the confirmed and unconfirmed balance of an address.'''
        hashX = self.address_to_hashX(address)
        return await self.get_balance(hashX)

    async def address_get_history(self, address):
        '''Return the confirmed and unconfirmed history of an address.'''
        hashX = self.address_to_hashX(address)
        return await self.confirmed_and_unconfirmed_history(hashX)

    async def address_get_mempool(self, address):
        '''Return the mempool transactions touching an address.'''
        hashX = self.address_to_hashX(address)
        return await self.unconfirmed_history(hashX)

    async def address_get_proof(self, address):
        '''Return the UTXO proof of an address.'''
        hashX = self.address_to_hashX(address)
        raise RPCError('address.get_proof is not yet implemented')

    async def address_listunspent(self, address):
        '''Return the list of UTXOs of an address.'''
        hashX = self.address_to_hashX(address)
        return [{'tx_hash': hash_to_str(utxo.tx_hash), 'tx_pos': utxo.tx_pos,
                 'height': utxo.height, 'value': utxo.value}
                for utxo in sorted(await self.get_utxos(hashX))]

    async def block_get_chunk(self, index):
        '''Return a chunk of block headers.

        index: the chunk index'''
        index = self.non_negative_integer(index)
        return self.get_chunk(index)

    async def block_get_header(self, height):
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

    async def relayfee(self):
        '''The minimum fee a low-priority tx must pay in order to be accepted
        to the daemon's memory pool.'''
        return await self.daemon_request('relayfee')

    async def transaction_get(self, tx_hash, height=None):
        '''Return the serialized raw transaction given its hash

        tx_hash: the transaction hash as a hexadecimal string
        height: ignored, do not use
        '''
        # For some reason Electrum passes a height.  We don't require
        # it in anticipation it might be dropped in the future.
        tx_hash = self.to_tx_hash(tx_hash)
        return await self.daemon_request('getrawtransaction', tx_hash)

    async def transaction_get_merkle(self, tx_hash, height):
        '''Return the markle tree to a confirmed transaction given its hash
        and height.

        tx_hash: the transaction hash as a hexadecimal string
        height: the height of the block it is in
        '''
        tx_hash = self.to_tx_hash(tx_hash)
        height = self.non_negative_integer(height)
        return await self.tx_merkle(tx_hash, height)

    async def utxo_get_address(self, tx_hash, index):
        '''Returns the address sent to in a UTXO, or null if the UTXO
        cannot be found.

        tx_hash: the transaction hash of the UTXO
        index: the index of the UTXO in the transaction'''
        # Used only for electrum client command-line requests.  We no
        # longer index by address, so need to request the raw
        # transaction.  So it works for any TXO not just UTXOs.
        tx_hash = self.to_tx_hash(tx_hash)
        index = self.non_negative_integer(index)
        raw_tx = await self.daemon_request('getrawtransaction', tx_hash)
        if not raw_tx:
            return None
        raw_tx = bytes.fromhex(raw_tx)
        deserializer = self.coin.deserializer()
        tx, tx_hash = deserializer(raw_tx).read_tx()
        if index >= len(tx.outputs):
            return None
        return self.coin.address_from_script(tx.outputs[index].pk_script)

    # Client RPC "server" command handlers

    async def banner(self):
        '''Return the server banner text.'''
        banner = 'Welcome to Electrum!'
        if self.env.banner_file:
            try:
                with codecs.open(self.env.banner_file, 'r', 'utf-8') as f:
                    banner = f.read()
            except Exception as e:
                self.log_error('reading banner file {}: {}'
                               .format(self.env.banner_file, e))
            else:
                network_info = await self.daemon_request('getnetworkinfo')
                version = network_info['version']
                major, minor = divmod(version, 1000000)
                minor, revision = divmod(minor, 10000)
                revision //= 100
                version = '{:d}.{:d}.{:d}'.format(major, minor, revision)
                for pair in [
                    ('$VERSION', VERSION),
                    ('$DAEMON_VERSION', version),
                    ('$DAEMON_SUBVERSION', network_info['subversion']),
                    ('$DONATION_ADDRESS', self.env.donation_address),
                ]:
                    banner = banner.replace(*pair)

        return banner

    async def donation_address(self):
        '''Return the donation address as a string, empty if there is none.'''
        return self.env.donation_address

    async def peers_subscribe(self):
        '''Returns the server peers as a list of (ip, host, ports) tuples.

        Despite the name this is not currently treated as a subscription.'''
        return list(self.irc.peers.values())

    async def version(self, client_name=None, protocol_version=None):
        '''Returns the server version as a string.

        client_name: a string identifying the client
        protocol_version: the protocol version spoken by the client
        '''
        if client_name:
            self.client = str(client_name)[:15]
        if protocol_version is not None:
            self.protocol_version = protocol_version
        return VERSION
