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
from lib.jsonrpc import JSONRPC
from lib.tx import Deserializer
import lib.util as util
from server.block_processor import BlockProcessor
from server.daemon import DaemonError
from server.irc import IRC
from server.version import VERSION


class MemPool(util.LoggedClass):
    '''Representation of the daemon's mempool.

    Updated regularly in caught-up state.  Goal is to enable efficient
    response to the value() and transactions() calls.

    To that end we maintain the following maps:

       tx_hash -> [txin_pairs, txout_pairs, unconfirmed]
       hash168 -> set of all tx hashes in which the hash168 appears

    A pair is a (hash168, value) tuple.  Unconfirmed is true if any of the
    tx's txins are unconfirmed.  tx hashes are hex strings.
    '''

    def __init__(self, daemon, coin, db, manager):
        super().__init__()
        self.daemon = daemon
        self.coin = coin
        self.db = db
        self.manager = manager
        self.txs = {}
        self.hash168s = defaultdict(set)  # None can be a key
        self.count = -1

    async def main_loop(self, caught_up):
        '''Asynchronously maintain mempool status with daemon.

        Waits until the caught up event is signalled.'''
        await caught_up.wait()
        self.logger.info('maintaining state with daemon...')
        while True:
            try:
                await self.update()
                await asyncio.sleep(5)
            except DaemonError as e:
                self.logger.info('ignoring daemon error: {}'.format(e))

    async def update(self):
        '''Update state given the current mempool to the passed set of hashes.

        Remove transactions that are no longer in our mempool.
        Request new transactions we don't have then add to our mempool.
        '''
        hex_hashes = set(await self.daemon.mempool_hashes())
        touched = set()
        missing_utxos = []

        initial = self.count < 0
        if initial:
            self.logger.info('beginning import of {:,d} mempool txs'
                             .format(len(hex_hashes)))

        # Remove gone items
        gone = set(self.txs).difference(hex_hashes)
        for hex_hash in gone:
            txin_pairs, txout_pairs, unconfirmed = self.txs.pop(hex_hash)
            hash168s = set(hash168 for hash168, value in txin_pairs)
            hash168s.update(hash168 for hash168, value in txout_pairs)
            for hash168 in hash168s:
                self.hash168s[hash168].remove(hex_hash)
                if not self.hash168s[hash168]:
                    del self.hash168s[hash168]
            touched.update(hash168s)

        # Get the raw transactions for the new hashes.  Ignore the
        # ones the daemon no longer has (it will return None).  Put
        # them into a dictionary of hex hash to deserialized tx.
        hex_hashes.difference_update(self.txs)
        raw_txs = await self.daemon.getrawtransactions(hex_hashes)
        if initial:
            self.logger.info('analysing {:,d} mempool txs'
                             .format(len(raw_txs)))
        new_txs = {hex_hash: Deserializer(raw_tx).read_tx()
                   for hex_hash, raw_tx in zip(hex_hashes, raw_txs) if raw_tx}
        del raw_txs, hex_hashes

        # The mempool is unordered, so process all outputs first so
        # that looking for inputs has full info.
        script_hash168 = self.coin.hash168_from_script()
        db_utxo_lookup = self.db.db_utxo_lookup

        def txout_pair(txout):
            return (script_hash168(txout.pk_script), txout.value)

        for n, (hex_hash, tx) in enumerate(new_txs.items()):
            # Yield to process e.g. signals
            if n % 20 == 0:
                await asyncio.sleep(0)
            txout_pairs = [txout_pair(txout) for txout in tx.outputs]
            self.txs[hex_hash] = (None, txout_pairs, None)

        def txin_info(txin):
            hex_hash = hash_to_str(txin.prev_hash)
            mempool_entry = self.txs.get(hex_hash)
            if mempool_entry:
                return mempool_entry[1][txin.prev_idx], True
            pair = db_utxo_lookup(txin.prev_hash, txin.prev_idx)
            return pair, False

        if initial:
            next_log = time.time()
            self.logger.info('processed outputs, now examining inputs. '
                             'This can take some time...')

        # Now add the inputs
        for n, (hex_hash, tx) in enumerate(new_txs.items()):
            # Yield to process e.g. signals
            await asyncio.sleep(0)

            if initial and time.time() > next_log:
                next_log = time.time() + 20
                self.logger.info('{:,d} done ({:d}%)'
                                 .format(n, int(n / len(new_txs) * 100)))

            txout_pairs = self.txs[hex_hash][1]
            try:
                infos = (txin_info(txin) for txin in tx.inputs)
                txin_pairs, unconfs = zip(*infos)
            except self.db.MissingUTXOError:
                # Drop this TX.  If other mempool txs depend on it
                # it's harmless - next time the mempool is refreshed
                # they'll either be cleaned up or the UTXOs will no
                # longer be missing.
                del self.txs[hex_hash]
                continue
            self.txs[hex_hash] = (txin_pairs, txout_pairs, any(unconfs))

            # Update touched and self.hash168s for the new tx
            for hash168, value in txin_pairs:
                self.hash168s[hash168].add(hex_hash)
                touched.add(hash168)
            for hash168, value in txout_pairs:
                self.hash168s[hash168].add(hex_hash)
                touched.add(hash168)

        if missing_utxos:
            self.logger.info('{:,d} txs had missing UTXOs; probably the '
                             'daemon is a block or two ahead of us.'
                             .format(len(missing_utxos)))
            first = ', '.join('{} / {:,d}'.format(hash_to_str(txin.prev_hash),
                                                  txin.prev_idx)
                              for txin in sorted(missing_utxos)[:3])
            self.logger.info('first ones are {}'.format(first))

        self.count += 1
        if self.count % 25 == 0 or gone:
            self.count = 0
            self.logger.info('{:,d} txs touching {:,d} addresses'
                             .format(len(self.txs), len(self.hash168s)))

        self.manager.notify(touched)

    def transactions(self, hash168):
        '''Generate (hex_hash, tx_fee, unconfirmed) tuples for mempool
        entries for the hash168.

        unconfirmed is True if any txin is unconfirmed.
        '''
        for hex_hash in self.hash168s[hash168]:
            txin_pairs, txout_pairs, unconfirmed = self.txs[hex_hash]
            tx_fee = (sum(v for hash168, v in txin_pairs)
                      - sum(v for hash168, v in txout_pairs))
            yield (hex_hash, tx_fee, unconfirmed)

    def value(self, hash168):
        '''Return the unconfirmed amount in the mempool for hash168.

        Can be positive or negative.
        '''
        value = 0
        for hex_hash in self.hash168s[hash168]:
            txin_pairs, txout_pairs, unconfirmed = self.txs[hex_hash]
            value -= sum(v for h168, v in txin_pairs if h168 == hash168)
            value += sum(v for h168, v in txout_pairs if h168 == hash168)
        return value


class ServerManager(util.LoggedClass):
    '''Manages the client servers, a mempool, and a block processor.

    Servers are started immediately the block processor first catches
    up with the daemon.
    '''

    BANDS = 5

    class NotificationRequest(object):
        def __init__(self, fn_call):
            self.fn_call = fn_call

        def remaining(self):
            return 0

        async def process(self, limit):
            await self.fn_call()
            return 0

    def __init__(self, env):
        super().__init__()
        self.start = time.time()
        self.bp = BlockProcessor(self, env)
        self.mempool = MemPool(self.bp.daemon, env.coin, self.bp, self)
        self.irc = IRC(env)
        self.env = env
        self.servers = []
        self.sessions = {}
        self.groups = defaultdict(set)
        self.txs_sent = 0
        self.next_log_sessions = 0
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
        self.logger.info('session timeout: {:,d} seconds'
                         .format(env.session_timeout))
        self.logger.info('session bandwidth limit {:,d} bytes'
                         .format(env.bandwidth_limit))
        self.logger.info('max response size {:,d} bytes'.format(env.max_send))
        self.logger.info('max subscriptions across all sessions: {:,d}'
                         .format(self.max_subs))
        self.logger.info('max subscriptions per session: {:,d}'
                         .format(env.max_session_subs))

    def mempool_transactions(self, hash168):
        '''Generate (hex_hash, tx_fee, unconfirmed) tuples for mempool
        entries for the hash168.

        unconfirmed is True if any txin is unconfirmed.
        '''
        return self.mempool.transactions(hash168)

    def mempool_value(self, hash168):
        '''Return the unconfirmed amount in the mempool for hash168.

        Can be positive or negative.
        '''
        return self.mempool.value(hash168)

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
        return (bisect_left(self.bands, session.bandwidth_used)
                + bisect_left(self.bands, group_bandwidth) + 1) // 2

    async def enqueue_delayed_sessions(self):
        now = time.time()
        keep = []
        for pair in self.delayed_sessions:
            timeout, session = pair
            if timeout <= now:
                self.queue.put_nowait(session)
            else:
                keep.append(pair)
        self.delayed_sessions = keep
        await asyncio.sleep(1)

    def enqueue_session(self, session):
        # Might have disconnected whilst waiting
        if not session in self.sessions:
            return
        priority = self.session_priority(session)
        item = (priority, self.next_queue_id, session)
        self.next_queue_id += 1

        secs = priority - self.BANDS
        if secs >= 0:
            session.log_info('delaying response {:d}s'.format(secs))
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
        add_future(self.bp.main_loop())
        add_future(self.bp.prefetcher.main_loop())
        add_future(self.mempool.main_loop(self.bp.event))
        add_future(self.irc.start(self.bp.event))
        add_future(self.start_servers(self.bp.event))
        add_future(self.enqueue_delayed_sessions())
        for n in range(4):
            add_future(self.serve_requests())

        for future in asyncio.as_completed(self.futures):
            try:
                await future  # Note: future is not one of self.futures
            except asyncio.CancelledError:
                break
        await self.shutdown()

    async def start_server(self, kind, *args, **kw_args):
        loop = asyncio.get_event_loop()
        protocol_class = LocalRPC if kind == 'RPC' else ElectrumX
        protocol = partial(protocol_class, self, self.bp, self.env, kind)
        server = loop.create_server(protocol, *args, **kw_args)

        host, port = args[:2]
        try:
            self.servers.append(await server)
        except Exception as e:
            self.logger.error('{} server failed to listen on {}:{:d} :{}'
                              .format(kind, host, port, e))
        else:
            self.logger.info('{} server listening on {}:{:d}'
                             .format(kind, host, port))

    async def start_servers(self, caught_up):
        '''Connect to IRC and start listening for incoming connections.

        Only connect to IRC if enabled.  Start listening on RCP, TCP
        and SSL ports only if the port wasn't pecified.  Waits for the
        caught_up event to be signalled.
        '''
        await caught_up.wait()
        env = self.env

        if env.rpc_port is not None:
            await self.start_server('RPC', 'localhost', env.rpc_port)

        if env.tcp_port is not None:
            await self.start_server('TCP', env.host, env.tcp_port)

        if env.ssl_port is not None:
            # Python 3.5.3: use PROTOCOL_TLS
            sslc = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            sslc.load_cert_chain(env.ssl_certfile, keyfile=env.ssl_keyfile)
            await self.start_server('SSL', env.host, env.ssl_port, ssl=sslc)

    def notify(self, touched):
        '''Notify sessions about height changes and touched addresses.'''
        # Invalidate caches
        hc = self.history_cache
        for hash168 in set(hc).intersection(touched):
            del hc[hash168]
        if self.bp.db_height != self.height:
            self.height = self.bp.db_height
            self.header_cache.clear()

        for session in self.sessions:
            if isinstance(session, ElectrumX):
                fn_call = partial(session.notify, self.bp.db_height, touched)
                session.enqueue_request(self.NotificationRequest(fn_call))
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
            raise self.RPCError('height {:,d} out of range'.format(height))
        if height in self.header_cache:
            return self.header_cache[height]
        header = self.bp.read_headers(height, 1)
        header = self.env.coin.electrum_header(header, height)
        self.header_cache[height] = header
        return header

    async def async_get_history(self, hash168):
        if hash168 in self.history_cache:
            return self.history_cache[hash168]

        # History DoS limit.  Each element of history is about 99
        # bytes when encoded as JSON.  This limits resource usage on
        # bloated history requests, and uses a smaller divisor so
        # large requests are logged before refusing them.
        limit = self.env.max_send // 97
        # Python 3.6: use async generators; update callers
        history = []
        for item in self.bp.get_history(hash168, limit=limit):
            history.append(item)
            if len(history) % 100 == 0:
                await asyncio.sleep(0)

        self.history_cache[hash168] = history
        return history

    async def shutdown(self):
        '''Call to shutdown the servers.  Returns when done.'''
        self.bp.shutdown()
        # Don't cancel the block processor main loop - let it close itself
        for future in self.futures[1:]:
            future.cancel()
        for server in self.servers:
            server.close()
            await server.wait_closed()
        self.servers = [] # So add_session closes new sessions
        while not all(future.done() for future in self.futures):
            await asyncio.sleep(0)
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
        await asyncio.sleep(1)

    def add_session(self, session):
        # Some connections are acknowledged after the servers are closed
        if not self.servers:
            return
        now = time.time()
        if now > self.next_stale_check:
            self.next_stale_check = now + 60
            self.clear_stale_sessions()
        group = self.groups[int(session.start - self.start) // 60]
        group.add(session)
        self.sessions[session] = group
        session.log_info('connection from {}, {:,d} total'
                         .format(session.peername(), len(self.sessions)))

    def remove_session(self, session):
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

        # Clear out empty groups
        for key in [k for k, v in self.groups.items() if not v]:
            del self.groups[key]

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
        yield fmt.format('ID', 'Sessions', 'Bw Qta KB', 'Reqs', 'Txs', 'Subs',
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

    async def rpc_numsessions(self, params):
        return self.session_count()

    async def rpc_peers(self, params):
        return self.irc.peers

    async def rpc_numpeers(self, params):
        return len(self.irc.peers)


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
        return sum(request.remaining() for request in self.requests)

    def enqueue_request(self, request):
        '''Add a request to the session's list.'''
        if not self.requests:
            self.manager.enqueue_session(self)
        self.requests.append(request)

    async def serve_requests(self):
        '''Serve requests in batches.'''
        done_reqs = 0
        done_jobs = 0
        limit = 4
        for request in self.requests:
            try:
                done_jobs += await request.process(limit - done_jobs)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Getting here should probably be considered a bug and fixed
                self.log_error('error handling request {}'.format(request))
                traceback.print_exc()
                done_reqs += 1
            else:
                if not request.remaining():
                    done_reqs += 1
            if done_jobs >= limit:
                break

        # Remove completed requests and re-enqueue ourself if any remain.
        if done_reqs:
            self.requests = self.requests[done_reqs:]
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
        mempool = self.manager.mempool_transactions(hash168)

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

    def unconfirmed_history(self, hash168):
        # Note unconfirmed history is unordered in electrum-server
        # Height is -1 if unconfirmed txins, otherwise 0
        mempool = self.manager.mempool_transactions(hash168)
        return [{'tx_hash': tx_hash, 'height': -unconfirmed, 'fee': fee}
                for tx_hash, fee, unconfirmed in mempool]

    async def get_history(self, hash168):
        # Note history is ordered but unconfirmed is unordered in e-s
        history = await self.manager.async_get_history(hash168)
        conf = [{'tx_hash': hash_to_str(tx_hash), 'height': height}
                for tx_hash, height in history]

        return conf + self.unconfirmed_history(hash168)

    def get_chunk(self, index):
        '''Return header chunk as hex.  Index is a non-negative integer.'''
        chunk_size = self.coin.CHUNK_SIZE
        next_height = self.height() + 1
        start_height = min(index * chunk_size, next_height)
        count = min(next_height - start_height, chunk_size)
        return self.bp.read_headers(start_height, count).hex()

    async def get_utxos(self, hash168):
        # Python 3.6: use async generators; update callers
        utxos = []
        for utxo in self.bp.get_utxos(hash168, limit=None):
            utxos.append(utxo)
            if len(utxos) % 25 == 0:
                await asyncio.sleep(0)
        return utxos

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
        return self.unconfirmed_history(hash168)

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
            self.manager.txs_sent += 1
            self.log_info('sent tx: {}'.format(tx_hash))
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
        cmds = ('disconnect getinfo groups log numpeers numsessions '
                'peers sessions'
                .split())
        self.handlers = {cmd: getattr(self.manager, 'rpc_{}'.format(cmd))
                         for cmd in cmds}
        self.client = 'RPC'
        self.max_send = 5000000
