
import json
import math
import os
import ssl
import time
from electrumx.lib.merkle import MerkleCache

from electrumx.lib.text import sessions_lines
from functools import partial
from ipaddress import IPv4Address, IPv6Address
from collections import defaultdict
from electrumx.server.peers import PeerManager


from aiorpcx import (
    serve_rs, serve_ws,
    TaskGroup, RPCError,  sleep, Event,
)

import pylru

import electrumx
import electrumx.lib.util as util
from electrumx.lib.hash import (hash_to_hex_str, Base58Error)
from electrumx.server.daemon import DaemonError

from electrumx.server.session.session import SessionBase, SessionGroup, SessionReferences, BAD_REQUEST, DAEMON_ERROR, non_negative_integer

class LocalRPC(SessionBase):
    '''A local TCP RPC server session.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = 'RPC'
        self.connection.max_response_size = 0

    def protocol_version_string(self):
        return 'RPC'

class SessionManager:
    '''Holds global state about all sessions.'''

    def __init__(self, env, db, bp, daemon, mempool, shutdown_event):
        env.max_send = max(350000, env.max_send)
        self.env = env
        self.db = db
        self.bp = bp
        self.daemon = daemon
        self.mempool = mempool
        self.peer_mgr = PeerManager(env, db)
        self.shutdown_event = shutdown_event
        self.logger = util.class_logger(__name__, self.__class__.__name__)
        self.servers = {}           # service->server
        self.sessions = {}          # session->iterable of its SessionGroups
        self.session_groups = {}    # group name->SessionGroup instance
        self.txs_sent = 0
        self.start_time = time.time()
        self._method_counts = defaultdict(int)
        self._reorg_count = 0
        self._history_cache = pylru.lrucache(1000)
        self._history_lookups = 0
        self._history_hits = 0
        self._tx_hashes_cache = pylru.lrucache(1000)
        self._tx_hashes_lookups = 0
        self._tx_hashes_hits = 0
        # Really a MerkleCache cache
        self._merkle_cache = pylru.lrucache(1000)
        self._merkle_lookups = 0
        self._merkle_hits = 0
        self.notified_height = None
        self.hsub_results = None
        self._task_group = TaskGroup()
        self._sslc = None
        # Event triggered when electrumx is listening for incoming requests.
        self.server_listening = Event()
        self.session_event = Event()

        # Set up the RPC request handlers
        cmds = ('add_peer daemon_url disconnect getinfo groups log peers '
                'query reorg sessions stop'.split())
        LocalRPC.request_handlers = {cmd: getattr(self, 'rpc_' + cmd)
                                     for cmd in cmds}

    def _ssl_context(self):
        if self._sslc is None:
            self._sslc = ssl.SSLContext(ssl.PROTOCOL_TLS)
            self._sslc.options |= ssl.OP_NO_TLSv1
            self._sslc.options |= ssl.OP_NO_TLSv1_1
            self._sslc.load_cert_chain(self.env.ssl_certfile, keyfile=self.env.ssl_keyfile)
        return self._sslc

    async def _start_servers(self, services):
        for service in services:
            kind = service.protocol.upper()
            if service.protocol in self.env.SSL_PROTOCOLS:
                sslc = self._ssl_context()
            else:
                sslc = None
            if service.protocol == 'rpc':
                session_class = LocalRPC
            else:
                session_class = self.env.coin.SESSIONCLS
            if service.protocol in ('ws', 'wss'):
                serve = serve_ws
            else:
                serve = serve_rs
            # FIXME: pass the service not the kind
            session_factory = partial(session_class, self, self.db, self.mempool,
                                      self.peer_mgr, kind)
            host = None if service.host == 'all_interfaces' else str(service.host)
            try:
                self.servers[service] = await serve(session_factory, host,
                                                    service.port, ssl=sslc)
            except OSError as e:    # don't suppress CancelledError
                self.logger.error(f'{kind} server failed to listen on {service.address}: {e}')
            else:
                self.logger.info(f'{kind} server listening on {service.address}')

    async def _start_external_servers(self):
        '''Start listening on TCP and SSL ports, but only if the respective
        port was given in the environment.
        '''
        await self._start_servers(service for service in self.env.services
                                  if service.protocol != 'rpc')
        self.server_listening.set()

    async def _stop_servers(self, services):
        '''Stop the servers of the given protocols.'''
        server_map = {service: self.servers.pop(service)
                      for service in set(services).intersection(self.servers)}
        # Close all before waiting
        for service, server in server_map.items():
            self.logger.info(f'closing down server for {service}')
            server.close()
        # No value in doing these concurrently
        for server in server_map.values():
            await server.wait_closed()

    async def _manage_servers(self):
        paused = False
        max_sessions = self.env.max_sessions
        low_watermark = max_sessions * 19 // 20
        while True:
            await self.session_event.wait()
            self.session_event.clear()
            if not paused and len(self.sessions) >= max_sessions:
                self.logger.info(f'maximum sessions {max_sessions:,d} '
                                 f'reached, stopping new connections until '
                                 f'count drops to {low_watermark:,d}')
                await self._stop_servers(service for service in self.servers
                                         if service.protocol != 'rpc')
                paused = True
            # Start listening for incoming connections if paused and
            # session count has fallen
            if paused and len(self.sessions) <= low_watermark:
                self.logger.info('resuming listening for incoming connections')
                await self._start_external_servers()
                paused = False

    async def _log_sessions(self):
        '''Periodically log sessions.'''
        log_interval = self.env.log_sessions
        if log_interval:
            while True:
                await sleep(log_interval)
                data = self._session_data(for_log=True)
                for line in sessions_lines(data):
                    self.logger.info(line)
                self.logger.info(json.dumps(self._get_info()))

    async def _disconnect_sessions(self, sessions, reason, *, force_after=1.0):
        if sessions:
            session_ids = ', '.join(str(session.session_id) for session in sessions)
            self.logger.info(f'{reason} session ids {session_ids}')
            for session in sessions:
                await self._task_group.spawn(session.close(force_after=force_after))

    async def _clear_stale_sessions(self):
        '''Cut off sessions that haven't done anything for 10 minutes.'''
        while True:
            await sleep(60)
            stale_cutoff = time.time() - self.env.session_timeout
            stale_sessions = [session for session in self.sessions
                              if session.last_recv < stale_cutoff]
            await self._disconnect_sessions(stale_sessions, 'closing stale')
            del stale_sessions

    async def _handle_chain_reorgs(self):
        '''Clear caches on chain reorgs.'''
        while True:
            await self.bp.backed_up_event.wait()
            self.logger.info(f'reorg signalled; clearing tx_hashes and merkle caches')
            self._reorg_count += 1
            self._tx_hashes_cache.clear()
            self._merkle_cache.clear()

    async def _recalc_concurrency(self):
        '''Periodically recalculate session concurrency.'''
        session_class = self.env.coin.SESSIONCLS
        period = 300
        while True:
            await sleep(period)
            hard_limit = session_class.cost_hard_limit

            # Reduce retained group cost
            refund = period * hard_limit / 5000
            dead_groups = []
            for group in self.session_groups.values():
                group.retained_cost = max(0.0, group.retained_cost - refund)
                if group.retained_cost == 0 and not group.sessions:
                    dead_groups.append(group)
            # Remove dead groups
            for group in dead_groups:
                self.session_groups.pop(group.name)

            # Recalc concurrency for sessions where cost is changing gradually, and update
            # cost_decay_per_sec.
            for session in self.sessions:
                # Subs have an on-going cost so decay more slowly with more subs
                session.cost_decay_per_sec = hard_limit / (10000 + 5 * session.sub_count())
                session.recalc_concurrency()

    def _get_info(self):
        '''A summary of server state.'''
        cache_fmt = '{:,d} lookups {:,d} hits {:,d} entries'
        sessions = self.sessions
        return {
            'coin': self.env.coin.__name__,
            'daemon': self.daemon.logged_url(),
            'daemon height': self.daemon.cached_height(),
            'db height': self.db.db_height,
            'db_flush_count': self.db.history.flush_count,
            'groups': len(self.session_groups),
            'history cache': cache_fmt.format(
                self._history_lookups, self._history_hits, len(self._history_cache)),
            'merkle cache': cache_fmt.format(
                self._merkle_lookups, self._merkle_hits, len(self._merkle_cache)),
            'pid': os.getpid(),
            'peers': self.peer_mgr.info(),
            'request counts': self._method_counts,
            'request total': sum(self._method_counts.values()),
            'sessions': {
                'count': len(sessions),
                'count with subs': sum(len(getattr(s, 'hashX_subs', ())) > 0 for s in sessions),
                'errors': sum(s.errors for s in sessions),
                'logged': len([s for s in sessions if s.log_me]),
                'pending requests': sum(s.unanswered_request_count() for s in sessions),
                'subs': sum(s.sub_count() for s in sessions),
            },
            'tx hashes cache': cache_fmt.format(
                self._tx_hashes_lookups, self._tx_hashes_hits, len(self._tx_hashes_cache)),
            'txs sent': self.txs_sent,
            'uptime': util.formatted_time(time.time() - self.start_time),
            'version': electrumx.version,
        }

    def _session_data(self, for_log):
        '''Returned to the RPC 'sessions' call.'''
        now = time.time()
        sessions = sorted(self.sessions, key=lambda s: s.start_time)
        return [(session.session_id,
                 session.flags(),
                 session.remote_address_string(for_log=for_log),
                 session.client,
                 session.protocol_version_string(),
                 session.cost,
                 session.extra_cost(),
                 session.unanswered_request_count(),
                 session.txs_sent,
                 session.sub_count(),
                 session.recv_count, session.recv_size,
                 session.send_count, session.send_size,
                 now - session.start_time)
                for session in sessions]

    def _group_data(self):
        '''Returned to the RPC 'groups' call.'''
        result = []
        for name, group in self.session_groups.items():
            sessions = group.sessions
            result.append([name,
                           len(sessions),
                           group.session_cost(),
                           group.retained_cost,
                           sum(s.unanswered_request_count() for s in sessions),
                           sum(s.txs_sent for s in sessions),
                           sum(s.sub_count() for s in sessions),
                           sum(s.recv_count for s in sessions),
                           sum(s.recv_size for s in sessions),
                           sum(s.send_count for s in sessions),
                           sum(s.send_size for s in sessions),
                           ])
        return result

    async def _refresh_hsub_results(self, height):
        '''Refresh the cached header subscription responses to be for height,
        and record that as notified_height.
        '''
        # Paranoia: a reorg could race and leave db_height lower
        height = min(height, self.db.db_height)
        raw = await self.raw_header(height)
        self.hsub_results = {'hex': raw.hex(), 'height': height}
        self.notified_height = height

    def _session_references(self, items, special_strings):
        '''Return a SessionReferences object.'''
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            raise RPCError(BAD_REQUEST, 'expected a list of session IDs')

        sessions_by_id = {session.session_id: session for session in self.sessions}
        groups_by_name = self.session_groups

        sessions = set()
        groups = set()     # Names as groups are not hashable
        specials = set()
        unknown = set()

        for item in items:
            if item.isdigit():
                session = sessions_by_id.get(int(item))
                if session:
                    sessions.add(session)
                else:
                    unknown.add(item)
            else:
                lc_item = item.lower()
                if lc_item in special_strings:
                    specials.add(lc_item)
                else:
                    if lc_item in groups_by_name:
                        groups.add(lc_item)
                    else:
                        unknown.add(item)

        groups = [groups_by_name[group] for group in groups]
        return SessionReferences(sessions, groups, specials, unknown)

    # --- LocalRPC command handlers

    async def rpc_add_peer(self, real_name):
        '''Add a peer.

        real_name: "bch.electrumx.cash t50001 s50002" for example
        '''
        await self.peer_mgr.add_localRPC_peer(real_name)
        return "peer '{}' added".format(real_name)

    async def rpc_disconnect(self, session_ids):
        '''Disconnect sesssions.

        session_ids: array of session IDs
        '''
        refs = self._session_references(session_ids, {'all'})
        result = []

        if 'all' in refs.specials:
            sessions = self.sessions
            result.append('disconnecting all sessions')
        else:
            sessions = refs.sessions
            result.extend(f'disconnecting session {session.session_id}' for session in sessions)
            for group in refs.groups:
                result.append(f'disconnecting group {group.name}')
                sessions.update(group.sessions)
        result.extend(f'unknown: {item}' for item in refs.unknown)

        await self._disconnect_sessions(sessions, 'local RPC request to disconnect')
        return result

    async def rpc_log(self, session_ids):
        '''Toggle logging of sesssions.

        session_ids: array of session or group IDs, or 'all', 'none', 'new'
        '''
        refs = self._session_references(session_ids, {'all', 'none', 'new'})
        result = []

        def add_result(text, value):
            result.append(f'logging {text}' if value else f'not logging {text}')

        if 'all' in refs.specials:
            for session in self.sessions:
                session.log_me = True
            SessionBase.log_new = True
            result.append('logging all sessions')
        if 'none' in refs.specials:
            for session in self.sessions:
                session.log_me = False
            SessionBase.log_new = False
            result.append('logging no sessions')
        if 'new' in refs.specials:
            SessionBase.log_new = not SessionBase.log_new
            add_result('new sessions', SessionBase.log_new)

        sessions = refs.sessions
        for session in sessions:
            session.log_me = not session.log_me
            add_result(f'session {session.session_id}', session.log_me)
        for group in refs.groups:
            for session in group.sessions.difference(sessions):
                sessions.add(session)
                session.log_me = not session.log_me
                add_result(f'session {session.session_id}', session.log_me)

        result.extend(f'unknown: {item}' for item in refs.unknown)
        return result

    async def rpc_daemon_url(self, daemon_url):
        '''Replace the daemon URL.'''
        daemon_url = daemon_url or self.env.daemon_url
        try:
            self.daemon.set_url(daemon_url)
        except Exception as e:
            raise RPCError(BAD_REQUEST, f'an error occured: {e!r}')
        return f'now using daemon at {self.daemon.logged_url()}'

    async def rpc_stop(self):
        '''Shut down the server cleanly.'''
        self.shutdown_event.set()
        return 'stopping'

    async def rpc_getinfo(self):
        '''Return summary information about the server process.'''
        return self._get_info()

    async def rpc_groups(self):
        '''Return statistics about the session groups.'''
        return self._group_data()

    async def rpc_peers(self):
        '''Return a list of data about server peers.'''
        return self.peer_mgr.rpc_data()

    async def rpc_query(self, items, limit):
        '''Returns data about a script, address or name.'''
        coin = self.env.coin
        db = self.db
        lines = []

        def arg_to_hashX(arg):
            try:
                script = bytes.fromhex(arg)
                lines.append(f'Script: {arg}')
                return coin.hashX_from_script(script)
            except ValueError:
                pass

            try:
                hashX = coin.address_to_hashX(arg)
                lines.append(f'Address: {arg}')
                return hashX
            except Base58Error:
                pass

            try:
                script = coin.build_name_index_script(arg.encode("ascii"))
                hashX = coin.name_hashX_from_script(script)
                lines.append(f'Name: {arg}')
                return hashX
            except (AttributeError, UnicodeEncodeError):
                pass

            return None

        for arg in items:
            hashX = arg_to_hashX(arg)
            if not hashX:
                continue
            n = None
            history = await db.limited_history(hashX, limit=limit)
            for n, (tx_hash, height) in enumerate(history):
                lines.append(f'History #{n:,d}: height {height:,d} '
                             f'tx_hash {hash_to_hex_str(tx_hash)}')
            if n is None:
                lines.append('No history found')
            n = None
            utxos = await db.all_utxos(hashX)
            for n, utxo in enumerate(utxos, start=1):
                lines.append(f'UTXO #{n:,d}: tx_hash '
                             f'{hash_to_hex_str(utxo.tx_hash)} '
                             f'tx_pos {utxo.tx_pos:,d} height '
                             f'{utxo.height:,d} value {utxo.value:,d}')
                if n == limit:
                    break
            if n is None:
                lines.append('No UTXOs found')

            balance = sum(utxo.value for utxo in utxos)
            lines.append(f'Balance: {coin.decimal_value(balance):,f} '
                         f'{coin.SHORTNAME}')

        return lines

    async def rpc_sessions(self):
        '''Return statistics about connected sessions.'''
        return self._session_data(for_log=False)

    async def rpc_reorg(self, count):
        '''Force a reorg of the given number of blocks.

        count: number of blocks to reorg
        '''
        count = non_negative_integer(count)
        if not self.bp.force_chain_reorg(count):
            raise RPCError(BAD_REQUEST, 'still catching up with daemon')
        return f'scheduled a reorg of {count:,d} blocks'

    # --- External Interface

    async def serve(self, notifications, event):
        '''Start the RPC server if enabled.  When the event is triggered,
        start TCP and SSL servers.'''
        try:
            await self._start_servers(service for service in self.env.services
                                      if service.protocol == 'rpc')
            await event.wait()

            session_class = self.env.coin.SESSIONCLS
            session_class.cost_soft_limit = self.env.cost_soft_limit
            session_class.cost_hard_limit = self.env.cost_hard_limit
            session_class.cost_decay_per_sec = session_class.cost_hard_limit / 10000
            session_class.bw_cost_per_byte = 1.0 / self.env.bw_unit_cost
            session_class.cost_sleep = self.env.request_sleep / 1000
            session_class.initial_concurrent = self.env.initial_concurrent
            session_class.processing_timeout = self.env.request_timeout

            self.logger.info(f'max session count: {self.env.max_sessions:,d}')
            self.logger.info(f'session timeout: {self.env.session_timeout:,d} seconds')
            self.logger.info(f'session cost hard limit {self.env.cost_hard_limit:,d}')
            self.logger.info(f'session cost soft limit {self.env.cost_soft_limit:,d}')
            self.logger.info(f'bandwidth unit cost {self.env.bw_unit_cost:,d}')
            self.logger.info(f'request sleep {self.env.request_sleep:,d}ms')
            self.logger.info(f'request timeout {self.env.request_timeout:,d}s')
            self.logger.info(f'initial concurrent {self.env.initial_concurrent:,d}')

            self.logger.info(f'max response size {self.env.max_send:,d} bytes')
            if self.env.drop_client is not None:
                self.logger.info('drop clients matching: {}'
                                 .format(self.env.drop_client.pattern))
            for service in self.env.report_services:
                self.logger.info(f'advertising service {service}')
            # Start notifications; initialize hsub_results
            await notifications.start(self.db.db_height, self._notify_sessions)
            await self._start_external_servers()
            # Peer discovery should start after the external servers
            # because we connect to ourself
            async with self._task_group as group:
                await group.spawn(self.peer_mgr.discover_peers())
                await group.spawn(self._clear_stale_sessions())
                await group.spawn(self._handle_chain_reorgs())
                await group.spawn(self._recalc_concurrency())
                await group.spawn(self._log_sessions())
                await group.spawn(self._manage_servers())
        finally:
            # Close servers then sessions
            await self._stop_servers(self.servers.keys())
            async with TaskGroup() as group:
                for session in list(self.sessions):
                    await group.spawn(session.close(force_after=1))

    def extra_cost(self, session):
        # Note there is no guarantee that session is still in self.sessions.  Example traceback:
        # notify_sessions->notify->address_status->bump_cost->recalc_concurrency->extra_cost
        # during which there are many places the sesssion could be removed
        groups = self.sessions.get(session)
        if groups is None:
            return 0
        return sum((group.cost() - session.cost) * group.weight for group in groups)

    async def _merkle_branch(self, height, tx_hashes, tx_pos):
        tx_hash_count = len(tx_hashes)
        cost = tx_hash_count

        if tx_hash_count >= 200:
            self._merkle_lookups += 1
            merkle_cache = self._merkle_cache.get(height)
            if merkle_cache:
                self._merkle_hits += 1
                cost = 10 * math.sqrt(tx_hash_count)
            else:
                async def tx_hashes_func(start, count):
                    return tx_hashes[start: start + count]

                merkle_cache = MerkleCache(self.db.merkle, tx_hashes_func)
                self._merkle_cache[height] = merkle_cache
                await merkle_cache.initialize(len(tx_hashes))
            branch, _root = await merkle_cache.branch_and_root(tx_hash_count, tx_pos)
        else:
            branch, _root = self.db.merkle.branch_and_root(tx_hashes, tx_pos)

        branch = [hash_to_hex_str(hash) for hash in branch]
        return branch, cost / 2500

    async def merkle_branch_for_tx_hash(self, height, tx_hash):
        '''Return a triple (branch, tx_pos, cost).'''
        tx_hashes, tx_hashes_cost = await self.tx_hashes_at_blockheight(height)
        try:
            tx_pos = tx_hashes.index(tx_hash)
        except ValueError:
            raise RPCError(BAD_REQUEST,
                           f'tx {hash_to_hex_str(tx_hash)} not in block at height {height:,d}')
        branch, merkle_cost = await self._merkle_branch(height, tx_hashes, tx_pos)
        return branch, tx_pos, tx_hashes_cost + merkle_cost

    async def merkle_branch_for_tx_pos(self, height, tx_pos):
        '''Return a triple (branch, tx_hash_hex, cost).'''
        tx_hashes, tx_hashes_cost = await self.tx_hashes_at_blockheight(height)
        try:
            tx_hash = tx_hashes[tx_pos]
        except IndexError:
            raise RPCError(BAD_REQUEST,
                           f'no tx at position {tx_pos:,d} in block at height {height:,d}')
        branch, merkle_cost = await self._merkle_branch(height, tx_hashes, tx_pos)
        return branch, hash_to_hex_str(tx_hash), tx_hashes_cost + merkle_cost

    async def tx_hashes_at_blockheight(self, height):
        '''Returns a pair (tx_hashes, cost).

        tx_hashes is an ordered list of binary hashes, cost is an estimated cost of
        getting the hashes; cheaper if in-cache.  Raises RPCError.
        '''
        self._tx_hashes_lookups += 1
        tx_hashes = self._tx_hashes_cache.get(height)
        if tx_hashes:
            self._tx_hashes_hits += 1
            return tx_hashes, 0.1

        # Ensure the tx_hashes are fresh before placing in the cache
        while True:
            reorg_count = self._reorg_count
            try:
                tx_hashes = await self.db.tx_hashes_at_blockheight(height)
            except self.db.DBError as e:
                raise RPCError(BAD_REQUEST, f'db error: {e!r}')
            if reorg_count == self._reorg_count:
                break

        self._tx_hashes_cache[height] = tx_hashes

        return tx_hashes, 0.25 + len(tx_hashes) * 0.0001

    def session_count(self):
        '''The number of connections that we've sent something to.'''
        return len(self.sessions)

    async def daemon_request(self, method, *args):
        '''Catch a DaemonError and convert it to an RPCError.'''
        try:
            return await getattr(self.daemon, method)(*args)
        except DaemonError as e:
            raise RPCError(DAEMON_ERROR, f'daemon error: {e!r}') from None

    async def raw_header(self, height):
        '''Return the binary header at the given height.'''
        try:
            return await self.db.raw_header(height)
        except IndexError:
            raise RPCError(BAD_REQUEST, f'height {height:,d} '
                           'out of range') from None

    async def broadcast_transaction(self, raw_tx):
        hex_hash = await self.daemon.broadcast_transaction(raw_tx)
        self.txs_sent += 1
        return hex_hash

    async def limited_history(self, hashX):
        '''Returns a pair (history, cost).

        History is a sorted list of (tx_hash, height) tuples, or an RPCError.'''
        # History DoS limit.  Each element of history is about 99 bytes when encoded
        # as JSON.
        limit = self.env.max_send // 99
        cost = 0.1
        self._history_lookups += 1
        try:
            result = self._history_cache[hashX]
            self._history_hits += 1
        except KeyError:
            result = await self.db.limited_history(hashX, limit=limit)
            cost += 0.1 + len(result) * 0.001
            if len(result) >= limit:
                result = RPCError(BAD_REQUEST, f'history too large', cost=cost)
            self._history_cache[hashX] = result

        if isinstance(result, Exception):
            raise result
        return result, cost

    async def _notify_sessions(self, height, touched):
        '''Notify sessions about height changes and touched addresses.'''
        height_changed = height != self.notified_height
        if height_changed:
            await self._refresh_hsub_results(height)
            # Invalidate our history cache for touched hashXs
            cache = self._history_cache
            for hashX in set(cache).intersection(touched):
                del cache[hashX]

        for session in self.sessions:
            await self._task_group.spawn(session.notify, touched, height_changed)

    def _ip_addr_group_name(self, session):
        host = session.remote_address().host
        if isinstance(host, IPv4Address):
            return '.'.join(str(host).split('.')[:3])
        if isinstance(host, IPv6Address):
            return ':'.join(host.exploded.split(':')[:3])
        return 'unknown_addr'

    def _timeslice_name(self, session):
        return f't{int(session.start_time - self.start_time) // 300}'

    def _session_group(self, name, weight):
        group = self.session_groups.get(name)
        if not group:
            group = SessionGroup(name, weight, set(), 0)
            self.session_groups[name] = group
        return group

    def add_session(self, session):
        self.session_event.set()
        # Return the session groups
        groups = (
            self._session_group(self._timeslice_name(session), 0.03),
            self._session_group(self._ip_addr_group_name(session), 1.0),
        )
        self.sessions[session] = groups
        for group in groups:
            group.sessions.add(session)

    def remove_session(self, session):
        '''Remove a session from our sessions list if there.'''
        self.session_event.set()
        groups = self.sessions.pop(session)
        for group in groups:
            group.retained_cost += session.cost
            group.sessions.remove(session)
