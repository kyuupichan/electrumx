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
from collections import defaultdict, namedtuple
from functools import partial

from lib.hash import sha256, double_sha256, hash_to_str, hex_str_to_hash
from lib.jsonrpc import JSONRPC, json_notification_payload
from lib.tx import Deserializer
from lib.util import LoggedClass
from server.block_processor import BlockProcessor
from server.daemon import DaemonError
from server.irc import IRC
from server.version import VERSION


class BlockServer(BlockProcessor):
    '''Like BlockProcessor but also has a mempool and a server manager.

    Servers are started immediately the block processor first catches
    up with the daemon.
    '''

    def __init__(self, env):
        super().__init__(env)
        self.server_mgr = ServerManager(self, env)
        self.mempool = MemPool(self)
        self.caught_up_yet = False

    async def caught_up(self, mempool_hashes):
        # Call the base class to flush before doing anything else.
        await super().caught_up(mempool_hashes)
        if not self.caught_up_yet:
            await self.server_mgr.start_servers()
            self.caught_up_yet = True
        self.touched.update(await self.mempool.update(mempool_hashes))
        self.server_mgr.notify(self.height, self.touched)

    def on_cancel(self):
        '''Called when the main loop is cancelled.'''
        self.server_mgr.stop()
        super().on_cancel()

    async def wait_shutdown(self):
        '''Wait for shutdown to complete cleanly, and return.'''
        await self.server_mgr.wait_shutdown()
        await super().wait_shutdown()

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


class MemPool(LoggedClass):
    '''Representation of the daemon's mempool.

    Updated regularly in caught-up state.  Goal is to enable efficient
    response to the value() and transactions() calls.

    To that end we maintain the following maps:

       tx_hash -> [txin_pairs, txout_pairs, unconfirmed]
       hash168 -> set of all tx hashes in which the hash168 appears

    A pair is a (hash168, value) tuple.  Unconfirmed is true if any of the
    tx's txins are unconfirmed.  tx hashes are hex strings.
    '''

    def __init__(self, bp):
        super().__init__()
        self.txs = {}
        self.hash168s = defaultdict(set)  # None can be a key
        self.bp = bp
        self.count = -1

    async def update(self, hex_hashes):
        '''Update state given the current mempool to the passed set of hashes.

        Remove transactions that are no longer in our mempool.
        Request new transactions we don't have then add to our mempool.
        '''
        hex_hashes = set(hex_hashes)
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
        raw_txs = await self.bp.daemon.getrawtransactions(hex_hashes)
        if initial:
            self.logger.info('analysing {:,d} mempool txs'
                             .format(len(raw_txs)))
        new_txs = {hex_hash: Deserializer(raw_tx).read_tx()
                   for hex_hash, raw_tx in zip(hex_hashes, raw_txs) if raw_tx}
        del raw_txs, hex_hashes

        # The mempool is unordered, so process all outputs first so
        # that looking for inputs has full info.
        script_hash168 = self.bp.coin.hash168_from_script()
        db_utxo_lookup = self.bp.db_utxo_lookup

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
            except self.bp.MissingUTXOError:
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

        # Might include a None
        return touched

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


class ServerManager(LoggedClass):
    '''Manages the servers.'''

    MgrTask = namedtuple('MgrTask', 'session task')

    def __init__(self, bp, env):
        super().__init__()
        self.bp = bp
        self.env = env
        self.servers = []
        self.irc = IRC(env)
        self.sessions = {}
        self.max_subs = env.max_subs
        self.subscription_count = 0
        self.irc_future = None
        self.logger.info('max subscriptions across all sessions: {:,d}'
                         .format(self.max_subs))
        self.logger.info('max subscriptions per session: {:,d}'
                         .format(env.max_session_subs))

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

    async def start_servers(self):
        '''Connect to IRC and start listening for incoming connections.

        Only connect to IRC if enabled.  Start listening on RCP, TCP
        and SSL ports only if the port wasn pecified.
        '''
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

        if env.irc:
            self.logger.info('starting IRC coroutine')
            self.irc_future = asyncio.ensure_future(self.irc.start())
        else:
            self.logger.info('IRC disabled')

    def notify(self, height, touched):
        '''Notify sessions about height changes and touched addresses.'''
        cache = {}
        for session in self.sessions:
            if isinstance(session, ElectrumX):
                # Use a tuple to distinguish from JSON
                session.jobs.put_nowait((height, touched, cache))

    def stop(self):
        '''Close listening servers.'''
        self.logger.info('cleanly closing client sessions, please wait...')
        for server in self.servers:
            server.close()
        if self.irc_future:
            self.irc_future.cancel()
        for session in self.sessions:
            self.close_session(session)

    async def wait_shutdown(self):
        # Wait for servers to close
        for server in self.servers:
            await server.wait_closed()
        self.servers = []

        secs = 60
        self.logger.info('server listening sockets closed, waiting '
                         '{:d} seconds for socket cleanup'.format(secs))

        limit = time.time() + secs
        while self.sessions and time.time() < limit:
            await asyncio.sleep(4)
            self.logger.info('{:,d} sessions remaining'
                             .format(len(self.sessions)))

    def add_session(self, session):
        coro = session.serve_requests()
        future = asyncio.ensure_future(coro)
        self.sessions[session] = future
        # Some connections are acknowledged after the servers are closed
        if not self.servers:
            self.close_session(session)

    def close_session(self, session):
        '''Close the session's transport and cancel its future.'''
        session.transport.close()
        self.sessions[session].cancel()

    def remove_session(self, session):
        self.subscription_count -= session.sub_count()
        future = self.sessions.pop(session)
        future.cancel()

    def new_subscription(self):
        if self.subscription_count >= self.max_subs:
            raise JSONRPC.RPCError('server subscription limit {:,d} reached'
                                   .format(self.max_subs))
        self.subscription_count += 1

    def irc_peers(self):
        return self.irc.peers

    def session_count(self):
        '''Returns a dictionary.'''
        active = len([s for s in self.sessions if s.send_count])
        total = len(self.sessions)
        return {'active': active, 'inert': total - active, 'total': total}

    async def rpc_getinfo(self, params):
        '''The RPC 'getinfo' call.'''
        return {
            'blocks': self.bp.height,
            'peers': len(self.irc.peers),
            'sessions': self.session_count(),
            'watched': self.subscription_count,
        }

    async def rpc_sessions(self, params):
        '''Returned to the RPC 'sessions' call.'''
        now = time.time()
        return [(session.kind,
                 session.peername(for_log=False),
                 session.sub_count(),
                 session.client,
                 session.recv_count, session.recv_size,
                 session.send_count, session.send_size,
                 session.error_count,
                 now - session.start)
                for session in self.sessions]

    async def rpc_numsessions(self, params):
        return self.session_count()

    async def rpc_peers(self, params):
        return self.irc.peers

    async def rpc_numpeers(self, params):
        return len(self.irc.peers)


class Session(JSONRPC):
    '''Base class of ElectrumX JSON session protocols.

    Each session runs its tasks in asynchronous parallelism with other
    sessions.  To prevent some sessions blocking othersr, potentially
    long-running requests should yield (not yet implemented).
    '''

    def __init__(self, manager, bp, env, kind):
        super().__init__()
        self.manager = manager
        self.bp = bp
        self.env = env
        self.daemon = bp.daemon
        self.coin = bp.coin
        self.kind = kind
        self.jobs = asyncio.Queue()
        self.client = 'unknown'

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        super().connection_made(transport)
        self.logger.info('connection from {}'.format(self.peername()))
        self.manager.add_session(self)

    def connection_lost(self, exc):
        '''Handle client disconnection.'''
        super().connection_lost(exc)
        if self.error_count or self.send_size >= 1024*1024:
            self.logger.info('{} disconnected.  '
                             'Sent {:,d} bytes in {:,d} messages {:,d} errors'
                             .format(self.peername(), self.send_size,
                                     self.send_count, self.error_count))
        self.manager.remove_session(self)

    def method_handler(self, method):
        '''Return the handler that will handle the RPC method.'''
        return self.handlers.get(method)

    def on_json_request(self, request):
        '''Queue the request for asynchronous handling.'''
        self.jobs.put_nowait(request)

    async def serve_requests(self):
        '''Asynchronously run through the task queue.'''
        while True:
            await asyncio.sleep(0)
            job = await self.jobs.get()
            try:
                if isinstance(job, tuple):  # Height / mempool notification
                    await self.notify(*job)
                else:
                    await self.handle_json_request(job)
            except asyncio.CancelledError:
                break
            except Exception:
                # Getting here should probably be considered a bug and fixed
                self.logger.error('error handling request {}'.format(job))
                traceback.print_exc()

    def peername(self, *, for_log=True):
        if not self.peer_info:
            return 'unknown'
        # Anonymize IP addresses that will be logged
        if for_log and self.env.anon_logs:
            return 'xx.xx.xx.xx:xx'
        return '{}:{}'.format(self.peer_info[0], self.peer_info[1])

    def sub_count(self):
        return 0

    async def daemon_request(self, method, *args):
        '''Catch a DaemonError and convert it to an RPCError.'''
        try:
            return await getattr(self.daemon, method)(*args)
        except DaemonError as e:
            raise RPCError('daemon error: {}'.format(e))

    def tx_hash_from_param(self, param):
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

    def hash168_from_param(self, param):
        if isinstance(param, str):
            try:
                return self.coin.address_to_hash168(param)
            except:
                pass
        raise self.RPCError('parameter should be a valid address: {}'
                            .format(param))

    def non_negative_integer_from_param(self, param):
        try:
            param = int(param)
        except ValueError:
            pass
        else:
            if param >= 0:
                return param

        raise self.RPCError('param should be a non-negative integer: {}'
                            .format(param))

    def extract_hash168(self, params):
        if len(params) == 1:
            return self.hash168_from_param(params[0])
        raise self.RPCError('params should contain a single address: {}'
                            .format(params))

    def extract_non_negative_integer(self, params):
        if len(params) == 1:
            return self.non_negative_integer_from_param(params[0])
        raise self.RPCError('params should contain a non-negative integer: {}'
                            .format(params))

    def require_empty_params(self, params):
        if params:
            raise self.RPCError('params should be empty: {}'.format(params))


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

    async def notify(self, height, touched, cache):
        '''Notify the client about changes in height and touched addresses.

        Cache is a shared cache for this update.
        '''
        if height != self.notified_height:
            self.notified_height = height
            if self.subscribe_headers:
                key = 'headers_payload'
                if key not in cache:
                    cache[key] = json_notification_payload(
                        'blockchain.headers.subscribe',
                        (self.electrum_header(height), ),
                    )
                self.send_json(cache[key])

            if self.subscribe_height:
                payload = json_notification_payload(
                    'blockchain.numblocks.subscribe',
                    (height, ),
                )
                self.send_json(payload)

        hash168_to_address = self.coin.hash168_to_address
        matches = self.hash168s.intersection(touched)
        for hash168 in matches:
            address = hash168_to_address(hash168)
            status = await self.address_status(hash168)
            payload = json_notification_payload(
                'blockchain.address.subscribe', (address, status))
            self.send_json(payload)

        if matches:
            self.logger.info('notified {} of {} addresses'
                             .format(self.peername(), len(matches)))

    def height(self):
        '''Return the block processor's current height.'''
        return self.bp.height

    def current_electrum_header(self):
        '''Used as response to a headers subscription request.'''
        return self.electrum_header(self.height())

    def electrum_header(self, height):
        '''Return the binary header at the given height.'''
        if not 0 <= height <= self.height():
            raise self.RPCError('height {:,d} out of range'.format(height))
        header = self.bp.read_headers(height, 1)
        return self.coin.electrum_header(header, height)

    async def address_status(self, hash168):
        '''Returns status as 32 bytes.'''
        # Note history is ordered and mempool unordered in electrum-server
        # For mempool, height is -1 if unconfirmed txins, otherwise 0
        history = await self.async_get_history(hash168)
        mempool = self.bp.mempool_transactions(hash168)

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
        mempool = self.bp.mempool_transactions(hash168)
        return [{'tx_hash': tx_hash, 'height': -unconfirmed, 'fee': fee}
                for tx_hash, fee, unconfirmed in mempool]

    async def get_history(self, hash168):
        # Note history is ordered but unconfirmed is unordered in e-s
        history = await self.async_get_history(hash168)
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

    async def async_get_history(self, hash168):
        # Python 3.6: use async generators; update callers
        history = []
        for item in self.bp.get_history(hash168, limit=None):
            history.append(item)
            if len(history) % 100 == 0:
                await asyncio.sleep(0)
        return history

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
        unconfirmed = self.bp.mempool_value(hash168)
        return {'confirmed': confirmed, 'unconfirmed': unconfirmed}

    async def list_unspent(self, hash168):
        return [{'tx_hash': hash_to_str(utxo.tx_hash), 'tx_pos': utxo.tx_pos,
                 'height': utxo.height, 'value': utxo.value}
                for utxo in sorted(await self.get_utxos(hash168))]

    # --- blockchain commands

    async def address_get_balance(self, params):
        hash168 = self.extract_hash168(params)
        return await self.get_balance(hash168)

    async def address_get_history(self, params):
        hash168 = self.extract_hash168(params)
        return await self.get_history(hash168)

    async def address_get_mempool(self, params):
        hash168 = self.extract_hash168(params)
        return self.unconfirmed_history(hash168)

    async def address_get_proof(self, params):
        hash168 = self.extract_hash168(params)
        raise self.RPCError('get_proof is not yet implemented')

    async def address_listunspent(self, params):
        hash168 = self.extract_hash168(params)
        return await self.list_unspent(hash168)

    async def address_subscribe(self, params):
        hash168 = self.extract_hash168(params)
        if len(self.hash168s) >= self.max_subs:
            raise self.RPCError('your address subscription limit {:,d} reached'
                                .format(self.max_subs))
        result = await self.address_status(hash168)
        # add_subscription can raise so call it before adding
        self.manager.new_subscription()
        self.hash168s.add(hash168)
        return result

    async def block_get_chunk(self, params):
        index = self.extract_non_negative_integer(params)
        return self.get_chunk(index)

    async def block_get_header(self, params):
        height = self.extract_non_negative_integer(params)
        return self.electrum_header(height)

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
            self.logger.info('sent tx: {}'.format(tx_hash))
            return tx_hash
        except DaemonError as e:
            error = e.args[0]
            message = error['message']
            self.logger.info('sendrawtransaction: {}'.format(message))
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
            tx_hash = self.tx_hash_from_param(params[0])
            return await self.daemon_request('getrawtransaction', tx_hash)

        raise self.RPCError('params wrong length: {}'.format(params))

    async def transaction_get_merkle(self, params):
        if len(params) == 2:
            tx_hash = self.tx_hash_from_param(params[0])
            height = self.non_negative_integer_from_param(params[1])
            return await self.tx_merkle(tx_hash, height)

        raise self.RPCError('params should contain a transaction hash '
                            'and height')

    async def utxo_get_address(self, params):
        if len(params) == 2:
            tx_hash = self.tx_hash_from_param(params[0])
            index = self.non_negative_integer_from_param(params[1])
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
                self.logger.error('reading banner file {}: {}'
                                  .format(self.env.banner_file, e))
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
        if len(params) == 2:
            self.client = str(params[0])
            self.protocol_version = params[1]
        return VERSION


class LocalRPC(Session):
    '''A local TCP RPC server for querying status.'''

    def __init__(self, *args):
        super().__init__(*args)
        cmds = 'getinfo sessions numsessions peers numpeers'.split()
        self.handlers = {cmd: getattr(self.manager, 'rpc_{}'.format(cmd))
                         for cmd in cmds}
        self.client = 'RPC'
