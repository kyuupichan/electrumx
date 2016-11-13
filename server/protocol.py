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
from collections import namedtuple
from functools import partial

from lib.hash import sha256, double_sha256, hash_to_str, hex_str_to_hash
from lib.jsonrpc import JSONRPC, json_notification_payload
from lib.util import LoggedClass
from server.block_processor import BlockProcessor
from server.daemon import DaemonError
from server.irc import IRC
from server.version import VERSION


class BlockServer(BlockProcessor):
    '''Like BlockProcessor but also has a server manager and starts
    servers when caught up.'''

    def __init__(self, env):
        super().__init__(env)
        self.server_mgr = ServerManager(self, env)

    async def caught_up(self, mempool_hashes):
        await super().caught_up(mempool_hashes)
        self.server_mgr.notify(self.height, self.touched)

    def stop(self):
        '''Close the listening servers.'''
        self.server_mgr.stop()


class ServerManager(LoggedClass):
    '''Manages the servers.'''

    AsyncTask = namedtuple('AsyncTask', 'session job')

    def __init__(self, bp, env):
        super().__init__()
        self.bp = bp
        self.env = env
        self.servers = []
        self.irc = IRC(env)
        self.sessions = set()
        self.tasks = asyncio.Queue()
        self.current_task = None

    async def start_server(self, kind, *args, **kw_args):
        loop = asyncio.get_event_loop()
        protocol_class = LocalRPC if kind == 'RPC' else ElectrumX
        protocol = partial(protocol_class, self, self.bp, self.env, kind)
        server = loop.create_server(protocol, *args, **kw_args)

        try:
            self.servers.append(await server)
        except asyncio.CancelledError:
            raise
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
            # FIXME: update if we want to require Python >= 3.5.3
            sslc = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            sslc.load_cert_chain(env.ssl_certfile, keyfile=env.ssl_keyfile)
            await self.start_server('SSL', env.host, env.ssl_port, ssl=sslc)

        asyncio.ensure_future(self.run_tasks())

        if env.irc:
            self.logger.info('starting IRC coroutine')
            asyncio.ensure_future(self.irc.start())
        else:
            self.logger.info('IRC disabled')

    async def notify(self, height, touched):
        '''Notify electrum clients about height changes and touched addresses.

        Start listening if not yet listening.
        '''
        if not self.servers:
            await self.start_servers()

        sessions = [session for session in self.sessions
                    if isinstance(session, ElectrumX)]
        self.ElectrumX.notify(sessions, height, touched)

    def stop(self):
        '''Close the listening servers.'''
        for server in self.servers:
            server.close()

    def add_session(self, session):
        assert session not in self.sessions
        self.sessions.add(session)

    def remove_session(self, session):
        self.sessions.remove(session)
        if self.current_task and session == self.current_task.session:
            self.logger.info('cancelling running task')
            self.current_task.job.cancel()

    def add_task(self, session, job):
        assert session in self.sessions
        task = asyncio.ensure_future(job)
        self.tasks.put_nowait(self.AsyncTask(session, task))

    async def run_tasks(self):
        '''Asynchronously run through the task queue.'''
        while True:
            task = await self.tasks.get()
            try:
                if task.session in self.sessions:
                    self.current_task = task
                    await task.job
                else:
                    task.job.cancel()
            except asyncio.CancelledError:
                self.logger.info('cancelled task noted')
            except Exception:
                # Getting here should probably be considered a bug and fixed
                traceback.print_exc()
            finally:
                self.current_task = None

    def irc_peers(self):
        return self.irc.peers

    def session_count(self):
        return len(self.manager.sessions)

    def info(self):
        '''Returned in the RPC 'getinfo' call.'''
        address_count = sum(len(session.hash168s)
                            for session in self.sessions
                            if isinstance(session, ElectrumX))
        return {
            'blocks': self.bp.height,
            'peers': len(self.irc_peers()),
            'sessions': self.session_count(),
            'watched': address_count,
            'cached': 0,
        }

    def sessions_info(self):
        '''Returned to the RPC 'sessions' call.'''
        now = time.time()
        return [(session.kind,
                 session.peername(),
                 len(session.hash168s),
                 'RPC' if isinstance(session, LocalRPC) else session.client,
                 now - session.start)
                for session in self.sessions]


class Session(JSONRPC):
    '''Base class of ElectrumX JSON session protocols.'''

    def __init__(self, manager, bp, env, kind):
        super().__init__()
        self.manager = manager
        self.bp = bp
        self.env = env
        self.daemon = bp.daemon
        self.coin = bp.coin
        self.kind = kind
        self.hash168s = set()
        self.client = 'unknown'

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        super().connection_made(transport)
        self.logger.info('connection from {}'.format(self.peername()))
        self.manager.add_session(self)

    def connection_lost(self, exc):
        '''Handle client disconnection.'''
        super().connection_lost(exc)
        if self.error_count or self.send_size >= 250000:
            self.logger.info('{} disconnected.  '
                             'Sent {:,d} bytes in {:,d} messages {:,d} errors'
                             .format(self.peername(), self.send_size,
                                     self.send_count, self.error_count))
        self.maanger.remove_session(self)

    def method_handler(self, method):
        '''Return the handler that will handle the RPC method.'''
        return self.handlers.get(method)

    def on_json_request(self, request):
        '''Queue the request for asynchronous handling.'''
        self.manager.add_task(self, self.handle_json_request(request))

    def peername(self):
        info = self.peer_info()
        return 'unknown' if not info else '{}:{}'.format(info[0], info[1])

    def tx_hash_from_param(self, param):
        '''Raise an RPCError if the parameter is not a valid transaction
        hash.'''
        if isinstance(param, str) and len(param) == 64:
            try:
                bytes.fromhex(param)
                return param
            except ValueError:
                pass
        raise RPCError('parameter should be a transaction hash: {}'
                       .format(param))

    def hash168_from_param(self, param):
        if isinstance(param, str):
            try:
                return self.coin.address_to_hash168(param)
            except:
                pass
        raise RPCError('parameter should be a valid address: {}'.format(param))

    def non_negative_integer_from_param(self, param):
        try:
            param = int(param)
        except ValueError:
            pass
        else:
            if param >= 0:
                return param

        raise RPCError('param should be a non-negative integer: {}'
                       .format(param))

    def extract_hash168(self, params):
        if len(params) == 1:
            return self.hash168_from_param(params[0])
        raise RPCError('params should contain a single address: {}'
                       .format(params))

    def extract_non_negative_integer(self, params):
        if len(params) == 1:
            return self.non_negative_integer_from_param(params[0])
        raise RPCError('params should contain a non-negative integer: {}'
                       .format(params))

    def require_empty_params(self, params):
        if params:
            raise RPCError('params should be empty: {}'.format(params))


class ElectrumX(Session):
    '''A TCP server that handles incoming Electrum connections.'''

    def __init__(self, *args):
        super().__init__(*args)
        self.subscribe_headers = False
        self.subscribe_height = False
        self.notified_height = None
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

    @classmethod
    def notify(cls, sessions, height, touched):
        headers_payload = height_payload = None

        for session in sessions:
            if height != session.notified_height:
                session.notified_height = height
                if session.subscribe_headers:
                    if headers_payload is None:
                        headers_payload = json_notification_payload(
                            'blockchain.headers.subscribe',
                            (session.electrum_header(height), ),
                        )
                    session.send_json(headers_payload)

                if session.subscribe_height:
                    if height_payload is None:
                        height_payload = json_notification_payload(
                            'blockchain.numblocks.subscribe',
                            (height, ),
                        )
                    session.send_json(height_payload)

            hash168_to_address = session.coin.hash168_to_address
            for hash168 in session.hash168s.intersection(touched):
                address = hash168_to_address(hash168)
                status = session.address_status(hash168)
                payload = json_notification_payload(
                    'blockchain.address.subscribe', (address, status))
                session.send_json(payload)

    def height(self):
        '''Return the block processor's current height.'''
        return self.bp.height

    def current_electrum_header(self):
        '''Used as response to a headers subscription request.'''
        return self.electrum_header(self.height())

    def electrum_header(self, height):
        '''Return the binary header at the given height.'''
        if not 0 <= height <= self.height():
            raise RPCError('height {:,d} out of range'.format(height))
        header = self.bp.read_headers(height, 1)
        return self.coin.electrum_header(header, height)

    def address_status(self, hash168):
        '''Returns status as 32 bytes.'''
        # Note history is ordered and mempool unordered in electrum-server
        # For mempool, height is -1 if unconfirmed txins, otherwise 0
        history = self.bp.get_history(hash168)
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
        hex_hashes = await self.daemon.block_hex_hashes(height, 1)
        block = await self.daemon.deserialised_block(hex_hashes[0])
        tx_hashes = block['tx']
        # This will throw if the tx_hash is bad
        pos = tx_hashes.index(tx_hash)

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

    def get_history(self, hash168):
        # Note history is ordered and mempool unordered in electrum-server
        # For mempool, height is -1 if unconfirmed txins, otherwise 0
        history = self.bp.get_history(hash168, limit=None)
        mempool = self.bp.mempool_transactions(hash168)

        conf = tuple({'tx_hash': hash_to_str(tx_hash), 'height': height}
                       for tx_hash, height in history)
        unconf = tuple({'tx_hash': tx_hash, 'height': -unconfirmed, 'fee': fee}
                       for tx_hash, fee, unconfirmed in mempool)
        return conf + unconf

    def get_chunk(self, index):
        '''Return header chunk as hex.  Index is a non-negative integer.'''
        chunk_size = self.coin.CHUNK_SIZE
        next_height = self.height() + 1
        start_height = min(index * chunk_size, next_height)
        count = min(next_height - start_height, chunk_size)
        return self.bp.read_headers(start_height, count).hex()

    def get_balance(self, hash168):
        confirmed = self.bp.get_balance(hash168)
        unconfirmed = self.bp.mempool_value(hash168)
        return {'confirmed': confirmed, 'unconfirmed': unconfirmed}

    def list_unspent(self, hash168):
        utxos = self.bp.get_utxos_sorted(hash168)
        return tuple({'tx_hash': hash_to_str(utxo.tx_hash),
                      'tx_pos': utxo.tx_pos, 'height': utxo.height,
                      'value': utxo.value}
                     for utxo in utxos)

    # --- blockchain commands

    async def address_get_balance(self, params):
        hash168 = self.extract_hash168(params)
        return self.get_balance(hash168)

    async def address_get_history(self, params):
        hash168 = self.extract_hash168(params)
        return self.get_history(hash168)

    async def address_get_mempool(self, params):
        hash168 = self.extract_hash168(params)
        raise RPCError('get_mempool is not yet implemented')

    async def address_get_proof(self, params):
        hash168 = self.extract_hash168(params)
        raise RPCError('get_proof is not yet implemented')

    async def address_listunspent(self, params):
        hash168 = self.extract_hash168(params)
        return self.list_unspent(hash168)

    async def address_subscribe(self, params):
        hash168 = self.extract_hash168(params)
        self.hash168s.add(hash168)
        return self.address_status(hash168)

    async def block_get_chunk(self, params):
        index = self.extract_non_negative_integer(params)
        return self.get_chunk(index)

    async def block_get_header(self, params):
        height = self.extract_non_negative_integer(params)
        return self.electrum_header(height)

    async def estimatefee(self, params):
        return await self.daemon.estimatefee(params)

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
        return await self.daemon.relayfee()

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
            return await self.daemon.getrawtransaction(tx_hash)

        raise RPCError('params wrong length: {}'.format(params))

    async def transaction_get_merkle(self, params):
        if len(params) == 2:
            tx_hash = self.tx_hash_from_param(params[0])
            height = self.non_negative_integer_from_param(params[1])
            return await self.tx_merkle(tx_hash, height)

        raise RPCError('params should contain a transaction hash and height')

    async def utxo_get_address(self, params):
        if len(params) == 2:
            tx_hash = self.tx_hash_from_param(params[0])
            index = self.non_negative_integer_from_param(params[1])
            tx_hash = hex_str_to_hash(tx_hash)
            hash168 = self.bp.get_utxo_hash168(tx_hash, index)
            if hash168:
                return self.coin.hash168_to_address(hash168)
            return None

        raise RPCError('params should contain a transaction hash and index')

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
        self.handlers = {cmd: getattr(self, cmd) for cmd in cmds}

    async def getinfo(self, params):
        return self.manager.info()

    async def sessions(self, params):
        return self.manager.sessions_info()

    async def numsessions(self, params):
        return self.manager.session_count()

    async def peers(self, params):
        return self.manager.irc_peers()

    async def numpeers(self, params):
        return len(self.manager.irc_peers())
