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
from lib.util import LoggedClass
from server.block_processor import BlockProcessor
from server.daemon import DaemonError
from server.irc import IRC
from server.version import VERSION


class RPCError(Exception):
    '''RPC handlers raise this error.'''


def json_notification(method, params):
    '''Create a json notification.'''
    return {'id': None, 'method': method, 'params': params}


class BlockServer(BlockProcessor):
    '''Like BlockProcessor but also starts servers when caught up.'''

    def __init__(self, env):
        super().__init__(env)
        self.servers = []
        self.irc = IRC(env)

    async def caught_up(self, mempool_hashes):
        await super().caught_up([]) #mempool_hashes)
        if not self.servers:
            await self.start_servers()
            if self.env.irc:
                asyncio.ensure_future(self.irc.start())
        ElectrumX.notify(self.height, self.touched)

    async def start_server(self, class_name, kind, host, port, *, ssl=None):
        loop = asyncio.get_event_loop()
        protocol = partial(class_name, self.env, kind)
        server = loop.create_server(protocol, host, port, ssl=ssl)
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
        '''Start listening on RPC, TCP and SSL ports.

        Does not start a server if the port wasn't specified.
        '''
        env = self.env
        JSONRPC.init(self, self.daemon, self.coin)
        if env.rpc_port is not None:
            await self.start_server(LocalRPC, 'RPC', 'localhost', env.rpc_port)

        if env.tcp_port is not None:
            await self.start_server(ElectrumX, 'TCP', env.host, env.tcp_port)

        if env.ssl_port is not None:
            # FIXME: update if we want to require Python >= 3.5.3
            sslc = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            sslc.load_cert_chain(env.ssl_certfile, keyfile=env.ssl_keyfile)
            await self.start_server(ElectrumX, 'SSL', env.host,
                                    env.ssl_port, ssl=sslc)

    def stop(self):
        '''Close the listening servers.'''
        for server in self.servers:
            server.close()

    def irc_peers(self):
        return self.irc.peers


AsyncTask = namedtuple('AsyncTask', 'session job')

class SessionManager(LoggedClass):

    def __init__(self):
        super().__init__()
        self.sessions = set()
        self.tasks = asyncio.Queue()
        self.current_task = None
        asyncio.ensure_future(self.run_tasks())

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
        self.tasks.put_nowait(AsyncTask(session, task))

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


class JSONRPC(asyncio.Protocol, LoggedClass):
    '''Base class that manages a JSONRPC connection.'''

    def __init__(self):
        super().__init__()
        self.parts = []
        self.send_count = 0
        self.send_size = 0
        self.error_count = 0
        self.hash168s = set()
        self.start = time.time()
        self.client = 'unknown'
        self.peername = 'unknown'

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        self.transport = transport
        peer = transport.get_extra_info('peername')
        self.peername = '{}:{}'.format(peer[0], peer[1])
        self.logger.info('connection from {}'.format(self.peername))
        self.SESSION_MGR.add_session(self)

    def connection_lost(self, exc):
        '''Handle client disconnection.'''
        self.logger.info('{} disconnected.  '
                         'Sent {:,d} bytes in {:,d} messages {:,d} errors'
                         .format(self.peername, self.send_size,
                                 self.send_count, self.error_count))
        self.SESSION_MGR.remove_session(self)

    def data_received(self, data):
        '''Handle incoming data (synchronously).

        Requests end in newline characters.  Pass complete requests to
        decode_message for handling.
        '''
        while True:
            npos = data.find(ord('\n'))
            if npos == -1:
                self.parts.append(data)
                break
            tail, data = data[:npos], data[npos + 1:]
            parts, self.parts = self.parts, []
            parts.append(tail)
            self.decode_message(b''.join(parts))

    def decode_message(self, message):
        '''Decode a binary message and queue it for asynchronous handling.'''
        try:
            message = json.loads(message.decode())
        except Exception as e:
            self.logger.info('error decoding JSON message: {}'.format(e))
        else:
            self.SESSION_MGR.add_task(self, self.request_handler(message))

    async def request_handler(self, request):
        '''Called asynchronously.'''
        error = result = None
        try:
            handler = self.rpc_handler(request.get('method'),
                                       request.get('params', []))
            result = await handler()
        except RPCError as e:
            self.error_count += 1
            error = {'code': 1, 'message': e.args[0]}
        payload = {'id': request.get('id'), 'error': error, 'result': result}
        if not self.json_send(payload):
            # Let asyncio call connection_lost() so we stop this
            # session's tasks
            await asyncio.sleep(0)

    def json_send(self, payload):
        if self.transport.is_closing():
            self.logger.info('connection closing, not writing')
            return False

        data = (json.dumps(payload) + '\n').encode()
        self.transport.write(data)
        self.send_count += 1
        self.send_size += len(data)
        return True

    def rpc_handler(self, method, params):
        handler = None
        if isinstance(method, str):
            handler = self.handlers.get(method)
        if not handler:
            self.logger.info('unknown method: {}'.format(method))
            raise RPCError('unknown method: {}'.format(method))

        if not isinstance(params, list):
            raise RPCError('params should be an array')

        return partial(handler, self, params)

    @classmethod
    def tx_hash_from_param(cls, param):
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

    @classmethod
    def hash168_from_param(cls, param):
        if isinstance(param, str):
            try:
                return cls.COIN.address_to_hash168(param)
            except:
                pass
        raise RPCError('parameter should be a valid address: {}'.format(param))

    @classmethod
    def non_negative_integer_from_param(cls, param):
        try:
            param = int(param)
        except ValueError:
            pass
        else:
            if param >= 0:
                return param

        raise RPCError('param should be a non-negative integer: {}'
                       .format(param))

    @classmethod
    def extract_hash168(cls, params):
        if len(params) == 1:
            return cls.hash168_from_param(params[0])
        raise RPCError('params should contain a single address: {}'
                       .format(params))

    @classmethod
    def extract_non_negative_integer(cls, params):
        if len(params) == 1:
            return cls.non_negative_integer_from_param(params[0])
        raise RPCError('params should contain a non-negative integer: {}'
                       .format(params))

    @classmethod
    def require_empty_params(cls, params):
        if params:
            raise RPCError('params should be empty: {}'.format(params))

    @classmethod
    def init(cls, block_processor, daemon, coin):
        cls.BLOCK_PROCESSOR = block_processor
        cls.DAEMON = daemon
        cls.COIN = coin
        cls.SESSION_MGR = SessionManager()

    @classmethod
    def irc_peers(cls):
        return cls.BLOCK_PROCESSOR.irc_peers()

    @classmethod
    def height(cls):
        '''Return the current height.'''
        return cls.BLOCK_PROCESSOR.height

    @classmethod
    def electrum_header(cls, height=None):
        '''Return the binary header at the given height.'''
        if not 0 <= height <= cls.height():
            raise RPCError('height {:,d} out of range'.format(height))
        header = cls.BLOCK_PROCESSOR.read_headers(height, 1)
        return cls.COIN.electrum_header(header, height)

    @classmethod
    def current_electrum_header(cls):
        '''Used as response to a headers subscription request.'''
        return cls.electrum_header(cls.height())


class ElectrumX(JSONRPC):
    '''A TCP server that handles incoming Electrum connections.'''

    def __init__(self, env, kind):
        super().__init__()
        self.env = env
        self.kind = kind
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
                         getattr(self.__class__, suffix.replace('.', '_'))
                         for prefix, suffixes in rpcs
                         for suffix in suffixes.split()}

    @classmethod
    def watched_address_count(cls):
        sessions = cls.SESSION_MGR.sessions
        return sum(len(session.hash168s) for session in sessions)

    @classmethod
    def notify(cls, height, touched):
        '''Notify electrum clients about height changes and touched
        addresses.'''
        headers_payload = json_notification(
            'blockchain.headers.subscribe',
            (cls.electrum_header(height), ),
        )
        height_payload = json_notification(
            'blockchain.numblocks.subscribe',
            (height, ),
        )
        hash168_to_address = cls.COIN.hash168_to_address

        for session in cls.SESSION_MGR.sessions:
            if not isinstance(session, ElectrumX):
                continue

            if height != session.notified_height:
                session.notified_height = height
                if session.subscribe_headers:
                    session.json_send(headers_payload)
                if session.subscribe_height:
                    session.json_send(height_payload)

            for hash168 in session.hash168s.intersection(touched):
                address = hash168_to_address(hash168)
                status = cls.address_status(hash168)
                payload = json_notification('blockchain.address.subscribe',
                                            (address, status))
                session.json_send(payload)

    @classmethod
    def address_status(cls, hash168):
        '''Returns status as 32 bytes.'''
        # Note history is ordered and mempool unordered in electrum-server
        # For mempool, height is -1 if unconfirmed txins, otherwise 0
        history = cls.BLOCK_PROCESSOR.get_history(hash168)
        mempool = cls.BLOCK_PROCESSOR.mempool_transactions(hash168)

        status = ''.join('{}:{:d}:'.format(hash_to_str(tx_hash), height)
                         for tx_hash, height in history)
        status += ''.join('{}:{:d}:'.format(hex_hash, -unconfirmed)
                          for hex_hash, tx_fee, unconfirmed in mempool)
        if status:
            return sha256(status.encode()).hex()
        return None

    @classmethod
    async def tx_merkle(cls, tx_hash, height):
        '''tx_hash is a hex string.'''
        hex_hashes = await cls.DAEMON.block_hex_hashes(height, 1)
        block = await cls.DAEMON.deserialised_block(hex_hashes[0])
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

    @classmethod
    def height(cls):
        return cls.BLOCK_PROCESSOR.height

    @classmethod
    def get_history(cls, hash168):
        # Note history is ordered and mempool unordered in electrum-server
        # For mempool, height is -1 if unconfirmed txins, otherwise 0
        history = cls.BLOCK_PROCESSOR.get_history(hash168, limit=None)
        mempool = cls.BLOCK_PROCESSOR.mempool_transactions(hash168)

        conf = tuple({'tx_hash': hash_to_str(tx_hash), 'height': height}
                       for tx_hash, height in history)
        unconf = tuple({'tx_hash': tx_hash, 'height': -unconfirmed, 'fee': fee}
                       for tx_hash, fee, unconfirmed in mempool)
        return conf + unconf

    @classmethod
    def get_chunk(cls, index):
        '''Return header chunk as hex.  Index is a non-negative integer.'''
        chunk_size = cls.COIN.CHUNK_SIZE
        next_height = cls.height() + 1
        start_height = min(index * chunk_size, next_height)
        count = min(next_height - start_height, chunk_size)
        return cls.BLOCK_PROCESSOR.read_headers(start_height, count).hex()

    @classmethod
    def get_balance(cls, hash168):
        confirmed = cls.BLOCK_PROCESSOR.get_balance(hash168)
        unconfirmed = cls.BLOCK_PROCESSOR.mempool_value(hash168)
        return {'confirmed': confirmed, 'unconfirmed': unconfirmed}

    @classmethod
    def list_unspent(cls, hash168):
        utxos = cls.BLOCK_PROCESSOR.get_utxos_sorted(hash168)
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
        return await self.DAEMON.estimatefee(params)

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
        return await self.DAEMON.relayfee()

    async def transaction_broadcast(self, params):
        '''Pass through the parameters to the daemon.

        An ugly API: current Electrum clients only pass the raw
        transaction in hex and expect error messages to be returned in
        the result field.  And the server shouldn't be doing the client's
        user interface job here.
        '''
        try:
            tx_hash = await self.DAEMON.sendrawtransaction(params)
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
            return await self.DAEMON.getrawtransaction(tx_hash)

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
            hash168 = self.BLOCK_PROCESSOR.get_utxo_hash168(tx_hash, index)
            if hash168:
                return self.COIN.hash168_to_address(hash168)
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
        return list(self.irc_peers().values())

    async def version(self, params):
        '''Return the server version as a string.'''
        if len(params) == 2:
            self.client = str(params[0])
            self.protocol_version = params[1]
        return VERSION


class LocalRPC(JSONRPC):
    '''A local TCP RPC server for querying status.'''

    def __init__(self, env, kind):
        super().__init__()
        cmds = 'getinfo sessions numsessions peers numpeers'.split()
        self.handlers = {cmd: getattr(self.__class__, cmd) for cmd in cmds}
        self.env = env
        self.kind = kind

    async def getinfo(self, params):
        return {
            'blocks': self.height(),
            'peers': len(self.irc_peers()),
            'sessions': len(self.SESSION_MGR.sessions),
            'watched': ElectrumX.watched_address_count(),
            'cached': 0,
        }

    async def sessions(self, params):
        now = time.time()
        return [(session.kind,
                 'this RPC client' if session == self else session.peername,
                 len(session.hash168s), session.client, now - session.start)
                for session in self.SESSION_MGR.sessions]

    async def numsessions(self, params):
        return len(self.SESSION_MGR.sessions)

    async def peers(self, params):
        return self.irc_peers()

    async def numpeers(self, params):
        return len(self.irc_peers())
