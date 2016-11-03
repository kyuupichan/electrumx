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
import struct
import traceback
from functools import partial

from server.daemon import DaemonError
from lib.hash import hex_str_to_hash
from lib.util import LoggedClass
from server.version import VERSION


class RPCError(Exception):
    '''RPC handlers raise this error.'''


def json_notification(method, params):
    '''Create a json notification.'''
    return {'id': None, 'method': method, 'params': params}


class JSONRPC(asyncio.Protocol, LoggedClass):
    '''Base class that manages a JSONRPC connection.'''
    SESSIONS = set()
    BLOCK_PROCESSOR = None
    COIN = None

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.parts = []
        self.send_count = 0
        self.send_size = 0
        self.error_count = 0
        self.subscribe_headers = False
        self.subscribe_height = False
        self.notified_height = None

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        self.transport = transport
        self.peername = transport.get_extra_info('peername')
        self.logger.info('connection from {}'.format(self.peername))
        self.SESSIONS.add(self)

    def connection_lost(self, exc):
        '''Handle client disconnection.'''
        self.logger.info('{} disconnected.  '
                         'Sent {:,d} bytes in {:,d} messages {:,d} errors'
                         .format(self.peername, self.send_size,
                                 self.send_count, self.error_count))
        self.SESSIONS.remove(self)

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
            self.logger.info('error decoding JSON message'.format(e))
        else:
            self.controller.add_job(self.request_handler(message))

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
        self.json_send(payload)

    def json_send(self, payload):
        data = (json.dumps(payload) + '\n').encode()
        self.transport.write(data)
        self.send_count += 1
        self.send_size += len(data)

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
    def init(cls, block_processor, coin):
        cls.BLOCK_PROCESSOR = block_processor
        cls.COIN = coin

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

        for session in cls.SESSIONS:
            if height != session.notified_height:
                session.notified_height = height
                if session.subscribe_headers:
                    session.json_send(headers_payload)
                if session.subscribe_height:
                    session.json_send(height_payload)

            for hash168 in session.hash168s.intersection(touched):
                address = hash168_to_address(hash168)
                payload = json_notification('blockchain.address.subscribe',
                                            (address, ))
                session.json_send(payload)


class ElectrumX(JSONRPC):
    '''A TCP server that handles incoming Electrum connections.'''

    def __init__(self, controller, daemon, env):
        super().__init__(controller)
        self.daemon = daemon
        self.env = env
        self.hash168s = set()
        rpcs = [(
            'blockchain',
            'address.get_balance address.get_history address.get_mempool '
            'address.get_proof address.listunspent address.subscribe '
            'block.get_header block.get_chunk estimatefee headers.subscribe '
            'numblocks.subscribe relayfee transaction.broadcast '
            'transaction.get transaction.get_merkle utxo.get_address'),
        (
            'server',
            'banner donation_address peers.subscribe version'),
        ]
        self.handlers = {'.'.join([prefix, suffix]):
                         getattr(self.__class__, suffix.replace('.', '_'))
                         for prefix, suffixes in rpcs
                         for suffix in suffixes.split()}

    @classmethod
    def watched_address_count(cls):
        return sum(len(session.hash168s) for session in self.SESSIONS
                   if isinstance(session, cls))

    # --- blockchain commands

    async def address_get_balance(self, params):
        hash168 = self.extract_hash168(params)
        return self.controller.get_balance(hash168)

    async def address_get_history(self, params):
        hash168 = self.extract_hash168(params)
        return self.controller.get_history(hash168)

    async def address_get_mempool(self, params):
        hash168 = self.extract_hash168(params)
        raise RPCError('get_mempool is not yet implemented')

    async def address_get_proof(self, params):
        hash168 = self.extract_hash168(params)
        raise RPCError('get_proof is not yet implemented')

    async def address_listunspent(self, params):
        hash168 = self.extract_hash168(params)
        return self.controller.list_unspent(hash168)

    async def address_subscribe(self, params):
        hash168 = self.extract_hash168(params)
        self.hash168s.add(hash168)
        status = self.controller.address_status(hash168)
        return status.hex() if status else None

    async def block_get_chunk(self, params):
        index = self.extract_non_negative_integer(params)
        return self.controller.get_chunk(index)

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
            errors = e.args[0]
            error = errors[0]
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
            return await self.controller.get_merkle(tx_hash, height)

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
        peers = self.controller.get_peers()
        return tuple(peers.values())

    async def version(self, params):
        '''Return the server version as a string.'''
        return VERSION


class LocalRPC(JSONRPC):
    '''A local TCP RPC server for querying status.'''

    def __init__(self):
        super().__init__()
        cmds = 'getinfo sessions numsessions peers numpeers'.split()
        self.handlers = {cmd: getattr(self.__class__, cmd) for cmd in cmds}

    async def getinfo(self, params):
        return {
            'blocks': self.height(),
            'peers': len(self.controller.get_peers()),
            'sessions': len(self.SESSIONS),
            'watched': ElectrumX.watched_address_count(),
            'cached': 0,
        }

    async def sessions(self, params):
        return []

    async def numsessions(self, params):
        return len(self.SESSIONS)

    async def peers(self, params):
        return tuple(self.controller.get_peers().keys())

    async def numpeers(self, params):
        return len(self.controller.get_peers())
