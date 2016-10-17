# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import asyncio
import codecs
import json
import traceback
from functools import partial

from lib.hash import hash_to_str
from lib.util import LoggedClass
from server.version import VERSION


class Error(Exception):
    BAD_REQUEST = 1
    INTERNAL_ERROR = 2


class JSONRPC(asyncio.Protocol, LoggedClass):

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.parts = []

    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info('peername')
        self.logger.info('connection from {}'.format(peername))
        self.controller.add_session(self)

    def connection_lost(self, exc):
        self.logger.info('disconnected')
        self.controller.remove_session(self)

    def data_received(self, data):
        while True:
            npos = data.find(ord('\n'))
            if npos == -1:
                break
            tail, data = data[:npos], data[npos + 1:]
            parts = self.parts
            self.parts = []
            parts.append(tail)
            self.decode_message(b''.join(parts))

        if data:
            self.parts.append(data)

    def decode_message(self, message):
        '''Message is a binary message.'''
        try:
            message = json.loads(message.decode())
        except Exception as e:
            self.logger.info('caught exception decoding message'.format(e))
            return

        job = self.request_handler(message)
        self.controller.add_job(job)

    async def request_handler(self, request):
        '''Called asynchronously.'''
        error = result = None
        try:
            result = await self.json_handler(request)
        except Error as e:
            error = {'code': e.args[0], 'message': e.args[1]}
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # This should be considered a bug and fixed
            traceback.print_exc()
            error = {'code': Error.INTERNAL_ERROR, 'message': str(e)}

        payload = {'id': request.get('id'), 'error': error, 'result': result}
        try:
            data = json.dumps(payload) + '\n'
        except TypeError:
            msg = 'cannot JSON encode response to request {}'.format(request)
            self.logger.error(msg)
            error = {'code': Error.INTERNAL_ERROR, 'message': msg}
            payload = {'id': request.get('id'), 'error': error, 'result': None}
            data = json.dumps(payload) + '\n'
        self.transport.write(data.encode())

    async def json_handler(self, request):
        method = request.get('method')
        handler = None
        if isinstance(method, str):
            handler_name = 'handle_{}'.format(method.replace('.', '_'))
            handler = getattr(self, handler_name, None)
        if not handler:
            self.logger.info('unknown method: {}'.format(method))
            raise Error(Error.BAD_REQUEST, 'unknown method: {}'.format(method))
        params = request.get('params', [])
        if not isinstance(params, list):
            raise Error(Error.BAD_REQUEST, 'params should be an array')
        return await handler(params)


class ElectrumX(JSONRPC):

    def __init__(self, controller, env):
        super().__init__(controller)
        self.BC = controller.block_cache
        self.db = controller.db
        self.env = env
        self.addresses = set()
        self.subscribe_headers = False

    def params_to_hash168(self, params):
        if len(params) != 1:
            raise Error(Error.BAD_REQUEST,
                        'params should contain a single address')
        address = params[0]
        try:
            return self.env.coin.address_to_hash168(address)
        except:
            raise Error(Error.BAD_REQUEST,
                        'invalid address: {}'.format(address))

    async def handle_blockchain_address_get_history(self, params):
        hash168 = self.params_to_hash168(params)
        history = [
            {'tx_hash': hash_to_str(tx_hash), 'height': height}
            for tx_hash, height in self.db.get_history(hash168, limit=None)
        ]
        return history

    async def handle_blockchain_address_subscribe(self, params):
        hash168 = self.params_to_hash168(params)
        status = self.controller.address_status(hash168)
        return status.hex() if status else None

    async def handle_blockchain_estimatefee(self, params):
        result = await self.BC.send_single('estimatefee', params)
        return result

    async def handle_blockchain_headers_subscribe(self, params):
        self.subscribe_headers = True
        return self.db.get_current_header()

    async def handle_blockchain_relayfee(self, params):
        '''The minimum fee a low-priority tx must pay in order to be accepted
        to this daemon's memory pool.
        '''
        net_info = await self.BC.send_single('getnetworkinfo')
        return net_info['relayfee']

    async def handle_blockchain_transaction_get(self, params):
        if len(params) != 1:
            raise Error(Error.BAD_REQUEST,
                        'params should contain a transaction hash')
        tx_hash = params[0]
        return await self.BC.send_single('getrawtransaction', (tx_hash, 0))

    async def handle_blockchain_transaction_get_merkle(self, params):
        if len(params) != 2:
            raise Error(Error.BAD_REQUEST,
                        'params should contain a transaction hash and height')
        tx_hash, height = params
        return await self.controller.get_merkle(tx_hash, height)

    async def handle_server_banner(self, params):
        '''Return the server banner.'''
        banner = 'Welcome to Electrum!'
        if self.env.banner_file:
            try:
                with codecs.open(self.env.banner_file, 'r', 'utf-8') as f:
                    banner = f.read()
            except Exception as e:
                self.logger.error('reading banner file {}: {}'
                                  .format(self.env.banner_file, e))
        return banner

    async def handle_server_donation_address(self, params):
        '''Return the donation address as a string.

        If none is specified return the empty string.
        '''
        return self.env.donation_address

    async def handle_server_peers_subscribe(self, params):
        '''Returns the peer (ip, host, ports) tuples.

        Despite the name electrum-server does not treat this as a
        subscription.
        '''
        peers = self.controller.get_peers()
        return tuple(peers.values())

    async def handle_server_version(self, params):
        '''Return the server version as a string.'''
        return VERSION


class LocalRPC(JSONRPC):

    async def handle_getinfo(self, params):
        return {
            'blocks': self.controller.db.height,
            'peers': len(self.controller.get_peers()),
            'sessions': len(self.controller.sessions),
            'watched': sum(len(s.addresses) for s in self.controller.sessions
                           if isinstance(s, ElectrumX)),
            'cached': 0,
        }

    async def handle_sessions(self, params):
        return []

    async def handle_numsessions(self, params):
        return len(self.controller.sessions)

    async def handle_peers(self, params):
        return tuple(self.controller.get_peers().keys())

    async def handle_numpeers(self, params):
        return len(self.controller.get_peers())
