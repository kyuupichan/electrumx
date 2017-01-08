# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Classes for local RPC server and remote client TCP/SSL servers.'''


import asyncio
import codecs
import traceback

from lib.hash import sha256, double_sha256, hash_to_str, hex_str_to_hash
from lib.jsonrpc import JSONRPC
from server.daemon import DaemonError
from server.version import VERSION


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
        self.last_delay = 0
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
        if (self.pause or self.manager.is_deprioritized(self)
                 or self.send_size >= 1024*1024 or self.error_count):
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

    def param_to_hashX(self, param):
        if isinstance(param, str):
            try:
                return self.coin.address_to_hashX(param)
            except:
                pass
        raise self.RPCError('param {} is not a valid address'.format(param))

    def params_to_hashX(self, params):
        if len(params) == 1:
            return self.param_to_hashX(params[0])
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
        self.hashX_subs = {}
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
        return len(self.hashX_subs)

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

        matches = touched.intersection(self.hashX_subs)
        for hashX in matches:
            address = self.hashX_subs[hashX]
            status = await self.address_status(hashX)
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

    async def address_status(self, hashX):
        '''Returns status as 32 bytes.'''
        # Note history is ordered and mempool unordered in electrum-server
        # For mempool, height is -1 if unconfirmed txins, otherwise 0
        history = await self.manager.async_get_history(hashX)
        mempool = await self.manager.mempool_transactions(hashX)

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

    async def unconfirmed_history(self, hashX):
        # Note unconfirmed history is unordered in electrum-server
        # Height is -1 if unconfirmed txins, otherwise 0
        mempool = await self.manager.mempool_transactions(hashX)
        return [{'tx_hash': tx_hash, 'height': -unconfirmed, 'fee': fee}
                for tx_hash, fee, unconfirmed in mempool]

    async def get_history(self, hashX):
        # Note history is ordered but unconfirmed is unordered in e-s
        history = await self.manager.async_get_history(hashX)
        conf = [{'tx_hash': hash_to_str(tx_hash), 'height': height}
                for tx_hash, height in history]

        return conf + await self.unconfirmed_history(hashX)

    def get_chunk(self, index):
        '''Return header chunk as hex.  Index is a non-negative integer.'''
        chunk_size = self.coin.CHUNK_SIZE
        next_height = self.height() + 1
        start_height = min(index * chunk_size, next_height)
        count = min(next_height - start_height, chunk_size)
        return self.bp.read_headers(start_height, count).hex()

    async def get_utxos(self, hashX):
        '''Get UTXOs asynchronously to reduce latency.'''
        def job():
            return list(self.bp.get_utxos(hashX, limit=None))
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, job)

    async def get_balance(self, hashX):
        utxos = await self.get_utxos(hashX)
        confirmed = sum(utxo.value for utxo in utxos)
        unconfirmed = self.manager.mempool_value(hashX)
        return {'confirmed': confirmed, 'unconfirmed': unconfirmed}

    async def list_unspent(self, hashX):
        return [{'tx_hash': hash_to_str(utxo.tx_hash), 'tx_pos': utxo.tx_pos,
                 'height': utxo.height, 'value': utxo.value}
                for utxo in sorted(await self.get_utxos(hashX))]

    # --- blockchain commands

    async def address_get_balance(self, params):
        hashX = self.params_to_hashX(params)
        return await self.get_balance(hashX)

    async def address_get_history(self, params):
        hashX = self.params_to_hashX(params)
        return await self.get_history(hashX)

    async def address_get_mempool(self, params):
        hashX = self.params_to_hashX(params)
        return await self.unconfirmed_history(hashX)

    async def address_get_proof(self, params):
        hashX = self.params_to_hashX(params)
        raise self.RPCError('get_proof is not yet implemented')

    async def address_listunspent(self, params):
        hashX = self.params_to_hashX(params)
        return await self.list_unspent(hashX)

    async def address_subscribe(self, params):
        hashX = self.params_to_hashX(params)
        if len(self.hashX_subs) >= self.max_subs:
            raise self.RPCError('your address subscription limit {:,d} reached'
                                .format(self.max_subs))
        result = await self.address_status(hashX)
        # add_subscription can raise so call it before adding
        self.manager.new_subscription()
        self.hashX_subs[hashX] = params[0]
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
            self.log_info('sendrawtransaction: {}'.format(message),
                          throttle=True)
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
        '''Returns the address for a TXO.

        Used only for electrum client command-line requests.  We no
        longer index by address, so need to request the raw
        transaction.  So it works for any TXO not just UTXOs.
        '''
        if len(params) == 2:
            tx_hash = self.param_to_tx_hash(params[0])
            index = self.param_to_non_negative_integer(params[1])
            raw_tx = await self.daemon_request('getrawtransaction', tx_hash)
            if not raw_tx:
                return None
            raw_tx = bytes.fromhex(raw_tx)
            deserializer = self.coin.deserializer()
            tx, tx_hash = deserializer(raw_tx).read_tx()
            if index >= len(tx.outputs):
                return None
            return self.coin.address_from_script(tx.outputs[index].pk_script)

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
                for pair in [
                    ('$VERSION', VERSION),
                    ('$DAEMON_VERSION', version),
                    ('$DAEMON_SUBVERSION', network_info['subversion']),
                    ('$DONATION_ADDRESS', self.env.donation_address),
                ]:
                    banner = banner.replace(*pair)

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
