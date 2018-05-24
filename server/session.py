# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Classes for local RPC server and remote client TCP/SSL servers.'''

import codecs
import itertools
import time
from functools import partial

from aiorpcx import ServerSession, JSONRPCAutoDetect, RPCError

from lib.hash import sha256, hash_to_str
import lib.util as util
from server.daemon import DaemonError

BAD_REQUEST = 1
DAEMON_ERROR = 2


class Semaphores(object):

    def __init__(self, semaphores):
        self.semaphores = semaphores
        self.acquired = []

    async def __aenter__(self):
        for semaphore in self.semaphores:
            await semaphore.acquire()
            self.acquired.append(semaphore)

    async def __aexit__(self, exc_type, exc_value, traceback):
        for semaphore in self.acquired:
            semaphore.release()


class SessionBase(ServerSession):
    '''Base class of ElectrumX JSON sessions.

    Each session runs its tasks in asynchronous parallelism with other
    sessions.
    '''

    MAX_CHUNK_SIZE = 2016
    session_counter = itertools.count()

    def __init__(self, controller, kind):
        super().__init__(rpc_protocol=JSONRPCAutoDetect)
        self.kind = kind  # 'RPC', 'TCP' etc.
        self.controller = controller
        self.bp = controller.bp
        self.env = controller.env
        self.daemon = self.bp.daemon
        self.client = 'unknown'
        self.client_version = (1, )
        self.anon_logs = self.env.anon_logs
        self.txs_sent = 0
        self.log_me = False
        self.bw_limit = self.env.bandwidth_limit
        self._orig_mr = self.rpc.message_received

    def peer_address_str(self, *, for_log=True):
        '''Returns the peer's IP address and port as a human-readable
        string, respecting anon logs if the output is for a log.'''
        if for_log and self.anon_logs:
            return 'xx.xx.xx.xx:xx'
        return super().peer_address_str()

    def message_received(self, message):
        self.logger.info(f'processing {message}')
        self._orig_mr(message)

    def toggle_logging(self):
        self.log_me = not self.log_me
        if self.log_me:
            self.rpc.message_received = self.message_received
        else:
            self.rpc.message_received = self._orig_mr

    def flags(self):
        '''Status flags.'''
        status = self.kind[0]
        if self.is_closing():
            status += 'C'
        if self.log_me:
            status += 'L'
        status += str(self.concurrency.max_concurrent)
        return status

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        super().connection_made(transport)
        self.session_id = next(self.session_counter)
        context = {'conn_id': f'{self.session_id}'}
        self.logger = util.ConnectionLogger(self.logger, context)
        self.rpc.logger = self.logger
        self.group = self.controller.add_session(self)
        self.logger.info(f'{self.kind} {self.peer_address_str()}, '
                         f'{len(self.controller.sessions):,d} total')

    def connection_lost(self, exc):
        '''Handle client disconnection.'''
        super().connection_lost(exc)
        self.controller.remove_session(self)
        msg = ''
        if self.paused:
            msg += ' whilst paused'
        if self.concurrency.max_concurrent != self.max_concurrent:
            msg += ' whilst throttled'
        if self.send_size >= 1024*1024:
            msg += ('.  Sent {:,d} bytes in {:,d} messages'
                    .format(self.send_size, self.send_count))
        if msg:
            msg = 'disconnected' + msg
            self.logger.info(msg)

    def count_pending_items(self):
        return self.rpc.pending_requests

    def semaphore(self):
        return Semaphores([self.concurrency.semaphore, self.group.semaphore])

    def sub_count(self):
        return 0


class ElectrumX(SessionBase):
    '''A TCP server that handles incoming Electrum connections.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subscribe_headers = False
        self.subscribe_headers_raw = False
        self.subscribe_height = False
        self.notified_height = None
        self.max_response_size = self.env.max_send
        self.max_subs = self.env.max_session_subs
        self.hashX_subs = {}
        self.mempool_statuses = {}
        self.protocol_version = None
        self.set_protocol_handlers((1, 0))

    def sub_count(self):
        return len(self.hashX_subs)

    async def notify_async(self, our_touched):
        changed = {}

        for hashX in our_touched:
            alias = self.hashX_subs[hashX]
            status = await self.address_status(hashX)
            changed[alias] = status

        # Check mempool hashXs - the status is a function of the
        # confirmed state of other transactions.  Note: we cannot
        # iterate over mempool_statuses as it changes size.
        for hashX in set(self.mempool_statuses):
            old_status = self.mempool_statuses[hashX]
            status = await self.address_status(hashX)
            if status != old_status:
                alias = self.hashX_subs[hashX]
                changed[alias] = status

        for alias, status in changed.items():
            if len(alias) == 64:
                method = 'blockchain.scripthash.subscribe'
            else:
                method = 'blockchain.address.subscribe'
            self.send_notification(method, (alias, status))

        if changed:
            es = '' if len(changed) == 1 else 'es'
            self.logger.info('notified of {:,d} address{}'
                             .format(len(changed), es))

    def notify(self, height, touched):
        '''Notify the client about changes to touched addresses (from mempool
        updates or new blocks) and height.

        Return the set of addresses the session needs to be
        asyncronously notified about.  This can be empty if there are
        possible mempool status updates.

        Returns None if nothing needs to be notified asynchronously.
        '''
        height_changed = height != self.notified_height
        if height_changed:
            self.notified_height = height
            if self.subscribe_headers:
                args = (self.subscribe_headers_result(height), )
                self.send_notification('blockchain.headers.subscribe', args)
            if self.subscribe_height:
                args = (height, )
                self.send_notification('blockchain.numblocks.subscribe', args)

        our_touched = touched.intersection(self.hashX_subs)
        if our_touched or (height_changed and self.mempool_statuses):
            return our_touched

        return None

    def height(self):
        '''Return the current flushed database height.'''
        return self.bp.db_height

    def assert_boolean(self, value):
        '''Return param value it is boolean otherwise raise an RPCError.'''
        if value in (False, True):
            return value
        raise RPCError(BAD_REQUEST, f'{value} should be a boolean value')

    def subscribe_headers_result(self, height):
        '''The result of a header subscription for the given height.'''
        if self.subscribe_headers_raw:
            raw_header = self.controller.raw_header(height)
            return {'hex': raw_header.hex(), 'height': height}
        return self.controller.electrum_header(height)

    def headers_subscribe(self, raw=False):
        '''Subscribe to get headers of new blocks.'''
        self.subscribe_headers = True
        self.subscribe_headers_raw = self.assert_boolean(raw)
        self.notified_height = self.height()
        return self.subscribe_headers_result(self.height())

    def numblocks_subscribe(self):
        '''Subscribe to get height of new blocks.'''
        self.subscribe_height = True
        return self.height()

    async def add_peer(self, features):
        '''Add a peer (but only if the peer resolves to the source).'''
        peer_mgr = self.controller.peer_mgr
        return await peer_mgr.on_add_peer(features, self.peer_address())

    def peers_subscribe(self):
        '''Return the server peers as a list of (ip, host, details) tuples.'''
        return self.controller.peer_mgr.on_peers_subscribe(self.is_tor())

    async def address_status(self, hashX):
        '''Returns an address status.

        Status is a hex string, but must be None if there is no history.
        '''
        # Note history is ordered and mempool unordered in electrum-server
        # For mempool, height is -1 if unconfirmed txins, otherwise 0
        history = await self.controller.get_history(hashX)
        mempool = await self.controller.mempool_transactions(hashX)

        status = ''.join('{}:{:d}:'.format(hash_to_str(tx_hash), height)
                         for tx_hash, height in history)
        status += ''.join('{}:{:d}:'.format(hex_hash, -unconfirmed)
                          for hex_hash, tx_fee, unconfirmed in mempool)
        if status:
            status = sha256(status.encode()).hex()
        else:
            status = None

        if mempool:
            self.mempool_statuses[hashX] = status
        else:
            self.mempool_statuses.pop(hashX, None)

        return status

    async def hashX_subscribe(self, hashX, alias):
        # First check our limit.
        if len(self.hashX_subs) >= self.max_subs:
            raise RPCError(BAD_REQUEST, 'your address subscription limit '
                           f'{self.max_subs:,d} reached')

        # Now let the controller check its limit
        self.controller.new_subscription()
        self.hashX_subs[hashX] = alias
        return await self.address_status(hashX)

    async def address_subscribe(self, address):
        '''Subscribe to an address.

        address: the address to subscribe to'''
        hashX = self.controller.address_to_hashX(address)
        return await self.hashX_subscribe(hashX, address)

    async def scripthash_subscribe(self, scripthash):
        '''Subscribe to a script hash.

        scripthash: the SHA256 hash of the script to subscribe to'''
        hashX = self.controller.scripthash_to_hashX(scripthash)
        return await self.hashX_subscribe(hashX, scripthash)

    def block_headers(self, start_height, count):
        '''Return count concatenated block headers as hex for the main chain;
        starting at start_height.

        start_height and count must be non-negative integers.  At most
        MAX_CHUNK_SIZE headers will be returned.
        '''
        start_height = self.controller.non_negative_integer(start_height)
        count = self.controller.non_negative_integer(count)
        count = min(count, self.MAX_CHUNK_SIZE)
        hex_str, n =  self.controller.block_headers(start_height, count)
        return {'hex': hex_str, 'count': n, 'max': self.MAX_CHUNK_SIZE}

    def block_get_chunk(self, index):
        '''Return a chunk of block headers as a hexadecimal string.

        index: the chunk index'''
        index = self.controller.non_negative_integer(index)
        chunk_size = self.controller.coin.CHUNK_SIZE
        start_height = index * chunk_size
        hex_str, n =  self.controller.block_headers(start_height, chunk_size)
        return hex_str

    def is_tor(self):
        '''Try to detect if the connection is to a tor hidden service we are
        running.'''
        peername = self.controller.peer_mgr.proxy_peername()
        if not peername:
            return False
        peer_address = self.peer_address()
        return peer_address and peer_address[0] == peername[0]

    async def replaced_banner(self, banner):
        network_info = await self.controller.daemon_request('getnetworkinfo')
        ni_version = network_info['version']
        major, minor = divmod(ni_version, 1000000)
        minor, revision = divmod(minor, 10000)
        revision //= 100
        daemon_version = '{:d}.{:d}.{:d}'.format(major, minor, revision)
        for pair in [
                ('$SERVER_VERSION', self.controller.short_version()),
                ('$SERVER_SUBVERSION', self.controller.VERSION),
                ('$DAEMON_VERSION', daemon_version),
                ('$DAEMON_SUBVERSION', network_info['subversion']),
                ('$DONATION_ADDRESS', self.env.donation_address),
        ]:
            banner = banner.replace(*pair)
        return banner

    def donation_address(self):
        '''Return the donation address as a string, empty if there is none.'''
        return self.env.donation_address

    async def banner(self):
        '''Return the server banner text.'''
        banner = 'Welcome to Electrum!'

        if self.is_tor():
            banner_file = self.env.tor_banner_file
        else:
            banner_file = self.env.banner_file
        if banner_file:
            try:
                with codecs.open(banner_file, 'r', 'utf-8') as f:
                    banner = f.read()
            except Exception as e:
                self.loggererror(f'reading banner file {banner_file}: {e}')
            else:
                banner = await self.replaced_banner(banner)

        return banner

    def ping(self):
        '''Serves as a connection keep-alive mechanism and for the client to
        confirm the server is still responding.
        '''
        return None

    def server_version(self, client_name=None, protocol_version=None):
        '''Returns the server version as a string.

        client_name: a string identifying the client
        protocol_version: the protocol version spoken by the client
        '''
        if client_name:
            if self.env.drop_client is not None and \
                    self.env.drop_client.match(client_name):
                self.close_after_send = True
                raise RPCError(BAD_REQUEST,
                               f'unsupported client: {client_name}')
            self.client = str(client_name)[:17]
            try:
                self.client_version = tuple(int(part) for part
                                            in self.client.split('.'))
            except Exception:
                pass

        # Find the highest common protocol version.  Disconnect if
        # that protocol version in unsupported.
        ptuple = self.controller.protocol_tuple(protocol_version)

        # From protocol version 1.1, protocol_version cannot be omitted
        if ptuple is None or (ptuple >= (1, 1) and protocol_version is None):
            self.logger.info('unsupported protocol version request {}'
                             .format(protocol_version))
            self.close_after_send = True
            raise RPCError(BAD_REQUEST,
                           f'unsupported protocol version: {protocol_version}')

        self.set_protocol_handlers(ptuple)

        # The return value depends on the protocol version
        if ptuple < (1, 1):
            return self.controller.VERSION
        else:
            return (self.controller.VERSION, self.protocol_version)

    async def transaction_broadcast(self, raw_tx):
        '''Broadcast a raw transaction to the network.

        raw_tx: the raw transaction as a hexadecimal string'''
        # This returns errors as JSON RPC errors, as is natural
        try:
            tx_hash = await self.daemon.sendrawtransaction([raw_tx])
            self.txs_sent += 1
            self.logger.info('sent tx: {}'.format(tx_hash))
            self.controller.sent_tx(tx_hash)
            return tx_hash
        except DaemonError as e:
            error, = e.args
            message = error['message']
            self.logger.info('sendrawtransaction: {}'.format(message))
            raise RPCError(BAD_REQUEST, 'the transaction was rejected by '
                           f'network rules.\n\n{message}\n[{raw_tx}]')

    async def transaction_broadcast_1_0(self, raw_tx):
        '''Broadcast a raw transaction to the network.

        raw_tx: the raw transaction as a hexadecimal string'''
        # An ugly API: current Electrum clients only pass the raw
        # transaction in hex and expect error messages to be returned in
        # the result field.  And the server shouldn't be doing the client's
        # user interface job here.
        try:
            return await self.transaction_broadcast(raw_tx)
        except RPCError as e:
            message = e.message
            if 'non-mandatory-script-verify-flag' in message:
                message = (
                    'Your client produced a transaction that is not accepted '
                    'by the network any more.  Please upgrade to Electrum '
                    '2.5.1 or newer.'
                )

            return message

    def set_protocol_handlers(self, ptuple):
        protocol_version = '.'.join(str(part) for part in ptuple)
        if protocol_version == self.protocol_version:
            return
        self.protocol_version = protocol_version

        controller = self.controller
        handlers = {
            'blockchain.address.get_balance': controller.address_get_balance,
            'blockchain.address.get_history': controller.address_get_history,
            'blockchain.address.get_mempool': controller.address_get_mempool,
            'blockchain.address.listunspent': controller.address_listunspent,
            'blockchain.address.subscribe': self.address_subscribe,
            'blockchain.block.get_chunk': self.block_get_chunk,
            'blockchain.block.get_header': controller.block_get_header,
            'blockchain.estimatefee': controller.estimatefee,
            'blockchain.headers.subscribe': self.headers_subscribe,
            'blockchain.relayfee': controller.relayfee,
            'blockchain.transaction.get_merkle':
            controller.transaction_get_merkle,
            'server.add_peer': self.add_peer,
            'server.banner': self.banner,
            'server.donation_address': self.donation_address,
            'server.features': self.controller.server_features,
            'server.peers.subscribe': self.peers_subscribe,
            'server.version': self.server_version,
        }

        if ptuple < (1, 1):
            # Methods or semantics unique to 1.0 and earlier protocols
            handlers.update({
                'blockchain.numblocks.subscribe': self.numblocks_subscribe,
                'blockchain.utxo.get_address': controller.utxo_get_address,
                'blockchain.transaction.broadcast':
                self.transaction_broadcast_1_0,
                'blockchain.transaction.get': controller.transaction_get_1_0,
            })

        if ptuple >= (1, 1):
            # New handlers as of 1.1, or different semantics
            handlers.update({
                'blockchain.scripthash.get_balance':
                controller.scripthash_get_balance,
                'blockchain.scripthash.get_history':
                controller.scripthash_get_history,
                'blockchain.scripthash.get_mempool':
                controller.scripthash_get_mempool,
                'blockchain.scripthash.listunspent':
                controller.scripthash_listunspent,
                'blockchain.scripthash.subscribe': self.scripthash_subscribe,
                'blockchain.transaction.broadcast': self.transaction_broadcast,
                'blockchain.transaction.get': controller.transaction_get,
            })

        if ptuple >= (1, 2):
            # New handler as of 1.2
            handlers.update({
                'mempool.get_fee_histogram':
                controller.mempool_get_fee_histogram,
                'blockchain.block.headers': self.block_headers,
                'server.ping': self.ping,
            })

        self.electrumx_handlers = handlers

    def request_handler(self, method):
        '''Return the async handler for the given request method.'''
        return self.electrumx_handlers.get(method)


class LocalRPC(SessionBase):
    '''A local TCP RPC server session.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = 'RPC'
        self.max_response_size = 0
        self.protocol_version = 'RPC'

    def request_handler(self, method):
        '''Return the async handler for the given request method.'''
        return self.controller.rpc_handlers.get(method)


class DashElectrumX(ElectrumX):
    '''A TCP server that handles incoming Electrum Dash connections.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mns = set()

    def set_protocol_handlers(self, ptuple):
        super().set_protocol_handlers(ptuple)
        mna_broadcast = (self.masternode_announce_broadcast if ptuple >= (1, 1)
                         else self.masternode_announce_broadcast_1_0)
        self.electrumx_handlers.update({
            'masternode.announce.broadcast': mna_broadcast,
            'masternode.subscribe': self.masternode_subscribe,
        })

    def notify(self, height, touched):
        '''Notify the client about changes in masternode list.'''
        result = super().notify(height, touched)

        for masternode in self.mns:
            status = self.daemon.masternode_list(['status', masternode])
            self.send_notification('masternode.subscribe',
                                   [masternode, status.get(masternode)])
        return result

    # Masternode command handlers
    async def masternode_announce_broadcast(self, signmnb):
        '''Pass through the masternode announce message to be broadcast
        by the daemon.'''
        try:
            return await self.daemon.masternode_broadcast(['relay', signmnb])
        except DaemonError as e:
            error, = e.args
            message = error['message']
            self.logger.info('masternode_broadcast: {}'.format(message))
            raise RPCError(BAD_REQUEST, 'the masternode broadcast was '
                           f'rejected.\n\n{message}\n[{signmnb}]')

    async def masternode_announce_broadcast_1_0(self, signmnb):
        '''Pass through the masternode announce message to be broadcast
        by the daemon.'''
        # An ugly API, like the old Electrum transaction broadcast API
        try:
            return await self.masternode_announce_broadcast(signmnb)
        except RPCError as e:
            return e.message

    async def masternode_subscribe(self, vin):
        '''Returns the status of masternode.'''
        result = await self.daemon.masternode_list(['status', vin])
        if result is not None:
            self.mns.add(vin)
            return result.get(vin)
        return None
