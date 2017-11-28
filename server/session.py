# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Classes for local RPC server and remote client TCP/SSL servers.'''

import codecs
import time
from functools import partial

from lib.hash import sha256, hash_to_str
from lib.jsonrpc import JSONSession, RPCError, JSONRPCv2, JSONRPC
import lib.util as util
from server.daemon import DaemonError
import server.version as version


class SessionBase(JSONSession):
    '''Base class of ElectrumX JSON sessions.

    Each session runs its tasks in asynchronous parallelism with other
    sessions.
    '''

    def __init__(self, controller, kind):
        # Force v2 as a temporary hack for old Coinomi wallets
        # Remove in April 2017
        super().__init__(version=JSONRPCv2)
        self.kind = kind  # 'RPC', 'TCP' etc.
        self.controller = controller
        self.bp = controller.bp
        self.env = controller.env
        self.daemon = self.bp.daemon
        self.client = 'unknown'
        self.client_version = (1, )
        self.anon_logs = self.env.anon_logs
        self.last_delay = 0
        self.txs_sent = 0
        self.requests = []
        self.start_time = time.time()
        self.close_time = 0
        self.bw_limit = self.env.bandwidth_limit
        self.bw_time = self.start_time
        self.bw_interval = 3600
        self.bw_used = 0

    def close_connection(self):
        '''Call this to close the connection.'''
        self.close_time = time.time()
        super().close_connection()

    def peername(self, *, for_log=True):
        '''Return the peer address and port.'''
        return self.peer_addr(anon=for_log and self.anon_logs)

    def flags(self):
        '''Status flags.'''
        status = self.kind[0]
        if self.is_closing():
            status += 'C'
        if self.log_me:
            status += 'L'
        status += str(self.controller.session_priority(self))
        return status

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        super().connection_made(transport)
        self.controller.add_session(self)

    def connection_lost(self, exc):
        '''Handle client disconnection.'''
        super().connection_lost(exc)
        msg = ''
        if self.pause:
            msg += ' whilst paused'
        if self.controller.is_deprioritized(self):
            msg += ' whilst deprioritized'
        if self.send_size >= 1024*1024:
            msg += ('.  Sent {:,d} bytes in {:,d} messages'
                    .format(self.send_size, self.send_count))
        if msg:
            msg = 'disconnected' + msg
            self.log_info(msg)
        self.controller.remove_session(self)

    def using_bandwidth(self, amount):
        now = time.time()
        # Reduce the recorded usage in proportion to the elapsed time
        elapsed = now - self.bw_time
        self.bandwidth_start = now
        refund = int(elapsed / self.bw_interval * self.bw_limit)
        refund = min(refund, self.bw_used)
        self.bw_used += amount - refund

    def sub_count(self):
        return 0


class ElectrumX(SessionBase):
    '''A TCP server that handles incoming Electrum connections.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subscribe_headers = False
        self.subscribe_height = False
        self.notified_height = None
        self.max_send = self.env.max_send
        self.max_subs = self.env.max_session_subs
        self.hashX_subs = {}
        self.mempool_statuses = {}
        self.chunk_indices = []
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
            self.log_info('notified of {:,d} address{}'
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
                args = (self.controller.electrum_header(height), )
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

    def headers_subscribe(self):
        '''Subscribe to get headers of new blocks.'''
        self.subscribe_headers = True
        height = self.height()
        self.notified_height = height
        return self.controller.electrum_header(height)

    def numblocks_subscribe(self):
        '''Subscribe to get height of new blocks.'''
        self.subscribe_height = True
        return self.height()

    async def add_peer(self, features):
        '''Add a peer (but only if the peer resolves to the source).'''
        peer_mgr = self.controller.peer_mgr
        return await peer_mgr.on_add_peer(features, self.peer_info())

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
            raise RPCError('your address subscription limit {:,d} reached'
                           .format(self.max_subs))

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

    def server_features(self):
        '''Returns a dictionary of server features.'''
        return self.env.server_features()

    def block_get_chunk(self, index):
        '''Return a chunk of block headers as a hexadecimal string.

        index: the chunk index'''
        index = self.controller.non_negative_integer(index)
        if self.client_version < (2, 8, 3):
            self.chunk_indices.append(index)
            self.chunk_indices = self.chunk_indices[-5:]
            # -2 allows backing up a single chunk but no more.
            if index <= max(self.chunk_indices[:-2], default=-1):
                msg = ('chunk indices not advancing (wrong network?): {}'
                       .format(self.chunk_indices))
                # use INVALID_REQUEST to trigger a disconnect
                raise RPCError(msg, JSONRPC.INVALID_REQUEST)
        return self.controller.get_chunk(index)

    def is_tor(self):
        '''Try to detect if the connection is to a tor hidden service we are
        running.'''
        proxy = self.controller.peer_mgr.proxy
        peer_info = self.peer_info()
        return peer_info and peer_info[0] == proxy.ip_addr

    async def replaced_banner(self, banner):
        network_info = await self.controller.daemon_request('getnetworkinfo')
        ni_version = network_info['version']
        major, minor = divmod(ni_version, 1000000)
        minor, revision = divmod(minor, 10000)
        revision //= 100
        daemon_version = '{:d}.{:d}.{:d}'.format(major, minor, revision)
        server_version = version.VERSION.split()[-1]
        for pair in [
                ('$VERSION', version.VERSION), # legacy
                ('$SERVER_VERSION', server_version),
                ('$SERVER_SUBVERSION', version.VERSION),
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
                self.log_error('reading banner file {}: {}'
                               .format(banner_file, e))
            else:
                banner = await self.replaced_banner(banner)

        return banner

    def server_version(self, client_name=None, protocol_version=None):
        '''Returns the server version as a string.

        client_name: a string identifying the client
        protocol_version: the protocol version spoken by the client
        '''
        if client_name:
            self.client = str(client_name)[:17]
            try:
                self.client_version = tuple(int(part) for part
                                            in self.client.split('.'))
            except Exception:
                pass

        # Find the highest common protocol version.  Disconnect if
        # that protocol version in unsupported.
        ptuple = util.protocol_version(protocol_version, version.PROTOCOL_MIN,
                                       version.PROTOCOL_MAX)

        # From protocol version 1.1, protocol_version cannot be omitted
        if ptuple is None or (ptuple >= (1, 1) and protocol_version is None):
            self.log_info('unsupported protocol version request {}'
                          .format(protocol_version))
            raise RPCError('unsupported protocol version: {}'
                           .format(protocol_version), JSONRPC.FATAL_ERROR)

        self.set_protocol_handlers(ptuple)

        # The return value depends on the protocol version
        if ptuple < (1, 1):
            return version.VERSION
        else:
            return (version.VERSION, self.protocol_version)

    async def transaction_broadcast(self, raw_tx):
        '''Broadcast a raw transaction to the network.

        raw_tx: the raw transaction as a hexadecimal string'''
        # This returns errors as JSON RPC errors, as is natural
        try:
            tx_hash = await self.daemon.sendrawtransaction([raw_tx])
            self.txs_sent += 1
            self.log_info('sent tx: {}'.format(tx_hash))
            self.controller.sent_tx(tx_hash)
            return tx_hash
        except DaemonError as e:
            error, = e.args
            message = error['message']
            self.log_info('sendrawtransaction: {}'.format(message),
                          throttle=True)
            raise RPCError('the transaction was rejected by network rules.'
                           '\n\n{}\n[{}]'.format(message, raw_tx))

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
            message = e.msg
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
            'server.features': self.server_features,
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

        self.electrumx_handlers = handlers

    def request_handler(self, method):
        '''Return the async handler for the given request method.'''
        return self.electrumx_handlers.get(method)


class LocalRPC(SessionBase):
    '''A local TCP RPC server session.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = 'RPC'
        self.max_send = 0
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

    async def notify(self, height, touched):
        '''Notify the client about changes in masternode list.'''
        await super().notify(height, touched)

        for masternode in self.mns:
            status = await self.daemon.masternode_list(['status', masternode])
            payload = {
                'id': None,
                'method': 'masternode.subscribe',
                'params': [masternode],
                'result': status.get(masternode),
            }
            self.send_binary(self.encode_payload(payload))

    def server_version(self, client_name=None, protocol_version=None):
        '''Returns the server version as a string.
        Force version string response for Electrum-Dash 2.6.4 client caused by
        https://github.com/dashpay/electrum-dash/commit/638cf6c0aeb7be14a85ad98f873791cb7b49ee29
        '''
        default_return = super().server_version(client_name, protocol_version)
        if self.client == '2.6.4':
            return '1.0'
        return default_return

    # Masternode command handlers
    async def masternode_announce_broadcast(self, signmnb):
        '''Pass through the masternode announce message to be broadcast
        by the daemon.'''
        try:
            return await self.daemon.masternode_broadcast(['relay', signmnb])
        except DaemonError as e:
            error, = e.args
            message = error['message']
            self.log_info('masternode_broadcast: {}'.format(message))
            raise RPCError('the masternode broadcast was rejected.'
                           '\n\n{}\n[{}]'.format(message, signmnb))

    async def masternode_announce_broadcast_1_0(self, signmnb):
        '''Pass through the masternode announce message to be broadcast
        by the daemon.'''
        # An ugly API, like the old Electrum transaction broadcast API
        try:
            return await self.masternode_announce_broadcast(signmnb)
        except RPCError as e:
            return e.msg

    async def masternode_subscribe(self, vin):
        '''Returns the status of masternode.'''
        result = await self.daemon.masternode_list(['status', vin])
        if result is not None:
            self.mns.add(vin)
            return result.get(vin)
        return None
