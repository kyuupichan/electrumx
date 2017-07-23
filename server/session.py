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
        self.protocol_version = '1.0'
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
        self.electrumx_handlers = {
            'blockchain.address.subscribe': self.address_subscribe,
            'blockchain.block.get_chunk': self.block_get_chunk,
            'blockchain.headers.subscribe': self.headers_subscribe,
            'blockchain.numblocks.subscribe': self.numblocks_subscribe,
            'blockchain.script_hash.subscribe': self.script_hash_subscribe,
            'blockchain.transaction.broadcast': self.transaction_broadcast,
            'server.add_peer': self.add_peer,
            'server.banner': self.banner,
            'server.features': self.server_features,
            'server.peers.subscribe': self.peers_subscribe,
            'server.version': self.server_version,
        }

    def sub_count(self):
        return len(self.hashX_subs)

    async def notify(self, height, touched):
        '''Notify the client about changes in height and touched addresses.

        Cache is a shared cache for this update.
        '''
        pairs = []
        changed = []

        matches = touched.intersection(self.hashX_subs)
        for hashX in matches:
            alias = self.hashX_subs[hashX]
            status = await self.address_status(hashX)
            changed.append((alias, status))

        if height != self.notified_height:
            self.notified_height = height
            if self.subscribe_headers:
                args = (self.controller.electrum_header(height), )
                pairs.append(('blockchain.headers.subscribe', args))

            if self.subscribe_height:
                pairs.append(('blockchain.numblocks.subscribe', (height, )))

            # Check mempool hashXs - the status is a function of the
            # confirmed state of other transactions
            for hashX in set(self.mempool_statuses).difference(matches):
                old_status = self.mempool_statuses[hashX]
                status = await self.address_status(hashX)
                if status != old_status:
                    alias = self.hashX_subs[hashX]
                    changed.append((alias, status))

        for alias_status in changed:
            if len(alias_status[0]) == 64:
                method = 'blockchain.script_hash.subscribe'
            else:
                method = 'blockchain.address.subscribe'
            pairs.append((method, alias_status))

        if pairs:
            self.send_notifications(pairs)
            if changed:
                es = '' if len(changed) == 1 else 'es'
                self.log_info('notified of {:,d} address{}'
                              .format(len(changed), es))

    def height(self):
        '''Return the current flushed database height.'''
        return self.bp.db_height

    def current_electrum_header(self):
        '''Used as response to a headers subscription request.'''
        return self.controller.electrum_header(self.height())

    def headers_subscribe(self):
        '''Subscribe to get headers of new blocks.'''
        self.subscribe_headers = True
        return self.current_electrum_header()

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

    async def script_hash_subscribe(self, script_hash):
        '''Subscribe to a script hash.

        script_hash: the SHA256 hash of the script to subscribe to'''
        hashX = self.controller.script_hash_to_hashX(script_hash)
        return await self.hashX_subscribe(hashX, script_hash)

    def server_features(self):
        '''Returns a dictionary of server features.'''
        return self.controller.peer_mgr.my_clearnet_peer().features

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
        if protocol_version is not None:
            self.protocol_version = protocol_version
        return version.VERSION

    async def transaction_broadcast(self, raw_tx):
        '''Broadcast a raw transaction to the network.

        raw_tx: the raw transaction as a hexadecimal string'''
        # An ugly API: current Electrum clients only pass the raw
        # transaction in hex and expect error messages to be returned in
        # the result field.  And the server shouldn't be doing the client's
        # user interface job here.
        try:
            tx_hash = await self.daemon.sendrawtransaction([raw_tx])
            self.txs_sent += 1
            self.log_info('sent tx: {}'.format(tx_hash))
            self.controller.sent_tx(tx_hash)
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
                .format(message, raw_tx)
            )

    def request_handler(self, method):
        '''Return the async handler for the given request method.'''
        handler = self.electrumx_handlers.get(method)
        if not handler:
            handler = self.controller.electrumx_handlers.get(method)
        return handler


class LocalRPC(SessionBase):
    '''A local TCP RPC server session.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = 'RPC'
        self.max_send = 0

    def request_handler(self, method):
        '''Return the async handler for the given request method.'''
        return self.controller.rpc_handlers.get(method)


class DashElectrumX(ElectrumX):
    '''A TCP server that handles incoming Electrum Dash connections.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.electrumx_handlers['masternode.announce.broadcast'] = self.masternode_announce_broadcast
        self.electrumx_handlers['masternode.subscribe'] = self.masternode_subscribe
        self.mns = set()

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
        '''Pass through the masternode announce message to be broadcast by the daemon.'''

        try:
            mnb_info = await self.daemon.masternode_broadcast(['relay', signmnb])
            return mnb_info
        except DaemonError as e:
            error = e.args[0]
            message = error['message']
            self.log_info('masternode_broadcast: {}'.format(message))
            return (
                'The masternode broadcast was rejected.  ({})\n[{}]'
                .format(message, signmnb)
            )

    async def masternode_subscribe(self, vin):
        '''Returns the status of masternode.'''
        result = await self.daemon.masternode_list(['status', vin])
        if result is not None:
            self.mns.add(vin)
            return result.get(vin)
        return None
