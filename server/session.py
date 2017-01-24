# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Classes for local RPC server and remote client TCP/SSL servers.'''

import time
import traceback
from functools import partial

from lib.jsonrpc import JSONSession, RPCError
from server.daemon import DaemonError
from server.version import VERSION


class SessionBase(JSONSession):
    '''Base class of ElectrumX JSON sessions.

    Each session runs its tasks in asynchronous parallelism with other
    sessions.
    '''

    def __init__(self, controller, kind):
        super().__init__()
        self.kind = kind  # 'RPC', 'TCP' etc.
        self.controller = controller
        self.bp = controller.bp
        self.env = controller.env
        self.daemon = self.bp.daemon
        self.client = 'unknown'
        self.anon_logs = self.env.anon_logs
        self.last_delay = 0
        self.txs_sent = 0
        self.requests = []
        self.start_time = time.time()
        self.close_time = 0
        self.bw_time = self.start_time
        self.bw_interval = 3600
        self.bw_used = 0

    def have_pending_items(self):
        '''Called each time the pending item queue goes from empty to having
        one item.'''
        self.controller.enqueue_session(self)

    def close_connection(self):
        '''Call this to close the connection.'''
        self.close_time = time.time()
        super().close_connection()

    def peername(self, *, for_log=True):
        '''Return the peer name of this connection.'''
        peer_info = self.peer_info()
        if not peer_info:
            return 'unknown'
        if for_log and self.anon_logs:
            return 'xx.xx.xx.xx:xx'
        if ':' in peer_info[0]:
            return '[{}]:{}'.format(peer_info[0], peer_info[1])
        else:
            return '{}:{}'.format(peer_info[0], peer_info[1])

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

    def sub_count(self):
        return 0


class ElectrumX(SessionBase):
    '''A TCP server that handles incoming Electrum connections.'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subscribe_headers = False
        self.subscribe_height = False
        self.subscribe_peers = False
        self.notified_height = None
        self.max_send = self.env.max_send
        self.max_subs = self.env.max_session_subs
        self.hashX_subs = {}
        self.electrumx_handlers = {
            'blockchain.address.subscribe': self.address_subscribe,
            'blockchain.headers.subscribe': self.headers_subscribe,
            'blockchain.numblocks.subscribe': self.numblocks_subscribe,
            'blockchain.transaction.broadcast': self.transaction_broadcast,
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
        controller = self.controller
        pairs = []

        if height != self.notified_height:
            self.notified_height = height
            if self.subscribe_headers:
                args = (controller.electrum_header(height), )
                pairs.append(('blockchain.headers.subscribe', args))

            if self.subscribe_height:
                pairs.append(('blockchain.numblocks.subscribe', (height, )))

        matches = touched.intersection(self.hashX_subs)
        for hashX in matches:
            address = self.hashX_subs[hashX]
            status = await controller.address_status(hashX)
            pairs.append(('blockchain.address.subscribe', (address, status)))

        self.send_notifications(pairs)
        if matches:
            es = '' if len(matches) == 1 else 'es'
            self.log_info('notified of {:,d} address{}'
                          .format(len(matches), es))

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

    def peers_subscribe(self, incremental=False):
        '''Returns the server peers as a list of (ip, host, details) tuples.

        If incremental is False there is no subscription.  If True the
        remote side will receive notifications of new or modified
        peers (peers that disappeared are not notified).
        '''
        self.subscribe_peers = incremental
        return self.controller.peers.peer_list()

    def notify_peers(self, updates):
        '''Notify of peer updates.  Updates are sent as a list in the same
        format as the subscription reply, as the first parameter.
        '''
        if self.subscribe_peers:
            self.send_notification('server.peers.subscribe', [updates])

    async def address_subscribe(self, address):
        '''Subscribe to an address.

        address: the address to subscribe to'''
        # First check our limit.
        if len(self.hashX_subs) >= self.max_subs:
            raise RPCError('your address subscription limit {:,d} reached'
                           .format(self.max_subs))
        # Now let the controller check its limit
        hashX, status = await self.controller.new_subscription(address)
        self.hashX_subs[hashX] = address
        return status

    def server_features(self):
        '''Returns a dictionary of server features.'''
        peers = self.controller.peers
        hosts = {identity.host: {
            'tcp_port': identity.tcp_port,
            'ssl_port': identity.ssl_port,
            'pruning': peers.pruning,
            'version': peers.VERSION,
        } for identity in self.controller.peers.identities()}

        return {
            'hosts': hosts,
        }

    def server_version(self, client_name=None, protocol_version=None):
        '''Returns the server version as a string.

        client_name: a string identifying the client
        protocol_version: the protocol version spoken by the client
        '''
        if client_name:
            self.client = str(client_name)[:15]
        if protocol_version is not None:
            self.protocol_version = protocol_version
        return VERSION

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
