# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Classes for local RPC server and remote client TCP/SSL servers.'''


import asyncio
import traceback

from lib.jsonrpc import JSONRPC, RPCError
from server.daemon import DaemonError


class Session(JSONRPC):
    '''Base class of ElectrumX JSON session protocols.

    Each session runs its tasks in asynchronous parallelism with other
    sessions.  To prevent some sessions blocking others, potentially
    long-running requests should yield.
    '''

    def __init__(self, controller, bp, env, kind):
        super().__init__()
        self.controller = controller
        self.bp = bp
        self.env = env
        self.daemon = bp.daemon
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
        status += str(self.controller.session_priority(self))
        return status

    def requests_remaining(self):
        return sum(request.remaining for request in self.requests)

    def enqueue_request(self, request):
        '''Add a request to the session's list.'''
        self.requests.append(request)
        if len(self.requests) == 1:
            self.controller.enqueue_session(self)

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
            self.controller.enqueue_session(self)

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        super().connection_made(transport)
        self.controller.add_session(self)

    def connection_lost(self, exc):
        '''Handle client disconnection.'''
        super().connection_lost(exc)
        if (self.pause or self.controller.is_deprioritized(self)
                 or self.send_size >= 1024*1024 or self.error_count):
            self.log_info('disconnected.  Sent {:,d} bytes in {:,d} messages '
                          '{:,d} errors'
                          .format(self.send_size, self.send_count,
                                  self.error_count))
        self.controller.remove_session(self)

    def sub_count(self):
        return 0


class ElectrumX(Session):
    '''A TCP server that handles incoming Electrum connections.'''

    def __init__(self, *args):
        super().__init__(*args)
        self.subscribe_headers = False
        self.subscribe_height = False
        self.notified_height = None
        self.max_subs = self.env.max_session_subs
        self.hashX_subs = {}
        self.electrumx_handlers = {
            'blockchain.address.subscribe': self.address_subscribe,
            'blockchain.headers.subscribe': self.headers_subscribe,
            'blockchain.numblocks.subscribe': self.numblocks_subscribe,
            'blockchain.transaction.broadcast': self.transaction_broadcast,
        }

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
                    (self.controller.electrum_header(height), ),
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
            status = await self.controller.address_status(hashX)
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
        return self.controller.electrum_header(self.height())

    async def headers_subscribe(self):
        '''Subscribe to get headers of new blocks.'''
        self.subscribe_headers = True
        return self.current_electrum_header()

    async def numblocks_subscribe(self):
        '''Subscribe to get height of new blocks.'''
        self.subscribe_height = True
        return self.height()

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


class LocalRPC(Session):
    '''A local TCP RPC server for querying status.'''

    def __init__(self, *args):
        super().__init__(*args)
        self.client = 'RPC'
        self.max_send = 5000000

    def request_handler(self, method):
        '''Return the async handler for the given request method.'''
        return self.controller.rpc_handlers.get(method)
