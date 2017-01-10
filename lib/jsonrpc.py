# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Class for handling JSON RPC 2.0 connections, server or client.'''

import asyncio
import inspect
import json
import numbers
import time
import traceback

from lib.util import LoggedClass


class RPCError(Exception):
    '''RPC handlers raise this error.'''
    def __init__(self, msg, code=-1, **kw_args):
        super().__init__(**kw_args)
        self.msg = msg
        self.code = code


class RequestBase(object):
    '''An object that represents a queued request.'''

    def __init__(self, remaining):
        self.remaining = remaining


class SingleRequest(RequestBase):
    '''An object that represents a single request.'''

    def __init__(self, payload):
        super().__init__(1)
        self.payload = payload

    async def process(self, session):
        '''Asynchronously handle the JSON request.'''
        self.remaining = 0
        binary = await session.process_single_payload(self.payload)
        if binary:
            session._send_bytes(binary)

    def __str__(self):
        return str(self.payload)


class BatchRequest(RequestBase):
    '''An object that represents a batch request and its processing state.

    Batches are processed in chunks.
    '''

    def __init__(self, payload):
        super().__init__(len(payload))
        self.payload = payload
        self.parts = []

    async def process(self, session):
        '''Asynchronously handle the JSON batch according to the JSON 2.0
        spec.'''
        target = max(self.remaining - 4, 0)
        while self.remaining > target:
            item = self.payload[len(self.payload) - self.remaining]
            self.remaining -= 1
            part = await session.process_single_payload(item)
            if part:
                self.parts.append(part)

        total_len = sum(len(part) + 2 for part in self.parts)
        if session.is_oversized_request(total_len):
            raise RPCError('request too large', JSONRPC.INVALID_REQUEST)

        if not self.remaining:
            if self.parts:
                binary = b'[' + b', '.join(self.parts) + b']'
                session._send_bytes(binary)

    def __str__(self):
        return str(self.payload)


class JSONRPC(asyncio.Protocol, LoggedClass):
    '''Manages a JSONRPC connection.

    Assumes JSON messages are newline-separated and that newlines
    cannot appear in the JSON other than to separate lines.  Incoming
    requests are passed to enqueue_request(), which should arrange for
    their asynchronous handling via the request's process() method.

    Derived classes may want to override connection_made() and
    connection_lost() but should be sure to call the implementation in
    this base class first.  They may also want to implement the asynchronous
    function handle_response() which by default does nothing.

    The functions request_handler() and notification_handler() are
    passed an RPC method name, and should return an asynchronous
    function to call to handle it.  The functions' docstrings are used
    for help, and the arguments are what can be used as JSONRPC 2.0
    named arguments (and thus become part of the external interface).
    If the method is unknown return None.

    Request handlers should return a Python object to return to the
    caller, or raise an RPCError on error.  Notification handlers
    should not return a value or raise any exceptions.
    '''

    # See http://www.jsonrpc.org/specification
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_ARGS = -32602
    INTERNAL_ERROR = -32603

    ID_TYPES = (type(None), str, numbers.Number)
    NEXT_SESSION_ID = 0

    @classmethod
    def request_payload(cls, method, id_, params=None):
        payload = {'jsonrpc': '2.0', 'id': id_, 'method': method}
        if params:
            payload['params'] = params
        return payload

    @classmethod
    def response_payload(cls, result, id_):
        return {'jsonrpc': '2.0', 'result': result, 'id': id_}

    @classmethod
    def notification_payload(cls, method, params=None):
        return cls.request_payload(method, None, params)

    @classmethod
    def error_payload(cls, message, code, id_=None):
        error = {'message': message, 'code': code}
        return {'jsonrpc': '2.0', 'error': error, 'id': id_}

    @classmethod
    def check_payload_id(cls, payload):
        '''Extract and return the ID from the payload.

        Raises an RPCError if it is missing or invalid.'''
        if not 'id' in payload:
            raise RPCError('missing id', JSONRPC.INVALID_REQUEST)

        id_ = payload['id']
        if not isinstance(id_, JSONRPC.ID_TYPES):
            raise RPCError('invalid id: {}'.format(id_),
                           JSONRPC.INVALID_REQUEST)
        return id_

    @classmethod
    def payload_id(cls, payload):
        '''Extract and return the ID from the payload.

        Returns None if it is missing or invalid.'''
        try:
            return cls.check_payload_id(payload)
        except RPCError:
            return None

    def __init__(self):
        super().__init__()
        self.start = time.time()
        self.stop = 0
        self.last_recv = self.start
        self.bandwidth_start = self.start
        self.bandwidth_interval = 3600
        self.bandwidth_used = 0
        self.bandwidth_limit = 5000000
        self.transport = None
        self.pause = False
        # Parts of an incomplete JSON line.  We buffer them until
        # getting a newline.
        self.parts = []
        # recv_count is JSON messages not calls to data_received()
        self.recv_count = 0
        self.recv_size = 0
        self.send_count = 0
        self.send_size = 0
        self.error_count = 0
        self.close_after_send = False
        self.peer_info = None
        # Sends longer than max_send are prevented, instead returning
        # an oversized request error to other end of the network
        # connection.  The request causing it is logged.  Values under
        # 1000 are treated as 1000.
        self.max_send = 0
        # If buffered incoming data exceeds this the connection is closed
        self.max_buffer_size = 1000000
        self.anon_logs = False
        self.id_ = JSONRPC.NEXT_SESSION_ID
        JSONRPC.NEXT_SESSION_ID += 1
        self.log_prefix = '[{:d}] '.format(self.id_)
        self.log_me = False

    def peername(self, *, for_log=True):
        '''Return the peer name of this connection.'''
        if not self.peer_info:
            return 'unknown'
        if for_log and self.anon_logs:
            return 'xx.xx.xx.xx:xx'
        if ':' in self.peer_info[0]:
            return '[{}]:{}'.format(self.peer_info[0], self.peer_info[1])
        else:
            return '{}:{}'.format(self.peer_info[0], self.peer_info[1])

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        self.transport = transport
        self.peer_info = transport.get_extra_info('peername')
        transport.set_write_buffer_limits(high=500000)

    def connection_lost(self, exc):
        '''Handle client disconnection.'''
        pass

    def pause_writing(self):
        '''Called by asyncio when the write buffer is full.'''
        self.log_info('pausing request processing whilst socket drains')
        self.pause = True

    def resume_writing(self):
        '''Called by asyncio when the write buffer has room.'''
        self.log_info('resuming request processing')
        self.pause = False

    def close_connection(self):
        self.stop = time.time()
        if self.transport:
            self.transport.close()

    def using_bandwidth(self, amount):
        now = time.time()
        # Reduce the recorded usage in proportion to the elapsed time
        elapsed = now - self.bandwidth_start
        self.bandwidth_start = now
        refund = int(elapsed / self.bandwidth_interval * self.bandwidth_limit)
        refund = min(refund, self.bandwidth_used)
        self.bandwidth_used += amount - refund
        self.throttled = max(0, self.throttled - int(elapsed) // 60)

    def data_received(self, data):
        '''Handle incoming data (synchronously).

        Requests end in newline characters.  Pass complete requests to
        decode_message for handling.
        '''
        self.recv_size += len(data)
        self.using_bandwidth(len(data))

        # Close abusive connections where buffered data exceeds limit
        buffer_size = len(data) + sum(len(part) for part in self.parts)
        if buffer_size > self.max_buffer_size:
            self.log_error('read buffer of {:,d} bytes exceeds {:,d} '
                           'byte limit, closing {}'
                           .format(buffer_size, self.max_buffer_size,
                                   self.peername()))
            self.close_connection()

        # Do nothing if this connection is closing
        if self.transport.is_closing():
            return

        while True:
            npos = data.find(ord('\n'))
            if npos == -1:
                self.parts.append(data)
                break
            self.last_recv = time.time()
            self.recv_count += 1
            tail, data = data[:npos], data[npos + 1:]
            parts, self.parts = self.parts, []
            parts.append(tail)
            self.decode_message(b''.join(parts))

    def decode_message(self, message):
        '''Decode a binary message and queue it for asynchronous handling.

        Messages that cannot be decoded are logged and dropped.
        '''
        try:
            message = message.decode()
        except UnicodeDecodeError as e:
            msg = 'cannot decode binary bytes: {}'.format(e)
            self.send_json_error(msg, JSONRPC.PARSE_ERROR)
            return

        try:
            message = json.loads(message)
        except json.JSONDecodeError as e:
            msg = 'cannot decode JSON: {}'.format(e)
            self.send_json_error(msg, JSONRPC.PARSE_ERROR)
            return

        if isinstance(message, list):
            # Batches must have at least one object.
            if not message:
                self.send_json_error('empty batch', JSONRPC.INVALID_REQUEST)
                return
            request = BatchRequest(message)
        else:
            request = SingleRequest(message)

        '''Queue the request for asynchronous handling.'''
        self.enqueue_request(request)
        if self.log_me:
            self.log_info('queued {}'.format(message))

    def send_json_error(self, message, code, id_=None):
        '''Send a JSON error.'''
        self._send_bytes(self.json_error_bytes(message, code, id_))

    def encode_payload(self, payload):
        assert isinstance(payload, dict)

        try:
            binary = json.dumps(payload).encode()
        except TypeError:
            msg = 'JSON encoding failure: {}'.format(payload)
            self.log_error(msg)
            binary = self.json_error_bytes(msg, JSONRPC.INTERNAL_ERROR,
                                           payload.get('id'))

        if self.is_oversized_request(len(binary)):
            binary = self.json_error_bytes('request too large',
                                           JSONRPC.INVALID_REQUEST,
                                           payload.get('id'))
        self.send_count += 1
        self.send_size += len(binary)
        self.using_bandwidth(len(binary))
        return binary

    def is_oversized_request(self, total_len):
        return total_len > max(1000, self.max_send)

    def _send_bytes(self, binary):
        '''Send JSON text over the transport.  Close it if close is True.'''
        # Confirmed this happens, sometimes a lot
        if self.transport.is_closing():
            return
        self.transport.write(binary)
        self.transport.write(b'\n')
        if self.close_after_send:
            self.close_connection()

    def encode_and_send_payload(self, payload):
        '''Encode the payload and send it.'''
        self._send_bytes(self.encode_payload(payload))

    def json_notification_bytes(self, method, params):
        '''Return the bytes of a json notification.'''
        return self.encode_payload(self.notification_payload(method, params))

    def json_request_bytes(self, method, id_, params=None):
        '''Return the bytes of a JSON request.'''
        return self.encode_payload(self.request_payload(method, id_, params))

    def json_response_bytes(self, result, id_):
        '''Return the bytes of a JSON response.'''
        return self.encode_payload(self.response_payload(result, id_))

    def json_error_bytes(self, message, code, id_=None):
        '''Return the bytes of a JSON error.

        Flag the connection to close on a fatal error or too many errors.'''
        self.error_count += 1
        if (code in (JSONRPC.PARSE_ERROR, JSONRPC.INVALID_REQUEST)
                or self.error_count > 10):
            self.close_after_send = True
        return self.encode_payload(self.error_payload(message, code, id_))

    async def process_single_payload(self, payload):
        '''Handle a single JSON request, notification or response.

        If it is a request, return the binary response, oterhwise None.'''
        if not isinstance(payload, dict):
            return self.json_error_bytes('request must be a dict',
                                         JSONRPC.INVALID_REQUEST)

        # Requests and notifications must have a method.
        # Notifications are distinguished by having no 'id'.
        if 'method' in payload:
            if 'id' in payload:
                return await self.process_single_request(payload)
            else:
                await self.process_single_notification(payload)
        else:
            await self.process_single_response(payload)

        return None

    async def process_single_request(self, payload):
        '''Handle a single JSON request and return the binary response.'''
        try:
            result = await self.handle_payload(payload, self.request_handler)
            return self.json_response_bytes(result, payload['id'])
        except RPCError as e:
            return self.json_error_bytes(e.msg, e.code,
                                         self.payload_id(payload))
        except Exception:
            self.log_error(traceback.format_exc())
            return self.json_error_bytes('internal error processing request',
                                         JSONRPC.INTERNAL_ERROR,
                                         self.payload_id(payload))

    async def process_single_notification(self, payload):
        '''Handle a single JSON notification.'''
        try:
            await self.handle_payload(payload, self.notification_handler)
        except RPCError:
            pass
        except Exception:
            self.log_error(traceback.format_exc())

    async def process_single_response(self, payload):
        '''Handle a single JSON response.'''
        try:
            id_ = self.check_payload_id(payload)
            # Only one of result and error should exist
            if 'error' in payload:
                error = payload['error']
                if (not 'result' in payload and isinstance(error, dict)
                        and 'code' in error and 'message' in error):
                    await self.handle_response(None, error, id_)
            elif 'result' in payload:
                await self.handle_response(payload['result'], None, id_)
        except RPCError:
            pass
        except Exception:
            self.log_error(traceback.format_exc())

    async def handle_payload(self, payload, get_handler):
        '''Handle a request or notification payload given the handlers.'''
        # An argument is the value passed to a function parameter...
        args = payload.get('params', [])
        method = payload.get('method')

        if not isinstance(method, str):
            raise RPCError("invalid method: '{}'".format(method),
                           JSONRPC.INVALID_REQUEST)

        handler = get_handler(method)
        if not handler:
            raise RPCError("unknown method: '{}'".format(method),
                           JSONRPC.METHOD_NOT_FOUND)

        if not isinstance(args, (list, dict)):
            raise RPCError('arguments should be an array or a dict',
                           JSONRPC.INVALID_REQUEST)

        params = inspect.signature(handler).parameters
        names = list(params)
        min_args = sum(p.default is p.empty for p in params.values())

        if len(args) < min_args:
            raise RPCError('too few arguments: expected {:d} got {:d}'
                           .format(min_args, len(args)), JSONRPC.INVALID_ARGS)

        if len(args) > len(params):
            raise RPCError('too many arguments: expected {:d} got {:d}'
                           .format(len(params), len(args)),
                           JSONRPC.INVALID_ARGS)

        if isinstance(args, list):
            kw_args = {name: arg for name, arg in zip(names, args)}
        else:
            kw_args = args
            bad_names = ['<{}>'.format(name) for name in args
                         if name not in names]
            if bad_names:
                raise RPCError('invalid parameter names: {}'
                               .format(', '.join(bad_names)))

        return await handler(**kw_args)

    # --- derived classes are intended to override these functions
    def enqueue_request(self, request):
        '''Enqueue a request for later asynchronous processing.'''
        raise NotImplementedError

    async def handle_response(self, result, error, id_):
        '''Handle a JSON response.

        Should not raise an exception.  Return values are ignored.
        '''

    def notification_handler(self, method):
        '''Return the async handler for the given notification method.'''
        return None

    def request_handler(self, method):
        '''Return the async handler for the given request method.'''
        return None
