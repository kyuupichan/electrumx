# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Class for handling JSON RPC 2.0 connections, server or client.'''

import asyncio
import json
import numbers
import time

from lib.util import LoggedClass


class SingleRequest(object):
    '''An object that represents a single request.'''
    def __init__(self, session, payload):
        self.payload = payload
        self.session = session

    async def process(self):
        '''Asynchronously handle the JSON request.'''
        binary = await self.session.process_single_payload(self.payload)
        if binary:
            self.session._send_bytes(binary)


class BatchRequest(object):
    '''An object that represents a batch request and its processing state.

    Batches are processed in parts chunks.
    '''

    CUHNK_SIZE = 3

    def __init__(self, session, payload):
        self.session = session
        self.payload = payload
        self.done = 0
        self.parts = []

    async def process(self):
        '''Asynchronously handle the JSON batch according to the JSON 2.0
        spec.'''
        for n in range(self.CHUNK_SIZE):
            if self.done >= len(self.payload):
                if self.parts:
                    binary = b'[' + b', '.join(self.parts) + b']'
                    self.session._send_bytes(binary)
                return
            item = self.payload[self.done]
            part = await self.session.process_single_payload(item)
            if part:
                self.parts.append(part)
            self.done += 1

        # Re-enqueue to continue the rest later
        self.session.enqueue_request(self)
        return b''


class JSONRPC(asyncio.Protocol, LoggedClass):
    '''Manages a JSONRPC connection.

    Assumes JSON messages are newline-separated and that newlines
    cannot appear in the JSON other than to separate lines.  Incoming
    messages are queued on the messages queue for later asynchronous
    processing, and should be passed to the handle_request() function.

    Derived classes may want to override connection_made() and
    connection_lost() but should be sure to call the implementation in
    this base class first.  They will also want to implement some or
    all of the asynchronous functions handle_notification(),
    handle_response() and handle_request().

    handle_request() returns the result to pass over the network, and
    must raise an RPCError if there is an error.
    handle_notification() and handle_response() should not return
    anything or raise any exceptions.  All three functions have
    default "ignore" implementations supplied by this class.
    '''

    # See http://www.jsonrpc.org/specification
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    ID_TYPES = (type(None), str, numbers.Number)
    NEXT_SESSION_ID = 0

    class RPCError(Exception):
        '''RPC handlers raise this error.'''
        def __init__(self, msg, code=-1, **kw_args):
            super().__init__(**kw_args)
            self.msg = msg
            self.code = code

    @classmethod
    def request_payload(cls, method, id_, params=None):
        payload = {'jsonrpc': '2.0', 'id': id_, 'method': method}
        if params:
            payload['params'] = params
        return payload

    @classmethod
    def response_payload(cls, result, id_):
        # We should not respond to notifications
        assert id_ is not None
        return {'jsonrpc': '2.0', 'result': result, 'id': id_}

    @classmethod
    def notification_payload(cls, method, params=None):
        return cls.request_payload(method, None, params)

    @classmethod
    def error_payload(cls, message, code, id_=None):
        error = {'message': message, 'code': code}
        return {'jsonrpc': '2.0', 'error': error, 'id': id_}

    @classmethod
    def payload_id(cls, payload):
        return payload.get('id') if isinstance(payload, dict) else None

    def __init__(self):
        super().__init__()
        self.start = time.time()
        self.last_recv = self.start
        self.bandwidth_start = self.start
        self.bandwidth_interval = 3600
        self.bandwidth_used = 0
        self.bandwidth_limit = 5000000
        self.transport = None
        # Parts of an incomplete JSON line.  We buffer them until
        # getting a newline.
        self.parts = []
        # recv_count is JSON messages not calls to data_received()
        self.recv_count = 0
        self.recv_size = 0
        self.send_count = 0
        self.send_size = 0
        self.error_count = 0
        self.peer_info = None
        self.messages = asyncio.Queue()
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
        return '{}:{}'.format(self.peer_info[0], self.peer_info[1])

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        self.transport = transport
        self.peer_info = transport.get_extra_info('peername')

    def connection_lost(self, exc):
        '''Handle client disconnection.'''
        pass

    def using_bandwidth(self, amount):
        now = time.time()
        # Reduce the recorded usage in proportion to the elapsed time
        elapsed = now - self.bandwidth_start
        self.bandwidth_start = now
        refund = int(elapsed / self.bandwidth_interval * self.bandwidth_limit)
        refund = min(refund, self.bandwidth_used)
        self.bandwidth_used += amount - refund

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
            self.transport.close()

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
            self.send_json_error(msg, self.PARSE_ERROR, close=True)
            return

        try:
            message = json.loads(message)
        except json.JSONDecodeError as e:
            msg = 'cannot decode JSON: {}'.format(e)
            self.send_json_error(msg, self.PARSE_ERROR, close=True)
            return

        if isinstance(message, list):
            # Batches must have at least one request.
            if not message:
                self.send_json_error('empty batch', self.INVALID_REQUEST)
                return
            request = BatchRequest(self, message)
        else:
            request = SingleRequest(self, message)

        '''Queue the request for asynchronous handling.'''
        self.enqueue_request(request)
        if self.log_me:
            self.log_info('queued {}'.format(message))

    def encode_payload(self, payload):
        try:
            binary = json.dumps(payload).encode()
        except TypeError:
            msg = 'JSON encoding failure: {}'.format(payload)
            self.log_error(msg)
            return self.json_error(msg, self.INTERNAL_ERROR,
                                   self.payload_id(payload))

        self.check_oversized_request(len(binary))
        self.send_count += 1
        self.send_size += len(binary)
        self.using_bandwidth(len(binary))
        return binary

    def _send_bytes(self, binary, close=False):
        '''Send JSON text over the transport.  Close it if close is True.'''
        # Confirmed this happens, sometimes a lot
        if self.transport.is_closing():
            return
        self.transport.write(binary)
        self.transport.write(b'\n')
        if close or self.error_count > 10:
            self.transport.close()

    def send_json_error(self, message, code, id_=None, close=False):
        '''Send a JSON error and close the connection by default.'''
        self._send_bytes(self.json_error_bytes(message, code, id_), close)

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
        '''Return the bytes of a JSON error.'''
        self.error_count += 1
        return self.encode_payload(self.error_payload(message, code, id_))

    async def process_single_payload(self, payload):
        '''Return the binary JSON result of a single JSON request, response or
        notification.

        The result is empty if nothing is to be sent.
        '''

        if not isinstance(payload, dict):
            return self.json_error_bytes('request must be a dict',
                                         self.INVALID_REQUEST)

        try:
            if not 'id' in payload:
                return await self.process_json_notification(payload)

            id_ = payload['id']
            if not isinstance(id_, self.ID_TYPES):
                return self.json_error_bytes('invalid id: {}'.format(id_),
                                             self.INVALID_REQUEST)

            if 'method' in payload:
                return await self.process_json_request(payload)

            return await self.process_json_response(payload)
        except self.RPCError as e:
            return self.json_error_bytes(e.msg, e.code,
                                         self.payload_id(payload))

    @classmethod
    def method_and_params(cls, payload):
        method = payload.get('method')
        params = payload.get('params', [])

        if not isinstance(method, str):
            raise cls.RPCError('invalid method: {}'.format(method),
                               cls.INVALID_REQUEST)

        if not isinstance(params, list):
            raise cls.RPCError('params should be an array',
                               cls.INVALID_REQUEST)

        return method, params

    async def process_json_notification(self, payload):
        try:
            method, params = self.method_and_params(payload)
        except self.RPCError:
            pass
        else:
            await self.handle_notification(method, params)
        return b''

    async def process_json_request(self, payload):
        method, params = self.method_and_params(payload)
        result = await self.handle_request(method, params)
        return self.json_response_bytes(result, payload['id'])

    async def process_json_response(self, payload):
        # Only one of result and error should exist; we go with 'error'
        # if both are supplied.
        if 'error' in payload:
            await self.handle_response(None, payload['error'], payload['id'])
        elif 'result' in payload:
            await self.handle_response(payload['result'], None, payload['id'])
        return b''

    def check_oversized_request(self, total_len):
        if total_len > max(1000, self.max_send):
            raise self.RPCError('request too large', self.INVALID_REQUEST)

    def raise_unknown_method(self, method):
        '''Respond to a request with an unknown method.'''
        raise self.RPCError("unknown method: '{}'".format(method),
                            self.METHOD_NOT_FOUND)

    # Common parameter verification routines
    @classmethod
    def param_to_non_negative_integer(cls, param):
        '''Return param if it is or can be converted to a non-negative
        integer, otherwise raise an RPCError.'''
        try:
            param = int(param)
            if param >= 0:
                return param
        except ValueError:
            pass

        raise cls.RPCError('param {} should be a non-negative integer'
                           .format(param))

    @classmethod
    def params_to_non_negative_integer(cls, params):
        if len(params) == 1:
            return cls.param_to_non_negative_integer(params[0])
        raise cls.RPCError('params {} should contain one non-negative integer'
                            .format(params))

    @classmethod
    def require_empty_params(cls, params):
        if params:
            raise cls.RPCError('params {} should be empty'.format(params))


    # --- derived classes are intended to override these functions
    def enqueue_request(self, request):
        '''Enqueue a request for later asynchronous processing.'''
        self.messages.put_nowait(request)

    async def handle_notification(self, method, params):
        '''Handle a notification.'''

    async def handle_request(self, method, params):
        '''Handle a request.'''
        return None

    async def handle_response(self, result, error, id_):
        '''Handle a response.'''
