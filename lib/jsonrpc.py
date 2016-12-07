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


def json_response_payload(result, id_):
    # We should not respond to notifications
    assert id_ is not None
    return {'jsonrpc': '2.0', 'result': result, 'id': id_}

def json_error_payload(message, code, id_=None):
    error = {'message': message, 'code': code}
    return {'jsonrpc': '2.0', 'error': error, 'id': id_}

def json_request_payload(method, id_, params=None):
    payload = {'jsonrpc': '2.0', 'id': id_, 'method': method}
    if params:
        payload['params'] = params
    return payload

def json_notification_payload(method, params=None):
    return json_request_payload(method, None, params)

def json_payload_id(payload):
    return payload.get('id') if isinstance(payload, dict) else None


class JSONRPC(asyncio.Protocol, LoggedClass):
    '''Manages a JSONRPC connection.

    Assumes JSON messages are newline-separated and that newlines
    cannot appear in the JSON other than to separate lines.  Incoming
    messages are queued on the messages queue for later asynchronous
    processing, and should be passed to the handle_message() function.

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

    class LargeRequestError(Exception):
        '''Raised if a large request was prevented from being sent.'''


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
            self.send_json_error(msg, self.INVALID_REQUEST)
            return

        try:
            message = json.loads(message)
        except json.JSONDecodeError as e:
            msg = 'cannot decode JSON: {}'.format(e)
            self.send_json_error(msg, self.INVALID_REQUEST)
            return

        '''Queue the request for asynchronous handling.'''
        self.messages.put_nowait(message)
        if self.log_me:
            self.log_info('queued {}'.format(message))

    def encode_payload(self, payload):
        try:
            text = (json.dumps(payload) + '\n').encode()
        except TypeError:
            msg = 'JSON encoding failure: {}'.format(payload)
            self.log_error(msg)
            return self.json_error(msg, self.INTERNAL_ERROR,
                                   json_payload_id(payload))

        self.check_oversized_request(len(text))
        if 'error' in payload:
            self.error_count += 1
        self.send_count += 1
        self.send_size += len(text)
        self.using_bandwidth(len(text))
        return text

    def send_text(self, text, close):
        '''Send JSON text over the transport.  Close it if close is True.'''
        # Confirmed this happens, sometimes a lot
        if self.transport.is_closing():
            return
        self.transport.write(text)
        if close:
            self.transport.close()

    def send_json_error(self, message, code, id_=None, close=True):
        '''Send a JSON error and close the connection by default.'''
        self.send_text(self.json_error_text(message, code, id_), close)

    def encode_and_send_payload(self, payload):
        '''Encode the payload and send it.'''
        self.send_text(self.encode_payload(payload), False)

    def json_notification_text(self, method, params):
        '''Return the text of a json notification.'''
        return self.encode_payload(json_notification_payload(method, params))

    def json_request_text(self, method, id_, params=None):
        '''Return the text of a JSON request.'''
        return self.encode_payload(json_request_payload(method, id_, params))

    def json_response_text(self, result, id_):
        '''Return the text of a JSON response.'''
        return self.encode_payload(json_response_payload(result, id_))

    def json_error_text(self, message, code, id_=None):
        '''Return the text of a JSON error.'''
        return self.encode_payload(json_error_payload(message, code, id_))

    async def handle_message(self, payload):
        '''Asynchronously handle a JSON request or response.

        Handles batches according to the JSON 2.0 spec.
        '''
        try:
            if isinstance(payload, list):
                text = await self.process_json_batch(payload)
            else:
                text = await self.process_single_json(payload)
        except self.RPCError as e:
            text = self.json_error_text(e.msg, e.code,
                                        json_payload_id(payload))

        if text:
            self.send_text(text, self.error_count > 10)

    async def process_json_batch(self, batch):
        '''Return the text response to a JSON batch request.'''
        # Batches must have at least one request.
        if not batch:
            return self.json_error_text('empty batch', self.INVALID_REQUEST)

        # PYTHON 3.6: use asynchronous comprehensions when supported
        parts = []
        total_len = 0
        for item in batch:
            part = await self.process_single_json(item)
            if part:
                parts.append(part)
                total_len += len(part) + 2
                self.check_oversized_request(total_len)
        if parts:
            return '{' + ', '.join(parts) + '}'
        return ''

    async def process_single_json(self, payload):
        '''Return the JSON result of a single JSON request, response or
        notification.

        Return None if the request is a notification or a response.
        '''
        # Throttle high-bandwidth connections by delaying processing
        # their requests.  Delay more the higher the excessive usage.
        excess = self.bandwidth_used - self.bandwidth_limit
        if excess > 0:
            secs = 1 + excess // self.bandwidth_limit
            self.log_warning('high bandwidth use of {:,d} bytes, '
                             'sleeping {:d}s'
                             .format(self.bandwidth_used, secs))
            await asyncio.sleep(secs)

        if not isinstance(payload, dict):
            return self.json_error_text('request must be a dict',
                                        self.INVALID_REQUEST)

        if not 'id' in payload:
            return await self.process_json_notification(payload)

        id_ = payload['id']
        if not isinstance(id_, self.ID_TYPES):
            return self.json_error_text('invalid id: {}'.format(id_),
                                        self.INVALID_REQUEST)

        if 'method' in payload:
            return await self.process_json_request(payload)

        return await self.process_json_response(payload)

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
        return ''

    async def process_json_request(self, payload):
        method, params = self.method_and_params(payload)
        result = await self.handle_request(method, params)
        return self.json_response_text(result, payload['id'])

    async def process_json_response(self, payload):
        # Only one of result and error should exist; we go with 'error'
        # if both are supplied.
        if 'error' in payload:
            await self.handle_response(None, payload['error'], payload['id'])
        elif 'result' in payload:
            await self.handle_response(payload['result'], None, payload['id'])
        return ''

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
    async def handle_notification(self, method, params):
        '''Handle a notification.'''

    async def handle_request(self, method, params):
        '''Handle a request.'''
        return None

    async def handle_response(self, result, error, id_):
        '''Handle a response.'''
