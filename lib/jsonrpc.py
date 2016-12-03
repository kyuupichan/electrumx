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
        if now >= self.bandwidth_start + self.bandwidth_interval:
            self.bandwidth_start = now
            self.bandwidth_used = 0
        self.bandwidth_used += amount

    def data_received(self, data):
        '''Handle incoming data (synchronously).

        Requests end in newline characters.  Pass complete requests to
        decode_message for handling.
        '''
        self.recv_size += len(data)
        self.using_bandwidth(len(data))

        # Close abuvsive connections where buffered data exceeds limit
        buffer_size = len(data) + sum(len(part) for part in self.parts)
        if buffer_size > self.max_buffer_size:
            self.logger.error('read buffer of {:,d} bytes exceeds {:,d} '
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
            self.send_json_error(msg, self.PARSE_ERROR)
            self.transport.close()
            return

        try:
            message = json.loads(message)
        except json.JSONDecodeError as e:
            msg = 'cannot decode JSON: {}'.format(e)
            self.send_json_error(msg, self.PARSE_ERROR)
            self.transport.close()
            return

        '''Queue the request for asynchronous handling.'''
        self.messages.put_nowait(message)

    def send_json_notification(self, method, params):
        '''Create a json notification.'''
        self.send_json(json_notification_payload(method, params))

    def send_json_request(self, method, id_, params=None):
        '''Send a JSON request.'''
        self.send_json(json_request_payload(method, id_, params))

    def send_json_response(self, result, id_):
        '''Send a JSON result.'''
        self.send_json(json_response_payload(result, id_))

    def send_json_error(self, message, code, id_=None):
        '''Send a JSON error.'''
        self.send_json(json_error_payload(message, code, id_))
        self.error_count += 1
        # Close abusive clients
        if self.error_count >= 10:
            self.transport.close()

    def send_json(self, payload):
        '''Send a JSON payload.'''
        # Confirmed this happens, sometimes a lot
        if self.transport.is_closing():
            return

        id_ = payload.get('id') if isinstance(payload, dict) else None
        try:
            data = (json.dumps(payload) + '\n').encode()
        except TypeError:
            msg = 'JSON encoding failure: {}'.format(payload)
            self.logger.error(msg)
            self.send_json_error(msg, self.INTERNAL_ERROR, id_)
        else:
            if len(data) > max(1000, self.max_send):
                self.send_json_error('request too large',
                                     self.INVALID_REQUEST, id_)
                raise self.LargeRequestError
            else:
                self.send_count += 1
                self.send_size += len(data)
                self.using_bandwidth(len(data))
                self.transport.write(data)

    async def handle_message(self, message):
        '''Asynchronously handle a JSON request or response.

        Handles batches according to the JSON 2.0 spec.
        '''
        # Throttle high-bandwidth connections by delaying processing
        # their requests.  Delay more the higher the excessive usage.
        excess = self.bandwidth_used - self.bandwidth_limit
        if excess > 0:
            secs = 1 + excess // self.bandwidth_limit
            self.logger.warning('{} has high bandwidth use of {:,d} bytes, '
                                'sleeping {:d}s'
                                .format(self.peername(), self.bandwidth_used,
                                        secs))
            await asyncio.sleep(secs)

        if isinstance(message, list):
            payload = await self.batch_payload(message)
        else:
            payload = await self.single_payload(message)

        if payload:
            try:
                self.send_json(payload)
            except self.LargeRequestError:
                self.logger.warning('blocked large request from {}: {}'
                                    .format(self.peername(), message))

    async def batch_payload(self, batch):
        '''Return the JSON payload corresponding to a batch JSON request.'''
        # Batches must have at least one request.
        if not batch:
            return json_error_payload('empty request list',
                                      self.INVALID_REQUEST)

        # PYTHON 3.6: use asynchronous comprehensions when supported
        payload = []
        for message in batch:
            message_payload = await self.single_payload(message)
            if message_payload:
                payload.append(message_payload)
        return payload

    async def single_payload(self, message):
        '''Return the JSON payload corresponding to a single JSON request,
        response or notification.

        Return None if the request is a notification or a response.
        '''
        if not isinstance(message, dict):
            return json_error_payload('request must be a dict',
                                      self.INVALID_REQUEST)

        if not 'id' in message:
            return await self.json_notification(message)

        id_ = message['id']
        if not isinstance(id_, self.ID_TYPES):
            return json_error_payload('invalid id: {}'.format(id_),
                                      self.INVALID_REQUEST)

        if 'method' in message:
            return await self.json_request(message)

        return await self.json_response(message)

    def method_and_params(self, message):
        method = message.get('method')
        params = message.get('params', [])

        if not isinstance(method, str):
            raise self.RPCError('invalid method: {}'.format(method),
                                self.INVALID_REQUEST)

        if not isinstance(params, list):
            raise self.RPCError('params should be an array',
                                self.INVALID_REQUEST)

        return method, params

    async def json_notification(self, message):
        try:
            method, params = self.method_and_params(message)
        except self.RPCError:
            pass
        else:
            await self.handle_notification(method, params)
        return None

    async def json_request(self, message):
        try:
            method, params = self.method_and_params(message)
            result = await self.handle_request(method, params)
            return json_response_payload(result, message['id'])
        except self.RPCError as e:
            return json_error_payload(e.msg, e.code, message['id'])

    async def json_response(self, message):
        # Only one of result and error should exist; we go with 'error'
        # if both are supplied.
        if 'error' in message:
            await self.handle_response(None, message['error'], message['id'])
        elif 'result' in message:
            await self.handle_response(message['result'], None, message['id'])
        return None

    def raise_unknown_method(self, method):
        '''Respond to a request with an unknown method.'''
        raise self.RPCError("unknown method: '{}'".format(method),
                            self.METHOD_NOT_FOUND)

    # --- derived classes are intended to override these functions
    async def handle_notification(self, method, params):
        '''Handle a notification.'''

    async def handle_request(self, method, params):
        '''Handle a request.'''
        return None

    async def handle_response(self, result, error, id_):
        '''Handle a response.'''
