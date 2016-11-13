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


def json_result_payload(result, id_):
    # We should not respond to notifications
    assert id_ is not None
    return {'jsonrpc': '2.0', 'error': None, 'result': result, 'id': id_}

def json_error_payload(message, code, id_=None):
    error = {'message': message, 'code': code}
    return {'jsonrpc': '2.0', 'error': error, 'result': None, 'id': id_}

def json_notification_payload(method, params):
    return {'jsonrpc': '2.0', 'id': None, 'method': method, 'params': params}


class JSONRPC(asyncio.Protocol, LoggedClass):
    '''Manages a JSONRPC connection.

    Assumes JSON messages are newline-separated and that newlines
    cannot appear in the JSON other than to separate lines.

    Derived classes need to implement the synchronous functions
    on_json_request() and method_handler().  They probably also want
    to override connection_made() and connection_lost() but should be
    sure to call the implementation in this base class first.

    on_json_request() is passed a JSON request as a python object
    after decoding.  It should arrange to pass on to the asynchronous
    handle_json_request() method.

    method_handler() takes a method string and should return a function
    that can be passed a parameters array, or None for an unknown method.

    Handlers should raise an RPCError on error.
    '''

    # See http://www.jsonrpc.org/specification
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERAL_ERROR = -32603

    ID_TYPES = (type(None), str, numbers.Number)

    class RPCError(Exception):
        '''RPC handlers raise this error.'''
        def __init__(self, msg, code=-1, **kw_args):
            super().__init__(**kw_args)
            self.msg = msg
            self.code


    def __init__(self):
        super().__init__()
        self.start = time.time()
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

    def connection_made(self, transport):
        '''Handle an incoming client connection.'''
        self.transport = transport

    def peer_info(self):
        '''Return peer info.'''
        if self.transport:
            return self.transport.get_extra_info('peername')
        return None

    def connection_lost(self, exc):
        '''Handle client disconnection.'''
        pass

    def data_received(self, data):
        '''Handle incoming data (synchronously).

        Requests end in newline characters.  Pass complete requests to
        decode_message for handling.
        '''
        self.recv_size += len(data)
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
            self.logger.warning(msg)
            self.send_json_error(msg, self.PARSE_ERROR)
            return

        try:
            message = json.loads(message)
        except json.JSONDecodeError as e:
            msg = 'cannot decode JSON: {}'.format(e)
            self.logger.warning(msg)
            self.send_json_error(msg, self.PARSE_ERROR)
            return

        self.on_json_request(message)

    def send_json_notification(self, method, params):
        '''Create a json notification.'''
        return self.send_json(json_notification_payload(method, params))

    def send_json_result(self, result, id_):
        '''Send a JSON result.'''
        return self.send_json(json_result_payload(result, id_))

    def send_json_error(self, message, code, id_=None):
        '''Send a JSON error.'''
        self.error_count += 1
        return self.send_json(json_error_payload(message, code, id_))

    def send_json(self, payload):
        '''Send a JSON payload.'''
        if self.transport.is_closing():
            self.logger.info('send_json: connection closing, not sending')
            return False

        try:
            data = (json.dumps(payload) + '\n').encode()
        except TypeError:
            msg = 'JSON encoding failure: {}'.format(payload)
            self.logger.error(msg)
            return self.send_json_error(msg, self.INTERNAL_ERROR,
                                         payload.get('id'))

        self.send_count += 1
        self.send_size += len(data)
        self.transport.write(data)
        return True

    async def handle_json_request(self, request):
        '''Asynchronously handle a JSON request.

        Handles batch requests.  Returns True if the request response
        was sent (or if nothing was sent because the request was a
        notification).  Returns False if the send was aborted because
        the connection is closing.
        '''
        if isinstance(request, list):
            payload = self.batch_request_payload(request)
        else:
            payload = await self.single_request_payload(request)

        if not payload:
            return True
        return self.send_json(payload)

    async def batch_request_payload(self, batch):
        '''Return the JSON payload corresponding to a batch JSON request.'''
        # Batches must have at least one request.
        if not batch:
            return json_error_payload('empty request list',
                                      self.INVALID_REQUEST)

        # PYTHON 3.6: use asynchronous comprehensions when supported
        payload = []
        for item in request:
            item_payload = await self.single_request_payload(item)
            if item_payload:
                payload.append(item_payload)
        return payload

    async def single_request_payload(self, request):
        '''Return the JSON payload corresponding to a single JSON request.

        Return None if the request is a notification.
        '''
        if not isinstance(request, dict):
            return json_error_payload('request must be a dict',
                                      self.INVALID_REQUEST)

        id_ = request.get('id')
        if not isinstance(id_, self.ID_TYPES):
            return json_error_payload('invalid id: {}'.format(id_),
                                      self.INVALID_REQUEST)

        try:
            result = await self.method_result(request.get('method'),
                                              request.get('params', []))
            if id_ is None:
                return None
            return json_result_payload(result, id_)
        except self.RPCError as e:
            if id_ is None:
                return None
            return json_error_payload(e.msg, e.code, id_)

    async def method_result(self, method, params):
        if not isinstance(method, str):
            raise self.RPCError('invalid method: {}'.format(method),
                                self.INVALID_REQUEST)

        if not isinstance(params, list):
            raise self.RPCError('params should be an array',
                                self.INVALID_REQUEST)

        handler = self.method_handler(method)
        if not handler:
            raise self.RPCError('unknown method: {}'.format(method),
                                self.METHOD_NOT_FOUND)

        return await handler(params)

    def on_json_request(self, request):
        raise NotImplementedError('on_json_request in class {}'.
                                  format(self.__class__.__name__))

    def method_handler(self, method):
        raise NotImplementedError('method_handler in class {}'.
                                  format(self.__class__.__name__))
