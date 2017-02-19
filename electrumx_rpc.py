#!/usr/bin/env python3
#
# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Script to send RPC commands to a running ElectrumX server.'''


import argparse
import asyncio
import json
from functools import partial
from os import environ

from lib.jsonrpc import JSONSession, JSONRPCv2
from server.controller import Controller


class RPCClient(JSONSession):

    def __init__(self):
        super().__init__(version=JSONRPCv2)
        self.max_send = 0
        self.max_buffer_size = 5*10**6

    async def wait_for_response(self):
        await self.items_event.wait()
        await self.process_pending_items()

    def send_rpc_request(self, method, params):
        handler = partial(self.handle_response, method)
        self.send_request(handler, method, params)

    def handle_response(self, method, result, error):
        if method in ('groups', 'peers', 'sessions') and not error:
            lines_func = getattr(Controller, '{}_text_lines'.format(method))
            for line in lines_func(result):
                print(line)
        elif error:
            print('error: {} (code {:d})'
                  .format(error['message'], error['code']))
        else:
            print(json.dumps(result, indent=4, sort_keys=True))


def rpc_send_and_wait(port, method, params, timeout=15):
    loop = asyncio.get_event_loop()
    coro = loop.create_connection(RPCClient, 'localhost', port)
    try:
        transport, rpc_client = loop.run_until_complete(coro)
        rpc_client.send_rpc_request(method, params)
        try:
            coro = rpc_client.wait_for_response()
            loop.run_until_complete(asyncio.wait_for(coro, timeout))
        except asyncio.TimeoutError:
            print('request timed out after {}s'.format(timeout))
    except OSError:
        print('cannot connect - is ElectrumX catching up, not running, or '
              'is {:d} the wrong RPC port?'.format(port))
    finally:
        loop.close()


def main():
    '''Send the RPC command to the server and print the result.'''
    parser = argparse.ArgumentParser('Send electrumx an RPC command')
    parser.add_argument('-p', '--port', metavar='port_num', type=int,
                        help='RPC port number')
    parser.add_argument('command', nargs=1, default=[],
                        help='command to send')
    parser.add_argument('param', nargs='*', default=[],
                        help='params to send')
    args = parser.parse_args()

    port = args.port
    if port is None:
        port = int(environ.get('RPC_PORT', 8000))

    # Get the RPC request.
    method = args.command[0]
    params = args.param
    if method in ('log', 'disconnect'):
        params = [params]

    rpc_send_and_wait(port, method, params)


if __name__ == '__main__':
    main()
