#!/usr/bin/env python3
#
# Copyright (c) 2016-2018, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Script to send RPC commands to a running ElectrumX server.'''


import argparse
import asyncio
import json
from os import environ

from aiorpcx import ClientSession

from server.controller import Controller


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

    async def send_request():
        # aiorpcX makes this so easy...
        async with ClientSession('localhost', port) as session:
            result = await session.send_request(method, params, timeout=15)
            if method in ('groups', 'peers', 'sessions'):
                lines_func = getattr(Controller, f'{method}_text_lines')
                for line in lines_func(result):
                    print(line)
            else:
                print(json.dumps(result, indent=4, sort_keys=True))

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(send_request())
    except OSError:
        print('cannot connect - is ElectrumX catching up, not running, or '
              f'is {port} the wrong RPC port?')
    except Exception as e:
        print(f'error making request: {e}')


if __name__ == '__main__':
    main()
