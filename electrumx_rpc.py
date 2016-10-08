#!/usr/bin/env python3

# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import argparse
import asyncio
import json
from os import environ

import aiohttp


async def send(url, payload):
    data = json.dumps(payload)

    async with aiohttp.post(url, data = data) as resp:
        return await resp.json()


def main():
    '''Send the RPC command to the server and print the result.'''
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', metavar='port_num', type=int,
                        help='specify the RPC port number')
    parser.add_argument('command', nargs='*', default=[],
                        help='send a command to the server')
    args = parser.parse_args()

    if args.port is None:
        args.port = int(environ.get('ELECTRUMX_RPC_PORT', 8000))

    url = 'http://127.0.0.1:{:d}/'.format(args.port)
    payload = {'method': args.command[0], 'params': args.command[1:]}
    task = send(url, payload)

    loop = asyncio.get_event_loop()
    try:
        result = loop.run_until_complete(task)
    finally:
        loop.close()

    print(result)


if __name__ == '__main__':
    main()
