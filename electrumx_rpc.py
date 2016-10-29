#!/usr/bin/env python3

# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import argparse
import asyncio
import json
from functools import partial
from os import environ


class RPCClient(asyncio.Protocol):

    def __init__(self, loop):
        self.loop = loop

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        self.loop.stop()

    def send(self, payload):
        data = json.dumps(payload) + '\n'
        self.transport.write(data.encode())

    def data_received(self, data):
        payload = json.loads(data.decode())
        self.transport.close()
        print(json.dumps(payload, indent=4, sort_keys=True))


def main():
    '''Send the RPC command to the server and print the result.'''
    parser = argparse.ArgumentParser('Send electrumx an RPC command' )
    parser.add_argument('-p', '--port', metavar='port_num', type=int,
                        help='RPC port number')
    parser.add_argument('command', nargs='*', default=[],
                        help='command to send')
    args = parser.parse_args()

    if args.port is None:
        args.port = int(environ.get('ELECTRUMX_RPC_PORT', 8000))

    payload = {'method': args.command[0], 'params': args.command[1:]}

    loop = asyncio.get_event_loop()
    proto_factory = partial(RPCClient, loop)
    coro = loop.create_connection(proto_factory, 'localhost', args.port)
    try:
        transport, protocol = loop.run_until_complete(coro)
        protocol.send(payload)
        loop.run_forever()
    except OSError:
        print('error connecting - is ElectrumX running?')
    finally:
        loop.close()


if __name__ == '__main__':
    main()
