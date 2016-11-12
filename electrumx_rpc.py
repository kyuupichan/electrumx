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
import pprint
from functools import partial
from os import environ


class RPCClient(asyncio.Protocol):

    def __init__(self, loop):
        self.loop = loop
        self.method = None

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, exc):
        self.loop.stop()

    def send(self, method, params):
        self.method = method
        payload = {'method': method, 'params': params}
        data = json.dumps(payload) + '\n'
        self.transport.write(data.encode())

    def data_received(self, data):
        payload = json.loads(data.decode())
        self.transport.close()
        result = payload['result']
        error = payload['error']
        if error:
            print("ERROR: {}".format(error))
        else:
            if self.method == 'sessions':
                fmt = '{:<4} {:>23} {:>7} {:>15} {:>7}'
                print(fmt.format('Type', 'Peer', 'Subs', 'Client', 'Time'))
                for kind, peer, subs, client, time in result:
                    print(fmt.format(kind, peer, '{:,d}'.format(subs),
                                     client, '{:,d}'.format(int(time))))
            else:
                pprint.pprint(result, indent=4)

def main():
    '''Send the RPC command to the server and print the result.'''
    parser = argparse.ArgumentParser('Send electrumx an RPC command' )
    parser.add_argument('-p', '--port', metavar='port_num', type=int,
                        help='RPC port number')
    parser.add_argument('command', nargs=1, default=[],
                        help='command to send')
    parser.add_argument('param', nargs='*', default=[],
                        help='params to send')
    args = parser.parse_args()

    if args.port is None:
        args.port = int(environ.get('ELECTRUMX_RPC_PORT', 8000))

    loop = asyncio.get_event_loop()
    proto_factory = partial(RPCClient, loop)
    coro = loop.create_connection(proto_factory, 'localhost', args.port)
    try:
        transport, protocol = loop.run_until_complete(coro)
        protocol.send(args.command[0], args.param)
        loop.run_forever()
    except OSError:
        print('error connecting - is ElectrumX catching up or not running?')
    finally:
        loop.close()


if __name__ == '__main__':
    main()
