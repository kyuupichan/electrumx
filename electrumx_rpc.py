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
        payload = {'method': method, 'params': params, 'id': 'RPC'}
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
            def data_fmt(count, size):
                return '{:,d}/{:,d}KB'.format(count, size // 1024)
            def time_fmt(t):
                t = int(t)
                return ('{:3d}:{:02d}:{:02d}'
                        .format(t // 3600, (t % 3600) // 60, t % 60))

            if self.method == 'sessions':
                fmt = ('{:<4} {:>23} {:>15} {:>5} '
                       '{:>7} {:>7} {:>7} {:>7} {:>5} {:>9}')
                print(fmt.format('Type', 'Peer', 'Client', 'Subs',
                                 'Snt #', 'Snt MB', 'Rcv #', 'Rcv MB',
                                 'Errs', 'Time'))
                for (kind, peer, subs, client, recv_count, recv_size,
                     send_count, send_size, error_count, time) in result:
                    print(fmt.format(kind, peer, client, '{:,d}'.format(subs),
                                     '{:,d}'.format(recv_count),
                                     '{:,.1f}'.format(recv_size / 1048576),
                                     '{:,d}'.format(send_count),
                                     '{:,.1f}'.format(send_size / 1048576),
                                     '{:,d}'.format(error_count),
                                     time_fmt(time)))
            else:
                print(json.dumps(result, indent=4, sort_keys=True))

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
