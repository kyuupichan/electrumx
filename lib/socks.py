# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# and warranty status of this software.

'''Socks proxying.'''

import asyncio
import ipaddress
import logging
import socket
import struct
from functools import partial

import lib.util as util


class Socks(util.LoggedClass):
    '''Socks protocol wrapper.'''

    SOCKS5_ERRORS = {
        1: 'general SOCKS server failure',
        2: 'connection not allowed by ruleset',
        3: 'network unreachable',
        4: 'host unreachable',
        5: 'connection refused',
        6: 'TTL expired',
        7: 'command not supported',
        8: 'address type not supported',
    }

    class Error(Exception):
        pass

    def __init__(self, loop, sock, host, port):
        super().__init__()
        self.loop = loop
        self.sock = sock
        self.host = host
        self.port = port
        try:
            self.ip_address = ipaddress.ip_address(host)
        except ValueError:
            self.ip_address = None
        self.debug = False

    async def _socks4_handshake(self):
        if self.ip_address:
            # Socks 4
            ip_addr = self.ip_address
            host_bytes = b''
        else:
            # Socks 4a
            ip_addr = ipaddress.ip_address('0.0.0.1')
            host_bytes = self.host.encode() + b'\0'

        user_id = ''
        data = b'\4\1' + struct.pack('>H', self.port) + ip_addr.packed
        data += user_id.encode() + b'\0' + host_bytes
        await self.loop.sock_sendall(self.sock, data)
        data = await self.loop.sock_recv(self.sock, 8)
        if data[0] != 0:
            raise self.Error('proxy sent bad initial Socks4 byte')
        if data[1] != 0x5a:
            raise self.Error('proxy request failed or rejected')

    async def _socks5_handshake(self):
        await self.loop.sock_sendall(self.sock, b'\5\1\0')
        data = await self.loop.sock_recv(self.sock, 2)
        if data[0] != 5:
            raise self.Error('proxy sent bad SOCKS5 initial byte')
        if data[1] != 0:
            raise self.Error('proxy rejected SOCKS5 authentication method')

        if self.ip_address:
            if self.ip_address.version == 4:
                addr = b'\1' + self.ip_address.packed
            else:
                addr = b'\4' + self.ip_address.packed
        else:
            host = self.host.encode()
            addr = b'\3' + bytes([len(host)]) + host

        data = b'\5\1\0' + addr + struct.pack('>H', self.port)
        await self.loop.sock_sendall(self.sock, data)
        data = await self.loop.sock_recv(self.sock, 5)
        if data[0] != 5:
            raise self.Error('proxy sent bad SOSCK5 response initial byte')
        if data[1] != 0:
            msg = self.SOCKS5_ERRORS.get(data[1], 'unknown SOCKS5 error {:d}'
                                         .format(data[1]))
            raise self.Error(msg)
        if data[3] == 1:
            addr_len, data = 3, data[4:]
        elif data[3] == 3:
            addr_len, data = data[4], b''
        elif data[3] == 4:
            addr_len, data = 15, data[4:]
        data = await self.loop.sock_recv(self.sock, addr_len + 2)
        addr = data[:addr_len]
        port, = struct.unpack('>H', data[-2:])

    async def handshake(self):
        '''Write the proxy handshake sequence.'''
        if self.ip_address and self.ip_address.version == 6:
            await self._socks5_handshake()
        else:
            await self._socks4_handshake()

        if self.debug:
            address = (self.host, self.port)
            self.log_info('successful connection via proxy to {}'
                          .format(util.address_string(address)))


class SocksProxy(util.LoggedClass):

    def __init__(self, host, port, loop=None):
        '''Host can be an IPv4 address, IPv6 address, or a host name.'''
        super().__init__()
        self.host = host
        self.port = port
        self.ip_addr = None
        self.loop = loop or asyncio.get_event_loop()

    async def create_connection(self, protocol_factory, host, port, ssl=None):
        '''All arguments are as to asyncio's create_connection method.'''
        if self.port is None:
            proxy_ports = [9050, 9150, 1080]
        else:
            proxy_ports = [self.port]

        for proxy_port in proxy_ports:
            address = (self.host, proxy_port)
            sock = socket.socket()
            sock.setblocking(False)
            try:
                await self.loop.sock_connect(sock, address)
            except OSError as e:
                if proxy_port == proxy_ports[-1]:
                    raise
                continue

            socks = Socks(self.loop, sock, host, port)
            try:
                await socks.handshake()
                if self.port is None:
                    self.ip_addr = sock.getpeername()[0]
                    self.port = proxy_port
                    self.logger.info('detected proxy at {} ({})'
                                     .format(util.address_string(address),
                                             self.ip_addr))
                break
            except Exception as e:
                sock.close()
                raise

        hostname = host if ssl else None
        return await self.loop.create_connection(
            protocol_factory, ssl=ssl, sock=sock, server_hostname=hostname)
