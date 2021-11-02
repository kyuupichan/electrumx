# Copyright (c) 2021 Neil Booth
#
# All rights reserved.
#
# This file is licensed under the OpenBSV licence version 3; see LICENCE for details.

'''Shared memory functionality.'''

from multi_processing import shared_memory
from os import urandom

import curio
from curio import Channel


class Page:

    def __init__(self, page):
        self.page = page
        self.free_list =


    @classmethod
    def create(cls, name, size):
        return cls(shared_memory.SharedMemory(name=name, create=True, size=size))

    @classmethod
    def attach(cls, name):
        return cls(shared_memory.SharedMemory(name=name, create=False))

    def close(self):
        self.page.close()

    def unlink(self):
        self.page.unlink()

    async def reserve(self, size):


    async def write(self, item):
        size = len(item)
        loc = await self.reserve(size)
        offset = loc % self.page.size
        self.page.buf[loc: loc + size] = item
        return offset


async def start_worker(name, prodlistener):
    channel = Channel(('localhost', socket.INADDR_ANY))
    channel.bind()
    authkey = urandom(12)
    async with TaskGroup() as group:
        await group.spawn(listener, channel)
    return await run_in_process(worker_main, name, channel, authkey)


class Worker:

    def __init__(self, name, connection):
        self.name = name
        self.connection = connection

    @classmethod
    def main(cls, name, address, authkey):
        async def main():
            channel = Channel(address)
            connection = await channel.connect(authkey=authkey)
            worker = cls(name, connection)
            return await worker.run()

        return curio.run(main)

    async def run(self):
        return self.name


class BlockProcessor:

    def __init__(self):
        self.channel = Channel('localhost', socket.INADDR_ANY)
        self.channel.bind()
        self.authkey = urandom(12)

    async def spawn_worker(self, name, func):
        return await run_in_process(worker_main, name, self.channel.address, self.authkey)




    def __init__(self, name):
        self.name = name
