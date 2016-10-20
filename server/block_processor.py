# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import asyncio

from server.daemon import DaemonError
from lib.util import LoggedClass


class BlockProcessor(LoggedClass):
    '''Requests and caches blocks ahead of time from the daemon.  Serves
    them to the blockchain processor.  Coordinates backing up in case of
    block chain reorganisations.
    '''

    def __init__(self, db, daemon):
        super().__init__()
        self.db = db
        self.daemon = daemon
        # Target cache size.  Has little effect on sync time.
        self.target_cache_size = 10 * 1024 * 1024
        self.fetched_height = db.height
        self.queue = asyncio.Queue()
        self.queue_size = 0
        self.recent_sizes = [0]

    def flush_db(self):
        self.db.flush(self.daemon.cached_height(), True)

    async def process_blocks(self):
        try:
            while True:
                blocks, total_size = await self.queue.get()
                self.queue_size -= total_size
                for block in blocks:
                    self.db.process_block(block, self.daemon.cached_height())
                    # Release asynchronous block fetching
                    await asyncio.sleep(0)

                if self.db.height == self.daemon.cached_height():
                    self.logger.info('caught up to height {:d}'
                                     .format(self.db_height))
                    self.flush_db()
        finally:
            self.flush_db()

    async def prefetcher(self):
        '''Loops forever polling for more blocks.'''
        self.logger.info('prefetching blocks...')
        while True:
            try:
                await self.maybe_prefetch()
            except DaemonError as e:
                self.logger.info('ignoring daemon errors: {}'.format(e))
            await asyncio.sleep(2)

    def cache_used(self):
        return sum(len(block) for block in self.blocks)

    def prefill_count(self, room):
        ave_size = sum(self.recent_sizes) // len(self.recent_sizes)
        count = room // ave_size if ave_size else 0
        return max(count, 10)

    async def maybe_prefetch(self):
        '''Prefetch blocks if there are any to prefetch.'''
        while self.queue_size < self.target_cache_size:
            # Keep going by getting a whole new cache_limit of blocks
            daemon_height = await self.daemon.height()
            max_count = min(daemon_height - self.fetched_height, 4000)
            count = min(max_count, self.prefill_count(self.target_cache_size))
            if not count:
                break

            first = self.fetched_height + 1
            hashes = await self.daemon.block_hex_hashes(first, count)
            blocks = await self.daemon.raw_blocks(hashes)

            self.fetched_height += count
            sizes = [len(block) for block in blocks]
            total_size = sum(sizes)
            self.queue.put_nowait((blocks, total_size))
            self.queue_size += total_size

            # Keep 50 most recent block sizes for fetch count estimation
            self.recent_sizes.extend(sizes)
            excess = len(self.recent_sizes) - 50
            if excess > 0:
                self.recent_sizes = self.recent_sizes[excess:]
