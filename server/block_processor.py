# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import asyncio

from server.daemon import DaemonError
from lib.util import LoggedClass


class Prefetcher(LoggedClass):
    '''Prefetches blocks (in the forward direction only).'''

    def __init__(self, daemon, height):
        super().__init__()
        self.daemon = daemon
        self.queue = asyncio.Queue()
        self.queue_semaphore = asyncio.Semaphore()
        self.queue_size = 0
        # Target cache size.  Has little effect on sync time.
        self.target_cache_size = 10 * 1024 * 1024
        self.fetched_height = height
        self.recent_sizes = [0]

    async def get_blocks(self):
        '''Returns a list of prefetched blocks.'''
        blocks, total_size = await self.queue.get()
        self.queue_size -= total_size
        return blocks

    async def start(self):
        '''Loops forever polling for more blocks.'''
        self.logger.info('prefetching blocks...')
        while True:
            while self.queue_size < self.target_cache_size:
                try:
                    await self._prefetch()
                except DaemonError as e:
                    self.logger.info('ignoring daemon errors: {}'.format(e))
            await asyncio.sleep(2)

    def _prefill_count(self, room):
        ave_size = sum(self.recent_sizes) // len(self.recent_sizes)
        count = room // ave_size if ave_size else 0
        return max(count, 10)

    async def _prefetch(self):
        '''Prefetch blocks if there are any to prefetch.'''
        daemon_height = await self.daemon.height()
        max_count = min(daemon_height - self.fetched_height, 4000)
        count = min(max_count, self._prefill_count(self.target_cache_size))
        first = self.fetched_height + 1
        hashes = await self.daemon.block_hex_hashes(first, count)
        if not hashes:
            return

        blocks = await self.daemon.raw_blocks(hashes)
        sizes = [len(block) for block in blocks]
        total_size = sum(sizes)
        self.queue.put_nowait((blocks, total_size))
        self.queue_size += total_size
        self.fetched_height += len(blocks)

        # Keep 50 most recent block sizes for fetch count estimation
        self.recent_sizes.extend(sizes)
        excess = len(self.recent_sizes) - 50
        if excess > 0:
            self.recent_sizes = self.recent_sizes[excess:]


class BlockProcessor(LoggedClass):
    '''Process blocks and update the DB state to match.

    Employ a prefetcher to prefetch blocks in batches for processing.
    Coordinate backing up in case of chain reorganisations.
    '''

    def __init__(self, db, daemon):
        super().__init__()
        self.db = db
        self.daemon = daemon
        self.prefetcher = Prefetcher(daemon, db.height)

    def coros(self):
        return [self.start(), self.prefetcher.start()]

    def flush_db(self):
        self.db.flush(self.daemon.cached_height(), True)

    async def start(self):
        '''Loop forever processing blocks in the appropriate direction.'''
        try:
            while True:
                blocks = await self.prefetcher.get_blocks()
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
