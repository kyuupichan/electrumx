# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Block prefetcher and chain processor.'''


import array
import asyncio
import itertools
import os
from struct import pack, unpack
import time
from bisect import bisect_left
from collections import defaultdict
from functools import partial

from server.daemon import Daemon, DaemonError
from lib.hash import hash_to_str
from lib.tx import Deserializer
from lib.util import chunks, LoggedClass
import server.db
from server.storage import open_db

# Limits single address history to ~ 65536 * HIST_ENTRIES_PER_KEY entries
HIST_ENTRIES_PER_KEY = 1024
HIST_VALUE_BYTES = HIST_ENTRIES_PER_KEY * 4


def formatted_time(t):
    '''Return a number of seconds as a string in days, hours, mins and
    secs.'''
    t = int(t)
    return '{:d}d {:02d}h {:02d}m {:02d}s'.format(
        t // 86400, (t % 86400) // 3600, (t % 3600) // 60, t % 60)


class ChainError(Exception):
    pass


class Prefetcher(LoggedClass):
    '''Prefetches blocks (in the forward direction only).'''

    def __init__(self, daemon, height):
        super().__init__()
        self.daemon = daemon
        self.semaphore = asyncio.Semaphore()
        self.queue = asyncio.Queue()
        self.queue_size = 0
        self.fetched_height = height
        self.mempool_hashes = []
        # Target cache size.  Has little effect on sync time.
        self.target_cache_size = 10 * 1024 * 1024
        # First fetch to be 10 blocks
        self.ave_size = self.target_cache_size // 10

    async def clear(self, height):
        '''Clear prefetched blocks and restart from the given height.

        Used in blockchain reorganisations.  This coroutine can be
        called asynchronously to the _prefetch coroutine so we must
        synchronize.
        '''
        with await self.semaphore:
            while not self.queue.empty():
                self.queue.get_nowait()
            self.queue_size = 0
            self.fetched_height = height

    async def get_blocks(self):
        '''Returns a list of prefetched blocks and the mempool.'''
        blocks, height, size = await self.queue.get()
        self.queue_size -= size
        if height == self.daemon.cached_height():
            return blocks, self.mempool_hashes
        else:
            return blocks, None

    async def main_loop(self):
        '''Loop forever polling for more blocks.'''
        self.logger.info('starting daemon poll loop')
        while True:
            try:
                if await self._caught_up():
                    await asyncio.sleep(5)
                else:
                    await asyncio.sleep(0)
            except DaemonError as e:
                self.logger.info('ignoring daemon error: {}'.format(e))
            except asyncio.CancelledError:
                break

    async def _caught_up(self):
        '''Poll for new blocks and mempool state.

        Mempool is only queried if caught up with daemon.'''
        with await self.semaphore:
            blocks, size = await self._prefetch()
            self.fetched_height += len(blocks)
            caught_up = self.fetched_height == self.daemon.cached_height()
            if caught_up:
                self.mempool_hashes = await self.daemon.mempool_hashes()

            # Wake up block processor if we have something
            if blocks or caught_up:
                self.queue.put_nowait((blocks, self.fetched_height, size))
                self.queue_size += size

            return caught_up

    async def _prefetch(self):
        '''Prefetch blocks unless the prefetch queue is full.'''
        if self.queue_size >= self.target_cache_size:
            return [], 0

        daemon_height = await self.daemon.height()
        cache_room = self.target_cache_size // self.ave_size

        # Try and catch up all blocks but limit to room in cache.
        # Constrain count to between 0 and 4000 regardless
        count = min(daemon_height - self.fetched_height, cache_room)
        count = min(4000, max(count, 0))
        if not count:
            return [], 0

        first = self.fetched_height + 1
        hex_hashes = await self.daemon.block_hex_hashes(first, count)
        blocks = await self.daemon.raw_blocks(hex_hashes)

        size = sum(len(block) for block in blocks)

        # Update our recent average block size estimate
        if count >= 10:
            self.ave_size = size // count
        else:
            self.ave_size = (size + (10 - count) * self.ave_size) // 10

        return blocks, size


class ChainReorg(Exception):
    '''Raised on a blockchain reorganisation.'''


class MemPool(LoggedClass):
    '''Representation of the daemon's mempool.

    Updated regularly in caught-up state.  Goal is to enable efficient
    response to the value() and transactions() calls.

    To that end we maintain the following maps:

       tx_hash -> [txin_pairs, txout_pairs, unconfirmed]
       hash168 -> set of all tx hashes in which the hash168 appears

    A pair is a (hash168, value) tuple.  Unconfirmed is true if any of the
    tx's txins are unconfirmed.  tx hashes are hex strings.
    '''

    def __init__(self, bp):
        super().__init__()
        self.txs = {}
        self.hash168s = defaultdict(set)  # None can be a key
        self.bp = bp
        self.count = -1

    async def update(self, hex_hashes):
        '''Update state given the current mempool to the passed set of hashes.

        Remove transactions that are no longer in our mempool.
        Request new transactions we don't have then add to our mempool.
        '''
        hex_hashes = set(hex_hashes)
        touched = set()
        missing_utxos = []

        initial = self.count < 0
        if initial:
            self.logger.info('beginning import of {:,d} mempool txs'
                             .format(len(hex_hashes)))

        # Remove gone items
        gone = set(self.txs).difference(hex_hashes)
        for hex_hash in gone:
            txin_pairs, txout_pairs, unconfirmed = self.txs.pop(hex_hash)
            hash168s = set(hash168 for hash168, value in txin_pairs)
            hash168s.update(hash168 for hash168, value in txout_pairs)
            for hash168 in hash168s:
                self.hash168s[hash168].remove(hex_hash)
                if not self.hash168s[hash168]:
                    del self.hash168s[hash168]
            touched.update(hash168s)

        # Get the raw transactions for the new hashes.  Ignore the
        # ones the daemon no longer has (it will return None).  Put
        # them into a dictionary of hex hash to deserialized tx.
        hex_hashes.difference_update(self.txs)
        raw_txs = await self.bp.daemon.getrawtransactions(hex_hashes)
        if initial:
            self.logger.info('analysing {:,d} mempool txs'
                             .format(len(raw_txs)))
        new_txs = {hex_hash: Deserializer(raw_tx).read_tx()
                   for hex_hash, raw_tx in zip(hex_hashes, raw_txs) if raw_tx}
        del raw_txs, hex_hashes

        # The mempool is unordered, so process all outputs first so
        # that looking for inputs has full info.
        script_hash168 = self.bp.coin.hash168_from_script()
        db_utxo_lookup = self.bp.db_utxo_lookup

        def txout_pair(txout):
            return (script_hash168(txout.pk_script), txout.value)

        for n, (hex_hash, tx) in enumerate(new_txs.items()):
            # Yield to process e.g. signals
            if n % 100 == 0:
                await asyncio.sleep(0)
            txout_pairs = [txout_pair(txout) for txout in tx.outputs]
            self.txs[hex_hash] = (None, txout_pairs, None)

        def txin_info(txin):
            hex_hash = hash_to_str(txin.prev_hash)
            mempool_entry = self.txs.get(hex_hash)
            if mempool_entry:
                return mempool_entry[1][txin.prev_idx], True
            pair = db_utxo_lookup(txin.prev_hash, txin.prev_idx)
            return pair, False

        if initial:
            next_log = time.time()
            self.logger.info('processed outputs, now examining inputs. '
                             'This can take some time...')

        # Now add the inputs
        for n, (hex_hash, tx) in enumerate(new_txs.items()):
            # Yield to process e.g. signals
            if n % 10 == 0:
                await asyncio.sleep(0)

            if initial and time.time() > next_log:
                next_log = time.time() + 20
                self.logger.info('{:,d} done ({:d}%)'
                                 .format(n, int(n / len(new_txs) * 100)))

            txout_pairs = self.txs[hex_hash][1]
            try:
                infos = (txin_info(txin) for txin in tx.inputs)
                txin_pairs, unconfs = zip(*infos)
            except self.bp.MissingUTXOError:
                # Drop this TX.  If other mempool txs depend on it
                # it's harmless - next time the mempool is refreshed
                # they'll either be cleaned up or the UTXOs will no
                # longer be missing.
                del self.txs[hex_hash]
                continue
            self.txs[hex_hash] = (txin_pairs, txout_pairs, any(unconfs))

            # Update touched and self.hash168s for the new tx
            for hash168, value in txin_pairs:
                self.hash168s[hash168].add(hex_hash)
                touched.add(hash168)
            for hash168, value in txout_pairs:
                self.hash168s[hash168].add(hex_hash)
                touched.add(hash168)

        if missing_utxos:
            self.logger.info('{:,d} txs had missing UTXOs; probably the '
                             'daemon is a block or two ahead of us.'
                             .format(len(missing_utxos)))
            first = ', '.join('{} / {:,d}'.format(hash_to_str(txin.prev_hash),
                                                  txin.prev_idx)
                              for txin in sorted(missing_utxos)[:3])
            self.logger.info('first ones are {}'.format(first))

        self.count += 1
        if self.count % 25 == 0 or gone:
            self.count = 0
            self.logger.info('{:,d} txs touching {:,d} addresses'
                             .format(len(self.txs), len(self.hash168s)))

        # Might include a None
        return touched

    def transactions(self, hash168):
        '''Generate (hex_hash, tx_fee, unconfirmed) tuples for mempool
        entries for the hash168.

        unconfirmed is True if any txin is unconfirmed.
        '''
        for hex_hash in self.hash168s[hash168]:
            txin_pairs, txout_pairs, unconfirmed = self.txs[hex_hash]
            tx_fee = (sum(v for hash168, v in txin_pairs)
                      - sum(v for hash168, v in txout_pairs))
            yield (hex_hash, tx_fee, unconfirmed)

    def value(self, hash168):
        '''Return the unconfirmed amount in the mempool for hash168.

        Can be positive or negative.
        '''
        value = 0
        for hex_hash in self.hash168s[hash168]:
            txin_pairs, txout_pairs, unconfirmed = self.txs[hex_hash]
            value -= sum(v for h168, v in txin_pairs if h168 == hash168)
            value += sum(v for h168, v in txout_pairs if h168 == hash168)
        return value


class BlockProcessor(server.db.DB):
    '''Process blocks and update the DB state to match.

    Employ a prefetcher to prefetch blocks in batches for processing.
    Coordinate backing up in case of chain reorganisations.
    '''

    def __init__(self, env):
        super().__init__(env)

        # These are our state as we move ahead of DB state
        self.fs_height = self.db_height
        self.fs_tx_count = self.db_tx_count
        self.height = self.db_height
        self.tip = self.db_tip
        self.tx_count = self.db_tx_count

        self.daemon = Daemon(env.daemon_url, env.debug)
        self.daemon.debug_set_height(self.height)
        self.mempool = MemPool(self)
        self.touched = set()
        self.futures = []

        # Meta
        self.utxo_MB = env.utxo_MB
        self.hist_MB = env.hist_MB
        self.next_cache_check = 0
        self.reorg_limit = env.reorg_limit

        # Headers and tx_hashes have one entry per block
        self.history = defaultdict(partial(array.array, 'I'))
        self.history_size = 0
        self.prefetcher = Prefetcher(self.daemon, self.height)

        self.last_flush = time.time()
        self.last_flush_tx_count = self.tx_count

        # Caches of unflushed items
        self.headers = []
        self.tx_hashes = []

        # UTXO cache
        self.utxo_cache = {}
        self.utxo_cache_spends = 0
        self.db_deletes = []

        # Log state
        self.logger.info('coin: {}'.format(self.coin.NAME))
        self.logger.info('network: {}'.format(self.coin.NET))
        self.logger.info('height: {:,d}'.format(self.db_height))
        self.logger.info('tx count: {:,d}'.format(self.db_tx_count))
        self.logger.info('reorg limit is {:,d} blocks'
                         .format(self.reorg_limit))
        if self.first_sync:
            self.logger.info('sync time so far: {}'
                             .format(formatted_time(self.wall_time)))
            self.logger.info('flushing UTXO cache at {:,d} MB'
                             .format(self.utxo_MB))
            self.logger.info('flushing history cache at {:,d} MB'
                             .format(self.hist_MB))
        self.clean_db()

    async def main_loop(self):
        '''Main loop for block processing.

        Safely flushes the DB on clean shutdown.
        '''
        self.futures.append(asyncio.ensure_future(self.prefetcher.main_loop()))
        try:
            while True:
                await self._wait_for_update()
                await asyncio.sleep(0)   # Yield
        except asyncio.CancelledError:
            self.on_cancel()
            # This lets the asyncio subsystem process futures cancellations
            await asyncio.sleep(0)

    def on_cancel(self):
        '''Called when the main loop is cancelled.

        Intended to be overridden in derived classes.'''
        for future in self.futures:
            future.cancel()
        self.flush(True)

    async def _wait_for_update(self):
        '''Wait for the prefetcher to deliver blocks or a mempool update.

        Blocks are only processed in the forward direction.  The
        prefetcher only provides a non-None mempool when caught up.
        '''
        blocks, mempool_hashes = await self.prefetcher.get_blocks()

        '''Strip the unspendable genesis coinbase.'''
        if self.height == -1:
            blocks[0] = blocks[0][:self.coin.HEADER_LEN] + bytes(1)

        caught_up = mempool_hashes is not None
        try:
            for block in blocks:
                self.advance_block(block, caught_up)
                await asyncio.sleep(0)  # Yield
            if caught_up:
                await self.caught_up(mempool_hashes)
            self.touched = set()
        except ChainReorg:
            await self.handle_chain_reorg()

    async def caught_up(self, mempool_hashes):
        '''Called after each deamon poll if caught up.'''
        # Caught up to daemon height.  Flush everything as queries
        # are performed on the DB and not in-memory.
        self.flush(True)
        if self.first_sync:
            self.first_sync = False
            self.logger.info('synced to height {:,d}'.format(self.height))
        self.touched.update(await self.mempool.update(mempool_hashes))

    async def handle_chain_reorg(self):
        # First get all state on disk
        self.logger.info('chain reorg detected')
        self.flush(True)
        self.logger.info('finding common height...')

        hashes = await self.reorg_hashes()
        # Reverse and convert to hex strings.
        hashes = [hash_to_str(hash) for hash in reversed(hashes)]
        for hex_hashes in chunks(hashes, 50):
            blocks = await self.daemon.raw_blocks(hex_hashes)
            self.backup_blocks(blocks)

        self.logger.info('backed up to height {:,d}'.format(self.height))
        await self.prefetcher.clear(self.height)
        self.logger.info('prefetcher reset')

    async def reorg_hashes(self):
        '''Return the list of hashes to back up beacuse of a reorg.

        The hashes are returned in order of increasing height.'''

        def match_pos(hashes1, hashes2):
            for n, (hash1, hash2) in enumerate(zip(hashes1, hashes2)):
                if hash1 == hash2:
                    return n
            return -1

        start = self.height - 1
        count = 1
        while start > 0:
            hashes = self.fs_block_hashes(start, count)
            hex_hashes = [hash_to_str(hash) for hash in hashes]
            d_hex_hashes = await self.daemon.block_hex_hashes(start, count)
            n = match_pos(hex_hashes, d_hex_hashes)
            if n >= 0:
                start += n + 1
                break
            count = min(count * 2, start)
            start -= count

        # Hashes differ from height 'start'
        count = (self.height - start) + 1

        self.logger.info('chain was reorganised for {:,d} blocks from '
                         'height {:,d} to height {:,d}'
                         .format(count, start, start + count - 1))

        return self.fs_block_hashes(start, count)

    def clean_db(self):
        '''Clean out stale DB items.

        Stale DB items are excess history flushed since the most
        recent UTXO flush (only happens on unclean shutdown), and aged
        undo information.
        '''
        if self.flush_count < self.utxo_flush_count:
            raise ChainError('DB corrupt: flush_count < utxo_flush_count')
        with self.db.write_batch() as batch:
            if self.flush_count > self.utxo_flush_count:
                self.logger.info('DB shut down uncleanly.  Scanning for '
                                 'excess history flushes...')
                self.remove_excess_history(batch)
                self.utxo_flush_count = self.flush_count
            self.remove_stale_undo_items(batch)
            self.flush_state(batch)

    def remove_excess_history(self, batch):
        prefix = b'H'
        keys = []
        for key, hist in self.db.iterator(prefix=prefix):
            flush_id, = unpack('>H', key[-2:])
            if flush_id > self.utxo_flush_count:
                keys.append(key)

        self.logger.info('deleting {:,d} history entries'
                         .format(len(keys)))
        for key in keys:
            batch.delete(key)

    def remove_stale_undo_items(self, batch):
        prefix = b'U'
        cutoff = self.db_height - self.reorg_limit
        keys = []
        for key, hist in self.db.iterator(prefix=prefix):
            height, = unpack('>I', key[-4:])
            if height > cutoff:
                break
            keys.append(key)

        self.logger.info('deleting {:,d} stale undo entries'
                         .format(len(keys)))
        for key in keys:
            batch.delete(key)

    def flush_state(self, batch):
        '''Flush chain state to the batch.'''
        now = time.time()
        self.wall_time += now - self.last_flush
        self.last_flush = now
        self.last_flush_tx_count = self.tx_count
        self.write_state(batch)

    def assert_flushed(self):
        '''Asserts state is fully flushed.'''
        assert self.tx_count == self.fs_tx_count == self.db_tx_count
        assert self.height == self.fs_height == self.db_height
        assert not self.history
        assert not self.utxo_cache
        assert not self.db_deletes

    def flush(self, flush_utxos=False, flush_history=None):
        '''Flush out cached state.

        History is always flushed.  UTXOs are flushed if flush_utxos.'''
        if self.height == self.db_height:
            assert flush_history is None
            self.assert_flushed()
            return

        self.flush_count += 1
        flush_start = time.time()
        last_flush = self.last_flush
        tx_diff = self.tx_count - self.last_flush_tx_count
        show_stats = self.first_sync

        if self.height > self.db_height:
            assert flush_history is None
            flush_history = self.flush_history

        with self.db.write_batch() as batch:
            # History first - fast and frees memory.  Flush state last
            # as it reads the wall time.
            flush_history(batch)
            if flush_utxos:
                self.flush_utxos(batch)
            self.flush_state(batch)
            self.logger.info('committing transaction...')

        # Update and put the wall time again - otherwise we drop the
        # time it took to commit the batch
        self.flush_state(self.db)

        self.logger.info('flush #{:,d} to height {:,d} txs: {:,d} '
                         'took {:,.1f}s'
                         .format(self.flush_count, self.height, self.tx_count,
                                 self.last_flush - flush_start))

        # Catch-up stats
        if show_stats:
            daemon_height = self.daemon.cached_height()
            tx_per_sec = int(self.tx_count / self.wall_time)
            this_tx_per_sec = 1 + int(tx_diff / (self.last_flush - last_flush))
            if self.height > self.coin.TX_COUNT_HEIGHT:
                tx_est = (daemon_height - self.height) * self.coin.TX_PER_BLOCK
            else:
                tx_est = ((daemon_height - self.coin.TX_COUNT_HEIGHT)
                          * self.coin.TX_PER_BLOCK
                          + (self.coin.TX_COUNT - self.tx_count))

            # Damp the enthusiasm
            realism = 2.0 - 0.9 * self.height / self.coin.TX_COUNT_HEIGHT
            tx_est *= max(realism, 1.0)

            self.logger.info('tx/sec since genesis: {:,d}, '
                             'since last flush: {:,d}'
                             .format(tx_per_sec, this_tx_per_sec))
            self.logger.info('sync time: {}  ETA: {}'
                             .format(formatted_time(self.wall_time),
                                     formatted_time(tx_est / this_tx_per_sec)))

    def flush_history(self, batch):
        fs_flush_start = time.time()
        self.fs_flush()
        fs_flush_end = time.time()
        self.logger.info('FS flush took {:.1f} seconds'
                         .format(fs_flush_end - fs_flush_start))

        flush_id = pack('>H', self.flush_count)

        for hash168, hist in self.history.items():
            key = b'H' + hash168 + flush_id
            batch.put(key, hist.tobytes())

        self.logger.info('flushed {:,d} history entries for {:,d} addrs '
                         'in {:.1f}s'
                         .format(self.history_size, len(self.history),
                                 time.time() - fs_flush_end))
        self.history = defaultdict(partial(array.array, 'I'))
        self.history_size = 0

    def fs_flush(self):
        '''Flush the things stored on the filesystem.'''
        blocks_done = len(self.headers)
        prior_tx_count = (self.tx_counts[self.fs_height]
                          if self.fs_height >= 0 else 0)
        cur_tx_count = self.tx_counts[-1] if self.tx_counts else 0
        txs_done = cur_tx_count - prior_tx_count

        assert self.fs_height + blocks_done == self.height
        assert len(self.tx_hashes) == blocks_done
        assert len(self.tx_counts) == self.height + 1
        assert cur_tx_count == self.tx_count, \
            'cur: {:,d} new: {:,d}'.format(cur_tx_count, self.tx_count)

        # First the headers
        headers = b''.join(self.headers)
        header_len = self.coin.HEADER_LEN
        self.headers_file.seek((self.fs_height + 1) * header_len)
        self.headers_file.write(headers)
        self.headers_file.flush()

        # Then the tx counts
        self.txcount_file.seek((self.fs_height + 1) * self.tx_counts.itemsize)
        self.txcount_file.write(self.tx_counts[self.fs_height + 1:])
        self.txcount_file.flush()

        # Finally the hashes
        hashes = memoryview(b''.join(itertools.chain(*self.tx_hashes)))
        assert len(hashes) % 32 == 0
        assert len(hashes) // 32 == txs_done
        cursor = 0
        file_pos = prior_tx_count * 32
        while cursor < len(hashes):
            file_num, offset = divmod(file_pos, self.tx_hash_file_size)
            size = min(len(hashes) - cursor, self.tx_hash_file_size - offset)
            filename = 'hashes{:04d}'.format(file_num)
            with self.open_file(filename, create=True) as f:
                f.seek(offset)
                f.write(hashes[cursor:cursor + size])
            cursor += size
            file_pos += size

        os.sync()
        self.fs_height = self.height
        self.fs_tx_count = self.tx_count
        self.tx_hashes = []
        self.headers = []

    def backup_history(self, batch, hash168s):
        self.logger.info('backing up history to height {:,d}  tx_count {:,d}'
                         .format(self.height, self.tx_count))

        assert not self.history

        nremoves = 0
        for hash168 in sorted(hash168s):
            prefix = b'H' + hash168
            deletes = []
            puts = {}
            for key, hist in self.db.iterator(prefix=prefix, reverse=True):
                a = array.array('I')
                a.frombytes(hist)
                # Remove all history entries >= self.tx_count
                idx = bisect_left(a, self.tx_count)
                nremoves += len(a) - idx
                if idx > 0:
                    puts[key] = a[:idx].tobytes()
                    break
                deletes.append(key)

            for key in deletes:
                batch.delete(key)
            for key, value in puts.items():
                batch.put(key, value)

        self.logger.info('removed {:,d} history entries from {:,d} addresses'
                         .format(nremoves, len(hash168s)))

    def cache_sizes(self):
        '''Returns the approximate size of the cache, in MB.'''
        # Good average estimates based on traversal of subobjects and
        # requesting size from Python (see deep_getsizeof).  For
        # whatever reason Python O/S mem usage is typically +30% or
        # more, so we scale our already bloated object sizes.
        one_MB = int(1048576 / 1.3)
        utxo_cache_size = len(self.utxo_cache) * 187
        db_deletes_size = len(self.db_deletes) * 61
        hist_cache_size = len(self.history) * 180 + self.history_size * 4
        tx_hash_size = (self.tx_count - self.fs_tx_count) * 74
        utxo_MB = (db_deletes_size + utxo_cache_size) // one_MB
        hist_MB = (hist_cache_size + tx_hash_size) // one_MB

        self.logger.info('UTXOs: {:,d}  deletes: {:,d}  '
                         'UTXOs {:,d}MB  hist {:,d}MB'
                         .format(len(self.utxo_cache),
                                 len(self.db_deletes) // 2,
                                 utxo_MB, hist_MB))
        self.logger.info('our height: {:,d}  daemon height: {:,d}'
                         .format(self.height, self.daemon.cached_height()))
        return utxo_MB, hist_MB

    def undo_key(self, height):
        '''DB key for undo information at the given height.'''
        return b'U' + pack('>I', height)

    def write_undo_info(self, height, undo_info):
        '''Write out undo information for the current height.'''
        self.db.put(self.undo_key(height), undo_info)

    def read_undo_info(self, height):
        '''Read undo information from a file for the current height.'''
        return self.db.get(self.undo_key(height))

    def fs_advance_block(self, header, tx_hashes, txs):
        '''Update unflushed FS state for a new block.'''
        prior_tx_count = self.tx_counts[-1] if self.tx_counts else 0

        # Cache the new header, tx hashes and cumulative tx count
        self.headers.append(header)
        self.tx_hashes.append(tx_hashes)
        self.tx_counts.append(prior_tx_count + len(txs))

    def advance_block(self, block, update_touched):
        # We must update the FS cache before calling advance_txs() as
        # the UTXO cache uses the FS cache via get_tx_hash() to
        # resolve compressed key collisions
        header, tx_hashes, txs = self.coin.read_block(block)
        prev_hash, header_hash = self.coin.header_hashes(header)
        if prev_hash != self.tip:
            raise ChainReorg

        touched = set()
        self.fs_advance_block(header, tx_hashes, txs)
        self.tip = header_hash
        self.height += 1
        undo_info = self.advance_txs(tx_hashes, txs, touched)
        if self.daemon.cached_height() - self.height <= self.reorg_limit:
            self.write_undo_info(self.height, b''.join(undo_info))

        # Check if we're getting full and time to flush?
        now = time.time()
        if now > self.next_cache_check:
            self.next_cache_check = now + 60
            utxo_MB, hist_MB = self.cache_sizes()
            if utxo_MB >= self.utxo_MB or hist_MB >= self.hist_MB:
                self.flush(utxo_MB >= self.utxo_MB)

        if update_touched:
            self.touched.update(touched)

    def advance_txs(self, tx_hashes, txs, touched):
        put_utxo = self.utxo_cache.__setitem__
        spend_utxo = self.spend_utxo
        undo_info = []

        # Use local vars for speed in the loops
        history = self.history
        tx_num = self.tx_count
        script_hash168 = self.coin.hash168_from_script()
        s_pack = pack

        for tx, tx_hash in zip(txs, tx_hashes):
            hash168s = set()
            tx_numb = s_pack('<I', tx_num)

            # Spend the inputs
            if not tx.is_coinbase:
                for txin in tx.inputs:
                    cache_value = spend_utxo(txin.prev_hash, txin.prev_idx)
                    undo_info.append(cache_value)
                    hash168s.add(cache_value[:21])

            # Add the new UTXOs
            for idx, txout in enumerate(tx.outputs):
                # Get the hash168.  Ignore unspendable outputs
                hash168 = script_hash168(txout.pk_script)
                if hash168:
                    hash168s.add(hash168)
                    put_utxo(tx_hash + s_pack('<H', idx),
                             hash168 + tx_numb + s_pack('<Q', txout.value))

            for hash168 in hash168s:
                history[hash168].append(tx_num)
            self.history_size += len(hash168s)
            touched.update(hash168s)
            tx_num += 1

        self.tx_count = tx_num

        return undo_info

    def backup_blocks(self, blocks):
        '''Backup the blocks and flush.

        The blocks should be in order of decreasing height.
        A flush is performed once the blocks are backed up.
        '''
        self.logger.info('backing up {:,d} blocks'.format(len(blocks)))
        self.assert_flushed()

        touched = set()
        for block in blocks:
            header, tx_hashes, txs = self.coin.read_block(block)
            prev_hash, header_hash = self.coin.header_hashes(header)
            if header_hash != self.tip:
                raise ChainError('backup block {} is not tip {} at height {:,d}'
                                 .format(hash_to_str(header_hash),
                                         hash_to_str(self.tip), self.height))

            self.backup_txs(tx_hashes, txs, touched)
            self.tip = prev_hash
            assert self.height >= 0
            self.height -= 1

        assert not self.headers
        assert not self.tx_hashes

        self.logger.info('backed up to height {:,d}'.format(self.height))

        self.touched.update(touched)
        flush_history = partial(self.backup_history, hash168s=touched)
        self.flush(True, flush_history=flush_history)

    def backup_txs(self, tx_hashes, txs, touched):
        # Prevout values, in order down the block (coinbase first if present)
        # undo_info is in reverse block order
        undo_info = self.read_undo_info(self.height)
        n = len(undo_info)

        # Use local vars for speed in the loops
        s_pack = pack
        put_utxo = self.utxo_cache.__setitem__
        spend_utxo = self.spend_utxo

        rtxs = reversed(txs)
        rtx_hashes = reversed(tx_hashes)

        for tx_hash, tx in zip(rtx_hashes, rtxs):
            # Spend the outputs
            for idx, txout in enumerate(tx.outputs):
                cache_value = spend_utxo(tx_hash, idx)
                touched.add(cache_value[:21])

            # Restore the inputs
            if not tx.is_coinbase:
                for txin in reversed(tx.inputs):
                    n -= 33
                    undo_item = undo_info[n:n + 33]
                    put_utxo(txin.prev_hash + s_pack('<H', txin.prev_idx),
                             undo_item)
                    touched.add(undo_item[:21])

        assert n == 0
        self.tx_count -= len(txs)

    '''An in-memory UTXO cache, representing all changes to UTXO state
    since the last DB flush.

    We want to store millions of these in memory for optimal
    performance during initial sync, because then it is possible to
    spend UTXOs without ever going to the database (other than as an
    entry in the address history, and there is only one such entry per
    TX not per UTXO).  So store them in a Python dictionary with
    binary keys and values.

      Key:    TX_HASH + TX_IDX           (32 + 2 = 34 bytes)
      Value:  HASH168 + TX_NUM + VALUE   (21 + 4 + 8 = 33 bytes)

    That's 67 bytes of raw data.  Python dictionary overhead means
    each entry actually uses about 187 bytes of memory.  So almost
    11.5 million UTXOs can fit in 2GB of RAM.  There are approximately
    42 million UTXOs on bitcoin mainnet at height 433,000.

    Semantics:

      add:   Add it to the cache dictionary.

      spend: Remove it if in the cache dictionary.  Otherwise it's
             been flushed to the DB.  Each UTXO is responsible for two
             entries in the DB.  Mark them for deletion in the next
             cache flush.

    The UTXO database format has to be able to do two things efficiently:

      1.  Given an address be able to list its UTXOs and their values
          so its balance can be efficiently computed.

      2.  When processing transactions, for each prevout spent - a (tx_hash,
          idx) pair - we have to be able to remove it from the DB.  To send
          notifications to clients we also need to know any address it paid
          to.

    To this end we maintain two "tables", one for each point above:

      1.  Key: b'u' + address_hash168 + tx_idx + tx_num
          Value: the UTXO value as a 64-bit unsigned integer

      2.  Key: b'h' + compressed_tx_hash + tx_idx + tx_num
          Value: hash168

    The compressed tx hash is just the first few bytes of the hash of
    the tx in which the UTXO was created.  As this is not unique there
    will be potential collisions so tx_num is also in the key.  When
    looking up a UTXO the prefix space of the compressed hash needs to
    be searched and resolved if necessary with the tx_num.  The
    collision rate is low (<0.1%).
    '''

    def spend_utxo(self, tx_hash, tx_idx):
        '''Spend a UTXO and return the 33-byte value.

        If the UTXO is not in the cache it must be on disk.  We store
        all UTXOs so not finding one indicates a logic error or DB
        corruption.
        '''
        # Fast track is it being in the cache
        idx_packed = pack('<H', tx_idx)
        cache_value = self.utxo_cache.pop(tx_hash + idx_packed, None)
        if cache_value:
            self.utxo_cache_spends += 1
            return cache_value

        # Spend it from the DB.

        # Key: b'h' + compressed_tx_hash + tx_idx + tx_num
        # Value: hash168
        prefix = b'h' + tx_hash[:4] + idx_packed
        candidates = {db_key: hash168 for db_key, hash168
                      in self.db.iterator(prefix=prefix)}

        for hdb_key, hash168 in candidates.items():
            tx_num_packed = hdb_key[-4:]

            if len(candidates) > 1:
                tx_num, = unpack('<I', tx_num_packed)
                hash, height = self.get_tx_hash(tx_num)
                if hash != tx_hash:
                    continue

            # Key: b'u' + address_hash168 + tx_idx + tx_num
            # Value: the UTXO value as a 64-bit unsigned integer
            udb_key = b'u' + hash168 + hdb_key[-6:]
            utxo_value_packed = self.db.get(udb_key)
            if utxo_value_packed:
                # Remove both entries for this UTXO
                self.db_deletes.append(hdb_key)
                self.db_deletes.append(udb_key)
                return hash168 + tx_num_packed + utxo_value_packed

        raise ChainError('UTXO {} / {:,d} not found in "h" table'
                         .format(hash_to_str(tx_hash), tx_idx))

    def flush_utxos(self, batch):
        '''Flush the cached DB writes and UTXO set to the batch.'''
        # Care is needed because the writes generated by flushing the
        # UTXO state may have keys in common with our write cache or
        # may be in the DB already.
        flush_start = time.time()
        self.logger.info('flushing {:,d} blocks with {:,d} txs'
                         .format(self.height - self.db_height,
                                 self.tx_count - self.db_tx_count))
        self.logger.info('UTXO cache adds: {:,d} spends: {:,d} '
                         'DB spends: {:,d}'
                         .format(len(self.utxo_cache) + self.utxo_cache_spends,
                                 self.utxo_cache_spends,
                                 len(self.db_deletes) // 2))

        batch_delete = batch.delete
        for key in self.db_deletes:
            batch_delete(key)
        self.db_deletes = []

        batch_put = batch.put
        for cache_key, cache_value in self.utxo_cache.items():
            # suffix = tx_num + tx_idx
            hash168 = cache_value[:21]
            suffix =  cache_key[-2:] + cache_value[21:25]
            batch_put(b'h' + cache_key[:4] + suffix, hash168)
            batch_put(b'u' + hash168 + suffix, cache_value[25:])

        self.utxo_cache = {}
        self.db_deletes = []
        self.utxo_cache_spends = 0
        self.utxo_flush_count = self.flush_count
        self.db_tx_count = self.tx_count
        self.db_height = self.height
        self.db_tip = self.tip

        self.logger.info('UTXO flush took {:.1f} seconds'
                         .format(time.time() - flush_start))

    def read_headers(self, start, count):
        # Read some from disk
        disk_count = min(count, self.fs_height + 1 - start)
        result = self.fs_read_headers(start, disk_count)
        count -= disk_count
        start += disk_count

        # The rest from memory
        if count:
            start -= self.fs_height + 1
            if not (count >= 0 and start + count <= len(self.headers)):
                raise ChainError('{:,d} headers starting at {:,d} not on disk'
                                 .format(count, start))
            result += b''.join(self.headers[start: start + count])

        return result

    def get_tx_hash(self, tx_num):
        '''Returns the tx_hash and height of a tx number.'''
        tx_hash, tx_height = self.fs_tx_hash(tx_num)

        # Is this unflushed?
        if tx_hash is None:
            tx_hashes = self.tx_hashes[tx_height - (self.fs_height + 1)]
            tx_hash = tx_hashes[tx_num - self.tx_counts[tx_height - 1]]

        return tx_hash, tx_height

    def mempool_transactions(self, hash168):
        '''Generate (hex_hash, tx_fee, unconfirmed) tuples for mempool
        entries for the hash168.

        unconfirmed is True if any txin is unconfirmed.
        '''
        return self.mempool.transactions(hash168)

    def mempool_value(self, hash168):
        '''Return the unconfirmed amount in the mempool for hash168.

        Can be positive or negative.
        '''
        return self.mempool.value(hash168)
