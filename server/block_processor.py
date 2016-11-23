# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Block prefetcher and chain processor.'''


import array
import asyncio
from struct import pack, unpack
import time
from bisect import bisect_left
from collections import defaultdict
from functools import partial

from server.daemon import Daemon, DaemonError
from server.version import VERSION
from lib.hash import hash_to_str
from lib.util import chunks, formatted_time, LoggedClass
import server.db


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
        self.caught_up = False
        self.fetched_height = height
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
            self.caught_up = False

    async def get_blocks(self):
        '''Blocking function that returns prefetched blocks.

        The returned result empty just once - when the prefetcher
        has caught up with the daemon.
        '''
        blocks, size = await self.queue.get()
        self.queue_size -= size
        return blocks

    async def main_loop(self):
        '''Loop forever polling for more blocks.'''
        self.logger.info('catching up to daemon height {:,d}...'
                         .format(await self.daemon.height()))
        while True:
            try:
                with await self.semaphore:
                    await self._prefetch()
                await asyncio.sleep(5 if self.caught_up else 0)
            except DaemonError as e:
                self.logger.info('ignoring daemon error: {}'.format(e))
            except asyncio.CancelledError:
                break

    async def _prefetch(self):
        '''Prefetch blocks unless the prefetch queue is full.'''
        if self.queue_size >= self.target_cache_size:
            return

        daemon_height = await self.daemon.height()
        cache_room = self.target_cache_size // self.ave_size

        # Try and catch up all blocks but limit to room in cache.
        # Constrain count to between 0 and 4000 regardless
        count = min(daemon_height - self.fetched_height, cache_room)
        count = min(4000, max(count, 0))
        if not count:
            # Indicate when we have caught up for the first time only
            if not self.caught_up:
                self.caught_up = True
                self.queue.put_nowait(([], 0))
            return

        first = self.fetched_height + 1
        hex_hashes = await self.daemon.block_hex_hashes(first, count)
        if self.caught_up:
            self.logger.info('new block height {:,d} hash {}'
                             .format(first + count - 1, hex_hashes[-1]))
        blocks = await self.daemon.raw_blocks(hex_hashes)
        size = sum(len(block) for block in blocks)

        # Update our recent average block size estimate
        if count >= 10:
            self.ave_size = size // count
        else:
            self.ave_size = (size + (10 - count) * self.ave_size) // 10

        self.fetched_height += len(blocks)
        self.queue.put_nowait((blocks, size))
        self.queue_size += size


class ChainReorg(Exception):
    '''Raised on a blockchain reorganisation.'''


class BlockProcessor(server.db.DB):
    '''Process blocks and update the DB state to match.

    Employ a prefetcher to prefetch blocks in batches for processing.
    Coordinate backing up in case of chain reorganisations.
    '''

    def __init__(self, client, env):
        super().__init__(env)

        self.client = client

        # These are our state as we move ahead of DB state
        self.fs_height = self.db_height
        self.fs_tx_count = self.db_tx_count
        self.height = self.db_height
        self.tip = self.db_tip
        self.tx_count = self.db_tx_count

        self.daemon = Daemon(self.coin.daemon_urls(env.daemon_url))
        self.caught_up = False
        self.event = asyncio.Event()

        # Meta
        self.utxo_MB = env.utxo_MB
        self.hist_MB = env.hist_MB
        self.next_cache_check = 0

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
        self.db_deletes = []

        # Log state
        if self.first_sync:
            self.logger.info('flushing UTXO cache at {:,d} MB'
                             .format(self.utxo_MB))
            self.logger.info('flushing history cache at {:,d} MB'
                             .format(self.hist_MB))

    async def main_loop(self):
        '''Main loop for block processing.'''
        try:
            # Simulate a reorg if requested
            if self.env.force_reorg > 0:
                self.logger.info('DEBUG: simulating reorg of {:,d} blocks'
                                 .format(self.env.force_reorg))
                await self.handle_chain_reorg(self.env.force_reorg, set())

            while True:
                await self._wait_for_update()
        except asyncio.CancelledError:
            pass

    async def shutdown(self):
        '''Shut down the DB cleanly.'''
        self.logger.info('flushing state to DB for clean shutdown...')
        self.flush(True)

    async def _wait_for_update(self):
        '''Wait for the prefetcher to deliver blocks.

        Blocks are only processed in the forward direction.
        '''
        blocks = await self.prefetcher.get_blocks()
        if not blocks:
            self.first_caught_up()
            return

        '''Strip the unspendable genesis coinbase.'''
        if self.height == -1:
            blocks[0] = blocks[0][:self.coin.HEADER_LEN] + bytes(1)

        touched = set()
        try:
            for block in blocks:
                self.advance_block(block, touched)
                await asyncio.sleep(0)  # Yield
        except ChainReorg:
            await self.handle_chain_reorg(None, touched)

        if self.caught_up:
            # Flush everything as queries are performed on the DB and
            # not in-memory.
            self.flush(True)
            self.client.notify(touched)
        elif time.time() > self.next_cache_check:
            self.check_cache_size()
            self.next_cache_check = time.time() + 60

    def first_caught_up(self):
        '''Called when first caught up after start, or after a reorg.'''
        self.caught_up = True
        if self.first_sync:
            self.first_sync = False
            self.logger.info('{} synced to height {:,d}.  DB version:'
                             .format(VERSION, self.height, self.db_version))
        self.flush(True)
        self.event.set()

    async def handle_chain_reorg(self, count, touched):
        '''Handle a chain reorganisation.

        Count is the number of blocks to simulate a reorg, or None for
        a real reorg.'''
        self.logger.info('chain reorg detected')
        self.flush(True)
        self.logger.info('finding common height...')

        hashes = await self.reorg_hashes(count)
        # Reverse and convert to hex strings.
        hashes = [hash_to_str(hash) for hash in reversed(hashes)]
        for hex_hashes in chunks(hashes, 50):
            blocks = await self.daemon.raw_blocks(hex_hashes)
            self.backup_blocks(blocks, touched)

        await self.prefetcher.clear(self.height)
        self.logger.info('prefetcher reset')

    async def reorg_hashes(self, count):
        '''Return the list of hashes to back up beacuse of a reorg.

        The hashes are returned in order of increasing height.'''

        def match_pos(hashes1, hashes2):
            for n, (hash1, hash2) in enumerate(zip(hashes1, hashes2)):
                if hash1 == hash2:
                    return n
            return -1

        if count is None:
            # A real reorg
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

            count = (self.height - start) + 1
        else:
            start = (self.height - count) + 1

        self.logger.info('chain was reorganised: {:,d} blocks at '
                         'heights {:,d}-{:,d} were replaced'
                         .format(count, start, start + count - 1))

        return self.fs_block_hashes(start, count)

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

        # Update and put the wall time again - otherwise we drop the
        # time it took to commit the batch
        self.flush_state(self.db)

        self.logger.info('flush #{:,d} took {:.1f}s.  Height {:,d} txs: {:,d}'
                         .format(self.flush_count,
                                 self.last_flush - flush_start,
                                 self.height, self.tx_count))

        # Catch-up stats
        if self.first_sync:
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
        fs_start = time.time()
        self.fs_flush()
        fs_end = time.time()

        flush_id = pack('>H', self.flush_count)

        for hash168, hist in self.history.items():
            key = b'H' + hash168 + flush_id
            batch.put(key, hist.tobytes())

        if self.first_sync:
            self.logger.info('flushed to FS in {:.1f}s, history in {:.1f}s '
                             'for {:,d} addrs'
                             .format(fs_end - fs_start, time.time() - fs_end,
                                     len(self.history)))
        self.history = defaultdict(partial(array.array, 'I'))
        self.history_size = 0

    def fs_flush(self):
        '''Flush the things stored on the filesystem.'''
        assert self.fs_height + len(self.headers) == self.height
        assert self.tx_count == self.tx_counts[-1] if self.tx_counts else 0

        self.fs_update(self.fs_height, self.headers, self.tx_hashes)

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

        self.fs_height = self.height
        self.fs_tx_count = self.tx_count
        assert not self.headers
        assert not self.tx_hashes

        self.logger.info('removed {:,d} history entries from {:,d} addresses'
                         .format(nremoves, len(hash168s)))

    def check_cache_size(self):
        '''Flush a cache if it gets too big.'''
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

        self.logger.info('our height: {:,d} daemon: {:,d} '
                         'UTXOs {:,d}MB hist {:,d}MB'
                         .format(self.height, self.daemon.cached_height(),
                                 utxo_MB, hist_MB))

        # Flush if a cache is too big
        if utxo_MB >= self.utxo_MB or hist_MB >= self.hist_MB:
            self.flush(utxo_MB >= self.utxo_MB)

    def fs_advance_block(self, header, tx_hashes, txs):
        '''Update unflushed FS state for a new block.'''
        prior_tx_count = self.tx_counts[-1] if self.tx_counts else 0

        # Cache the new header, tx hashes and cumulative tx count
        self.headers.append(header)
        self.tx_hashes.append(tx_hashes)
        self.tx_counts.append(prior_tx_count + len(txs))

    def advance_block(self, block, touched):
        # We must update the FS cache before calling advance_txs() as
        # the UTXO cache uses the FS cache via get_tx_hash() to
        # resolve compressed key collisions
        header, tx_hashes, txs = self.coin.read_block(block)
        if self.tip != self.coin.header_prevhash(header):
            raise ChainReorg

        self.fs_advance_block(header, tx_hashes, txs)
        self.tip = self.coin.header_hash(header)
        self.height += 1
        undo_info = self.advance_txs(tx_hashes, txs, touched)
        if self.daemon.cached_height() - self.height <= self.env.reorg_limit:
            self.write_undo_info(self.height, b''.join(undo_info))

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

    def backup_blocks(self, blocks, touched):
        '''Backup the blocks and flush.

        The blocks should be in order of decreasing height.
        A flush is performed once the blocks are backed up.
        '''
        self.logger.info('backing up {:,d} blocks'.format(len(blocks)))
        self.assert_flushed()

        for block in blocks:
            header, tx_hashes, txs = self.coin.read_block(block)
            header_hash = self.coin.header_hash(header)
            if header_hash != self.tip:
                raise ChainError('backup block {} is not tip {} at height {:,d}'
                                 .format(hash_to_str(header_hash),
                                         hash_to_str(self.tip), self.height))

            self.backup_txs(tx_hashes, txs, touched)
            self.tip = self.coin.header_prevhash(header)
            assert self.height >= 0
            self.height -= 1
            self.tx_counts.pop()

        self.logger.info('backed up to height {:,d}'.format(self.height))

        # touched includes those passed into this function.  That will
        # generally be empty but is harmless if not.
        flush_history = partial(self.backup_history, hash168s=touched)
        self.flush(True, flush_history=flush_history)

    def backup_txs(self, tx_hashes, txs, touched):
        # Prevout values, in order down the block (coinbase first if present)
        # undo_info is in reverse block order
        undo_info = self.read_undo_info(self.height)
        if not undo_info:
            raise ChainError('no undo information found for height {:,d}'
                             .format(self.height))
        n = len(undo_info)

        # Use local vars for speed in the loops
        s_pack = pack
        put_utxo = self.utxo_cache.__setitem__
        spend_utxo = self.spend_utxo
        script_hash168 = self.coin.hash168_from_script()

        rtxs = reversed(txs)
        rtx_hashes = reversed(tx_hashes)

        for tx_hash, tx in zip(rtx_hashes, rtxs):
            for idx, txout in enumerate(tx.outputs):
                # Spend the TX outputs.  Be careful with unspendable
                # outputs - we didn't save those in the first place.
                hash168 = script_hash168(txout.pk_script)
                if hash168:
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

        if self.first_sync:
            self.logger.info('flushed {:,d} blocks with {:,d} txs, {:,d} UTXO '
                             'adds, {:,d} spends in {:.1f}s, committing...'
                             .format(self.height - self.db_height,
                                     self.tx_count - self.db_tx_count,
                                     len(self.utxo_cache),
                                     len(self.db_deletes) // 2,
                                     time.time() - flush_start))

        self.utxo_cache = {}
        self.db_deletes = []
        self.utxo_flush_count = self.flush_count
        self.db_tx_count = self.tx_count
        self.db_height = self.height
        self.db_tip = self.tip

    def get_tx_hash(self, tx_num):
        '''Returns the tx_hash and height of a tx number.'''
        tx_hash, tx_height = self.fs_tx_hash(tx_num)

        # Is this unflushed?
        if tx_hash is None:
            tx_hashes = self.tx_hashes[tx_height - (self.fs_height + 1)]
            tx_hash = tx_hashes[tx_num - self.tx_counts[tx_height - 1]]

        return tx_hash, tx_height
