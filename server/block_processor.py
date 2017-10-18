# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.
"""Block prefetcher and chain processor."""

import array
import asyncio
import time
from collections import defaultdict
from functools import partial
from struct import pack, unpack

import server.db
from lib.hash import hash_to_str
from lib.util import chunks, formatted_time, LoggedClass
from server.daemon import DaemonError
from server.version import VERSION


class Prefetcher(LoggedClass):
    """Prefetches blocks (in the forward direction only)."""

    def __init__(self, bp):
        super().__init__()
        self.bp = bp
        self.caught_up = False
        # Access to fetched_height should be protected by the semaphore
        self.fetched_height = None
        self.semaphore = asyncio.Semaphore()
        self.refill_event = asyncio.Event()
        # The prefetched block cache size.  The min cache size has
        # little effect on sync time.
        self.cache_size = 0
        self.min_cache_size = 10 * 1024 * 1024
        # This makes the first fetch be 10 blocks
        self.ave_size = self.min_cache_size // 10

    async def main_loop(self):
        """Loop forever polling for more blocks."""
        while True:
            try:
                # Sleep a while if there is nothing to prefetch
                await self.refill_event.wait()
                if not await self._prefetch_blocks():
                    await asyncio.sleep(5)
            except DaemonError as e:
                self.logger.info(f'ignoring daemon error: {e}')

    def processing_blocks(self, blocks):
        """Called by block processor when it is processing queued blocks."""
        self.cache_size -= sum(len(block) for block in blocks)
        if self.cache_size < self.min_cache_size:
            self.refill_event.set()

    async def reset_height(self):
        """Reset to prefetch blocks from the block processor's height.

        Used in blockchain reorganisations.  This coroutine can be
        called asynchronously to the _prefetch coroutine so we must
        synchronize with a semaphore."""
        with await self.semaphore:
            self.fetched_height = self.bp.height
            self.refill_event.set()

        daemon_height = await self.bp.daemon.height()
        behind = daemon_height - self.bp.height
        if behind > 0:
            self.logger.info(f'catching up to daemon height {daemon_height:,d}'
                             f' ({behind:,d} blocks behind)')
        else:
            self.logger.info(f'caught up to daemon height {daemon_height:,d}')

    async def _prefetch_blocks(self):
        """Prefetch some blocks and put them on the queue.

        Repeats until the queue is full or caught up.
        """
        daemon = self.bp.daemon
        daemon_height = await daemon.height(self.bp.caught_up_event.is_set())
        with await self.semaphore:
            while self.cache_size < self.min_cache_size:
                # Try and catch up all blocks but limit to room in cache.
                # Constrain fetch count to between 0 and 500 regardless;
                # testnet can be lumpy.
                cache_room = self.min_cache_size // self.ave_size
                count = min(daemon_height - self.fetched_height, cache_room)
                count = min(500, max(count, 0))
                if not count:
                    if not self.caught_up:
                        self.caught_up = True
                        self.bp.on_prefetcher_first_caught_up()
                    return False

                first = self.fetched_height + 1
                hex_hashes = await daemon.block_hex_hashes(first, count)
                if self.caught_up:
                    self.logger.info(f'new block height {first + count - 1:,d}'
                                     f' hash {hex_hashes[-1]}')
                blocks = await daemon.raw_blocks(hex_hashes)

                assert count == len(blocks)

                # Special handling for genesis block
                if first == 0:
                    blocks[0] = self.bp.coin.genesis_block(blocks[0])
                    self.logger.info(f'verified genesis block with '
                                     f'hash {hex_hashes[0]}')

                # Update our recent average block size estimate
                size = sum(len(block) for block in blocks)
                if count >= 10:
                    self.ave_size = size // count
                else:
                    self.ave_size = (size + (10 - count) * self.ave_size) // 10

                self.bp.on_prefetched_blocks(blocks, first)
                self.cache_size += size
                self.fetched_height += count

        self.refill_event.clear()
        return True


class ChainError(Exception):
    """Raised on error processing blocks."""


class BlockProcessor(server.db.DB):
    """Process blocks and update the DB state to match.

    Employ a prefetcher to prefetch blocks in batches for processing.
    Coordinate backing up in case of chain reorganisations.
    """

    def __init__(self, env, controller, daemon):
        super().__init__(env)

        # An incomplete compaction needs to be cancelled otherwise
        # restarting it will corrupt the history
        self.cancel_history_compaction()

        self.daemon = daemon
        self.controller = controller

        # These are our state as we move ahead of DB state
        self.fs_height = self.db_height
        self.fs_tx_count = self.db_tx_count
        self.height = self.db_height
        self.tip = self.db_tip
        self.tx_count = self.db_tx_count

        self.caught_up_event = asyncio.Event()
        self.task_queue = asyncio.Queue()

        # Meta
        self.cache_MB = env.cache_MB
        self.next_cache_check = 0
        self.last_flush = time.time()
        self.last_flush_tx_count = self.tx_count
        self.touched = set()

        # Caches of unflushed items.
        self.headers = []
        self.tx_hashes = []
        self.undo_infos = []
        self.history = defaultdict(partial(array.array, 'I'))
        self.history_size = 0

        # UTXO cache
        self.utxo_cache = {}
        self.db_deletes = []

        # From flush utxos
        self.utxo_flush_count = None
        self.db_tx_count = None
        self.db_height = None
        self.db_tip = None
        self.first_sync = False

        self.prefetcher = Prefetcher(self)

        if self.utxo_db.for_sync:
            self.logger.info(f'flushing DB cache at {self.cache_MB:,d} MB')

    def add_task(self, task):
        """Add the task to our task queue."""
        self.task_queue.put_nowait(task)

    def on_prefetched_blocks(self, blocks, first):
        """Called by the prefetcher when it has prefetched some blocks."""
        self.add_task(partial(self.check_and_advance_blocks, blocks, first))

    def on_prefetcher_first_caught_up(self):
        """Called by the prefetcher when it first catches up."""
        self.add_task(self.first_caught_up)

    async def main_loop(self):
        """Main loop for block processing."""
        self.controller.ensure_future(self.prefetcher.main_loop())
        await self.prefetcher.reset_height()

        while True:
            task = await self.task_queue.get()
            await task()

    def shutdown(self, executor):
        """Shutdown cleanly and flush to disk."""
        # First stut down the executor; it may be processing a block.
        # Then we can flush anything remaining to disk.
        executor.shutdown()
        if self.height != self.db_height:
            self.logger.info('flushing state to DB for a clean shutdown...')
            self.flush(True)

    async def first_caught_up(self):
        """Called when first caught up to daemon after starting."""
        # Flush everything with updated first_sync->False state.
        self.first_sync = False
        await self.controller.run_in_executor(self.flush, True)
        if self.utxo_db.for_sync:
            self.logger.info(f'{VERSION} synced to height {self.height:,d}')
        self.open_dbs()
        self.caught_up_event.set()

    async def check_and_advance_blocks(self, raw_blocks, first):
        """Process the list of raw blocks passed.  Detects and handles
        reorgs.
        """
        self.prefetcher.processing_blocks(raw_blocks)
        if first != self.height + 1:
            # If we prefetched two sets of blocks and the first caused
            # a reorg this will happen when we try to process the
            # second.  It should be very rare.
            self.logger.warning(f'ignoring {len(raw_blocks):,d} '
                                f'blocks starting height {first:,d}, '
                                f'expected {self.height + 1:,d}')
            return

        blocks = [self.coin.block(raw_block, first + n)
                  for n, raw_block in enumerate(raw_blocks)]
        headers = [block.header for block in blocks]
        hprevs = [self.coin.header_prevhash(h) for h in headers]
        chain = [self.tip] + [self.coin.header_hash(h) for h in headers[:-1]]

        if hprevs == chain:
            start = time.time()
            await self.controller.run_in_executor(self.advance_blocks, blocks)
            if not self.first_sync:
                s = '' if len(blocks) == 1 else 's'
                self.logger.info(f'processed {len(blocks):,d} '
                                 f'block{s} in {time.time() - start:.1f}s')
        elif hprevs[0] != chain[0]:
            await self.reorg_chain()
        else:
            # It is probably possible but extremely rare that what
            # bitcoind returns doesn't form a chain because it
            # reorg-ed the chain as it was processing the batched
            # block hash requests.  Should this happen it's simplest
            # just to reset the prefetcher and try again.
            self.logger.warning('daemon blocks do not form a chain; '
                                'resetting the prefetcher')
            await self.prefetcher.reset_height()

    def force_chain_reorg(self, count):
        """Force a reorg of the given number of blocks.

        Returns True if a reorg is queued, false if not caught up.
        """
        if self.caught_up_event.is_set():
            self.add_task(partial(self.reorg_chain, count=count))
            return True
        return False

    async def reorg_chain(self, count=None):
        """Handle a chain reorganisation.

        Count is the number of blocks to simulate a reorg, or None for
        a real reorg."""
        if count is None:
            self.logger.info('chain reorg detected')
        else:
            self.logger.info(f'faking a reorg of {count:,d} blocks')
        await self.controller.run_in_executor(self.flush, True)

        hashes = await self.reorg_hashes(count)
        # Reverse and convert to hex strings.
        hashes = [hash_to_str(_hash) for _hash in reversed(hashes)]
        for hex_hashes in chunks(hashes, 50):
            blocks = await self.daemon.raw_blocks(hex_hashes)
            await self.controller.run_in_executor(self.backup_blocks, blocks)
        await self.prefetcher.reset_height()

    async def reorg_hashes(self, count):
        """Return the list of hashes to back up beacuse of a reorg.

        The hashes are returned in order of increasing height."""

        def diff_pos(hashes1, hashes2):
            """Returns the index of the first difference in the hash lists.
            If both lists match returns their length."""
            for length, (hash1, hash2) in enumerate(zip(hashes1, hashes2)):
                if hash1 != hash2:
                    return length
            return len(hashes)

        if count is None:
            # A real reorg
            start = self.height - 1
            count = 1
            while start > 0:
                hashes = self.fs_block_hashes(start, count)
                hex_hashes = [hash_to_str(_hash) for _hash in hashes]
                d_hex_hashes = await self.daemon.block_hex_hashes(start, count)
                n = diff_pos(hex_hashes, d_hex_hashes)
                if n > 0:
                    start += n
                    break
                count = min(count * 2, start)
                start -= count

            count = (self.height - start) + 1
        else:
            start = (self.height - count) + 1

        s = '' if count == 1 else 's'
        self.logger.info(f'chain was reorganised replacing {count:,d} block{s}'
                         f' at heights {start:,d}-{start + count - 1:,d}')

        return self.fs_block_hashes(start, count)

    def flush_state(self, batch):
        """Flush chain state to the batch."""
        now = time.time()
        self.wall_time += now - self.last_flush
        self.last_flush = now
        self.last_flush_tx_count = self.tx_count
        self.write_utxo_state(batch)

    def assert_flushed(self):
        """Asserts state is fully flushed."""
        assert self.tx_count == self.fs_tx_count == self.db_tx_count
        assert self.height == self.fs_height == self.db_height
        assert not self.undo_infos
        assert not self.history
        assert not self.utxo_cache
        assert not self.db_deletes

    def flush(self, flush_utxos=False):
        """Flush out cached state.

        History is always flushed.  UTXOs are flushed if flush_utxos."""
        if self.height == self.db_height:
            self.assert_flushed()
            return

        flush_start = time.time()
        last_flush = self.last_flush
        tx_diff = self.tx_count - self.last_flush_tx_count

        # Flush to file system
        self.fs_flush()
        fs_end = time.time()
        if self.utxo_db.for_sync:
            self.logger.info(f'flushed to FS in {fs_end - flush_start:.1f}s')

        # History next - it's fast and frees memory
        self.flush_history(self.history)
        if self.utxo_db.for_sync:
            self.logger.info(f'flushed history in {time.time() - fs_end:.1f}s '
                             f'for {len(self.history):,d} addrs')
        self.history = defaultdict(partial(array.array, 'I'))
        self.history_size = 0

        # Flush state last as it reads the wall time.
        with self.utxo_db.write_batch() as batch:
            if flush_utxos:
                self.flush_utxos(batch)
            self.flush_state(batch)

        # Update and put the wall time again - otherwise we drop the
        # time it took to commit the batch
        self.flush_state(self.utxo_db)

        self.logger.info(f'flush #{self.flush_count:,d} '
                         f'took {self.last_flush - flush_start:.1f}s.  '
                         f'Height {self.height:,d} '
                         f'txs: {self.tx_count:,d}')

        # Catch-up stats
        if self.utxo_db.for_sync:
            tx_per_sec = int(self.tx_count / self.wall_time)
            this_tx_per_sec = 1 + int(tx_diff / (self.last_flush - last_flush))
            self.logger.info(f'tx/sec since genesis: {tx_per_sec:,d}, '
                             f'since last flush: {this_tx_per_sec:,d}')

            daemon_height = self.daemon.cached_height()
            if self.height > self.coin.TX_COUNT_HEIGHT:
                tx_est = (daemon_height - self.height) * self.coin.TX_PER_BLOCK
            else:
                tx_est = ((daemon_height - self.coin.TX_COUNT_HEIGHT)
                          * self.coin.TX_PER_BLOCK
                          + (self.coin.TX_COUNT - self.tx_count))

            # Damp the enthusiasm
            realism = 2.0 - 0.9 * self.height / self.coin.TX_COUNT_HEIGHT
            tx_est *= max(realism, 1.0)

            self.logger.info(f'sync time: {formatted_time(self.wall_time)}  '
                             'ETA: {formatted_time(tx_est / this_tx_per_sec)}')

    def fs_flush(self):
        """Flush the things stored on the filesystem."""
        assert self.fs_height + len(self.headers) == self.height
        assert self.tx_count == self.tx_counts[-1] if self.tx_counts else 0

        self.fs_update(self.fs_height, self.headers, self.tx_hashes)
        self.fs_height = self.height
        self.fs_tx_count = self.tx_count
        self.tx_hashes = []
        self.headers = []

    def backup_flush(self):
        """Like flush() but when backing up.  All UTXOs are flushed.

        hash_xs - sequence of hash_xs which were touched by backing
        up.  Searched for history entries to remove after the backup
        height.
        """
        assert self.height < self.db_height
        assert not self.history

        flush_start = time.time()

        # Backup FS (just move the pointers back)
        self.fs_height = self.height
        self.fs_tx_count = self.tx_count
        assert not self.headers
        assert not self.tx_hashes

        # Backup history.  self.touched can include other addresses
        # which is harmless, but remove None.
        self.touched.discard(None)
        nremoves = self.backup_history(self.touched)
        self.logger.info(f'backing up removed {nremoves:,d} history entries')

        with self.utxo_db.write_batch() as batch:
            # Flush state last as it reads the wall time.
            self.flush_utxos(batch)
            self.flush_state(batch)

        self.logger.info(f'backup flush #{self.flush_count:,d} '
                         f'took {self.last_flush - flush_start:.1f}s.  '
                         f'Height {self.height:,d} '
                         f'txs: {self.tx_count:,d}')

    def check_cache_size(self):
        """Flush a cache if it gets too big."""
        # Good average estimates based on traversal of subobjects and
        # requesting size from Python (see deep_getsizeof).
        one_MB = 1000 * 1000
        utxo_cache_size = len(self.utxo_cache) * 205
        db_deletes_size = len(self.db_deletes) * 57
        hist_cache_size = len(self.history) * 180 + self.history_size * 4
        # Roughly ntxs * 32 + nblocks * 42
        tx_hash_size = ((self.tx_count - self.fs_tx_count) * 32
                        + (self.height - self.fs_height) * 42)
        utxo_MB = (db_deletes_size + utxo_cache_size) // one_MB
        hist_MB = (hist_cache_size + tx_hash_size) // one_MB

        self.logger.info(f'our height: {self.height:,d} '
                         f'daemon: {self.daemon.cached_height():,d} '
                         f'UTXOs {utxo_MB:,d}MB hist {hist_MB:,d}MB')

        # Flush history if it takes up over 20% of cache memory.
        # Flush UTXOs once they take up 80% of cache memory.
        if utxo_MB + hist_MB >= self.cache_MB or hist_MB >= self.cache_MB // 5:
            self.flush(utxo_MB >= self.cache_MB * 4 // 5)

    def advance_blocks(self, blocks):
        """Synchronously advance the blocks.

        It is already verified they correctly connect onto our tip.
        """
        min_height = self.min_undo_height(self.daemon.cached_height())
        height = self.height

        for block in blocks:
            height += 1
            undo_info = self.advance_txs(block.transactions)
            if height >= min_height:
                self.undo_infos.append((undo_info, height))

        headers = [block.header for block in blocks]
        self.height = height
        self.headers.extend(headers)
        self.tip = self.coin.header_hash(headers[-1])

        # If caught up, flush everything as client queries are
        # performed on the DB.
        if self.caught_up_event.is_set():
            self.flush(True)
        else:
            self.touched.clear()
            if time.time() > self.next_cache_check:
                self.check_cache_size()
                self.next_cache_check = time.time() + 30

    def advance_txs(self, txs):
        self.tx_hashes.append(b''.join(tx_hash for tx, tx_hash in txs))

        # Use local vars for speed in the loops
        undo_info = []
        history = self.history
        history_size = self.history_size
        tx_num = self.tx_count
        script_hash_x = self.coin.hash_x_from_script
        s_pack = pack
        put_utxo = self.utxo_cache.__setitem__
        spend_utxo = self.spend_utxo
        undo_info_append = undo_info.append
        touched = self.touched

        for tx, tx_hash in txs:
            hash_xs = set()
            add_hash_x = hash_xs.add
            tx_numb = s_pack('<I', tx_num)

            # Spend the inputs
            if not tx.is_coinbase:
                for txin in tx.inputs:
                    cache_value = spend_utxo(txin.prev_hash, txin.prev_idx)
                    undo_info_append(cache_value)
                    add_hash_x(cache_value[:-12])

            # Add the new UTXOs
            for idx, txout in enumerate(tx.outputs):
                # Get the hash_x.  Ignore unspendable outputs
                hash_x = script_hash_x(txout.pk_script)
                if hash_x:
                    add_hash_x(hash_x)
                    put_utxo(tx_hash + s_pack('<H', idx),
                             hash_x + tx_numb + s_pack('<Q', txout.value))

            for hash_x in hash_xs:
                history[hash_x].append(tx_num)
            history_size += len(hash_xs)
            touched.update(hash_xs)
            tx_num += 1

        self.tx_count = tx_num
        self.tx_counts.append(tx_num)
        self.history_size = history_size

        return undo_info

    def backup_blocks(self, raw_blocks):
        """Backup the raw blocks and flush.

        The blocks should be in order of decreasing height, starting at.
        self.height.  A flush is performed once the blocks are backed up.
        """
        self.assert_flushed()
        assert self.height >= len(raw_blocks)

        coin = self.coin
        for raw_block in raw_blocks:
            # Check and update self.tip
            block = coin.block(raw_block, self.height)
            header_hash = coin.header_hash(block.header)
            if header_hash != self.tip:
                raise ChainError(f'backup block {hash_to_str(header_hash)} '
                                 f'not tip {hash_to_str(self.tip)} '
                                 f'at height {self.height:,d}')
            self.tip = coin.header_prevhash(block.header)
            self.backup_txs(block.transactions)
            self.height -= 1
            self.tx_counts.pop()

        self.logger.info(f'backed up to height {self.height):,d}')
        self.backup_flush()

    def backup_txs(self, txs):
        # Prevout values, in order down the block (coinbase first if present)
        # undo_info is in reverse block order
        undo_info = self.read_undo_info(self.height)
        if undo_info is None:
            raise ChainError(f'no undo information found for height '
                             f'{self.height:,d}')
        n = len(undo_info)

        # Use local vars for speed in the loops
        s_pack = pack
        put_utxo = self.utxo_cache.__setitem__
        spend_utxo = self.spend_utxo
        script_hash_x = self.coin.hash_x_from_script
        touched = self.touched
        undo_entry_len = 12 + self.coin.HASHX_LEN

        for tx, tx_hash in reversed(txs):
            for idx, txout in enumerate(tx.outputs):
                # Spend the TX outputs.  Be careful with unspendable
                # outputs - we didn't save those in the first place.
                hash_x = script_hash_x(txout.pk_script)
                if hash_x:
                    cache_value = spend_utxo(tx_hash, idx)
                    touched.add(cache_value[:-12])

            # Restore the inputs
            if not tx.is_coinbase:
                for txin in reversed(tx.inputs):
                    n -= undo_entry_len
                    undo_item = undo_info[n:n + undo_entry_len]
                    put_utxo(txin.prev_hash + s_pack('<H', txin.prev_idx),
                             undo_item)
                    touched.add(undo_item[:-12])

        assert n == 0
        self.tx_count -= len(txs)

    """An in-memory UTXO cache, representing all changes to UTXO state
    since the last DB flush.

    We want to store millions of these in memory for optimal
    performance during initial sync, because then it is possible to
    spend UTXOs without ever going to the database (other than as an
    entry in the address history, and there is only one such entry per
    TX not per UTXO).  So store them in a Python dictionary with
    binary keys and values.

      Key:    TX_HASH + TX_IDX           (32 + 2 = 34 bytes)
      Value:  HASHX + TX_NUM + VALUE     (11 + 4 + 8 = 23 bytes)

    That's 57 bytes of raw data in-memory.  Python dictionary overhead
    means each entry actually uses about 205 bytes of memory.  So
    almost 5 million UTXOs can fit in 1GB of RAM.  There are
    approximately 42 million UTXOs on bitcoin mainnet at height
    433,000.

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

      1.  Key: b'u' + address_hash_x + tx_idx + tx_num
          Value: the UTXO value as a 64-bit unsigned integer

      2.  Key: b'h' + compressed_tx_hash + tx_idx + tx_num
          Value: hash_x

    The compressed tx hash is just the first few bytes of the hash of
    the tx in which the UTXO was created.  As this is not unique there
    will be potential collisions so tx_num is also in the key.  When
    looking up a UTXO the prefix space of the compressed hash needs to
    be searched and resolved if necessary with the tx_num.  The
    collision rate is low (<0.1%).
    """

    def spend_utxo(self, tx_hash, tx_idx):
        """Spend a UTXO and return the 33-byte value.

        If the UTXO is not in the cache it must be on disk.  We store
        all UTXOs so not finding one indicates a logic error or DB
        corruption.
        """
        # Fast track is it being in the cache
        idx_packed = pack('<H', tx_idx)
        cache_value = self.utxo_cache.pop(tx_hash + idx_packed, None)
        if cache_value:
            return cache_value

        # Spend it from the DB.

        # Key: b'h' + compressed_tx_hash + tx_idx + tx_num
        # Value: hash_x
        prefix = b'h' + tx_hash[:4] + idx_packed
        candidates = {db_key: hash_x for db_key, hash_x
                      in self.utxo_db.iterator(prefix=prefix)}

        for hdb_key, hash_x in candidates.items():
            tx_num_packed = hdb_key[-4:]

            if len(candidates) > 1:
                tx_num, = unpack('<I', tx_num_packed)
                _hash, height = self.fs_tx_hash(tx_num)
                if _hash != tx_hash:
                    assert _hash is not None  # Should always be found
                    continue

            # Key: b'u' + address_hash_x + tx_idx + tx_num
            # Value: the UTXO value as a 64-bit unsigned integer
            udb_key = b'u' + hash_x + hdb_key[-6:]
            utxo_value_packed = self.utxo_db.get(udb_key)
            if utxo_value_packed:
                # Remove both entries for this UTXO
                self.db_deletes.append(hdb_key)
                self.db_deletes.append(udb_key)
                return hash_x + tx_num_packed + utxo_value_packed

        raise ChainError(f'UTXO {hash_to_str(tx_hash)} / '
                         f'{tx_idx:,d} not found in "h" table')

    def flush_utxos(self, batch):
        """Flush the cached DB writes and UTXO set to the batch."""
        # Care is needed because the writes generated by flushing the
        # UTXO state may have keys in common with our write cache or
        # may be in the DB already.
        flush_start = time.time()
        delete_count = len(self.db_deletes) // 2
        utxo_cache_len = len(self.utxo_cache)

        # Spends
        batch_delete = batch.delete
        for key in sorted(self.db_deletes):
            batch_delete(key)
        self.db_deletes = []

        # New UTXOs
        batch_put = batch.put
        for cache_key, cache_value in self.utxo_cache.items():
            # suffix = tx_idx + tx_num
            hash_x = cache_value[:-12]
            suffix = cache_key[-2:] + cache_value[-12:-8]
            batch_put(b'h' + cache_key[:4] + suffix, hash_x)
            batch_put(b'u' + hash_x + suffix, cache_value[-8:])
        self.utxo_cache = {}

        # New undo information
        self.flush_undo_infos(batch_put, self.undo_infos)
        self.undo_infos = []

        if self.utxo_db.for_sync:
            self.logger.info(f'flushed {self.height - self.db_height:,d} '
                             f'blocks with '
                             f'{self.tx_count - self.db_tx_count:,d} txs, '
                             f'{utxo_cache_len:,d} UTXO adds, '
                             f'{delete_count:,d} spends '
                             f'in {time.time() - flush_start:.1f}s, '
                             f'committing...')

        self.utxo_flush_count = self.flush_count
        self.db_tx_count = self.tx_count
        self.db_height = self.height
        self.db_tip = self.tip
