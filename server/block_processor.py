# Copyright (c) 2016-2017, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Block prefetcher and chain processor.'''


import array
import asyncio
import logging
from struct import pack, unpack
import time
from functools import partial

from server.daemon import DaemonError
from lib.hash import hash_to_str, HASHX_LEN
from lib.util import chunks, formatted_time
import server.db


class Prefetcher(object):
    '''Prefetches blocks (in the forward direction only).'''

    def __init__(self, bp):
        self.logger = logging.getLogger(self.__class__.__name__)
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
        '''Loop forever polling for more blocks.'''
        while True:
            try:
                # Sleep a while if there is nothing to prefetch
                await self.refill_event.wait()
                if not await self._prefetch_blocks():
                    await asyncio.sleep(5)
            except DaemonError as e:
                self.logger.info('ignoring daemon error: {}'.format(e))

    def processing_blocks(self, blocks):
        '''Called by block processor when it is processing queued blocks.'''
        self.cache_size -= sum(len(block) for block in blocks)
        if self.cache_size < self.min_cache_size:
            self.refill_event.set()

    async def reset_height(self):
        '''Reset to prefetch blocks from the block processor's height.

        Used in blockchain reorganisations.  This coroutine can be
        called asynchronously to the _prefetch coroutine so we must
        synchronize with a semaphore.'''
        async with self.semaphore:
            self.fetched_height = self.bp.height
            self.refill_event.set()

        daemon_height = await self.bp.daemon.height()
        behind = daemon_height - self.bp.height
        if behind > 0:
            self.logger.info('catching up to daemon height {:,d} '
                             '({:,d} blocks behind)'
                             .format(daemon_height, behind))
        else:
            self.logger.info('caught up to daemon height {:,d}'
                             .format(daemon_height))

    async def _prefetch_blocks(self):
        '''Prefetch some blocks and put them on the queue.

        Repeats until the queue is full or caught up.
        '''
        daemon = self.bp.daemon
        daemon_height = await daemon.height(self.bp.caught_up_event.is_set())
        async with self.semaphore:
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
                    self.logger.info('new block height {:,d} hash {}'
                                     .format(first + count-1, hex_hashes[-1]))
                blocks = await daemon.raw_blocks(hex_hashes)

                assert count == len(blocks)

                # Special handling for genesis block
                if first == 0:
                    blocks[0] = self.bp.coin.genesis_block(blocks[0])
                    self.logger.info('verified genesis block with hash {}'
                                     .format(hex_hashes[0]))

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
    '''Raised on error processing blocks.'''


class BlockProcessor(server.db.DB):
    '''Process blocks and update the DB state to match.

    Employ a prefetcher to prefetch blocks in batches for processing.
    Coordinate backing up in case of chain reorganisations.
    '''

    def __init__(self, env, controller, daemon):
        super().__init__(env)

        # An incomplete compaction needs to be cancelled otherwise
        # restarting it will corrupt the history
        self.history.cancel_compaction()

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

        # UTXO cache
        self.utxo_cache = {}
        self.db_deletes = []

        self.prefetcher = Prefetcher(self)

        if self.utxo_db.for_sync:
            self.logger.info('flushing DB cache at {:,d} MB'
                             .format(self.cache_MB))

    def add_task(self, task):
        '''Add the task to our task queue.'''
        self.task_queue.put_nowait(task)

    def on_prefetched_blocks(self, blocks, first):
        '''Called by the prefetcher when it has prefetched some blocks.'''
        self.add_task(partial(self.check_and_advance_blocks, blocks, first))

    def on_prefetcher_first_caught_up(self):
        '''Called by the prefetcher when it first catches up.'''
        self.add_task(self.first_caught_up)

    async def main_loop(self):
        '''Main loop for block processing.'''
        self.controller.create_task(self.prefetcher.main_loop())
        await self.prefetcher.reset_height()

        while True:
            task = await self.task_queue.get()
            await task()

    def shutdown(self, executor):
        '''Shutdown cleanly and flush to disk.'''
        # First stut down the executor; it may be processing a block.
        # Then we can flush anything remaining to disk.
        executor.shutdown()
        if self.height != self.db_height:
            self.logger.info('flushing state to DB for a clean shutdown...')
            self.flush(True)

    async def first_caught_up(self):
        '''Called when first caught up to daemon after starting.'''
        # Flush everything with updated first_sync->False state.
        self.first_sync = False
        await self.controller.run_in_executor(self.flush, True)
        if self.utxo_db.for_sync:
            self.logger.info(f'{self.controller.VERSION} synced to '
                             f'height {self.height:,d}')
        self.open_dbs()
        self.caught_up_event.set()

    async def check_and_advance_blocks(self, raw_blocks, first):
        '''Process the list of raw blocks passed.  Detects and handles
        reorgs.
        '''
        self.prefetcher.processing_blocks(raw_blocks)
        if first != self.height + 1:
            # If we prefetched two sets of blocks and the first caused
            # a reorg this will happen when we try to process the
            # second.  It should be very rare.
            self.logger.warning('ignoring {:,d} blocks starting height {:,d}, '
                                'expected {:,d}'.format(len(raw_blocks), first,
                                                        self.height + 1))
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
                self.logger.info('processed {:,d} block{} in {:.1f}s'
                                 .format(len(blocks), s,
                                         time.time() - start))
                self.controller.mempool.on_new_block(self.touched)
            self.touched.clear()
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
        '''Force a reorg of the given number of blocks.

        Returns True if a reorg is queued, false if not caught up.
        '''
        if self.caught_up_event.is_set():
            self.add_task(partial(self.reorg_chain, count=count))
            return True
        return False

    async def reorg_chain(self, count=None):
        '''Handle a chain reorganisation.

        Count is the number of blocks to simulate a reorg, or None for
        a real reorg.'''
        if count is None:
            self.logger.info('chain reorg detected')
        else:
            self.logger.info('faking a reorg of {:,d} blocks'.format(count))
        await self.controller.run_in_executor(self.flush, True)

        hashes = await self.reorg_hashes(count)
        # Reverse and convert to hex strings.
        hashes = [hash_to_str(hash) for hash in reversed(hashes)]
        for hex_hashes in chunks(hashes, 50):
            blocks = await self.daemon.raw_blocks(hex_hashes)
            await self.controller.run_in_executor(self.backup_blocks, blocks)
        await self.prefetcher.reset_height()

    async def reorg_hashes(self, count):
        '''Return the list of hashes to back up beacuse of a reorg.

        The hashes are returned in order of increasing height.'''

        def diff_pos(hashes1, hashes2):
            '''Returns the index of the first difference in the hash lists.
            If both lists match returns their length.'''
            for n, (hash1, hash2) in enumerate(zip(hashes1, hashes2)):
                if hash1 != hash2:
                    return n
            return len(hashes)

        if count is None:
            # A real reorg
            start = self.height - 1
            count = 1
            while start > 0:
                hashes = self.fs_block_hashes(start, count)
                hex_hashes = [hash_to_str(hash) for hash in hashes]
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
        self.logger.info('chain was reorganised replacing {:,d} block{} at '
                         'heights {:,d}-{:,d}'
                         .format(count, s, start, start + count - 1))

        return self.fs_block_hashes(start, count)

    def flush_state(self, batch):
        '''Flush chain state to the batch.'''
        now = time.time()
        self.wall_time += now - self.last_flush
        self.last_flush = now
        self.last_flush_tx_count = self.tx_count
        self.write_utxo_state(batch)

    def assert_flushed(self):
        '''Asserts state is fully flushed.'''
        assert self.tx_count == self.fs_tx_count == self.db_tx_count
        assert self.height == self.fs_height == self.db_height
        assert not self.undo_infos
        assert not self.utxo_cache
        assert not self.db_deletes
        self.history.assert_flushed()

    def flush(self, flush_utxos=False):
        '''Flush out cached state.

        History is always flushed.  UTXOs are flushed if flush_utxos.'''
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
            self.logger.info('flushed to FS in {:.1f}s'
                             .format(fs_end - flush_start))

        # History next - it's fast and frees memory
        hashX_count = self.history.flush()
        if self.utxo_db.for_sync:
            self.logger.info('flushed history in {:.1f}s for {:,d} addrs'
                             .format(time.time() - fs_end, hashX_count))

        # Flush state last as it reads the wall time.
        with self.utxo_db.write_batch() as batch:
            if flush_utxos:
                self.flush_utxos(batch)
            self.flush_state(batch)

        # Update and put the wall time again - otherwise we drop the
        # time it took to commit the batch
        self.flush_state(self.utxo_db)

        self.logger.info('flush #{:,d} took {:.1f}s.  Height {:,d} txs: {:,d}'
                         .format(self.history.flush_count,
                                 self.last_flush - flush_start,
                                 self.height, self.tx_count))

        # Catch-up stats
        if self.utxo_db.for_sync:
            tx_per_sec = int(self.tx_count / self.wall_time)
            this_tx_per_sec = 1 + int(tx_diff / (self.last_flush - last_flush))
            self.logger.info('tx/sec since genesis: {:,d}, '
                             'since last flush: {:,d}'
                             .format(tx_per_sec, this_tx_per_sec))

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

            self.logger.info('sync time: {}  ETA: {}'
                             .format(formatted_time(self.wall_time),
                                     formatted_time(tx_est / this_tx_per_sec)))

    def fs_flush(self):
        '''Flush the things stored on the filesystem.'''
        assert self.fs_height + len(self.headers) == self.height
        assert self.tx_count == self.tx_counts[-1] if self.tx_counts else 0

        self.fs_update(self.fs_height, self.headers, self.tx_hashes)
        self.fs_height = self.height
        self.fs_tx_count = self.tx_count
        self.tx_hashes = []
        self.headers = []

    def backup_flush(self):
        '''Like flush() but when backing up.  All UTXOs are flushed.

        hashXs - sequence of hashXs which were touched by backing
        up.  Searched for history entries to remove after the backup
        height.
        '''
        assert self.height < self.db_height
        self.history.assert_flushed()

        flush_start = time.time()

        # Backup FS (just move the pointers back)
        self.fs_height = self.height
        self.fs_tx_count = self.tx_count
        assert not self.headers
        assert not self.tx_hashes

        # Backup history.  self.touched can include other addresses
        # which is harmless, but remove None.
        self.touched.discard(None)
        nremoves = self.history.backup(self.touched, self.tx_count)
        self.logger.info('backing up removed {:,d} history entries'
                         .format(nremoves))

        with self.utxo_db.write_batch() as batch:
            # Flush state last as it reads the wall time.
            self.flush_utxos(batch)
            self.flush_state(batch)

        self.logger.info('backup flush #{:,d} took {:.1f}s.  '
                         'Height {:,d} txs: {:,d}'
                         .format(self.history.flush_count,
                                 self.last_flush - flush_start,
                                 self.height, self.tx_count))

    def check_cache_size(self):
        '''Flush a cache if it gets too big.'''
        # Good average estimates based on traversal of subobjects and
        # requesting size from Python (see deep_getsizeof).
        one_MB = 1000*1000
        utxo_cache_size = len(self.utxo_cache) * 205
        db_deletes_size = len(self.db_deletes) * 57
        hist_cache_size = self.history.unflushed_memsize()
        # Roughly ntxs * 32 + nblocks * 42
        tx_hash_size = ((self.tx_count - self.fs_tx_count) * 32
                        + (self.height - self.fs_height) * 42)
        utxo_MB = (db_deletes_size + utxo_cache_size) // one_MB
        hist_MB = (hist_cache_size + tx_hash_size) // one_MB

        self.logger.info('our height: {:,d} daemon: {:,d} '
                         'UTXOs {:,d}MB hist {:,d}MB'
                         .format(self.height, self.daemon.cached_height(),
                                 utxo_MB, hist_MB))

        # Flush history if it takes up over 20% of cache memory.
        # Flush UTXOs once they take up 80% of cache memory.
        if utxo_MB + hist_MB >= self.cache_MB or hist_MB >= self.cache_MB // 5:
            self.flush(utxo_MB >= self.cache_MB * 4 // 5)

    def advance_blocks(self, blocks):
        '''Synchronously advance the blocks.

        It is already verified they correctly connect onto our tip.
        '''
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
            if time.time() > self.next_cache_check:
                self.check_cache_size()
                self.next_cache_check = time.time() + 30

    def advance_txs(self, txs):
        self.tx_hashes.append(b''.join(tx_hash for tx, tx_hash in txs))

        # Use local vars for speed in the loops
        undo_info = []
        tx_num = self.tx_count
        script_hashX = self.coin.hashX_from_script
        s_pack = pack
        put_utxo = self.utxo_cache.__setitem__
        spend_utxo = self.spend_utxo
        undo_info_append = undo_info.append
        update_touched = self.touched.update
        hashXs_by_tx = []
        append_hashXs = hashXs_by_tx.append

        for tx, tx_hash in txs:
            hashXs = []
            append_hashX = hashXs.append
            tx_numb = s_pack('<I', tx_num)

            # Spend the inputs
            if not tx.is_coinbase:
                for txin in tx.inputs:
                    cache_value = spend_utxo(txin.prev_hash, txin.prev_idx)
                    undo_info_append(cache_value)
                    append_hashX(cache_value[:-12])

            # Add the new UTXOs
            for idx, txout in enumerate(tx.outputs):
                # Get the hashX.  Ignore unspendable outputs
                hashX = script_hashX(txout.pk_script)
                if hashX:
                    append_hashX(hashX)
                    put_utxo(tx_hash + s_pack('<H', idx),
                             hashX + tx_numb + s_pack('<Q', txout.value))

            append_hashXs(hashXs)
            update_touched(hashXs)
            tx_num += 1

        self.history.add_unflushed(hashXs_by_tx, self.tx_count)

        self.tx_count = tx_num
        self.tx_counts.append(tx_num)

        return undo_info

    def backup_blocks(self, raw_blocks):
        '''Backup the raw blocks and flush.

        The blocks should be in order of decreasing height, starting at.
        self.height.  A flush is performed once the blocks are backed up.
        '''
        self.assert_flushed()
        assert self.height >= len(raw_blocks)

        coin = self.coin
        for raw_block in raw_blocks:
            # Check and update self.tip
            block = coin.block(raw_block, self.height)
            header_hash = coin.header_hash(block.header)
            if header_hash != self.tip:
                raise ChainError('backup block {} not tip {} at height {:,d}'
                                 .format(hash_to_str(header_hash),
                                         hash_to_str(self.tip), self.height))
            self.tip = coin.header_prevhash(block.header)
            self.backup_txs(block.transactions)
            self.height -= 1
            self.tx_counts.pop()

        self.logger.info('backed up to height {:,d}'.format(self.height))
        self.backup_flush()

    def backup_txs(self, txs):
        # Prevout values, in order down the block (coinbase first if present)
        # undo_info is in reverse block order
        undo_info = self.read_undo_info(self.height)
        if undo_info is None:
            raise ChainError('no undo information found for height {:,d}'
                             .format(self.height))
        n = len(undo_info)

        # Use local vars for speed in the loops
        s_pack = pack
        put_utxo = self.utxo_cache.__setitem__
        spend_utxo = self.spend_utxo
        script_hashX = self.coin.hashX_from_script
        touched = self.touched
        undo_entry_len = 12 + HASHX_LEN

        for tx, tx_hash in reversed(txs):
            for idx, txout in enumerate(tx.outputs):
                # Spend the TX outputs.  Be careful with unspendable
                # outputs - we didn't save those in the first place.
                hashX = script_hashX(txout.pk_script)
                if hashX:
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

    '''An in-memory UTXO cache, representing all changes to UTXO state
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

      1.  Key: b'u' + address_hashX + tx_idx + tx_num
          Value: the UTXO value as a 64-bit unsigned integer

      2.  Key: b'h' + compressed_tx_hash + tx_idx + tx_num
          Value: hashX

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
        # Value: hashX
        prefix = b'h' + tx_hash[:4] + idx_packed
        candidates = {db_key: hashX for db_key, hashX
                      in self.utxo_db.iterator(prefix=prefix)}

        for hdb_key, hashX in candidates.items():
            tx_num_packed = hdb_key[-4:]

            if len(candidates) > 1:
                tx_num, = unpack('<I', tx_num_packed)
                hash, height = self.fs_tx_hash(tx_num)
                if hash != tx_hash:
                    assert hash is not None  # Should always be found
                    continue

            # Key: b'u' + address_hashX + tx_idx + tx_num
            # Value: the UTXO value as a 64-bit unsigned integer
            udb_key = b'u' + hashX + hdb_key[-6:]
            utxo_value_packed = self.utxo_db.get(udb_key)
            if utxo_value_packed:
                # Remove both entries for this UTXO
                self.db_deletes.append(hdb_key)
                self.db_deletes.append(udb_key)
                return hashX + tx_num_packed + utxo_value_packed

        raise ChainError('UTXO {} / {:,d} not found in "h" table'
                         .format(hash_to_str(tx_hash), tx_idx))

    def flush_utxos(self, batch):
        '''Flush the cached DB writes and UTXO set to the batch.'''
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
            hashX = cache_value[:-12]
            suffix = cache_key[-2:] + cache_value[-12:-8]
            batch_put(b'h' + cache_key[:4] + suffix, hashX)
            batch_put(b'u' + hashX + suffix, cache_value[-8:])
        self.utxo_cache = {}

        # New undo information
        self.flush_undo_infos(batch_put, self.undo_infos)
        self.undo_infos = []

        if self.utxo_db.for_sync:
            self.logger.info('flushed {:,d} blocks with {:,d} txs, {:,d} UTXO '
                             'adds, {:,d} spends in {:.1f}s, committing...'
                             .format(self.height - self.db_height,
                                     self.tx_count - self.db_tx_count,
                                     utxo_cache_len, delete_count,
                                     time.time() - flush_start))

        self.utxo_flush_count = self.history.flush_count
        self.db_tx_count = self.tx_count
        self.db_height = self.height
        self.db_tip = self.tip
