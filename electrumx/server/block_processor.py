# Copyright (c) 2016-2021, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Block prefetcher and chain processor.'''


import asyncio
import os
import re
import time
from asyncio import sleep
from datetime import datetime
from struct import error as struct_error

from aiorpcx import CancelledError, run_in_thread, spawn, timeout_after

import electrumx
from electrumx.lib.hash import hash_to_hex_str, HASHX_LEN
from electrumx.lib.script import is_unspendable_legacy, is_unspendable_genesis
from electrumx.lib.tx import Deserializer
from electrumx.lib.util import (
    class_logger, pack_le_uint32, pack_le_uint64, unpack_le_uint64, open_file, unpack_le_uint32,
)
from electrumx.server.db import FlushData


logger = class_logger(__name__, 'BlockProcessor')


class OnDiskBlock:

    path = 'meta/blocks'
    legacy_del_regex = re.compile('block[0-9]{1,7}$')
    block_regex = re.compile('([0-9]{1,7})-([0-9a-f]{64})$')
    chunk_size = 25_000_000
    # On-disk blocks. hex_hash->(height, size) pair
    blocks = {}
    # Map from hex hash to prefetch task
    tasks = {}
    last_time = 0

    def __init__(self, hex_hash, height, size):
        self.hex_hash = hex_hash
        self.height = height
        self.size = size
        self.block_file = None
        self.header = None

    @classmethod
    def filename(cls, hex_hash, height):
        return os.path.join(cls.path, f'{height:d}-{hex_hash}')

    def __enter__(self):
        self.block_file = open_file(self.filename(self.hex_hash, self.height))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.block_file.close()

    def _read(self, size):
        result = self.block_file.read(size)
        if not result:
            raise RuntimeError(f'truncated block file for block {self.hex_hash} '
                               f'height {self.height:,d}')
        return result

    def _read_at_pos(self, pos, size):
        self.block_file.seek(pos, os.SEEK_SET)
        result = self.block_file.read(size)
        if len(result) != size:
            raise RuntimeError(f'truncated block file for block {self.hex_hash} '
                               f'height {self.height:,d}')
        return result

    def read_header(self):
        self.header = self._read(80)

    def date_str(self):
        timestamp, = unpack_le_uint32(self.header[68:72])
        return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

    def iter_txs(self):
        # Asynchronous generator of (tx, tx_hash) pairs
        raw = self._read(self.chunk_size)
        deserializer = Deserializer(raw)
        tx_count = deserializer._read_varint()

        t = time.monotonic()
        if t - OnDiskBlock.last_time > 1:
            logger.info(f'processing block height {self.height:,d} {self.date_str()} '
                        f'{self.hex_hash} size {self.size / 1_000_000_000:.3f} GB '
                        f'tx_count: {tx_count:,d}')
        OnDiskBlock.last_time = t

        count = 0
        while True:
            read = deserializer.read_tx_and_hash
            try:
                while True:
                    cursor = deserializer.cursor
                    yield read()
                    count += 1
            except (AssertionError, IndexError, struct_error):
                pass

            if count == tx_count:
                return
            raw = raw[cursor:] + self._read(self.chunk_size)
            deserializer = Deserializer(raw)

    def _chunk_offsets(self):
        '''Iterate the transactions forwards to find their boundaries.'''
        base_offset = self.block_file.tell()
        assert base_offset == 80
        raw = self._read(self.chunk_size)
        deserializer = Deserializer(raw)
        tx_count = deserializer._read_varint()
        logger.info(f'backing up block {self.hex_hash} height {self.height:,d} '
                    f'tx_count {tx_count:,d}')
        offsets = [base_offset + deserializer.cursor]

        while True:
            read = deserializer.read_tx
            count = 0
            try:
                while True:
                    cursor = deserializer.cursor
                    read()
                    count += 1
            except (AssertionError, IndexError, struct_error):
                pass

            if count:
                offsets.append(base_offset + cursor)
                base_offset += cursor
            tx_count -= count
            if tx_count == 0:
                return offsets
            raw = raw[cursor:] + self._read(self.chunk_size)
            deserializer = Deserializer(raw)

    def iter_txs_reversed(self):
        # Iterate the block transactions in reverse order.  We need to iterate the
        # transactions forwards first to find their boundaries.
        offsets = self._chunk_offsets()
        for n in reversed(range(len(offsets) - 1)):
            start = offsets[n]
            size = offsets[n + 1] - start
            deserializer = Deserializer(self._read_at_pos(start, size))
            pairs = []
            while deserializer.cursor < size:
                pairs.append(deserializer.read_tx_and_hash())
            for item in reversed(pairs):
                yield item

    @classmethod
    async def delete_stale(cls, items, log):
        def delete(paths):
            count = total_size = 0
            for path, size in paths.items():
                try:
                    os.remove(path)
                    count += 1
                    total_size += size
                except FileNotFoundError as e:
                    logger.error(f'could not delete stale block file {path}: {e}')
            return count, total_size

        if not items:
            return
        paths = {}
        for item in items:
            if isinstance(item, os.DirEntry):
                paths[item.path] = item.stat().st_size
            else:
                height, size = cls.blocks.pop(item)
                paths[cls.filename(item, height)] = size

        count, total_size = await run_in_thread(delete, paths)
        if log:
            logger.info(f'deleted {count:,d} stale block files, total size {total_size:,d} bytes')

    @classmethod
    async def delete_blocks(cls, min_height, log):
        blocks_to_delete = [hex_hash for hex_hash, (height, size) in cls.blocks.items()
                            if height < min_height]
        await cls.delete_stale(blocks_to_delete, log)

    @classmethod
    async def scan_files(cls):
        # Remove stale block files
        def scan():
            to_delete = []
            with os.scandir(cls.path) as it:
                for dentry in it:
                    if dentry.is_file():
                        match = cls.block_regex.match(dentry.name)
                        if match:
                            to_delete.append(dentry)
            return to_delete

        def find_legacy_blocks():
            with os.scandir('meta') as it:
                return [dentry for dentry in it
                        if dentry.is_file() and cls.legacy_del_regex.match(dentry.name)]

        try:
            # This only succeeds the first time with the new code
            os.mkdir(cls.path)
            logger.info(f'created block directory {cls.path}')
            await cls.delete_stale(await run_in_thread(find_legacy_blocks), True)
        except FileExistsError:
            pass

        logger.info(f'scanning block directory {cls.path}...')
        to_delete = await run_in_thread(scan)
        await cls.delete_stale(to_delete, True)

    @classmethod
    async def prefetch_many(cls, daemon, pairs, kind):
        async def prefetch_one(hex_hash, height):
            '''Read a block in chunks to a file.  As the files may not be complete they need
            to be removed when the server starts up.'''
            try:
                filename = cls.filename(hex_hash, height)
                async with timeout_after(20):
                    size = await daemon.get_block(hex_hash, filename)
                cls.blocks[hex_hash] = (height, size)
                if kind == 'new':
                    logger.info(f'fetched new block height {height:,d} hash {hex_hash}')
                elif kind == 'reorg':
                    logger.info(f'fetched reorged block height {height:,d} hash {hex_hash}')
            finally:
                cls.tasks.pop(hex_hash)

        # Pairs is a (height, hex_hash) iterable
        for height, hex_hash in pairs:
            if hex_hash not in cls.tasks and hex_hash not in cls.blocks:
                cls.tasks[hex_hash] = await spawn(prefetch_one, hex_hash, height)

    @classmethod
    async def streamed_block(cls, hex_hash):
        # Waits for a block to come in.
        task = cls.tasks.get(hex_hash)
        if task:
            try:
                await task
            except Exception as e:
                logger.error(f'error prefetching {hex_hash}: {e}')
        item = cls.blocks.get(hex_hash)
        if not item:
            logger.error(f'block {hex_hash} missing on-disk')
            return None
        height, size = item
        return cls(hex_hash, height, size)

    @classmethod
    async def stop_prefetching(cls):
        for task in cls.tasks.values():
            task.cancel()
        logger.info('prefetcher stopped')


class ChainError(Exception):
    '''Raised on error processing blocks.'''


class BlockProcessor:
    '''Process blocks and update the DB state to match.  Prefetch blocks so they are
    immediately available when the processor is ready for a new block.  Coordinate backing
    up in case of chain reorganisations.
    '''

    polling_delay = 5

    def __init__(self, env, db, daemon, notifications):
        self.env = env
        self.db = db
        self.daemon = daemon
        self.notifications = notifications
        self.coin = env.coin

        self.caught_up = False
        self.ok = False
        self.touched = set()
        # A count >= 0 is a user-forced reorg; < 0 is a natural reorg
        self.reorg_count = None
        self.height = -1
        self.tip = None
        self.tx_count = 0
        self.force_flush_arg = None

        # Caches of unflushed items.
        self.headers = []
        self.tx_hashes = []
        self.undo_infos = []

        # UTXO cache
        self.utxo_cache = {}
        self.db_deletes = []

        # Signalled after backing up during a reorg to flush session manager caches
        self.backed_up_event = asyncio.Event()

        # When the lock is acquired, in-memory chain state is consistent with self.height.
        # This is a requirement for safe flushing.
        self.state_lock = asyncio.Lock()

    async def run_with_lock(self, coro):
        # Shielded so that cancellations from shutdown don't lose work.  Cancellation will
        # cause fetch_and_process_blocks to block on the lock in flush(), the task completes,
        # and then the data is flushed.  We also don't want user-signalled reorgs to happen
        # in the middle of processing blocks; they need to wait.
        async def run_locked():
            async with self.state_lock:
                return await coro
        return await asyncio.shield(run_locked())

    async def next_block_hashes(self, count=30):
        daemon_height = await self.daemon.height()

        # Fetch remaining block hashes to a limit
        first = self.height + 1
        n = min(daemon_height - first + 1, count * 2)
        if n:
            hex_hashes = await self.daemon.block_hex_hashes(first, n)
            kind = 'new' if self.caught_up else 'sync'
            await OnDiskBlock.prefetch_many(self.daemon, enumerate(hex_hashes, start=first), kind)
        else:
            hex_hashes = []

        # Remove stale blocks
        await OnDiskBlock.delete_blocks(first - 5, False)

        return hex_hashes[:count], daemon_height

    async def reorg_chain(self, count):
        '''Handle a chain reorganisation.

        Count is the number of blocks to simulate a reorg, or None for a real reorg.
        This is passed in as self.reorg_count may change asynchronously.
        '''
        if count < 0:
            logger.info('chain reorg detected')
        else:
            logger.info(f'faking a reorg of {count:,d} blocks')
        await self.flush(True)

        start, hex_hashes = await self._reorg_hashes(count)
        pairs = reversed(list(enumerate(hex_hashes, start=start)))
        await OnDiskBlock.prefetch_many(self.daemon, pairs, 'reorg')

        for hex_hash in reversed(hex_hashes):
            if hex_hash != hash_to_hex_str(self.tip):
                logger.error(f'block {hex_hash} is not tip; cannot back up')
                return
            block = await OnDiskBlock.streamed_block(hex_hash)
            if not block:
                break
            await self.run_with_lock(run_in_thread(self.backup_block, block))

        logger.info(f'backed up to height {self.height:,d}')
        self.backed_up_event.set()
        self.backed_up_event.clear()

    async def _reorg_hashes(self, count):
        '''Return a pair (start, hashes) of blocks to back up during a
        reorg.

        The hashes are returned in order of increasing height.  Start
        is the height of the first hash, last of the last.
        '''
        start, count = await self._calc_reorg_range(count)
        last = start + count - 1
        if count == 1:
            logger.info(f'chain was reorganised replacing 1 block at height {start:,d}')
        else:
            logger.info(f'chain was reorganised replacing {count:,d} blocks at heights '
                        f'{start:,d}-{last:,d}')

        hashes = await self.db.fs_block_hashes(start, count)
        hex_hashes = [hash_to_hex_str(block_hash) for block_hash in hashes]
        return start, hex_hashes

    async def _calc_reorg_range(self, count):
        '''Calculate the reorg range'''

        def diff_pos(hashes1, hashes2):
            '''Returns the index of the first difference in the hash lists.
            If both lists match returns their length.'''
            for n, (hash1, hash2) in enumerate(zip(hashes1, hashes2)):
                if hash1 != hash2:
                    return n
            return len(hashes)

        if count < 0:
            # A real reorg
            start = self.height - 1
            count = 1
            while start > 0:
                hashes = await self.db.fs_block_hashes(start, count)
                hex_hashes = [hash_to_hex_str(hash) for hash in hashes]
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

        return start, count

    def estimate_txs_remaining(self):
        # Try to estimate how many txs there are to go
        daemon_height = self.daemon.cached_height()
        coin = self.coin
        tail_count = daemon_height - max(self.height, coin.TX_COUNT_HEIGHT)
        # Damp the initial enthusiasm
        realism = max(2.0 - 0.9 * self.height / coin.TX_COUNT_HEIGHT, 1.0)
        return (tail_count * coin.TX_PER_BLOCK +
                max(coin.TX_COUNT - self.tx_count, 0)) * realism

    # - Flushing
    def flush_data(self):
        '''The data for a flush.'''
        return FlushData(self.height, self.tx_count, self.headers,
                         self.tx_hashes, self.undo_infos, self.utxo_cache,
                         self.db_deletes, self.tip)

    async def flush(self, flush_utxos):
        self.force_flush_arg = None
        await run_in_thread(self.db.flush_dbs, self.flush_data(), flush_utxos,
                            self.estimate_txs_remaining)

    async def check_cache_size_loop(self):
        '''Signal to flush caches if they get too big.'''
        one_MB = 1000*1000
        cache_MB = self.env.cache_MB
        log_next = False
        while True:
            # Good average estimates based on traversal of subobjects and
            # requesting size from Python (see deep_getsizeof).
            utxo_cache_size = len(self.utxo_cache) * 205
            db_deletes_size = len(self.db_deletes) * 57
            hist_cache_size = self.db.history.unflushed_memsize()
            # Roughly ntxs * 32 + nblocks * 42
            tx_hash_size = ((self.tx_count - self.db.fs_tx_count) * 32
                            + (self.height - self.db.fs_height) * 42)
            utxo_MB = (db_deletes_size + utxo_cache_size) // one_MB
            hist_MB = (hist_cache_size + tx_hash_size) // one_MB

            if not hist_MB:
                log_next = False
            elif log_next:
                logger.info(f'our height: {self.height:,d} '
                            f'daemon: {self.daemon.cached_height():,d} '
                            f'UTXOs {utxo_MB:,d}MB hist {hist_MB:,d}MB')
            else:
                log_next = True

            # Flush history if it takes up over 20% of cache memory.
            # Flush UTXOs once they take up 80% of cache memory.
            if utxo_MB + hist_MB >= cache_MB or hist_MB >= cache_MB // 5:
                self.force_flush_arg = utxo_MB >= cache_MB * 4 // 5
            await sleep(30)

    async def advance_blocks(self, hex_hashes):
        '''Process the blocks passed.  Detects and handles reorgs.'''
        for hex_hash in hex_hashes:
            # Stop if we must flush
            if self.force_flush_arg is not None or self.reorg_count is not None:
                break
            block = await OnDiskBlock.streamed_block(hex_hash)
            if not block:
                break
            await self.run_with_lock(run_in_thread(self.advance_block, block))

        # If we've not caught up we have no clients for the touched set
        if not self.caught_up:
            self.touched = set()

        if self.force_flush_arg is not None:
            await self.flush(self.force_flush_arg)

    def advance_block(self, block):
        '''Advance once block.  It is already verified they correctly connect onto our tip.'''

        is_unspendable = (is_unspendable_genesis if block.height >=
                          self.coin.GENESIS_ACTIVATION else is_unspendable_legacy)

        # Use local vars for speed in the loops
        tx_hashes = []
        undo_info = []
        tx_num = self.tx_count
        script_hashX = self.coin.hashX_from_script
        put_utxo = self.utxo_cache.__setitem__
        spend_utxo = self.spend_utxo
        undo_info_append = undo_info.append
        update_touched = self.touched.update
        hashXs_by_tx = []
        append_hashXs = hashXs_by_tx.append
        append_tx_hash = tx_hashes.append
        to_le_uint32 = pack_le_uint32
        to_le_uint64 = pack_le_uint64

        self.ok = False
        with block as block:
            block.read_header()
            if self.coin.header_prevhash(block.header) != self.tip:
                self.reorg_count = -1
                return

            for tx, tx_hash in block.iter_txs():
                hashXs = []
                append_hashX = hashXs.append
                tx_numb = to_le_uint64(tx_num)[:5]

                # Spend the inputs
                for txin in tx.inputs:
                    if txin.is_generation():
                        continue
                    cache_value = spend_utxo(txin.prev_hash, txin.prev_idx)
                    undo_info_append(cache_value)
                    append_hashX(cache_value[:-13])

                # Add the new UTXOs
                for idx, txout in enumerate(tx.outputs):
                    # Ignore unspendable outputs
                    if is_unspendable(txout.pk_script):
                        continue

                    # Get the hashX
                    hashX = script_hashX(txout.pk_script)
                    append_hashX(hashX)
                    put_utxo(tx_hash + to_le_uint32(idx),
                             hashX + tx_numb + to_le_uint64(txout.value))

                append_hashXs(hashXs)
                update_touched(hashXs)
                append_tx_hash(tx_hash)
                tx_num += 1

        self.tx_hashes.append(b''.join(tx_hashes))
        self.db.history.add_unflushed(hashXs_by_tx, self.tx_count)

        self.tx_count = tx_num
        self.db.tx_counts.append(tx_num)

        if block.height >= self.db.min_undo_height(self.daemon.cached_height()):
            self.undo_infos.append((undo_info, block.height))

        self.height = block.height
        self.headers.append(block.header)
        self.tip = self.coin.header_hash(block.header)
        self.ok = True

    def backup_block(self, block):
        '''Backup the streamed block.'''
        self.db.assert_flushed(self.flush_data())
        assert block.height > 0
        genesis_activation = self.coin.GENESIS_ACTIVATION

        is_unspendable = (is_unspendable_genesis if self.height >= genesis_activation
                          else is_unspendable_legacy)

        # Prevout values, in order down the block (coinbase first if present)
        # undo_info is in reverse block order
        undo_info = self.db.read_undo_info(block.height)
        if undo_info is None:
            raise ChainError(f'no undo information found for height {block.height:,d}')
        n = len(undo_info)

        # Use local vars for speed in the loops
        put_utxo = self.utxo_cache.__setitem__
        spend_utxo = self.spend_utxo
        touched_add = self.touched.add
        undo_entry_len = 13 + HASHX_LEN

        count = 0

        with block as block:
            block.read_header()
            for tx, tx_hash in block.iter_txs_reversed():
                for idx, txout in enumerate(tx.outputs):
                    # Spend the TX outputs.  Be careful with unspendable
                    # outputs - we didn't save those in the first place.
                    if is_unspendable(txout.pk_script):
                        continue

                    cache_value = spend_utxo(tx_hash, idx)
                    touched_add(cache_value[:-13])

                # Restore the inputs
                for txin in reversed(tx.inputs):
                    if txin.is_generation():
                        continue
                    n -= undo_entry_len
                    undo_item = undo_info[n:n + undo_entry_len]
                    put_utxo(txin.prev_hash + pack_le_uint32(txin.prev_idx), undo_item)
                    touched_add(undo_item[:-13])
                count += 1

        assert n == 0
        self.tx_count -= count
        self.tip = self.coin.header_prevhash(block.header)
        self.height -= 1
        self.db.tx_counts.pop()

        # self.touched can include other addresses which is harmless, but remove None.
        self.touched.discard(None)
        self.db.flush_backup(self.flush_data(), self.touched)

    '''An in-memory UTXO cache, representing all changes to UTXO state
    since the last DB flush.

    We want to store millions of these in memory for optimal
    performance during initial sync, because then it is possible to
    spend UTXOs without ever going to the database (other than as an
    entry in the address history, and there is only one such entry per
    TX not per UTXO).  So store them in a Python dictionary with
    binary keys and values.

      Key:    TX_HASH + TX_IDX           (32 + 4 = 36 bytes)
      Value:  HASHX + TX_NUM + VALUE     (11 + 5 + 8 = 24 bytes)

    That's 60 bytes of raw data in-memory.  Python dictionary overhead
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
        idx_packed = pack_le_uint32(tx_idx)
        cache_value = self.utxo_cache.pop(tx_hash + idx_packed, None)
        if cache_value:
            return cache_value

        # Spend it from the DB.

        # Key: b'h' + compressed_tx_hash + tx_idx + tx_num
        # Value: hashX
        prefix = b'h' + tx_hash[:4] + idx_packed
        candidates = {db_key: hashX for db_key, hashX
                      in self.db.utxo_db.iterator(prefix=prefix)}

        for hdb_key, hashX in candidates.items():
            tx_num_packed = hdb_key[-5:]

            if len(candidates) > 1:
                tx_num, = unpack_le_uint64(tx_num_packed + bytes(3))
                fs_hash, _height = self.db.fs_tx_hash(tx_num)
                if fs_hash != tx_hash:
                    assert fs_hash is not None  # Should always be found
                    continue

            # Key: b'u' + address_hashX + tx_idx + tx_num
            # Value: the UTXO value as a 64-bit unsigned integer
            udb_key = b'u' + hashX + hdb_key[-9:]
            utxo_value_packed = self.db.utxo_db.get(udb_key)
            if utxo_value_packed:
                # Remove both entries for this UTXO
                self.db_deletes.append(hdb_key)
                self.db_deletes.append(udb_key)
                return hashX + tx_num_packed + utxo_value_packed

        raise ChainError(f'UTXO {hash_to_hex_str(tx_hash)} / {tx_idx:,d} not found in "h" table')

    async def on_caught_up(self):
        is_first_sync = self.db.first_sync
        self.db.first_sync = False
        await self.flush(True)
        if self.caught_up:
            # Flush everything before notifying as client queries are performed on the DB
            await self.notifications.on_block(self.touched, self.height)
            self.touched = set()
        else:
            self.caught_up = True
            if is_first_sync:
                logger.info(f'{electrumx.version} synced to height {self.height:,d}')
            # Reopen for serving
            await self.db.open_for_serving()

    async def _first_open_dbs(self):
        await self.db.open_for_sync()
        self.height = self.db.db_height
        self.tip = self.db.db_tip
        self.tx_count = self.db.db_tx_count

    # --- External API

    async def fetch_and_process_blocks(self, caught_up_event):
        '''Fetch, process and index blocks from the daemon.

        Sets caught_up_event when first caught up.  Flushes to disk
        and shuts down cleanly if cancelled.

        This is mainly because if, during initial sync ElectrumX is
        asked to shut down when a large number of blocks have been
        processed but not written to disk, it should write those to
        disk before exiting, as otherwise a significant amount of work
        could be lost.
        '''
        await self._first_open_dbs()
        await OnDiskBlock.scan_files()

        try:
            show_summary = True
            while True:
                hex_hashes, daemon_height = await self.next_block_hashes()
                if show_summary:
                    show_summary = False
                    behind = daemon_height - self.height
                    if behind > 0:
                        logger.info(f'catching up to daemon height {daemon_height:,d} '
                                    f'({behind:,d} blocks behind)')
                    else:
                        logger.info(f'caught up to daemon height {daemon_height:,d}')

                if hex_hashes:
                    await self.advance_blocks(hex_hashes)
                else:
                    await self.on_caught_up()
                    caught_up_event.set()
                    await sleep(self.polling_delay)

                if self.reorg_count is not None:
                    await self.reorg_chain(self.reorg_count)
                    self.reorg_count = None
                    show_summary = True

        # Don't flush for arbitrary exceptions as they might be a cause or consequence of
        # corrupted data
        except CancelledError:
            await OnDiskBlock.stop_prefetching()
            await self.run_with_lock(self.flush_if_safe())

    async def flush_if_safe(self):
        if self.ok:
            logger.info('flushing to DB for a clean shutdown...')
            await self.flush(True)
            logger.info('flushed cleanly')
        else:
            logger.warning('not flushing to DB as data in memory is incomplete')

    def force_chain_reorg(self, count):
        '''Force a reorg of the given number of blocks.  Returns True if a reorg is queued.
        During initial sync we don't store undo information so cannot fake a reorg until
        caught up.
        '''
        if self.caught_up:
            self.reorg_count = count
            return True
        return False
