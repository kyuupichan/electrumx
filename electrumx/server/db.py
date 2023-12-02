# Copyright (c) 2016-2021, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# This file is licensed under the Open BSV License version 3, see LICENCE for details.

'''Interface to the blockchain database.'''


import ast
import copy
import os
import time
from array import array
from bisect import bisect_right
from collections import namedtuple

import attr
from aiorpcx import run_in_thread, sleep

from electrumx.lib import util
from electrumx.lib.hash import hash_to_hex_str
from electrumx.lib.merkle import Merkle, MerkleCache
from electrumx.lib.util import (
    formatted_time, pack_be_uint32, pack_le_uint32,
    unpack_le_uint32, unpack_be_uint32, unpack_le_uint64,
)
from electrumx.server.storage import db_class
from electrumx.server.history import History


UTXO = namedtuple("UTXO", "tx_num tx_pos tx_hash height value")


@attr.s(slots=True)
class FlushData:
    state = attr.ib()
    headers = attr.ib()
    block_tx_hashes = attr.ib()
    # The following are flushed to the UTXO DB if undo_infos is not None
    undo_infos = attr.ib()
    adds = attr.ib()
    deletes = attr.ib()


@attr.s(slots=True)
class ChainState:
    height = attr.ib()
    tx_count = attr.ib()
    chain_size = attr.ib()
    tip = attr.ib()
    flush_count = attr.ib()   # of UTXOs
    sync_time = attr.ib()     # Cumulative
    flush_time = attr.ib()    # Time of flush
    first_sync = attr.ib()
    db_version = attr.ib()
    utxo_count = attr.ib()

    def copy(self):
        return copy.copy(self)


class DB:
    '''Simple wrapper of the backend database for querying.

    Performs no DB update, though the DB will be cleaned on opening if
    it was shutdown uncleanly.
    '''

    DB_VERSIONS = [8]

    class DBError(Exception):
        '''Raised on general DB errors generally indicating corruption.'''

    def __init__(self, env):
        self.logger = util.class_logger(__name__, self.__class__.__name__)
        self.env = env
        self.coin = env.coin

        self.logger.info(f'switching current directory to {env.db_dir}')
        os.chdir(env.db_dir)

        self.db_class = db_class(self.env.db_engine)
        self.history = History()
        self.utxo_db = None
        self.state = None
        self.last_flush_state = None

        self.fs_height = -1
        self.fs_tx_count = 0
        self.tx_counts = None

        self.logger.info(f'using {self.env.db_engine} for DB backend')

        # Header merkle cache
        self.merkle = Merkle()
        self.header_mc = MerkleCache(self.merkle, self.fs_block_hashes)

        self.headers_file = util.LogicalFile('meta/headers', 2, 16000000)
        self.tx_counts_file = util.LogicalFile('meta/txcounts', 2, 2000000)
        self.hashes_file = util.LogicalFile('meta/hashes', 4, 16000000)

    async def _read_tx_counts(self):
        if self.tx_counts is not None:
            return
        # tx_counts[N] has the cumulative number of txs at the end of
        # height N.  So tx_counts[0] is 1 - the genesis coinbase
        size = (self.state.height + 1) * 8
        tx_counts = self.tx_counts_file.read(0, size)
        assert len(tx_counts) == size
        self.tx_counts = array('Q', tx_counts)
        if self.tx_counts:
            assert self.state.tx_count == self.tx_counts[-1]
        else:
            assert self.state.tx_count == 0

    async def _open_dbs(self, for_sync, compacting):
        assert self.utxo_db is None

        # First UTXO DB
        self.utxo_db = self.db_class('utxo', for_sync)
        if self.utxo_db.is_new:
            self.logger.info('created new database')
            self.logger.info('creating metadata directory')
            os.mkdir('meta')
            with util.open_file('COIN', create=True) as f:
                f.write(f'ElectrumX databases and metadata for '
                        f'{self.coin.NAME} {self.coin.NET}'.encode())
        else:
            self.logger.info(f'opened UTXO DB (for sync: {for_sync})')
        self.read_utxo_state()

        # Then history DB
        self.state.flush_count = self.history.open_db(self.db_class, for_sync,
                                                      self.state.flush_count,
                                                      compacting)
        self.clear_excess_undo_info()

        # Read TX counts (requires meta directory)
        await self._read_tx_counts()
        return self.state

    async def open_for_compacting(self):
        return await self._open_dbs(True, True)

    async def open_for_sync(self):
        '''Open the databases to sync to the daemon.

        When syncing we want to reserve a lot of open files for the
        synchronization.  When serving clients we want the open files for
        serving network connections.
        '''
        return await self._open_dbs(True, False)

    async def open_for_serving(self):
        '''Open the databases for serving.  If they are already open they are
        closed first.
        '''
        if self.utxo_db:
            self.logger.info('closing DBs to re-open for serving')
            self.utxo_db.close()
            self.history.close_db()
            self.utxo_db = None
        return await self._open_dbs(False, False)

    # Header merkle cache

    async def populate_header_merkle_cache(self):
        self.logger.info('populating header merkle cache...')
        length = max(1, self.state.height - self.env.reorg_limit)
        start = time.monotonic()
        await self.header_mc.initialize(length)
        elapsed = time.monotonic() - start
        self.logger.info(f'header merkle cache populated in {elapsed:.1f}s')

    async def header_branch_and_root(self, length, height):
        return await self.header_mc.branch_and_root(length, height)

    # Flushing
    def assert_flushed(self, flush_data):
        '''Asserts state is fully flushed.'''
        assert flush_data.state.tx_count == self.fs_tx_count == self.state.tx_count
        assert flush_data.state.height == self.fs_height == self.state.height
        assert flush_data.state.tip == self.state.tip
        assert not flush_data.headers
        assert not flush_data.block_tx_hashes
        assert not flush_data.adds
        assert not flush_data.deletes
        assert not flush_data.undo_infos
        self.history.assert_flushed()

    def log_flush_stats(self, prefix, flush_data, elapsed):
        tx_delta = flush_data.state.tx_count - self.last_flush_state.tx_count
        size_delta = flush_data.state.chain_size - self.last_flush_state.chain_size
        utxo_count_delta = flush_data.state.utxo_count - self.last_flush_state.utxo_count

        self.logger.info(f'{prefix} #{self.history.flush_count:,d} took {elapsed:.1f}s.  '
                         f'Height {flush_data.state.height:,d} '
                         f'txs: {flush_data.state.tx_count:,d} ({tx_delta:+,d}) '
                         f'utxos: {flush_data.state.utxo_count:,d} ({utxo_count_delta:+,d}) '
                         f'size: {flush_data.state.chain_size:,d} ({size_delta:+,d})')
        return size_delta

    def flush_dbs(self, flush_data, flush_utxos, size_remaining):
        '''Flush out cached state.  History is always flushed; UTXOs are
        flushed if flush_utxos.'''
        if flush_data.state.height == self.state.height:
            self.assert_flushed(flush_data)
            return

        start_time = time.time()

        # Flush to file system
        self.flush_fs(flush_data)

        # Then history
        self.flush_history()
        flush_data.state.flush_count = self.history.flush_count

        # Flush state last as it reads the wall time.
        if flush_utxos:
            self.flush_utxo_db(flush_data)

        end_time = time.time()
        elapsed = end_time - start_time
        flush_interval = end_time - self.last_flush_state.flush_time
        flush_data.state.flush_time = end_time
        flush_data.state.sync_time += flush_interval

        # Update and flush state again so as not to drop the batch commit time
        if flush_utxos:
            self.state = flush_data.state.copy()
            self.write_utxo_state(self.utxo_db)

        size_delta = self.log_flush_stats('flush', flush_data, elapsed)

        # Catch-up stats
        if self.utxo_db.for_sync:
            size_per_sec_gen = flush_data.state.chain_size / (flush_data.state.sync_time + 0.01)
            size_per_sec_last = size_delta / (flush_interval + 0.01)
            eta = size_remaining / (size_per_sec_last + 0.01)
            self.logger.info(f'MB/sec since genesis: {size_per_sec_gen / 1_000_000:.2f}, '
                             f'since last flush: {size_per_sec_last / 1_000_000:.2f}')
            self.logger.info(f'sync time: {formatted_time(flush_data.state.sync_time)}  '
                             f'ETA: {formatted_time(eta)}')

        self.last_flush_state = flush_data.state.copy()

    def flush_fs(self, flush_data):
        '''Write headers, tx counts and block tx hashes to the filesystem.

        The first height to write is self.fs_height + 1.  The FS
        metadata is all append-only, so in a crash we just pick up
        again from the height stored in the DB.
        '''
        prior_tx_count = (self.tx_counts[self.fs_height]
                          if self.fs_height >= 0 else 0)
        assert len(flush_data.block_tx_hashes) == len(flush_data.headers)
        assert flush_data.state.height == self.fs_height + len(flush_data.headers)
        assert flush_data.state.tx_count == (self.tx_counts[-1] if self.tx_counts else 0)
        assert len(self.tx_counts) == flush_data.state.height + 1
        hashes = b''.join(flush_data.block_tx_hashes)
        flush_data.block_tx_hashes.clear()
        assert len(hashes) % 32 == 0
        assert len(hashes) // 32 == flush_data.state.tx_count - prior_tx_count

        # Write the headers, tx counts, and tx hashes
        height_start = self.fs_height + 1
        offset = height_start * 80
        self.headers_file.write(offset, b''.join(flush_data.headers))
        flush_data.headers.clear()

        offset = height_start * self.tx_counts.itemsize
        self.tx_counts_file.write(offset,
                                  self.tx_counts[height_start:].tobytes())
        offset = prior_tx_count * 32
        self.hashes_file.write(offset, hashes)

        self.fs_height = flush_data.state.height
        self.fs_tx_count = flush_data.state.tx_count

    def flush_history(self):
        self.history.flush()

    def flush_utxo_db(self, flush_data):
        '''Flush the cached DB writes and UTXO set to the batch.'''
        # Care is needed because the writes generated by flushing the
        # UTXO state may have keys in common with our write cache or
        # may be in the DB already.
        start_time = time.monotonic()
        add_count = len(flush_data.adds)
        spend_count = len(flush_data.deletes) // 2

        with self.utxo_db.write_batch() as batch:
            # Spends
            batch_delete = batch.delete
            for key in sorted(flush_data.deletes):
                batch_delete(key)
            flush_data.deletes.clear()

            # New UTXOs
            batch_put = batch.put
            for key, value in flush_data.adds.items():
                # suffix = tx_idx + tx_num
                hashX = value[:-13]
                suffix = key[-4:] + value[-13:-8]
                batch_put(b'h' + key[:4] + suffix, hashX)
                batch_put(b'u' + hashX + suffix, value[-8:])
            flush_data.adds.clear()

            # New undo information
            self.flush_undo_infos(batch_put, flush_data.undo_infos)
            flush_data.undo_infos.clear()

            if self.utxo_db.for_sync:
                block_count = flush_data.state.height - self.state.height
                tx_count = flush_data.state.tx_count - self.state.tx_count
                size = (flush_data.state.chain_size - self.state.chain_size) / 1_000_000_000
                elapsed = time.monotonic() - start_time
                self.logger.info(f'flushed {block_count:,d} blocks size {size:.1f} GB with '
                                 f'{tx_count:,d} txs, {add_count:,d} UTXO adds, '
                                 f'{spend_count:,d} spends in '
                                 f'{elapsed:.1f}s, committing...')

            self.state = flush_data.state.copy()
            self.write_utxo_state(batch)

    def flush_backup(self, flush_data, touched):
        '''Like flush_dbs() but when backing up.  All UTXOs are flushed.'''
        assert not flush_data.headers
        assert not flush_data.block_tx_hashes
        assert flush_data.state.height < self.state.height
        self.history.assert_flushed()

        start_time = time.time()

        self.backup_fs(flush_data.state.height, flush_data.state.tx_count)
        self.history.backup(touched, flush_data.state.tx_count)
        self.flush_utxo_db(flush_data)

        self.log_flush_stats('backup flush', flush_data, time.time() - start_time)

        self.last_flush_state = flush_data.state.copy()

    def backup_fs(self, height, tx_count):
        '''Back up during a reorg.  This just updates our pointers.'''
        self.fs_height = height
        self.fs_tx_count = tx_count
        # Truncate header_mc: header count is 1 more than the height.
        self.header_mc.truncate(height + 1)

    async def raw_header(self, height):
        '''Return the binary header at the given height.'''
        header, n = await self.read_headers(height, 1)
        if n != 1:
            raise IndexError(f'height {height:,d} out of range')
        return header

    async def read_headers(self, start_height, count):
        '''Requires start_height >= 0, count >= 0.  Reads as many headers as are available
        starting at start_height up to count.  This would be zero if start_height is
        beyond state.height, for example.

        Returns a (binary, n) pair where binary is the concatenated binary headers, and n
        is the count of headers returned.
        '''
        if start_height < 0 or count < 0:
            raise self.DBError(f'{count:,d} headers starting at '
                               f'{start_height:,d} not on disk')

        def read_headers():
            # Read some from disk
            disk_count = max(0, min(count, self.state.height + 1 - start_height))
            if disk_count:
                offset = start_height * 80
                size = disk_count * 80
                return self.headers_file.read(offset, size), disk_count
            return b'', 0

        return await run_in_thread(read_headers)

    def fs_tx_hash(self, tx_num):
        '''Return a pair (tx_hash, tx_height) for the given tx number.

        If the tx_height is not on disk, returns (None, tx_height).'''
        tx_height = bisect_right(self.tx_counts, tx_num)
        if tx_height > self.state.height:
            tx_hash = None
        else:
            tx_hash = self.hashes_file.read(tx_num * 32, 32)
        return tx_hash, tx_height

    def fs_tx_hashes_at_blockheight(self, block_height):
        '''Return a list of tx_hashes at given block height,
        in the same order as in the block.
        '''
        if block_height > self.state.height:
            raise self.DBError(f'block {block_height:,d} not on disk (>{self.state.height:,d})')
        assert block_height >= 0
        if block_height > 0:
            first_tx_num = self.tx_counts[block_height - 1]
        else:
            first_tx_num = 0
        num_txs_in_block = self.tx_counts[block_height] - first_tx_num
        tx_hashes = self.hashes_file.read(first_tx_num * 32, num_txs_in_block * 32)
        assert num_txs_in_block == len(tx_hashes) // 32
        return [tx_hashes[idx * 32: (idx + 1) * 32] for idx in range(num_txs_in_block)]

    async def tx_hashes_at_blockheight(self, block_height):
        return await run_in_thread(self.fs_tx_hashes_at_blockheight, block_height)

    async def fs_block_hashes(self, height, count):
        headers_concat, headers_count = await self.read_headers(height, count)
        if headers_count != count:
            raise self.DBError(f'only got {headers_count:,d} headers starting at {height:,d}, '
                               f'not {count:,d}')
        offset = 0
        hlen = 80
        headers = []
        for _ in range(count):
            headers.append(headers_concat[offset:offset + hlen])
            offset += hlen

        return [self.coin.header_hash(header) for header in headers]

    async def limited_history(self, hashX, *, limit=1000):
        '''Return an unpruned, sorted list of (tx_hash, height) tuples of
        confirmed transactions that touched the address, earliest in
        the blockchain first.  Includes both spending and receiving
        transactions.  By default returns at most 1000 entries.  Set
        limit to None to get them all.
        '''
        def read_history():
            tx_nums = list(self.history.get_txnums(hashX, limit))
            fs_tx_hash = self.fs_tx_hash
            return [fs_tx_hash(tx_num) for tx_num in tx_nums]

        while True:
            history = await run_in_thread(read_history)
            if all(hash is not None for hash, height in history):
                return history
            self.logger.warning('limited_history: tx hash not found (reorg?), retrying...')
            await sleep(0.25)

    # -- Undo information

    def min_undo_height(self, max_height):
        '''Returns a height from which we should store undo info.'''
        return max_height - self.env.reorg_limit + 1

    def undo_key(self, height):
        '''DB key for undo information at the given height.'''
        return b'U' + pack_be_uint32(height)

    def read_undo_info(self, height):
        '''Read undo information from a file for the current height.'''
        return self.utxo_db.get(self.undo_key(height))

    def flush_undo_infos(self, batch_put, undo_infos):
        '''undo_infos is a list of (undo_info, height) pairs.'''
        for undo_info, height in undo_infos:
            batch_put(self.undo_key(height), b''.join(undo_info))

    def clear_excess_undo_info(self):
        '''Clear excess undo info.  Only most recent N are kept.'''
        prefix = b'U'
        min_height = self.min_undo_height(self.state.height)
        keys = []
        for key, _hist in self.utxo_db.iterator(prefix=prefix):
            height, = unpack_be_uint32(key[-4:])
            if height >= min_height:
                break
            keys.append(key)

        if keys:
            with self.utxo_db.write_batch() as batch:
                for key in keys:
                    batch.delete(key)
            self.logger.info(f'deleted {len(keys):,d} stale undo entries')

    # -- UTXO database

    def read_utxo_state(self):
        def count_utxos():
            count = 0
            for db_key, db_value in self.utxo_db.iterator(prefix=b'u'):
                count += 1
            return count

        now = time.time()
        state = self.utxo_db.get(b'state')
        if not state:
            state = ChainState(height=-1, tx_count=0, chain_size=0, tip=bytes(32),
                               flush_count=0, sync_time=0, flush_time=now,
                               first_sync=True, db_version=max(self.DB_VERSIONS),
                               utxo_count=0)
        else:
            state = ast.literal_eval(state.decode())
            if not isinstance(state, dict):
                raise self.DBError('failed reading state from DB')
            if state['genesis'] != self.coin.GENESIS_HASH:
                raise self.DBError(f'DB genesis hash {state["genesis"]} does not match '
                                   f'coin {self.coin.GENESIS_HASH}')

            state = ChainState(
                height=state['height'],
                tx_count=state['tx_count'],
                chain_size=state.get('chain_size', 0),
                tip=state['tip'],
                flush_count=state['utxo_flush_count'],
                sync_time=state['wall_time'],
                flush_time=now,
                first_sync=state['first_sync'],
                db_version=state['db_version'],
                utxo_count=state.get('utxo_count', -1),
            )

        self.state = state
        if state.db_version not in self.DB_VERSIONS:
            raise self.DBError(f'your UTXO DB version is {state.db_version} but this '
                               f'software only handles versions {self.DB_VERSIONS}')

        if self.state.utxo_count == -1:
            self.logger.info('counting UTXOs, please wait...')
            self.state.utxo_count = count_utxos()

        self.last_flush_state = state.copy()

        # These are as we flush data to disk ahead of DB state
        self.fs_height = state.height
        self.fs_tx_count = state.tx_count

        # Log some stats
        self.logger.info(f'UTXO DB version: {state.db_version:d}')
        self.logger.info(f'coin: {self.coin.NAME}')
        self.logger.info(f'network: {self.coin.NET}')
        self.logger.info(f'height: {state.height:,d}')
        self.logger.info(f'tip: {hash_to_hex_str(state.tip)}')
        self.logger.info(f'tx count: {state.tx_count:,d}')
        self.logger.info(f'utxo count: {state.utxo_count:,d}')
        self.logger.info(f'chain size: {state.chain_size // 1_000_000_000} GB '
                         f'({state.chain_size:,d} bytes)')
        if self.utxo_db.for_sync:
            self.logger.info(f'flushing DB cache at {self.env.cache_MB:,d} MB')
        if self.state.first_sync:
            self.logger.info(f'sync time so far: {util.formatted_time(state.sync_time)}')

    def write_utxo_state(self, batch):
        '''Write (UTXO) state to the batch.'''
        state = {
            'genesis': self.coin.GENESIS_HASH,
            'height': self.state.height,
            'tx_count': self.state.tx_count,
            'chain_size': self.state.chain_size,
            'tip': self.state.tip,
            'utxo_flush_count': self.state.flush_count,
            'wall_time': self.state.sync_time,
            'first_sync': self.state.first_sync,
            'db_version': self.state.db_version,
            'utxo_count': self.state.utxo_count,
        }
        batch.put(b'state', repr(state).encode())

    def set_flush_count(self, count):
        self.state.flush_count = count
        self.write_utxo_state(self.utxo_db)

    async def all_utxos(self, hashX):
        '''Return all UTXOs for an address sorted in no particular order.'''
        def read_utxos():
            utxos = []
            utxos_append = utxos.append
            # Key: b'u' + address_hashX + tx_idx + tx_num
            # Value: the UTXO value as a 64-bit unsigned integer
            prefix = b'u' + hashX
            for db_key, db_value in self.utxo_db.iterator(prefix=prefix):
                tx_pos, = unpack_le_uint32(db_key[-9:-5])
                tx_num, = unpack_le_uint64(db_key[-5:] + bytes(3))
                value, = unpack_le_uint64(db_value)
                tx_hash, height = self.fs_tx_hash(tx_num)
                utxos_append(UTXO(tx_num, tx_pos, tx_hash, height, value))
            return utxos

        while True:
            utxos = await run_in_thread(read_utxos)
            if all(utxo.tx_hash is not None for utxo in utxos):
                return utxos
            self.logger.warning('all_utxos: tx hash not found (reorg?), retrying...')
            await sleep(0.25)

    async def lookup_utxos(self, prevouts):
        '''For each prevout, lookup it up in the DB and return a (hashX,
        value) pair or None if not found.

        Used by the mempool code.
        '''
        def lookup_hashXs():
            '''Return (hashX, suffix) pairs, or None if not found,
            for each prevout.
            '''
            def lookup_hashX(tx_hash, tx_idx):
                idx_packed = pack_le_uint32(tx_idx)

                # Key: b'h' + compressed_tx_hash + tx_idx + tx_num
                # Value: hashX
                prefix = b'h' + tx_hash[:4] + idx_packed

                # Find which entry, if any, the TX_HASH matches.
                for db_key, hashX in self.utxo_db.iterator(prefix=prefix):
                    tx_num_packed = db_key[-5:]
                    tx_num, = unpack_le_uint64(tx_num_packed + bytes(3))
                    fs_hash, _height = self.fs_tx_hash(tx_num)
                    if fs_hash == tx_hash:
                        return hashX, idx_packed + tx_num_packed
                return None, None
            return [lookup_hashX(*prevout) for prevout in prevouts]

        def lookup_utxos(hashX_pairs):
            def lookup_utxo(hashX, suffix):
                if not hashX:
                    # This can happen when the daemon is a block ahead
                    # of us and has mempool txs spending outputs from
                    # that new block
                    return None
                # Key: b'u' + address_hashX + tx_idx + tx_num
                # Value: the UTXO value as a 64-bit unsigned integer
                key = b'u' + hashX + suffix
                db_value = self.utxo_db.get(key)
                if not db_value:
                    # This can happen if the DB was updated between
                    # getting the hashXs and getting the UTXOs
                    return None
                value, = unpack_le_uint64(db_value)
                return hashX, value
            return [lookup_utxo(*hashX_pair) for hashX_pair in hashX_pairs]

        hashX_pairs = await run_in_thread(lookup_hashXs)
        return await run_in_thread(lookup_utxos, hashX_pairs)
