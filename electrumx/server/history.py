# Copyright (c) 2016-2018, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''History by script hash (address).'''

import array
import ast
import bisect
import time
from collections import defaultdict
from functools import partial

import electrumx.lib.util as util
from electrumx.lib.util import (
    pack_be_uint16, pack_le_uint64, unpack_be_uint16_from, unpack_le_uint64,
)
from electrumx.lib.hash import hash_to_hex_str, HASHX_LEN


class History(object):

    DB_VERSIONS = [0, 1]

    def __init__(self):
        self.logger = util.class_logger(__name__, self.__class__.__name__)
        # For history compaction
        self.max_hist_row_entries = 12500
        self.unflushed = defaultdict(bytearray)
        self.unflushed_count = 0
        self.flush_count = 0
        self.comp_flush_count = -1
        self.comp_cursor = -1
        self.db_version = max(self.DB_VERSIONS)
        self.upgrade_cursor = -1
        self.db = None

    def open_db(self, db_class, for_sync, utxo_flush_count, compacting):
        self.db = db_class('hist', for_sync)
        self.read_state()
        self.clear_excess(utxo_flush_count)
        # An incomplete compaction needs to be cancelled otherwise
        # restarting it will corrupt the history
        if not compacting:
            self._cancel_compaction()
        return self.flush_count

    def close_db(self):
        if self.db:
            self.db.close()
            self.db = None

    def read_state(self):
        state = self.db.get(b'state\0\0')
        if state:
            state = ast.literal_eval(state.decode())
            if not isinstance(state, dict):
                raise RuntimeError('failed reading state from history DB')
            self.flush_count = state['flush_count']
            self.comp_flush_count = state.get('comp_flush_count', -1)
            self.comp_cursor = state.get('comp_cursor', -1)
            self.db_version = state.get('db_version', 0)
            self.upgrade_cursor = state.get('upgrade_cursor', -1)
        else:
            self.flush_count = 0
            self.comp_flush_count = -1
            self.comp_cursor = -1
            self.db_version = max(self.DB_VERSIONS)
            self.upgrade_cursor = -1

        if self.db_version not in self.DB_VERSIONS:
            msg = (f'your history DB version is {self.db_version} but '
                   f'this software only handles DB versions {self.DB_VERSIONS}')
            self.logger.error(msg)
            raise RuntimeError(msg)
        if self.db_version != max(self.DB_VERSIONS):
            self.upgrade_db()
        self.logger.info(f'history DB version: {self.db_version}')
        self.logger.info(f'flush count: {self.flush_count:,d}')

    def clear_excess(self, utxo_flush_count):
        # < might happen at end of compaction as both DBs cannot be
        # updated atomically
        if self.flush_count <= utxo_flush_count:
            return

        self.logger.info('DB shut down uncleanly.  Scanning for '
                         'excess history flushes...')

        keys = []
        for key, _hist in self.db.iterator(prefix=b''):
            flush_id, = unpack_be_uint16_from(key[-2:])
            if flush_id > utxo_flush_count:
                keys.append(key)

        self.logger.info(f'deleting {len(keys):,d} history entries')

        self.flush_count = utxo_flush_count
        with self.db.write_batch() as batch:
            for key in keys:
                batch.delete(key)
            self.write_state(batch)

        self.logger.info('deleted excess history entries')

    def write_state(self, batch):
        '''Write state to the history DB.'''
        state = {
            'flush_count': self.flush_count,
            'comp_flush_count': self.comp_flush_count,
            'comp_cursor': self.comp_cursor,
            'db_version': self.db_version,
            'upgrade_cursor': self.upgrade_cursor,
        }
        # History entries are not prefixed; the suffix \0\0 ensures we
        # look similar to other entries and aren't interfered with
        batch.put(b'state\0\0', repr(state).encode())

    def add_unflushed(self, hashXs_by_tx, first_tx_num):
        unflushed = self.unflushed
        count = 0
        for tx_num, hashXs in enumerate(hashXs_by_tx, start=first_tx_num):
            tx_numb = pack_le_uint64(tx_num)[:5]
            hashXs = set(hashXs)
            for hashX in hashXs:
                unflushed[hashX].extend(tx_numb)
            count += len(hashXs)
        self.unflushed_count += count

    def unflushed_memsize(self):
        return len(self.unflushed) * 180 + self.unflushed_count * 5

    def assert_flushed(self):
        assert not self.unflushed

    def flush(self):
        start_time = time.monotonic()
        self.flush_count += 1
        flush_id = pack_be_uint16(self.flush_count)
        unflushed = self.unflushed

        with self.db.write_batch() as batch:
            for hashX in sorted(unflushed):
                key = hashX + flush_id
                batch.put(key, bytes(unflushed[hashX]))
            self.write_state(batch)

        count = len(unflushed)
        unflushed.clear()
        self.unflushed_count = 0

        if self.db.for_sync:
            elapsed = time.monotonic() - start_time
            self.logger.info(f'flushed history in {elapsed:.1f}s '
                             f'for {count:,d} addrs')

    def backup(self, hashXs, tx_count):
        # Not certain this is needed, but it doesn't hurt
        self.flush_count += 1
        nremoves = 0
        bisect_left = bisect.bisect_left
        chunks = util.chunks

        with self.db.write_batch() as batch:
            for hashX in sorted(hashXs):
                deletes = []
                puts = {}
                for key, hist in self.db.iterator(prefix=hashX, reverse=True):
                    a = array.array('Q')
                    a.frombytes(b''.join(item + bytes(3) for item in chunks(hist, 5)))
                    # Remove all history entries >= tx_count
                    idx = bisect_left(a, tx_count)
                    nremoves += len(a) - idx
                    if idx > 0:
                        puts[key] = hist[:5 * idx]
                        break
                    deletes.append(key)

                for key in deletes:
                    batch.delete(key)
                for key, value in puts.items():
                    batch.put(key, value)
            self.write_state(batch)

        self.logger.info(f'backing up removed {nremoves:,d} history entries')

    def get_txnums(self, hashX, limit=1000):
        '''Generator that returns an unpruned, sorted list of tx_nums in the
        history of a hashX.  Includes both spending and receiving
        transactions.  By default yields at most 1000 entries.  Set
        limit to None to get them all.  '''
        limit = util.resolve_limit(limit)
        chunks = util.chunks
        for _key, hist in self.db.iterator(prefix=hashX):
            for tx_numb in chunks(hist, 5):
                if limit == 0:
                    return
                tx_num, = unpack_le_uint64(tx_numb + bytes(3))
                yield tx_num
                limit -= 1

    #
    # History compaction
    #

    # comp_cursor is a cursor into compaction progress.
    # -1: no compaction in progress
    # 0-65535: Compaction in progress; all prefixes < comp_cursor have
    #     been compacted, and later ones have not.
    # 65536: compaction complete in-memory but not flushed
    #
    # comp_flush_count applies during compaction, and is a flush count
    #     for history with prefix < comp_cursor.  flush_count applies
    #     to still uncompacted history.  It is -1 when no compaction is
    #     taking place.  Key suffixes up to and including comp_flush_count
    #     are used, so a parallel history flush must first increment this
    #
    # When compaction is complete and the final flush takes place,
    # flush_count is reset to comp_flush_count, and comp_flush_count to -1

    def _flush_compaction(self, cursor, write_items, keys_to_delete):
        '''Flush a single compaction pass as a batch.'''
        # Update compaction state
        if cursor == 65536:
            self.flush_count = self.comp_flush_count
            self.comp_cursor = -1
            self.comp_flush_count = -1
        else:
            self.comp_cursor = cursor

        # History DB.  Flush compacted history and updated state
        with self.db.write_batch() as batch:
            # Important: delete first!  The keyspace may overlap.
            for key in keys_to_delete:
                batch.delete(key)
            for key, value in write_items:
                batch.put(key, value)
            self.write_state(batch)

    def _compact_hashX(self, hashX, hist_map, hist_list,
                       write_items, keys_to_delete):
        '''Compres history for a hashX.  hist_list is an ordered list of
        the histories to be compressed.'''
        # History entries (tx numbers) are 4 bytes each.  Distribute
        # over rows of up to 50KB in size.  A fixed row size means
        # future compactions will not need to update the first N - 1
        # rows.
        max_row_size = self.max_hist_row_entries * 5
        full_hist = b''.join(hist_list)
        nrows = (len(full_hist) + max_row_size - 1) // max_row_size
        if nrows > 4:
            self.logger.info('hashX {} is large: {:,d} entries across '
                             '{:,d} rows'
                             .format(hash_to_hex_str(hashX),
                                     len(full_hist) // 5, nrows))

        # Find what history needs to be written, and what keys need to
        # be deleted.  Start by assuming all keys are to be deleted,
        # and then remove those that are the same on-disk as when
        # compacted.
        write_size = 0
        keys_to_delete.update(hist_map)
        for n, chunk in enumerate(util.chunks(full_hist, max_row_size)):
            key = hashX + pack_be_uint16(n)
            if hist_map.get(key) == chunk:
                keys_to_delete.remove(key)
            else:
                write_items.append((key, chunk))
                write_size += len(chunk)

        assert n + 1 == nrows
        self.comp_flush_count = max(self.comp_flush_count, n)

        return write_size

    def _compact_prefix(self, prefix, write_items, keys_to_delete):
        '''Compact all history entries for hashXs beginning with the
        given prefix.  Update keys_to_delete and write.'''
        prior_hashX = None
        hist_map = {}
        hist_list = []

        key_len = HASHX_LEN + 2
        write_size = 0
        for key, hist in self.db.iterator(prefix=prefix):
            # Ignore non-history entries
            if len(key) != key_len:
                continue
            hashX = key[:-2]
            if hashX != prior_hashX and prior_hashX:
                write_size += self._compact_hashX(prior_hashX, hist_map,
                                                  hist_list, write_items,
                                                  keys_to_delete)
                hist_map.clear()
                hist_list.clear()
            prior_hashX = hashX
            hist_map[key] = hist
            hist_list.append(hist)

        if prior_hashX:
            write_size += self._compact_hashX(prior_hashX, hist_map, hist_list,
                                              write_items, keys_to_delete)
        return write_size

    def _compact_history(self, limit):
        '''Inner loop of history compaction.  Loops until limit bytes have
        been processed.
        '''
        keys_to_delete = set()
        write_items = []   # A list of (key, value) pairs
        write_size = 0

        # Loop over 2-byte prefixes
        cursor = self.comp_cursor
        while write_size < limit and cursor < 65536:
            prefix = pack_be_uint16(cursor)
            write_size += self._compact_prefix(prefix, write_items,
                                               keys_to_delete)
            cursor += 1

        max_rows = self.comp_flush_count + 1
        self._flush_compaction(cursor, write_items, keys_to_delete)

        self.logger.info('history compaction: wrote {:,d} rows ({:.1f} MB), '
                         'removed {:,d} rows, largest: {:,d}, {:.1f}% complete'
                         .format(len(write_items), write_size / 1000000,
                                 len(keys_to_delete), max_rows,
                                 100 * cursor / 65536))
        return write_size

    def _cancel_compaction(self):
        if self.comp_cursor != -1:
            self.logger.warning('cancelling in-progress history compaction')
            self.comp_flush_count = -1
            self.comp_cursor = -1

    #
    # DB upgrade
    #

    def upgrade_db(self):
        self.logger.info(f'history DB version: {self.db_version}')
        self.logger.info('Upgrading your history DB; this can take some time...')

        def upgrade_cursor(cursor):
            count = 0
            prefix = pack_be_uint16(cursor)
            key_len = HASHX_LEN + 2
            chunks = util.chunks
            with self.db.write_batch() as batch:
                batch_put = batch.put
                for key, hist in self.db.iterator(prefix=prefix):
                    # Ignore non-history entries
                    if len(key) != key_len:
                        continue
                    count += 1
                    hist = b''.join(item + b'\0' for item in chunks(hist, 4))
                    batch_put(key, hist)
                self.upgrade_cursor = cursor
                self.write_state(batch)
            return count

        last = time.monotonic()
        count = 0

        for cursor in range(self.upgrade_cursor + 1, 65536):
            count += upgrade_cursor(cursor)
            now = time.monotonic()
            if now > last + 10:
                last = now
                self.logger.info(f'DB 3 of 3: {count:,d} entries updated, '
                                 f'{cursor * 100 / 65536:.1f}% complete')

        self.db_version = max(self.DB_VERSIONS)
        self.upgrade_cursor = -1
        with self.db.write_batch() as batch:
            self.write_state(batch)
        self.logger.info('DB 3 of 3 upgraded successfully')
