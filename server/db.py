# Copyright (c) 2016, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Interface to the blockchain database.'''


import array
import ast
import os
from struct import pack, unpack
from bisect import bisect_left, bisect_right
from collections import namedtuple

import lib.util as util
from lib.hash import hash_to_str
from server.storage import db_class
from server.version import VERSION


UTXO = namedtuple("UTXO", "tx_num tx_pos tx_hash height value")


class DB(util.LoggedClass):
    '''Simple wrapper of the backend database for querying.

    Performs no DB update, though the DB will be cleaned on opening if
    it was shutdown uncleanly.
    '''

    DB_VERSIONS = [5]

    class MissingUTXOError(Exception):
        '''Raised if a mempool tx input UTXO couldn't be found.'''

    class DBError(Exception):
        '''Raised on general DB errors generally indicating corruption.'''

    def __init__(self, env):
        super().__init__()
        self.env = env
        self.coin = env.coin

        # Setup block header size handlers
        if self.coin.STATIC_BLOCK_HEADERS:
            self.header_offset = self.coin.static_header_offset
            self.header_len = self.coin.static_header_len
        else:
            self.header_offset = self.dynamic_header_offset
            self.header_len = self.dynamic_header_len

        self.logger.info('switching current directory to {}'
                         .format(env.db_dir))
        os.chdir(env.db_dir)

        self.db_class = db_class(self.env.db_engine)
        self.logger.info('using {} for DB backend'.format(self.env.db_engine))

        self.utxo_db = None
        self.open_dbs()
        self.clean_db()

        self.logger.info('reorg limit is {:,d} blocks'
                         .format(self.env.reorg_limit))

        self.headers_file = util.LogicalFile('meta/headers', 2, 16000000)
        self.tx_counts_file = util.LogicalFile('meta/txcounts', 2, 2000000)
        self.hashes_file = util.LogicalFile('meta/hashes', 4, 16000000)
        if not self.coin.STATIC_BLOCK_HEADERS:
            self.headers_offsets_file = util.LogicalFile(
                'meta/headers_offsets', 2, 16000000)
            # Write the offset of the genesis block
            if self.headers_offsets_file.read(0, 8) != b'\x00' * 8:
                self.headers_offsets_file.write(0, b'\x00' * 8)

        # tx_counts[N] has the cumulative number of txs at the end of
        # height N.  So tx_counts[0] is 1 - the genesis coinbase
        size = (self.db_height + 1) * 4
        tx_counts = self.tx_counts_file.read(0, size)
        assert len(tx_counts) == size
        self.tx_counts = array.array('I', tx_counts)
        if self.tx_counts:
            assert self.db_tx_count == self.tx_counts[-1]
        else:
            assert self.db_tx_count == 0

    def open_dbs(self):
        '''Open the databases.  If already open they are closed and re-opened.

        When syncing we want to reserve a lot of open files for the
        synchtonization.  When serving clients we want the open files for
        serving network connections.
        '''
        def log_reason(message, is_for_sync):
            reason = 'sync' if is_for_sync else 'serving'
            self.logger.info('{} for {}'.format(message, reason))

        # Assume we're serving until we find out otherwise
        for for_sync in [False, True]:
            if self.utxo_db:
                if self.utxo_db.for_sync == for_sync:
                    return
                log_reason('closing DB to re-open', for_sync)
                self.utxo_db.close()
                self.hist_db.close()

            # Open DB and metadata files.  Record some of its state.
            self.utxo_db = self.db_class('utxo', for_sync)
            self.hist_db = self.db_class('hist', for_sync)
            if self.utxo_db.is_new:
                self.logger.info('created new database')
                self.logger.info('creating metadata directory')
                os.mkdir('meta')
                with util.open_file('COIN', create=True) as f:
                    f.write('ElectrumX databases and metadata for {} {}'
                            .format(self.coin.NAME, self.coin.NET).encode())
            else:
                log_reason('opened DB', self.utxo_db.for_sync)

            self.read_utxo_state()
            if self.first_sync == self.utxo_db.for_sync:
                break

        self.read_history_state()

        self.logger.info('software version: {}'.format(VERSION))
        self.logger.info('DB version: {:d}'.format(self.db_version))
        self.logger.info('coin: {}'.format(self.coin.NAME))
        self.logger.info('network: {}'.format(self.coin.NET))
        self.logger.info('height: {:,d}'.format(self.db_height))
        self.logger.info('tip: {}'.format(hash_to_str(self.db_tip)))
        self.logger.info('tx count: {:,d}'.format(self.db_tx_count))
        if self.first_sync:
            self.logger.info('sync time so far: {}'
                             .format(util.formatted_time(self.wall_time)))

    def read_utxo_state(self):
        state = self.utxo_db.get(b'state')
        if not state:
            self.db_height = -1
            self.db_tx_count = 0
            self.db_tip = b'\0' * 32
            self.db_version = max(self.DB_VERSIONS)
            self.utxo_flush_count = 0
            self.wall_time = 0
            self.first_sync = True
        else:
            state = ast.literal_eval(state.decode())
            if not isinstance(state, dict):
                raise self.DBError('failed reading state from DB')
            self.db_version = state['db_version']
            if self.db_version not in self.DB_VERSIONS:
                raise self.DBError('your DB version is {} but this software '
                                   'only handles versions {}'
                                   .format(self.db_version, self.DB_VERSIONS))
            # backwards compat
            genesis_hash = state['genesis']
            if isinstance(genesis_hash, bytes):
                genesis_hash = genesis_hash.decode()
            if genesis_hash != self.coin.GENESIS_HASH:
                raise self.DBError('DB genesis hash {} does not match coin {}'
                                   .format(state['genesis_hash'],
                                           self.coin.GENESIS_HASH))
            self.db_height = state['height']
            self.db_tx_count = state['tx_count']
            self.db_tip = state['tip']
            self.utxo_flush_count = state['utxo_flush_count']
            self.wall_time = state['wall_time']
            self.first_sync = state['first_sync']

    def write_state(self, batch):
        '''Write (UTXO) state to the batch.'''
        state = {
            'genesis': self.coin.GENESIS_HASH,
            'height': self.db_height,
            'tx_count': self.db_tx_count,
            'tip': self.db_tip,
            'utxo_flush_count': self.utxo_flush_count,
            'wall_time': self.wall_time,
            'first_sync': self.first_sync,
            'db_version': self.db_version,
        }
        batch.put(b'state', repr(state).encode())

    def clean_db(self):
        '''Clean out stale DB items.

        Stale DB items are excess history flushed since the most
        recent UTXO flush (only happens on unclean shutdown), and aged
        undo information.
        '''
        if self.flush_count < self.utxo_flush_count:
            raise self.DBError('DB corrupt: flush_count < utxo_flush_count')
        if self.flush_count > self.utxo_flush_count:
            self.clear_excess_history(self.utxo_flush_count)
        self.clear_excess_undo_info()

    def fs_update_header_offsets(self, offset_start, height_start, headers):
        if self.coin.STATIC_BLOCK_HEADERS:
            return
        offset = offset_start
        offsets = []
        for h in headers:
            offset += len(h)
            offsets.append(pack("<Q", offset))
        # For each header we get the offset of the next header, hence we
        # start writing from the next height
        pos = (height_start + 1) * 8
        self.headers_offsets_file.write(pos, b''.join(offsets))

    def dynamic_header_offset(self, height):
        assert not self.coin.STATIC_BLOCK_HEADERS
        offset, = unpack('<Q', self.headers_offsets_file.read(height * 8, 8))
        return offset

    def dynamic_header_len(self, height):
        return self.dynamic_header_offset(height + 1)\
               - self.dynamic_header_offset(height)

    def fs_update(self, fs_height, headers, block_tx_hashes):
        '''Write headers, the tx_count array and block tx hashes to disk.

        Their first height is fs_height.  No recorded DB state is
        updated.  These arrays are all append only, so in a crash we
        just pick up again from the DB height.
        '''
        blocks_done = len(headers)
        height_start = fs_height + 1
        new_height = fs_height + blocks_done
        prior_tx_count = (self.tx_counts[fs_height] if fs_height >= 0 else 0)
        cur_tx_count = self.tx_counts[-1] if self.tx_counts else 0
        txs_done = cur_tx_count - prior_tx_count

        assert len(block_tx_hashes) == blocks_done
        assert len(self.tx_counts) == new_height + 1
        hashes = b''.join(block_tx_hashes)
        assert len(hashes) % 32 == 0
        assert len(hashes) // 32 == txs_done

        # Write the headers, tx counts, and tx hashes
        offset = self.header_offset(height_start)
        self.headers_file.write(offset, b''.join(headers))
        self.fs_update_header_offsets(offset, height_start, headers)
        offset = height_start * self.tx_counts.itemsize
        self.tx_counts_file.write(offset,
                                  self.tx_counts[height_start:].tobytes())
        offset = prior_tx_count * 32
        self.hashes_file.write(offset, hashes)

    def read_headers(self, start, count):
        '''Requires count >= 0.'''
        # Read some from disk
        disk_count = min(count, self.db_height + 1 - start)
        if start < 0 or count < 0 or disk_count != count:
            raise self.DBError('{:,d} headers starting at {:,d} not on disk'
                               .format(count, start))
        if disk_count:
            offset = self.header_offset(start)
            size = self.header_offset(start + disk_count) - offset
            return self.headers_file.read(offset, size)
        return b''

    def fs_tx_hash(self, tx_num):
        '''Return a par (tx_hash, tx_height) for the given tx number.

        If the tx_height is not on disk, returns (None, tx_height).'''
        tx_height = bisect_right(self.tx_counts, tx_num)
        if tx_height > self.db_height:
            tx_hash = None
        else:
            tx_hash = self.hashes_file.read(tx_num * 32, 32)
        return tx_hash, tx_height

    def fs_block_hashes(self, height, count):
        headers_concat = self.read_headers(height, count)
        offset = 0
        headers = []
        for n in range(count):
            hlen = self.header_len(height + n)
            headers.append(headers_concat[offset:offset + hlen])
            offset += hlen

        return [self.coin.header_hash(header) for header in headers]

    @staticmethod
    def _resolve_limit(limit):
        if limit is None:
            return -1
        assert isinstance(limit, int) and limit >= 0
        return limit

    def get_balance(self, hashX):
        '''Returns the confirmed balance of an address.'''
        return sum(utxo.value for utxo in self.get_utxos(hashX, limit=None))

    def get_utxos(self, hashX, limit=1000):
        '''Generator that yields all UTXOs for an address sorted in no
        particular order.  By default yields at most 1000 entries.
        Set limit to None to get them all.
        '''
        limit = self._resolve_limit(limit)
        s_unpack = unpack
        # Key: b'u' + address_hashX + tx_idx + tx_num
        # Value: the UTXO value as a 64-bit unsigned integer
        prefix = b'u' + hashX
        for db_key, db_value in self.utxo_db.iterator(prefix=prefix):
            if limit == 0:
                return
            limit -= 1
            tx_pos, tx_num = s_unpack('<HI', db_key[-6:])
            value, = unpack('<Q', db_value)
            tx_hash, height = self.fs_tx_hash(tx_num)
            yield UTXO(tx_num, tx_pos, tx_hash, height, value)

    def db_hashX(self, tx_hash, idx_packed):
        '''Return (hashX, tx_num_packed) for the given TXO.

        Both are None if not found.'''
        # Key: b'h' + compressed_tx_hash + tx_idx + tx_num
        # Value: hashX
        prefix = b'h' + tx_hash[:4] + idx_packed

        # Find which entry, if any, the TX_HASH matches.
        for db_key, hashX in self.utxo_db.iterator(prefix=prefix):
            tx_num_packed = db_key[-4:]
            tx_num, = unpack('<I', tx_num_packed)
            hash, height = self.fs_tx_hash(tx_num)
            if hash == tx_hash:
                return hashX, tx_num_packed

        return None, None

    def db_utxo_lookup(self, tx_hash, tx_idx):
        '''Given a prevout return a (hashX, value) pair.

        Raises MissingUTXOError if the UTXO is not found.  Used by the
        mempool code.
        '''
        idx_packed = pack('<H', tx_idx)
        hashX, tx_num_packed = self.db_hashX(tx_hash, idx_packed)
        if not hashX:
            # This can happen when the daemon is a block ahead of us
            # and has mempool txs spending outputs from that new block
            raise self.MissingUTXOError

        # Key: b'u' + address_hashX + tx_idx + tx_num
        # Value: the UTXO value as a 64-bit unsigned integer
        key = b'u' + hashX + idx_packed + tx_num_packed
        db_value = self.utxo_db.get(key)
        if not db_value:
            raise self.DBError('UTXO {} / {:,d} in one table only'
                               .format(hash_to_str(tx_hash), tx_idx))
        value, = unpack('<Q', db_value)
        return hashX, value

    # -- Undo information

    def min_undo_height(self, max_height):
        '''Returns a height from which we should store undo info.'''
        return max_height - self.env.reorg_limit + 1

    def undo_key(self, height):
        '''DB key for undo information at the given height.'''
        return b'U' + pack('>I', height)

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
        min_height = self.min_undo_height(self.db_height)
        keys = []
        for key, hist in self.utxo_db.iterator(prefix=prefix):
            height, = unpack('>I', key[-4:])
            if height >= min_height:
                break
            keys.append(key)

        if keys:
            with self.utxo_db.write_batch() as batch:
                for key in keys:
                    batch.delete(key)
            self.logger.info('deleted {:,d} stale undo entries'
                             .format(len(keys)))

    # -- History database

    def clear_excess_history(self, flush_count):
        self.logger.info('DB shut down uncleanly.  Scanning for '
                         'excess history flushes...')

        keys = []
        for key, hist in self.hist_db.iterator(prefix=b''):
            flush_id, = unpack('>H', key[-2:])
            if flush_id > flush_count:
                keys.append(key)

        self.logger.info('deleting {:,d} history entries'.format(len(keys)))

        self.flush_count = flush_count
        with self.hist_db.write_batch() as batch:
            for key in keys:
                batch.delete(key)
            self.write_history_state(batch)

        self.logger.info('deleted excess history entries')

    def write_history_state(self, batch):
        state = {'flush_count': self.flush_count}
        # History entries are not prefixed; the suffix \0\0 ensures we
        # look similar to other entries and aren't interfered with
        batch.put(b'state\0\0', repr(state).encode())

    def read_history_state(self):
        state = self.hist_db.get(b'state\0\0')
        if state:
            state = ast.literal_eval(state.decode())
            if not isinstance(state, dict):
                raise self.DBError('failed reading state from history DB')
            self.flush_count = state['flush_count']
        else:
            self.flush_count = 0

    def flush_history(self, history):
        self.flush_count += 1
        flush_id = pack('>H', self.flush_count)

        with self.hist_db.write_batch() as batch:
            for hashX in sorted(history):
                key = hashX + flush_id
                batch.put(key, history[hashX].tobytes())
            self.write_history_state(batch)

    def backup_history(self, hashXs):
        # Not certain this is needed, but it doesn't hurt
        self.flush_count += 1
        nremoves = 0

        with self.hist_db.write_batch() as batch:
            for hashX in sorted(hashXs):
                deletes = []
                puts = {}
                for key, hist in self.hist_db.iterator(prefix=hashX,
                                                       reverse=True):
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
            self.write_history_state(batch)

        return nremoves

    def get_history_txnums(self, hashX, limit=1000):
        '''Generator that returns an unpruned, sorted list of tx_nums in the
        history of a hashX.  Includes both spending and receiving
        transactions.  By default yields at most 1000 entries.  Set
        limit to None to get them all.  '''
        limit = self._resolve_limit(limit)
        for key, hist in self.hist_db.iterator(prefix=hashX):
            a = array.array('I')
            a.frombytes(hist)
            for tx_num in a:
                if limit == 0:
                    return
                yield tx_num
                limit -= 1

    def get_history(self, hashX, limit=1000):
        '''Generator that returns an unpruned, sorted list of (tx_hash,
        height) tuples of confirmed transactions that touched the address,
        earliest in the blockchain first.  Includes both spending and
        receiving transactions.  By default yields at most 1000 entries.
        Set limit to None to get them all.
        '''
        for tx_num in self.get_history_txnums(hashX, limit):
            yield self.fs_tx_hash(tx_num)
