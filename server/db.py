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
import logging
import os
from struct import pack, unpack
from bisect import bisect_right
from collections import namedtuple

import lib.util as util
from lib.hash import hash_to_str, HASHX_LEN
from server.storage import db_class
from server.history import History


UTXO = namedtuple("UTXO", "tx_num tx_pos tx_hash height value")


class DB(object):
    '''Simple wrapper of the backend database for querying.

    Performs no DB update, though the DB will be cleaned on opening if
    it was shutdown uncleanly.
    '''

    DB_VERSIONS = [6]

    class MissingUTXOError(Exception):
        '''Raised if a mempool tx input UTXO couldn't be found.'''

    class DBError(Exception):
        '''Raised on general DB errors generally indicating corruption.'''

    def __init__(self, env):
        self.logger = logging.getLogger(self.__class__.__name__)
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

        self.history = History()
        self.utxo_db = None
        self.open_dbs()

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
        synchronization.  When serving clients we want the open files for
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
                self.history.close_db()

            # Open DB and metadata files.  Record some of its state.
            self.utxo_db = self.db_class('utxo', for_sync)
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

        # Open history DB, clear excess history
        self.utxo_flush_count = self.history.open_db(self.db_class, for_sync,
                                                     self.utxo_flush_count)
        self.clear_excess_undo_info()

        self.logger.info('DB version: {:d}'.format(self.db_version))
        self.logger.info('coin: {}'.format(self.coin.NAME))
        self.logger.info('network: {}'.format(self.coin.NET))
        self.logger.info('height: {:,d}'.format(self.db_height))
        self.logger.info('tip: {}'.format(hash_to_str(self.db_tip)))
        self.logger.info('tx count: {:,d}'.format(self.db_tx_count))
        if self.first_sync:
            self.logger.info('sync time so far: {}'
                             .format(util.formatted_time(self.wall_time)))

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

    def read_headers(self, start_height, count):
        '''Requires start_height >= 0, count >= 0.  Reads as many headers as
        are available starting at start_height up to count.  This
        would be zero if start_height is beyond self.db_height, for
        example.

        Returns a (binary, n) pair where binary is the concatenated
        binary headers, and n is the count of headers returned.
        '''
        # Read some from disk
        if start_height < 0 or count < 0:
            raise self.DBError('{:,d} headers starting at {:,d} not on disk'
                               .format(count, start_height))
        disk_count = max(0, min(count, self.db_height + 1 - start_height))
        if disk_count:
            offset = self.header_offset(start_height)
            size = self.header_offset(start_height + disk_count) - offset
            return self.headers_file.read(offset, size), disk_count
        return b'', 0

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
        headers_concat, headers_count = self.read_headers(height, count)
        if headers_count != count:
            raise self.DBError('only got {:,d} headers starting at {:,d}, not '
                               '{:,d}'.format(headers_count, start, count))
        offset = 0
        headers = []
        for n in range(count):
            hlen = self.header_len(height + n)
            headers.append(headers_concat[offset:offset + hlen])
            offset += hlen

        return [self.coin.header_hash(header) for header in headers]

    def get_history(self, hashX, limit=1000):
        '''Generator that returns an unpruned, sorted list of (tx_hash,
        height) tuples of confirmed transactions that touched the address,
        earliest in the blockchain first.  Includes both spending and
        receiving transactions.  By default yields at most 1000 entries.
        Set limit to None to get them all.
        '''
        for tx_num in self.history.get_txnums(hashX, limit):
            yield self.fs_tx_hash(tx_num)

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

    # -- UTXO database

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
                raise self.DBError('your UTXO DB version is {} but this '
                                   'software only handles versions {}'
                                   .format(self.db_version, self.DB_VERSIONS))
            # backwards compat
            genesis_hash = state['genesis']
            if isinstance(genesis_hash, bytes):
                genesis_hash = genesis_hash.decode()
            if genesis_hash != self.coin.GENESIS_HASH:
                raise self.DBError('DB genesis hash {} does not match coin {}'
                                   .format(genesis_hash,
                                           self.coin.GENESIS_HASH))
            self.db_height = state['height']
            self.db_tx_count = state['tx_count']
            self.db_tip = state['tip']
            self.utxo_flush_count = state['utxo_flush_count']
            self.wall_time = state['wall_time']
            self.first_sync = state['first_sync']

    def write_utxo_state(self, batch):
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

    def set_flush_count(self, count):
        self.utxo_flush_count = count
        with self.utxo_db.write_batch() as batch:
            self.write_utxo_state(batch)

    def get_balance(self, hashX):
        '''Returns the confirmed balance of an address.'''
        return sum(utxo.value for utxo in self.get_utxos(hashX, limit=None))

    def get_utxos(self, hashX, limit=1000):
        '''Generator that yields all UTXOs for an address sorted in no
        particular order.  By default yields at most 1000 entries.
        Set limit to None to get them all.
        '''
        limit = util.resolve_limit(limit)
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

    def db_utxo_lookup(self, tx_hash, tx_idx):
        '''Given a prevout return a (hashX, value) pair.

        Raises MissingUTXOError if the UTXO is not found.  Used by the
        mempool code.
        '''
        idx_packed = pack('<H', tx_idx)
        hashX, tx_num_packed = self._db_hashX(tx_hash, idx_packed)
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

    def _db_hashX(self, tx_hash, idx_packed):
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
