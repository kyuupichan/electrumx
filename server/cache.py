# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''UTXO and file cache.

During initial sync these cache data and only flush occasionally.
Once synced flushes are performed after processing each block.
'''


import array
import itertools
import os
import struct
from bisect import bisect_right

from lib.util import chunks, LoggedClass
from lib.hash import double_sha256, hash_to_str


# History can hold approx. 65536 * HIST_ENTRIES_PER_KEY entries
HIST_ENTRIES_PER_KEY = 1024
HIST_VALUE_BYTES = HIST_ENTRIES_PER_KEY * 4
ADDR_TX_HASH_LEN = 4
UTXO_TX_HASH_LEN = 4
NO_HASH_168 = bytes([255]) * 21
NO_CACHE_ENTRY = NO_HASH_168 + bytes(12)


class UTXOCache(LoggedClass):
    '''An in-memory UTXO cache, representing all changes to UTXO state
    since the last DB flush.

    We want to store millions, perhaps 10s of millions of these in
    memory for optimal performance during initial sync, because then
    it is possible to spend UTXOs without ever going to the database
    (other than as an entry in the address history, and there is only
    one such entry per TX not per UTXO).  So store them in a Python
    dictionary with binary keys and values.

      Key:    TX_HASH + TX_IDX           (32 + 2 = 34 bytes)
      Value:  HASH168 + TX_NUM + VALUE   (21 + 4 + 8 = 33 bytes)

    That's 67 bytes of raw data.  Python dictionary overhead means
    each entry actually uses about 187 bytes of memory.  So almost
    11.5 million UTXOs can fit in 2GB of RAM.  There are approximately
    42 million UTXOs on bitcoin mainnet at height 433,000.

    Semantics:

      add:   Add it to the cache dictionary.
      spend: Remove it if in the cache dictionary.
             Otherwise it's been flushed to the DB.  Each UTXO
             is responsible for two entries in the DB stored using
             compressed keys.  Mark both for deletion in the next
             flush of the in-memory UTXO cache.

    A UTXO is stored in the DB in 2 "tables":

      1.  The output value and tx number.  Must be keyed with a
          hash168 prefix so the unspent outputs and balance of an
          arbitrary address can be looked up with a simple key
          traversal.
          Key: b'u' + hash168 + compressed_tx_hash + tx_idx
          Value: a (tx_num, value) pair

      2.  Given a prevout, we need to be able to look up the UTXO key
          to remove it.  As is keyed by hash168 and that is not part
          of the prevout, we need a hash168 lookup.
          Key: b'h' + compressed tx_hash + tx_idx
          Value: (hash168, tx_num) pair

    The compressed TX hash is just the first few bytes of the hash of
    the TX the UTXO is in (and needn't be the same number of bytes in
    each table).  As this is not unique there will be collisions;
    tx_num is stored to resolve them.  The collision rate is around
    0.02% for the hash168 table, and almost zero for the UTXO table
    (there are around 100 collisions in the whole bitcoin blockchain).

    '''

    def __init__(self, parent, db, coin):
        super().__init__()
        self.parent = parent
        self.coin = coin
        self.cache = {}
        self.put = self.cache.__setitem__
        self.db = db
        self.db_cache = {}
        # Statistics
        self.cache_spends = 0
        self.db_deletes = 0

    def spend(self, prev_hash, prev_idx):
        '''Spend a UTXO and return the cache's value.

        If the UTXO is not in the cache it must be on disk.
        '''
        # Fast track is it's in the cache
        pack = struct.pack
        idx_packed = pack('<H', prev_idx)
        value = self.cache.pop(prev_hash + idx_packed, None)
        if value:
            self.cache_spends += 1
            return value

        # Oh well.  Find and remove it from the DB.
        hash168 = self.hash168(prev_hash, idx_packed)
        if not hash168:
            return NO_CACHE_ENTRY

        self.db_deletes += 1

        # Read the UTXO through the cache from the disk.  We have to
        # go through the cache because compressed keys can collide.
        key = b'u' + hash168 + prev_hash[:UTXO_TX_HASH_LEN] + idx_packed
        data = self.cache_get(key)
        if data is None:
            # Uh-oh, this should not happen...
            self.logger.error('found no UTXO for {} / {:d} key {}'
                             .format(hash_to_str(prev_hash), prev_idx,
                                     bytes(key).hex()))
            return NO_CACHE_ENTRY

        if len(data) == 12:
            self.cache_delete(key)
            return hash168 + data

        # Resolve the compressed key collison.  These should be
        # extremely rare.
        assert len(data) % 12 == 0
        for n in range(0, len(data), 12):
            (tx_num, ) = struct.unpack('<I', data[n:n+4])
            tx_hash, height = self.parent.get_tx_hash(tx_num)
            if prev_hash == tx_hash:
                result = hash168 + data[n: n+12]
                data = data[:n] + data[n+12:]
                self.cache_write(key, data)
                return result

        raise Exception('could not resolve UTXO key collision')

    def hash168(self, tx_hash, idx_packed):
        '''Return the hash168 paid to by the given TXO.

        Refers to the database.  Returns None if not found (which is
        indicates a non-standard script).
        '''
        key = b'h' + tx_hash[:ADDR_TX_HASH_LEN] + idx_packed
        data = self.cache_get(key)
        if data is None:
            # Assuming the DB is not corrupt, this indicates a
            # successful spend of a non-standard script
            return None

        if len(data) == 25:
            self.cache_delete(key)
            return data[:21]

        assert len(data) % 25 == 0

        # Resolve the compressed key collision using the TX number
        for n in range(0, len(data), 25):
            (tx_num, ) = struct.unpack('<I', data[n+21:n+25])
            my_hash, height = self.parent.get_tx_hash(tx_num)
            if my_hash == tx_hash:
                self.cache_write(key, data[:n] + data[n+25:])
                return data[n:n+21]

        raise Exception('could not resolve hash168 collision')

    def cache_write(self, key, value):
        '''Cache write of a (key, value) pair to the DB.'''
        assert(bool(value))
        self.db_cache[key] = value

    def cache_delete(self, key):
        '''Cache deletion of a key from the DB.'''
        self.db_cache[key] = None

    def cache_get(self, key):
        '''Fetch a value from the DB through our write cache.'''
        value = self.db_cache.get(key)
        if value:
            return value
        return self.db.get(key)

    def flush(self, batch):
        '''Flush the cached DB writes and UTXO set to the batch.'''
        # Care is needed because the writes generated by flushing the
        # UTXO state may have keys in common with our write cache or
        # may be in the DB already.
        hcolls = ucolls = 0
        new_utxos = len(self.cache)

        for cache_key, cache_value in self.cache.items():
            # Frist write to the hash168 lookup table
            key = b'h' + cache_key[:ADDR_TX_HASH_LEN] + cache_key[-2:]
            value = cache_value[:25]
            prior_value = self.cache_get(key)
            if prior_value:   # Should rarely happen
                hcolls += 1
                value += prior_value
            self.cache_write(key, value)

            # Next write the UTXO table
            key = (b'u' + cache_value[:21] + cache_key[:UTXO_TX_HASH_LEN]
                   + cache_key[-2:])
            value = cache_value[-12:]
            prior_value = self.cache_get(key)
            if prior_value:   # Should almost never happen
                ucolls += 1
                value += prior_value
            self.cache_write(key, value)

        # GC-ing this now can only help the levelDB write.
        self.cache = {}
        self.put = self.cache.__setitem__

        # Now we can update to the batch.
        for key, value in self.db_cache.items():
            if value:
                batch.put(key, value)
            else:
                batch.delete(key)

        self.db_cache = {}

        adds = new_utxos + self.cache_spends

        self.logger.info('UTXO cache adds: {:,d} spends: {:,d} '
                         .format(adds, self.cache_spends))
        self.logger.info('UTXO DB adds: {:,d} spends: {:,d}. '
                         'Collisions: hash168: {:,d} UTXO: {:,d}'
                         .format(new_utxos, self.db_deletes,
                                 hcolls, ucolls))
        self.cache_spends = self.db_deletes = 0


class FSCache(LoggedClass):

    def __init__(self, coin, height, tx_count):
        super().__init__()

        self.coin = coin
        self.tx_hash_file_size = 16 * 1024 * 1024
        assert self.tx_hash_file_size % 32 == 0

        # On-disk values, updated by a flush
        self.height = height

        # Unflushed items
        self.headers = []
        self.tx_hashes = []

        is_new = height == -1
        self.headers_file = self.open_file('headers', is_new)
        self.txcount_file = self.open_file('txcount', is_new)

        # tx_counts[N] has the cumulative number of txs at the end of
        # height N.  So tx_counts[0] is 1 - the genesis coinbase
        self.tx_counts = array.array('I')
        self.txcount_file.seek(0)
        self.tx_counts.fromfile(self.txcount_file, self.height + 1)
        if self.tx_counts:
            assert tx_count == self.tx_counts[-1]
        else:
            assert tx_count == 0

    def open_file(self, filename, create=False):
        '''Open the file name.  Return its handle.'''
        try:
            return open(filename, 'rb+')
        except FileNotFoundError:
            if create:
                return open(filename, 'wb+')
            raise

    def advance_block(self, header, tx_hashes, txs):
        '''Update the FS cache for a new block.'''
        prior_tx_count = self.tx_counts[-1] if self.tx_counts else 0

        # Cache the new header, tx hashes and cumulative tx count
        self.headers.append(header)
        self.tx_hashes.append(tx_hashes)
        self.tx_counts.append(prior_tx_count + len(txs))

    def backup_block(self):
        '''Revert a block.'''
        assert not self.headers
        assert not self.tx_hashes
        assert self.height >= 0
        # Just update in-memory.  It doesn't matter if disk files are
        # too long, they will be overwritten when advancing.
        self.height -= 1
        self.tx_counts.pop()

    def flush(self, new_height, new_tx_count):
        '''Flush the things stored on the filesystem.
        The arguments are passed for sanity check assertions only.'''
        self.logger.info('flushing to file system')

        blocks_done = len(self.headers)
        prior_tx_count = self.tx_counts[self.height] if self.height >= 0 else 0
        cur_tx_count = self.tx_counts[-1] if self.tx_counts else 0
        txs_done = cur_tx_count - prior_tx_count

        assert self.height + blocks_done == new_height
        assert len(self.tx_hashes) == blocks_done
        assert len(self.tx_counts) == new_height + 1
        assert cur_tx_count == new_tx_count, \
            'cur: {:,d} new: {:,d}'.format(cur_tx_count, new_tx_count)

        # First the headers
        headers = b''.join(self.headers)
        header_len = self.coin.HEADER_LEN
        self.headers_file.seek((self.height + 1) * header_len)
        self.headers_file.write(headers)
        self.headers_file.flush()

        # Then the tx counts
        self.txcount_file.seek((self.height + 1) * self.tx_counts.itemsize)
        self.txcount_file.write(self.tx_counts[self.height + 1:])
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

        self.tx_hashes = []
        self.headers = []
        self.height += blocks_done

    def read_headers(self, height, count):
        read_count = min(count, self.height + 1 - height)

        assert height >= 0 and read_count >= 0
        assert count <= read_count + len(self.headers)

        result = b''
        if read_count > 0:
            header_len = self.coin.HEADER_LEN
            self.headers_file.seek(height * header_len)
            result = self.headers_file.read(read_count * header_len)

        count -= read_count
        if count:
            start = (height + read_count) - (self.height + 1)
            result += b''.join(self.headers[start: start + count])

        return result

    def get_tx_hash(self, tx_num):
        '''Returns the tx_hash and height of a tx number.'''
        height = bisect_right(self.tx_counts, tx_num)

        # Is this on disk or unflushed?
        if height > self.height:
            tx_hashes = self.tx_hashes[height - (self.height + 1)]
            tx_hash = tx_hashes[tx_num - self.tx_counts[height - 1]]
        else:
            file_pos = tx_num * 32
            file_num, offset = divmod(file_pos, self.tx_hash_file_size)
            filename = 'hashes{:04d}'.format(file_num)
            with self.open_file(filename) as f:
                f.seek(offset)
                tx_hash = f.read(32)

        return tx_hash, height

    def block_hashes(self, height, count):
        headers = self.read_headers(height, count)
        hlen = self.coin.HEADER_LEN
        return [double_sha256(header) for header in chunks(headers, hlen)]
