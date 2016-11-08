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


import struct

from lib.util import LoggedClass
from lib.hash import hash_to_str


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

    def __init__(self, get_tx_hash, db, coin):
        super().__init__()
        self.get_tx_hash = get_tx_hash
        self.coin = coin
        self.cache = {}
        self.put = self.cache.__setitem__
        self.db = db
        self.db_cache = {}
        # Statistics
        self.cache_spends = 0
        self.db_deletes = 0

    def lookup(self, prev_hash, prev_idx):
        '''Given a prevout, return a pair (hash168, value).

        If the UTXO is not found, returns (None, None).'''
        # Fast track is it being in the cache
        idx_packed = struct.pack('<H', prev_idx)
        value = self.cache.get(prev_hash + idx_packed, None)
        if value:
            return value
        return self.db_lookup(prev_hash, idx_packed, False)

    def db_lookup(self, tx_hash, idx_packed, delete=True):
        '''Return a UTXO from the DB.  Remove it if delete is True.

        Return NO_CACHE_ENTRY if it is not in the DB.'''
        hash168 = self.hash168(tx_hash, idx_packed, delete)
        if not hash168:
            return NO_CACHE_ENTRY

        # Read the UTXO through the cache from the disk.  We have to
        # go through the cache because compressed keys can collide.
        key = b'u' + hash168 + tx_hash[:UTXO_TX_HASH_LEN] + idx_packed
        data = self.cache_get(key)
        if data is None:
            # Uh-oh, this should not happen...
            self.logger.error('found no UTXO for {} / {:d} key {}'
                             .format(hash_to_str(tx_hash),
                                     struct.unpack('<H', idx_packed),
                                     bytes(key).hex()))
            return NO_CACHE_ENTRY

        if len(data) == 12:
            if delete:
                self.db_deletes += 1
                self.cache_delete(key)
            return hash168 + data

        # Resolve the compressed key collison.  These should be
        # extremely rare.
        assert len(data) % 12 == 0
        for n in range(0, len(data), 12):
            (tx_num, ) = struct.unpack('<I', data[n:n+4])
            this_tx_hash, height = self.get_tx_hash(tx_num)
            if tx_hash == this_tx_hash:
                result = hash168 + data[n:n+12]
                if delete:
                    self.db_deletes += 1
                    self.cache_write(key, data[:n] + data[n+12:])
                return result

        raise Exception('could not resolve UTXO key collision')

    def spend(self, prev_hash, prev_idx):
        '''Spend a UTXO and return the cache's value.

        If the UTXO is not in the cache it must be on disk.
        '''
        # Fast track is it being in the cache
        idx_packed = struct.pack('<H', prev_idx)
        value = self.cache.pop(prev_hash + idx_packed, None)
        if value:
            self.cache_spends += 1
            return value

        return self.db_lookup(prev_hash, idx_packed)

    def hash168(self, tx_hash, idx_packed, delete=True):
        '''Return the hash168 paid to by the given TXO.

        Look it up in the DB and removes it if delete is True.  Return
        None if not found.
        '''
        key = b'h' + tx_hash[:ADDR_TX_HASH_LEN] + idx_packed
        data = self.cache_get(key)
        if data is None:
            # Assuming the DB is not corrupt, if delete is True this
            # indicates a successful spend of a non-standard script
            # as we don't currently record those
            return None

        if len(data) == 25:
            if delete:
                self.cache_delete(key)
            return data[:21]

        assert len(data) % 25 == 0

        # Resolve the compressed key collision using the TX number
        for n in range(0, len(data), 25):
            (tx_num, ) = struct.unpack('<I', data[n+21:n+25])
            my_hash, height = self.get_tx_hash(tx_num)
            if my_hash == tx_hash:
                if delete:
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
