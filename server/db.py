# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import array
import ast
import itertools
import os
import struct
import time
from binascii import hexlify, unhexlify
from bisect import bisect_right
from collections import defaultdict, namedtuple
from functools import partial
import logging

import plyvel

from lib.coins import Bitcoin
from lib.script import ScriptPubKey

# History can hold approx. 65536 * HIST_ENTRIES_PER_KEY entries
HIST_ENTRIES_PER_KEY = 1024
HIST_VALUE_BYTES = HIST_ENTRIES_PER_KEY * 4
ADDR_TX_HASH_LEN = 4
UTXO_TX_HASH_LEN = 4
UTXO = namedtuple("UTXO", "tx_num tx_pos tx_hash height value")


def formatted_time(t):
    t = int(t)
    return '{:d}d {:02d}h {:02d}m {:02d}s'.format(
        t // 86400, (t % 86400) // 3600, (t % 3600) // 60, t % 60)


class UTXOCache(object):
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
        self.logger = logging.getLogger('UTXO')
        self.logger.setLevel(logging.INFO)
        self.parent = parent
        self.coin = coin
        self.cache = {}
        self.db = db
        self.db_cache = {}
        # Statistics
        self.adds = 0
        self.cache_hits = 0
        self.db_deletes = 0

    def add_many(self, tx_hash, tx_num, txouts):
        '''Add a sequence of UTXOs to the cache, return the set of hash168s
        seen.

        Pass the hash of the TX it appears in, its TX number, and the
        TX outputs.
        '''
        parse_script = ScriptPubKey.from_script
        pack = struct.pack
        tx_numb = pack('<I', tx_num)
        hash168s = set()

        self.adds += len(txouts)
        for idx, txout in enumerate(txouts):
            # Get the hash168.  Ignore scripts we can't grok.
            pk = parse_script(txout.pk_script, self.coin)
            hash168 = pk.hash168
            if not hash168:
                continue

            hash168s.add(hash168)
            key = tx_hash + pack('<H', idx)

            # Well-known duplicate coinbases from heights 91722-91880
            # that destoyed 100 BTC forever:
            # e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468
            # d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599
            #if key in self.cache:
            #    self.logger.info('duplicate tx hash {}'
            #                     .format(bytes(reversed(tx_hash)).hex()))

            self.cache[key] = hash168 + tx_numb + pack('<Q', txout.value)

        return hash168s

    def spend(self, prevout):
        '''Spend a UTXO and return the address spent.

        If the UTXO is not in the cache it must be on disk.
        '''
        # Fast track is it's in the cache
        pack = struct.pack
        key = prevout.hash + pack('<H', prevout.n)
        value = self.cache.pop(key, None)
        if value:
            self.cache_hits += 1
            return value[:21]

        # Oh well.  Find and remove it from the DB.
        hash168 = self.hash168(prevout.hash, prevout.n)
        if not hash168:
            return None

        self.db_deletes += 1

        # Read the UTXO through the cache from the disk.  We have to
        # go through the cache because compressed keys can collide.
        key = (b'u' + hash168 + prevout.hash[:UTXO_TX_HASH_LEN]
               + pack('<H', prevout.n))
        data = self.cache_get(key)
        if data is None:
            # Uh-oh, this should not happen...
            self.logger.error('found no UTXO for {} / {:d} key {}'
                             .format(bytes(reversed(prevout.hash)).hex(),
                                     prevout.n, bytes(key).hex()))
            return hash168

        if len(data) == 12:
            (tx_num, ) = struct.unpack('<I', data[:4])
            self.cache_delete(key)
            return hash168

        # Resolve the compressed key collison.  These should be
        # extremely rare.
        assert len(data) % 12 == 0
        for n in range(0, len(data), 12):
            (tx_num, ) = struct.unpack('<I', data[n:n+4])
            tx_hash, height = self.parent.get_tx_hash(tx_num)
            if prevout.hash == tx_hash:
                data = data[:n] + data[n + 12:]
                self.cache_write(key, data)
                return hash168

        raise Exception('could not resolve UTXO key collision')

    def hash168(self, tx_hash, idx):
        '''Return the hash168 paid to by the given TXO.

        Refers to the database.  Returns None if not found (which is
        indicates a non-standard script).
        '''
        key = b'h' + tx_hash[:ADDR_TX_HASH_LEN] + struct.pack('<H', idx)
        data = self.cache_get(key)
        if data is None:
            # Assuming the DB is not corrupt, this indicates a
            # successful spend of a non-standard script
            # self.logger.info('ignoring spend of non-standard UTXO {} / {:d}'
            #                  .format(bytes(reversed(tx_hash)).hex(), idx)))
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

        # Now we can update to the batch.
        for key, value in self.db_cache.items():
            if value:
                batch.put(key, value)
            else:
                batch.delete(key)

        self.db_cache = {}

        self.logger.info('UTXO cache adds: {:,d} spends: {:,d} '
                         .format(self.adds, self.cache_hits))
        self.logger.info('UTXO DB adds: {:,d} spends: {:,d}. '
                         'Collisions: hash168: {:,d} UTXO: {:,d}'
                         .format(new_utxos, self.db_deletes,
                                 hcolls, ucolls))
        self.adds = self.cache_hits = self.db_deletes = 0


class DB(object):

    class Error(Exception):
        pass

    def __init__(self, env):
        self.logger = logging.getLogger('DB')
        self.logger.setLevel(logging.INFO)

        # Meta
        self.tx_hash_file_size = 16 * 1024 * 1024
        self.utxo_MB = env.utxo_MB
        self.hist_MB = env.hist_MB
        self.next_cache_check = 0
        self.last_flush = time.time()
        self.coin = env.coin

        # Chain state (initialize to genesis in case of new DB)
        self.db_height = -1
        self.db_tx_count = 0
        self.flush_count = 0
        self.utxo_flush_count = 0
        self.wall_time = 0
        self.tip = self.coin.GENESIS_HASH

        # Open DB and metadata files.  Record some of its state.
        self.db = self.open_db(self.coin)
        self.tx_count = self.fs_tx_count = self.db_tx_count
        self.height = self.fs_height = self.db_height

        # Caches to be flushed later.  Headers and tx_hashes have one
        # entry per block
        self.headers = []
        self.tx_hashes = []
        self.history = defaultdict(partial(array.array, 'I'))
        self.history_size = 0
        self.utxo_cache = UTXOCache(self, self.db, self.coin)
        self.tx_counts = array.array('I')
        self.txcount_file.seek(0)
        self.tx_counts.fromfile(self.txcount_file, self.height + 1)

        # Log state
        self.logger.info('{}/{} height: {:,d} tx count: {:,d} '
                         'flush count: {:,d} utxo flush count: {:,d} '
                         'sync time: {}'
                         .format(self.coin.NAME, self.coin.NET, self.height,
                                 self.tx_count, self.flush_count,
                                 self.utxo_flush_count,
                                 formatted_time(self.wall_time)))
        self.logger.info('flushing UTXO cache at {:,d} MB'
                         .format(self.utxo_MB))
        self.logger.info('flushing history cache at {:,d} MB'
                         .format(self.hist_MB))


    def open_db(self, coin):
        db_name = '{}-{}'.format(coin.NAME, coin.NET)
        is_new = False
        try:
            db = plyvel.DB(db_name, create_if_missing=False,
                           error_if_exists=False, compression=None)
        except:
            db = plyvel.DB(db_name, create_if_missing=True,
                           error_if_exists=True, compression=None)
            is_new = True

        if is_new:
            self.logger.info('created new database {}'.format(db_name))
            self.flush_state(db)
        else:
            self.logger.info('successfully opened database {}'.format(db_name))
            self.read_state(db)
            self.delete_excess_history(db)

        self.headers_file = self.open_file('headers', is_new)
        self.txcount_file = self.open_file('txcount', is_new)

        return db

    def read_state(self, db):
        state = db.get(b'state')
        state = ast.literal_eval(state.decode('ascii'))
        if state['genesis'] != self.coin.GENESIS_HASH:
            raise self.Error('DB genesis hash {} does not match coin {}'
                             .format(state['genesis_hash'],
                                     self.coin.GENESIS_HASH))
        self.db_height = state['height']
        self.db_tx_count = state['tx_count']
        self.tip = state['tip']
        self.flush_count = state['flush_count']
        self.utxo_flush_count = state['utxo_flush_count']
        self.wall_time = state['wall_time']

    def delete_excess_history(self, db):
        '''Clear history flushed since the most recent UTXO flush.'''
        utxo_flush_count = self.utxo_flush_count
        diff = self.flush_count - utxo_flush_count
        if diff == 0:
            return
        if diff < 0:
            raise self.Error('DB corrupt: flush_count < utxo_flush_count')

        self.logger.info('DB not shut down cleanly.  Scanning for most '
                         'recent {:,d} history flushes'.format(diff))
        prefix = b'H'
        unpack = struct.unpack
        keys = []
        for key, hist in db.iterator(prefix=prefix):
            flush_id, = unpack('>H', key[-2:])
            if flush_id > self.utxo_flush_count:
                keys.append(key)

        self.logger.info('deleting {:,d} history entries'.format(len(keys)))
        with db.write_batch(transaction=True) as batch:
            for key in keys:
                db.delete(key)
            self.utxo_flush_count = self.flush_count
            self.flush_state(batch)
        self.logger.info('deletion complete')

    def flush_to_fs(self):
        '''Flush the things stored on the filesystem.'''
        # First the headers
        headers = b''.join(self.headers)
        header_len = self.coin.HEADER_LEN
        self.headers_file.seek((self.fs_height + 1) * header_len)
        self.headers_file.write(headers)
        self.headers_file.flush()
        self.headers = []

        # Then the tx counts
        self.txcount_file.seek((self.fs_height + 1) * self.tx_counts.itemsize)
        self.txcount_file.write(self.tx_counts[self.fs_height + 1:
                                               self.height + 1])
        self.txcount_file.flush()

        # Finally the hashes
        hashes = memoryview(b''.join(itertools.chain(*self.tx_hashes)))
        assert len(hashes) % 32 == 0
        assert self.tx_hash_file_size % 32 == 0
        cursor = 0
        file_pos = self.fs_tx_count * 32
        while cursor < len(hashes):
            file_num, offset = divmod(file_pos, self.tx_hash_file_size)
            size = min(len(hashes) - cursor, self.tx_hash_file_size - offset)
            filename = 'hashes{:04d}'.format(file_num)
            with self.open_file(filename, create=True) as f:
                f.seek(offset)
                f.write(hashes[cursor:cursor + size])
            cursor += size
            file_pos += size
        self.tx_hashes = []

        self.fs_height = self.height
        self.fs_tx_count = self.tx_count
        os.sync()

    def flush_state(self, batch):
        '''Flush chain state to the batch.'''
        now = time.time()
        self.wall_time += now - self.last_flush
        self.last_flush = now
        state = {
            'genesis': self.coin.GENESIS_HASH,
            'height': self.db_height,
            'tx_count': self.db_tx_count,
            'tip': self.tip,
            'flush_count': self.flush_count,
            'utxo_flush_count': self.utxo_flush_count,
            'wall_time': self.wall_time,
        }
        batch.put(b'state', repr(state).encode('ascii'))

    def flush_utxos(self, batch):
        self.logger.info('flushing UTXOs: {:,d} txs and {:,d} blocks'
                         .format(self.tx_count - self.db_tx_count,
                                 self.height - self.db_height))
        self.utxo_cache.flush(batch)
        self.utxo_flush_count = self.flush_count
        self.db_tx_count = self.tx_count
        self.db_height = self.height

    def flush(self, daemon_height, flush_utxos=False):
        '''Flush out cached state.

        History is always flushed.  UTXOs are flushed if flush_utxos.'''
        flush_start = time.time()
        last_flush = self.last_flush
        tx_diff = self.tx_count - self.fs_tx_count

        # Write out the files to the FS before flushing to the DB.  If
        # the DB transaction fails, the files being too long doesn't
        # matter.  But if writing the files fails we do not want to
        # have updated the DB.
        self.logger.info('commencing history flush')
        self.flush_to_fs()

        with self.db.write_batch(transaction=True) as batch:
            # History first - fast and frees memory.  Flush state last
            # as it reads the wall time.
            self.flush_history(batch)
            if flush_utxos:
                self.flush_utxos(batch)
            self.flush_state(batch)
            self.logger.info('committing transaction...')

        # Update and put the wall time again - otherwise we drop the
        # time it took leveldb to commit the batch
        self.flush_state(self.db)

        flush_time = int(self.last_flush - flush_start)
        self.logger.info('flush #{:,d} to height {:,d} took {:,d}s'
                         .format(self.flush_count, self.height, flush_time))

        # Log handy stats
        txs_per_sec = int(self.tx_count / self.wall_time)
        this_txs_per_sec = 1 + int(tx_diff / (self.last_flush - last_flush))
        if self.height > self.coin.TX_COUNT_HEIGHT:
            tx_est = (daemon_height - self.height) * self.coin.TX_PER_BLOCK
        else:
            tx_est = ((daemon_height - self.coin.TX_COUNT_HEIGHT)
                      * self.coin.TX_PER_BLOCK
                      + (self.coin.TX_COUNT - self.tx_count))

        self.logger.info('txs: {:,d}  tx/sec since genesis: {:,d}, '
                         'since last flush: {:,d}'
                         .format(self.tx_count, txs_per_sec, this_txs_per_sec))
        self.logger.info('sync time: {}  ETA: {}'
                         .format(formatted_time(self.wall_time),
                                 formatted_time(tx_est / this_txs_per_sec)))

    def flush_history(self, batch):
        # Drop any None entry
        self.history.pop(None, None)

        self.flush_count += 1
        flush_id = struct.pack('>H', self.flush_count)
        for hash168, hist in self.history.items():
            key = b'H' + hash168 + flush_id
            batch.put(key, hist.tobytes())

        self.logger.info('{:,d} history entries in {:,d} addrs'
                         .format(self.history_size, len(self.history)))

        self.history = defaultdict(partial(array.array, 'I'))
        self.history_size = 0

    def open_file(self, filename, create=False):
        '''Open the file name.  Return its handle.'''
        try:
            return open(filename, 'rb+')
        except FileNotFoundError:
            if create:
                return open(filename, 'wb+')
            raise

    def read_headers(self, height, count):
        header_len = self.coin.HEADER_LEN
        self.headers_file.seek(height * header_len)
        return self.headers_file.read(count * header_len)

    def cache_sizes(self, daemon_height):
        '''Returns the approximate size of the cache, in MB.'''
        # Good average estimates based on traversal of subobjects and
        # requesting size from Python (see deep_getsizeof).  For
        # whatever reason Python O/S mem usage is typically +30% or
        # more, so we scale our already bloated object sizes.
        one_MB = int(1048576 / 1.3)
        utxo_cache_size = len(self.utxo_cache.cache) * 187
        db_cache_size = len(self.utxo_cache.db_cache) * 105
        hist_cache_size = len(self.history) * 180 + self.history_size * 4
        utxo_MB = (db_cache_size + utxo_cache_size) // one_MB
        hist_MB = hist_cache_size // one_MB

        self.logger.info('cache stats at height {:,d}  daemon height: {:,d}'
                         .format(self.height, daemon_height))
        self.logger.info('  entries: UTXO: {:,d}  DB: {:,d}  '
                         'hist addrs: {:,d}  hist size: {:,d}'
                         .format(len(self.utxo_cache.cache),
                                 len(self.utxo_cache.db_cache),
                                 len(self.history),
                                 self.history_size))
        self.logger.info('  size: {:,d}MB  (UTXOs {:,d}MB hist {:,d}MB)'
                         .format(utxo_MB + hist_MB, utxo_MB, hist_MB))
        return utxo_MB, hist_MB

    def process_block(self, block, daemon_height):
        self.headers.append(block[:self.coin.HEADER_LEN])

        tx_hashes, txs = self.coin.read_block(block)
        self.height += 1

        assert len(self.tx_counts) == self.height

        # These both need to be updated before calling process_tx().
        # It uses them for tx hash lookup
        self.tx_hashes.append(tx_hashes)
        self.tx_counts.append(self.tx_count + len(txs))

        for tx_hash, tx in zip(tx_hashes, txs):
            self.process_tx(tx_hash, tx)

        # Check if we're getting full and time to flush?
        now = time.time()
        if now > self.next_cache_check:
            self.next_cache_check = now + 60
            utxo_MB, hist_MB = self.cache_sizes(daemon_height)
            if utxo_MB >= self.utxo_MB or hist_MB >= self.hist_MB:
                self.flush(daemon_height, utxo_MB >= self.utxo_MB)

    def process_tx(self, tx_hash, tx):
        cache = self.utxo_cache
        tx_num = self.tx_count

        # Add the outputs as new UTXOs; spend the inputs
        hash168s = cache.add_many(tx_hash, tx_num, tx.outputs)
        if not tx.is_coinbase:
            for txin in tx.inputs:
                hash168s.add(cache.spend(txin.prevout))

        for hash168 in hash168s:
            self.history[hash168].append(tx_num)
        self.history_size += len(hash168s)

        self.tx_count += 1

    def get_tx_hash(self, tx_num):
        '''Returns the tx_hash and height of a tx number.'''
        height = bisect_right(self.tx_counts, tx_num)

        # Is this on disk or unflushed?
        if height > self.fs_height:
            tx_hashes = self.tx_hashes[height - (self.fs_height + 1)]
            tx_hash = tx_hashes[tx_num - self.tx_counts[height - 1]]
        else:
            file_pos = tx_num * 32
            file_num, offset = divmod(file_pos, self.tx_hash_file_size)
            filename = 'hashes{:04d}'.format(file_num)
            with self.open_file(filename) as f:
                f.seek(offset)
                tx_hash = f.read(32)

        return tx_hash, height

    @staticmethod
    def resolve_limit(limit):
        if limit is None:
            return -1
        assert isinstance(limit, int) and limit >= 0
        return limit

    def get_history(self, hash168, limit=1000):
        '''Generator that returns an unpruned, sorted list of (tx_hash,
        height) tuples of transactions that touched the address,
        earliest in the blockchain first.  Includes both spending and
        receiving transactions.  By default yields at most 1000 entries.
        Set limit to None to get them all.
        '''
        limit = self.resolve_limit(limit)
        prefix = b'H' + hash168
        for key, hist in self.db.iterator(prefix=prefix):
            a = array.array('I')
            a.frombytes(hist)
            for tx_num in a:
                if limit == 0:
                    return
                yield self.get_tx_hash(tx_num)
                limit -= 1

    def get_balance(self, hash168):
        '''Returns the confirmed balance of an address.'''
        return sum(utxo.value for utxo in self.get_utxos(hash168, limit=None))

    def get_utxos(self, hash168, limit=1000):
        '''Generator that yields all UTXOs for an address sorted in no
        particular order.  By default yields at most 1000 entries.
        Set limit to None to get them all.
        '''
        limit = self.resolve_limit(limit)
        unpack = struct.unpack
        prefix = b'u' + hash168
        utxos = []
        for k, v in self.db.iterator(prefix=prefix):
            (tx_pos, ) = unpack('<H', k[-2:])

            for n in range(0, len(v), 12):
                if limit == 0:
                    return
                (tx_num, ) = unpack('<I', v[n:n+4])
                (value, ) = unpack('<Q', v[n+4:n+12])
                tx_hash, height = self.get_tx_hash(tx_num)
                yield UTXO(tx_num, tx_pos, tx_hash, height, value)
                limit -= 1

    def get_utxos_sorted(self, hash168):
        '''Returns all the UTXOs for an address sorted by height and
        position in the block.'''
        return sorted(self.get_utxos(hash168, limit=None))
