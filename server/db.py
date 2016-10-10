# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import array
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


def to_4_bytes(value):
    return struct.pack('<I', value)

def from_4_bytes(b):
    return struct.unpack('<I', b)[0]


class DB(object):

    HEIGHT_KEY = b'height'
    TIP_KEY = b'tip'
    GENESIS_KEY = b'genesis'
    TX_COUNT_KEY = b'tx_count'
    FLUSH_COUNT_KEY = b'flush_count'
    WALL_TIME_KEY = b'wall_time'

    class Error(Exception):
        pass

    def __init__(self, env):
        self.logger = logging.getLogger('DB')
        self.logger.setLevel(logging.INFO)

        self.coin = env.coin
        self.flush_size = env.flush_size
        self.logger.info('using flush size of {:,d} entries'
                         .format(self.flush_size))

        self.tx_counts = array.array('I')
        self.tx_hash_file_size = 4*1024*1024
        # Unflushed items.  Headers and tx_hashes have one entry per block
        self.headers = []
        self.tx_hashes = []
        self.history = defaultdict(list)
        self.writes_avoided = 0
        self.read_cache_hits = 0
        self.write_cache_hits = 0
        self.hcolls = 0

        # Things put in a batch are not visible until the batch is written,
        # so use a cache.
        # Semantics: a key/value pair in this dictionary represents the
        # in-memory state of the DB.  Anything in this dictionary will be
        # written at the next flush.
        self.write_cache = {}
        # Read cache: a key/value pair in this dictionary represents
        # something read from the DB; it is on-disk as of the prior
        # flush.  If a key is in write_cache that value is more
        # recent.  Any key in write_cache and not in read_cache has
        # never hit the disk.
        self.read_cache = {}

        db_name = '{}-{}'.format(self.coin.NAME, self.coin.NET)
        try:
            self.db = self.open_db(db_name, False)
        except:
            self.db = self.open_db(db_name, True)
            self.headers_file = self.open_file('headers', True)
            self.txcount_file = self.open_file('txcount', True)
            self.init_db()
            self.logger.info('created new database {}'.format(db_name))
        else:
            self.logger.info('successfully opened database {}'.format(db_name))
            self.headers_file = self.open_file('headers')
            self.txcount_file = self.open_file('txcount')
            self.read_db()

        # Note that DB_HEIGHT is the height of the next block to be written.
        # So an empty DB has a DB_HEIGHT of 0 not -1.
        self.tx_count = self.db_tx_count
        self.height = self.db_height - 1
        self.tx_counts.fromfile(self.txcount_file, self.db_height)
        self.last_flush = time.time()
        # FIXME: this sucks and causes issues with exceptions in init_db()
        if self.tx_count == 0:
            self.flush()

    def open_db(self, db_name, create):
        return plyvel.DB(db_name, create_if_missing=create,
                         error_if_exists=create,
                         compression=None)
                         # lru_cache_size=256*1024*1024)

    def init_db(self):
        self.db_height = 0
        self.db_tx_count = 0
        self.flush_count = 0
        self.wall_time = 0
        self.tip = self.coin.GENESIS_HASH
        self.put(self.GENESIS_KEY, unhexlify(self.tip))

    def read_db(self):
        genesis_hash = hexlify(self.get(self.GENESIS_KEY))
        if genesis_hash != self.coin.GENESIS_HASH:
            raise self.Error('DB genesis hash {} does not match coin {}'
                             .format(genesis_hash, self.coin.GENESIS_HASH))
        self.db_height = from_4_bytes(self.get(self.HEIGHT_KEY))
        self.db_tx_count = from_4_bytes(self.get(self.TX_COUNT_KEY))
        self.flush_count = from_4_bytes(self.get(self.FLUSH_COUNT_KEY))
        self.wall_time = from_4_bytes(self.get(self.WALL_TIME_KEY))
        self.tip = hexlify(self.get(self.TIP_KEY))
        self.logger.info('{}/{} height: {:,d} tx count: {:,d} '
                         'flush count: {:,d} sync time: {}'
                         .format(self.coin.NAME, self.coin.NET,
                                 self.db_height - 1, self.db_tx_count,
                                 self.flush_count, self.formatted_wall_time()))

    def formatted_wall_time(self):
        wall_time = int(self.wall_time)
        return '{:d}d {:02d}h {:02d}m {:02d}s'.format(
            wall_time // 86400, (wall_time % 86400) // 3600,
            (wall_time % 3600) // 60, wall_time % 60)

    def get(self, key):
        # Get a key from write_cache, then read_cache, then the DB
        value = self.write_cache.get(key)
        if not value:
            value = self.read_cache.get(key)
            if not value:
                value = self.db.get(key)
                self.read_cache[key] = value
            else:
                self.read_cache_hits += 1
        else:
            self.write_cache_hits += 1
        return value

    def put(self, key, value):
        assert(bool(value))
        self.write_cache[key] = value

    def delete(self, key):
        # Deleting an on-disk key requires a later physical delete
        # If it's not on-disk we can just drop it entirely
        if self.read_cache.get(key) is None:
            self.writes_avoided += 1
            self.write_cache.pop(key, None)
        else:
            self.write_cache[key] = None

    def flush(self):
        '''Flush out all cached state.'''
        flush_start = time.time()
        last_flush = self.last_flush
        tx_diff = self.tx_count - self.db_tx_count
        height_diff = self.height + 1 - self.db_height
        self.logger.info('starting flush {:,d} txs and {:,d} blocks'
                         .format(tx_diff, height_diff))

        # Write out the files to the FS before flushing to the DB.  If
        # the DB transaction fails, the files being too long doesn't
        # matter.  But if writing the files fails we do not want to
        # have updated the DB.  Flush state last as it reads the wall
        # time.
        self.flush_to_fs()
        with self.db.write_batch(transaction=True) as batch:
            self.flush_cache(batch)
            self.flush_history(batch)
            self.logger.info('flushed history...')
            self.flush_state(batch)
            self.logger.info('committing transaction...')

        # Update and put the wall time again - otherwise we drop the
        # time it takes leveldb to commit the batch
        self.update_wall_time(self.db)

        flush_time = int(self.last_flush - flush_start)
        self.logger.info('flushed in {:,d}s to height {:,d} tx count {:,d} '
                         'flush count {:,d}'
                         .format(flush_time, self.height, self.tx_count,
                                 self.flush_count))

        txs_per_sec = int(self.tx_count / self.wall_time)
        this_txs_per_sec = int(tx_diff / (self.last_flush - last_flush))
        self.logger.info('tx/s since genesis: {:,d} since last flush: {:,d} '
                         'sync time {}'
                         .format(txs_per_sec, this_txs_per_sec,
                                 self.formatted_wall_time()))

        # Note this preserves semantics and hopefully saves time
        self.read_cache = self.write_cache
        self.write_cache = {}
        self.writes_avoided = 0
        self.read_cache_hits = 0
        self.write_cache_hits = 0

    def flush_to_fs(self):
        '''Flush the things stored on the filesystem.'''
        self.write_headers()
        self.write_tx_counts()
        self.write_tx_hashes()
        os.sync()

    def update_wall_time(self, dest):
        now = time.time()
        self.wall_time += now - self.last_flush
        self.last_flush = now
        dest.put(self.WALL_TIME_KEY, to_4_bytes(int(self.wall_time)))

    def flush_state(self, batch):
        self.db_tx_count = self.tx_count
        self.db_height = self.height + 1
        batch.put(self.HEIGHT_KEY, to_4_bytes(self.db_height))
        batch.put(self.TX_COUNT_KEY, to_4_bytes(self.db_tx_count))
        batch.put(self.FLUSH_COUNT_KEY, to_4_bytes(self.flush_count))
        batch.put(self.TIP_KEY, unhexlify(self.tip))
        self.update_wall_time(batch)
        self.flush_count += 1

    def flush_cache(self, batch):
        '''Flushes the UTXO write cache.'''
        deletes = writes = 0
        for n, (key, value) in enumerate(self.write_cache.items()):
            if value is None:
                batch.delete(key)
                deletes += 1
            else:
                batch.put(key, value)
                writes += 1

        self.logger.info('flushed UTXO cache.  Hits: {:,d}/{:,d} '
                         'writes: {:,d} deletes: {:,d} elided: {:,d}'
                         .format(self.write_cache_hits,
                                 self.read_cache_hits, writes, deletes,
                                 self.writes_avoided))

    def flush_history(self, batch):
        # Drop any None entry
        self.history.pop(None, None)

        flush_id = struct.pack('>H', self.flush_count)
        for hash168, hist in self.history.items():
            key = b'H' + hash168 + flush_id
            batch.put(key, array.array('I', hist).tobytes())

        self.history = defaultdict(list)

    def get_hash168(self, tx_hash, idx, delete=True):
        key = b'h' + tx_hash[:ADDR_TX_HASH_LEN] + struct.pack('<H', idx)
        data = self.get(key)
        if data is None:
            return None

        if len(data) == 25:
            if delete:
                self.delete(key)
            return data[:21]

        assert len(data) % 25 == 0
        self.hcolls += 1
        if self.hcolls % 1000 == 0:
            self.logger.info('{} total hash168 compressed key collisions'
                             .format(self.hcolls))
        for n in range(0, len(data), 25):
            (tx_num, ) = struct.unpack('<I', data[n+21 : n+25])
            my_hash, height = self.get_tx_hash(tx_num)
            if my_hash == tx_hash:
                if delete:
                    self.put(key, data[:n] + data[n+25:])
                return data[n : n+21]

        raise Exception('could not resolve hash168 collision')

    def spend_utxo(self, prevout):
        hash168 = self.get_hash168(prevout.hash, prevout.n)
        if hash168 is None:
            # This indicates a successful spend of a non-standard script
            # self.logger.info('ignoring spend of non-standard UTXO {}/{:d} '
            #                  'at height {:d}'
            #                  .format(bytes(reversed(prevout.hash)).hex(),
            #                          prevout.n, self.height))
            return None
        key = (b'u' + hash168 + prevout.hash[:UTXO_TX_HASH_LEN]
               + struct.pack('<H', prevout.n))
        data = self.get(key)
        if data is None:
            # Uh-oh, this should not happen.  It may be recoverable...
            self.logger.error('found no UTXO for {} / {:d} key {}'
                             .format(bytes(reversed(prevout.hash)).hex(),
                                     prevout.n, bytes(key).hex()))
            return hash168

        if len(data) == 12:
            (tx_num, ) = struct.unpack('<I', data[:4])
            self.delete(key)
        else:
            # This should almost never happen
            assert len(data) % (4 + 8) == 0
            for n in range(0, len(data), 12):
                (tx_num, ) = struct.unpack('<I', data[n:n+4])
                tx_hash, height = self.get_tx_hash(tx_num)
                if prevout.hash == tx_hash:
                    break
            else:
                raise Exception('could not resolve UTXO key collision')

            data = data[:n] + data[n + 12:]
            self.put(key, data)

        return hash168

    def put_utxo(self, tx_hash, idx, txout):
        pk = ScriptPubKey.from_script(txout.pk_script, self.coin)
        if not pk.hash168:
            return None

        pack = struct.pack
        idxb = pack('<H', idx)
        txcb = pack('<I', self.tx_count)

        # First write the hash168 lookup
        key = b'h' + tx_hash[:ADDR_TX_HASH_LEN] + idxb
        # b''.join avoids this: https://bugs.python.org/issue13298
        value = b''.join((pk.hash168, txcb))
        prior_value = self.get(key)
        if prior_value:   # Should almost never happen
            value += prior_value
        self.put(key, value)

        # Next write the UTXO
        key = b'u' + pk.hash168 + tx_hash[:UTXO_TX_HASH_LEN] + idxb
        value = txcb + pack('<Q', txout.value)
        prior_value = self.get(key)
        if prior_value:   # Should almost never happen
            value += prior_value
        self.put(key, value)

        return pk.hash168

    def open_file(self, filename, truncate=False, create=False):
        try:
            return open(filename, 'wb+' if truncate else 'rb+')
        except FileNotFoundError:
            if create:
                return open(filename, 'wb+')
            raise

    def read_headers(self, height, count):
        header_len = self.coin.HEADER_LEN
        self.headers_file.seek(height * header_len)
        return self.headers_file.read(count * header_len)

    def write_headers(self):
        headers = b''.join(self.headers)
        header_len = self.coin.HEADER_LEN
        assert len(headers) % header_len == 0
        self.headers_file.seek(self.db_height * header_len)
        self.headers_file.write(headers)
        self.headers_file.flush()
        self.headers = []

    def write_tx_counts(self):
        self.txcount_file.seek(self.db_height * self.tx_counts.itemsize)
        self.txcount_file.write(self.tx_counts[self.db_height: self.height + 1])
        self.txcount_file.flush()

    def write_tx_hashes(self):
        hash_blob = b''.join(itertools.chain(*self.tx_hashes))
        assert len(hash_blob) % 32 == 0
        assert self.tx_hash_file_size % 32 == 0
        hashes = memoryview(hash_blob)
        cursor = 0
        file_pos = self.db_tx_count * 32
        while cursor < len(hashes):
            file_num, offset = divmod(file_pos, self.tx_hash_file_size)
            size = min(len(hashes) - cursor, self.tx_hash_file_size - offset)
            filename = 'hashes{:05d}'.format(file_num)
            with self.open_file(filename, create=True) as f:
                f.seek(offset)
                f.write(hashes[cursor:cursor + size])
            cursor += size
            file_pos += size
        self.tx_hashes = []

    def process_block(self, block):
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

        # Flush if we're getting full
        if len(self.write_cache) + len(self.history) > self.flush_size:
            self.flush()

    def process_tx(self, tx_hash, tx):
        hash168s = set()
        if not tx.is_coinbase:
            for txin in tx.inputs:
                hash168s.add(self.spend_utxo(txin.prevout))

        for idx, txout in enumerate(tx.outputs):
            hash168s.add(self.put_utxo(tx_hash, idx, txout))

        for hash168 in hash168s:
            self.history[hash168].append(self.tx_count)

        self.tx_count += 1

    def get_tx_hash(self, tx_num):
        '''Returns the tx_hash and height of a tx number.'''
        height = bisect_right(self.tx_counts, tx_num)

        # Is this on disk or unflushed?
        if height >= self.db_height:
            tx_hashes = self.tx_hashes[height - self.db_height]
            tx_hash = tx_hashes[tx_num - self.tx_counts[height - 1]]
        else:
            file_pos = tx_num * 32
            file_num, offset = divmod(file_pos, self.tx_hash_file_size)
            filename = 'hashes{:05d}'.format(file_num)
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
