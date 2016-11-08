# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Interface to the blockchain database.'''


import array
import ast
import os
import struct
from collections import namedtuple

from server.cache import FSCache, NO_CACHE_ENTRY
from lib.util import LoggedClass
from server.storage import open_db

UTXO = namedtuple("UTXO", "tx_num tx_pos tx_hash height value")

class DB(LoggedClass):
    '''Simple wrapper of the backend database for querying.

    Performs no DB update, though the DB will be cleaned on opening if
    it was shutdown uncleanly.
    '''

    class DBError(Exception):
        pass

    def __init__(self, env):
        super().__init__()
        self.env = env
        self.coin = env.coin

        self.logger.info('switching current directory to {}'
                         .format(env.db_dir))
        os.chdir(env.db_dir)

        # Open DB and metadata files.  Record some of its state.
        db_name = '{}-{}'.format(self.coin.NAME, self.coin.NET)
        self.db = open_db(db_name, env.db_engine)
        if self.db.is_new:
            self.logger.info('created new {} database {}'
                             .format(env.db_engine, db_name))
        else:
            self.logger.info('successfully opened {} database {}'
                             .format(env.db_engine, db_name))

        self.init_state_from_db()
        self.tx_count = self.db_tx_count
        self.height = self.db_height
        self.tip = self.db_tip

        # Cache wrapping the filesystem and redirected functions
        self.fs_cache = FSCache(self.coin, self.height, self.tx_count)
        self.get_tx_hash = self.fs_cache.get_tx_hash
        self.read_headers = self.fs_cache.read_headers

    def init_state_from_db(self):
        if self.db.is_new:
            self.db_height = -1
            self.db_tx_count = 0
            self.db_tip = b'\0' * 32
            self.flush_count = 0
            self.utxo_flush_count = 0
            self.wall_time = 0
            self.first_sync = True
        else:
            state = self.db.get(b'state')
            state = ast.literal_eval(state.decode())
            if state['genesis'] != self.coin.GENESIS_HASH:
                raise self.DBError('DB genesis hash {} does not match coin {}'
                                   .format(state['genesis_hash'],
                                           self.coin.GENESIS_HASH))
            self.db_height = state['height']
            self.db_tx_count = state['tx_count']
            self.db_tip = state['tip']
            self.flush_count = state['flush_count']
            self.utxo_flush_count = state['utxo_flush_count']
            self.wall_time = state['wall_time']
            self.first_sync = state.get('first_sync', True)

    @staticmethod
    def _resolve_limit(limit):
        if limit is None:
            return -1
        assert isinstance(limit, int) and limit >= 0
        return limit

    def get_history(self, hash168, limit=1000):
        '''Generator that returns an unpruned, sorted list of (tx_hash,
        height) tuples of confirmed transactions that touched the address,
        earliest in the blockchain first.  Includes both spending and
        receiving transactions.  By default yields at most 1000 entries.
        Set limit to None to get them all.
        '''
        limit = self._resolve_limit(limit)
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
        limit = self._resolve_limit(limit)
        unpack = struct.unpack
        prefix = b'u' + hash168
        for k, v in self.db.iterator(prefix=prefix):
            (tx_pos,) = unpack('<H', k[-2:])

            for n in range(0, len(v), 12):
                if limit == 0:
                    return
                (tx_num,) = unpack('<I', v[n:n + 4])
                (value,) = unpack('<Q', v[n + 4:n + 12])
                tx_hash, height = self.get_tx_hash(tx_num)
                yield UTXO(tx_num, tx_pos, tx_hash, height, value)
                limit -= 1

    def get_utxos_sorted(self, hash168):
        '''Returns all the UTXOs for an address sorted by height and
        position in the block.'''
        return sorted(self.get_utxos(hash168, limit=None))

    def get_utxo_hash168(self, tx_hash, index):
        '''Returns the hash168 for a UTXO.'''
        hash168 = None
        if 0 <= index <= 65535:
            idx_packed = struct.pack('<H', index)
            hash168 = self.hash168(tx_hash, idx_packed, False)
            if hash168 == NO_CACHE_ENTRY:
                hash168 = None
        return hash168

    def hash168(self, tx_hash, idx_packed):
        '''Return the hash168 paid to by the given TXO.

        Return None if not found.'''
        key = b'h' + tx_hash[:ADDR_TX_HASH_LEN] + idx_packed
        data = self.db.get(key)
        if data is None:
            return None

        if len(data) == 25:
            return data[:21]

        assert len(data) % 25 == 0

        # Resolve the compressed key collision using the TX number
        for n in range(0, len(data), 25):
            tx_num, = struct.unpack('<I', data[n+21:n+25])
            my_hash, height = self.get_tx_hash(tx_num)
            if my_hash == tx_hash:
                return data[n:n+21]

        raise self.DBError('could not resolve hash168 collision')
