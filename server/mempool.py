# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Mempool handling.'''

import asyncio
import itertools
import time
from collections import defaultdict

from lib.hash import hash_to_str, hex_str_to_hash
import lib.util as util
from server.daemon import DaemonError


class MemPool(util.LoggedClass):
    '''Representation of the daemon's mempool.

    Updated regularly in caught-up state.  Goal is to enable efficient
    response to the value() and transactions() calls.

    To that end we maintain the following maps:

       tx_hash -> (txin_pairs, txout_pairs)
       hashX   -> set of all tx hashes in which the hashX appears

    A pair is a (hashX, value) tuple.  tx hashes are hex strings.
    '''

    def __init__(self, daemon, coin, db):
        super().__init__()
        self.daemon = daemon
        self.coin = coin
        self.db = db
        self.touched = set()
        self.touched_event = asyncio.Event()
        self.prioritized = set()
        self.stop = False
        self.txs = {}
        self.hashXs = defaultdict(set)  # None can be a key

    def prioritize(self, tx_hash):
        '''Prioritize processing the given hash.  This is important during
        initial mempool sync.'''
        self.prioritized.add(tx_hash)

    def resync_daemon_hashes(self, unprocessed, unfetched):
        '''Re-sync self.txs with the list of hashes in the daemon's mempool.

        Additionally, remove gone hashes from unprocessed and
        unfetched.  Add new ones to unprocessed.
        '''
        txs = self.txs
        hashXs = self.hashXs
        touched = self.touched

        hashes = self.daemon.cached_mempool_hashes()
        gone = set(txs).difference(hashes)
        for hex_hash in gone:
            unfetched.discard(hex_hash)
            unprocessed.pop(hex_hash, None)
            item = txs.pop(hex_hash)
            if item:
                txin_pairs, txout_pairs = item
                tx_hashXs = set(hashX for hashX, value in txin_pairs)
                tx_hashXs.update(hashX for hashX, value in txout_pairs)
                for hashX in tx_hashXs:
                    hashXs[hashX].remove(hex_hash)
                    if not hashXs[hashX]:
                        del hashXs[hashX]
                touched.update(tx_hashXs)

        new = hashes.difference(txs)
        unfetched.update(new)
        for hex_hash in new:
            txs[hex_hash] = None

    async def main_loop(self):
        '''Asynchronously maintain mempool status with daemon.

        Processes the mempool each time the daemon's mempool refresh
        event is signalled.
        '''
        unprocessed = {}
        unfetched = set()
        txs = self.txs
        fetch_size = 800
        process_some = self.async_process_some(unfetched, fetch_size // 2)

        await self.daemon.mempool_refresh_event.wait()
        self.logger.info ('beginning processing of daemon mempool.  '
                          'This can take some time...')
        next_log = 0
        loops = -1  # Zero during initial catchup

        while True:
            # Avoid double notifications if processing a block
            if self.touched and not self.processing_new_block():
                self.touched_event.set()

            # Log progress / state
            todo = len(unfetched) + len(unprocessed)
            if loops == 0:
                pct = (len(txs) - todo) * 100 // len(txs) if txs else 0
                self.logger.info('catchup {:d}% complete '
                                 '({:,d} txs left)'.format(pct, todo))
            if not todo:
                loops += 1
                now = time.time()
                if now >= next_log and loops:
                    self.logger.info('{:,d} txs touching {:,d} addresses'
                                     .format(len(txs), len(self.hashXs)))
                    next_log = now + 150

            try:
                if not todo:
                    self.prioritized.clear()
                    await self.daemon.mempool_refresh_event.wait()

                self.resync_daemon_hashes(unprocessed, unfetched)
                self.daemon.mempool_refresh_event.clear()

                if unfetched:
                    count = min(len(unfetched), fetch_size)
                    hex_hashes = [unfetched.pop() for n in range(count)]
                    unprocessed.update(await self.fetch_raw_txs(hex_hashes))

                if unprocessed:
                    await process_some(unprocessed)
            except DaemonError as e:
                self.logger.info('ignoring daemon error: {}'.format(e))
            except asyncio.CancelledError:
                # This aids clean shutdowns
                self.stop = True
                break

    def async_process_some(self, unfetched, limit):
        loop = asyncio.get_event_loop()
        pending = []
        txs = self.txs

        async def process(unprocessed):
            nonlocal pending

            raw_txs = {}

            for hex_hash in self.prioritized:
                if hex_hash in unprocessed:
                    raw_txs[hex_hash] = unprocessed.pop(hex_hash)

            while unprocessed and len(raw_txs) < limit:
                hex_hash, raw_tx = unprocessed.popitem()
                raw_txs[hex_hash] = raw_tx

            if unprocessed:
                deferred = []
            else:
                deferred = pending
                pending = []

            def job():
                return self.process_raw_txs(raw_txs, deferred)
            result, deferred = await loop.run_in_executor(None, job)

            pending.extend(deferred)
            hashXs = self.hashXs
            touched = self.touched
            for hex_hash, in_out_pairs in result.items():
                if hex_hash in txs:
                    txs[hex_hash] = in_out_pairs
                    for hashX, value in itertools.chain(*in_out_pairs):
                        touched.add(hashX)
                        hashXs[hashX].add(hex_hash)

        return process

    def processing_new_block(self):
        '''Return True if we're processing a new block.'''
        return self.daemon.cached_height() > self.db.db_height

    async def fetch_raw_txs(self, hex_hashes):
        '''Fetch a list of mempool transactions.'''
        raw_txs = await self.daemon.getrawtransactions(hex_hashes)

        # Skip hashes the daemon has dropped.  Either they were
        # evicted or they got in a block.
        return {hh:raw for hh, raw in zip(hex_hashes, raw_txs) if raw}

    def process_raw_txs(self, raw_tx_map, pending):
        '''Process the dictionary of raw transactions and return a dictionary
        of updates to apply to self.txs.

        This runs in the executor so should not update any member
        variables it doesn't own.  Atomic reads of self.txs that do
        not depend on the result remaining the same are fine.
        '''
        script_hashX = self.coin.hashX_from_script
        deserializer = self.coin.deserializer()
        db_utxo_lookup = self.db.db_utxo_lookup
        txs = self.txs

        # Deserialize each tx and put it in our priority queue
        for tx_hash, raw_tx in raw_tx_map.items():
            if not tx_hash in txs:
                continue
            tx, _tx_hash = deserializer(raw_tx).read_tx()

            # Convert the tx outputs into (hashX, value) pairs
            txout_pairs = [(script_hashX(txout.pk_script), txout.value)
                           for txout in tx.outputs]

            # Convert the tx inputs to ([prev_hex_hash, prev_idx) pairs
            txin_pairs = [(hash_to_str(txin.prev_hash), txin.prev_idx)
                          for txin in tx.inputs]

            pending.append((tx_hash, txin_pairs, txout_pairs))

        # Now process what we can
        result = {}
        deferred = []

        for item in pending:
            if self.stop:
                break

            tx_hash, old_txin_pairs, txout_pairs = item
            if tx_hash not in txs:
                continue

            mempool_missing = False
            txin_pairs = []

            try:
                for prev_hex_hash, prev_idx in old_txin_pairs:
                    tx_info = txs.get(prev_hex_hash, 0)
                    if tx_info is None:
                        tx_info = result.get(prev_hex_hash)
                        if not tx_info:
                            mempool_missing = True
                            continue
                    if tx_info:
                        txin_pairs.append(tx_info[1][prev_idx])
                    elif not mempool_missing:
                        prev_hash = hex_str_to_hash(prev_hex_hash)
                        txin_pairs.append(db_utxo_lookup(prev_hash, prev_idx))
            except (self.db.MissingUTXOError, self.db.DBError):
                # DBError can happen when flushing a newly processed
                # block.  MissingUTXOError typically happens just
                # after the daemon has accepted a new block and the
                # new mempool has deps on new txs in that block.
                continue

            if mempool_missing:
                deferred.append(item)
            else:
                result[tx_hash] = (txin_pairs, txout_pairs)

        return result, deferred

    async def transactions(self, hashX):
        '''Generate (hex_hash, tx_fee, unconfirmed) tuples for mempool
        entries for the hashX.

        unconfirmed is True if any txin is unconfirmed.
        '''
        # hashXs is a defaultdict
        if not hashX in self.hashXs:
            return []

        deserializer = self.coin.deserializer()
        hex_hashes = self.hashXs[hashX]
        raw_txs = await self.daemon.getrawtransactions(hex_hashes)
        result = []
        for hex_hash, raw_tx in zip(hex_hashes, raw_txs):
            item = self.txs.get(hex_hash)
            if not item or not raw_tx:
                continue
            txin_pairs, txout_pairs = item
            tx_fee = (sum(v for hashX, v in txin_pairs)
                      - sum(v for hashX, v in txout_pairs))
            tx, tx_hash = deserializer(raw_tx).read_tx()
            unconfirmed = any(txin.prev_hash in self.txs for txin in tx.inputs)
            result.append((hex_hash, tx_fee, unconfirmed))
        return result

    def value(self, hashX):
        '''Return the unconfirmed amount in the mempool for hashX.

        Can be positive or negative.
        '''
        value = 0
        # hashXs is a defaultdict
        if hashX in self.hashXs:
            for hex_hash in self.hashXs[hashX]:
                txin_pairs, txout_pairs = self.txs[hex_hash]
                value -= sum(v for h168, v in txin_pairs if h168 == hashX)
                value += sum(v for h168, v in txout_pairs if h168 == hashX)
        return value
