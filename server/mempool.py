# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Mempool handling.'''

import asyncio
import itertools
import logging
import time
from collections import defaultdict

from lib.hash import hash_to_str, hex_str_to_hash
from server.daemon import DaemonError
from server.db import UTXO


class MemPool(object):
    '''Representation of the daemon's mempool.

    Updated regularly in caught-up state.  Goal is to enable efficient
    response to the value() and transactions() calls.

    To that end we maintain the following maps:

       tx_hash -> (txin_pairs, txout_pairs, tx_fee, tx_size)
       hashX   -> set of all tx hashes in which the hashX appears

    A pair is a (hashX, value) tuple.  tx hashes are hex strings.
    '''

    def __init__(self, bp, controller):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.daemon = bp.daemon
        self.controller = controller
        self.coin = bp.coin
        self.db = bp
        self.touched = set()
        self.stop = False
        self.txs = {}
        self.hashXs = defaultdict(set)  # None can be a key
        self.synchronized_event = asyncio.Event()
        self.fee_histogram = defaultdict(int)
        self.compact_fee_histogram = []
        self.histogram_time = 0

    def _resync_daemon_hashes(self, unprocessed, unfetched):
        '''Re-sync self.txs with the list of hashes in the daemon's mempool.

        Additionally, remove gone hashes from unprocessed and
        unfetched.  Add new ones to unprocessed.
        '''
        txs = self.txs
        hashXs = self.hashXs
        touched = self.touched
        fee_hist = self.fee_histogram

        hashes = self.daemon.cached_mempool_hashes()
        gone = set(txs).difference(hashes)
        for hex_hash in gone:
            unfetched.discard(hex_hash)
            unprocessed.pop(hex_hash, None)
            item = txs.pop(hex_hash)
            if item:
                txin_pairs, txout_pairs, tx_fee, tx_size = item
                fee_rate = tx_fee // tx_size
                fee_hist[fee_rate] -= tx_size
                if fee_hist[fee_rate] == 0:
                    fee_hist.pop(fee_rate)
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
        process_some = self._async_process_some(fetch_size // 2)

        self.logger.info('beginning processing of daemon mempool.  '
                         'This can take some time...')
        await self.daemon.mempool_refresh_event.wait()
        next_log = 0
        loops = -1  # Zero during initial catchup

        while True:
            # Avoid double notifications if processing a block
            if self.touched and not self.processing_new_block():
                self.controller.notify_sessions(self.touched)
                self.touched.clear()

            # Log progress / state
            todo = len(unfetched) + len(unprocessed)
            if loops == 0:
                pct = (len(txs) - todo) * 100 // len(txs) if txs else 0
                self.logger.info('catchup {:d}% complete '
                                 '({:,d} txs left)'.format(pct, todo))
            if not todo:
                loops += 1
                if loops > 0:
                    self.synchronized_event.set()
                now = time.time()
                if now >= next_log and loops:
                    self.logger.info('{:,d} txs touching {:,d} addresses'
                                     .format(len(txs), len(self.hashXs)))
                    next_log = now + 150

            try:
                if not todo:
                    await self.daemon.mempool_refresh_event.wait()

                self._resync_daemon_hashes(unprocessed, unfetched)
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

    def _async_process_some(self, limit):
        pending = []
        txs = self.txs
        fee_hist = self.fee_histogram

        async def process(unprocessed):
            nonlocal pending

            raw_txs = {}

            while unprocessed and len(raw_txs) < limit:
                hex_hash, raw_tx = unprocessed.popitem()
                raw_txs[hex_hash] = raw_tx

            if unprocessed:
                deferred = []
            else:
                deferred = pending
                pending = []

            result, deferred = await self.controller.run_in_executor(
                self.process_raw_txs, raw_txs, deferred)

            pending.extend(deferred)
            hashXs = self.hashXs
            touched = self.touched
            for hex_hash, item in result.items():
                if hex_hash in txs:
                    txs[hex_hash] = item
                    txin_pairs, txout_pairs, tx_fee, tx_size = item
                    fee_rate = tx_fee // tx_size
                    fee_hist[fee_rate] += tx_size
                    for hashX, value in itertools.chain(txin_pairs, txout_pairs):
                        touched.add(hashX)
                        hashXs[hashX].add(hex_hash)

        return process

    def on_new_block(self, touched):
        '''Called after processing one or more new blocks.

        Touched is a set of hashXs touched by the transactions in the
        block.  Caller must be aware it is modified by this function.
        '''
        # Minor race condition here with mempool processor thread
        touched.update(self.touched)
        self.touched.clear()
        self.controller.notify_sessions(touched)

    def processing_new_block(self):
        '''Return True if we're processing a new block.'''
        return self.daemon.cached_height() > self.db.db_height

    async def fetch_raw_txs(self, hex_hashes):
        '''Fetch a list of mempool transactions.'''
        raw_txs = await self.daemon.getrawtransactions(hex_hashes)

        # Skip hashes the daemon has dropped.  Either they were
        # evicted or they got in a block.
        return {hh: raw for hh, raw in zip(hex_hashes, raw_txs) if raw}

    def process_raw_txs(self, raw_tx_map, pending):
        '''Process the dictionary of raw transactions and return a dictionary
        of updates to apply to self.txs.

        This runs in the executor so should not update any member
        variables it doesn't own.  Atomic reads of self.txs that do
        not depend on the result remaining the same are fine.
        '''
        script_hashX = self.coin.hashX_from_script
        deserializer = self.coin.DESERIALIZER
        db_utxo_lookup = self.db.db_utxo_lookup
        txs = self.txs

        # Deserialize each tx and put it in a pending list
        for tx_hash, raw_tx in raw_tx_map.items():
            if tx_hash not in txs:
                continue
            tx, tx_size = deserializer(raw_tx).read_tx_and_vsize()

            # Convert the tx outputs into (hashX, value) pairs
            txout_pairs = [(script_hashX(txout.pk_script), txout.value)
                           for txout in tx.outputs]

            # Convert the tx inputs to ([prev_hex_hash, prev_idx) pairs
            txin_pairs = [(hash_to_str(txin.prev_hash), txin.prev_idx)
                          for txin in tx.inputs]

            pending.append((tx_hash, txin_pairs, txout_pairs, tx_size))

        # Now process what we can
        result = {}
        deferred = []

        for item in pending:
            if self.stop:
                break

            tx_hash, old_txin_pairs, txout_pairs, tx_size = item
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
                # Compute fee
                tx_fee = (sum(v for hashX, v in txin_pairs) -
                          sum(v for hashX, v in txout_pairs))
                result[tx_hash] = (txin_pairs, txout_pairs, tx_fee, tx_size)

        return result, deferred

    async def raw_transactions(self, hashX):
        '''Returns an iterable of (hex_hash, raw_tx) pairs for all
        transactions in the mempool that touch hashX.

        raw_tx can be None if the transaction has left the mempool.
        '''
        # hashXs is a defaultdict
        if hashX not in self.hashXs:
            return []

        hex_hashes = self.hashXs[hashX]
        raw_txs = await self.daemon.getrawtransactions(hex_hashes)
        return zip(hex_hashes, raw_txs)

    async def transactions(self, hashX):
        '''Generate (hex_hash, tx_fee, unconfirmed) tuples for mempool
        entries for the hashX.

        unconfirmed is True if any txin is unconfirmed.
        '''
        deserializer = self.coin.DESERIALIZER
        pairs = await self.raw_transactions(hashX)
        result = []
        for hex_hash, raw_tx in pairs:
            item = self.txs.get(hex_hash)
            if not item or not raw_tx:
                continue
            tx_fee = item[2]
            tx = deserializer(raw_tx).read_tx()
            unconfirmed = any(hash_to_str(txin.prev_hash) in self.txs
                              for txin in tx.inputs)
            result.append((hex_hash, tx_fee, unconfirmed))
        return result

    def get_utxos(self, hashX):
        '''Return an unordered list of UTXO named tuples from mempool
        transactions that pay to hashX.

        This does not consider if any other mempool transactions spend
        the outputs.
        '''
        utxos = []
        # hashXs is a defaultdict, so use get() to query
        for hex_hash in self.hashXs.get(hashX, []):
            item = self.txs.get(hex_hash)
            if not item:
                continue
            txout_pairs = item[1]
            for pos, (hX, value) in enumerate(txout_pairs):
                if hX == hashX:
                    # Unfortunately UTXO holds a binary hash
                    utxos.append(UTXO(-1, pos, hex_str_to_hash(hex_hash),
                                      0, value))
        return utxos

    async def potential_spends(self, hashX):
        '''Return a set of (prev_hash, prev_idx) pairs from mempool
        transactions that touch hashX.

        None, some or all of these may be spends of the hashX.
        '''
        deserializer = self.coin.DESERIALIZER
        pairs = await self.raw_transactions(hashX)
        result = set()
        for hex_hash, raw_tx in pairs:
            if not raw_tx:
                continue
            tx = deserializer(raw_tx).read_tx()
            for txin in tx.inputs:
                result.add((txin.prev_hash, txin.prev_idx))
        return result

    def value(self, hashX):
        '''Return the unconfirmed amount in the mempool for hashX.

        Can be positive or negative.
        '''
        value = 0
        # hashXs is a defaultdict
        if hashX in self.hashXs:
            for hex_hash in self.hashXs[hashX]:
                txin_pairs, txout_pairs, tx_fee, tx_size = self.txs[hex_hash]
                value -= sum(v for h168, v in txin_pairs if h168 == hashX)
                value += sum(v for h168, v in txout_pairs if h168 == hashX)
        return value

    def get_fee_histogram(self):
        now = time.time()
        if now > self.histogram_time + 30:
            self.update_compact_histogram()
            self.histogram_time = now
        return self.compact_fee_histogram

    def update_compact_histogram(self):
        # For efficiency, get_fees returns a compact histogram with
        # variable bin size.  The compact histogram is an array of
        # (fee, vsize) values.  vsize_n is the cumulative virtual size
        # of mempool transactions with a fee rate in the interval
        # [fee_(n-1), fee_n)], and fee_(n-1) > fee_n. Fee intervals
        # are chosen so as to create tranches that contain at least
        # 100kb of transactions
        l = list(reversed(sorted(self.fee_histogram.items())))
        out = []
        size = 0
        r = 0
        binsize = 100000
        for fee, s in l:
            size += s
            if size + r > binsize:
                out.append((fee, size))
                r += size - binsize
                size = 0
                binsize *= 1.1
        self.compact_fee_histogram = out
