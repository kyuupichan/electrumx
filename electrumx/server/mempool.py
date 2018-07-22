# Copyright (c) 2016-2018, Neil Booth
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

import attr

from electrumx.lib.hash import hash_to_hex_str, hex_str_to_hash
from electrumx.lib.util import class_logger
from electrumx.server.db import UTXO


@attr.s(slots=True)
class MemPoolTx(object):
    hash = attr.ib()
    in_pairs = attr.ib()
    out_pairs = attr.ib()
    fee = attr.ib()
    size = attr.ib()


class MemPool(object):
    '''Representation of the daemon's mempool.

    Updated regularly in caught-up state.  Goal is to enable efficient
    response to the value() and transactions() calls.

    To that end we maintain the following maps:

       tx_hash -> MemPoolTx
       hashX   -> set of all tx hashes in which the hashX appears

    A pair is a (hashX, value) tuple.  tx hashes are hex strings.
    '''

    def __init__(self, coin, tasks, daemon, notifications, lookup_utxos):
        self.logger = class_logger(__name__, self.__class__.__name__)
        self.coin = coin
        self.lookup_utxos = lookup_utxos
        self.tasks = tasks
        self.daemon = daemon
        self.notifications = notifications
        self.txs = {}
        self.hashXs = defaultdict(set)  # None can be a key
        self.fee_histogram = defaultdict(int)
        self.cached_compact_histogram = []
        self.histogram_time = 0

    async def _log_stats(self):
        while True:
            self.logger.info(f'{len(self.txs):,d} txs '
                             f'touching {len(self.hashXs):,d} addresses')
            await asyncio.sleep(120)

    async def _synchronize_forever(self):
        while True:
            await asyncio.sleep(5)
            await self._synchronize(False)

    async def _refresh_hashes(self):
        '''Return a (hash set, height) pair when we're sure which height they
        are for.'''
        while True:
            height = self.daemon.cached_height()
            hashes = await self.daemon.mempool_hashes()
            if height == await self.daemon.height():
                return set(hashes), height

    async def _synchronize(self, first_time):
        '''Asynchronously maintain mempool status with daemon.

        Processes the mempool each time the mempool refresh event is
        signalled.
        '''
        unprocessed = {}
        unfetched = set()
        touched = set()
        txs = self.txs
        next_refresh = 0
        fetch_size = 800
        process_some = self._async_process_some(fetch_size // 2)

        while True:
            now = time.time()
            # If processing a large mempool, a block being found might
            # shrink our work considerably, so refresh our view every 20s
            if now > next_refresh:
                hashes, height = await self._refresh_hashes()
                self._resync_hashes(hashes, unprocessed, unfetched, touched)
                next_refresh = time.time() + 20

            # Log progress of initial sync
            todo = len(unfetched) + len(unprocessed)
            if first_time:
                pct = (len(txs) - todo) * 100 // len(txs) if txs else 0
                self.logger.info(f'catchup {pct:d}% complete '
                                 f'({todo:,d} txs left)')
            if not todo:
                break

            # FIXME: parallelize
            if unfetched:
                count = min(len(unfetched), fetch_size)
                hex_hashes = [unfetched.pop() for n in range(count)]
                unprocessed.update(await self._fetch_raw_txs(hex_hashes))
            if unprocessed:
                await process_some(unprocessed, touched)

        await self.notifications.on_mempool(touched, height)

    def _resync_hashes(self, hashes, unprocessed, unfetched, touched):
        '''Re-sync self.txs with the list of hashes in the daemon's mempool.

        Additionally, remove gone hashes from unprocessed and
        unfetched.  Add new ones to unprocessed.
        '''
        txs = self.txs
        hashXs = self.hashXs
        fee_hist = self.fee_histogram
        gone = set(txs).difference(hashes)
        for hex_hash in gone:
            unfetched.discard(hex_hash)
            unprocessed.pop(hex_hash, None)
            tx = txs.pop(hex_hash)
            if tx:
                fee_rate = tx.fee // tx.size
                fee_hist[fee_rate] -= tx.size
                if fee_hist[fee_rate] == 0:
                    fee_hist.pop(fee_rate)
                tx_hashXs = set(hashX for hashX, value in tx.in_pairs)
                tx_hashXs.update(hashX for hashX, value in tx.out_pairs)
                for hashX in tx_hashXs:
                    hashXs[hashX].remove(hex_hash)
                    if not hashXs[hashX]:
                        del hashXs[hashX]
                touched.update(tx_hashXs)

        new = hashes.difference(txs)
        unfetched.update(new)
        for hex_hash in new:
            txs[hex_hash] = None

    def _async_process_some(self, limit):
        pending = []
        txs = self.txs

        async def process(unprocessed, touched):
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

            deferred = await self._process_raw_txs(raw_txs, deferred, touched)
            pending.extend(deferred)

        return process

    async def _fetch_raw_txs(self, hex_hashes):
        '''Fetch a list of mempool transactions.'''
        raw_txs = await self.daemon.getrawtransactions(hex_hashes)

        # Skip hashes the daemon has dropped.  Either they were
        # evicted or they got in a block.
        return {hh: raw for hh, raw in zip(hex_hashes, raw_txs) if raw}

    async def _process_raw_txs(self, raw_tx_map, pending, touched):
        '''Process the dictionary of raw transactions and return a dictionary
        of updates to apply to self.txs.
        '''
        def deserialize_txs():
            script_hashX = self.coin.hashX_from_script
            deserializer = self.coin.DESERIALIZER

            # Deserialize each tx and put it in a pending list
            for tx_hash, raw_tx in raw_tx_map.items():
                tx, tx_size = deserializer(raw_tx).read_tx_and_vsize()

                # Convert the tx outputs into (hashX, value) pairs
                txout_pairs = [(script_hashX(txout.pk_script), txout.value)
                               for txout in tx.outputs]

                # Convert the tx inputs to ([prev_hex_hash, prev_idx) pairs
                txin_pairs = [(hash_to_hex_str(txin.prev_hash), txin.prev_idx)
                              for txin in tx.inputs]

                pending.append(MemPoolTx(tx_hash, txin_pairs, txout_pairs,
                                         0, tx_size))

        # Do this potentially slow operation in a thread so as not to
        # block
        await self.tasks.run_in_thread(deserialize_txs)

        # The transaction inputs can be from other mempool
        # transactions (which may or may not be processed yet) or are
        # otherwise presumably in the DB.
        txs = self.txs
        db_prevouts = [(hex_str_to_hash(prev_hash), prev_idx)
                       for tx in pending
                       for (prev_hash, prev_idx) in tx.in_pairs
                       if prev_hash not in txs]

        # If a lookup fails, it returns a None entry
        db_utxos = await self.lookup_utxos(db_prevouts)
        db_utxo_map = {(hash_to_hex_str(prev_hash), prev_idx): db_utxo
                       for (prev_hash, prev_idx), db_utxo
                       in zip(db_prevouts, db_utxos)}

        deferred = []
        hashXs = self.hashXs
        fee_hist = self.fee_histogram

        for tx in pending:
            if tx.hash not in txs:
                continue

            in_pairs = []
            try:
                for previn in tx.in_pairs:
                    utxo = db_utxo_map.get(previn)
                    if not utxo:
                        prev_hash, prev_index = previn
                        # This can raise a KeyError or TypeError
                        utxo = txs[prev_hash][1][prev_index]
                    in_pairs.append(utxo)
            except (KeyError, TypeError):
                deferred.append(tx)
                continue

            tx.in_pairs = in_pairs
            # Compute fee
            tx_fee = (sum(v for hashX, v in tx.in_pairs) -
                      sum(v for hashX, v in tx.out_pairs))
            fee_rate = tx.fee // tx.size
            fee_hist[fee_rate] += tx.size
            txs[tx.hash] = tx
            for hashX, value in itertools.chain(tx.in_pairs, tx.out_pairs):
                touched.add(hashX)
                hashXs[hashX].add(tx.hash)

        return deferred

    async def _raw_transactions(self, hashX):
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

    def _calc_compact_histogram(self):
        # For efficiency, get_fees returns a compact histogram with
        # variable bin size.  The compact histogram is an array of
        # (fee, vsize) values.  vsize_n is the cumulative virtual size
        # of mempool transactions with a fee rate in the interval
        # [fee_(n-1), fee_n)], and fee_(n-1) > fee_n. Fee intervals
        # are chosen so as to create tranches that contain at least
        # 100kb of transactions
        out = []
        size = 0
        r = 0
        binsize = 100000
        for fee, s in sorted(self.fee_histogram.items(), reverse=True):
            size += s
            if size + r > binsize:
                out.append((fee, size))
                r += size - binsize
                size = 0
                binsize *= 1.1
        return out

    # External interface
    async def start_and_wait_for_sync(self):
        '''Starts the mempool synchronizer.

        Waits for an initial synchronization before returning.
        '''
        self.logger.info('beginning processing of daemon mempool.  '
                         'This can take some time...')
        await self._synchronize(True)
        self.tasks.create_task(self._log_stats())
        self.tasks.create_task(self._synchronize_forever())

    async def balance_delta(self, hashX):
        '''Return the unconfirmed amount in the mempool for hashX.

        Can be positive or negative.
        '''
        value = 0
        # hashXs is a defaultdict
        if hashX in self.hashXs:
            for hex_hash in self.hashXs[hashX]:
                tx = self.txs[hex_hash]
                value -= sum(v for h168, v in tx.in_pairs if h168 == hashX)
                value += sum(v for h168, v in tx.out_pairs if h168 == hashX)
        return value

    async def compact_fee_histogram(self):
        '''Return a compact fee histogram of the current mempool.'''
        now = time.time()
        if now > self.histogram_time:
            self.histogram_time = now + 30
            self.cached_compact_histogram = self._calc_compact_histogram()
        return self.cached_compact_histogram

    async def potential_spends(self, hashX):
        '''Return a set of (prev_hash, prev_idx) pairs from mempool
        transactions that touch hashX.

        None, some or all of these may be spends of the hashX.
        '''
        deserializer = self.coin.DESERIALIZER
        pairs = await self._raw_transactions(hashX)
        result = set()
        for hex_hash, raw_tx in pairs:
            if not raw_tx:
                continue
            tx = deserializer(raw_tx).read_tx()
            for txin in tx.inputs:
                result.add((txin.prev_hash, txin.prev_idx))
        return result

    async def transaction_summaries(self, hashX):
        '''Return a list of (tx_hex_hash, tx_fee, unconfirmed) tuples for
        mempool entries for the hashX.

        unconfirmed is True if any txin is unconfirmed.
        '''
        deserializer = self.coin.DESERIALIZER
        pairs = await self._raw_transactions(hashX)
        result = []
        for hex_hash, raw_tx in pairs:
            mempool_tx = self.txs.get(hex_hash)
            if not mempool_tx or not raw_tx:
                continue
            tx = deserializer(raw_tx).read_tx()
            unconfirmed = any(hash_to_hex_str(txin.prev_hash) in self.txs
                              for txin in tx.inputs)
            result.append((hex_hash, mempool_tx.fee, unconfirmed))
        return result

    async def unordered_UTXOs(self, hashX):
        '''Return an unordered list of UTXO named tuples from mempool
        transactions that pay to hashX.

        This does not consider if any other mempool transactions spend
        the outputs.
        '''
        utxos = []
        # hashXs is a defaultdict, so use get() to query
        for hex_hash in self.hashXs.get(hashX, []):
            tx = self.txs.get(hex_hash)
            if not tx:
                continue
            for pos, (hX, value) in enumerate(tx.out_pairs):
                if hX == hashX:
                    # Unfortunately UTXO holds a binary hash
                    utxos.append(UTXO(-1, pos, hex_str_to_hash(hex_hash),
                                      0, value))
        return utxos
