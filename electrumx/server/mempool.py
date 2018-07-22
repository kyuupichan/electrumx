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
from electrumx.lib.util import class_logger, chunks
from electrumx.server.db import UTXO


@attr.s(slots=True)
class MemPoolTx(object):
    in_pairs = attr.ib()
    out_pairs = attr.ib()
    fee = attr.ib()
    size = attr.ib()


class MemPool(object):
    '''Representation of the daemon's mempool.

    Updated regularly in caught-up state.  Goal is to enable efficient
    response to the value() and transactions() calls.

    To that end we maintain the following maps:

       tx_hash -> MemPoolTx  (in_paris
       hashX   -> set of all tx hashes in which the hashX appears

    A pair is a (hashX, value) tuple.  tx hashes are binary not strings.
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

    def _accept_transactions(self, tx_map, utxo_map, touched):
        '''Accept transactions in tx_map to the mempool if all their inputs
        can be found in the existing mempool or a utxo_map from the
        DB.

        Returns an (unprocessed tx_map, unspent utxo_map) pair.
        '''
        hashXs = self.hashXs
        txs = self.txs
        fee_hist = self.fee_histogram
        init_count = len(utxo_map)

        deferred = {}
        unspent = set(utxo_map)
        # Try to find all previns so we can accept the TX
        for hash, tx in tx_map.items():
            in_pairs = []
            try:
                for previn in tx.in_pairs:
                    utxo = utxo_map.get(previn)
                    if not utxo:
                        prev_hash, prev_index = previn
                        # Raises KeyError if prev_hash is not in txs
                        utxo = txs[prev_hash].out_pairs[prev_index]
                    in_pairs.append(utxo)
            except KeyError:
                deferred[hash] = tx
                continue

            # Spend the previns
            unspent.difference_update(tx.in_pairs)

            # Convert in_pairs and add the TX to
            tx.in_pairs = in_pairs
            # Compute fee
            tx_fee = (sum(v for hashX, v in tx.in_pairs) -
                      sum(v for hashX, v in tx.out_pairs))
            fee_rate = tx.fee // tx.size
            fee_hist[fee_rate] += tx.size
            txs[hash] = tx
            for hashX, value in itertools.chain(tx.in_pairs, tx.out_pairs):
                touched.add(hashX)
                hashXs[hashX].add(hash)

        return deferred, {previn: utxo_map[previn] for previn in unspent}

    async def _refresh_hashes(self, single_pass):
        '''Return a (hash set, height) pair when we're sure which height they
        are for.'''
        refresh_event = asyncio.Event()
        loop = self.tasks.loop
        while True:
            height = self.daemon.cached_height()
            hex_hashes = await self.daemon.mempool_hashes()
            if height != await self.daemon.height():
                continue
            loop.call_later(5, refresh_event.set)
            hashes = set(hex_str_to_hash(hh) for hh in hex_hashes)
            touched = await self._process_mempool(hashes)
            await self.notifications.on_mempool(touched, height)
            if single_pass:
                return
            await refresh_event.wait()
            refresh_event.clear()

    async def _process_mempool(self, all_hashes):
        # Re-sync with the new set of hashes
        txs = self.txs
        hashXs = self.hashXs
        touched = set()
        fee_hist = self.fee_histogram

        # First handle txs that have disappeared
        for tx_hash in set(txs).difference(all_hashes):
            tx = txs.pop(tx_hash)
            fee_rate = tx.fee // tx.size
            fee_hist[fee_rate] -= tx.size
            if fee_hist[fee_rate] == 0:
                fee_hist.pop(fee_rate)
            tx_hashXs = set(hashX for hashX, value in tx.in_pairs)
            tx_hashXs.update(hashX for hashX, value in tx.out_pairs)
            for hashX in tx_hashXs:
                hashXs[hashX].remove(tx_hash)
                if not hashXs[hashX]:
                    del hashXs[hashX]
            touched.update(tx_hashXs)

        # Process new transactions
        new_hashes = list(all_hashes.difference(txs))
        jobs = [self.tasks.create_task(self._fetch_and_accept
                                       (hashes, all_hashes, touched))
                for hashes in chunks(new_hashes, 2000)]
        if jobs:
            await asyncio.wait(jobs)
            tx_map = {}
            utxo_map = {}
            for job in jobs:
                deferred, unspent = job.result()
                tx_map.update(deferred)
                utxo_map.update(unspent)

            # Handle the stragglers
            if len(tx_map) >= 10:
                self.logger.info(f'{len(tx_map)} stragglers')
            prior_count = 0
            # FIXME: this is not particularly efficient
            while tx_map and len(tx_map) != prior_count:
                prior_count = len(tx_map)
                tx_map, utxo_map = self._accept_transactions(tx_map, utxo_map,
                                                             touched)
            if tx_map:
                self.logger.info(f'{len(tx_map)} txs dropped')

        return touched

    async def _fetch_and_accept(self, hashes, all_hashes, touched):
        '''Fetch a list of mempool transactions.'''
        hex_hashes = [hash_to_hex_str(hash) for hash in hashes]
        raw_txs = await self.daemon.getrawtransactions(hex_hashes)
        count = len([raw_tx for raw_tx in raw_txs if raw_tx])

        def deserialize_txs():
            # This function is pure
            script_hashX = self.coin.hashX_from_script
            deserializer = self.coin.DESERIALIZER

            txs = {}
            for hash, raw_tx in zip(hashes, raw_txs):
                # The daemon may have evicted the tx from its
                # mempool or it may have gotten in a block
                if not raw_tx:
                    continue
                tx, tx_size = deserializer(raw_tx).read_tx_and_vsize()

                # Convert the tx outputs into (hashX, value) pairs
                txout_pairs = [(script_hashX(txout.pk_script), txout.value)
                               for txout in tx.outputs]

                # Convert the tx inputs to (prev_hash, prev_idx) pairs
                txin_pairs = [(txin.prev_hash, txin.prev_idx)
                              for txin in tx.inputs]

                txs[hash] = MemPoolTx(txin_pairs, txout_pairs, 0, tx_size)
            return txs

        # Thread this potentially slow operation so as not to block
        tx_map = await self.tasks.run_in_thread(deserialize_txs)

        # Determine all prevouts not in the mempool, and fetch the
        # UTXO information from the database.  Failed prevout lookups
        # return None - concurrent database updates happen
        prevouts = [tx_in for tx in tx_map.values()for tx_in in tx.in_pairs
                    if tx_in[0] not in all_hashes]
        utxos = await self.lookup_utxos(prevouts)
        utxo_map = {prevout: utxo for prevout, utxo in zip(prevouts, utxos)}

        # Attempt to complete processing of txs
        return self._accept_transactions(tx_map, utxo_map, touched)

    async def _raw_transactions(self, hashX):
        '''Returns an iterable of (hex_hash, raw_tx) pairs for all
        transactions in the mempool that touch hashX.

        raw_tx can be None if the transaction has left the mempool.
        '''
        # hashXs is a defaultdict
        if hashX not in self.hashXs:
            return []

        hashes = self.hashXs[hashX]
        hex_hashes = [hash_to_hex_str(hash) for hash in hashes]
        raw_txs = await self.daemon.getrawtransactions(hex_hashes)
        return zip(hashes, raw_txs)

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
        start = time.time()
        await self._refresh_hashes(True)
        elapsed = time.time() - start
        self.logger.info(f'synced in {elapsed:.2f}s')
        self.tasks.create_task(self._log_stats())
        self.tasks.create_task(self._refresh_hashes(False))

    async def balance_delta(self, hashX):
        '''Return the unconfirmed amount in the mempool for hashX.

        Can be positive or negative.
        '''
        value = 0
        # hashXs is a defaultdict
        if hashX in self.hashXs:
            for hash in self.hashXs[hashX]:
                tx = self.txs[hash]
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
        for hash, raw_tx in pairs:
            if not raw_tx:
                continue
            tx = deserializer(raw_tx).read_tx()
            for txin in tx.inputs:
                result.add((txin.prev_hash, txin.prev_idx))
        return result

    async def transaction_summaries(self, hashX):
        '''Return a list of (tx_hash, tx_fee, unconfirmed) tuples for
        mempool entries for the hashX.

        unconfirmed is True if any txin is unconfirmed.
        '''
        deserializer = self.coin.DESERIALIZER
        pairs = await self._raw_transactions(hashX)
        result = []
        for tx_hash, raw_tx in pairs:
            mempool_tx = self.txs.get(tx_hash)
            if not mempool_tx or not raw_tx:
                continue
            tx = deserializer(raw_tx).read_tx()
            # FIXME: use all_hashes not self.txs
            unconfirmed = any(txin.prev_hash in self.txs
                              for txin in tx.inputs)
            result.append((tx_hash, mempool_tx.fee, unconfirmed))
        return result

    async def unordered_UTXOs(self, hashX):
        '''Return an unordered list of UTXO named tuples from mempool
        transactions that pay to hashX.

        This does not consider if any other mempool transactions spend
        the outputs.
        '''
        utxos = []
        # hashXs is a defaultdict, so use get() to query
        for tx_hash in self.hashXs.get(hashX, []):
            tx = self.txs.get(tx_hash)
            if not tx:
                continue
            for pos, (hX, value) in enumerate(tx.out_pairs):
                if hX == hashX:
                    utxos.append(UTXO(-1, pos, tx_hash, 0, value))
        return utxos
