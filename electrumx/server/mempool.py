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
from aiorpcx import TaskGroup, run_in_thread

from electrumx.lib.hash import hash_to_hex_str, hex_str_to_hash
from electrumx.lib.util import class_logger, chunks
from electrumx.server.db import UTXO


@attr.s(slots=True)
class MemPoolTx(object):
    prevouts = attr.ib()
    # A pair is a (hashX, value) tuple
    in_pairs = attr.ib()
    out_pairs = attr.ib()
    fee = attr.ib()
    size = attr.ib()


class MemPool(object):
    '''Representation of the daemon's mempool.

    Updated regularly in caught-up state.  Goal is to enable efficient
    response to the calls in the external interface.  To that end we
    maintain the following maps:

       tx:     tx_hash -> MemPoolTx
       hashXs: hashX   -> set of all hashes of txs touching the hashX
    '''

    def __init__(self, coin, daemon, notifications, lookup_utxos):
        self.logger = class_logger(__name__, self.__class__.__name__)
        self.coin = coin
        self.lookup_utxos = lookup_utxos
        self.daemon = daemon
        self.notifications = notifications
        self.txs = {}
        self.hashXs = defaultdict(set)  # None can be a key
        self.cached_compact_histogram = []

    async def _log_stats(self):
        while True:
            self.logger.info(f'{len(self.txs):,d} txs '
                             f'touching {len(self.hashXs):,d} addresses')
            await asyncio.sleep(120)

    def _update_histogram(self):
        # Build a histogram by fee rate
        histogram = defaultdict(int)
        for tx in self.txs.values():
            histogram[tx.fee // tx.size] += tx.size

        # Now compact it.  For efficiency, get_fees returns a
        # compact histogram with variable bin size.  The compact
        # histogram is an array of (fee_rate, vsize) values.
        # vsize_n is the cumulative virtual size of mempool
        # transactions with a fee rate in the interval
        # [rate_(n-1), rate_n)], and rate_(n-1) > rate_n.
        # Intervals are chosen to create tranches containing at
        # least 100kb of transactions
        compact = []
        cum_size = 0
        r = 0   # ?
        bin_size = 100 * 1000
        for fee_rate, size in sorted(histogram.items(), reverse=True):
            cum_size += size
            if cum_size + r > bin_size:
                compact.append((fee_rate, cum_size))
                r += cum_size - bin_size
                cum_size = 0
                bin_size *= 1.1
        self.logger.info(f'compact fee histogram: {compact}')
        self.cached_compact_histogram = compact

    def _accept_transactions(self, tx_map, utxo_map, touched):
        '''Accept transactions in tx_map to the mempool if all their inputs
        can be found in the existing mempool or a utxo_map from the
        DB.

        Returns an (unprocessed tx_map, unspent utxo_map) pair.
        '''
        hashXs = self.hashXs
        txs = self.txs

        deferred = {}
        unspent = set(utxo_map)
        # Try to find all prevouts so we can accept the TX
        for hash, tx in tx_map.items():
            in_pairs = []
            try:
                for prevout in tx.prevouts:
                    utxo = utxo_map.get(prevout)
                    if not utxo:
                        prev_hash, prev_index = prevout
                        # Raises KeyError if prev_hash is not in txs
                        utxo = txs[prev_hash].out_pairs[prev_index]
                    in_pairs.append(utxo)
            except KeyError:
                deferred[hash] = tx
                continue

            # Spend the prevouts
            unspent.difference_update(tx.prevouts)

            # Save the in_pairs, compute the fee and accept the TX
            tx.in_pairs = tuple(in_pairs)
            tx.fee = (sum(v for hashX, v in tx.in_pairs) -
                      sum(v for hashX, v in tx.out_pairs))
            txs[hash] = tx

            for hashX, value in itertools.chain(tx.in_pairs, tx.out_pairs):
                touched.add(hashX)
                hashXs[hashX].add(hash)

        return deferred, {prevout: utxo_map[prevout] for prevout in unspent}

    async def _refresh_hashes(self, synchronized_event):
        '''Refresh our view of the daemon's mempool.'''
        sleep = 5
        histogram_refresh = self.coin.MEMPOOL_HISTOGRAM_REFRESH_SECS // sleep
        for loop_count in itertools.count():
            height = self.daemon.cached_height()
            hex_hashes = await self.daemon.mempool_hashes()
            if height != await self.daemon.height():
                continue
            hashes = set(hex_str_to_hash(hh) for hh in hex_hashes)
            touched = await self._process_mempool(hashes)
            synchronized_event.set()
            await self.notifications.on_mempool(touched, height)
            # Thread mempool histogram refreshes - they can be expensive
            if loop_count % histogram_refresh == 0:
                await run_in_thread(self._update_histogram)
            await asyncio.sleep(sleep)

    async def _process_mempool(self, all_hashes):
        # Re-sync with the new set of hashes
        txs = self.txs
        hashXs = self.hashXs
        touched = set()

        # First handle txs that have disappeared
        for tx_hash in set(txs).difference(all_hashes):
            tx = txs.pop(tx_hash)
            tx_hashXs = set(hashX for hashX, value in tx.in_pairs)
            tx_hashXs.update(hashX for hashX, value in tx.out_pairs)
            for hashX in tx_hashXs:
                hashXs[hashX].remove(tx_hash)
                if not hashXs[hashX]:
                    del hashXs[hashX]
            touched.update(tx_hashXs)

        # Process new transactions
        new_hashes = list(all_hashes.difference(txs))
        if new_hashes:
            group = TaskGroup()
            for hashes in chunks(new_hashes, 200):
                coro = self._fetch_and_accept(hashes, all_hashes, touched)
                await group.spawn(coro)
            tx_map = {}
            utxo_map = {}
            async for task in group:
                deferred, unspent = task.result()
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
        hex_hashes_iter = (hash_to_hex_str(hash) for hash in hashes)
        raw_txs = await self.daemon.getrawtransactions(hex_hashes_iter)

        def deserialize_txs():    # This function is pure
            to_hashX = self.coin.hashX_from_script
            deserializer = self.coin.DESERIALIZER

            txs = {}
            for hash, raw_tx in zip(hashes, raw_txs):
                # The daemon may have evicted the tx from its
                # mempool or it may have gotten in a block
                if not raw_tx:
                    continue
                tx, tx_size = deserializer(raw_tx).read_tx_and_vsize()
                # Convert the inputs and outputs into (hashX, value) pairs
                txin_pairs = tuple((txin.prev_hash, txin.prev_idx)
                                   for txin in tx.inputs)
                txout_pairs = tuple((to_hashX(txout.pk_script), txout.value)
                                    for txout in tx.outputs)
                txs[hash] = MemPoolTx(txin_pairs, None, txout_pairs,
                                      0, tx_size)
            return txs

        # Thread this potentially slow operation so as not to block
        tx_map = await run_in_thread(deserialize_txs)

        # Determine all prevouts not in the mempool, and fetch the
        # UTXO information from the database.  Failed prevout lookups
        # return None - concurrent database updates happen - which is
        # relied upon by _accept_transactions
        prevouts = tuple(prevout for tx in tx_map.values()
                         for prevout in tx.prevouts
                         if prevout[0] not in all_hashes)
        utxos = await self.lookup_utxos(prevouts)
        utxo_map = {prevout: utxo for prevout, utxo in zip(prevouts, utxos)}

        return self._accept_transactions(tx_map, utxo_map, touched)

    #
    # External interface
    #

    async def keep_synchronized(self, synchronized_event):
        '''Starts the mempool synchronizer.

        Waits for an initial synchronization before returning.
        '''
        self.logger.info('beginning processing of daemon mempool.  '
                         'This can take some time...')
        async with TaskGroup() as group:
            await group.spawn(self._refresh_hashes(synchronized_event))
            start = time.time()
            await synchronized_event.wait()
            elapsed = time.time() - start
            self.logger.info(f'synced in {elapsed:.2f}s')
            await group.spawn(self._log_stats())

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
        return self.cached_compact_histogram

    async def potential_spends(self, hashX):
        '''Return a set of (prev_hash, prev_idx) pairs from mempool
        transactions that touch hashX.

        None, some or all of these may be spends of the hashX.
        '''
        result = set()
        for tx_hash in self.hashXs.get(hashX, ()):
            tx = self.txs[tx_hash]
            result.update(tx.prevouts)
        return result

    async def transaction_summaries(self, hashX):
        '''Return a list of (tx_hash, tx_fee, unconfirmed) tuples for
        mempool entries for the hashX.

        unconfirmed is True if any txin is unconfirmed.
        '''
        # hashXs is a defaultdict, so use get() to query
        result = []
        for tx_hash in self.hashXs.get(hashX, ()):
            tx = self.txs[tx_hash]
            unconfirmed = any(prev_hash in self.txs
                              for prev_hash, prev_idx in tx.prevouts)
            result.append((tx_hash, tx.fee, unconfirmed))
        return result

    async def unordered_UTXOs(self, hashX):
        '''Return an unordered list of UTXO named tuples from mempool
        transactions that pay to hashX.

        This does not consider if any other mempool transactions spend
        the outputs.
        '''
        utxos = []
        # hashXs is a defaultdict, so use get() to query
        for tx_hash in self.hashXs.get(hashX, ()):
            tx = self.txs.get(tx_hash)
            if not tx:
                continue
            for pos, (hX, value) in enumerate(tx.out_pairs):
                if hX == hashX:
                    utxos.append(UTXO(-1, pos, tx_hash, 0, value))
        return utxos
