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
from functools import partial

from lib.hash import hash_to_str, hex_str_to_hash
from lib.tx import Deserializer
import lib.util as util
from server.daemon import DaemonError


class MemPool(util.LoggedClass):
    '''Representation of the daemon's mempool.

    Updated regularly in caught-up state.  Goal is to enable efficient
    response to the value() and transactions() calls.

    To that end we maintain the following maps:

       tx_hash -> (txin_pairs, txout_pairs)
       hash168 -> set of all tx hashes in which the hash168 appears

    A pair is a (hash168, value) tuple.  tx hashes are hex strings.
    '''

    def __init__(self, daemon, coin, db, touched, touched_event):
        super().__init__()
        self.daemon = daemon
        self.coin = coin
        self.db = db
        self.touched = touched
        self.touched_event = touched_event
        self.stop = False
        self.txs = {}
        self.hash168s = defaultdict(set)  # None can be a key

    async def main_loop(self, caught_up):
        '''Asynchronously maintain mempool status with daemon.

        Waits until the caught up event is signalled.'''
        await caught_up.wait()
        self.logger.info('beginning processing of daemon mempool.  '
                         'This can take some time...')
        try:
            await self.fetch_and_process()
        except asyncio.CancelledError:
            # This aids clean shutdowns
            self.stop = True

    async def fetch_and_process(self):
        '''The inner loop unprotected by try / except.'''
        unfetched = set()
        unprocessed = {}
        log_every = 150
        log_secs = 0
        fetch_size = 400
        process_some = self.async_process_some(unfetched, fetch_size // 2)
        next_refresh = 0
        # The list of mempool hashes is fetched no more frequently
        # than this number of seconds
        refresh_secs = 5

        while True:
            try:
                now = time.time()
                if now >= next_refresh:
                    await self.new_hashes(unprocessed, unfetched)
                    next_refresh = now + refresh_secs
                    log_secs -= refresh_secs

                # Fetch some txs if unfetched ones remain
                if unfetched:
                    count = min(len(unfetched), fetch_size)
                    hex_hashes = [unfetched.pop() for n in range(count)]
                    unprocessed.update(await self.fetch_raw_txs(hex_hashes))

                # Process some txs if unprocessed ones remain
                if unprocessed:
                    await process_some(unprocessed)

                if self.touched:
                    self.touched_event.set()

                if log_secs <= 0 and not unprocessed:
                    log_secs = log_every
                    self.logger.info('{:,d} txs touching {:,d} addresses'
                                     .format(len(self.txs),
                                             len(self.hash168s)))
                    await asyncio.sleep(1)
            except DaemonError as e:
                self.logger.info('ignoring daemon error: {}'.format(e))

    async def new_hashes(self, unprocessed, unfetched):
        '''Get the current list of hashes in the daemon's mempool.

        Remove ones that have disappeared from self.txs and unprocessed.
        '''
        txs = self.txs
        hash168s = self.hash168s
        touched = self.touched

        hashes = set(await self.daemon.mempool_hashes())
        new = hashes.difference(txs)
        gone = set(txs).difference(hashes)
        for hex_hash in gone:
            unprocessed.pop(hex_hash, None)
            item = txs.pop(hex_hash)
            if item:
                txin_pairs, txout_pairs = item
                tx_hash168s = set(hash168 for hash168, value in txin_pairs)
                tx_hash168s.update(hash168 for hash168, value in txout_pairs)
                for hash168 in tx_hash168s:
                    hash168s[hash168].remove(hex_hash)
                    if not hash168s[hash168]:
                        del hash168s[hash168]
                touched.update(tx_hash168s)

        unfetched.update(new)
        for hex_hash in new:
            txs[hex_hash] = None

    def async_process_some(self, unfetched, limit):
        loop = asyncio.get_event_loop()
        pending = []
        txs = self.txs
        first = True

        async def process(unprocessed):
            nonlocal first, pending

            raw_txs = {}
            while unprocessed and len(raw_txs) < limit:
                hex_hash, raw_tx = unprocessed.popitem()
                raw_txs[hex_hash] = raw_tx

            if unprocessed:
                deferred = []
            else:
                deferred = pending
                pending = []

            process_raw_txs = partial(self.process_raw_txs, raw_txs, deferred)
            result, deferred = (
                await loop.run_in_executor(None, process_raw_txs))

            pending.extend(deferred)
            hash168s = self.hash168s
            touched = self.touched
            for hex_hash, in_out_pairs in result.items():
                if hex_hash in txs:
                    txs[hex_hash] = in_out_pairs
                    for hash168, value in itertools.chain(*in_out_pairs):
                        touched.add(hash168)
                        hash168s[hash168].add(hex_hash)

            to_do = len(unfetched) + len(unprocessed)
            if to_do and txs:
                percent = max(0, len(txs) - to_do) * 100 // len(txs)
                self.logger.info('catchup {:d}% complete'.format(percent))
            elif first:
                first = False
                self.logger.info('caught up')

        return process

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
        script_hash168 = self.coin.hash168_from_script()
        db_utxo_lookup = self.db.db_utxo_lookup
        txs = self.txs

        # Deserialize each tx and put it in our priority queue
        for tx_hash, raw_tx in raw_tx_map.items():
            if not tx_hash in txs:
                continue
            tx = Deserializer(raw_tx).read_tx()

            # Convert the tx outputs into (hash168, value) pairs
            txout_pairs = [(script_hash168(txout.pk_script), txout.value)
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
            except self.db.MissingUTXOError:
                # This typically happens just after the daemon has
                # accepted a new block and the new mempool has deps on
                # new txs in that block.
                continue

            if mempool_missing:
                deferred.append(item)
            else:
                result[tx_hash] = (txin_pairs, txout_pairs)

        return result, deferred

    async def transactions(self, hash168):
        '''Generate (hex_hash, tx_fee, unconfirmed) tuples for mempool
        entries for the hash168.

        unconfirmed is True if any txin is unconfirmed.
        '''
        # hash168s is a defaultdict
        if not hash168 in self.hash168s:
            return []

        hex_hashes = self.hash168s[hash168]
        raw_txs = await self.daemon.getrawtransactions(hex_hashes)
        result = []
        for hex_hash, raw_tx in zip(hex_hashes, raw_txs):
            item = self.txs.get(hex_hash)
            if not item or not raw_tx:
                continue
            tx = Deserializer(raw_tx).read_tx()
            txin_pairs, txout_pairs = item
            tx_fee = (sum(v for hash168, v in txin_pairs)
                      - sum(v for hash168, v in txout_pairs))
            unconfirmed = any(txin.prev_hash not in self.txs
                              for txin in tx.inputs)
            result.append((hex_hash, tx_fee, unconfirmed))
        return result

    def value(self, hash168):
        '''Return the unconfirmed amount in the mempool for hash168.

        Can be positive or negative.
        '''
        value = 0
        # hash168s is a defaultdict
        if hash168 in self.hash168s:
            for hex_hash in self.hash168s[hash168]:
                txin_pairs, txout_pairs = self.txs[hex_hash]
                value -= sum(v for h168, v in txin_pairs if h168 == hash168)
                value += sum(v for h168, v in txout_pairs if h168 == hash168)
        return value
