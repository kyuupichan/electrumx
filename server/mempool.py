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

    def __init__(self, daemon, coin, db):
        super().__init__()
        self.daemon = daemon
        self.coin = coin
        self.db = db
        self.touched = set()
        self.touched_event = asyncio.Event()
        self.stop = False
        self.txs = {}
        self.hash168s = defaultdict(set)  # None can be a key

    def resync_daemon_hashes(self, unprocessed, unfetched):
        '''Re-sync self.txs with the list of hashes in the daemon's mempool.

        Additionally, remove gone hashes from unprocessed and
        unfetched.  Add new ones to unprocessed.
        '''
        txs = self.txs
        hash168s = self.hash168s
        touched = self.touched

        hashes = self.daemon.mempool_hashes
        gone = set(txs).difference(hashes)
        for hex_hash in gone:
            unfetched.discard(hex_hash)
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
        fetch_size = 400
        process_some = self.async_process_some(unfetched, fetch_size // 2)

        await self.daemon.mempool_refresh_event.wait()
        self.logger.info ('beginning processing of daemon mempool.  '
                          'This can take some time...')
        next_log = time.time() + 0.1

        while True:
            try:
                todo = len(unfetched) + len(unprocessed)
                if todo:
                    pct = (len(txs) - todo) * 100 // len(txs) if txs else 0
                    self.logger.info('catchup {:d}% complete ({:,d} txs left)'
                                     .format(pct, todo))
                else:
                    now = time.time()
                    if now >= next_log:
                        self.logger.info('{:,d} txs touching {:,d} addresses'
                                         .format(len(txs), len(self.hash168s)))
                        next_log = now + 150
                    await self.daemon.mempool_refresh_event.wait()

                self.resync_daemon_hashes(unprocessed, unfetched)
                self.daemon.mempool_refresh_event.clear()

                if unfetched:
                    count = min(len(unfetched), fetch_size)
                    hex_hashes = [unfetched.pop() for n in range(count)]
                    unprocessed.update(await self.fetch_raw_txs(hex_hashes))

                if unprocessed:
                    await process_some(unprocessed)

                # Avoid double notifications if processing a block
                if self.touched and not self.processing_new_block():
                    self.touched_event.set()
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
            txin_pairs, txout_pairs = item
            tx_fee = (sum(v for hash168, v in txin_pairs)
                      - sum(v for hash168, v in txout_pairs))
            tx = Deserializer(raw_tx).read_tx()
            unconfirmed = any(txin.prev_hash in self.txs for txin in tx.inputs)
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
