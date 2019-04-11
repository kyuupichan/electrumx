# Test of compaction code in server/history.py

import array
import asyncio
from os import environ, urandom
import random

from electrumx.lib.hash import HASHX_LEN
from electrumx.lib.util import pack_be_uint16
from electrumx.server.env import Env
from electrumx.server.db import DB


def create_histories(history, hashX_count=100):
    '''Creates a bunch of random transaction histories, and write them
    to disk in a series of small flushes.'''
    hashXs = [urandom(HASHX_LEN) for n in range(hashX_count)]
    mk_array = lambda : array.array('I')
    histories = {hashX : mk_array() for hashX in hashXs}
    unflushed = history.unflushed
    tx_num = 0
    while hashXs:
        hash_indexes = set(random.randrange(len(hashXs))
                           for n in range(1 + random.randrange(4)))
        for index in hash_indexes:
            histories[hashXs[index]].append(tx_num)
            unflushed[hashXs[index]].append(tx_num)

        tx_num += 1
        # Occasionally flush and drop a random hashX if non-empty
        if random.random() < 0.1:
            history.flush()
            index = random.randrange(0, len(hashXs))
            if histories[hashXs[index]]:
                del hashXs[index]

    return histories


def check_hashX_compaction(history):
    history.max_hist_row_entries = 40
    row_size = history.max_hist_row_entries * 4
    full_hist = array.array('I', range(100)).tobytes()
    hashX = urandom(HASHX_LEN)
    pairs = ((1, 20), (26, 50), (56, 30))

    cum = 0
    hist_list = []
    hist_map = {}
    for flush_count, count in pairs:
        key = hashX + pack_be_uint16(flush_count)
        hist = full_hist[cum * 4: (cum+count) * 4]
        hist_map[key] = hist
        hist_list.append(hist)
        cum += count

    write_items = []
    keys_to_delete = set()
    write_size = history._compact_hashX(hashX, hist_map, hist_list,
                                        write_items, keys_to_delete)
    # Check results for sanity
    assert write_size == len(full_hist)
    assert len(write_items) == 3
    assert len(keys_to_delete) == 3
    assert len(hist_map) == len(pairs)
    for n, item in enumerate(write_items):
        assert item == (hashX + pack_be_uint16(n),
                        full_hist[n * row_size: (n + 1) * row_size])
    for flush_count, count in pairs:
        assert hashX + pack_be_uint16(flush_count) in keys_to_delete

    # Check re-compaction is null
    hist_map = {key: value for key, value in write_items}
    hist_list = [value for key, value in write_items]
    write_items.clear()
    keys_to_delete.clear()
    write_size = history._compact_hashX(hashX, hist_map, hist_list,
                                        write_items, keys_to_delete)
    assert write_size == 0
    assert len(write_items) == 0
    assert len(keys_to_delete) == 0
    assert len(hist_map) == len(pairs)

    # Check re-compaction adding a single tx writes the one row
    hist_list[-1] += array.array('I', [100]).tobytes()
    write_size = history._compact_hashX(hashX, hist_map, hist_list,
                                        write_items, keys_to_delete)
    assert write_size == len(hist_list[-1])
    assert write_items == [(hashX + pack_be_uint16(2), hist_list[-1])]
    assert len(keys_to_delete) == 1
    assert write_items[0][0] in keys_to_delete
    assert len(hist_map) == len(pairs)


def check_written(history, histories):
    for hashX, hist in histories.items():
        db_hist = array.array('I', history.get_txnums(hashX, limit=None))
        assert hist == db_hist

def compact_history(history):
    '''Synchronously compact the DB history.'''
    history.comp_cursor = 0

    history.comp_flush_count = max(history.comp_flush_count, 1)
    limit = 5 * 1000

    write_size = 0
    while history.comp_cursor != -1:
        write_size += history._compact_history(limit)
    assert write_size != 0

async def run_test(db_dir):
    environ.clear()
    environ['DB_DIRECTORY'] = db_dir
    environ['DAEMON_URL'] = ''
    environ['COIN'] = 'BitcoinSV'
    db = DB(Env())
    await db.open_for_serving()
    history = db.history

    # Test abstract compaction
    check_hashX_compaction(history)
    # Now test in with random data
    histories = create_histories(history)
    check_written(history, histories)
    compact_history(history)
    check_written(history, histories)

def test_compaction(tmpdir):
    db_dir = str(tmpdir)
    print('Temp dir: {}'.format(db_dir))
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_test(db_dir))
