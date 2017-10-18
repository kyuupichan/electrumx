# Test of compaction code in server/db.py

import array
import random
from collections import defaultdict
from os import environ, urandom
from struct import pack

from server.db import DB
from server.env import Env


def create_histories(db, hash_x_count=100):
    """Creates a bunch of random transaction histories, and write them
    to disk in a series of small flushes."""
    hash_xs = [urandom(db.coin.HASHX_LEN) for _ in range(hash_x_count)]
    histories = {hash_x: array.array('I') for hash_x in hash_xs}
    this_history = defaultdict(array.array('I'))
    tx_num = 0
    while hash_xs:
        hash_indexes = set(random.randrange(len(hash_xs))
                           for n in range(1 + random.randrange(4)))
        for index in hash_indexes:
            histories[hash_xs[index]].append(tx_num)
            this_history[hash_xs[index]].append(tx_num)

        tx_num += 1
        # Occasionally flush and drop a random hash_x if non-empty
        if random.random() < 0.1:
            db.flush_history(this_history)
            this_history.clear()
            index = random.randrange(0, len(hash_xs))
            if histories[hash_xs[index]]:
                del hash_xs[index]

    return histories


def check_hash_x_compaction(db):
    db.max_hist_row_entries = 40
    row_size = db.max_hist_row_entries * 4
    full_hist = array.array('I', range(100)).tobytes()
    hash_x = urandom(db.coin.HASHX_LEN)
    pairs = ((1, 20), (26, 50), (56, 30))

    cum = 0
    hist_list = []
    hist_map = {}
    for flush_count, count in pairs:
        key = hash_x + pack('>H', flush_count)
        hist = full_hist[cum * 4: (cum + count) * 4]
        hist_map[key] = hist
        hist_list.append(hist)
        cum += count

    write_items = []
    keys_to_delete = set()
    write_size = db._compact_hash_x(hash_x, hist_map, hist_list,
                                    write_items, keys_to_delete)
    # Check results for sanity
    assert write_size == len(full_hist)
    assert len(write_items) == 3
    assert len(keys_to_delete) == 3
    assert len(hist_map) == len(pairs)
    for n, item in enumerate(write_items):
        assert item == (hash_x + pack('>H', n),
                        full_hist[n * row_size: (n + 1) * row_size])
    for flush_count, count in pairs:
        assert hash_x + pack('>H', flush_count) in keys_to_delete

    # Check re-compaction is null
    hist_map = {key: value for key, value in write_items}
    hist_list = [value for key, value in write_items]
    write_items.clear()
    keys_to_delete.clear()
    write_size = db._compact_hash_x(hash_x, hist_map, hist_list,
                                    write_items, keys_to_delete)
    assert write_size == 0
    assert len(write_items) == 0
    assert len(keys_to_delete) == 0
    assert len(hist_map) == len(pairs)

    # Check re-compaction adding a single tx writes the one row
    hist_list[-1] += array.array('I', [100]).tobytes()
    write_size = db._compact_hash_x(hash_x, hist_map, hist_list,
                                    write_items, keys_to_delete)
    assert write_size == len(hist_list[-1])
    assert write_items == [(hash_x + pack('>H', 2), hist_list[-1])]
    assert len(keys_to_delete) == 1
    assert write_items[0][0] in keys_to_delete
    assert len(hist_map) == len(pairs)


def check_written(db, histories):
    for hash_x, hist in histories.items():
        db_hist = array.array('I', db.get_history_txnums(hash_x, limit=None))
        assert hist == db_hist


def compact_history(db):
    """Synchronously compact the DB history."""
    db.first_sync = False
    db.comp_cursor = 0

    db.comp_flush_count = max(db.comp_flush_count, 1)
    limit = 5 * 1000

    write_size = 0
    while db.comp_cursor != -1:
        write_size += db._compact_history(limit)
    assert write_size != 0


def run_test(db_dir):
    environ.clear()
    environ['DB_DIRECTORY'] = db_dir
    environ['DAEMON_URL'] = ''
    environ['COIN'] = 'BitcoinCash'
    env = Env()
    db = DB(env)
    # Test abstract compaction
    check_hash_x_compaction(db)
    # Now test in with random data
    histories = create_histories(db)
    check_written(db, histories)
    compact_history(db)
    check_written(db, histories)


def test_compaction(tmpdir):
    db_dir = str(tmpdir)
    print('Temp dir: {}'.format(db_dir))
    run_test(db_dir)
