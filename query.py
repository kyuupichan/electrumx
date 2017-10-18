#!/usr/bin/env python3
"""Script to query the database for debugging purposes.
Not currently documented; might become easier to use in future.
"""

import sys

from lib.hash import hash_to_str
from server.db import DB
from server.env import Env


def count_entries(hist_db, utxo_db):
    utxos = 0
    for key in utxo_db.iterator(prefix=b'u', include_value=False):
        utxos += 1
    print("UTXO count:", utxos)

    hash_x = 0
    for key in utxo_db.iterator(prefix=b'h', include_value=False):
        hash_x += 1
    print("HashX count:", hash_x)

    hist = 0
    hist_len = 0
    for key, value in hist_db.iterator(prefix=b'H'):
        hist += 1
        hist_len += len(value) // 4
    print("History rows {:,d} entries {:,d}".format(hist, hist_len))


def main():
    env = Env()
    bp = DB(env)
    coin = env.coin
    if len(sys.argv) == 1:
        count_entries(bp.hist_db, bp.utxo_db)
        return
    argc = 1
    try:
        limit = int(sys.argv[argc])
        argc += 1
    except Exception:
        limit = 10
    for addr in sys.argv[argc:]:
        print('Address: ', addr)
        hash_x = coin.address_to_hash_x(addr)

        for n, (tx_hash, height) in enumerate(bp.get_history(hash_x, limit)):
            print('History #{:d}: hash: {} height: {:d}'
                  .format(n + 1, hash_to_str(tx_hash), height))
        n = None
        for n, utxo in enumerate(bp.get_utxos(hash_x, limit)):
            print('UTXOs #{:d}: hash: {} pos: {:d} height: {:d} value: {:d}'
                  .format(n + 1, hash_to_str(utxo.tx_hash),
                          utxo.tx_pos, utxo.height, utxo.value))
        if n is None:
            print('No UTXOs')
        balance = bp.get_balance(hash_x)
        print('Balance: {} {}'.format(coin.decimal_value(balance),
                                      coin.SHORTNAME))


if __name__ == '__main__':
    main()
