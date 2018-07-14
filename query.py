#!/usr/bin/env python3
#
# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Script to query the database for debugging purposes.

Not currently documented; might become easier to use in future.
'''


import sys

from electrumx import Env
from electrumx.server.db import DB
from electrumx.lib.hash import hash_to_hex_str


def count_entries(hist_db, utxo_db):
    utxos = 0
    for key in utxo_db.iterator(prefix=b'u', include_value=False):
        utxos += 1
    print("UTXO count:", utxos)

    hashX = 0
    for key in utxo_db.iterator(prefix=b'h', include_value=False):
        hashX += 1
    print("HashX count:", hashX)

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
        hashX = coin.address_to_hashX(addr)

        for n, (tx_hash, height) in enumerate(bp.get_history(hashX, limit)):
            print('History #{:d}: hash: {} height: {:d}'
                  .format(n + 1, hash_to_hex_str(tx_hash), height))
        n = None
        for n, utxo in enumerate(bp.get_utxos(hashX, limit)):
            print('UTXOs #{:d}: hash: {} pos: {:d} height: {:d} value: {:d}'
                  .format(n + 1, hash_to_hex_str(utxo.tx_hash),
                          utxo.tx_pos, utxo.height, utxo.value))
        if n is None:
            print('No UTXOs')
        balance = bp.get_balance(hashX)
        print('Balance: {} {}'.format(coin.decimal_value(balance),
                                      coin.SHORTNAME))


if __name__ == '__main__':
    main()
