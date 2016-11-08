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

from server.env import Env
from server.DB import DB
from lib.hash import hash_to_str


def count_entries(db):
    utxos = 0
    for key in db.iterator(prefix=b'u', include_value=False):
        utxos += 1
    print("UTXO count:", utxos)

    hash168 = 0
    for key in db.iterator(prefix=b'h', include_value=False):
        hash168 += 1
    print("Hash168 count:", hash168)

    hist = 0
    for key in db.iterator(prefix=b'H', include_value=False):
        hist += 1
    print("History addresses:", hist)


def main():
    env = Env()
    bp = DB(env)
    coin = env.coin
    if len(sys.argv) == 1:
        count_entries(bp.db)
        return
    argc = 1
    try:
        limit = int(sys.argv[argc])
        argc += 1
    except:
        limit = 10
    for addr in sys.argv[argc:]:
        print('Address: ', addr)
        hash168 = coin.address_to_hash168(addr)
        n = None
        for n, (tx_hash, height) in enumerate(bp.get_history(hash168, limit)):
            print('History #{:d}: hash: {} height: {:d}'
                  .format(n + 1, hash_to_str(tx_hash), height))
        if n is None:
            print('No history')
        n = None
        for n, utxo in enumerate(bp.get_utxos(hash168, limit)):
            print('UTXOs #{:d}: hash: {} pos: {:d} height: {:d} value: {:d}'
                  .format(n + 1, hash_to_str(utxo.tx_hash),
                          utxo.tx_pos, utxo.height, utxo.value))
        if n is None:
            print('No UTXOs')
        balance = bp.get_balance(hash168)
        print('Balance: {} {}'.format(coin.decimal_value(balance),
                                      coin.SHORTNAME))

if __name__ == '__main__':
    main()
