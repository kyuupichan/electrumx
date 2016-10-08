#!/usr/bin/env python3

# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import os
import sys

from server.env import Env
from server.db import DB


def main():
    env = Env()
    os.chdir(env.db_dir)
    db = DB(env)
    coin = db.coin
    argc = 1
    try:
        limit = int(sys.argv[argc])
        argc += 1
    except:
        limit = 10
    for addr in sys.argv[argc:]:
        print('Address: ', addr)
        hash160 = coin.address_to_hash160(addr)
        n = None
        for n, (tx_hash, height) in enumerate(db.get_history(hash160, limit)):
            print('History #{:d}: hash: {} height: {:d}'
                  .format(n + 1, bytes(reversed(tx_hash)).hex(), height))
        if n is None:
            print('No history')
        n = None
        for n, utxo in enumerate(db.get_utxos(hash160, limit)):
            print('UTXOs #{:d}: hash: {} pos: {:d} height: {:d} value: {:d}'
                  .format(n, bytes(reversed(utxo.tx_hash)).hex(),
                          utxo.tx_pos, utxo.height, utxo.value))
        if n is None:
            print('No UTXOs')

if __name__ == '__main__':
    main()
