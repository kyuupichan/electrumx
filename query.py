#!/usr/bin/env python3

# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import asyncio
import os
import sys

from server.env import Env
from server.server import Server


def main():
    env = Env()
    os.chdir(env.db_dir)
    loop = asyncio.get_event_loop()
    server = Server(env, loop)
    db = server.db
    coin = db.coin
    for addr in sys.argv[1:]:
        print('Address: ', addr)
        hash160 = coin.address_to_hash160(addr)
        for n, (tx_hash, height) in enumerate(db.get_history(hash160)):
            print('History #{:d}: hash: {} height: {:d}'
                  .format(n + 1, bytes(reversed(tx_hash)).hex(), height))
        for n, utxo in enumerate(db.get_utxos(hash160)):
            print('UTXOs #{:d}: hash: {} pos: {:d} height: {:d} value: {:d}'
                  .format(n, bytes(reversed(utxo.tx_hash)).hex(),
                          utxo.tx_pos, utxo.height, utxo.value))

if __name__ == '__main__':
    main()
