#!/usr/bin/env python3
#
# Copyright (c) 2016-2018, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Script to query the database for debugging purposes.

Not currently documented; might become easier to use in future.
'''

import argparse
import asyncio
import sys

from electrumx import Env
from electrumx.server.db import DB
from electrumx.lib.hash import hash_to_hex_str, Base58Error


async def print_stats(hist_db, utxo_db):
    count = 0
    for key in utxo_db.iterator(prefix=b'u', include_value=False):
        count += 1
    print(f'UTXO count: {utxos}')

    count = 0
    for key in utxo_db.iterator(prefix=b'h', include_value=False):
        count += 1
    print(f'HashX count: {count}')

    hist = 0
    hist_len = 0
    for key, value in hist_db.iterator(prefix=b'H'):
        hist += 1
        hist_len += len(value) // 4
    print(f'History rows {hist:,d} entries {hist_len:,d}')


def arg_to_hashX(coin, arg):
    try:
        script = bytes.fromhex(arg)
        print(f'Script: {arg}')
        return coin.hashX_from_script(script)
    except ValueError:
        pass

    try:
        hashX = coin.address_to_hashX(arg)
        print(f'Address: {arg}')
        return hashX
    except Base58Error:
        print(f'Ingoring unknown arg: {arg}')
        return None


async def query(args):
    env = Env()
    db = DB(env)
    coin = env.coin

    await db.open_for_serving()

    if not args.scripts:
        await print_stats(db.hist_db, db.utxo_db)
        return
    limit = args.limit
    for arg in args.scripts:
        hashX = arg_to_hashX(coin, arg)
        if not hashX:
            continue
        n = None
        history = await db.limited_history(hashX, limit=limit)
        for n, (tx_hash, height) in enumerate(history, start=1):
            print(f'History #{n:,d}: height {height:,d} '
                  f'tx_hash {hash_to_hex_str(tx_hash)}')
        if n is None:
            print('No history found')
        n = None
        utxos = await db.all_utxos(hashX)
        for n, utxo in enumerate(utxos, start=1):
            print(f'UTXO #{n:,d}: tx_hash {hash_to_hex_str(utxo.tx_hash)} '
                  f'tx_pos {utxo.tx_pos:,d} height {utxo.height:,d} '
                  f'value {utxo.value:,d}')
            if n == limit:
                break
        if n is None:
            print('No UTXOs found')
        balance = sum(utxo.value for utxo in utxos)
        print(f'Balance: {coin.decimal_value(balance):,f} {coin.SHORTNAME}')


def main():
    default_limit = 10
    parser = argparse.ArgumentParser(
        'query.py',
        description='Invoke with COIN and DB_DIRECTORY set in the '
        'environment as they would be invoking electrumx_server'
    )
    parser.add_argument('-l', '--limit', metavar='limit', type=int,
                        default=10, help=f'maximum number of entries to '
                        f'return (default: {default_limit})')
    parser.add_argument('scripts', nargs='*', default=[], type=str,
                        help='hex scripts to query')
    args = parser.parse_args()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(query(args))

if __name__ == '__main__':
    main()
