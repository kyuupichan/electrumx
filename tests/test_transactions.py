# Copyright (c) 2018, John L. Jegutanis
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

import json
import os
from binascii import unhexlify

import pytest

from electrumx.lib.coins import Coin
from electrumx.lib.hash import hash_to_hex_str

TRANSACTION_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), 'transactions')

# Find out which db engines to test
# Those that are not installed will be skipped
transactions = []

for name in os.listdir(TRANSACTION_DIR):
    try:
        name_parts = name.split("_")
        coinFound = Coin.lookup_coin_class(name_parts[0], name_parts[1])
        with open(os.path.join(TRANSACTION_DIR, name)) as f:
            transactions.append((coinFound, json.load(f)))
    except Exception as e:
        transactions.append(pytest.fail(name))


@pytest.fixture(params=transactions)
def transaction_details(request):
    return request.param


def test_transaction(transaction_details):
    coin, tx_info = transaction_details

    raw_tx = unhexlify(tx_info['hex'])
    tx, tx_hash = coin.DESERIALIZER(raw_tx, 0).read_tx_and_hash()
    assert tx_info['txid'] == hash_to_hex_str(tx_hash)

    vin = tx_info['vin']
    for i in range(len(vin)):
        assert vin[i]['txid'] == hash_to_hex_str(tx.inputs[i].prev_hash)
        assert vin[i]['vout'] == tx.inputs[i].prev_idx

    vout = tx_info['vout']
    for i in range(len(vout)):
        # value pk_script
        assert vout[i]['value'] == tx.outputs[i].value
        spk = vout[i]['scriptPubKey']
        tx_pks = tx.outputs[i].pk_script
        assert spk['hex'] == tx_pks.hex()
        assert coin.address_to_hashX(spk['address']) == \
               coin.hashX_from_script(tx_pks)
