import json
import os
from binascii import unhexlify

import pytest

from lib.coins import Coin
from lib.hash import hex_str_to_hash

BLOCKS_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), 'blocks')

# Find out which db engines to test
# Those that are not installed will be skipped
blocks = []

for name in os.listdir(BLOCKS_DIR):
    try:
        name_parts = name.split("_")
        coin = Coin.lookup_coin_class(name_parts[0], name_parts[1])
        with open(os.path.join(BLOCKS_DIR, name)) as f:
            blocks.append((coin, json.load(f)))
    except Exception as e:
        blocks.append(pytest.fail(name))


@pytest.fixture(params=blocks)
def block_details(request):
    return request.param


def test_block(block_details):
    coin, block_info = block_details

    raw_block = unhexlify(block_info['block'])
    block = coin.block(raw_block, block_info['height'])
    bih = block_info['hash']
    pbh = block_info['previousblockhash']
    assert coin.header_hash(block.header) == hex_str_to_hash(bih)
    assert coin.header_prevhash(block.header) == hex_str_to_hash(pbh)
    for n, (tx, txid) in enumerate(block.transactions):
        assert txid == hex_str_to_hash(block_info['tx'][n])
