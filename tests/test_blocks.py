# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# and warranty status of this software.

import json
import os
from binascii import unhexlify

import pytest

from electrumx.lib.coins import Coin
from electrumx.lib.hash import hex_str_to_hash
from electrumx.lib.util import pack_be_uint32

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

    assert coin.header_hash(
        block.header) == hex_str_to_hash(block_info['hash'])
    assert (coin.header_prevhash(block.header)
            == hex_str_to_hash(block_info['previousblockhash']))
    for n, (tx, txid) in enumerate(block.transactions):
        assert txid == hex_str_to_hash(block_info['tx'][n])
