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

import pytest

from electrumx.lib.coins import Litecoin, BitcoinCash, Zcash, Emercoin, BitcoinGold
from electrumx.lib.hash import Base58

addresses = [
    (BitcoinCash, "13xDKJbjh4acmLpNVr6Lc9hFcXRr9fyt4x",
     "206168f5322583ff37f8e55665a4789ae8963532", "b8cb80b26e8932f5b12a7e"),
    (BitcoinCash, "3GxRZWkJufR5XA8hnNJgQ2gkASSheoBcmW",
     "a773db925b09add367dcc253c1f9bbc1d11ec6fd", "062d8515e50cb92b8a3a73"),
    (BitcoinGold, "GZjH8pETu5xXd5DTt5VAqS9giooLNoHjnJ",
     "ae40655d7006806fd668248d10e7822c0b774dab", "3a1af301b378ad92493b17"),
    (BitcoinGold, "AXfENBm9FP1PMa8AWnVPZZ4tHEwBiqNZav",
     "ae40655d7006806fd668248d10e7822c0b774dab", "cb3db4271432c0ac9f88d5"),
    (Emercoin, "ELAeVHQg2mmdTTrTrZSzMgAQyXfC9TSRys",
     "210c4482ad8eacb0d349992973608300677adb15", "d71f2df4ef1b397088d731"),
    (Litecoin, "LNBAaWuZmipg29WXfz5dtAm1pjo8FEH8yg",
     "206168f5322583ff37f8e55665a4789ae8963532", "b8cb80b26e8932f5b12a7e"),
    (Litecoin, "MPAZsQAGrnGWKfQbtFJ2Dfw9V939e7D3E2",
     "a773db925b09add367dcc253c1f9bbc1d11ec6fd", "062d8515e50cb92b8a3a73"),
    (Zcash, "t1LppKe1sfPNDMysGSGuTjxoAsBcvvSYv5j",
     "206168f5322583ff37f8e55665a4789ae8963532", "b8cb80b26e8932f5b12a7e"),
    (Zcash, "t3Zq2ZrASszCg7oBbio7oXqnfR6dnSWqo76",
     "a773db925b09add367dcc253c1f9bbc1d11ec6fd", "062d8515e50cb92b8a3a73"),
]


@pytest.fixture(params=addresses)
def address(request):
    return request.param


def test_address_to_hashX(address):
    coin, addr, _, hashX = address
    assert coin.address_to_hashX(addr).hex() == hashX


def test_address_from_hash160(address):
    coin, addr, hash, _ = address

    raw = coin.DECODE_CHECK(addr)
    verlen = len(raw) - 20
    assert verlen > 0
    verbyte, hash_bytes = raw[:verlen], raw[verlen:]
    if coin.P2PKH_VERBYTE == verbyte:
        assert coin.P2PKH_address_from_hash160(bytes.fromhex(hash)) == addr
    elif verbyte in coin.P2SH_VERBYTES:
        assert coin.P2SH_address_from_hash160(bytes.fromhex(hash)) == addr
    else:
        raise Exception("Unknown version byte")
