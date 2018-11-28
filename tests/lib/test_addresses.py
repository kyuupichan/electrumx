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

import electrumx.lib.coins as coins

addresses = [
    (coins.BitcoinCash, "13xDKJbjh4acmLpNVr6Lc9hFcXRr9fyt4x",
     "206168f5322583ff37f8e55665a4789ae8963532", "b8cb80b26e8932f5b12a7e"),
    (coins.BitcoinCash, "3GxRZWkJufR5XA8hnNJgQ2gkASSheoBcmW",
     "a773db925b09add367dcc253c1f9bbc1d11ec6fd", "062d8515e50cb92b8a3a73"),
    (coins.BitcoinGold, "GZjH8pETu5xXd5DTt5VAqS9giooLNoHjnJ",
     "ae40655d7006806fd668248d10e7822c0b774dab", "3a1af301b378ad92493b17"),
    (coins.BitcoinGold, "AXfENBm9FP1PMa8AWnVPZZ4tHEwBiqNZav",
     "ae40655d7006806fd668248d10e7822c0b774dab", "cb3db4271432c0ac9f88d5"),
    (coins.Emercoin, "ELAeVHQg2mmdTTrTrZSzMgAQyXfC9TSRys",
     "210c4482ad8eacb0d349992973608300677adb15", "d71f2df4ef1b397088d731"),
    (coins.Litecoin, "LNBAaWuZmipg29WXfz5dtAm1pjo8FEH8yg",
     "206168f5322583ff37f8e55665a4789ae8963532", "b8cb80b26e8932f5b12a7e"),
    (coins.Litecoin, "MPAZsQAGrnGWKfQbtFJ2Dfw9V939e7D3E2",
     "a773db925b09add367dcc253c1f9bbc1d11ec6fd", "062d8515e50cb92b8a3a73"),
    (coins.Zcash, "t1LppKe1sfPNDMysGSGuTjxoAsBcvvSYv5j",
     "206168f5322583ff37f8e55665a4789ae8963532", "b8cb80b26e8932f5b12a7e"),
    (coins.Zcash, "t3Zq2ZrASszCg7oBbio7oXqnfR6dnSWqo76",
     "a773db925b09add367dcc253c1f9bbc1d11ec6fd", "062d8515e50cb92b8a3a73"),
    (coins.Decred, "DsUZxxoHJSty8DCfwfartwTYbuhmVct7tJu",
     "2789d58cfa0957d206f025c2af056fc8a77cebb0", "8cc9b11122272bd7b79a50"),
    (coins.Decred, "DcuQKx8BES9wU7C6Q5VmLBjw436r27hayjS",
     "f0b4e85100aee1a996f22915eb3c3f764d53779a", "a03c1a27de9ac3b3122e8d"),
    (coins.Groestlcoin, "FY7vmDL7FZGACwqVNx5p4fVaGghojWM5AF",
     "206168f5322583ff37f8e55665a4789ae8963532", "b8cb80b26e8932f5b12a7e"),
    (coins.Bitg, "GP1vBChXjjbaKwMcoPGB4T8cZLXWCe2wLV",
     "38bc968f95157bb7446feb1a7d75f2791fc8cf91", "4c7332cd142b788dd89241"),
    (coins.Bitg, "GaXGkXrm4dK1CYfSWvKubKgMcrYN59BZGF",
     "b6f335a20a887f03a1d8a5c701f967c35d9b45c4", "383b20a90a9109531ccd7e"),
    (coins.Pivx, "DGSHy3fsygJTZtvnkpT1qG8QvNim5kwyqp",
     "7be9fe7b9f894ba8481814c5eb085b788597059a", "9f1c9c70216bdc67a897fc"),
    (coins.Pivx, "DSHxy3zZLUxZndKtXq9rXhwAMH1Ypt8qEW",
     "e808105b7bfcc8b102cafa7242089b22c77a3b94", "31d61c3076fa0b2b7c74ef"),
    (coins.PivxTestnet, "yJ8iHtUxj9U4vsXLCZTbPNbuxG6NJNCvb8",
     "e808105b7bfcc8b102cafa7242089b22c77a3b94", "31d61c3076fa0b2b7c74ef"),
    (coins.PivxTestnet, "yCcNWqqMhDmsPzKchCPK1ux4HpxK7j3xpB",
     "ab72728952c06dfc0f6cf21449dd645422731ec4", "eb3a3155215538d51de7cc"),
    (coins.TokenPay, "TDE2X28FGtckatxuP3d8s3V726G4TLNHpT",
     "23b5dd9b7b402388c7a40bc88c261f3178acf30d", "7c7bdf0e0713f3752f4b88"),
    (coins.SmartCash, "SQFDM9NtRRmpHebq3H5RA3qpGJfGqp8Xgw",
     "206168f5322583ff37f8e55665a4789ae8963532", "b8cb80b26e8932f5b12a7e"),
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
