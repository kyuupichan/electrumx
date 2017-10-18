import pytest

from lib.coins import Litecoin, BitcoinCash, Zcash, Emercoin
from lib.hash import Base58

addresses = [
    (BitcoinCash, "13xDKJbjh4acmLpNVr6Lc9hFcXRr9fyt4x",
     "206168f5322583ff37f8e55665a4789ae8963532", "b8cb80b26e8932f5b12a7e"),
    (BitcoinCash, "3GxRZWkJufR5XA8hnNJgQ2gkASSheoBcmW",
     "a773db925b09add367dcc253c1f9bbc1d11ec6fd", "062d8515e50cb92b8a3a73"),
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


def test_address_to_hash_x(_address):
    coin, addr, _, hash_x = _address
    assert coin.address_to_hash_x(addr).hex() == hash_x


def test_address_from_hash160(_address):
    coin, addr, _hash, _ = _address

    raw = Base58.decode_check(addr)
    verlen = len(raw) - 20
    assert verlen > 0
    verbyte, hash_bytes = raw[:verlen], raw[verlen:]
    if coin.P2PKH_VERBYTE == verbyte:
        assert coin.P2PKH_address_from_hash160(bytes.fromhex(_hash)) == addr
    elif verbyte in coin.P2SH_VERBYTES:
        assert coin.P2SH_address_from_hash160(bytes.fromhex(_hash)) == addr
    else:
        raise Exception("Unknown version byte")
