#
# Tests of wallet/bip32.py
#

import pytest

import electrumx.wallet.bip32 as bip32
from electrumx.lib.coins import BitcoinCash as Bitcoin, CoinError
from electrumx.lib.hash import Base58


MXPRV = 'xprv9s21ZrQH143K2gMVrSwwojnXigqHgm1khKZGTCm7K8w4PmuDEUrudk11ZBxhGPUiUeVcrfGLoZmt8rFNRDLp18jmKMcVma89z7PJd2Vn7R9'
MPRIVKEY = b';\xf4\xbfH\xd20\xea\x94\x01_\x10\x1b\xc3\xb0\xff\xc9\x17$?K\x02\xe5\x82R\xe5\xb3A\xdb\x87&E\x00'
MXPUB = 'xpub661MyMwAqRbcFARxxUUxAsjGGifn6Djc4YUsFbAisUU3GaEMn2BABYKVQTHrDtwvSfgY2bK8aFGyCNmB52SKjkFGP18sSRTNn1sCeez7Utd'

mpubkey, mpubcoin = bip32.from_extended_key_string(MXPUB)
mprivkey, mprivcoin = bip32.from_extended_key_string(MXPRV)


def test_from_extended_key():
    # Tests the failure modes of from_extended_key.
    with pytest.raises(TypeError):
        bip32._from_extended_key('')
    with pytest.raises(ValueError):
        bip32._from_extended_key(b'')
    with pytest.raises(CoinError):
        bip32._from_extended_key(bytes(78))
    # Invalid prefix byte
    raw = Base58.decode_check(MXPRV)
    with pytest.raises(ValueError):
        bip32._from_extended_key(raw[:45] + b'\1' + raw[46:])


class TestPubKey(object):

    def test_constructor(self):
        cls = bip32.PubKey
        raw_pubkey = b'\2' * 33
        chain_code = bytes(32)

        # Invalid constructions
        with pytest.raises(TypeError):
            cls(' ' * 33, chain_code, 0, 0)
        with pytest.raises(ValueError):
            cls(bytes(32), chain_code, -1, 0)
        with pytest.raises(ValueError):
            cls(bytes(33), chain_code, -1, 0)
        with pytest.raises(ValueError):
            cls(chain_code, chain_code, 0, 0)
        with pytest.raises(TypeError):
            cls(raw_pubkey, '0' * 32, 0, 0)
        with pytest.raises(ValueError):
            cls(raw_pubkey, bytes(31), 0, 0)
        with pytest.raises(ValueError):
            cls(raw_pubkey, chain_code, -1, 0)
        with pytest.raises(ValueError):
            cls(raw_pubkey, chain_code, 1 << 32, 0)
        with pytest.raises(ValueError):
            cls(raw_pubkey, chain_code, 0, -1)
        with pytest.raises(ValueError):
            cls(raw_pubkey, chain_code, 0, 256)
        with pytest.raises(ValueError):
            cls(b'\0' + b'\2' * 32, chain_code, 0, 0)

        # These are OK
        cls(b'\2' + b'\2' * 32, chain_code, 0, 0)
        cls(b'\3' + b'\2' * 32, chain_code, 0, 0)
        cls(raw_pubkey, chain_code, (1 << 32) - 1, 0)
        cls(raw_pubkey, chain_code, 0, 255)
        cls(raw_pubkey, chain_code, 0, 255, mpubkey)

        # Construction from verifying key
        dup = cls(mpubkey.verifying_key, chain_code, 0, 0)
        assert mpubkey.ec_point() == dup.ec_point()

        # Construction from raw pubkey bytes
        pubkey = mpubkey.pubkey_bytes
        dup = cls(pubkey, chain_code, 0, 0)
        assert mpubkey.ec_point() == dup.ec_point()

        # Construction from PubKey
        with pytest.raises(TypeError):
            cls(mpubkey, chain_code, 0, 0)

    def test_from_extended_key_string(self):
        assert mpubcoin == Bitcoin
        assert mpubkey.n == 0
        assert mpubkey.depth == 0
        assert mpubkey.parent is None
        assert mpubkey.chain_code == b'>V\x83\x92`\r\x17\xb3"\xa6\x7f\xaf\xc0\x930\xf7\x1e\xdc\x12i\x9c\xe4\xc0,a\x1a\x04\xec\x16\x19\xaeK'
        assert mpubkey.ec_point().x() == 44977109961578369385937116592536468905742111247230478021459394832226142714624

    def test_extended_key(self):
        # Test argument validation
        with pytest.raises(TypeError):
            mpubkey._extended_key('foot', bytes(33))
        with pytest.raises(ValueError):
            mpubkey._extended_key(b'foo', bytes(33))
        with pytest.raises(TypeError):
            mpubkey._extended_key(bytes(4), ' ' * 33)
        with pytest.raises(ValueError):
            mpubkey._extended_key(b'foot', bytes(32))
        mpubkey._extended_key(b'foot', bytes(33))

    def test_extended_key_string(self):
        # Implictly tests extended_key()
        assert mpubkey.extended_key_string(Bitcoin) == MXPUB
        chg_master = mpubkey.child(1)
        chg5 = chg_master.child(5)
        assert chg5.address(Bitcoin) == '1BsEFqGtcZnVBbPeimcfAFTitQdTLvUXeX'
        assert chg5.extended_key_string(Bitcoin) == 'xpub6AzPNZ1SAS7zmSnj6gakQ6tAKPzRVdQzieL3eCnoeT3A89nJaJKuUYWoZuYp8xWhCs1gF9yXAwGg7zKYhvCfhk9jrb1bULhLkQCwtB1Nnn1'

        ext_key_base58 = chg5.extended_key_string(Bitcoin)
        assert ext_key_base58 == 'xpub6AzPNZ1SAS7zmSnj6gakQ6tAKPzRVdQzieL3eCnoeT3A89nJaJKuUYWoZuYp8xWhCs1gF9yXAwGg7zKYhvCfhk9jrb1bULhLkQCwtB1Nnn1'

        # Check can recreate
        dup, coin = bip32.from_extended_key_string(ext_key_base58)
        assert coin is Bitcoin
        assert dup.chain_code == chg5.chain_code
        assert dup.n == chg5.n == 5
        assert dup.depth == chg5.depth == 2
        assert dup.ec_point() == chg5.ec_point()

    def test_child(self):
        '''Test child derivations agree with Electrum.'''
        rec_master = mpubkey.child(0)
        assert rec_master.address(Bitcoin) == '18zW4D1Vxx9jVPGzsFzgXj8KrSLHt7w2cg'
        chg_master = mpubkey.child(1)
        assert chg_master.parent is mpubkey
        assert chg_master.address(Bitcoin) == '1G8YpbkZd7bySHjpdQK3kMcHhc6BvHr5xy'
        rec0 = rec_master.child(0)
        assert rec0.address(Bitcoin) == '13nASW7rdE2dnSycrAP9VePhRmaLg9ziaw'
        rec19 = rec_master.child(19)
        assert rec19.address(Bitcoin) == '15QrXnPQ8aS8yCpA5tJkyvXfXpw8F8k3fB'
        chg0 = chg_master.child(0)
        assert chg0.parent is chg_master
        assert chg0.address(Bitcoin) == '1L6fNSVhWjuMKNDigA99CweGEWtcqqhzDj'

        with pytest.raises(ValueError):
            mpubkey.child(-1)
        with pytest.raises(ValueError):
            mpubkey.child(1 << 31)
        # OK
        mpubkey.child((1 << 31) - 1)

    def test_address(self):
        assert mpubkey.address(Bitcoin) == '1ENCpq6mbb1KYcaodGG7eTpSpYvPnDjFmU'

    def test_identifier(self):
        assert mpubkey.identifier() == b'\x92\x9c=\xb8\xd6\xe7\xebR\x90Td\x85\x1c\xa7\x0c\x8aE`\x87\xdd'

    def test_fingerprint(self):
        assert mpubkey.fingerprint() == b'\x92\x9c=\xb8'

    def test_parent_fingerprint(self):
        assert mpubkey.parent_fingerprint() == bytes(4)
        child = mpubkey.child(0)
        assert child.parent_fingerprint() == mpubkey.fingerprint()

    def test_pubkey_bytes(self):
        # Also tests _exponent_to_bytes
        pubkey = mpubkey.pubkey_bytes
        assert pubkey == b'\x02cp$a\x18\xa7\xc2\x18\xfdUt\x96\xeb\xb2\xb0\x86-Y\xc6Hn\x88\xf8>\x07\xfd\x12\xce\x8a\x88\xfb\x00'


class TestPrivKey(object):

    def test_constructor(self):
        # Includes full tests of _signing_key_from_privkey and
        # _privkey_secret_exponent
        cls = bip32.PrivKey
        chain_code = bytes(32)

        # These are invalid
        with pytest.raises(TypeError):
            cls('0' * 32, chain_code, 0, 0)
        with pytest.raises(ValueError):
            cls(b'0' * 31, chain_code, 0, 0)
        with pytest.raises(ValueError):
            cls(MPRIVKEY, chain_code, -1, 0)
        with pytest.raises(ValueError):
            cls(MPRIVKEY, chain_code, 1 << 32, 0)
        with pytest.raises(ValueError):
            cls(MPRIVKEY, chain_code, 0, -1)
        with pytest.raises(ValueError):
            cls(MPRIVKEY, chain_code, 0, 256)
        # Invalid exponents
        with pytest.raises(ValueError):
            cls(bip32._exponent_to_bytes(0), chain_code, 0, 0)
        with pytest.raises(ValueError):
            cls(bip32._exponent_to_bytes(cls.CURVE.order), chain_code, 0, 0)

        # These are good
        cls(MPRIVKEY, chain_code, 0, 0)
        cls(MPRIVKEY, chain_code, (1 << 32) - 1, 0)
        cls(MPRIVKEY, chain_code, 0, 0)
        cls(bip32._exponent_to_bytes(cls.CURVE.order - 1), chain_code, 0, 0)
        privkey = cls(MPRIVKEY, chain_code, 0, 255)

        # Construction with bad parent
        with pytest.raises(TypeError):
            cls(MPRIVKEY, chain_code, 0, 0, privkey.public_key)

        # Construction from signing key
        dup = cls(privkey.signing_key, chain_code, 0, 0)
        assert dup.ec_point() == privkey.ec_point()

        # Construction from PrivKey
        with pytest.raises(TypeError):
            cls(privkey, chain_code, 0, 0)

    def test_secret_exponent(self):
        assert mprivkey.secret_exponent() == 27118888947022743980605817563635166434451957861641813930891160184742578898176

    def test_identifier(self):
        assert mprivkey.identifier() == mpubkey.identifier()

    def test_address(self):
        assert mprivkey.address(Bitcoin) == mpubkey.address(Bitcoin)

    def test_fingerprint(self):
        assert mprivkey.fingerprint() == mpubkey.fingerprint()

    def test_parent_fingerprint(self):
        assert mprivkey.parent_fingerprint() == bytes(4)
        child = mprivkey.child(0)
        assert child.parent_fingerprint() == mprivkey.fingerprint()

    def test_from_extended_key_string(self):
        # Also tests privkey_bytes and public_key
        assert mprivcoin is Bitcoin
        assert mprivkey.privkey_bytes == MPRIVKEY
        assert mprivkey.ec_point() == mpubkey.ec_point()
        assert mprivkey.public_key.chain_code == mpubkey.chain_code
        assert mprivkey.public_key.n == mpubkey.n
        assert mprivkey.public_key.depth == mpubkey.depth

    def test_extended_key(self):
        # Test argument validation
        with pytest.raises(TypeError):
            mprivkey._extended_key('foot', bytes(33))
        with pytest.raises(ValueError):
            mprivkey._extended_key(b'foo', bytes(33))
        with pytest.raises(TypeError):
            mprivkey._extended_key(bytes(4), ' ' * 33)
        with pytest.raises(ValueError):
            mprivkey._extended_key(b'foot', bytes(32))
        mprivkey._extended_key(b'foot', bytes(33))

    def test_extended_key_string(self):
        # Also tests extended_key, WIF and privkey_bytes
        assert mprivkey.extended_key_string(Bitcoin) == MXPRV
        chg_master = mprivkey.child(1)
        chg5 = chg_master.child(5)
        assert chg5.WIF(Bitcoin) == 'L5kTYMuajTGWdYiMoD4V8k6LS4Bg3HFMA5UGTfxG9Wh7UKu9CHFC'
        ext_key_base58 = chg5.extended_key_string(Bitcoin)
        assert ext_key_base58 == 'xprv9x12y3UYL4ZhYxiFzf3k2xwRmN9w6Ah9MRQSqpPC67WBFMTA2m1evkCKidz7UYBa5i8QwxmU9Ju7giqEmcPRXKXwzgAJwssNeZNQLPT3LAY'

        # Check can recreate
        dup, coin = bip32.from_extended_key_string(ext_key_base58)
        assert coin is Bitcoin
        assert dup.chain_code == chg5.chain_code
        assert dup.n == chg5.n == 5
        assert dup.depth == chg5.depth == 2
        assert dup.ec_point() == chg5.ec_point()

    def test_child(self):
        '''Test child derivations agree with Electrum.'''
        # Also tests WIF, address
        rec_master = mprivkey.child(0)
        assert rec_master.address(Bitcoin) == '18zW4D1Vxx9jVPGzsFzgXj8KrSLHt7w2cg'
        chg_master = mprivkey.child(1)
        assert chg_master.parent is mprivkey
        assert chg_master.address(Bitcoin) == '1G8YpbkZd7bySHjpdQK3kMcHhc6BvHr5xy'
        rec0 = rec_master.child(0)
        assert rec0.WIF(Bitcoin) == 'L2M6WWMdu3YfWxvLGF76HZgHCA6idwVQx5QL91vfdqeZi8XAgWkz'
        rec19 = rec_master.child(19)
        assert rec19.WIF(Bitcoin) == 'KwMHa1fynU2J2iBGCuBZxumM2qDXHe5tVPU9VecNGQv3UCqnET7X'
        chg0 = chg_master.child(0)
        assert chg0.parent is chg_master
        assert chg0.WIF(Bitcoin) == 'L4J1esD4rYuBHXwjg72yi7Rw4G3iF2yUHt7LN9trpC3snCppUbq8'

        with pytest.raises(ValueError):
            mprivkey.child(-1)
        with pytest.raises(ValueError):
            mprivkey.child(1 << 32)
        # OK
        mprivkey.child((1 << 32) - 1)


class TestVectors():

    def test_vector1(self):
        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

        # Chain m
        m = bip32.PrivKey.from_seed(seed)
        xprv = m.extended_key_string(Bitcoin)
        assert xprv == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        xpub = m.public_key.extended_key_string(Bitcoin)
        assert xpub == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

        # Chain m/0H
        m1 = m.child(0 + m.HARDENED)
        xprv = m1.extended_key_string(Bitcoin)
        assert xprv == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
        xpub = m1.public_key.extended_key_string(Bitcoin)
        assert xpub == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

        # Chain m/0H/1
        m2 = m1.child(1)
        xprv = m2.extended_key_string(Bitcoin)
        assert xprv == "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
        xpub = m2.public_key.extended_key_string(Bitcoin)
        assert xpub == "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"

        # Chain m/0H/1/2H
        m3 = m2.child(2 + m.HARDENED)
        xprv = m3.extended_key_string(Bitcoin)
        assert xprv == "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
        xpub = m3.public_key.extended_key_string(Bitcoin)
        assert xpub == "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"

        # Chain m/0H/1/2H/2
        m4 = m3.child(2)
        xprv = m4.extended_key_string(Bitcoin)
        assert xprv == "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
        xpub = m4.public_key.extended_key_string(Bitcoin)
        assert xpub == "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"

        # Chain m/0H/1/2H/2/1000000000
        m5 = m4.child(1000000000)
        xprv = m5.extended_key_string(Bitcoin)
        assert xprv == "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
        xpub = m5.public_key.extended_key_string(Bitcoin)
        assert xpub == "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"

    def test_vector2(self):
        seed = bytes.fromhex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
        # Chain m
        m = bip32.PrivKey.from_seed(seed)
        xprv = m.extended_key_string(Bitcoin)
        assert xprv == "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
        xpub = m.public_key.extended_key_string(Bitcoin)
        assert xpub == "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"

        # Chain m/0
        m1 = m.child(0)
        xprv = m1.extended_key_string(Bitcoin)
        assert xprv == "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
        xpub = m1.public_key.extended_key_string(Bitcoin)
        assert xpub == "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"

        # Chain m/0H/2147483647H
        m2 = m1.child(2147483647 + m.HARDENED)
        xprv = m2.extended_key_string(Bitcoin)
        assert xprv == "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
        xpub = m2.public_key.extended_key_string(Bitcoin)
        assert xpub == "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"

        # Chain m/0H/2147483647H/1
        m3 = m2.child(1)
        xprv = m3.extended_key_string(Bitcoin)
        xpub = m3.public_key.extended_key_string(Bitcoin)
        assert xprv == "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
        assert xpub == "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"

        # Chain m/0/2147483647H/1/2147483646H
        m4 = m3.child(2147483646 + m.HARDENED)
        xprv = m4.extended_key_string(Bitcoin)
        xpub = m4.public_key.extended_key_string(Bitcoin)
        assert xprv == "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
        assert xpub == "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"

        # Chain m/0/2147483647H/1/2147483646H/2
        m5 = m4.child(2)
        xprv = m5.extended_key_string(Bitcoin)
        xpub = m5.public_key.extended_key_string(Bitcoin)
        assert xprv == "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
        assert xpub == "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"

    def test_vector3(self):
        seed = bytes.fromhex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")

        # Chain m
        m = bip32.PrivKey.from_seed(seed)
        xprv = m.extended_key_string(Bitcoin)
        xpub = m.public_key.extended_key_string(Bitcoin)
        assert xprv == "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
        assert xpub == "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"

        # Chain m/0H
        m1 = m.child(0 + m.HARDENED)
        xprv = m1.extended_key_string(Bitcoin)
        xpub = m1.public_key.extended_key_string(Bitcoin)
        assert xprv == "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
        assert xpub == "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
