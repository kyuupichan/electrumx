# See the file "COPYING" for information about the copyright
# and warranty status of this software.


import inspect
import sys

from lib.hash import Base58, hash160
from lib.script import ScriptPubKey
from lib.tx import Deserializer


class CoinError(Exception):
    pass


class Coin(object):
    '''Base class of coin hierarchy'''

    # Not sure if these are coin-specific
    HEADER_LEN = 80
    DEFAULT_RPC_PORT = 8332

    @staticmethod
    def coins():
        is_coin = lambda obj: (inspect.isclass(obj)
                               and issubclass(obj, Coin)
                               and obj != Coin)
        pairs = inspect.getmembers(sys.modules[__name__], is_coin)
        # Returned in the order they appear in this file
        return [pair[1] for pair in pairs]

    @classmethod
    def lookup_coin_class(cls, name, net):
        for coin in cls.coins():
            if (coin.NAME.lower() == name.lower()
                    and coin.NET.lower() == net.lower()):
                return coin
        raise CoinError('unknown coin {} and network {} combination'
                        .format(name, net))

    @staticmethod
    def lookup_xverbytes(verbytes):
        # Order means BTC testnet will override NMC testnet
        for coin in Coin.coins():
            if verbytes == coin.XPUB_VERBYTES:
                return True, coin
            if verbytes == coin.XPRV_VERBYTES:
                return False, coin
        raise CoinError("version bytes unrecognised")

    @classmethod
    def address_to_hash160(cls, addr):
        '''Returns a hash160 given an address'''
        result = Base58.decode_check(addr)
        if len(result) != 21:
            raise CoinError('invalid address: {}'.format(addr))
        return result[1:]

    @classmethod
    def P2PKH_address_from_hash160(cls, hash_bytes):
        '''Returns a P2PKH address given a public key'''
        assert len(hash_bytes) == 20
        payload = bytes([cls.P2PKH_VERBYTE]) + hash_bytes
        return Base58.encode_check(payload)

    @classmethod
    def P2PKH_address_from_pubkey(cls, pubkey):
        '''Returns a coin address given a public key'''
        return cls.P2PKH_address_from_hash160(hash160(pubkey))

    @classmethod
    def P2SH_address_from_hash160(cls, pubkey_bytes):
        '''Returns a coin address given a public key'''
        assert len(hash_bytes) == 20
        payload = bytes([cls.P2SH_VERBYTE]) + hash_bytes
        return Base58.encode_check(payload)

    @classmethod
    def multisig_address(cls, m, pubkeys):
        '''Returns the P2SH address for an M of N multisig transaction.  Pass
        the N pubkeys of which M are needed to sign it.  If generating
        an address for a wallet, it is the caller's responsibility to
        sort them to ensure order does not matter for, e.g., wallet
        recovery.'''
        script = cls.pay_to_multisig_script(m, pubkeys)
        payload = bytes([cls.P2SH_VERBYTE]) + hash160(pubkey_bytes)
        return Base58.encode_check(payload)

    @classmethod
    def pay_to_multisig_script(cls, m, pubkeys):
        '''Returns a P2SH multisig script for an M of N multisig
        transaction.'''
        return ScriptPubKey.multisig_script(m, pubkeys)

    @classmethod
    def pay_to_pubkey_script(cls, pubkey):
        '''Returns a pubkey script that pays to pubkey.  The input is the
        raw pubkey bytes (length 33 or 65).'''
        return ScriptPubKey.P2PK_script(pubkey)

    @classmethod
    def pay_to_address_script(cls, address):
        '''Returns a pubkey script that pays to pubkey hash.  Input is the
        address (either P2PKH or P2SH) in base58 form.'''
        raw = Base58.decode_check(address)

        # Require version byte plus hash160.
        verbyte = -1
        if len(raw) == 21:
            verbyte, hash_bytes = raw[0], raw[1:]

        if verbyte == cls.P2PKH_VERYBYTE:
            return ScriptPubKey.P2PKH_script(hash_bytes)
        if verbyte == cls.P2SH_VERBYTE:
            return ScriptPubKey.P2SH_script(hash_bytes)

        raise CoinError('invalid address: {}'.format(address))

    @classmethod
    def prvkey_WIF(privkey_bytes, compressed):
        "The private key encoded in Wallet Import Format"
        payload = bytearray([cls.WIF_BYTE]) + privkey_bytes
        if compressed:
            payload.append(0x01)
        return Base58.encode_check(payload)

    @classmethod
    def read_block(cls, block):
        assert isinstance(block, memoryview)
        d = Deserializer(block[cls.HEADER_LEN:])
        return d.read_block()


class Bitcoin(Coin):
    NAME = "Bitcoin"
    SHORTNAME = "BTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = 0x00
    P2SH_VERBYTE = 0x05
    WIF_BYTE = 0x80
    GENESIS_HASH=(b'000000000019d6689c085ae165831e93'
                  b'4ff763ae46a2a6c172b3f1b60a8ce26f')

class BitcoinTestnet(Coin):
    NAME = "Bitcoin"
    SHORTNAME = "XTN"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = 0x6f
    P2SH_VERBYTE = 0xc4
    WIF_BYTE = 0xef

# Source: pycoin and others
class Litecoin(Coin):
    NAME = "Litecoin"
    SHORTNAME = "LTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("019da462")
    XPRV_VERBYTES = bytes.fromhex("019d9cfe")
    P2PKH_VERBYTE = 0x30
    P2SH_VERBYTE = 0x05
    WIF_BYTE = 0xb0

class LitecoinTestnet(Coin):
    NAME = "Litecoin"
    SHORTNAME = "XLT"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("0436f6e1")
    XPRV_VERBYTES = bytes.fromhex("0436ef7d")
    P2PKH_VERBYTE = 0x6f
    P2SH_VERBYTE = 0xc4
    WIF_BYTE = 0xef

# Source: namecoin.org
class Namecoin(Coin):
    NAME = "Namecoin"
    SHORTNAME = "NMC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("d7dd6370")
    XPRV_VERBYTES = bytes.fromhex("d7dc6e31")
    P2PKH_VERBYTE = 0x34
    P2SH_VERBYTE = 0x0d
    WIF_BYTE = 0xe4

class NamecoinTestnet(Coin):
    NAME = "Namecoin"
    SHORTNAME = "XNM"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = 0x6f
    P2SH_VERBYTE = 0xc4
    WIF_BYTE = 0xef

# For DOGE there is disagreement across sites like bip32.org and
# pycoin.  Taken from bip32.org and bitmerchant on github
class Dogecoin(Coin):
    NAME = "Dogecoin"
    SHORTNAME = "DOGE"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("02facafd")
    XPRV_VERBYTES = bytes.fromhex("02fac398")
    P2PKH_VERBYTE = 0x1e
    P2SH_VERBYTE = 0x16
    WIF_BYTE = 0x9e

class DogecoinTestnet(Coin):
    NAME = "Dogecoin"
    SHORTNAME = "XDT"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("0432a9a8")
    XPRV_VERBYTES = bytes.fromhex("0432a243")
    P2PKH_VERBYTE = 0x71
    P2SH_VERBYTE = 0xc4
    WIF_BYTE = 0xf1

# Source: pycoin
class Dash(Coin):
    NAME = "Dash"
    SHORTNAME = "DASH"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("02fe52cc")
    XPRV_VERBYTES = bytes.fromhex("02fe52f8")
    P2PKH_VERBYTE = 0x4c
    P2SH_VERBYTE = 0x10
    WIF_BYTE = 0xcc

class DashTestnet(Coin):
    NAME = "Dogecoin"
    SHORTNAME = "tDASH"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("3a805837")
    XPRV_VERBYTES = bytes.fromhex("3a8061a0")
    P2PKH_VERBYTE = 0x8b
    P2SH_VERBYTE = 0x13
    WIF_BYTE = 0xef
