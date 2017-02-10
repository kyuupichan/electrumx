# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Module providing coin abstraction.

Anything coin-specific should go in this file and be subclassed where
necessary for appropriate handling.
'''

from decimal import Decimal
from functools import partial
from hashlib import sha256
import inspect
import re
import struct
import sys

from lib.hash import Base58, hash160, ripemd160, double_sha256, hash_to_str
from lib.script import ScriptPubKey
from lib.tx import Deserializer, DeserializerSegWit, DeserializerFairCoin
import lib.util as util


class CoinError(Exception):
    '''Exception raised for coin-related errors.'''


class Coin(object):
    '''Base class of coin hierarchy.'''

    REORG_LIMIT = 200
    # Not sure if these are coin-specific
    RPC_URL_REGEX = re.compile('.+@[^:]+(:[0-9]+)?')
    VALUE_PER_COIN = 100000000
    CHUNK_SIZE = 2016
    IRC_SERVER = "irc.freenode.net"
    IRC_PORT = 6667
    HASHX_LEN = 11
    # Peer discovery
    PEER_DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    PEERS = []

    @classmethod
    def lookup_coin_class(cls, name, net):
        '''Return a coin class given name and network.

        Raise an exception if unrecognised.'''
        req_attrs = ('TX_COUNT', 'TX_COUNT_HEIGHT', 'TX_PER_BLOCK',
                     'IRC_CHANNEL', 'IRC_PREFIX')
        for coin in util.subclasses(Coin):
            if (coin.NAME.lower() == name.lower()
                    and coin.NET.lower() == net.lower()):
                missing = [attr for attr in req_attrs
                           if not hasattr(coin, attr)]
                if missing:
                    raise CoinError('coin {} missing {} attributes'
                                    .format(name, missing))
                return coin
        raise CoinError('unknown coin {} and network {} combination'
                        .format(name, net))

    @classmethod
    def sanitize_url(cls, url):
        # Remove surrounding ws and trailing /s
        url = url.strip().rstrip('/')
        match = cls.RPC_URL_REGEX.match(url)
        if not match:
            raise CoinError('invalid daemon URL: "{}"'.format(url))
        if match.groups()[0] is None:
            url += ':{:d}'.format(cls.RPC_PORT)
        if not url.startswith('http://'):
            url = 'http://' + url
        return url + '/'

    @classmethod
    def daemon_urls(cls, urls):
        return [cls.sanitize_url(url) for url in urls.split(',')]

    @classmethod
    def genesis_block(cls, block):
        '''Check the Genesis block is the right one for this coin.

        Return the block less its unspendable coinbase.
        '''
        header = cls.block_header(block, 0)
        header_hex_hash = hash_to_str(cls.header_hash(header))
        if header_hex_hash != cls.GENESIS_HASH:
            raise CoinError('genesis block has hash {} expected {}'
                            .format(header_hex_hash, cls.GENESIS_HASH))

        return header + bytes(1)

    @classmethod
    def hashX_from_script(cls, script):
        '''Returns a hashX from a script.'''
        script = ScriptPubKey.hashX_script(script)
        if script is None:
            return None
        return sha256(script).digest()[:cls.HASHX_LEN]

    @util.cachedproperty
    def address_handlers(cls):
        return ScriptPubKey.PayToHandlers(
            address=cls.P2PKH_address_from_hash160,
            script_hash=cls.P2SH_address_from_hash160,
            pubkey=cls.P2PKH_address_from_pubkey,
            unspendable=lambda: None,
            strange=lambda script: None,
        )

    @classmethod
    def address_from_script(cls, script):
        '''Given a pk_script, return the adddress it pays to, or None.'''
        return ScriptPubKey.pay_to(cls.address_handlers, script)

    @staticmethod
    def lookup_xverbytes(verbytes):
        '''Return a (is_xpub, coin_class) pair given xpub/xprv verbytes.'''
        # Order means BTC testnet will override NMC testnet
        for coin in Coin.coin_classes():
            if verbytes == coin.XPUB_VERBYTES:
                return True, coin
            if verbytes == coin.XPRV_VERBYTES:
                return False, coin
        raise CoinError('version bytes unrecognised')

    @classmethod
    def address_to_hashX(cls, address):
        '''Return a hashX given a coin address.'''
        return cls.hashX_from_script(cls.pay_to_address_script(address))

    @classmethod
    def P2PKH_address_from_hash160(cls, hash160):
        '''Return a P2PKH address given a public key.'''
        assert len(hash160) == 20
        return Base58.encode_check(bytes([cls.P2PKH_VERBYTE]) + hash160)

    @classmethod
    def P2PKH_address_from_pubkey(cls, pubkey):
        '''Return a coin address given a public key.'''
        return cls.P2PKH_address_from_hash160(hash160(pubkey))

    @classmethod
    def P2SH_address_from_hash160(cls, hash160):
        '''Return a coin address given a hash160.'''
        assert len(hash160) == 20
        return Base58.encode_check(bytes([cls.P2SH_VERBYTE]) + hash160)

    @classmethod
    def multisig_address(cls, m, pubkeys):
        '''Return the P2SH address for an M of N multisig transaction.

        Pass the N pubkeys of which M are needed to sign it.  If
        generating an address for a wallet, it is the caller's
        responsibility to sort them to ensure order does not matter
        for, e.g., wallet recovery.
        '''
        script = cls.pay_to_multisig_script(m, pubkeys)
        return cls.P2SH_address_from_hash160(hash160(script))

    @classmethod
    def pay_to_multisig_script(cls, m, pubkeys):
        '''Return a P2SH script for an M of N multisig transaction.'''
        return ScriptPubKey.multisig_script(m, pubkeys)

    @classmethod
    def pay_to_pubkey_script(cls, pubkey):
        '''Return a pubkey script that pays to a pubkey.

        Pass the raw pubkey bytes (length 33 or 65).
        '''
        return ScriptPubKey.P2PK_script(pubkey)

    @classmethod
    def pay_to_address_script(cls, address):
        '''Return a pubkey script that pays to a pubkey hash.

        Pass the address (either P2PKH or P2SH) in base58 form.
        '''
        raw = Base58.decode_check(address)

        # Require version byte plus hash160.
        verbyte = -1
        if len(raw) == 21:
            verbyte, hash_bytes = raw[0], raw[1:]

        if verbyte == cls.P2PKH_VERBYTE:
            return ScriptPubKey.P2PKH_script(hash_bytes)
        if verbyte == cls.P2SH_VERBYTE:
            return ScriptPubKey.P2SH_script(hash_bytes)

        raise CoinError('invalid address: {}'.format(address))

    @classmethod
    def prvkey_WIF(privkey_bytes, compressed):
        '''Return the private key encoded in Wallet Import Format.'''
        payload = bytearray([cls.WIF_BYTE]) + privkey_bytes
        if compressed:
            payload.append(0x01)
        return Base58.encode_check(payload)

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header)

    @classmethod
    def header_prevhash(cls, header):
        '''Given a header return previous hash'''
        return header[4:36]

    @classmethod
    def header_offset(cls, height):
        '''Given a header height return its offset in the headers file.

        If header sizes change at some point, this is the only code
        that needs updating.'''
        return height * 80

    @classmethod
    def header_len(cls, height):
        '''Given a header height return its length.'''
        return cls.header_offset(height + 1) - cls.header_offset(height)

    @classmethod
    def block_header(cls, block, height):
        '''Returns the block header given a block and its height.'''
        return block[:cls.header_len(height)]

    @classmethod
    def block_txs(cls, block, height):
        '''Returns a list of (deserialized_tx, tx_hash) pairs given a
        block and its height.'''
        deserializer = cls.deserializer()
        return deserializer(block[cls.header_len(height):]).read_block()

    @classmethod
    def decimal_value(cls, value):
        '''Return the number of standard coin units as a Decimal given a
        quantity of smallest units.

        For example 1 BTC is returned for 100 million satoshis.
        '''
        return Decimal(value) / cls.VALUE_PER_COIN

    @classmethod
    def electrum_header(cls, header, height):
        version, = struct.unpack('<I', header[:4])
        timestamp, bits, nonce = struct.unpack('<III', header[68:80])

        return {
            'block_height': height,
            'version': version,
            'prev_block_hash': hash_to_str(header[4:36]),
            'merkle_root': hash_to_str(header[36:68]),
            'timestamp': timestamp,
            'bits': bits,
            'nonce': nonce,
        }

    @classmethod
    def deserializer(cls):
        return Deserializer


class Bitcoin(Coin):
    NAME = "Bitcoin"
    SHORTNAME = "BTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = 0x00
    P2SH_VERBYTE = 0x05
    WIF_BYTE = 0x80
    GENESIS_HASH = ('000000000019d6689c085ae165831e93'
                    '4ff763ae46a2a6c172b3f1b60a8ce26f')
    TX_COUNT = 156335304
    TX_COUNT_HEIGHT = 429972
    TX_PER_BLOCK = 1800
    IRC_PREFIX = "E_"
    IRC_CHANNEL = "#electrum"
    RPC_PORT = 8332
    PEERS = [
        '4cii7ryno5j3axe4.onion t'
        'btc.smsys.me s995',
        'ca6ulp2j2mpsft3y.onion s t',
        'electrum.be s t',
        'electrum.trouth.net s t',
        'electrum.vom-stausee.de s t',
        'electrum3.hachre.de s t',
        'electrum.hsmiths.com s t',
        'erbium1.sytes.net s t',
        'h.1209k.com s t',
        'helicarrier.bauerj.eu s t',
        'ozahtqwp25chjdjd.onion s t',
        'us11.einfachmalnettsein.de s t',
    ]


class BitcoinTestnet(Bitcoin):
    SHORTNAME = "XTN"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = 0x6f
    P2SH_VERBYTE = 0xc4
    WIF_BYTE = 0xef
    GENESIS_HASH = ('000000000933ea01ad0ee984209779ba'
                    'aec3ced90fa3f408719526f8d77f4943')
    REORG_LIMIT = 2000
    TX_COUNT = 12242438
    TX_COUNT_HEIGHT = 1035428
    TX_PER_BLOCK = 21
    IRC_PREFIX = "ET_"
    RPC_PORT = 18332
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    PEERS = [
        'electrum.akinbo.org s t',
        'he36kyperp3kbuxu.onion s t',
        'electrum-btc-testnet.petrkr.net s t',
        'testnet.hsmiths.com t53011 s53012',
        'hsmithsxurybd7uh.onion t53011',
        'testnet.not.fyi s t',
    ]


class BitcoinTestnetSegWit(BitcoinTestnet):
    '''Bitcoin Testnet for Core bitcoind >= 0.13.1.

    Unfortunately 0.13.1 broke backwards compatibility of the RPC
    interface's TX serialization, SegWit transactions serialize
    differently than with earlier versions.  If you are using such a
    bitcoind on testnet, you must use this class as your "COIN".
    '''
    NET = "testnet-segwit"

    @classmethod
    def deserializer(cls):
        return DeserializerSegWit


class Litecoin(Coin):
    NAME = "Litecoin"
    SHORTNAME = "LTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("019da462")
    XPRV_VERBYTES = bytes.fromhex("019d9cfe")
    P2PKH_VERBYTE = 0x30
    P2SH_VERBYTE = 0x05
    WIF_BYTE = 0xb0
    GENESIS_HASH = ('12a765e31ffd4059bada1e25190f6e98'
                    'c99d9714d334efa41a195a7e7e04bfe2')
    TX_COUNT = 8908766
    TX_COUNT_HEIGHT = 1105256
    TX_PER_BLOCK = 10
    IRC_PREFIX = "EL_"
    IRC_CHANNEL = "#electrum-ltc"
    RPC_PORT = 9332


class LitecoinTestnet(Litecoin):
    SHORTNAME = "XLT"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("0436f6e1")
    XPRV_VERBYTES = bytes.fromhex("0436ef7d")
    P2PKH_VERBYTE = 0x6f
    P2SH_VERBYTE = 0xc4
    WIF_BYTE = 0xef
    GENESIS_HASH = ('f5ae71e26c74beacc88382716aced69c'
                    'ddf3dffff24f384e1808905e0188f68f')


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
    GENESIS_HASH = ('000000000062b72c5e2ceb45fbc8587e'
                    '807c155b0da735e6483dfba2f0a9c770')


class NamecoinTestnet(Namecoin):
    NAME = "Namecoin"
    SHORTNAME = "XNM"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = 0x6f
    P2SH_VERBYTE = 0xc4
    WIF_BYTE = 0xef
    # TODO add GENESIS_HASH


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
    GENESIS_HASH = ('1a91e3dace36e2be3bf030a65679fe82'
                    '1aa1d6ef92e7c9902eb318182c355691')


class DogecoinTestnet(Dogecoin):
    NAME = "Dogecoin"
    SHORTNAME = "XDT"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("0432a9a8")
    XPRV_VERBYTES = bytes.fromhex("0432a243")
    P2PKH_VERBYTE = 0x71
    P2SH_VERBYTE = 0xc4
    WIF_BYTE = 0xf1
    GENESIS_HASH = ('bb0a78264637406b6360aad926284d54'
                    '4d7049f45189db5664f3c4d07350559e')


# Source: https://github.com/dashpay/dash
class Dash(Coin):
    NAME = "Dash"
    SHORTNAME = "DASH"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("02fe52cc")
    XPRV_VERBYTES = bytes.fromhex("02fe52f8")
    GENESIS_HASH = ('00000ffd590b1485b3caadc19b22e637'
                    '9c733355108f107a430458cdf3407ab6')
    P2PKH_VERBYTE = 0x4c
    P2SH_VERBYTE = 0x10
    WIF_BYTE = 0xcc
    TX_COUNT_HEIGHT = 569399
    TX_COUNT = 2157510
    TX_PER_BLOCK = 4
    RPC_PORT = 9998
    IRC_PREFIX = "D_"
    IRC_CHANNEL = "#electrum-dash"
    PEERS = [
        'electrum.dash.org s t'
        'electrum.masternode.io s t',
        'electrum-drk.club s t',
        'dashcrypto.space s t',
        'electrum.dash.siampm.com s t',
        'wl4sfwq2hwxnodof.onion s t',
    ]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x11_hash
        return x11_hash.getPoWHash(header)


class DashTestnet(Dash):
    SHORTNAME = "tDASH"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("3a805837")
    XPRV_VERBYTES = bytes.fromhex("3a8061a0")
    GENESIS_HASH = ('00000bafbc94add76cb75e2ec9289483'
                    '7288a481e5c005f6563d91623bf8bc2c')
    P2PKH_VERBYTE = 0x8c
    P2SH_VERBYTE = 0x13
    WIF_BYTE = 0xef
    TX_COUNT_HEIGHT = 101619
    TX_COUNT = 132681
    TX_PER_BLOCK = 1
    RPC_PORT = 19998
    IRC_PREFIX = "d_"
    PEER_DEFAULT_PORTS = {'t':'51001', 's':'51002'}
    PEERS = [
        'electrum.dash.siampm.com s t',
    ]


class Argentum(Coin):
    NAME = "Argentum"
    SHORTNAME = "ARG"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = 0x17
    P2SH_VERBYTE = 0x05
    WIF_BYTE = 0x97
    GENESIS_HASH = ('88c667bc63167685e4e4da058fffdfe8'
                    'e007e5abffd6855de52ad59df7bb0bb2')
    TX_COUNT = 2263089
    TX_COUNT_HEIGHT = 2050260
    TX_PER_BLOCK = 2000
    IRC_PREFIX = "A_"
    IRC_CHANNEL = "#electrum-arg"
    RPC_PORT = 13581


class ArgentumTestnet(Argentum):
    SHORTNAME = "XRG"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = 0x6f
    P2SH_VERBYTE = 0xc4
    WIF_BYTE = 0xef
    REORG_LIMIT = 2000


class DigiByte(Coin):
    NAME = "DigiByte"
    SHORTNAME = "DGB"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = 0x1E
    P2SH_VERBYTE = 0x05
    WIF_BYTE = 0x80
    GENESIS_HASH = ('7497ea1b465eb39f1c8f507bc877078f'
                    'e016d6fcb6dfad3a64c98dcc6e1e8496')
    TX_COUNT = 1046018
    TX_COUNT_HEIGHT = 1435000
    TX_PER_BLOCK = 1000
    IRC_PREFIX = "DE_"
    IRC_CHANNEL = "#electrum-dgb"
    RPC_PORT = 12022


class DigiByteTestnet(DigiByte):
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = 0x6f
    P2SH_VERBYTE = 0xc4
    WIF_BYTE = 0xef
    GENESIS_HASH = ('b5dca8039e300198e5fe7cd23bdd1728'
                    'e2a444af34c447dbd0916fa3430a68c2')
    IRC_PREFIX = "DET_"
    IRC_CHANNEL = "#electrum-dgb"
    RPC_PORT = 15022
    REORG_LIMIT = 2000


class FairCoin(Coin):
    NAME = "FairCoin"
    SHORTNAME = "FAIR"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = 0x5f
    P2SH_VERBYTE = 0x24
    WIF_BYTE = 0xdf
    GENESIS_HASH=('1f701f2b8de1339dc0ec908f3fb6e9b0'
                  'b870b6f20ba893e120427e42bbc048d7')
    TX_COUNT = 1000
    TX_COUNT_HEIGHT = 1000
    TX_PER_BLOCK = 1
    IRC_PREFIX = "E_"
    IRC_CHANNEL = "#fairlectrum"
    RPC_PORT = 40405
    PEER_DEFAULT_PORTS = {'t': '51811', 's': '51812'}
    PEERS = [
        'fairlectrum.fair-coin.net s',
        'fairlectrum.fair.to s'
    ]

    @classmethod
    def header_offset(cls, height):
        '''Given a header height return its offset in the headers file.
        If header sizes change at some point, this is the only code
        that needs updating.'''
        return height * 108

    @classmethod
    def header_len(cls, height):
        '''Given a header height return its length.'''
        return 108

    @classmethod
    def block_txs(cls, block, height):
        '''Returns a list of (deserialized_tx, tx_hash) pairs given a
        block and its height.'''

        if height == 0:
            return []

        deserializer = cls.deserializer()
        return deserializer(block[cls.header_len(height):]).read_block()

    @classmethod
    def electrum_header(cls, header, height):
        version, = struct.unpack('<I', header[:4])
        timestamp, creatorId = struct.unpack('<II', header[100:108])
        return {
            'block_height': height,
            'version': version,
            'prev_block_hash': hash_to_str(header[4:36]),
            'merkle_root': hash_to_str(header[36:68]),
            'payload_hash': hash_to_str(header[68:100]),
            'timestamp': timestamp,
            'creatorId': creatorId,
        }

    @classmethod
    def deserializer(cls):
        return DeserializerFairCoin
