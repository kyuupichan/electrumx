# Copyright (c) 2016-2017, Neil Booth
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

'''Module providing coin abstraction.

Anything coin-specific should go in this file and be subclassed where
necessary for appropriate handling.
'''

from collections import namedtuple
import re
import struct
from decimal import Decimal
from hashlib import sha256
from functools import partial
import base64

import lib.util as util
from lib.hash import Base58, hash160, double_sha256, hash_to_str
from lib.script import ScriptPubKey, OpCodes
import lib.tx as lib_tx
from server.block_processor import BlockProcessor
import server.daemon as daemon
from server.session import ElectrumX, DashElectrumX


Block = namedtuple("Block", "raw header transactions")
OP_RETURN = OpCodes.OP_RETURN


class CoinError(Exception):
    '''Exception raised for coin-related errors.'''


class Coin(object):
    '''Base class of coin hierarchy.'''

    REORG_LIMIT = 200
    # Not sure if these are coin-specific
    RPC_URL_REGEX = re.compile('.+@(\[[0-9a-fA-F:]+\]|[^:]+)(:[0-9]+)?')
    VALUE_PER_COIN = 100000000
    CHUNK_SIZE = 2016
    HASHX_LEN = 11
    BASIC_HEADER_SIZE = 80
    STATIC_BLOCK_HEADERS = True
    SESSIONCLS = ElectrumX
    DESERIALIZER = lib_tx.Deserializer
    DAEMON = daemon.Daemon
    BLOCK_PROCESSOR = BlockProcessor
    XPUB_VERBYTES = bytes('????', 'utf-8')
    XPRV_VERBYTES = bytes('????', 'utf-8')
    ENCODE_CHECK = Base58.encode_check
    DECODE_CHECK = Base58.decode_check
    # Peer discovery
    PEER_DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    PEERS = []

    @classmethod
    def lookup_coin_class(cls, name, net):
        '''Return a coin class given name and network.

        Raise an exception if unrecognised.'''
        req_attrs = ['TX_COUNT', 'TX_COUNT_HEIGHT', 'TX_PER_BLOCK']
        for coin in util.subclasses(Coin):
            if (coin.NAME.lower() == name.lower() and
                    coin.NET.lower() == net.lower()):
                coin_req_attrs = req_attrs.copy()
                missing = [attr for attr in coin_req_attrs
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
        if match.groups()[1] is None:
            url += ':{:d}'.format(cls.RPC_PORT)
        if not url.startswith('http://') and not url.startswith('https://'):
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
        '''Returns a hashX from a script, or None if the script is provably
        unspendable so the output can be dropped.
        '''
        if script and script[0] == OP_RETURN:
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
        for coin in util.subclasses(Coin):
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
        return cls.ENCODE_CHECK(cls.P2PKH_VERBYTE + hash160)

    @classmethod
    def P2PKH_address_from_pubkey(cls, pubkey):
        '''Return a coin address given a public key.'''
        return cls.P2PKH_address_from_hash160(hash160(pubkey))

    @classmethod
    def P2SH_address_from_hash160(cls, hash160):
        '''Return a coin address given a hash160.'''
        assert len(hash160) == 20
        return cls.ENCODE_CHECK(cls.P2SH_VERBYTES[0] + hash160)

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
        raw = cls.DECODE_CHECK(address)

        # Require version byte(s) plus hash160.
        verbyte = -1
        verlen = len(raw) - 20
        if verlen > 0:
            verbyte, hash_bytes = raw[:verlen], raw[verlen:]

        if verbyte == cls.P2PKH_VERBYTE:
            return ScriptPubKey.P2PKH_script(hash_bytes)
        if verbyte in cls.P2SH_VERBYTES:
            return ScriptPubKey.P2SH_script(hash_bytes)

        raise CoinError('invalid address: {}'.format(address))

    @classmethod
    def privkey_WIF(cls, privkey_bytes, compressed):
        '''Return the private key encoded in Wallet Import Format.'''
        payload = bytearray(cls.WIF_BYTE) + privkey_bytes
        if compressed:
            payload.append(0x01)
        return cls.ENCODE_CHECK(payload)

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header)

    @classmethod
    def header_prevhash(cls, header):
        '''Given a header return previous hash'''
        return header[4:36]

    @classmethod
    def static_header_offset(cls, height):
        '''Given a header height return its offset in the headers file.

        If header sizes change at some point, this is the only code
        that needs updating.'''
        assert cls.STATIC_BLOCK_HEADERS
        return height * cls.BASIC_HEADER_SIZE

    @classmethod
    def static_header_len(cls, height):
        '''Given a header height return its length.'''
        return cls.static_header_offset(height + 1) \
               - cls.static_header_offset(height)

    @classmethod
    def block_header(cls, block, height):
        '''Returns the block header given a block and its height.'''
        return block[:cls.static_header_len(height)]

    @classmethod
    def block(cls, raw_block, height):
        '''Return a Block namedtuple given a raw block and its height.'''
        header = cls.block_header(raw_block, height)
        txs = cls.DESERIALIZER(raw_block, start=len(header)).read_tx_block()
        return Block(raw_block, header, txs)

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


class AuxPowMixin(object):
    STATIC_BLOCK_HEADERS = False
    DESERIALIZER = lib_tx.DeserializerAuxPow

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header[:cls.BASIC_HEADER_SIZE])

    @classmethod
    def block_header(cls, block, height):
        '''Return the AuxPow block header bytes'''
        deserializer = cls.DESERIALIZER(block)
        return deserializer.read_header(height, cls.BASIC_HEADER_SIZE)


class EquihashMixin(object):
    STATIC_BLOCK_HEADERS = False
    BASIC_HEADER_SIZE = 140 # Excluding Equihash solution
    DESERIALIZER = lib_tx.DeserializerEquihash

    @classmethod
    def electrum_header(cls, header, height):
        version, = struct.unpack('<I', header[:4])
        timestamp, bits = struct.unpack('<II', header[100:108])

        return {
            'block_height': height,
            'version': version,
            'prev_block_hash': hash_to_str(header[4:36]),
            'merkle_root': hash_to_str(header[36:68]),
            'timestamp': timestamp,
            'bits': bits,
            'nonce': hash_to_str(header[108:140]),
        }

    @classmethod
    def block_header(cls, block, height):
        '''Return the block header bytes'''
        deserializer = cls.DESERIALIZER(block)
        return deserializer.read_header(height, cls.BASIC_HEADER_SIZE)


class ScryptMixin(object):

    DESERIALIZER = lib_tx.DeserializerTxTime
    HEADER_HASH = None

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        if cls.HEADER_HASH is None:
            import scrypt
            cls.HEADER_HASH = lambda x: scrypt.hash(x, x, 1024, 1, 1, 32)

        version, = struct.unpack('<I', header[:4])
        if version > 6:
            return super().header_hash(header)
        else:
            return cls.HEADER_HASH(header)


class KomodoMixin(object):
    P2PKH_VERBYTE = bytes.fromhex("3C")
    P2SH_VERBYTES = [bytes.fromhex("55")]
    WIF_BYTE = bytes.fromhex("BC")
    GENESIS_HASH = ('027e3758c3a65b12aa1046462b486d0a'
                    '63bfa1beae327897f56c5cfb7daaae71')
    DESERIALIZER = lib_tx.DeserializerZcash


class BitcoinMixin(object):
    SHORTNAME = "BTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("00")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('000000000019d6689c085ae165831e93'
                    '4ff763ae46a2a6c172b3f1b60a8ce26f')
    RPC_PORT = 8332

class HOdlcoin(Coin):
    NAME = "HOdlcoin"
    SHORTNAME = "HODLC"
    NET = "mainnet"
    BASIC_HEADER_SIZE = 88
    P2PKH_VERBYTE = bytes.fromhex("28")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("a8")
    GENESIS_HASH = ('008872e5582924544e5c707ee4b839bb'
                    '82c28a9e94e917c94b40538d5658c04b')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 258858
    TX_COUNT_HEIGHT = 382138
    TX_PER_BLOCK = 5


class BitcoinCash(BitcoinMixin, Coin):
    NAME = "BitcoinCash"
    SHORTNAME = "BCC"
    TX_COUNT = 243631085
    TX_COUNT_HEIGHT = 479636
    TX_PER_BLOCK = 50
    PEERS = [
        'electroncash.cascharia.com s50002',
        'bch.arihanc.com t52001 s52002',
        'bccarihace4jdcnt.onion t52001 s52002',
        'jelectrum-cash.1209k.com s t',
        'abc.vom-stausee.de t52001 s52002',
        'abc1.hsmiths.com t60001 s60002',
        'electroncash.checksum0.com s t',
        'electron.jns.im s t',
        'electrumx-cash.1209k.com s t',
    ]


class BitcoinSegwit(BitcoinMixin, Coin):
    NAME = "BitcoinSegwit"
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 217380620
    TX_COUNT_HEIGHT = 464000
    TX_PER_BLOCK = 1800
    PEERS = [
        'btc.smsys.me s995',
        'E-X.not.fyi s t',
        'elec.luggs.co s443',
        'electrum.vom-stausee.de s t',
        'electrum3.hachre.de s t',
        'electrum.hsmiths.com s t',
        'helicarrier.bauerj.eu s t',
        'hsmiths4fyqlw5xw.onion s t',
        'luggscoqbymhvnkp.onion t80',
        'ozahtqwp25chjdjd.onion s t',
        'node.arihanc.com s t',
        'arihancckjge66iv.onion s t',
    ]


class BitcoinGold(EquihashMixin, BitcoinMixin, Coin):
    CHUNK_SIZE = 252
    NAME = "BitcoinGold"
    SHORTNAME = "BTG"
    FORK_HEIGHT = 491407
    P2PKH_VERBYTE = bytes.fromhex("26")
    P2SH_VERBYTES = [bytes.fromhex("17")]
    DESERIALIZER = lib_tx.DeserializerEquihashSegWit
    TX_COUNT = 265026255
    TX_COUNT_HEIGHT = 499923
    TX_PER_BLOCK = 50
    REORG_LIMIT = 1000
    RPC_PORT = 8338

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        height, = struct.unpack('<I', header[68:72])

        if height >= cls.FORK_HEIGHT:
            return double_sha256(header)
        else:
            return double_sha256(header[:68] + header[100:112])

    @classmethod
    def electrum_header(cls, header, height):
        h = dict(
            block_height=height,
            version=struct.unpack('<I', header[:4])[0],
            prev_block_hash=hash_to_str(header[4:36]),
            merkle_root=hash_to_str(header[36:68]),
            timestamp=struct.unpack('<I', header[100:104])[0],
            reserved=hash_to_str(header[72:100]),
            bits=struct.unpack('<I', header[104:108])[0],
            nonce=hash_to_str(header[108:140]),
            solution=hash_to_str(header[140:])
        )

        return h


class BitcoinGoldTestnet(BitcoinGold):
    FORK_HEIGHT = 1
    SHORTNAME = "TBTG"
    XPUB_VERBYTES = bytes.fromhex("043587CF")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6F")
    P2SH_VERBYTES = [bytes.fromhex("C4")]
    WIF_BYTE = bytes.fromhex("EF")
    TX_COUNT = 0
    TX_COUNT_HEIGHT = 1
    NET = 'testnet'
    RPC_PORT = 18338
    GENESIS_HASH = ('00000000e0781ebe24b91eedc293adfe'
                    'a2f557b53ec379e78959de3853e6f9f6')


class BitcoinGoldRegtest(BitcoinGold):
    FORK_HEIGHT = 2000
    SHORTNAME = "TBTG"
    XPUB_VERBYTES = bytes.fromhex("043587CF")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6F")
    P2SH_VERBYTES = [bytes.fromhex("C4")]
    WIF_BYTE = bytes.fromhex("EF")
    TX_COUNT = 0
    TX_COUNT_HEIGHT = 1
    NET = 'regtest'
    RPC_PORT = 18444
    GENESIS_HASH = ('0f9188f13cb7b2c71f2a335e3a4fc328'
                    'bf5beb436012afca590b1a11466e2206')


class Emercoin(Coin):
    NAME = "Emercoin"
    SHORTNAME = "EMC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("21")
    P2SH_VERBYTES = [bytes.fromhex("5c")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('00000000bcccd459d036a588d1008fce'
                    '8da3754b205736f32ddfd35350e84c2d')
    TX_COUNT = 217380620
    TX_COUNT_HEIGHT = 464000
    TX_PER_BLOCK = 1700
    VALUE_PER_COIN = 1000000
    RPC_PORT = 6662

    DESERIALIZER = lib_tx.DeserializerTxTimeAuxPow

    PEERS = []

    @classmethod
    def block_header(cls, block, height):
        '''Returns the block header given a block and its height.'''
        deserializer = cls.DESERIALIZER(block)

        if deserializer.is_merged_block():
            return deserializer.read_header(height, cls.BASIC_HEADER_SIZE)
        return block[:cls.static_header_len(height)]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header[:cls.BASIC_HEADER_SIZE])


class BitcoinTestnetMixin(object):
    SHORTNAME = "XTN"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = [bytes.fromhex("c4")]
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('000000000933ea01ad0ee984209779ba'
                    'aec3ced90fa3f408719526f8d77f4943')
    REORG_LIMIT = 8000
    TX_COUNT = 12242438
    TX_COUNT_HEIGHT = 1035428
    TX_PER_BLOCK = 21
    RPC_PORT = 18332
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}


class BitcoinCashTestnet(BitcoinTestnetMixin, Coin):
    '''Bitcoin Testnet for Bitcoin Cash daemons.'''
    NAME = "BitcoinCash"
    PEERS = [
        'electrum-testnet-abc.criptolayer.net s50112',
        'bchtestnet.arihanc.com t53001 s53002',
        'ciiattqkgzebpp6jofjbrkhvhwmgnsfoayljdcrve2p3qmkbv3duaoyd.onion t53001 s53002',
    ]


class BitcoinSegwitTestnet(BitcoinTestnetMixin, Coin):
    '''Bitcoin Testnet for Core bitcoind >= 0.13.1.'''
    NAME = "BitcoinSegwit"
    DESERIALIZER = lib_tx.DeserializerSegWit
    PEERS = [
        'electrum.akinbo.org s t',
        'he36kyperp3kbuxu.onion s t',
        'testnet.hsmiths.com t53011 s53012',
        'hsmithsxurybd7uh.onion t53011 s53012',
        'testnetnode.arihanc.com s t',
        'w3e2orjpiiv2qwem3dw66d7c4krink4nhttngkylglpqe5r22n6n5wid.onion s t',
    ]


class BitcoinSegwitRegtest(BitcoinSegwitTestnet):
    NAME = "BitcoinSegwit"
    NET = "regtest"
    GENESIS_HASH = ('0f9188f13cb7b2c71f2a335e3a4fc328'
                    'bf5beb436012afca590b1a11466e2206')
    PEERS= []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1


class BitcoinNolnet(BitcoinCash):
    '''Bitcoin Unlimited nolimit testnet.'''
    NET = "nolnet"
    GENESIS_HASH = ('0000000057e31bd2066c939a63b7b862'
                    '3bd0f10d8c001304bdfc1a7902ae6d35')
    PEERS = []
    REORG_LIMIT = 8000
    TX_COUNT = 583589
    TX_COUNT_HEIGHT = 8617
    TX_PER_BLOCK = 50
    RPC_PORT = 28332
    PEER_DEFAULT_PORTS = {'t': '52001', 's': '52002'}


class Litecoin(Coin):
    NAME = "Litecoin"
    SHORTNAME = "LTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("30")
    P2SH_VERBYTES = [bytes.fromhex("32"), bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('12a765e31ffd4059bada1e25190f6e98'
                    'c99d9714d334efa41a195a7e7e04bfe2')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 8908766
    TX_COUNT_HEIGHT = 1105256
    TX_PER_BLOCK = 10
    RPC_PORT = 9332
    REORG_LIMIT = 800
    PEERS = [
        'elec.luggs.co s444',
        'electrum-ltc.bysh.me s t',
        'electrum-ltc.ddns.net s t',
        'electrum-ltc.wilv.in s t',
        'electrum.cryptomachine.com p1000 s t',
        'electrum.ltc.xurious.com s t',
        'eywr5eubdbbe2laq.onion s50008 t50007',
    ]


class LitecoinTestnet(Litecoin):
    SHORTNAME = "XLT"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = [bytes.fromhex("3a"), bytes.fromhex("c4")]
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('4966625a4b2851d9fdee139e56211a0d'
                    '88575f59ed816ff5e6a63deb4e3e29a0')
    TX_COUNT = 21772
    TX_COUNT_HEIGHT = 20800
    TX_PER_BLOCK = 2
    RPC_PORT = 19332
    REORG_LIMIT = 4000
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    PEERS = [
        'electrum-ltc.bysh.me s t',
        'electrum.ltc.xurious.com s t',
    ]


class Viacoin(AuxPowMixin, Coin):
    NAME="Viacoin"
    SHORTNAME = "VIA"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("47")
    P2SH_VERBYTES = [bytes.fromhex("21")]
    WIF_BYTE = bytes.fromhex("c7")
    GENESIS_HASH = ('4e9b54001f9976049830128ec0331515'
                    'eaabe35a70970d79971da1539a400ba1')
    TX_COUNT = 113638
    TX_COUNT_HEIGHT = 3473674
    TX_PER_BLOCK = 30
    RPC_PORT = 5222
    REORG_LIMIT = 5000
    DESERIALIZER = lib_tx.DeserializerAuxPowSegWit
    PEERS = [
        'vialectrum.bitops.me s t',
        'server.vialectrum.org s t',
        'vialectrum.viacoin.net s t',
        'viax1.bitops.me s t',
    ]


class ViacoinTestnet(Viacoin):
    SHORTNAME = "TVI"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("7f")
    P2SH_VERBYTES = [bytes.fromhex("c4")]
    WIF_BYTE = bytes.fromhex("ff")
    GENESIS_HASH = ('00000007199508e34a9ff81e6ec0c477'
                    'a4cccff2a4767a8eee39c11db367b008')
    RPC_PORT = 25222
    REORG_LIMIT = 2500
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    PEERS = [
        'vialectrum.bysh.me s t',
    ]


class ViacoinTestnetSegWit(ViacoinTestnet):
    NET = "testnet-segwit"
    DESERIALIZER = lib_tx.DeserializerSegWit


# Source: namecoin.org
class Namecoin(AuxPowMixin, Coin):
    NAME = "Namecoin"
    SHORTNAME = "NMC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("d7dd6370")
    XPRV_VERBYTES = bytes.fromhex("d7dc6e31")
    P2PKH_VERBYTE = bytes.fromhex("34")
    P2SH_VERBYTES = [bytes.fromhex("0d")]
    WIF_BYTE = bytes.fromhex("e4")
    GENESIS_HASH = ('000000000062b72c5e2ceb45fbc8587e'
                    '807c155b0da735e6483dfba2f0a9c770')
    TX_COUNT = 4415768
    TX_COUNT_HEIGHT = 329065
    TX_PER_BLOCK = 10
    PEERS = [
        'elec.luggs.co s446',
    ]


class NamecoinTestnet(Namecoin):
    NAME = "Namecoin"
    SHORTNAME = "XNM"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = [bytes.fromhex("c4")]
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('00000007199508e34a9ff81e6ec0c477'
                    'a4cccff2a4767a8eee39c11db367b008')


class Dogecoin(AuxPowMixin, Coin):
    NAME = "Dogecoin"
    SHORTNAME = "DOGE"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("02facafd")
    XPRV_VERBYTES = bytes.fromhex("02fac398")
    P2PKH_VERBYTE = bytes.fromhex("1e")
    P2SH_VERBYTES = [bytes.fromhex("16")]
    WIF_BYTE = bytes.fromhex("9e")
    GENESIS_HASH = ('1a91e3dace36e2be3bf030a65679fe82'
                    '1aa1d6ef92e7c9902eb318182c355691')
    TX_COUNT = 27583427
    TX_COUNT_HEIGHT = 1604979
    TX_PER_BLOCK = 20
    REORG_LIMIT = 2000


class DogecoinTestnet(Dogecoin):
    NAME = "Dogecoin"
    SHORTNAME = "XDT"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("71")
    P2SH_VERBYTES = [bytes.fromhex("c4")]
    WIF_BYTE = bytes.fromhex("f1")
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
    P2PKH_VERBYTE = bytes.fromhex("4c")
    P2SH_VERBYTES = [bytes.fromhex("10")]
    WIF_BYTE = bytes.fromhex("cc")
    TX_COUNT_HEIGHT = 569399
    TX_COUNT = 2157510
    TX_PER_BLOCK = 4
    RPC_PORT = 9998
    PEERS = [
        'electrum.dash.org s t',
        'electrum.masternode.io s t',
        'electrum-drk.club s t',
        'dashcrypto.space s t',
        'electrum.dash.siampm.com s t',
        'wl4sfwq2hwxnodof.onion s t',
    ]
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

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
    P2PKH_VERBYTE = bytes.fromhex("8c")
    P2SH_VERBYTES = [bytes.fromhex("13")]
    WIF_BYTE = bytes.fromhex("ef")
    TX_COUNT_HEIGHT = 101619
    TX_COUNT = 132681
    TX_PER_BLOCK = 1
    RPC_PORT = 19998
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    PEERS = [
        'electrum.dash.siampm.com s t',
    ]


class Argentum(AuxPowMixin, Coin):
    NAME = "Argentum"
    SHORTNAME = "ARG"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("17")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("97")
    GENESIS_HASH = ('88c667bc63167685e4e4da058fffdfe8'
                    'e007e5abffd6855de52ad59df7bb0bb2')
    TX_COUNT = 2263089
    TX_COUNT_HEIGHT = 2050260
    TX_PER_BLOCK = 2000
    RPC_PORT = 13581


class ArgentumTestnet(Argentum):
    SHORTNAME = "XRG"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = [bytes.fromhex("c4")]
    WIF_BYTE = bytes.fromhex("ef")
    REORG_LIMIT = 2000


class DigiByte(Coin):
    NAME = "DigiByte"
    SHORTNAME = "DGB"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1E")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('7497ea1b465eb39f1c8f507bc877078f'
                    'e016d6fcb6dfad3a64c98dcc6e1e8496')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1046018
    TX_COUNT_HEIGHT = 1435000
    TX_PER_BLOCK = 1000
    RPC_PORT = 12022


class DigiByteTestnet(DigiByte):
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = [bytes.fromhex("c4")]
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('b5dca8039e300198e5fe7cd23bdd1728'
                    'e2a444af34c447dbd0916fa3430a68c2')
    RPC_PORT = 15022
    REORG_LIMIT = 2000


class FairCoin(Coin):
    NAME = "FairCoin"
    SHORTNAME = "FAIR"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("5f")
    P2SH_VERBYTES = [bytes.fromhex("24")]
    WIF_BYTE = bytes.fromhex("df")
    GENESIS_HASH = ('beed44fa5e96150d95d56ebd5d262578'
                    '1825a9407a5215dd7eda723373a0a1d7')
    BASIC_HEADER_SIZE = 108
    TX_COUNT = 505
    TX_COUNT_HEIGHT = 470
    TX_PER_BLOCK = 1
    RPC_PORT = 40405
    PEER_DEFAULT_PORTS = {'t': '51811', 's': '51812'}
    PEERS = [
        'electrum.faircoin.world s',
        'electrumfair.punto0.org s',
    ]

    @classmethod
    def block(cls, raw_block, height):
        '''Return a Block namedtuple given a raw block and its height.'''
        if height > 0:
            return super().block(raw_block, height)
        else:
            return Block(raw_block, cls.block_header(raw_block, height), [])

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


class Zcash(EquihashMixin, Coin):
    NAME = "Zcash"
    SHORTNAME = "ZEC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1CB8")
    P2SH_VERBYTES = [bytes.fromhex("1CBD")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('00040fe8ec8471911baa1db1266ea15d'
                    'd06b4a8a5c453883c000b031973dce08')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 329196
    TX_COUNT_HEIGHT = 68379
    TX_PER_BLOCK = 5
    RPC_PORT = 8232
    REORG_LIMIT = 800

class SnowGem(EquihashMixin, Coin):
    NAME = "SnowGem"
    SHORTNAME = "SNG"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1C28")
    P2SH_VERBYTES = [bytes.fromhex("1C2D")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('00068b35729d9d2b0c294ff1fe9af009'
                    '4740524311a131de40e7f705e4c29a5b')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 140698
    TX_COUNT_HEIGHT = 102802
    TX_PER_BLOCK = 2
    RPC_PORT = 16112
    REORG_LIMIT = 800
    CHUNK_SIZE = 200

    @classmethod
    def electrum_header(cls, header, height):
        version, = struct.unpack('<I', header[:4])
        timestamp, bits = struct.unpack('<II', header[100:108])

        return {
            'block_height': height,
            'version': version,
            'prev_block_hash': hash_to_str(header[4:36]),
            'merkle_root': hash_to_str(header[36:68]),
            'hash_reserved': hash_to_str(header[68:100]),
            'timestamp': timestamp,
            'bits': bits,
            'nonce': hash_to_str(header[108:140]),
            'n_solution': base64.b64encode(lib_tx.Deserializer(header, start=140)._read_varbytes()).decode('utf8')
        }

class BitcoinZ(EquihashMixin, Coin):
    NAME = "BitcoinZ"
    SHORTNAME = "BTCZ"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1CB8")
    P2SH_VERBYTES = [bytes.fromhex("1CBD")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('f499ee3d498b4298ac6a64205b8addb7'
                    'c43197e2a660229be65db8a4534d75c1')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 171976
    TX_COUNT_HEIGHT = 81323
    TX_PER_BLOCK = 3
    RPC_PORT = 1979
    REORG_LIMIT = 800

class Hush(EquihashMixin, Coin):
    NAME = "Hush"
    SHORTNAME = "HUSH"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1CB8")
    P2SH_VERBYTES = [bytes.fromhex("1CBD")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH         = ( '0003a67bc26fe564b75daf11186d3606'
                          '52eb435a35ba3d9d3e7e5d5f8e62dc17')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 329196
    TX_COUNT_HEIGHT = 68379
    TX_PER_BLOCK = 5
    RPC_PORT = 8822
    REORG_LIMIT = 800

class Zclassic(EquihashMixin, Coin):
    NAME = "Zclassic"
    SHORTNAME = "ZCL"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1CB8")
    P2SH_VERBYTES = [bytes.fromhex("1CBD")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH         = ( '0007104ccda289427919efc39dc9e4d4'
                             '99804b7bebc22df55f8b834301260602')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 329196
    TX_COUNT_HEIGHT = 68379
    TX_PER_BLOCK = 5
    RPC_PORT = 8023
    REORG_LIMIT = 800

class Koto(Coin):
    NAME = "Koto"
    SHORTNAME = "KOTO"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1836")
    P2SH_VERBYTES = [bytes.fromhex("183B")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('6d424c350729ae633275d51dc3496e16'
                    'cd1b1d195c164da00f39c499a2e9959e')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 158914
    TX_COUNT_HEIGHT = 67574
    TX_PER_BLOCK = 3
    RPC_PORT = 8432
    REORG_LIMIT = 800
    PEERS = [
        'fr.kotocoin.info s t',
        'electrum.kotocoin.info s t',
    ]

class Komodo(KomodoMixin, EquihashMixin, Coin):
    NAME = "Komodo"
    SHORTNAME = "KMD"
    NET = "mainnet"
    TX_COUNT = 693629
    TX_COUNT_HEIGHT = 491777
    TX_PER_BLOCK = 2
    RPC_PORT = 7771
    REORG_LIMIT = 800
    PEERS = []

class Monaize(KomodoMixin, EquihashMixin, Coin):
    NAME = "Monaize"
    SHORTNAME = "MNZ"
    NET = "mainnet"
    TX_COUNT = 256
    TX_COUNT_HEIGHT = 128
    TX_PER_BLOCK = 2
    RPC_PORT = 14337
    REORG_LIMIT = 800
    PEERS = []


class Einsteinium(Coin):
    NAME = "Einsteinium"
    SHORTNAME = "EMC2"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("21")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('4e56204bb7b8ac06f860ff1c845f03f9'
                    '84303b5b97eb7b42868f714611aed94b')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 2087559
    TX_COUNT_HEIGHT = 1358517
    TX_PER_BLOCK = 2
    RPC_PORT = 41879
    REORG_LIMIT = 2000


class Blackcoin(ScryptMixin, Coin):
    NAME = "Blackcoin"
    SHORTNAME = "BLK"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = [bytes.fromhex("55")]
    WIF_BYTE = bytes.fromhex("99")
    GENESIS_HASH = ('000001faef25dec4fbcf906e6242621d'
                    'f2c183bf232f263d0ba5b101911e4563')
    DAEMON = daemon.LegacyRPCDaemon
    TX_COUNT = 4594999
    TX_COUNT_HEIGHT = 1667070
    TX_PER_BLOCK = 3
    RPC_PORT = 15715
    REORG_LIMIT = 5000


class Bitbay(ScryptMixin, Coin):
    NAME = "Bitbay"
    SHORTNAME = "BAY"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = [bytes.fromhex("55")]
    WIF_BYTE = bytes.fromhex("99")
    GENESIS_HASH = ('0000075685d3be1f253ce777174b1594'
                    '354e79954d2a32a6f77fe9cba00e6467')
    TX_COUNT = 4594999
    TX_COUNT_HEIGHT = 1667070
    TX_PER_BLOCK = 3
    RPC_PORT = 19914
    REORG_LIMIT = 5000


class Peercoin(Coin):
    NAME = "Peercoin"
    SHORTNAME = "PPC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("37")
    P2SH_VERBYTES = [bytes.fromhex("75")]
    WIF_BYTE = bytes.fromhex("b7")
    GENESIS_HASH = ('0000000032fe677166d54963b62a4677'
                    'd8957e87c508eaa4fd7eb1c880cd27e3')
    DESERIALIZER = lib_tx.DeserializerTxTime
    DAEMON = daemon.LegacyRPCDaemon
    TX_COUNT = 1207356
    TX_COUNT_HEIGHT = 306425
    TX_PER_BLOCK = 4
    RPC_PORT = 9902
    REORG_LIMIT = 5000


class Reddcoin(Coin):
    NAME = "Reddcoin"
    SHORTNAME = "RDD"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("3d")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("bd")
    GENESIS_HASH = ('b868e0d95a3c3c0e0dadc67ee587aaf9'
                    'dc8acbf99e3b4b3110fad4eb74c1decc')
    DESERIALIZER = lib_tx.DeserializerReddcoin
    TX_COUNT = 5413508
    TX_COUNT_HEIGHT = 1717382
    TX_PER_BLOCK = 3
    RPC_PORT = 45443


class Vertcoin(Coin):
    NAME = "Vertcoin"
    SHORTNAME = "VTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("47")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('4d96a915f49d40b1e5c2844d1ee2dccb'
                    '90013a990ccea12c492d22110489f0c4')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 2383423
    TX_COUNT_HEIGHT = 759076
    TX_PER_BLOCK = 3
    RPC_PORT = 5888
    REORG_LIMIT = 1000


class Monacoin(Coin):
    NAME = "Monacoin"
    SHORTNAME = "MONA"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("32")
    P2SH_VERBYTES = [bytes.fromhex("37"), bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("B0")
    GENESIS_HASH = ('ff9f1c0116d19de7c9963845e129f9ed'
                    '1bfc0b376eb54fd7afa42e0d418c8bb6')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 2568580
    TX_COUNT_HEIGHT = 1029766
    TX_PER_BLOCK = 2
    RPC_PORT = 9402
    REORG_LIMIT = 1000
    PEERS = [
        'electrumx.tamami-foundation.org s t',
        'electrumx2.tamami-foundation.org s t',
        'electrumx3.tamami-foundation.org s t',
        'electrumx1.monacoin.nl s t',
        'electrumx2.monacoin.nl s t',
        'electrumx1.monacoin.ninja s t',
        'electrumx2.monacoin.ninja s t',
        'electrumx1.movsign.info t',
        'electrumx2.movsign.info s t',
        'electrum-mona.bitbank.cc s t',
    ]

class MonacoinTestnet(Monacoin):
    SHORTNAME = "XMN"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587CF")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6F")
    P2SH_VERBYTES = [bytes.fromhex("75"), bytes.fromhex("C4")]
    WIF_BYTE = bytes.fromhex("EF")
    GENESIS_HASH = ('a2b106ceba3be0c6d097b2a6a6aacf9d'
                    '638ba8258ae478158f449c321061e0b2')
    TX_COUNT = 83602
    TX_COUNT_HEIGHT = 83252
    TX_PER_BLOCK = 1
    RPC_PORT = 19402
    REORG_LIMIT = 1000
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    PEERS = [
        'electrumx1.testnet.monacoin.ninja s t',
        'electrumx1.testnet.monacoin.nl s t',
    ]


class Crown(AuxPowMixin, Coin):
    NAME = "Crown"
    SHORTNAME = "CRW"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("00")
    P2SH_VERBYTES = [bytes.fromhex("1c")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('0000000085370d5e122f64f4ab19c686'
                    '14ff3df78c8d13cb814fd7e69a1dc6da')
    TX_COUNT = 13336629
    TX_COUNT_HEIGHT = 1268206
    TX_PER_BLOCK = 10
    RPC_PORT = 9341
    REORG_LIMIT = 1000
    PEERS = [
        'sgp-crwseed.crowndns.info s t',
        'blr-crwseed.crowndns.info s t',
        'sfo-crwseed.crowndns.info s t',
        'nyc-crwseed.crowndns.info s t',
        'ams-crwseed.crowndns.info s t',
        'tor-crwseed.crowndns.info s t',
        'lon-crwseed.crowndns.info s t',
        'fra-crwseed.crowndns.info s t',
    ]


class Fujicoin(Coin):
    NAME = "Fujicoin"
    SHORTNAME = "FJC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("24")
    P2SH_VERBYTES = [bytes.fromhex("10")]
    WIF_BYTE = bytes.fromhex("a4")
    GENESIS_HASH = ('adb6d9cfd74075e7f91608add4bd2a2e'
                    'a636f70856183086842667a1597714a0')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 170478
    TX_COUNT_HEIGHT = 1521676
    TX_PER_BLOCK = 1
    RPC_PORT = 3776
    REORG_LIMIT = 1000


class Neblio(ScryptMixin, Coin):
    NAME = "Neblio"
    SHORTNAME = "NEBL"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("35")
    P2SH_VERBYTES = [bytes.fromhex("70")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('7286972be4dbc1463d256049b7471c25'
                    '2e6557e222cab9be73181d359cd28bcc')
    TX_COUNT = 23675
    TX_COUNT_HEIGHT = 22785
    TX_PER_BLOCK = 1
    RPC_PORT = 6326
    REORG_LIMIT = 1000


class Bitzeny(Coin):
    NAME = "Bitzeny"
    SHORTNAME = "ZNY"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("51")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('000009f7e55e9e3b4781e22bd87a7cfa'
                    '4acada9e4340d43ca738bf4e9fb8f5ce')
    ESTIMATE_FEE = 0.001
    RELAY_FEE = 0.001
    DAEMON = daemon.FakeEstimateFeeDaemon
    TX_COUNT = 1408733
    TX_COUNT_HEIGHT = 1015115
    TX_PER_BLOCK = 1
    RPC_PORT = 9252
    REORG_LIMIT = 1000

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import zny_yescrypt
        return zny_yescrypt.getPoWHash(header)


class CanadaeCoin(AuxPowMixin, Coin):
    NAME = "CanadaeCoin"
    SHORTNAME = "CDN"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("1C")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("9c")
    GENESIS_HASH = ('863626dadaef221e2e2f30ff3dacae44'
                    'cabdae9e0028058072181b3fb675d94a')
    ESTIMATE_FEE = 0.0001
    RELAY_FEE = 0.0001
    DAEMON = daemon.FakeEstimateFeeDaemon
    TX_COUNT = 3455905
    TX_COUNT_HEIGHT = 3645419
    TX_PER_BLOCK = 1
    RPC_PORT = 34330
    REORG_LIMIT = 1000

class Denarius(Coin):
    NAME = "Denarius"
    SHORTNAME = "DNR"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("1E") #Address starts with a D
    P2SH_VERBYTES = [bytes.fromhex("5A")]
    WIF_BYTE = bytes.fromhex("9E") #WIF starts with a 6
    GENESIS_HASH = ('00000d5dbbda01621cfc16bbc1f9bf32'
                    '64d641a5dbf0de89fd0182c2c4828fcd')
    DESERIALIZER = lib_tx.DeserializerTxTime
    TX_COUNT = 4230
    RPC_PORT = 32339
    ESTIMATE_FEE = 0.00001
    RELAY_FEE = 0.00001
    DAEMON = daemon.FakeEstimateFeeDaemon
    TX_COUNT_HEIGHT = 306187
    TX_PER_BLOCK = 4000

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import tribus_hash
        return tribus_hash.getPoWHash(header)


class DenariusTestnet(Denarius):
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("12")
    P2SH_VERBYTES = [bytes.fromhex("74")]
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('000086bfe8264d241f7f8e5393f74778'
                    '4b8ca2aa98bdd066278d590462a4fdb4')
    RPC_PORT = 32338
    REORG_LIMIT = 2000


class Sibcoin(Dash):
    NAME = "Sibcoin"
    SHORTNAME = "SIB"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("3F")
    P2SH_VERBYTES = [bytes.fromhex("28")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('00000c492bf73490420868bc577680bf'
                    'c4c60116e7e85343bc624787c21efa4c')
    DAEMON = daemon.DashDaemon
    TX_COUNT = 1000
    TX_COUNT_HEIGHT = 10000
    TX_PER_BLOCK = 1
    RPC_PORT = 1944
    REORG_LIMIT = 1000
    PEERS = []

    @classmethod
    def header_hash(cls, header):
        '''
        Given a header return the hash for sibcoin.
        Need to download `x11_gost_hash` module
        Source code: https://github.com/ivansib/x11_gost_hash
        '''
        import x11_gost_hash
        return x11_gost_hash.getPoWHash(header)


class Chips(Coin):
    NAME = "Chips"
    SHORTNAME = "CHIPS"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("3c")
    P2SH_VERBYTES = [bytes.fromhex("55")]
    WIF_BYTE = bytes.fromhex("bc")
    GENESIS_HASH = ('0000006e75f6aa0efdbf7db03132aa4e'
                    '4d0c84951537a6f5a7c39a0a9d30e1e7')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 145290
    TX_COUNT_HEIGHT = 318637
    TX_PER_BLOCK = 2
    RPC_PORT = 57776
    REORG_LIMIT = 800


class Feathercoin(Coin):
    NAME = "Feathercoin"
    SHORTNAME = "FTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488BC26")
    XPRV_VERBYTES = bytes.fromhex("0488DAEE")
    P2PKH_VERBYTE = bytes.fromhex("0E")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("8E")
    GENESIS_HASH = ('12a765e31ffd4059bada1e25190f6e98'
                    'c99d9714d334efa41a195a7e7e04bfe2')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 3170843
    TX_COUNT_HEIGHT = 1981777
    TX_PER_BLOCK = 2
    RPC_PORT = 9337
    REORG_LIMIT = 2000
    PEERS = [
        'electrumx-ch-1.feathercoin.ch s t',
    ]

class UFO(Coin):
    NAME = "UniformFiscalObject"
    SHORTNAME = "UFO"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("1B")
    P2SH_VERBYTES = [bytes.fromhex("44")]
    WIF_BYTE = bytes.fromhex("9B")
    GENESIS_HASH = ('ba1d39b4928ab03d813d952daf65fb77'
                    '97fcf538a9c1b8274f4edc8557722d13')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1608926
    TX_COUNT_HEIGHT = 1300154
    TX_PER_BLOCK = 2
    RPC_PORT = 9888
    REORG_LIMIT = 2000
    PEERS = [
        'electrumx1.ufobject.com s t',
    ]

class Newyorkcoin(AuxPowMixin, Coin):
    NAME = "Newyorkcoin"
    SHORTNAME = "NYC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("3c")
    P2SH_VERBYTES = [bytes.fromhex("16")]
    WIF_BYTE = bytes.fromhex("bc")
    GENESIS_HASH = ('5597f25c062a3038c7fd815fe46c67de'
                    'dfcb3c839fbc8e01ed4044540d08fe48')
    DAEMON = daemon.LegacyRPCDaemon
    TX_COUNT = 5161944
    TX_COUNT_HEIGHT = 3948743
    TX_PER_BLOCK = 2
    REORG_LIMIT = 2000

class NewyorkcoinTestnet(Newyorkcoin):
    SHORTNAME = "tNYC"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("71")
    P2SH_VERBYTES = [bytes.fromhex("c4")]
    WIF_BYTE = bytes.fromhex("f1")
    GENESIS_HASH = ('24463e4d3c625b0a9059f309044c2cf0'
                    'd7e196cf2a6ecce901f24f681be33c8f')
    DAEMON = daemon.LegacyRPCDaemon
    TX_COUNT = 5161944
    TX_COUNT_HEIGHT = 3948743
    TX_PER_BLOCK = 2
    REORG_LIMIT = 2000

class Bitcore(BitcoinMixin, Coin):
    NAME = "Bitcore"
    SHORTNAME = "BTX"
    DESERIALIZER = lib_tx.DeserializerSegWit
    GENESIS_HASH = ('604148281e5c4b7f2487e5d03cd60d8e'
                    '6f69411d613f6448034508cea52e9574')
    TX_COUNT = 126979
    TX_COUNT_HEIGHT = 126946
    TX_PER_BLOCK = 2
    RPC_PORT = 8556


class GameCredits(Coin):
    NAME = "GameCredits"
    SHORTNAME = "GAME"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("26")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("a6")
    GENESIS_HASH = ('91ec5f25ee9a0ffa1af7d4da4db9a552'
                    '228dd2dc77cdb15b738be4e1f55f30ee')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 316796
    TX_COUNT_HEIGHT = 2040250
    TX_PER_BLOCK = 2
    RPC_PORT = 40001
    REORG_LIMIT = 1000


class BitcoinAtom(Coin):
    NAME = "BitcoinAtom"
    SHORTNAME = "BCA"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("17")
    P2SH_VERBYTES = [bytes.fromhex("0a")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('000000000019d6689c085ae165831e93'
                    '4ff763ae46a2a6c172b3f1b60a8ce26f')
    STATIC_BLOCK_HEADERS = False
    DESERIALIZER = lib_tx.DeserializerBitcoinAtom
    HEADER_SIZE_POST_FORK = 84
    BLOCK_PROOF_OF_STAKE = 0x01
    BLOCK_PROOF_OF_STAKE_FLAGS = b'\x01\x00\x00\x00'
    TX_COUNT = 295158744
    TX_COUNT_HEIGHT = 589197
    TX_PER_BLOCK = 10
    RPC_PORT = 9136
    REORG_LIMIT = 5000

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        header_to_be_hashed = header[:cls.BASIC_HEADER_SIZE]
        # New block header format has some extra flags in the end
        if len(header) == cls.HEADER_SIZE_POST_FORK:
            flags, = struct.unpack('<I', header[-4:])
            # Proof of work blocks have special serialization
            if flags & cls.BLOCK_PROOF_OF_STAKE != 0:
                header_to_be_hashed += cls.BLOCK_PROOF_OF_STAKE_FLAGS

        return double_sha256(header_to_be_hashed)

    @classmethod
    def block_header(cls, block, height):
        '''Return the block header bytes'''
        deserializer = cls.DESERIALIZER(block)
        return deserializer.read_header(height, cls.BASIC_HEADER_SIZE)


class Decred(Coin):
    NAME = "Decred"
    SHORTNAME = "DCR"
    NET = "mainnet"
    XPUB_VERBYTES = bytes('dpub', 'utf-8')
    XPRV_VERBYTES = bytes('dprv', 'utf-8')
    P2PKH_VERBYTE = bytes('Ds', 'utf-8')
    P2SH_VERBYTES = [bytes('Dc', 'utf-8')]
    WIF_BYTE = bytes('Pm', 'utf-8')
    GENESIS_HASH = ('298e5cc3d985bfe7f81dc135f360abe089edd4396b86d2de66b0cef42b21d980')
    DESERIALIZER = lib_tx.DeserializerDecred
    ENCODE_CHECK = partial(Base58.encode_check, hash_fn=lib_tx.DeserializerDecred.blake256)
    DECODE_CHECK = partial(Base58.decode_check, hash_fn=lib_tx.DeserializerDecred.blake256)
    HEADER_HASH = lib_tx.DeserializerDecred.blake256
    BASIC_HEADER_SIZE = 180
    ALLOW_ADVANCING_ERRORS = True
    TX_COUNT = 217380620
    TX_COUNT_HEIGHT = 218875
    TX_PER_BLOCK = 1000
    RPC_PORT = 9109

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        return cls.HEADER_HASH(header)

    @classmethod
    def block(cls, raw_block, height):
        '''Return a Block namedtuple given a raw block and its height.'''
        if height > 0:
            return super().block(raw_block, height)
        else:
            return Block(raw_block, cls.block_header(raw_block, height), [])


class DecredTestnet(Decred):
    NAME = "Decred"
    NET = "testnet"
    XPUB_VERBYTES = bytes('tpub', 'utf-8')
    XPRV_VERBYTES = bytes('tprv', 'utf-8')
    P2PKH_VERBYTE = bytes('Ts', 'utf-8')
    P2SH_VERBYTES = [bytes('Tc', 'utf-8')]
    WIF_BYTE = bytes('Pt', 'utf-8')
    GENESIS_HASH = ('4261602a9d07d80ad47621a64ba6a07754902e496777edc4ff581946bd7bc29c')
    TX_COUNT = 3176305
    TX_COUNT_HEIGHT = 254198
    TX_PER_BLOCK = 1000
    RPC_PORT = 19109


class Axe(Dash):
    NAME = "Axe"
    SHORTNAME = "AXE"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("02fe52cc")
    XPRV_VERBYTES = bytes.fromhex("02fe52f8")
    P2PKH_VERBYTE = bytes.fromhex("37")
    P2SH_VERBYTES = [bytes.fromhex("10")]
    WIF_BYTE = bytes.fromhex("cc")
    GENESIS_HASH = ('00000c33631ca6f2f61368991ce2dc03'
                    '306b5bb50bf7cede5cfbba6db38e52e6')
    DAEMON = daemon.DashDaemon
    TX_COUNT = 18405
    TX_COUNT_HEIGHT = 30237
    TX_PER_BLOCK = 1
    RPC_PORT = 9337
    REORG_LIMIT = 1000
    PEERS = []

    @classmethod
    def header_hash(cls, header):
        '''
        Given a header return the hash for AXE.
        Need to download `axe_hash` module
        Source code: https://github.com/AXErunners/axe_hash
        '''
        import x11_hash
        return x11_hash.getPoWHash(header)
