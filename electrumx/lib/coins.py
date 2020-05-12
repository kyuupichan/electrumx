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

import electrumx.lib.util as util
from electrumx.lib.hash import Base58, hash160, double_sha256, hash_to_hex_str
from electrumx.lib.hash import HASHX_LEN, hex_str_to_hash
from electrumx.lib.script import (_match_ops, Script, ScriptError,
                                  ScriptPubKey, OpCodes)
import electrumx.lib.tx as lib_tx
import electrumx.lib.tx_dash as lib_tx_dash
import electrumx.lib.tx_axe as lib_tx_axe
import electrumx.server.block_processor as block_proc
import electrumx.server.daemon as daemon
from electrumx.server.session import (ElectrumX, DashElectrumX,
                                      SmartCashElectrumX, AuxPoWElectrumX)


Block = namedtuple("Block", "raw header transactions")


class CoinError(Exception):
    '''Exception raised for coin-related errors.'''


class Coin(object):
    '''Base class of coin hierarchy.'''

    REORG_LIMIT = 200
    # Not sure if these are coin-specific
    RPC_URL_REGEX = re.compile('.+@(\\[[0-9a-fA-F:]+\\]|[^:]+)(:[0-9]+)?')
    VALUE_PER_COIN = 100000000
    CHUNK_SIZE = 2016
    BASIC_HEADER_SIZE = 80
    STATIC_BLOCK_HEADERS = True
    SESSIONCLS = ElectrumX
    DEFAULT_MAX_SEND = 1000000
    DESERIALIZER = lib_tx.Deserializer
    DAEMON = daemon.Daemon
    BLOCK_PROCESSOR = block_proc.BlockProcessor
    HEADER_VALUES = ('version', 'prev_block_hash', 'merkle_root', 'timestamp',
                     'bits', 'nonce')
    HEADER_UNPACK = struct.Struct('< I 32s 32s I I I').unpack_from
    MEMPOOL_HISTOGRAM_REFRESH_SECS = 500
    P2PKH_VERBYTE = bytes.fromhex("00")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    XPUB_VERBYTES = bytes('????', 'utf-8')
    XPRV_VERBYTES = bytes('????', 'utf-8')
    WIF_BYTE = bytes.fromhex("80")
    ENCODE_CHECK = Base58.encode_check
    DECODE_CHECK = Base58.decode_check
    GENESIS_HASH = ('000000000019d6689c085ae165831e93'
                    '4ff763ae46a2a6c172b3f1b60a8ce26f')
    GENESIS_ACTIVATION = 100_000_000
    # Peer discovery
    PEER_DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    PEERS = []
    CRASH_CLIENT_VER = None
    BLACKLIST_URL = None

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
    def max_fetch_blocks(cls, height):
        if height < 130000:
            return 1000
        return 100

    @classmethod
    def genesis_block(cls, block):
        '''Check the Genesis block is the right one for this coin.

        Return the block less its unspendable coinbase.
        '''
        header = cls.block_header(block, 0)
        header_hex_hash = hash_to_hex_str(cls.header_hash(header))
        if header_hex_hash != cls.GENESIS_HASH:
            raise CoinError('genesis block has hash {} expected {}'
                            .format(header_hex_hash, cls.GENESIS_HASH))

        return header + bytes(1)

    @classmethod
    def hashX_from_script(cls, script):
        '''Returns a hashX from a script.'''
        return sha256(script).digest()[:HASHX_LEN]

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
    def hash160_to_P2PKH_script(cls, hash160):
        return ScriptPubKey.P2PKH_script(hash160)

    @classmethod
    def hash160_to_P2PKH_hashX(cls, hash160):
        return cls.hashX_from_script(cls.hash160_to_P2PKH_script(hash160))

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
            verbyte, hash160 = raw[:verlen], raw[verlen:]

        if verbyte == cls.P2PKH_VERBYTE:
            return cls.hash160_to_P2PKH_script(hash160)
        if verbyte in cls.P2SH_VERBYTES:
            return ScriptPubKey.P2SH_script(hash160)

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
        return (cls.static_header_offset(height + 1)
                - cls.static_header_offset(height))

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
    def warn_old_client_on_tx_broadcast(cls, _client_ver):
        return False


class AuxPowMixin(object):
    STATIC_BLOCK_HEADERS = False
    DESERIALIZER = lib_tx.DeserializerAuxPow
    SESSIONCLS = AuxPoWElectrumX
    TRUNCATED_HEADER_SIZE = 80
    # AuxPoW headers are significantly larger, so the DEFAULT_MAX_SEND from
    # Bitcoin is insufficient.  In Namecoin mainnet, 5 MB wasn't enough to
    # sync, while 10 MB worked fine.
    DEFAULT_MAX_SEND = 10000000

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header[:cls.BASIC_HEADER_SIZE])

    @classmethod
    def block_header(cls, block, height):
        '''Return the AuxPow block header bytes'''
        deserializer = cls.DESERIALIZER(block)
        return deserializer.read_header(cls.BASIC_HEADER_SIZE)


class EquihashMixin(object):
    STATIC_BLOCK_HEADERS = False
    BASIC_HEADER_SIZE = 140  # Excluding Equihash solution
    DESERIALIZER = lib_tx.DeserializerEquihash
    HEADER_VALUES = ('version', 'prev_block_hash', 'merkle_root', 'reserved',
                     'timestamp', 'bits', 'nonce')
    HEADER_UNPACK = struct.Struct('< I 32s 32s 32s I I 32s').unpack_from

    @classmethod
    def block_header(cls, block, height):
        '''Return the block header bytes'''
        deserializer = cls.DESERIALIZER(block)
        return deserializer.read_header(cls.BASIC_HEADER_SIZE)


class ScryptMixin(object):

    DESERIALIZER = lib_tx.DeserializerTxTime
    HEADER_HASH = None

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        if cls.HEADER_HASH is None:
            import scrypt
            cls.HEADER_HASH = lambda x: scrypt.hash(x, x, 1024, 1, 1, 32)

        version, = util.unpack_le_uint32_from(header)
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
    RPC_PORT = 8332


class NameMixin(object):
    DATA_PUSH_MULTIPLE = -2

    @classmethod
    def interpret_name_prefix(cls, script, possible_ops):
        """Interprets a potential name prefix

        Checks if the given script has a name prefix.  If it has, the
        name prefix is split off the actual address script, and its parsed
        fields (e.g. the name) returned.

        possible_ops must be an array of arrays, defining the structures
        of name prefixes to look out for.  Each array can consist of
        actual opcodes, -1 for ignored data placeholders, -2 for
        multiple ignored data placeholders and strings for named placeholders.
        Whenever a data push matches a named placeholder,
        the corresponding value is put into a dictionary the placeholder name
        as key, and the dictionary of matches is returned."""

        try:
            ops = Script.get_ops(script)
        except ScriptError:
            return None, script

        name_op_count = None
        for pops in possible_ops:
            # Start by translating named placeholders to -1 values, and
            # keeping track of which op they corresponded to.
            template = []
            named_index = {}

            n = len(pops)
            offset = 0
            for i, op in enumerate(pops):
                if op == cls.DATA_PUSH_MULTIPLE:
                    # Emercoin stores value in multiple placeholders
                    # Script structure: https://git.io/fjuRu
                    added, template = cls._add_data_placeholders_to_template(ops[i:], template)
                    offset += added - 1  # subtract the "DATA_PUSH_MULTIPLE" opcode
                elif type(op) == str:
                    template.append(-1)
                    named_index[op] = i + offset
                else:
                    template.append(op)
            n += offset

            if not _match_ops(ops[:n], template):
                continue

            name_op_count = n
            named_values = {key: ops[named_index[key]] for key in named_index}
            break

        if name_op_count is None:
            return None, script

        name_end_pos = cls.find_end_position_of_name(script, name_op_count)

        address_script = script[name_end_pos:]
        return named_values, address_script

    @classmethod
    def _add_data_placeholders_to_template(cls, opcodes, template):
        num_dp = cls._read_data_placeholders_count(opcodes)
        num_2drop = num_dp // 2
        num_drop = num_dp % 2

        two_drops = [OpCodes.OP_2DROP for _ in range(num_2drop)]
        one_drops = [OpCodes.OP_DROP for _ in range(num_drop)]

        elements_added = num_dp + num_2drop + num_drop
        placeholders = [-1 for _ in range(num_dp)]
        drops = two_drops + one_drops

        return elements_added, template + placeholders + drops

    @classmethod
    def _read_data_placeholders_count(cls, opcodes):
        data_placeholders = 0

        for opcode in opcodes:
            if type(opcode) == tuple:
                data_placeholders += 1
            else:
                break

        return data_placeholders

    @staticmethod
    def find_end_position_of_name(script, length):
        """Finds the end position of the name data

        Given the number of opcodes in the name prefix (length), returns the
        index into the byte array of where the name prefix ends."""
        n = 0
        for _i in range(length):
            # Content of this loop is copied from Script.get_ops's loop
            op = script[n]
            n += 1

            if op <= OpCodes.OP_PUSHDATA4:
                # Raw bytes follow
                if op < OpCodes.OP_PUSHDATA1:
                    dlen = op
                elif op == OpCodes.OP_PUSHDATA1:
                    dlen = script[n]
                    n += 1
                elif op == OpCodes.OP_PUSHDATA2:
                    dlen, = struct.unpack('<H', script[n: n + 2])
                    n += 2
                else:
                    dlen, = struct.unpack('<I', script[n: n + 4])
                    n += 4
                if n + dlen > len(script):
                    raise IndexError
                n += dlen

        return n


class NameIndexMixin(NameMixin):
    """Shared definitions for coins that have a name index

    This class defines common functions and logic for coins that have
    a name index in addition to the index by address / script."""

    BLOCK_PROCESSOR = block_proc.NameIndexBlockProcessor

    @classmethod
    def build_name_index_script(cls, name):
        """Returns the script by which names are indexed"""

        from electrumx.lib.script import Script

        res = bytearray()
        res.append(cls.OP_NAME_UPDATE)
        res.extend(Script.push_data(name))
        res.extend(Script.push_data(bytes([])))
        res.append(OpCodes.OP_2DROP)
        res.append(OpCodes.OP_DROP)
        res.append(OpCodes.OP_RETURN)

        return bytes(res)

    @classmethod
    def split_name_script(cls, script):
        named_values, address_script = cls.interpret_name_prefix(script, cls.NAME_OPERATIONS)
        if named_values is None or "name" not in named_values:
            return None, address_script

        name_index_script = cls.build_name_index_script(named_values["name"][1])
        return name_index_script, address_script

    @classmethod
    def hashX_from_script(cls, script):
        _, address_script = cls.split_name_script(script)
        return super().hashX_from_script(address_script)

    @classmethod
    def address_from_script(cls, script):
        _, address_script = cls.split_name_script(script)
        return super().address_from_script(address_script)

    @classmethod
    def name_hashX_from_script(cls, script):
        name_index_script, _ = cls.split_name_script(script)
        if name_index_script is None:
            return None

        return super().hashX_from_script(name_index_script)


class HOdlcoin(Coin):
    NAME = "HOdlcoin"
    SHORTNAME = "HODLC"
    NET = "mainnet"
    BASIC_HEADER_SIZE = 88
    P2PKH_VERBYTE = bytes.fromhex("28")
    WIF_BYTE = bytes.fromhex("a8")
    GENESIS_HASH = ('008872e5582924544e5c707ee4b839bb'
                    '82c28a9e94e917c94b40538d5658c04b')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 258858
    TX_COUNT_HEIGHT = 382138
    TX_PER_BLOCK = 5


class BitcoinSV(BitcoinMixin, Coin):
    NAME = "BitcoinSV"
    SHORTNAME = "BSV"
    TX_COUNT = 267318795
    TX_COUNT_HEIGHT = 557037
    TX_PER_BLOCK = 400
    PEERS = [
        'electrumx.bitcoinsv.io s',
        'satoshi.vision.cash s',
        'sv.usebsv.com s t',
        'sv.jochen-hoenicke.de s t',
        'sv.satoshi.io s t',
    ]
    GENESIS_ACTIVATION = 620_538


class BitcoinCash(BitcoinMixin, Coin):
    NAME = "BitcoinCashABC"   # Some releases later remove the ABC suffix
    SHORTNAME = "BCH"
    TX_COUNT = 265479628
    TX_COUNT_HEIGHT = 556592
    TX_PER_BLOCK = 400
    PEERS = [
        'bch.imaginary.cash s t',
        'electroncash.dk s t',
        'wallet.satoshiscoffeehouse.com s t',
    ]
    BLOCK_PROCESSOR = block_proc.LTORBlockProcessor

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, client_ver):
        if client_ver < (3, 3, 4):
            return ('<br/><br/>'
                    'Your transaction was successfully broadcast.<br/><br/>'
                    'However, you are using a VULNERABLE version of Electron Cash.<br/>'
                    'Download the latest version from this web site ONLY:<br/>'
                    'https://electroncash.org/'
                    '<br/><br/>')
        return False


class BitcoinSegwit(BitcoinMixin, Coin):
    NAME = "BitcoinSegwit"
    DESERIALIZER = lib_tx.DeserializerSegWit
    MEMPOOL_HISTOGRAM_REFRESH_SECS = 120
    TX_COUNT = 318337769
    TX_COUNT_HEIGHT = 524213
    TX_PER_BLOCK = 1400
    CRASH_CLIENT_VER = (3, 2, 3)
    BLACKLIST_URL = 'https://electrum.org/blacklist.json'
    PEERS = [
        'E-X.not.fyi s t',
        'electrum.vom-stausee.de s t',
        'electrum.hsmiths.com s t',
        'helicarrier.bauerj.eu s t',
        'hsmiths4fyqlw5xw.onion s t',
        'ozahtqwp25chjdjd.onion s t',
        'electrum.hodlister.co s',
        'electrum3.hodlister.co s',
        'btc.usebsv.com s50006',
        'fortress.qtornado.com s443 t',
        'ecdsa.net s110 t',
        'e2.keff.org s t',
        'currentlane.lovebitco.in s t',
        'electrum.jochen-hoenicke.de s50005 t50003',
        'vps5.hsmiths.com s',
    ]

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, client_ver):
        if client_ver < (3, 3, 3):
            return ('<br/><br/>'
                    'Your transaction was successfully broadcast.<br/><br/>'
                    'However, you are using a VULNERABLE version of Electrum.<br/>'
                    'Download the new version from the usual place:<br/>'
                    'https://electrum.org/'
                    '<br/><br/>')
        return False


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
    RPC_PORT = 8332
    PEERS = [
        'electrumx-eu.bitcoingold.org s50002 t50001',
        'electrumx-us.bitcoingold.org s50002 t50001'
    ]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        height, = util.unpack_le_uint32_from(header, 68)
        if height >= cls.FORK_HEIGHT:
            return double_sha256(header)
        else:
            return double_sha256(header[:68] + header[100:112])


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
    RPC_PORT = 18332
    GENESIS_HASH = ('00000000e0781ebe24b91eedc293adfe'
                    'a2f557b53ec379e78959de3853e6f9f6')
    PEERS = [
        'test-node1.bitcoingold.org s50002',
        'test-node2.bitcoingold.org s50002',
        'test-node3.bitcoingold.org s50002'
    ]


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
    PEERS = []


class BitcoinDiamond(BitcoinSegwit, Coin):
    NAME = "BitcoinDiamond"
    SHORTNAME = "BCD"
    TX_VERSION = 12
    TX_COUNT = 274277819
    TX_COUNT_HEIGHT = 498678
    TX_PER_BLOCK = 50
    REORG_LIMIT = 1000
    PEERS = []
    VALUE_PER_COIN = 10000000
    DESERIALIZER = lib_tx.DeserializerBitcoinDiamondSegWit


class Emercoin(NameMixin, Coin):
    NAME = "Emercoin"
    SHORTNAME = "EMC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("21")
    P2SH_VERBYTES = [bytes.fromhex("5c")]
    GENESIS_HASH = ('00000000bcccd459d036a588d1008fce'
                    '8da3754b205736f32ddfd35350e84c2d')
    TX_COUNT = 217380620
    TX_COUNT_HEIGHT = 464000
    TX_PER_BLOCK = 1700
    VALUE_PER_COIN = 1000000
    RPC_PORT = 6662

    DESERIALIZER = lib_tx.DeserializerEmercoin

    PEERS = []

    # Name opcodes
    OP_NAME_NEW = OpCodes.OP_1
    OP_NAME_UPDATE = OpCodes.OP_2
    OP_NAME_DELETE = OpCodes.OP_3

    # Valid name prefixes.
    NAME_NEW_OPS = [OP_NAME_NEW, OpCodes.OP_DROP, "name", "days",
                    OpCodes.OP_2DROP, NameMixin.DATA_PUSH_MULTIPLE]
    NAME_UPDATE_OPS = [OP_NAME_UPDATE, OpCodes.OP_DROP, "name", "days",
                       OpCodes.OP_2DROP, NameMixin.DATA_PUSH_MULTIPLE]
    NAME_DELETE_OPS = [OP_NAME_DELETE, OpCodes.OP_DROP, "name",
                       OpCodes.OP_DROP]
    NAME_OPERATIONS = [
        NAME_NEW_OPS,
        NAME_UPDATE_OPS,
        NAME_DELETE_OPS,
    ]

    @classmethod
    def block_header(cls, block, height):
        '''Returns the block header given a block and its height.'''
        deserializer = cls.DESERIALIZER(block)

        if deserializer.is_merged_block():
            return deserializer.read_header(cls.BASIC_HEADER_SIZE)
        return block[:cls.static_header_len(height)]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header[:cls.BASIC_HEADER_SIZE])

    @classmethod
    def hashX_from_script(cls, script):
        _, address_script = cls.interpret_name_prefix(script, cls.NAME_OPERATIONS)

        return super().hashX_from_script(address_script)


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


class BitcoinSVTestnet(BitcoinTestnetMixin, Coin):
    '''Bitcoin Testnet for Bitcoin SV daemons.'''
    NAME = "BitcoinSV"
    PEERS = [
        'electrontest.cascharia.com t51001 s51002',
    ]
    GENESIS_ACTIVATION = 1_344_302


class BitcoinSVScalingTestnet(BitcoinSVTestnet):
    NET = "scalingtest"
    PEERS = [
        'stn-server.electrumsv.io t51001 s51002',
    ]
    TX_COUNT = 2015
    TX_COUNT_HEIGHT = 5711
    TX_PER_BLOCK = 5000
    GENESIS_ACTIVATION = 14_896

    @classmethod
    def max_fetch_blocks(cls, height):
        if height <= 10:
            return 100
        return 3


class BitcoinCashTestnet(BitcoinTestnetMixin, Coin):
    '''Bitcoin Testnet for Bitcoin Cash daemons.'''
    NAME = "BitcoinCashABC"
    PEERS = [
        'bch0.kister.net t s',
        'testnet.imaginary.cash t50001 s50002',
        'blackie.c3-soft.com t60001 s60002',
    ]
    BLOCK_PROCESSOR = block_proc.LTORBlockProcessor

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, client_ver):
        if client_ver < (3, 3, 4):
            return ('<br/><br/>'
                    'Your transaction was successfully broadcast.<br/><br/>'
                    'However, you are using a VULNERABLE version of Electron Cash.<br/>'
                    'Download the latest version from this web site ONLY:<br/>'
                    'https://electroncash.org/'
                    '<br/><br/>')
        return False


class BitcoinSVRegtest(BitcoinSVTestnet):
    NET = "regtest"
    GENESIS_HASH = ('0f9188f13cb7b2c71f2a335e3a4fc328'
                    'bf5beb436012afca590b1a11466e2206')
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    GENESIS_ACTIVATION = 10_000


class BitcoinSegwitTestnet(BitcoinTestnetMixin, Coin):
    '''Bitcoin Testnet for Core bitcoind >= 0.13.1.'''
    NAME = "BitcoinSegwit"
    DESERIALIZER = lib_tx.DeserializerSegWit
    CRASH_CLIENT_VER = (3, 2, 3)
    PEERS = [
        'testnet.hsmiths.com t53011 s53012',
        'hsmithsxurybd7uh.onion t53011 s53012',
        'testnet.qtornado.com s t',
        'testnet1.bauerj.eu t50001 s50002',
        'tn.not.fyi t55001 s55002',
        'bitcoin.cluelessperson.com s t',
    ]

    @classmethod
    def warn_old_client_on_tx_broadcast(cls, client_ver):
        if client_ver < (3, 3, 3):
            return ('<br/><br/>'
                    'Your transaction was successfully broadcast.<br/><br/>'
                    'However, you are using a VULNERABLE version of Electrum.<br/>'
                    'Download the new version from the usual place:<br/>'
                    'https://electrum.org/'
                    '<br/><br/>')
        return False


class BitcoinSegwitRegtest(BitcoinSegwitTestnet):
    NAME = "BitcoinSegwit"
    NET = "regtest"
    GENESIS_HASH = ('0f9188f13cb7b2c71f2a335e3a4fc328'
                    'bf5beb436012afca590b1a11466e2206')
    PEERS = []
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


# Source: https://github.com/sumcoinlabs/sumcoin
class Sumcoin(Coin):
    NAME = "Sumcoin"
    SHORTNAME = "SUM"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b41c")
    XPRV_VERBYTES = bytes.fromhex("0488abe6")
    P2PKH_VERBYTE = bytes.fromhex("3f")
    P2SH_VERBYTES = [bytes.fromhex("c8"), bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("bf")
    GENESIS_HASH = ('37d4696c5072cd012f3b7c651e5ce56a'
                    '1383577e4edacc2d289ec9b25eebfd5e')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 976394
    TX_COUNT_HEIGHT = 659520
    TX_PER_BLOCK = 2
    REORG_LIMIT = 800
    RPC_PORT = 3332
    PEER_DEFAULT_PORTS = {'t': '53332', 's': '53333'}
    PEERS = []


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
        'ex.lug.gs s444',
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


class LitecoinRegtest(LitecoinTestnet):
    NET = "regtest"
    GENESIS_HASH = ('530827f38f93b43ed12af0b3ad25a288'
                    'dc02ed74d6d7857862df51fc56c416f9')
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1


class BitcoinCashRegtest(BitcoinTestnetMixin, Coin):
    NAME = "BitcoinCashABC"   # Some releases later remove the ABC suffix
    NET = "regtest"
    PEERS = []
    GENESIS_HASH = ('0f9188f13cb7b2c71f2a335e3a4fc328'
                    'bf5beb436012afca590b1a11466e2206')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    BLOCK_PROCESSOR = block_proc.LTORBlockProcessor


class Viacoin(AuxPowMixin, Coin):
    NAME = "Viacoin"
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


# Source: https://github.com/GravityCoinOfficial/GravityCoin/
class GravityCoin(Coin):
    NAME = "GravityCoin"
    SHORTNAME = "GXX"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("28")
    P2SH_VERBYTES = [bytes.fromhex("0a")]
    WIF_BYTE = bytes.fromhex("d2")
    GENESIS_HASH = ('322bad477efb4b33fa4b1f0b2861eaf543c61068da9898a95062fdb02ada486f')
    TX_COUNT = 446050
    TX_COUNT_HEIGHT = 547346
    TX_PER_BLOCK = 2
    PEER_DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    RPC_PORT = 29200
    REORG_LIMIT = 5000
    PEERS = []


# Source: https://github.com/BitcoinZeroOfficial/bitcoinzero
class Bitcoinzero(Coin):
    NAME = "Bitcoinzero"
    SHORTNAME = "BZX"
    TX_COUNT = 43798
    TX_COUNT_HEIGHT = 44
    TX_PER_BLOCK = 576
    NET = "mainnet"
    GENESIS_HASH = '322bad477efb4b33fa4b1f0b2861eaf543c61068da9898a95062fdb02ada486f'
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("4b")
    P2SH_VERBYTES = [bytes.fromhex("22")]
    WIF_BYTE = bytes.fromhex("d2")
    RPC_PORT = 29202
    REORG_LIMIT = 5000
    PEERS = []


class Unitus(Coin):
    NAME = "Unitus"
    SHORTNAME = "UIS"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("44")
    P2SH_VERBYTES = [bytes.fromhex("0A")]
    WIF_BYTE = bytes.fromhex("84")
    GENESIS_HASH = ('d8a2b2439d013a59f3bfc626a33487a3'
                    'd7d27e42a3c9e0b81af814cd8e592f31')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 3484561
    TX_COUNT_HEIGHT = 1697605
    TX_PER_BLOCK = 3
    RPC_PORT = 50604
    REORG_LIMIT = 2000
    PEERS = [
        'electrumx.unituscurrency.com s t',
    ]


# Source: namecoin.org
class Namecoin(NameIndexMixin, AuxPowMixin, Coin):
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
    DESERIALIZER = lib_tx.DeserializerAuxPowSegWit
    TX_COUNT = 4415768
    TX_COUNT_HEIGHT = 329065
    TX_PER_BLOCK = 10
    RPC_PORT = 8336
    PEERS = [
        'electrum-nmc.le-space.de s50002',
        'ex.lug.gs s446',
        'luggscoqbymhvnkp.onion t82',
        'nmc.bitcoins.sk s50002',
        'ulrichard.ch s50006 t50005',
    ]
    BLOCK_PROCESSOR = block_proc.NameIndexBlockProcessor

    # Name opcodes
    OP_NAME_NEW = OpCodes.OP_1
    OP_NAME_FIRSTUPDATE = OpCodes.OP_2
    OP_NAME_UPDATE = OpCodes.OP_3

    # Valid name prefixes.
    NAME_NEW_OPS = [OP_NAME_NEW, -1, OpCodes.OP_2DROP]
    NAME_FIRSTUPDATE_OPS = [OP_NAME_FIRSTUPDATE, "name", -1, -1,
                            OpCodes.OP_2DROP, OpCodes.OP_2DROP]
    NAME_UPDATE_OPS = [OP_NAME_UPDATE, "name", -1, OpCodes.OP_2DROP,
                       OpCodes.OP_DROP]
    NAME_OPERATIONS = [
        NAME_NEW_OPS,
        NAME_FIRSTUPDATE_OPS,
        NAME_UPDATE_OPS,
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


class NamecoinRegtest(NamecoinTestnet):
    NAME = "Namecoin"
    NET = "regtest"
    GENESIS_HASH = ('0f9188f13cb7b2c71f2a335e3a4fc328'
                    'bf5beb436012afca590b1a11466e2206')
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1


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


# Source: https://github.com/motioncrypto/motion
class Motion(Coin):
    NAME = "Motion"
    SHORTNAME = "XMN"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    GENESIS_HASH = ('000001e9dc60dd2618e91f7b90141349'
                    '22c374496b61c1a272519b1c39979d78')
    P2PKH_VERBYTE = bytes.fromhex("32")
    P2SH_VERBYTES = [bytes.fromhex("12")]
    TX_COUNT_HEIGHT = 54353
    TX_COUNT = 92701
    TX_PER_BLOCK = 4
    RPC_PORT = 3385
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x16r_hash
        return x16r_hash.getPoWHash(header)


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
    DESERIALIZER = lib_tx_dash.DeserializerDash

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
        'dasht.random.re s54002 t54001',
    ]


class DashRegtest(DashTestnet):
    NET = "regtest"
    GENESIS_HASH = ('000008ca1832a4baf228eb1553c03d3a'
                    '2c8e02399550dd6ea8d65cec3ef23d2e')
    PEERS = []
    TX_COUNT_HEIGHT = 1
    TX_COUNT = 1


class Argentum(AuxPowMixin, Coin):
    NAME = "Argentum"
    SHORTNAME = "ARG"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("17")
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
    HEADER_VALUES = ('version', 'prev_block_hash', 'merkle_root',
                     'payload_hash', 'timestamp', 'creatorId')
    HEADER_UNPACK = struct.Struct('< I 32s 32s 32s I I').unpack_from
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


class Zcash(EquihashMixin, Coin):
    NAME = "Zcash"
    SHORTNAME = "ZEC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1CB8")
    P2SH_VERBYTES = [bytes.fromhex("1CBD")]
    GENESIS_HASH = ('00040fe8ec8471911baa1db1266ea15d'
                    'd06b4a8a5c453883c000b031973dce08')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 329196
    TX_COUNT_HEIGHT = 68379
    TX_PER_BLOCK = 5
    RPC_PORT = 8232
    REORG_LIMIT = 800


class ZcashTestnet(Zcash):
    SHORTNAME = "TAZ"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("1D25")
    P2SH_VERBYTES = [bytes.fromhex("1CBA")]
    WIF_BYTE = bytes.fromhex("EF")
    GENESIS_HASH = ('05a60a92d99d85997cce3b87616c089f'
                    '6124d7342af37106edc76126334a2c38')
    TX_COUNT = 242312
    TX_COUNT_HEIGHT = 321685
    TX_PER_BLOCK = 2
    RPC_PORT = 18232


class SnowGem(EquihashMixin, Coin):
    NAME = "SnowGem"
    SHORTNAME = "XSG"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1C28")
    P2SH_VERBYTES = [bytes.fromhex("1C2D")]
    GENESIS_HASH = ('00068b35729d9d2b0c294ff1fe9af009'
                    '4740524311a131de40e7f705e4c29a5b')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 1680878
    TX_COUNT_HEIGHT = 627250
    TX_PER_BLOCK = 2
    RPC_PORT = 16112
    REORG_LIMIT = 800
    CHUNK_SIZE = 200


class Zero(EquihashMixin, Coin):
    NAME = "Zero"
    SHORTNAME = "ZER"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1CB8")
    P2SH_VERBYTES = [bytes.fromhex("1CBD")]
    GENESIS_HASH = ('068cbb5db6bc11be5b93479ea4df41fa'
                    '7e012e92ca8603c315f9b1a2202205c6')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 329998
    TX_COUNT_HEIGHT = 847425
    TX_PER_BLOCK = 2
    RPC_PORT = 23811
    REORG_LIMIT = 800


class BitcoinZ(EquihashMixin, Coin):
    NAME = "BitcoinZ"
    SHORTNAME = "BTCZ"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1CB8")
    P2SH_VERBYTES = [bytes.fromhex("1CBD")]
    GENESIS_HASH = ('f499ee3d498b4298ac6a64205b8addb7'
                    'c43197e2a660229be65db8a4534d75c1')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 171976
    TX_COUNT_HEIGHT = 81323
    TX_PER_BLOCK = 3
    RPC_PORT = 1979
    REORG_LIMIT = 800


class ZelCash(EquihashMixin, Coin):
    NAME = "ZelCash"
    SHORTNAME = "ZEL"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1CB8")
    P2SH_VERBYTES = [bytes.fromhex("1CBD")]
    GENESIS_HASH = ('00052461a5006c2e3b74ce48992a0869'
                    '5607912d5604c3eb8da25749b0900444')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 450539
    TX_COUNT_HEIGHT = 167114
    TX_PER_BLOCK = 3
    RPC_PORT = 16124
    REORG_LIMIT = 800


class Zclassic(EquihashMixin, Coin):
    NAME = "Zclassic"
    SHORTNAME = "ZCL"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1CB8")
    P2SH_VERBYTES = [bytes.fromhex("1CBD")]
    GENESIS_HASH = ('0007104ccda289427919efc39dc9e4d4'
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


class KotoTestnet(Koto):
    SHORTNAME = "TOKO"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("18A4")
    P2SH_VERBYTES = [bytes.fromhex("1839")]
    WIF_BYTE = bytes.fromhex("EF")
    GENESIS_HASH = ('bf84afbde20c2d213b68b231ddb585ab'
                    '616ef7567226820f00d9b397d774d2f0')
    TX_COUNT = 91144
    TX_COUNT_HEIGHT = 89662
    TX_PER_BLOCK = 1
    RPC_PORT = 18432
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    PEERS = [
        'testnet.kotocoin.info s t',
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


class Hush(KomodoMixin, EquihashMixin, Coin):
    NAME = "Hush"
    SHORTNAME = "HUSH"
    NET = "mainnet"
    TX_COUNT = 111317
    TX_COUNT_HEIGHT = 169280
    TX_PER_BLOCK = 2
    RPC_PORT = 18031
    REORG_LIMIT = 800


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


class Verus(KomodoMixin, EquihashMixin, Coin):
    NAME = "Verus"
    SHORTNAME = "VRSC"
    NET = "mainnet"
    TX_COUNT = 55000
    TX_COUNT_HEIGHT = 42000
    TX_PER_BLOCK = 2
    RPC_PORT = 27486
    REORG_LIMIT = 800
    PEERS = []

    @classmethod
    def header_hash(cls, header):
        '''Given a header return hash'''
        import verushash
        # if this may be the genesis block, use sha256, otherwise, VerusHash
        if cls.header_prevhash(header) == bytes([0] * 32):
            return double_sha256(header)
        else:
            if (header[0] == 4 and header[2] >= 1):
                if (len(header) < 144 or header[143] < 3):
                    return verushash.verushash_v2b(header)
                else:
                    return verushash.verushash_v2b1(header)
            else:
                return verushash.verushash(header)


class Einsteinium(Coin):
    NAME = "Einsteinium"
    SHORTNAME = "EMC2"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("21")
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


class DeepOnion(Coin):
    NAME = "DeepOnion"
    SHORTNAME = "ONION"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1F")
    P2SH_VERBYTES = [bytes.fromhex("4E")]
    WIF_BYTE = bytes.fromhex("9f")
    GENESIS_HASH = ('000004e29458ef4f2e0abab544737b07'
                    '344e6ff13718f7c2d12926166db07b5e')
    DESERIALIZER = lib_tx.DeserializerTxTime
    DAEMON = daemon.LegacyRPCDaemon
    TX_COUNT = 1194707
    TX_COUNT_HEIGHT = 530000
    TX_PER_BLOCK = 2
    RPC_PORT = 18580
    REORG_LIMIT = 200
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    PEERS = []

    @classmethod
    def header_hash(cls, header):
        '''
        Given a header return the hash for DeepOnion.
        Need to download `x13_hash` module
        Source code: https://github.com/MaruCoinOfficial/x13-hash
        '''
        import x13_hash
        return x13_hash.getPoWHash(header)


class Peercoin(Coin):
    NAME = "Peercoin"
    SHORTNAME = "PPC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("37")
    P2SH_VERBYTES = [bytes.fromhex("75")]
    WIF_BYTE = bytes.fromhex("b7")
    GENESIS_HASH = ('0000000032fe677166d54963b62a4677'
                    'd8957e87c508eaa4fd7eb1c880cd27e3')
    DESERIALIZER = lib_tx.DeserializerTxTimeSegWit
    DAEMON = daemon.FakeEstimateFeeDaemon
    ESTIMATE_FEE = 0.001
    RELAY_FEE = 0.01
    TX_COUNT = 1691771
    TX_COUNT_HEIGHT = 455409
    TX_PER_BLOCK = 4
    RPC_PORT = 9902
    REORG_LIMIT = 5000

    PEERS = [
        "electrum.peercoinexplorer.net s"
    ]

    VALUE_PER_COIN = 1000000


class PeercoinTestnet(Peercoin):
    NAME = "PeercoinTestnet"
    SHORTNAME = "tPPC"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = [bytes.fromhex("c4")]
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('00000001f757bb737f6596503e17cd17'
                    'b0658ce630cc727c0cca81aec47c9f06')
    ESTIMATE_FEE = 0.001


class Trezarcoin(Coin):
    NAME = "Trezarcoin"
    SHORTNAME = "TZC"
    NET = "mainnet"
    VALUE_PER_COIN = 1000000
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("42")
    P2SH_VERBYTES = [bytes.fromhex("08")]
    WIF_BYTE = bytes.fromhex("c2")
    GENESIS_HASH = ('24502ba55d673d2ee9170d83dae2d1ad'
                    'b3bfb4718e4f200db9951382cc4f6ee6')
    DESERIALIZER = lib_tx.DeserializerTrezarcoin
    HEADER_HASH = lib_tx.DeserializerTrezarcoin.blake2s
    HEADER_HASH_GEN = lib_tx.DeserializerTrezarcoin.blake2s_gen
    BASIC_HEADER_SIZE = 80
    TX_COUNT = 742886
    TX_COUNT_HEIGHT = 643128
    TX_PER_BLOCK = 2
    RPC_PORT = 17299
    REORG_LIMIT = 2000
    PEERS = [
        'electrumx1.trezarcoin.com s t',
    ]

    @classmethod
    def genesis_block(cls, block):
        '''Check the Genesis block is the right one for this coin.

        Return the block less its unspendable coinbase.
        '''
        header = cls.block_header(block, 0)
        header_hex_hash = cls.HEADER_HASH_GEN(header)
        if header_hex_hash != cls.GENESIS_HASH:
            raise CoinError('genesis block has hash {} expected {}'
                            .format(header_hex_hash, cls.GENESIS_HASH))
        return header + bytes(1)

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        return cls.HEADER_HASH(header)


class Reddcoin(Coin):
    NAME = "Reddcoin"
    SHORTNAME = "RDD"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("3d")
    WIF_BYTE = bytes.fromhex("bd")
    GENESIS_HASH = ('b868e0d95a3c3c0e0dadc67ee587aaf9'
                    'dc8acbf99e3b4b3110fad4eb74c1decc')
    DESERIALIZER = lib_tx.DeserializerReddcoin
    TX_COUNT = 5413508
    TX_COUNT_HEIGHT = 1717382
    TX_PER_BLOCK = 3
    RPC_PORT = 45443


class TokenPay(ScryptMixin, Coin):
    NAME = "TokenPay"
    SHORTNAME = "TPAY"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("41")
    P2SH_VERBYTES = [bytes.fromhex("7e")]
    WIF_BYTE = bytes.fromhex("b3")
    GENESIS_HASH = ('000008b71ab32e585a23f0de642dc113'
                    '740144e94c0ece047751e9781f953ae9')
    DESERIALIZER = lib_tx.DeserializerTokenPay
    DAEMON = daemon.LegacyRPCDaemon
    TX_COUNT = 147934
    TX_COUNT_HEIGHT = 73967
    TX_PER_BLOCK = 100
    RPC_PORT = 8800
    REORG_LIMIT = 500
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")

    PEERS = [
        "electrum-us.tpay.ai s",
        "electrum-eu.tpay.ai s",
    ]


class Vertcoin(Coin):
    NAME = "Vertcoin"
    SHORTNAME = "VTC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("47")
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
    BLACKLIST_URL = 'https://electrum-mona.org/blacklist.json'
    PEERS = [
        'electrumx.tamami-foundation.org s t',
        'electrumx3.monacoin.nl s t',
        'electrumx1.monacoin.ninja s t',
        'electrumx2.movsign.info s t',
        'electrum-mona.bitbank.cc s t',
        'ri7rzlmdaf4eqbza.onion s t',
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


class MonacoinRegtest(MonacoinTestnet):
    NET = "regtest"
    GENESIS_HASH = ('7543a69d7c2fcdb29a5ebec2fc064c07'
                    '4a35253b6f3072c8a749473aa590a29c')
    PEERS = []
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1


class Crown(AuxPowMixin, Coin):
    NAME = "Crown"
    SHORTNAME = "CRW"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2SH_VERBYTES = [bytes.fromhex("1c")]
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
    GENESIS_HASH = ('000009f7e55e9e3b4781e22bd87a7cfa'
                    '4acada9e4340d43ca738bf4e9fb8f5ce')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1408733
    TX_COUNT_HEIGHT = 1015115
    TX_PER_BLOCK = 1
    RPC_PORT = 9252
    REORG_LIMIT = 1000

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import zny_yespower_0_5
        return zny_yespower_0_5.getPoWHash(header)


class CanadaeCoin(AuxPowMixin, Coin):
    NAME = "CanadaeCoin"
    SHORTNAME = "CDN"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("1C")
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
    P2PKH_VERBYTE = bytes.fromhex("1E")  # Address starts with a D
    P2SH_VERBYTES = [bytes.fromhex("5A")]
    WIF_BYTE = bytes.fromhex("9E")  # WIF starts with a 6
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


class SibcoinTestnet(Sibcoin):
    SHORTNAME = "tSIB"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    GENESIS_HASH = ('00000617791d0e19f524387f67e558b2'
                    'a928b670b9a3b387ae003ad7f9093017')

    RPC_PORT = 11944


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
        'electrumx-gb-1.feathercoin.network s t',
        'electrumx-gb-2.feathercoin.network s t',
        'electrumx-de-1.feathercoin.network s t',
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
    TX_COUNT = 5161944
    TX_COUNT_HEIGHT = 3948743
    TX_PER_BLOCK = 2
    REORG_LIMIT = 2000


class Bitcore(BitcoinMixin, Coin):
    NAME = "Bitcore"
    SHORTNAME = "BTX"
    P2PKH_VERBYTE = bytes.fromhex("03")
    P2SH_VERBYTES = [bytes.fromhex("7D")]
    DESERIALIZER = lib_tx.DeserializerSegWit
    GENESIS_HASH = ('604148281e5c4b7f2487e5d03cd60d8e'
                    '6f69411d613f6448034508cea52e9574')
    TX_COUNT = 126979
    TX_COUNT_HEIGHT = 126946
    TX_PER_BLOCK = 2
    RPC_PORT = 8556
    PEERS = [
        'ele1.bitcore.cc s t',
        'ele2.bitcore.cc s t',
        'ele3.bitcore.cc s t',
        'ele4.bitcore.cc s t'
    ]


class GameCredits(Coin):
    NAME = "GameCredits"
    SHORTNAME = "GAME"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("26")
    WIF_BYTE = bytes.fromhex("a6")
    GENESIS_HASH = ('91ec5f25ee9a0ffa1af7d4da4db9a552'
                    '228dd2dc77cdb15b738be4e1f55f30ee')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 316796
    TX_COUNT_HEIGHT = 2040250
    TX_PER_BLOCK = 2
    RPC_PORT = 40001
    REORG_LIMIT = 1000


class Machinecoin(Coin):
    NAME = "Machinecoin"
    SHORTNAME = "MAC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("32")
    P2SH_VERBYTES = [bytes.fromhex("26"), bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("b2")
    GENESIS_HASH = ('6a1f879bcea5471cbfdee1fd0cb2ddcc'
                    '4fed569a500e352d41de967703e83172')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 137641
    TX_COUNT_HEIGHT = 513020
    TX_PER_BLOCK = 2
    RPC_PORT = 40332
    REORG_LIMIT = 800


class BitcoinAtom(Coin):
    NAME = "BitcoinAtom"
    SHORTNAME = "BCA"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("17")
    P2SH_VERBYTES = [bytes.fromhex("0a")]
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
            flags, = util.unpack_le_uint32_from(header, len(header) - 4)
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
    XPUB_VERBYTES = bytes.fromhex("02fda926")
    XPRV_VERBYTES = bytes.fromhex("02fda4e8")
    P2PKH_VERBYTE = bytes.fromhex("073f")
    P2SH_VERBYTES = [bytes.fromhex("071a")]
    WIF_BYTE = bytes.fromhex("22de")
    GENESIS_HASH = ('298e5cc3d985bfe7f81dc135f360abe0'
                    '89edd4396b86d2de66b0cef42b21d980')
    BASIC_HEADER_SIZE = 180
    HEADER_HASH = lib_tx.DeserializerDecred.blake256
    DESERIALIZER = lib_tx.DeserializerDecred
    DAEMON = daemon.DecredDaemon
    BLOCK_PROCESSOR = block_proc.DecredBlockProcessor
    ENCODE_CHECK = partial(Base58.encode_check,
                           hash_fn=lib_tx.DeserializerDecred.blake256d)
    DECODE_CHECK = partial(Base58.decode_check,
                           hash_fn=lib_tx.DeserializerDecred.blake256d)
    HEADER_VALUES = ('version', 'prev_block_hash', 'merkle_root', 'stake_root',
                     'vote_bits', 'final_state', 'voters', 'fresh_stake',
                     'revocations', 'pool_size', 'bits', 'sbits',
                     'block_height', 'size', 'timestamp', 'nonce',
                     'extra_data', 'stake_version')
    HEADER_UNPACK = struct.Struct(
        '< i 32s 32s 32s H 6s H B B I I Q I I I I 32s I').unpack_from
    TX_COUNT = 4629388
    TX_COUNT_HEIGHT = 260628
    TX_PER_BLOCK = 17
    REORG_LIMIT = 1000
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
    SHORTNAME = "tDCR"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587d1")
    XPRV_VERBYTES = bytes.fromhex("04358397")
    P2PKH_VERBYTE = bytes.fromhex("0f21")
    P2SH_VERBYTES = [bytes.fromhex("0efc")]
    WIF_BYTE = bytes.fromhex("230e")
    GENESIS_HASH = (
        'a649dce53918caf422e9c711c858837e08d626ecfcd198969b24f7b634a49bac')
    BASIC_HEADER_SIZE = 180
    ALLOW_ADVANCING_ERRORS = True
    TX_COUNT = 217380620
    TX_COUNT_HEIGHT = 464000
    TX_PER_BLOCK = 1800
    REORG_LIMIT = 1000
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
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon
    DESERIALIZER = lib_tx_axe.DeserializerAxe
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


class AxeTestnet(Axe):
    SHORTNAME = "tAxe"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("3a805837")
    XPRV_VERBYTES = bytes.fromhex("3a8061a0")
    GENESIS_HASH = ('000005b709662e7bc5e89c71d3aba6c9'
                    'd4623b4bbf44ac205caec55f4cefb483')
    P2PKH_VERBYTE = bytes.fromhex("8c")
    P2SH_VERBYTES = [bytes.fromhex("13")]
    WIF_BYTE = bytes.fromhex("ef")
    TX_COUNT_HEIGHT = 101619
    TX_COUNT = 132681
    TX_PER_BLOCK = 1
    RPC_PORT = 19937
    PEER_DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    PEERS = []


class AxeRegtest(AxeTestnet):
    NET = "regtest"
    GENESIS_HASH = ('2026b8850f3774a0536152ba868c4dcb'
                    'de9aef5ffc28a5d23f76f80e9b46e565')
    PEERS = []
    TX_COUNT_HEIGHT = 1
    RPC_PORT = 19869
    TX_COUNT = 1


class Xuez(Coin):
    NAME = "Xuez"
    SHORTNAME = "XUEZ"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("022d2533")
    XPRV_VERBYTES = bytes.fromhex("0221312b")
    P2PKH_VERBYTE = bytes.fromhex("48")
    P2SH_VERBYTES = [bytes.fromhex("12")]
    WIF_BYTE = bytes.fromhex("d4")
    GENESIS_HASH = ('000000e1febc39965b055e8e0117179a'
                    '4d18e24e7aaa0c69864c4054b4f29445')
    TX_COUNT = 30000
    TX_COUNT_HEIGHT = 15000
    TX_PER_BLOCK = 1
    RPC_PORT = 41799
    REORG_LIMIT = 1000
    BASIC_HEADER_SIZE = 112
    PEERS = []

    @classmethod
    def header_hash(cls, header):
        '''
        Given a header return the hash for Xuez.
        Need to download `xevan_hash` module
        Source code: https://github.com/xuez/xuez
        '''
        version, = util.unpack_le_uint32_from(header)

        import xevan_hash

        if version == 1:
            return xevan_hash.getPoWHash(header[:80])
        else:
            return xevan_hash.getPoWHash(header)


# Source: https://github.com/odinblockchain/odin
class Odin(Coin):
    NAME = "ODIN"
    SHORTNAME = "ODIN"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("27561872")
    XPRV_VERBYTES = bytes.fromhex("27256746")
    P2PKH_VERBYTE = bytes.fromhex("73")
    P2SH_VERBYTES = [bytes.fromhex("39")]
    WIF_BYTE = bytes.fromhex("8a")
    GENESIS_HASH = ('31ca29566549e444cf227a0e2e067aed'
                    '847c2acc541d3bbf9ca1ae89f4fd57d7')

    TX_COUNT = 340000
    TX_COUNT_HEIGHT = 340000
    TX_PER_BLOCK = 2
    RPC_PORT = 22101
    REORG_LIMIT = 100

    BASIC_HEADER_SIZE = 80
    HDR_V4_SIZE = 112
    HDR_V4_HEIGHT = 143447
    HDR_V4_START_OFFSET = HDR_V4_HEIGHT * BASIC_HEADER_SIZE

    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon
    DESERIALIZER = lib_tx.DeserializerSegWit

    @classmethod
    def static_header_offset(cls, height):
        assert cls.STATIC_BLOCK_HEADERS
        if height >= cls.HDR_V4_HEIGHT:
            relative_v4_offset = (height - cls.HDR_V4_HEIGHT) * cls.HDR_V4_SIZE
            return cls.HDR_V4_START_OFFSET + relative_v4_offset
        else:
            return height * cls.BASIC_HEADER_SIZE

    @classmethod
    def header_hash(cls, header):
        version, = util.unpack_le_uint32_from(header)
        if version >= 4:
            return super().header_hash(header)
        else:
            import quark_hash
            return quark_hash.getPoWHash(header)


class Pac(Coin):
    NAME = "PAC"
    SHORTNAME = "PAC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    GENESIS_HASH = ('00000354655ff039a51273fe61d3b493'
                    'bd2897fe6c16f732dbc4ae19f04b789e')
    P2PKH_VERBYTE = bytes.fromhex("37")
    P2SH_VERBYTES = [bytes.fromhex("0A")]
    WIF_BYTE = bytes.fromhex("CC")
    TX_COUNT_HEIGHT = 14939
    TX_COUNT = 23708
    TX_PER_BLOCK = 2
    RPC_PORT = 7111
    PEERS = [
        'electrum.paccoin.io s t',
        'electro-pac.paccoin.io s t'
    ]
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon
    ESTIMATE_FEE = 0.00001
    RELAY_FEE = 0.00001

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x11_hash
        return x11_hash.getPoWHash(header)


class PacTestnet(Pac):
    SHORTNAME = "tPAC"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587CF")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    GENESIS_HASH = ('00000da63bd9478b655ef6bf1bf76cd9'
                    'af05202ab68643f9091e049b2b5280ed')
    P2PKH_VERBYTE = bytes.fromhex("78")
    P2SH_VERBYTES = [bytes.fromhex("0E")]
    WIF_BYTE = bytes.fromhex("EF")
    TX_COUNT_HEIGHT = 16275
    TX_COUNT = 16275
    TX_PER_BLOCK = 1
    RPC_PORT = 17111


class Zcoin(Coin):
    NAME = "Zcoin"
    SHORTNAME = "XZC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("52")
    P2SH_VERBYTES = [bytes.fromhex("07")]
    WIF_BYTE = bytes.fromhex("d2")
    GENESIS_HASH = ('4381deb85b1b2c9843c222944b616d99'
                    '7516dcbd6a964e1eaf0def0830695233')
    TX_COUNT = 667154
    TX_COUNT_HEIGHT = 100266
    TX_PER_BLOCK = 4000  # 2000 for 1MB block
    IRC_PREFIX = None
    RPC_PORT = 8888
    REORG_LIMIT = 5000
    PEER_DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    MTP_HEADER_EXTRA_SIZE = 100
    MTP_HEADER_DATA_SIZE = 198864
    MTP_HEADER_DATA_START = Coin.BASIC_HEADER_SIZE + MTP_HEADER_EXTRA_SIZE
    MTP_HEADER_DATA_END = MTP_HEADER_DATA_START + MTP_HEADER_DATA_SIZE
    STATIC_BLOCK_HEADERS = False
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.ZcoinMtpDaemon
    DESERIALIZER = lib_tx.DeserializerZcoin
    PEERS = [
        'electrum.polispay.com'
    ]

    @classmethod
    def is_mtp(cls, header):
        from electrumx.lib.util import unpack_le_uint32_from, hex_to_bytes
        if isinstance(header, str):
            nVersion, = unpack_le_uint32_from(hex_to_bytes(header[0:4*2]))
        elif isinstance(header, bytes):
            nVersion, = unpack_le_uint32_from(header[0:4])
        else:
            raise "Cannot handle the passed type"
        return nVersion & 0x1000

    @classmethod
    def block_header(cls, block, height):
        sz = cls.BASIC_HEADER_SIZE
        if cls.is_mtp(block):
            sz += cls.MTP_HEADER_EXTRA_SIZE
        return block[:sz]

    @classmethod
    def header_hash(cls, header):
        sz = cls.BASIC_HEADER_SIZE
        if cls.is_mtp(header):
            sz += cls.MTP_HEADER_EXTRA_SIZE
        return double_sha256(header[:sz])


class ZcoinTestnet(Zcoin):
    SHORTNAME = "tXZC"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("41")
    P2SH_VERBYTES = [bytes.fromhex("b2")]
    WIF_BYTE = bytes.fromhex("b9")
    GENESIS_HASH = '1e3487fdb1a7d46dac3e8f3e58339c6e' \
                   'ff54abf6aef353485f3ed64250a35e89'
    REORG_LIMIT = 8000
    RPC_PORT = 18888


class GINCoin(Coin):
    NAME = "GINCoin"
    SHORTNAME = "GIN"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    GENESIS_HASH = ('00000cd6bde619b2c3b23ad2e384328a'
                    '450a37fa28731debf748c3b17f91f97d')
    P2PKH_VERBYTE = bytes.fromhex("37")
    P2SH_VERBYTES = [bytes.fromhex("38")]
    WIF_BYTE = bytes.fromhex("3c")
    TX_COUNT_HEIGHT = 225000
    TX_COUNT = 470784
    TX_PER_BLOCK = 4
    RPC_PORT = 10211
    PEERS = [
        'electrum.polispay.com'
    ]
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

    # Seems that the main lyra2z_hash python package doesn't works.
    # Tested and working with: https://github.com/LapoLab/lyra2z-py
    @classmethod
    def header_hash(cls, header):
        timestamp = util.unpack_le_uint32_from(header, 68)[0]
        if timestamp > 1550246400:
            import x16rt_hash
            return x16rt_hash.getPoWHash(header)
        elif timestamp > 1525651200:
            import lyra2z_hash
            return lyra2z_hash.getPoWHash(header)
        import neoscrypt
        return neoscrypt.getPoWHash(header)


class Polis(Coin):
    NAME = "Polis"
    SHORTNAME = "POLIS"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("03E25D7E")
    XPRV_VERBYTES = bytes.fromhex("03E25945")
    GENESIS_HASH = ('000009701eb781a8113b1af1d814e2f0'
                    '60f6408a2c990db291bc5108a1345c1e')
    P2PKH_VERBYTE = bytes.fromhex("37")
    P2SH_VERBYTES = [bytes.fromhex("38")]
    WIF_BYTE = bytes.fromhex("3c")
    TX_COUNT_HEIGHT = 280600
    TX_COUNT = 635415
    TX_PER_BLOCK = 4
    RPC_PORT = 24127
    PEERS = [
        'electrum.polispay.com'
    ]
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x11_hash
        return x11_hash.getPoWHash(header)


class MNPCoin(Coin):
    NAME = "MNPCoin"
    SHORTNAME = "MNP"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    GENESIS_HASH = ('00000924036c67d803ce606ded814312'
                    '7e62fa2111dd3b063880a1067c69ccb1')
    P2PKH_VERBYTE = bytes.fromhex("32")
    P2SH_VERBYTES = [bytes.fromhex("35")]
    WIF_BYTE = bytes.fromhex("37")
    TX_COUNT_HEIGHT = 248000
    TX_COUNT = 506447
    TX_PER_BLOCK = 4
    RPC_PORT = 13373
    PEERS = [
        'electrum.polispay.com'
    ]
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import quark_hash
        return quark_hash.getPoWHash(header)


class ColossusXT(Coin):
    NAME = "ColossusXT"
    SHORTNAME = "COLX"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    GENESIS_HASH = ('a0ce8206c908357008c1b9a8ba2813af'
                    'f0989ca7f72d62b14e652c55f02b4f5c')
    P2PKH_VERBYTE = bytes.fromhex("1E")
    P2SH_VERBYTES = [bytes.fromhex("0D")]
    WIF_BYTE = bytes.fromhex("D4")
    TX_COUNT_HEIGHT = 356500
    BASIC_HEADER_SIZE = 80
    HDR_V5_HEIGHT = 500000
    HDR_V5_SIZE = 112
    HDR_V5_START_OFFSET = HDR_V5_HEIGHT * BASIC_HEADER_SIZE
    TX_COUNT = 761041
    TX_PER_BLOCK = 4
    RPC_PORT = 51473
    PEERS = [
        'electrum.polispay.com'
    ]
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

    @classmethod
    def static_header_offset(cls, height):
        assert cls.STATIC_BLOCK_HEADERS
        if height >= cls.HDR_V5_HEIGHT:
            relative_v4_offset = (height - cls.HDR_V5_HEIGHT) * cls.HDR_V5_SIZE
            return cls.HDR_V5_START_OFFSET + relative_v4_offset
        else:
            return height * cls.BASIC_HEADER_SIZE

    @classmethod
    def header_hash(cls, header):
        version, = util.unpack_le_uint32_from(header)
        if version >= 5:
            return super().header_hash(header)
        else:
            import quark_hash
            return quark_hash.getPoWHash(header)


class Minexcoin(EquihashMixin, Coin):
    NAME = "Minexcoin"
    SHORTNAME = "MNX"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("4b")
    GENESIS_HASH = ('490a36d9451a55ed197e34aca7414b35'
                    'd775baa4a8e896f1c577f65ce2d214cb')
    STATIC_BLOCK_HEADERS = True
    BASIC_HEADER_SIZE = 209
    HEADER_SIZE_NO_SOLUTION = 140
    TX_COUNT = 327963
    TX_COUNT_HEIGHT = 74495
    TX_PER_BLOCK = 5
    RPC_PORT = 8022
    CHUNK_SIZE = 960
    PEERS = [
        'electrumx.xpresit.net s t',
        'elex01-ams.turinex.eu s t',
        'eu.minexpool.nl s t'
    ]

    @classmethod
    def block_header(cls, block, height):
        '''Return the block header bytes'''
        deserializer = cls.DESERIALIZER(block)
        return deserializer.read_header(cls.HEADER_SIZE_NO_SOLUTION)


class Groestlcoin(Coin):
    NAME = "Groestlcoin"
    SHORTNAME = "GRS"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("24")
    GENESIS_HASH = ('00000ac5927c594d49cc0bdb81759d0d'
                    'a8297eb614683d3acb62f0703b639023')
    DESERIALIZER = lib_tx.DeserializerGroestlcoin
    TX_COUNT = 115900
    TX_COUNT_HEIGHT = 1601528
    TX_PER_BLOCK = 5
    RPC_PORT = 1441
    BLACKLIST_URL = 'https://groestlcoin.org/blacklist.json'
    PEERS = [
        'electrum1.groestlcoin.org s t',
        'electrum2.groestlcoin.org s t',
        '6brsrbiinpc32tfc.onion t',
        'xkj42efxrcy6vbfw.onion t',
    ]

    def grshash(data):
        import groestlcoin_hash
        return groestlcoin_hash.getHash(data, len(data))

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        return cls.grshash(header)

    ENCODE_CHECK = partial(Base58.encode_check, hash_fn=grshash)
    DECODE_CHECK = partial(Base58.decode_check, hash_fn=grshash)


class GroestlcoinTestnet(Groestlcoin):
    SHORTNAME = "TGRS"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = [bytes.fromhex("c4")]
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('000000ffbb50fc9898cdd36ec163e6ba'
                    '23230164c0052a28876255b7dcf2cd36')
    RPC_PORT = 17766
    PEERS = [
        'electrum-test1.groestlcoin.org s t',
        'electrum-test2.groestlcoin.org s t',
        '7frvhgofuf522b5i.onion t',
        'aocojvqcybdoxekv.onion t',
    ]


class Pivx(Coin):
    NAME = "PIVX"
    SHORTNAME = "PIVX"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("022D2533")
    XPRV_VERBYTES = bytes.fromhex("0221312B")
    GENESIS_HASH = ('0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818')
    P2PKH_VERBYTE = bytes.fromhex("1e")
    P2SH_VERBYTE = bytes.fromhex("0d")
    WIF_BYTE = bytes.fromhex("d4")
    TX_COUNT_HEIGHT = 569399
    TX_COUNT = 2157510
    TX_PER_BLOCK = 1
    STATIC_BLOCK_HEADERS = False
    RPC_PORT = 51470
    ZEROCOIN_HEADER = 112
    ZEROCOIN_START_HEIGHT = 863787
    ZEROCOIN_BLOCK_VERSION = 4

    @classmethod
    def static_header_len(cls, height):
        '''Given a header height return its length.'''
        if (height >= cls.ZEROCOIN_START_HEIGHT):
            return cls.ZEROCOIN_HEADER
        else:
            return cls.BASIC_HEADER_SIZE

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        version, = struct.unpack('<I', header[:4])
        if version >= cls.ZEROCOIN_BLOCK_VERSION:
            return super().header_hash(header)
        else:
            import quark_hash
            return quark_hash.getPoWHash(header)


class PivxTestnet(Pivx):
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("3a8061a0")
    XPRV_VERBYTES = bytes.fromhex("3a805837")
    GENESIS_HASH = ('0000041e482b9b9691d98eefb48473405c0b8ec31b76df3797c74a78680ef818')
    P2PKH_VERBYTE = bytes.fromhex("8B")
    P2SH_VERBYTE = bytes.fromhex("13")
    WIF_BYTE = bytes.fromhex("EF")
    TX_PER_BLOCK = 4
    RPC_PORT = 51472
    ZEROCOIN_START_HEIGHT = 201564


class Bitg(Coin):

    NAME = "BitcoinGreen"
    SHORTNAME = "BITG"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("26")
    P2SH_VERBYTES = [bytes.fromhex("06")]
    WIF_BYTE = bytes.fromhex("2e")
    GENESIS_HASH = (
        '000008467c3a9c587533dea06ad9380cded3ed32f9742a6c0c1aebc21bf2bc9b')
    DAEMON = daemon.DashDaemon
    TX_COUNT = 1000
    TX_COUNT_HEIGHT = 10000
    TX_PER_BLOCK = 1
    RPC_PORT = 9332
    REORG_LIMIT = 1000
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import quark_hash
        return quark_hash.getPoWHash(header)


class tBitg(Bitg):
    SHORTNAME = "tBITG"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("62")
    P2SH_VERBYTES = [bytes.fromhex("0c")]
    WIF_BYTE = bytes.fromhex("6c")
    GENESIS_HASH = (
        '000008467c3a9c587533dea06ad9380cded3ed32f9742a6c0c1aebc21bf2bc9b')
    RPC_PORT = 19332


class EXOS(Coin):
    NAME = "EXOS"
    SHORTNAME = "EXOS"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    GENESIS_HASH = ('00000036090a68c523471da7a4f0f958'
                    'c1b4403fef74a003be7f71877699cab7')
    P2PKH_VERBYTE = bytes.fromhex("1C")
    P2SH_VERBYTE = [bytes.fromhex("57")]
    WIF_BYTE = bytes.fromhex("9C")
    RPC_PORT = 4561
    TX_COUNT = 1000
    TX_COUNT_HEIGHT = 10000
    TX_PER_BLOCK = 4
    DAEMON = daemon.PreLegacyRPCDaemon
    DESERIALIZER = lib_tx.DeserializerTxTime

    @classmethod
    def header_hash(cls, header):
        version, = util.unpack_le_uint32_from(header)

        if version > 2:
            return double_sha256(header)
        else:
            return hex_str_to_hash(EXOS.GENESIS_HASH)


class EXOSTestnet(EXOS):
    SHORTNAME = "tEXOS"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    GENESIS_HASH = ('0000059bb2c2048493efcb0f1a034972'
                    'b3ce4089d54c93b69aaab212fb369887')
    P2PKH_VERBYTE = bytes.fromhex("4B")
    P2SH_VERBYTE = [bytes.fromhex("CE")]
    WIF_BYTE = bytes.fromhex("CB")
    RPC_PORT = 14561

    @classmethod
    def header_hash(cls, header):
        version, = util.unpack_le_uint32_from(header)

        if version > 2:
            return double_sha256(header)
        else:
            return hex_str_to_hash(EXOSTestnet.GENESIS_HASH)


class SmartCash(Coin):
    NAME = "SmartCash"
    SHORTNAME = "SMART"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("3f")
    P2SH_VERBYTES = [bytes.fromhex("12")]
    WIF_BYTE = bytes.fromhex("bf")
    GENESIS_HASH = ('000007acc6970b812948d14ea5a0a13d'
                    'b0fdd07d5047c7e69101fa8b361e05a4')
    DESERIALIZER = lib_tx.DeserializerSmartCash
    RPC_PORT = 9679
    REORG_LIMIT = 5000
    TX_COUNT = 1115016
    TX_COUNT_HEIGHT = 541656
    TX_PER_BLOCK = 1
    ENCODE_CHECK = partial(Base58.encode_check,
                           hash_fn=lib_tx.DeserializerSmartCash.keccak)
    DECODE_CHECK = partial(Base58.decode_check,
                           hash_fn=lib_tx.DeserializerSmartCash.keccak)
    HEADER_HASH = lib_tx.DeserializerSmartCash.keccak
    DAEMON = daemon.SmartCashDaemon
    SESSIONCLS = SmartCashElectrumX

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        return cls.HEADER_HASH(header)


class NIX(Coin):
    NAME = "NIX"
    SHORTNAME = "NIX"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("26")
    P2SH_VERBYTES = [bytes.fromhex("35")]
    GENESIS_HASH = ('dd28ad86def767c3cfc34267a950d871'
                    'fc7462bc57ea4a929fc3596d9b598e41')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 114240
    TX_COUNT_HEIGHT = 87846
    TX_PER_BLOCK = 3
    RPC_PORT = 6215
    REORG_LIMIT = 1000


class NIXTestnet(NIX):
    SHORTNAME = "tNIX"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    GENESIS_HASH = ('dd28ad86def767c3cfc34267a950d871'
                    'fc7462bc57ea4a929fc3596d9b598e41')
    P2PKH_VERBYTE = bytes.fromhex("01")
    P2SH_VERBYTE = [bytes.fromhex("03")]
    RPC_PORT = 16215
    DESERIALIZER = lib_tx.DeserializerSegWit


class Noir(Coin):
    NAME = "Noir"
    SHORTNAME = "NOR"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2SH_VERBYTES = [bytes.fromhex("07")]
    WIF_BYTE = bytes.fromhex("D0")
    GENESIS_HASH = ('23911212a525e3d149fcad6c559c8b17'
                    'f1e8326a272a75ff9bb315c8d96433ef')
    RPC_PORT = 8825
    TX_COUNT = 586369
    TX_COUNT_HEIGHT = 379290
    TX_PER_BLOCK = 5


class BitcoinPlus(Coin):
    NAME = "BitcoinPlus"
    SHORTNAME = "XBC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = [bytes.fromhex("55")]
    WIF_BYTE = bytes.fromhex("99")
    GENESIS_HASH = ('0000005f6a28e686f641c616e56182d1'
                    'b43afbe08a223f23bda23cdf9d55b882')
    DESERIALIZER = lib_tx.DeserializerTxTime
    DAEMON = daemon.LegacyRPCDaemon
    TX_COUNT = 1479247
    TX_COUNT_HEIGHT = 749740
    TX_PER_BLOCK = 2
    RPC_PORT = 8885
    REORG_LIMIT = 2000

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x13_hash
        return x13_hash.getPoWHash(header)


class Myriadcoin(AuxPowMixin, Coin):
    NAME = "Myriadcoin"
    SHORTNAME = "XMY"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("32")
    P2SH_VERBYTES = [bytes.fromhex("09")]
    WIF_BYTE = bytes.fromhex("b2")
    GENESIS_HASH = ('00000ffde4c020b5938441a0ea3d314b'
                    'f619eff0b38f32f78f7583cffa1ea485')
    DESERIALIZER = lib_tx.DeserializerAuxPowSegWit
    TX_COUNT = 1976629
    TX_COUNT_HEIGHT = 2580356
    TX_PER_BLOCK = 20
    REORG_LIMIT = 2000
    RPC_PORT = 10889


class MyriadcoinTestnet(Myriadcoin):
    NAME = "Myriadcoin"
    SHORTNAME = "XMT"
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587cf")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("58")
    P2SH_VERBYTES = [bytes.fromhex("bc")]
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('0000017ce2a79c8bddafbbe47c004aa9'
                    '2b20678c354b34085f62b762084b9788')


class Sparks(Coin):
    NAME = "Sparks"
    SHORTNAME = "SPK"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    GENESIS_HASH = ('00000a5c6ddfaac5097218560d5b92d4'
                    '16931cfeba1abf10c81d1d6a232fc8ea')
    P2PKH_VERBYTE = bytes.fromhex("26")
    P2SH_VERBYTES = [bytes.fromhex("0A")]
    WIF_BYTE = bytes.fromhex("C6")
    TX_COUNT_HEIGHT = 117400
    TX_COUNT = 162310
    TX_PER_BLOCK = 4
    RPC_PORT = 8818
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

    @classmethod
    def header_hash(cls, header):
        import neoscrypt
        return neoscrypt.getPoWHash(header)


# Source: https://github.com/LIMXTEC/BitSend
class Bitsend(Coin):
    NAME = "Bitsend"
    SHORTNAME = "BSD"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("66")
    WIF_BYTE = bytes.fromhex("cc")
    GENESIS_HASH = ('0000012e1b8843ac9ce8c18603658eaf'
                    '8895f99d3f5e7e1b7b1686f35e3c087a')
    TX_COUNT = 974672
    TX_COUNT_HEIGHT = 586022
    TX_PER_BLOCK = 2
    RPC_PORT = 8800
    REORG_LIMIT = 1000
    DESERIALIZER = lib_tx.DeserializerSegWit
    XEVAN_TIMESTAMP = 1477958400
    PEERS = [
        'ele1.bitsend.cc s t',
        '51.15.121.233 s t'
    ]

    @classmethod
    def header_hash(cls, header):
        timestamp, = util.unpack_le_uint32_from(header, 68)
        if timestamp > cls.XEVAN_TIMESTAMP:
            import xevan_hash
            return xevan_hash.getPoWHash(header)
        else:
            import x11_hash
            return x11_hash.getPoWHash(header)

    @classmethod
    def genesis_block(cls, block):
        header = cls.block_header(block, 0)
        header_hex_hash = hash_to_hex_str(cls.header_hash(header))
        if header_hex_hash != cls.GENESIS_HASH:
            raise CoinError('genesis block has hash {} expected {}'
                            .format(header_hex_hash, cls.GENESIS_HASH))
        return header + bytes(1)


class Ritocoin(Coin):
    NAME = "Ritocoin"
    SHORTNAME = "RITO"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0534E7CA")
    XPRV_VERBYTES = bytes.fromhex("05347EAC")
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = [bytes.fromhex("69")]
    GENESIS_HASH = ('00000075e344bdf1c0e433f453764b18'
                    '30a7aa19b2a5213e707502a22b779c1b')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1188090
    TX_COUNT_HEIGHT = 296030
    TX_PER_BLOCK = 3
    RPC_PORT = 8766
    REORG_LIMIT = 55
    PEERS = [
        'electrum-rito.minermore.com s t'
    ]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x21s_hash
        return x21s_hash.getPoWHash(header)


class Ravencoin(Coin):
    NAME = "Ravencoin"
    SHORTNAME = "RVN"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("3C")
    P2SH_VERBYTES = [bytes.fromhex("7A")]
    GENESIS_HASH = ('0000006b444bc2f2ffe627be9d9e7e7a'
                    '0730000870ef6eb6da46c8eae389df90')
    DESERIALIZER = lib_tx.DeserializerSegWit
    X16RV2_ACTIVATION_TIME = 1569945600  # algo switch to x16rv2 at this timestamp
    TX_COUNT = 5626682
    TX_COUNT_HEIGHT = 887000
    TX_PER_BLOCK = 6
    RPC_PORT = 8766
    REORG_LIMIT = 55
    PEERS = [
    ]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        timestamp = util.unpack_le_uint32_from(header, 68)[0]
        if timestamp >= cls.X16RV2_ACTIVATION_TIME:
            import x16rv2_hash
            return x16rv2_hash.getPoWHash(header)
        else:
            import x16r_hash
            return x16r_hash.getPoWHash(header)


class RavencoinTestnet(Ravencoin):
    NET = "testnet"
    XPUB_VERBYTES = bytes.fromhex("043587CF")
    XPRV_VERBYTES = bytes.fromhex("04358394")
    P2PKH_VERBYTE = bytes.fromhex("6F")
    P2SH_VERBYTES = [bytes.fromhex("C4")]
    WIF_BYTE = bytes.fromhex("EF")
    GENESIS_HASH = ('000000ecfc5e6324a079542221d00e10'
                    '362bdc894d56500c414060eea8a3ad5a')
    X16RV2_ACTIVATION_TIME = 1567533600
    TX_COUNT = 496158
    TX_COUNT_HEIGHT = 420500
    TX_PER_BLOCK = 1
    RPC_PORT = 18766
    PEER_DEFAULT_PORTS = {'t': '50003', 's': '50004'}
    REORG_LIMIT = 55
    PEERS = [
    ]


class Bolivarcoin(Coin):
    NAME = "Bolivarcoin"
    SHORTNAME = "BOLI"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("55")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("D5")
    GENESIS_HASH = ('00000e4fc293a1912b9d73cbb8d8f727'
                    '0007a7d84382f1370661e65d5d57b1f6')
    TX_COUNT = 1082515
    TX_COUNT_HEIGHT = 540410
    TX_PER_BLOCK = 10
    RPC_PORT = 3563
    REORG_LIMIT = 800
    PEERS = []
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x11_hash
        return x11_hash.getPoWHash(header)


class Onixcoin(Coin):
    NAME = "Onixcoin"
    SHORTNAME = "ONX"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("4B")
    GENESIS_HASH = ('000007140b7a6ca0b64965824f5731f6'
                    'e86daadf19eb299033530b1e61236e43')
    TX_COUNT = 431808
    TX_COUNT_HEIGHT = 321132
    TX_PER_BLOCK = 10
    RPC_PORT = 41019
    REORG_LIMIT = 800
    PEERS = []
    SESSIONCLS = DashElectrumX
    DAEMON = daemon.DashDaemon

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import x11_hash
        return x11_hash.getPoWHash(header)


class Electra(Coin):
    NAME = "Electra"
    SHORTNAME = "ECA"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("21")
    P2SH_VERBYTES = [bytes.fromhex("28")]
    WIF_BYTE = bytes.fromhex("A1")
    GENESIS_HASH = ('00000f98da995de0ef1665c7d3338687'
                    '923c1199230a44ecbdb5cec9306e4f4e')
    RPC_PORT = 5788
    TX_COUNT = 615729
    TX_COUNT_HEIGHT = 205243
    TX_PER_BLOCK = 3
    REORG_LIMIT = 100
    DESERIALIZER = lib_tx.DeserializerElectra

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        version, = util.unpack_le_uint32_from(header)
        import nist5_hash

        if version != 8:
            return nist5_hash.getPoWHash(header)
        else:
            return double_sha256(header)


class ECCoin(Coin):
    NAME = "ECCoin"
    SHORTNAME = "ECC"
    NET = "mainnet"
    DESERIALIZER = lib_tx.DeserializerECCoin
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("21")
    P2SH_VERBYTES = [bytes.fromhex("08")]
    GENESIS_HASH = ('a60ac43c88dbc44b826cf315352a8a7b373d2af8b6e1c4c4a0638859c5e9ecd1')
    TX_COUNT = 4661197
    TX_COUNT_HEIGHT = 2114846
    TX_PER_BLOCK = 10
    VALUE_PER_COIN = 1000000
    RPC_PORT = 19119

    @classmethod
    def header_hash(cls, header):
        # you have to install scryp python module (pip install scrypt)
        import scrypt
        return scrypt.hash(header, header, 1024, 1, 1, 32)


class Bellcoin(Coin):
    NAME = "Bellcoin"
    SHORTNAME = "BELL"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = [bytes.fromhex("55")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('000008f3b6bd10c2d03b06674a006b8d'
                    '9731f6cb58179ef1eee008cee2209603')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 264129
    TX_COUNT_HEIGHT = 219574
    TX_PER_BLOCK = 5
    RPC_PORT = 25252
    REORG_LIMIT = 1000
    PEERS = [
        'bell.electrumx.japanesecoin-pool.work s t',
        'bell.streetcrypto7.com s t',
    ]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import bell_yespower
        return bell_yespower.getPoWHash(header)


class CPUchain(Coin):
    NAME = "CPUchain"
    SHORTNAME = "CPU"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1C")
    P2SH_VERBYTES = [bytes.fromhex("1E")]
    GENESIS_HASH = ('000024d8766043ea0e1c9ad42e7ea4b5'
                    'fdb459887bd80b8f9756f3d87e128f12')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 4471
    TX_COUNT_HEIGHT = 3491
    TX_PER_BLOCK = 2
    RPC_PORT = 19707
    REORG_LIMIT = 1000
    PEERS = [
        'electrumx.cpuchain.org s t',
    ]

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        import cpupower
        return cpupower.getPoWHash(header)


class Xaya(NameIndexMixin, AuxPowMixin, Coin):
    NAME = "Xaya"
    SHORTNAME = "CHI"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("1c")
    P2SH_VERBYTES = [bytes.fromhex("1e")]
    WIF_BYTE = bytes.fromhex("82")
    GENESIS_HASH = ('e5062d76e5f50c42f493826ac9920b63'
                    'a8def2626fd70a5cec707ec47a4c4651')
    TX_COUNT = 1147749
    TX_COUNT_HEIGHT = 1030000
    TX_PER_BLOCK = 2
    DESERIALIZER = lib_tx.DeserializerXaya
    TRUNCATED_HEADER_SIZE = 80 + 5
    RPC_PORT = 8396
    PEERS = [
        'seeder.xaya.io s50002',
        'xaya.domob.eu s50002',
    ]

    # Op-codes for name operations
    OP_NAME_REGISTER = OpCodes.OP_1
    OP_NAME_UPDATE = OpCodes.OP_2

    # Valid name prefixes.
    NAME_REGISTER_OPS = [OP_NAME_REGISTER, "name", -1, OpCodes.OP_2DROP,
                         OpCodes.OP_DROP]
    NAME_UPDATE_OPS = [OP_NAME_UPDATE, "name", -1, OpCodes.OP_2DROP,
                       OpCodes.OP_DROP]
    NAME_OPERATIONS = [
        NAME_REGISTER_OPS,
        NAME_UPDATE_OPS,
    ]

    @classmethod
    def genesis_block(cls, block):
        super().genesis_block(block)

        # In Xaya, the genesis block's coinbase is spendable.  Thus unlike
        # the generic genesis_block() method, we return the full block here.
        return block


class XayaTestnet(Xaya):
    SHORTNAME = "XCH"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("58")
    P2SH_VERBYTES = [bytes.fromhex("5a")]
    WIF_BYTE = bytes.fromhex("e6")
    GENESIS_HASH = ('5195fc01d0e23d70d1f929f21ec55f47'
                    'e1c6ea1e66fae98ee44cbbc994509bba')
    TX_COUNT = 51557
    TX_COUNT_HEIGHT = 49000
    TX_PER_BLOCK = 1
    RPC_PORT = 18396
    PEERS = []


class XayaRegtest(XayaTestnet):
    NET = "regtest"
    GENESIS_HASH = ('6f750b36d22f1dc3d0a6e483af453010'
                    '22646dfc3b3ba2187865f5a7d6d83ab1')
    RPC_PORT = 18493

# Source: https://github.com/GZR0/GRZ0


class GravityZeroCoin(ScryptMixin, Coin):
    NAME = "GravityZeroCoin"
    SHORTNAME = "GZRO"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("26")
    WIF_BYTE = bytes.fromhex("26")
    GENESIS_HASH = ('0000028bfbf9ccaed8f28b3ca6b3ffe6b65e29490ab0e4430679bf41cc7c164f')
    DAEMON = daemon.FakeEstimateLegacyRPCDaemon
    TX_COUNT = 100
    TX_COUNT_HEIGHT = 747635
    TX_PER_BLOCK = 2
    RPC_PORT = 36442
    ESTIMATE_FEE = 0.01
    RELAY_FEE = 0.01


class Simplicity(Coin):
    NAME = "Simplicity"
    SHORTNAME = "SPL"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0444d5bc")
    XPRV_VERBYTES = bytes.fromhex("0444f0a3")
    P2PKH_VERBYTE = bytes.fromhex("12")
    P2SH_VERBYTE = bytes.fromhex("3b")
    WIF_BYTE = bytes.fromhex("5d")
    GENESIS_HASH = ('f4bbfc518aa3622dbeb8d2818a606b82c2b8b1ac2f28553ebdb6fc04d7abaccf')
    RPC_PORT = 11958
    TX_COUNT = 1726548
    TX_COUNT_HEIGHT = 1040000
    TX_PER_BLOCK = 5
    REORG_LIMIT = 100
    DESERIALIZER = lib_tx.DeserializerSimplicity

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        version, = util.unpack_le_uint32_from(header)

        if version < 2:
            import quark_hash
            return quark_hash.getPoWHash(header)
        else:
            return double_sha256(header)


class Myce(Coin):
    NAME = "Myce"
    SHORTNAME = "YCE"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("32")
    P2SH_VERBYTE = bytes.fromhex("55")
    WIF_BYTE = bytes.fromhex("99")
    GENESIS_HASH = ('0000c74cc66c72cb1a327c5c1d4893ae5276aa50be49fb23cec21df1a2f20d87')
    RPC_PORT = 23512
    TX_COUNT = 1568977
    TX_COUNT_HEIGHT = 774450
    TX_PER_BLOCK = 3
    REORG_LIMIT = 100
    DESERIALIZER = lib_tx.DeserializerSimplicity

    @classmethod
    def header_hash(cls, header):
        '''Given a header return the hash.'''
        version, = util.unpack_le_uint32_from(header)

        if version < 7:
            import scrypt
            return scrypt.hash(header, header, 1024, 1, 1, 32)
        else:
            return double_sha256(header)


class Navcoin(Coin):
    NAME = "Navcoin"
    SHORTNAME = "NAV"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("35")
    P2SH_VERBYTES = [bytes.fromhex("55")]
    WIF_BYTE = bytes.fromhex("96")
    GENESIS_HASH = ('00006a4e3e18c71c6d48ad6c261e2254'
                    'fa764cf29607a4357c99b712dfbb8e6a')
    DESERIALIZER = lib_tx.DeserializerTxTimeSegWitNavCoin
    TX_COUNT = 137641
    TX_COUNT_HEIGHT = 3649662
    TX_PER_BLOCK = 2
    RPC_PORT = 44444
    REORG_LIMIT = 1000

    @classmethod
    def header_hash(cls, header):
        if int.from_bytes(header[:4], "little") > 6:
            return double_sha256(header)
        else:
            import x13_hash
            return x13_hash.getPoWHash(header)


class Unobtanium(AuxPowMixin, Coin):
    NAME = "Unobtanium"
    SHORTNAME = "UNO"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    P2PKH_VERBYTE = bytes.fromhex("82")
    P2SH_VERBYTES = [bytes.fromhex("1e")]
    WIF_BYTE = bytes.fromhex("e0")
    GENESIS_HASH = ('000004c2fc5fffb810dccc197d603690'
                    '099a68305232e552d96ccbe8e2c52b75')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 65535
    REORG_LIMIT = 5000


class Linx(Coin):
    NAME = "Linx"
    SHORTNAME = "LINX"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("4b")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("cb")
    GENESIS_HASH = ('3bafea350a70f75e7a1cd279999faed7'
                    '1a51852aae88fed3c38553cecc810a92')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9381
    REORG_LIMIT = 5000


class Flashcoin(Coin):
    NAME = "Flashcoin"
    SHORTNAME = "FLASH"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("44")
    P2SH_VERBYTES = [bytes.fromhex("82")]
    WIF_BYTE = bytes.fromhex("c4")
    GENESIS_HASH = ('aa0cf4f5ce0a3c550ce5674c1e808c41'
                    '7cf5077b4e95bda1d6fbaeaf4258972b')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9385
    REORG_LIMIT = 5000


class Defcoin(Coin):
    NAME = "Defcoin"
    SHORTNAME = "DEFC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1e")
    P2SH_VERBYTES = bytes.fromhex("05")
    WIF_BYTE = bytes.fromhex("9e")
    GENESIS_HASH = ('192047379f33ffd2bbbab3d53b9c4b9e'
                    '9b72e48f888eadb3dcf57de95a6038ad')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9386
    REORG_LIMIT = 5000


class Smileycoin(Coin):
    NAME = "Smileycoin"
    SHORTNAME = "SMLY"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = bytes.fromhex("05")
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('660f734cf6c6d16111bde201bbd21228'
                    '73f2f2c078b969779b9d4c99732354fd')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9388
    REORG_LIMIT = 5000


class Iop(Coin):
    NAME = "Iop"
    SHORTNAME = "IOP"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("75")
    P2SH_VERBYTES = [bytes.fromhex("AE")]
    WIF_BYTE = bytes.fromhex("31")
    GENESIS_HASH = ('00000000bf5f2ee556cb9be8be64e077'
                    '6af14933438dbb1af72c41bfb6c82db3')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 8337
    REORG_LIMIT = 5000


class Egulden(Coin):
    NAME = "Egulden"
    SHORTNAME = "EFL"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("30")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('6d39f28ad01a7edd3e2374b355cf8c7f'
                    '8dbc1c5e4596ad3642fa6d10c2599217')
    TX_COUNT = 13336629
    TX_COUNT_HEIGHT = 1268206
    TX_PER_BLOCK = 10
    RPC_PORT = 9402
    REORG_LIMIT = 5000


class Ixcoin(AuxPowMixin, Coin):
    NAME = "ixcoin"
    SHORTNAME = "IXC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("8a")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('0000000001534ef8893b025b9c1da672'
                    '50285e35c9f76cae36a4904fdf72c591')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9406
    REORG_LIMIT = 5000


class Batacoin(Coin):
    NAME = "bata"
    SHORTNAME = "BTA"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("19")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("99")
    GENESIS_HASH = ('b4bee36fd54a6176fd832f462641415c'
                    '142d50e4b378f71c041870c2b1186bc8')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9412
    REORG_LIMIT = 5000


class Digitalcoin(Coin):
    NAME = "digitalcoin"
    SHORTNAME = "DGC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1e")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("9e")
    GENESIS_HASH = ('5e039e1ca1dbf128973bf6cff98169e4'
                    '0a1b194c3b91463ab74956f413b2f9c8')
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9413
    REORG_LIMIT = 5000


class Cannacoin(Coin):
    NAME = "cannacoin"
    SHORTNAME = "CCN"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1C")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("bd")
    GENESIS_HASH = ('f1b4cdf03c86099a0758f1c018d1a10b'
                    'f05afab436c92b93b42bb88970de9821')
    DESERIALIZER = lib_tx.DeserializerReddcoin
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 1234
    REORG_LIMIT = 5000


class Europecoin(Coin):
    NAME = "europecoin"
    SHORTNAME = "ERC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("21")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("a8")
    GENESIS_HASH = ('000d0da26987ead011c5d568e627f7e3'
                    'd4a4f83a0b280b1134d8e7e366377f9a')
    BASIC_HEADER_SIZE = 88
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9412
    REORG_LIMIT = 5000


class Adcoin(Coin):
    NAME = "Adcoin"
    SHORTNAME = "ACC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1e")
    P2SH_VERBYTES = [bytes.fromhex("0d")]
    WIF_BYTE = bytes.fromhex("97")
    GENESIS_HASH = ('000000fc5276647fd959f718c9526f87'
                    'f4858c4ef62f2e29d3772e4e37040a25')

    BASIC_HEADER_SIZE = 112
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9416
    REORG_LIMIT = 5000


class Lynx(Coin):
    NAME = "Lynx"
    SHORTNAME = "LYNX"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("2d")
    P2SH_VERBYTES = [bytes.fromhex("16")]
    WIF_BYTE = bytes.fromhex("ad")
    GENESIS_HASH = ('984b30fc9bb5e5ff424ad7f4ec193053'
                    '8a7b14a2d93e58ad7976c23154ea4a76')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9139
    REORG_LIMIT = 5000


class LitecoinCash(Coin):
    NAME = "LitecoinCash"
    SHORTNAME = "LCC"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1c")
    P2SH_VERBYTES = [bytes.fromhex("32"), bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('12a765e31ffd4059bada1e25190f6e98'
                    'c99d9714d334efa41a195a7e7e04bfe2')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 1
    RPC_PORT = 9140
    REORG_LIMIT = 5000


class BitcoinPrivate(EquihashMixin, Coin):
    NAME = "BitcoinPrivate"
    SHORTNAME = "BTCP"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("1325")
    P2SH_VERBYTES = [bytes.fromhex("13AF")]
    WIF_BYTE = bytes.fromhex("80")
    GENESIS_HASH = ('0007104ccda289427919efc39dc9e4d4'
                    '99804b7bebc22df55f8b834301260602')
    DESERIALIZER = lib_tx.DeserializerZcash
    TX_COUNT = 329196
    TX_COUNT_HEIGHT = 68379
    TX_PER_BLOCK = 5
    RPC_PORT = 9335
    REORG_LIMIT = 5000


class Aryacoin(Coin):
    NAME = "aryacoin"
    SHORTNAME = "AYA"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("019d9cfe")
    XPRV_VERBYTES = bytes.fromhex("019da462")
    P2PKH_VERBYTE = bytes.fromhex("17")
    P2SH_VERBYTES = [bytes.fromhex("6f")]
    WIF_BYTE = bytes.fromhex("b0")
    GENESIS_HASH = ('b553727635006d7faade229d152482df'
                    'b9da7822d41cf0cad9ffa82a54f67803')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 10
    RPC_PORT = 9151
    REORG_LIMIT = 800


class Donu(Coin):
    NAME = "donu"
    SHORTNAME = "DONU"
    NET = "mainnet"
    P2PKH_VERBYTE = bytes.fromhex("35")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("b1")
    XPUB_VERBYTES = bytes.fromhex("0488B21E")
    XPRV_VERBYTES = bytes.fromhex("0488ADE4")
    GENESIS_HASH = ('5f7f26e24291f5be2351e1dcdab18bf9'
                    '4cee718940e6b9f2fbb46227434c3f12')
    DESERIALIZER = lib_tx.DeserializerSegWit
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 10
    RPC_PORT = 26381
    REORG_LIMIT = 800


class Quebecoin(AuxPowMixin, Coin):
    NAME = "Quebecoin"
    SHORTNAME = "QBC"
    NET = "mainnet"
    XPUB_VERBYTES = bytes.fromhex("0488b21e")
    XPRV_VERBYTES = bytes.fromhex("0488ade4")
    P2PKH_VERBYTE = bytes.fromhex("3a")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    WIF_BYTE = bytes.fromhex("ba")
    GENESIS_HASH = ('000008c2d57759af6462352ee9f4923d'
                    '97401cb599a9318e6595a2a74c26ea74')
    DESERIALIZER = lib_tx.DeserializerAuxPowSegWit
    TX_COUNT = 1
    TX_COUNT_HEIGHT = 1
    TX_PER_BLOCK = 20
    REORG_LIMIT = 2000
    RPC_PORT = 10890
