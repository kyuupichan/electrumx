# Copyright (c) 2016-2021, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
#
# All rights reserved.
#
# This file is licensed under the Open BSV License version 3, see LICENCE for details.

'''Module providing coin abstraction.

Anything coin-specific should go in this file and be subclassed where
necessary for appropriate handling.
'''

import re
from decimal import Decimal
from hashlib import sha256

from electrumx.lib import util
from electrumx.lib.hash import Base58, double_sha256
from electrumx.lib.hash import HASHX_LEN
from electrumx.lib.script import ScriptPubKey
from electrumx.server.session import ElectrumX


class CoinError(Exception):
    '''Exception raised for coin-related errors.'''


class Coin:
    '''Base class of coin hierarchy.'''

    SHORTNAME = "BSV"
    NET = "mainnet"
    REORG_LIMIT = 200
    # Not sure if these are coin-specific
    RPC_URL_REGEX = re.compile('.+@(\\[[0-9a-fA-F:]+\\]|[^:]+)(:[0-9]+)?')
    VALUE_PER_COIN = 100000000
    SESSIONCLS = ElectrumX
    DEFAULT_MAX_SEND = 1000000
    P2PKH_VERBYTE = bytes.fromhex("00")
    P2SH_VERBYTES = [bytes.fromhex("05")]
    RPC_PORT = 8332
    GENESIS_HASH = ('000000000019d6689c085ae165831e93'
                    '4ff763ae46a2a6c172b3f1b60a8ce26f')
    GENESIS_ACTIVATION = 100_000_000
    # Peer discovery
    PEER_DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    PEERS = []

    @classmethod
    def lookup_coin_class(cls, name, net):
        '''Return a coin class given name and network.

        Raise an exception if unrecognised.'''
        req_attrs = ['CHAIN_SIZE', 'CHAIN_SIZE_HEIGHT', 'AVG_BLOCK_SIZE']
        for coin in util.subclasses(Coin):
            if coin.NAME.lower() == name.lower() and coin.NET.lower() == net.lower():
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
    def hashX_from_script(cls, script):
        '''Returns a hashX from a script.'''
        return sha256(script).digest()[:HASHX_LEN]

    @classmethod
    def address_to_hashX(cls, address):
        '''Return a hashX given a coin address.'''
        return cls.hashX_from_script(cls.pay_to_address_script(address))

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
        raw = Base58.decode_check(address)

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
    def header_hash(cls, header):
        '''Given a header return hash'''
        return double_sha256(header)

    @classmethod
    def header_prevhash(cls, header):
        '''Given a header return previous hash'''
        return header[4:36]

    @classmethod
    def decimal_value(cls, value):
        '''Return the number of standard coin units as a Decimal given a
        quantity of smallest units.

        For example 1 BSV is returned for 100 million satoshis.
        '''
        return Decimal(value) / cls.VALUE_PER_COIN

    @classmethod
    def prefetch_limit(cls, height):
        if height <= 650_000:
            return 100
        return 10


class BitcoinSV(Coin):
    NAME = "BitcoinSV"
    CHAIN_SIZE = 7_809_061_081_045
    CHAIN_SIZE_HEIGHT = 761_539
    AVG_BLOCK_SIZE = 800_000_000
    PEERS = [
        'satoshi.vision.cash s',
        'sv.usebsv.com s t',
        'sv.satoshi.io s t',
        'sv2.satoshi.io s t',
    ]
    GENESIS_ACTIVATION = 620_538


class BitcoinTestnetMixin:
    SHORTNAME = "XTN"
    NET = "testnet"
    P2PKH_VERBYTE = bytes.fromhex("6f")
    P2SH_VERBYTES = [bytes.fromhex("c4")]
    WIF_BYTE = bytes.fromhex("ef")
    GENESIS_HASH = ('000000000933ea01ad0ee984209779ba'
                    'aec3ced90fa3f408719526f8d77f4943')
    REORG_LIMIT = 8000
    CHAIN_SIZE = 26_584_216_544
    CHAIN_SIZE_HEIGHT = 1_454_438
    AVG_BLOCK_SIZE = 200_000

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
    CHAIN_SIZE = 20_000
    CHAIN_SIZE_HEIGHT = 100
    AVG_BLOCK_SIZE = 2_000_000_000
    GENESIS_ACTIVATION = 14_896

    @classmethod
    def prefetch_limit(cls, height):
        return 8


class BitcoinSVRegtest(BitcoinSVTestnet):
    NET = "regtest"
    GENESIS_HASH = ('0f9188f13cb7b2c71f2a335e3a4fc328'
                    'bf5beb436012afca590b1a11466e2206')
    PEERS = []
    CHAIN_SIZE = 20_000
    CHAIN_SIZE_HEIGHT = 100
    AVG_BLOCK_SIZE = 1_000_000
    GENESIS_ACTIVATION = 10_000


Bitcoin = BitcoinSV
