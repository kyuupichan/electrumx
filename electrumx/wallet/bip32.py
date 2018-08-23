# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Logic for BIP32 Hierarchical Key Derviation.'''

import struct

import ecdsa
import ecdsa.ellipticcurve as EC
import ecdsa.numbertheory as NT

from electrumx.lib.coins import Coin
from electrumx.lib.hash import Base58, hmac_sha512, hash160
from electrumx.lib.util import cachedproperty, bytes_to_int, int_to_bytes, \
    pack_be_uint32, unpack_be_uint32_from


class DerivationError(Exception):
    '''Raised when an invalid derivation occurs.'''


class _KeyBase(object):
    '''A BIP32 Key, public or private.'''

    CURVE = ecdsa.SECP256k1

    def __init__(self, chain_code, n, depth, parent):
        if not isinstance(chain_code, (bytes, bytearray)):
            raise TypeError('chain code must be raw bytes')
        if len(chain_code) != 32:
            raise ValueError('invalid chain code')
        if not 0 <= n < 1 << 32:
            raise ValueError('invalid child number')
        if not 0 <= depth < 256:
            raise ValueError('invalid depth')
        if parent is not None:
            if not isinstance(parent, type(self)):
                raise TypeError('parent key has bad type')
        self.chain_code = chain_code
        self.n = n
        self.depth = depth
        self.parent = parent

    def _hmac_sha512(self, msg):
        '''Use SHA-512 to provide an HMAC, returned as a pair of 32-byte
        objects.
        '''
        hmac = hmac_sha512(self.chain_code, msg)
        return hmac[:32], hmac[32:]

    def _extended_key(self, ver_bytes, raw_serkey):
        '''Return the 78-byte extended key given prefix version bytes and
        serialized key bytes.
        '''
        if not isinstance(ver_bytes, (bytes, bytearray)):
            raise TypeError('ver_bytes must be raw bytes')
        if len(ver_bytes) != 4:
            raise ValueError('ver_bytes must have length 4')
        if not isinstance(raw_serkey, (bytes, bytearray)):
            raise TypeError('raw_serkey must be raw bytes')
        if len(raw_serkey) != 33:
            raise ValueError('raw_serkey must have length 33')

        return (ver_bytes + bytes([self.depth])
                + self.parent_fingerprint() + pack_be_uint32(self.n)
                + self.chain_code + raw_serkey)

    def fingerprint(self):
        '''Return the key's fingerprint as 4 bytes.'''
        return self.identifier()[:4]

    def parent_fingerprint(self):
        '''Return the parent key's fingerprint as 4 bytes.'''
        return self.parent.fingerprint() if self.parent else bytes(4)

    def extended_key_string(self, coin):
        '''Return an extended key as a base58 string.'''
        return Base58.encode_check(self.extended_key(coin))


class PubKey(_KeyBase):
    '''A BIP32 public key.'''

    def __init__(self, pubkey, chain_code, n, depth, parent=None):
        super().__init__(chain_code, n, depth, parent)
        if isinstance(pubkey, ecdsa.VerifyingKey):
            self.verifying_key = pubkey
        else:
            self.verifying_key = self._verifying_key_from_pubkey(pubkey)
        self.addresses = {}

    @classmethod
    def _verifying_key_from_pubkey(cls, pubkey):
        '''Converts a 33-byte compressed pubkey into an ecdsa.VerifyingKey
        object'''
        if not isinstance(pubkey, (bytes, bytearray)):
            raise TypeError('pubkey must be raw bytes')
        if len(pubkey) != 33:
            raise ValueError('pubkey must be 33 bytes')
        if pubkey[0] not in (2, 3):
            raise ValueError('invalid pubkey prefix byte')
        curve = cls.CURVE.curve

        is_odd = pubkey[0] == 3
        x = bytes_to_int(pubkey[1:])

        # p is the finite field order
        a, b, p = curve.a(), curve.b(), curve.p()
        y2 = pow(x, 3, p) + b
        assert a == 0  # Otherwise y2 += a * pow(x, 2, p)
        y = NT.square_root_mod_prime(y2 % p, p)
        if bool(y & 1) != is_odd:
            y = p - y
        point = EC.Point(curve, x, y)

        return ecdsa.VerifyingKey.from_public_point(point, curve=cls.CURVE)

    @cachedproperty
    def pubkey_bytes(self):
        '''Return the compressed public key as 33 bytes.'''
        point = self.verifying_key.pubkey.point
        prefix = bytes([2 + (point.y() & 1)])
        padded_bytes = _exponent_to_bytes(point.x())
        return prefix + padded_bytes

    def address(self, coin):
        "The public key as a P2PKH address"
        address = self.addresses.get(coin)
        if not address:
            address = coin.P2PKH_address_from_pubkey(self.pubkey_bytes)
            self.addresses[coin] = address
        return address

    def ec_point(self):
        return self.verifying_key.pubkey.point

    def child(self, n):
        '''Return the derived child extended pubkey at index N.'''
        if not 0 <= n < (1 << 31):
            raise ValueError('invalid BIP32 public key child number')

        msg = self.pubkey_bytes + pack_be_uint32(n)
        L, R = self._hmac_sha512(msg)

        curve = self.CURVE
        L = bytes_to_int(L)
        if L >= curve.order:
            raise DerivationError

        point = curve.generator * L + self.ec_point()
        if point == EC.INFINITY:
            raise DerivationError

        verkey = ecdsa.VerifyingKey.from_public_point(point, curve=curve)

        return PubKey(verkey, R, n, self.depth + 1, self)

    def identifier(self):
        '''Return the key's identifier as 20 bytes.'''
        return hash160(self.pubkey_bytes)

    def extended_key(self, coin):
        '''Return a raw extended public key.'''
        return self._extended_key(coin.XPUB_VERBYTES, self.pubkey_bytes)


class PrivKey(_KeyBase):
    '''A BIP32 private key.'''

    HARDENED = 1 << 31

    def __init__(self, privkey, chain_code, n, depth, parent=None):
        super().__init__(chain_code, n, depth, parent)
        if isinstance(privkey, ecdsa.SigningKey):
            self.signing_key = privkey
        else:
            self.signing_key = self._signing_key_from_privkey(privkey)

    @classmethod
    def _signing_key_from_privkey(cls, privkey):
        '''Converts a 32-byte privkey into an ecdsa.SigningKey object.'''
        exponent = cls._privkey_secret_exponent(privkey)
        return ecdsa.SigningKey.from_secret_exponent(exponent, curve=cls.CURVE)

    @classmethod
    def _privkey_secret_exponent(cls, privkey):
        '''Return the private key as a secret exponent if it is a valid private
        key.'''
        if not isinstance(privkey, (bytes, bytearray)):
            raise TypeError('privkey must be raw bytes')
        if len(privkey) != 32:
            raise ValueError('privkey must be 32 bytes')
        exponent = bytes_to_int(privkey)
        if not 1 <= exponent < cls.CURVE.order:
            raise ValueError('privkey represents an invalid exponent')

        return exponent

    @classmethod
    def from_seed(cls, seed):
        # This hard-coded message string seems to be coin-independent...
        hmac = hmac_sha512(b'Bitcoin seed', seed)
        privkey, chain_code = hmac[:32], hmac[32:]
        return cls(privkey, chain_code, 0, 0)

    @cachedproperty
    def privkey_bytes(self):
        '''Return the serialized private key (no leading zero byte).'''
        return _exponent_to_bytes(self.secret_exponent())

    @cachedproperty
    def public_key(self):
        '''Return the corresponding extended public key.'''
        verifying_key = self.signing_key.get_verifying_key()
        parent_pubkey = self.parent.public_key if self.parent else None
        return PubKey(verifying_key, self.chain_code, self.n, self.depth,
                      parent_pubkey)

    def ec_point(self):
        return self.public_key.ec_point()

    def secret_exponent(self):
        '''Return the private key as a secret exponent.'''
        return self.signing_key.privkey.secret_multiplier

    def WIF(self, coin):
        '''Return the private key encoded in Wallet Import Format.'''
        return coin.privkey_WIF(self.privkey_bytes, compressed=True)

    def address(self, coin):
        "The public key as a P2PKH address"
        return self.public_key.address(coin)

    def child(self, n):
        '''Return the derived child extended privkey at index N.'''
        if not 0 <= n < (1 << 32):
            raise ValueError('invalid BIP32 private key child number')

        if n >= self.HARDENED:
            serkey = b'\0' + self.privkey_bytes
        else:
            serkey = self.public_key.pubkey_bytes

        msg = serkey + pack_be_uint32(n)
        L, R = self._hmac_sha512(msg)

        curve = self.CURVE
        L = bytes_to_int(L)
        exponent = (L + bytes_to_int(self.privkey_bytes)) % curve.order
        if exponent == 0 or L >= curve.order:
            raise DerivationError

        privkey = _exponent_to_bytes(exponent)

        return PrivKey(privkey, R, n, self.depth + 1, self)

    def identifier(self):
        '''Return the key's identifier as 20 bytes.'''
        return self.public_key.identifier()

    def extended_key(self, coin):
        '''Return a raw extended private key.'''
        return self._extended_key(coin.XPRV_VERBYTES,
                                  b'\0' + self.privkey_bytes)


def _exponent_to_bytes(exponent):
    '''Convert an exponent to 32 big-endian bytes'''
    return (bytes(32) + int_to_bytes(exponent))[-32:]


def _from_extended_key(ekey):
    '''Return a PubKey or PrivKey from an extended key raw bytes.'''
    if not isinstance(ekey, (bytes, bytearray)):
        raise TypeError('extended key must be raw bytes')
    if len(ekey) != 78:
        raise ValueError('extended key must have length 78')

    is_public, coin = Coin.lookup_xverbytes(ekey[:4])
    depth = ekey[4]
    fingerprint = ekey[5:9]   # Not used
    n, = unpack_be_uint32_from(ekey[9:13])
    chain_code = ekey[13:45]

    if is_public:
        pubkey = ekey[45:]
        key = PubKey(pubkey, chain_code, n, depth)
    else:
        if ekey[45] is not 0:
            raise ValueError('invalid extended private key prefix byte')
        privkey = ekey[46:]
        key = PrivKey(privkey, chain_code, n, depth)

    return key, coin


def from_extended_key_string(ekey_str):
    '''Given an extended key string, such as

    xpub6BsnM1W2Y7qLMiuhi7f7dbAwQZ5Cz5gYJCRzTNainXzQXYjFwtuQXHd
    3qfi3t3KJtHxshXezfjft93w4UE7BGMtKwhqEHae3ZA7d823DVrL

    return a (key, coin) pair.  key is either a PubKey or PrivKey.
    '''
    return _from_extended_key(Base58.decode_check(ekey_str))
