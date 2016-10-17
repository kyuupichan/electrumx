# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import hashlib
import hmac

from lib.util import bytes_to_int, int_to_bytes


def sha256(x):
    assert isinstance(x, (bytes, bytearray, memoryview))
    return hashlib.sha256(x).digest()


def ripemd160(x):
    assert isinstance(x, (bytes, bytearray, memoryview))
    h = hashlib.new('ripemd160')
    h.update(x)
    return h.digest()


def double_sha256(x):
    return sha256(sha256(x))


def hmac_sha512(key, msg):
    return hmac.new(key, msg, hashlib.sha512).digest()


def hash160(x):
    return ripemd160(sha256(x))

def hash_to_str(x):
    '''Converts a big-endian binary hash to a little-endian hex string, as
    shown in block explorers, etc.
    '''
    return bytes(reversed(x)).hex()

def hex_str_to_hash(x):
    '''Converts a little-endian hex string as shown to a big-endian binary
    hash.'''
    return bytes(reversed(bytes.fromhex(x)))

class InvalidBase58String(Exception):
    pass


class InvalidBase58CheckSum(Exception):
    pass


class Base58(object):

    chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    assert len(chars) == 58
    cmap = {c: n for n, c in enumerate(chars)}

    @staticmethod
    def char_value(c):
        val = Base58.cmap.get(c)
        if val is None:
            raise InvalidBase58String
        return val

    @staticmethod
    def decode(txt):
        """Decodes txt into a big-endian bytearray."""
        if not isinstance(txt, str):
            raise InvalidBase58String("a string is required")

        if not txt:
            raise InvalidBase58String("string cannot be empty")

        value = 0
        for c in txt:
            value = value * 58 + Base58.char_value(c)

        result = int_to_bytes(value)

        # Prepend leading zero bytes if necessary
        count = 0
        for c in txt:
            if c != '1':
                break
            count += 1
        if count:
            result = bytes(count) + result

        return result

    @staticmethod
    def encode(be_bytes):
        """Converts a big-endian bytearray into a base58 string."""
        value = bytes_to_int(be_bytes)

        txt = ''
        while value:
            value, mod = divmod(value, 58)
            txt += Base58.chars[mod]

        for byte in be_bytes:
            if byte != 0:
                break
            txt += '1'

        return txt[::-1]

    @staticmethod
    def decode_check(txt):
        '''Decodes a Base58Check-encoded string to a payload.  The version
        prefixes it.'''
        be_bytes = Base58.decode(txt)
        result, check = be_bytes[:-4], be_bytes[-4:]
        if check != double_sha256(result)[:4]:
            raise InvalidBase58CheckSum
        return result

    @staticmethod
    def encode_check(payload):
        """Encodes a payload bytearray (which includes the version byte(s))
        into a Base58Check string."""
        assert isinstance(payload, (bytes, bytearray))

        be_bytes = payload + double_sha256(payload)[:4]
        return Base58.encode(be_bytes)
