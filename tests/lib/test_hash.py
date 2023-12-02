#
# Tests of lib/hash.py
#
from functools import partial

import pytest

import electrumx.lib.hash as lib_hash


def test_sha256():
    assert lib_hash.sha256(b'sha256') == b'][\t\xf6\xdc\xb2\xd5:_\xff\xc6\x0cJ\xc0\xd5_\xab\xdfU`i\xd6c\x15E\xf4*\xa6\xe3P\x0f.'
    with pytest.raises(TypeError):
        lib_hash.sha256('sha256')

def test_double_sha256():
    assert lib_hash.double_sha256(b'double_sha256') == b'ksn\x8e\xb7\xb9\x0f\xf6\xd9\xad\x88\xd9#\xa1\xbcU(j1Bx\xce\xd5;s\xectL\xe7\xc5\xb4\x00'

def test_hash_to_hex_str():
    assert lib_hash.hash_to_hex_str(b'hash_to_str') == '7274735f6f745f68736168'

def test_hex_str_to_hash():
    assert lib_hash.hex_str_to_hash('7274735f6f745f68736168') == b'hash_to_str'

def test_Base58_char_value():
    chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    for value, c in enumerate(chars):
        assert lib_hash.Base58.char_value(c) == value
    for c in (' ', 'I', '0', 'l', 'O'):
        with pytest.raises(lib_hash.Base58Error):
            lib_hash.Base58.char_value(c)

def test_Base58_decode():
    with pytest.raises(TypeError):
        lib_hash.Base58.decode(b'foo')
    with pytest.raises(lib_hash.Base58Error):
        lib_hash.Base58.decode('')
    assert lib_hash.Base58.decode('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz') == b'\x00\x01\x11\xd3\x8e_\xc9\x07\x1f\xfc\xd2\x0bJv<\xc9\xaeO%+\xb4\xe4\x8f\xd6j\x83^%*\xda\x93\xffH\rm\xd4=\xc6*d\x11U\xa5'
    assert lib_hash.Base58.decode('3i37NcgooY8f1S') == b'0123456789'

def test_Base58_encode():
    with pytest.raises(TypeError):
        lib_hash.Base58.encode('foo')
    assert lib_hash.Base58.encode(b'') == ''
    assert lib_hash.Base58.encode(b'\0') == '1'
    assert lib_hash.Base58.encode(b'0123456789') == '3i37NcgooY8f1S'

def test_Base58_decode_check():
    with pytest.raises(TypeError):
        lib_hash.Base58.decode_check(b'foo')
    assert lib_hash.Base58.decode_check('4t9WKfuAB8') == b'foo'
    with pytest.raises(lib_hash.Base58Error):
        lib_hash.Base58.decode_check('4t9WKfuAB9')

def test_Base58_encode_check():
    with pytest.raises(TypeError):
        lib_hash.Base58.encode_check('foo')
    assert lib_hash.Base58.encode_check(b'foo') == '4t9WKfuAB8'

def test_Base58_decode_check_custom():
    decode_check_sha256 = partial(lib_hash.Base58.decode_check,
                                  hash_fn=lib_hash.sha256)
    with pytest.raises(TypeError):
        decode_check_sha256(b'foo')
    assert decode_check_sha256('4t9WFhKfWr') == b'foo'
    with pytest.raises(lib_hash.Base58Error):
        decode_check_sha256('4t9WFhKfWp')

def test_Base58_encode_check_custom():
    encode_check_sha256 = partial(lib_hash.Base58.encode_check,
                                  hash_fn=lib_hash.sha256)
    with pytest.raises(TypeError):
        encode_check_sha256('foo')
    assert encode_check_sha256(b'foo') == '4t9WFhKfWr'
