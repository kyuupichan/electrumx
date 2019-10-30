import os

import pytest

from electrumx.lib import util, tx


def test_cachedproperty():
    class Target:

        CALL_COUNT = 0

        def __init__(self):
            self.call_count = 0

        @util.cachedproperty
        def prop(self):
            self.call_count += 1
            return self.call_count

        @util.cachedproperty
        def cls_prop(cls):
            cls.CALL_COUNT += 1
            return cls.CALL_COUNT

    t = Target()
    assert t.prop == t.prop == 1
    assert Target.cls_prop == Target.cls_prop == 1

def test_formatted_time():
    assert util.formatted_time(0) == '00s'
    assert util.formatted_time(59) == '59s'
    assert util.formatted_time(60) == '01m 00s'
    assert util.formatted_time(3599) == '59m 59s'
    assert util.formatted_time(3600) == '01h 00m 00s'
    assert util.formatted_time(3600*24) == '1d 00h 00m'
    assert util.formatted_time(3600*24*367) == '367d 00h 00m'
    assert util.formatted_time(3600*24, ':') == '1d:00h:00m'

def test_deep_getsizeof():
    int_t = util.deep_getsizeof(1)
    assert util.deep_getsizeof('foo') == util.deep_getsizeof('') + 3
    assert util.deep_getsizeof([1, 1]) > 2 * int_t
    assert util.deep_getsizeof({1: 1}) > 2 * int_t
    assert util.deep_getsizeof({1: {1: 1}}) > 3 * int_t


class Base:
    pass


class A(Base):
    pass


class B(Base):
    pass


def test_subclasses():
    assert util.subclasses(Base) == [A, B]
    assert util.subclasses(Base, strict=False) == [A, B, Base]


def test_chunks():
    assert list(util.chunks([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]


def test_increment_byte_string():
    assert util.increment_byte_string(b'1') == b'2'
    assert util.increment_byte_string(b'\x01\x01') == b'\x01\x02'
    assert util.increment_byte_string(b'\xff\xff') is None


def test_bytes_to_int():
    assert util.bytes_to_int(b'\x07[\xcd\x15') == 123456789


def test_int_to_bytes():
    assert util.int_to_bytes(456789) == b'\x06\xf8U'


def test_LogicalFile(tmpdir):
    prefix = os.path.join(tmpdir, 'log')
    L = util.LogicalFile(prefix, 2, 6)
    with pytest.raises(FileNotFoundError):
        L.open_file(0, create=False)

    # Check L.open creates a file
    with L.open_file(8, create=True) as f:
        pass
    with util.open_file(prefix + '01') as f:
        pass

    L.write(0, b'987')
    assert L.read(0, -1) == b'987'
    assert L.read(0, 4) == b'987'
    assert L.read(1, 1) == b'8'

    L.write(0, b'01234567890')
    assert L.read(0, -1) == b'01234567890'
    assert L.read(5, -1) == b'567890'
    with util.open_file(prefix + '01') as f:
        assert f.read(-1) == b'67890'

    # Test file boundary
    L.write(0, b'957' * 6)
    assert L.read(0, -1) == b'957' * 6

def test_open_fns(tmpdir):
    tmpfile = os.path.join(tmpdir, 'file1')
    with pytest.raises(FileNotFoundError):
        util.open_file(tmpfile)
    with util.open_file(tmpfile, create=True) as f:
        f.write(b'56')
    with util.open_file(tmpfile) as f:
        assert f.read(3) == b'56'

    # Test open_truncate truncates and creates
    with util.open_truncate(tmpfile) as f:
        assert f.read(3) == b''
    tmpfile = os.path.join(tmpdir, 'file2')
    with util.open_truncate(tmpfile) as f:
        assert f.read(3) == b''

def test_address_string():
    assert util.address_string(('foo.bar', 84)) == 'foo.bar:84'
    assert util.address_string(('1.2.3.4', 84)) == '1.2.3.4:84'
    assert util.address_string(('0a::23', 84)) == '[a::23]:84'

def test_protocol_tuple():
    assert util.protocol_tuple(None) == (0, )
    assert util.protocol_tuple("foo") == (0, )
    assert util.protocol_tuple(1) == (0, )
    assert util.protocol_tuple("1") == (1, )
    assert util.protocol_tuple("0.1") == (0, 1)
    assert util.protocol_tuple("0.10") == (0, 10)
    assert util.protocol_tuple("2.5.3") == (2, 5, 3)

def test_version_string():
    assert util.version_string(()) == "0.0"
    assert util.version_string((1, )) == "1.0"
    assert util.version_string((1, 2)) == "1.2"
    assert util.version_string((1, 3, 2)) == "1.3.2"

def test_protocol_version():
    assert util.protocol_version(None, (1, 0), (1, 0)) == ((1, 0), (1, 0))
    assert util.protocol_version("0.10", (0, 1), (1, 1)) == ((0, 10), (0, 10))

    assert util.protocol_version("1.0", (1, 0), (1, 0)) == ((1, 0), (1, 0))
    assert util.protocol_version("1.0", (1, 0), (1, 1)) == ((1, 0), (1, 0))
    assert util.protocol_version("1.1", (1, 0), (1, 1)) == ((1, 1), (1, 1))
    assert util.protocol_version("1.2", (1, 0), (1, 1)) == (None, (1, 2))
    assert util.protocol_version("0.9", (1, 0), (1, 1)) == (None, (0, 9))

    assert util.protocol_version(["0.9", "1.0"], (1, 0), (1, 1)) \
                                                         == ((1, 0), (0, 9))
    assert util.protocol_version(["0.9", "1.1"], (1, 0), (1, 1)) \
                                                         == ((1, 1), (0,9))
    assert util.protocol_version(["1.1", "0.9"], (1, 0), (1, 1)) \
                                                         == (None, (1, 1))
    assert util.protocol_version(["0.8", "0.9"], (1, 0), (1, 1)) \
                                                         == (None, (0, 8))
    assert util.protocol_version(["1.1", "1.2"], (1, 0), (1, 1)) \
                                                         == ((1, 1), (1, 1))
    assert util.protocol_version(["1.2", "1.3"], (1, 0), (1, 1)) \
                                                         == (None, (1, 2))


def test_unpackers():
    b = bytes(range(256))
    assert util.unpack_le_int32_from(b, 0) == (50462976,)
    assert util.unpack_le_int32_from(b, 42) == (757869354,)
    assert util.unpack_le_int64_from(b, 0) == (506097522914230528,)
    assert util.unpack_le_int64_from(b, 42) == (3544384782113450794,)

    assert util.unpack_le_uint16_from(b, 0) == (256,)
    assert util.unpack_le_uint16_from(b, 42) == (11050,)
    assert util.unpack_le_uint32_from(b, 0) == (50462976,)
    assert util.unpack_le_uint32_from(b, 42) == (757869354,)
    assert util.unpack_le_uint64_from(b, 0) == (506097522914230528,)
    assert util.unpack_le_uint64_from(b, 42) == (3544384782113450794,)

def test_hex_transforms():
    h = "AABBCCDDEEFF"
    assert util.hex_to_bytes(h) == b'\xaa\xbb\xcc\xdd\xee\xff'


def test_pack_varint():
    tests = list(range(0, 258))
    tests.extend([1024, 65535, 65536, 4294967295, 4294967296, 8294967296])

    for n in tests:
        data = util.pack_varint(n)
        deser = tx.Deserializer(data)
        assert deser._read_varint() == n

    import struct
    with pytest.raises(struct.error):
        util.pack_varint(-1)
    assert util.pack_varint(0) == b'\0'
    assert util.pack_varint(5) == b'\5'
    assert util.pack_varint(252) == b'\xfc'
    assert util.pack_varint(253) == b'\xfd\xfd\0'
    assert util.pack_varint(65535) == b'\xfd\xff\xff'
    assert util.pack_varint(65536) == b'\xfe\0\0\1\0'
    assert util.pack_varint(2**32-1) == b'\xfe\xff\xff\xff\xff'
    assert util.pack_varint(2**32) == b'\xff\0\0\0\0\1\0\0\0'
    assert util.pack_varint(2**64-1) \
           == b'\xff\xff\xff\xff\xff\xff\xff\xff\xff'

def test_pack_varbytes():
    tests = [b'', b'1', b'2' * 253, b'3' * 254, b'4' * 256, b'5' * 65536]

    for test in tests:
        data = util.pack_varbytes(test)
        deser = tx.Deserializer(data)
        assert deser._read_varbytes() == test
