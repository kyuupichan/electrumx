from lib import util


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


def test_deep_getsizeof():
    int_t = util.deep_getsizeof(1)
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


def test_is_valid_hostname():
    is_valid_hostname = util.is_valid_hostname
    assert not is_valid_hostname('')
    assert is_valid_hostname('a')
    assert is_valid_hostname('_')
    # Hyphens
    assert not is_valid_hostname('-b')
    assert not is_valid_hostname('a.-b')
    assert is_valid_hostname('a-b')
    assert not is_valid_hostname('b-')
    assert not is_valid_hostname('b-.c')
    # Dots
    assert is_valid_hostname('a.')
    assert is_valid_hostname('foo1.Foo')
    assert not is_valid_hostname('foo1..Foo')
    assert is_valid_hostname('12Foo.Bar.Bax_')
    assert is_valid_hostname('12Foo.Bar.Baz_12')
    # 63 octets in part
    assert is_valid_hostname('a.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN'
                             'OPQRSTUVWXYZ0123456789_.bar')
    # Over 63 octets in part
    assert not is_valid_hostname('a.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN'
                                 'OPQRSTUVWXYZ0123456789_1.bar')
    len255 = ('a' * 62 + '.') * 4 + 'abc'
    assert is_valid_hostname(len255)
    assert not is_valid_hostname(len255 + 'd')


def test_protocol_tuple():
    assert util.protocol_tuple(None) == (0, )
    assert util.protocol_tuple("foo") == (0, )
    assert util.protocol_tuple(1) == (0, )
    assert util.protocol_tuple("1") == (1, )
    assert util.protocol_tuple("0.1") == (0, 1)
    assert util.protocol_tuple("0.10") == (0, 10)
    assert util.protocol_tuple("2.5.3") == (2, 5, 3)

def test_protocol_version_string():
    assert util.protocol_version_string(()) == "0.0"
    assert util.protocol_version_string((1, )) == "1.0"
    assert util.protocol_version_string((1, 2)) == "1.2"
    assert util.protocol_version_string((1, 3, 2)) == "1.3.2"

def test_protocol_version():
    assert util.protocol_version(None, "1.0", "1.0") == (1, 0)
    assert util.protocol_version("0.10", "0.10", "1.1") == (0, 10)

    assert util.protocol_version("1.0", "1.0", "1.0") == (1, 0)
    assert util.protocol_version("1.0", "1.0", "1.1") == (1, 0)
    assert util.protocol_version("1.1", "1.0", "1.1") == (1, 1)
    assert util.protocol_version("1.2", "1.0", "1.1") is None
    assert util.protocol_version("0.9", "1.0", "1.1") is None

    assert util.protocol_version(["0.9", "1.0"], "1.0", "1.1") == (1, 0)
    assert util.protocol_version(["0.9", "1.1"], "1.0", "1.1") == (1, 1)
    assert util.protocol_version(["1.1", "0.9"], "1.0", "1.1") is None
    assert util.protocol_version(["0.8", "0.9"], "1.0", "1.1") is None
    assert util.protocol_version(["1.1", "1.2"], "1.0", "1.1") == (1, 1)
    assert util.protocol_version(["1.2", "1.3"], "1.0", "1.1") is None


def test_unpackers():
    b = bytes(range(256))
    assert util.unpack_int32_from(b, 0) == (50462976,)
    assert util.unpack_int32_from(b, 42) == (757869354,)
    assert util.unpack_int64_from(b, 0) == (506097522914230528,)
    assert util.unpack_int64_from(b, 42) == (3544384782113450794,)

    assert util.unpack_uint16_from(b, 0) == (256,)
    assert util.unpack_uint16_from(b, 42) == (11050,)
    assert util.unpack_uint32_from(b, 0) == (50462976,)
    assert util.unpack_uint32_from(b, 42) == (757869354,)
    assert util.unpack_uint64_from(b, 0) == (506097522914230528,)
    assert util.unpack_uint64_from(b, 42) == (3544384782113450794,)

def test_hex_transforms():
    h = "AABBCCDDEEFF"
    assert util.hex_to_bytes(h) == b'\xaa\xbb\xcc\xdd\xee\xff'