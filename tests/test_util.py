from lib import util


def test_cachedproperty():
    class Target:
        def __init__(self):
            self.call_count = 0

        @util.cachedproperty
        def prop(self):
            self.call_count += 1
            return self.call_count

    t = Target()
    assert t.prop == t.prop == 1


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


def test_chunks():
    assert list(util.chunks([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]


def test_increment_byte_string():
    assert util.increment_byte_string(b'1') == b'2'
    assert util.increment_byte_string(b'\x01\x01') == b'\x01\x02'
    assert util.increment_byte_string(b'\xff\xff') == b'\x01\x00\x00'
