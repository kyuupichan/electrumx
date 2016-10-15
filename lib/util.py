# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import array
import sys
from collections import Container, Mapping


# Method decorator.  To be used for calculations that will always
# deliver the same result.  The method cannot take any arguments
# and should be accessed as an attribute.
class cachedproperty(object):

    def __init__(self, f):
        self.f = f

    def __get__(self, obj, type):
        if obj is None:
            return self
        value = self.f(obj)
        obj.__dict__[self.f.__name__] = value
        return value

    def __set__(self, obj, value):
        raise AttributeError('cannot set {} on {}'
                             .format(self.f.__name__, obj))


def deep_getsizeof(obj):
    """Find the memory footprint of a Python object.

    Based on code from code.tutsplus.com: http://goo.gl/fZ0DXK

    This is a recursive function that drills down a Python object graph
    like a dictionary holding nested dictionaries with lists of lists
    and tuples and sets.

    The sys.getsizeof function does a shallow size of only. It counts each
    object inside a container as pointer only regardless of how big it
    really is.
    """

    ids = set()

    def size(o):
        if id(o) in ids:
            return 0

        r = sys.getsizeof(o)
        ids.add(id(o))

        if isinstance(o, (str, bytes, bytearray, array.array)):
            return r

        if isinstance(o, Mapping):
            return r + sum(size(k) + size(v) for k, v in o.items())

        if isinstance(o, Container):
            return r + sum(size(x) for x in o)

        return r

    return size(obj)


def chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i: i + size]


def bytes_to_int(be_bytes):
    '''Interprets a big-endian sequence of bytes as an integer'''
    assert isinstance(be_bytes, (bytes, bytearray))
    value = 0
    for byte in be_bytes:
        value = value * 256 + byte
    return value


def int_to_bytes(value):
    '''Converts an integer to a big-endian sequence of bytes'''
    mods = []
    while value:
        value, mod = divmod(value, 256)
        mods.append(mod)
    return bytes(reversed(mods))
