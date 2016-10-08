# See the file "LICENSE" for information about the copyright
# and warranty status of this software.


import sys


class Log(object):
    '''Logging base class'''

    VERBOSE = True

    def diagnostic_name(self):
        return self.__class__.__name__

    def log(self, *msgs):
        if Log.VERBOSE:
            print('[{}]: '.format(self.diagnostic_name()), *msgs,
                  file=sys.stdout, flush=True)

    def log_error(self, *msg):
        print('[{}]: ERROR: {}'.format(self.diagnostic_name()), *msgs,
              file=sys.stderr, flush=True)


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
