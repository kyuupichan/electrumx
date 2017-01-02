# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Miscellaneous utility classes and functions.'''


import array
import asyncio
import inspect
import logging
import sys
from collections import Container, Mapping


class LoggedClass(object):

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
        self.log_prefix = ''
        self.throttled = 0

    def log_info(self, msg, throttle=False):
        # Prevent annoying log messages by throttling them if there
        # are too many in a short period
        if throttle:
            self.throttled += 1
            if self.throttled > 3:
                return
            if self.throttled == 3:
                msg += ' (throttling later logs)'
        self.logger.info(self.log_prefix + msg)

    def log_warning(self, msg):
        self.logger.warning(self.log_prefix + msg)

    def log_error(self, msg):
        self.logger.error(self.log_prefix + msg)


# Method decorator.  To be used for calculations that will always
# deliver the same result.  The method cannot take any arguments
# and should be accessed as an attribute.
class cachedproperty(object):

    def __init__(self, f):
        self.f = f

    def __get__(self, obj, type):
        obj = obj or type
        value = self.f(obj)
        setattr(obj, self.f.__name__, value)
        return value


def formatted_time(t):
    '''Return a number of seconds as a string in days, hours, mins and
    secs.'''
    t = int(t)
    return '{:d}d {:02d}h {:02d}m {:02d}s'.format(
        t // 86400, (t % 86400) // 3600, (t % 3600) // 60, t % 60)


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

def subclasses(base_class, strict=True):
    '''Return a list of subclasses of base_class in its module.'''
    def select(obj):
        return (inspect.isclass(obj) and issubclass(obj, base_class)
                and (not strict or obj != base_class))

    pairs = inspect.getmembers(sys.modules[base_class.__module__], select)
    return [pair[1] for pair in pairs]


def chunks(items, size):
    '''Break up items, an iterable, into chunks of length size.'''
    for i in range(0, len(items), size):
        yield items[i: i + size]


def bytes_to_int(be_bytes):
    '''Interprets a big-endian sequence of bytes as an integer'''
    return int.from_bytes(be_bytes, 'big')


def int_to_bytes(value):
    '''Converts an integer to a big-endian sequence of bytes'''
    return value.to_bytes((value.bit_length() + 7) // 8, 'big')


def increment_byte_string(bs):
    bs = bytearray(bs)
    incremented = False
    for i in reversed(range(len(bs))):
        if bs[i] < 0xff:
            # This is easy
            bs[i] += 1
            incremented = True
            break
        # Otherwise we need to look at the previous character
        bs[i] = 0
    if not incremented:
        # This can only happen if all characters are 0xff
        bs = bytes([1]) + bs
    return bytes(bs)


class LogicalFile(object):
    '''A logical binary file split across several separate files on disk.'''

    def __init__(self, prefix, digits, file_size):
        digit_fmt = '{' + ':0{:d}d'.format(digits) + '}'
        self.filename_fmt = prefix + digit_fmt
        self.file_size = file_size

    def read(self, start, size=-1):
        '''Read up to size bytes from the virtual file, starting at offset
        start, and return them.

        If size is -1 all bytes are read.'''
        parts = []
        while size != 0:
            try:
                with self.open_file(start, False) as f:
                    part = f.read(size)
                if not part:
                    break
            except FileNotFoundError:
                break
            parts.append(part)
            start += len(part)
            if size > 0:
                size -= len(part)
        return b''.join(parts)

    def write(self, start, b):
        '''Write the bytes-like object, b, to the underlying virtual file.'''
        while b:
            size = min(len(b), self.file_size - (start % self.file_size))
            with self.open_file(start, True) as f:
                f.write(b if size == len(b) else b[:size])
            b = b[size:]
            start += size

    def open_file(self, start, create):
        '''Open the virtual file and seek to start.  Return a file handle.
        Raise FileNotFoundError if the file does not exist and create
        is False.
        '''
        file_num, offset = divmod(start, self.file_size)
        filename = self.filename_fmt.format(file_num)
        try:
            f= open(filename, 'rb+')
        except FileNotFoundError:
            if not create:
                raise
            f = open(filename, 'wb+')
        f.seek(offset)
        return f
