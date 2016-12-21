# Copyright (c) 2016, the ElectrumX authors
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Backend database abstraction.

The abstraction needs to be improved to not heavily penalise LMDB.
'''

import os
from functools import partial

from lib.util import subclasses, increment_byte_string


def open_db(name, db_engine, for_sync):
    '''Returns a database handle.'''
    for db_class in subclasses(Storage):
        if db_class.__name__.lower() == db_engine.lower():
            db_class.import_module()
            return db_class(name, for_sync)

    raise RuntimeError('unrecognised DB engine "{}"'.format(db_engine))


class Storage(object):
    '''Abstract base class of the DB backend abstraction.'''

    def __init__(self, name, for_sync):
        self.is_new = not os.path.exists(name)
        self.open(name, create=self.is_new, for_sync=for_sync)

    @classmethod
    def import_module(cls):
        '''Import the DB engine module.'''
        raise NotImplementedError

    def open(self, name, create):
        '''Open an existing database or create a new one.'''
        raise NotImplementedError

    def close(self):
        '''Close an existing database.'''
        raise NotImplementedError

    def get(self, key):
        raise NotImplementedError

    def put(self, key, value):
        raise NotImplementedError

    def write_batch(self):
        '''Return a context manager that provides `put` and `delete`.

        Changes should only be committed when the context manager
        closes without an exception.
        '''
        raise NotImplementedError

    def iterator(self, prefix=b'', reverse=False):
        '''Return an iterator that yields (key, value) pairs from the
        database sorted by key.

        If `prefix` is set, only keys starting with `prefix` will be
        included.  If `reverse` is True the items are returned in
        reverse order.
        '''
        raise NotImplementedError


class LevelDB(Storage):
    '''LevelDB database engine.'''

    @classmethod
    def import_module(cls):
        import plyvel
        cls.module = plyvel

    def open(self, name, create, for_sync):
        mof = 1024 if for_sync else 256
        self.db = self.module.DB(name, create_if_missing=create,
                                 max_open_files=mof, compression=None)
        self.close = self.db.close
        self.get = self.db.get
        self.put = self.db.put
        self.iterator = self.db.iterator
        self.write_batch = partial(self.db.write_batch, transaction=True,
                                   sync=True)


class RocksDB(Storage):
    '''RocksDB database engine.'''

    @classmethod
    def import_module(cls):
        import rocksdb
        cls.module = rocksdb

    def open(self, name, create, for_sync):
        mof = 1024 if for_sync else 256
        compression = "no"
        compression = getattr(self.module.CompressionType,
                              compression + "_compression")
        options = self.module.Options(create_if_missing=create,
                                      compression=compression,
                                      use_fsync=True,
                                      target_file_size_base=33554432,
                                      max_open_files=mof)
        self.db = self.module.DB(name, options)
        self.get = self.db.get
        self.put = self.db.put

    def close(self):
        # PyRocksDB doesn't provide a close method; hopefully this is enough
        self.db = self.get = self.put = None
        import gc
        gc.collect()

    class WriteBatch(object):
        def __init__(self, db):
            self.batch = RocksDB.module.WriteBatch()
            self.db = db

        def __enter__(self):
            return self.batch

        def __exit__(self, exc_type, exc_val, exc_tb):
            if not exc_val:
                self.db.write(self.batch)

    def write_batch(self):
        return RocksDB.WriteBatch(self.db)

    class Iterator(object):
        def __init__(self, db, prefix, reverse):
            self.it = db.iteritems()
            self.reverse = reverse
            self.prefix = prefix
            # Whether we are at the first item
            self.first = True

        def __iter__(self):
            prefix = self.prefix
            if self.reverse:
                prefix = increment_byte_string(prefix)
                self.it = reversed(self.it)
            self.it.seek(prefix)
            return self

        def __next__(self):
            k, v = self.it.__next__()
            if self.first and self.reverse and not k.startswith(self.prefix):
                k, v = self.it.__next__()
            self.first = False
            if not k.startswith(self.prefix):
                # We're already ahead of the prefix
                raise StopIteration
            return k, v

    def iterator(self, prefix=b'', reverse=False):
        return RocksDB.Iterator(self.db, prefix, reverse)


class LMDB(Storage):
    '''RocksDB database engine.'''

    @classmethod
    def import_module(cls):
        import lmdb
        cls.module = lmdb

    def open(self, name, create, for_sync):
        # I don't see anything equivalent to max_open_files for for_sync
        self.env = LMDB.module.Environment('.', subdir=True, create=create,
                                          max_dbs=32, map_size=5 * 10 ** 10)
        self.db = self.env.open_db(create=create)

    def close(self):
        self.env.close()

    def get(self, key):
        with self.env.begin(db=self.db) as tx:
            return tx.get(key)

    def put(self, key, value):
        with self.env.begin(db=self.db, write=True) as tx:
            tx.put(key, value)

    def write_batch(self):
        return self.env.begin(db=self.db, write=True)

    def iterator(self, prefix=b'', reverse=False):
        return LMDB.Iterator(self.db, self.env, prefix, reverse)

    class Iterator:
        def __init__(self, db, env, prefix, reverse):
            self.transaction = env.begin(db=db)
            self.transaction.__enter__()
            self.db = db
            self.prefix = prefix
            self.reverse = reverse
            self._stop = False

        def __iter__(self):
            self.iterator = LMDB.module.Cursor(self.db, self.transaction)
            prefix = self.prefix
            if self.reverse:
                # Go to the first value after the prefix
                prefix = increment_byte_string(prefix)
            self.iterator.set_range(prefix)
            if not self.iterator.key().startswith(self.prefix) and self.reverse:
                # Go back to the first item starting with the prefix
                self.iterator.prev()
            return self

        def __next__(self):
            k, v = self.iterator.item()
            if not k.startswith(self.prefix) or self._stop:
                # We're already ahead of the prefix
                self.transaction.__exit__()
                raise StopIteration
            next = self.iterator.next \
                if not self.reverse else self.iterator.prev
            # Stop after the next value if we're at the end of the DB
            self._stop = not next()
            return k, v
