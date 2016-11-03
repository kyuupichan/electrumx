import os
from functools import partial


class Storage(object):
    def __init__(self, name, create_if_missing=False, error_if_exists=False, compression=None):
        if not create_if_missing and not os.path.exists(name):
            raise NoDatabaseException

    def get(self, key):
        raise NotImplementedError()

    def put(self, key, value):
        raise NotImplementedError()

    def write_batch(self):
        """
        Returns a context manager that provides `put` and `delete`.
        Changes should only be committed when the context manager closes without an exception.
        """
        raise NotImplementedError()

    def iterator(self, prefix=b'', reverse=False):
        """
        Returns an iterator that yields (key, value) pairs from the database sorted by key.
        If `prefix` is set, only keys starting with `prefix` will be included.
        """
        raise NotImplementedError()


class NoDatabaseException(Exception):
    pass


class LevelDB(Storage):
    def __init__(self, name, create_if_missing=False, error_if_exists=False, compression=None):
        super().__init__(name, create_if_missing, error_if_exists, compression)
        import plyvel
        self.db = plyvel.DB(name, create_if_missing=create_if_missing,
                            error_if_exists=error_if_exists, compression=compression)
        self.get = self.db.get
        self.put = self.db.put
        self.iterator = self.db.iterator
        self.write_batch = partial(self.db.write_batch, transaction=True)


class RocksDB(Storage):
    rocksdb = None

    def __init__(self, name, create_if_missing=False, error_if_exists=False, compression=None):
        super().__init__(name, create_if_missing, error_if_exists, compression)
        import rocksdb
        RocksDB.rocksdb = rocksdb
        if not compression:
            compression = "no"
        compression = getattr(rocksdb.CompressionType, compression + "_compression")
        self.db = rocksdb.DB(name, rocksdb.Options(create_if_missing=create_if_missing,
                                                   compression=compression,
                                                   target_file_size_base=33554432,
                                                   max_open_files=1024))
        self.get = self.db.get
        self.put = self.db.put

    class WriteBatch(object):
        def __init__(self, db):
            self.batch = RocksDB.rocksdb.WriteBatch()
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
            if reverse:
                self.it = reversed(self.it)
            self.prefix = prefix

        def __iter__(self):
            self.it.seek(self.prefix)
            return self

        def __next__(self):
            k, v = self.it.__next__()
            if not k.startswith(self.prefix):
                # We're already ahead of the prefix
                raise StopIteration
            return k, v

    def iterator(self, prefix=b'', reverse=False):
        return RocksDB.Iterator(self.db, prefix, reverse)


class LMDB(Storage):
    lmdb = None

    def __init__(self, name, create_if_missing=False, error_if_exists=False, compression=None):
        super().__init__(name, create_if_missing, error_if_exists, compression)
        import lmdb
        LMDB.lmdb = lmdb
        self.env = lmdb.Environment(".", subdir=True, create=create_if_missing, max_dbs=32, map_size=5 * 10 ** 10)
        self.db = self.env.open_db(create=create_if_missing)

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
            self.reverse = reverse   # FIXME

        def __iter__(self):
            self.iterator = LMDB.lmdb.Cursor(self.db, self.transaction)
            self.iterator.set_range(self.prefix)
            return self

        def __next__(self):
            k, v = self.iterator.item()
            if not k.startswith(self.prefix) or not self.iterator.next():
                # We're already ahead of the prefix
                self.transaction.__exit__()
                raise StopIteration
            return k, v
