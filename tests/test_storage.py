import gc
import pytest
import os

from server.storage import Storage, open_db
from lib.util import subclasses

# Find out which db engines to test
# Those that are not installed will be skipped
db_engines = []
for c in subclasses(Storage):
    try:
        c.import_module()
    except ImportError:
        db_engines.append(pytest.mark.skip(c.__name__))
    else:
        db_engines.append(c.__name__)


@pytest.fixture(params=db_engines)
def db(tmpdir, request):
    cwd = os.getcwd()
    os.chdir(str(tmpdir))
    db = open_db("db", request.param)
    os.chdir(cwd)
    yield db
    # Make sure all the locks and handles are closed
    del db
    gc.collect()


def test_put_get(db):
    db.put(b"x", b"y")
    assert db.get(b"x") == b"y"


def test_batch(db):
    db.put(b"a", b"1")
    with db.write_batch() as b:
        b.put(b"a", b"2")
        assert db.get(b"a") == b"1"
    assert db.get(b"a") == b"2"


def test_iterator(db):
    """
    The iterator should contain all key/value pairs starting with prefix ordered
    by key.
    """
    for i in range(5):
        db.put(b"abc" + str.encode(str(i)), str.encode(str(i)))
    db.put(b"abc", b"")
    db.put(b"a", b"xyz")
    db.put(b"abd", b"x")
    assert list(db.iterator(prefix=b"abc")) == [(b"abc", b"")] + [
            (b"abc" + str.encode(str(i)), str.encode(str(i))) for
            i in range(5)
        ]


def test_iterator_reverse(db):
    for i in range(5):
        db.put(b"abc" + str.encode(str(i)), str.encode(str(i)))
    db.put(b"a", b"xyz")
    db.put(b"abd", b"x")
    assert list(db.iterator(prefix=b"abc", reverse=True)) == [
            (b"abc" + str.encode(str(i)), str.encode(str(i))) for
            i in reversed(range(5))
        ]