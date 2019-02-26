import os
import pytest

from electrumx.lib.merkle import Merkle, MerkleCache


merkle = Merkle()
hashes = [merkle.hash_func(bytes([x])) for x in range(8)]
roots = [
    b'\x14\x06\xe0X\x81\xe2\x996wf\xd3\x13\xe2l\x05VN\xc9\x1b\xf7!\xd3\x17&\xbdnF\xe6\x06\x89S\x9a',
    b'K\xbe\x83\xbc8\xeb\xe2\xbc\xc7R\r#A9\xdf\x1c\x0e\xb9\xff\xa5\x1f\x83\xea\xb1\xc5\x12\x9b[\x90kvU',
    b'\xe1)\xdf\xe0/V\x7f\xc6\x12\xd1&YmC@aD\xf4\nw\x18\x10\xacqCB\x1d-\xf3\xe5\xc1\xd0',
    b'\xe3/W\x01\xa0\x11Z+M\xc7/Rj\xf1aLY,\x19\xee\x95\xcf\xcb\x055\x96\x1e\x07g\xba\xf7\x8e',
    b'\xf4\x118I\xd6(\xf7\xc3\xbc\x91\xcc\x0f\xf7\x85\xa6\xae\xe3\xee#l\x1c\x91+(\xcc\t\xc4O\x9f\x97\xb7H',
    b'\xfb[\xb7\xe4\x82Y"\xea\xe8\xc2\xba\xec\x96\x0c\x8fR3\x84R"\x13Jj=\x84\x0e<\x12\x01\xafu\xed',
    b'}\xe6\\}W\xcd\xc7)q\xc9\xbe\xab\x94\xafj\xd4\xe9\x9f#?\xb6\xcc\xeb\xd2\xb4\xb1\x9f\x13i|\xa5M',
    b'o\x97(*\xb3G\xa2e\xae3\x83\xe1V\x9eb\xda\x8c\x19\xa6\x8c\xfag\r+az\x7f\xedGD\xbb\xfe'
]



def test_branch_length():
    assert merkle.branch_length(1) == 0
    assert merkle.branch_length(2) == 1
    for n in range(3, 5):
        assert merkle.branch_length(n) == 2
    for n in range(5, 9):
        assert merkle.branch_length(n) == 3


def test_branch_length_bad():
    with pytest.raises(TypeError):
        merkle.branch_length(1.0)
    for n in (-1, 0):
        with pytest.raises(ValueError):
            merkle.branch_length(n)


def test_tree_depth():
    for n in range(1, 10):
        assert merkle.tree_depth(n) == merkle.branch_length(n) + 1


def test_root():
    for n in range(len(hashes)):
        assert merkle.root(hashes[:n + 1]) == roots[n]


def test_root_bad():
    with pytest.raises(TypeError):
        merkle.root(0)
    with pytest.raises(ValueError):
        merkle.root([])


def test_branch_and_root_from_proof():
    for n in range(len(hashes)):
        for m in range(n + 1):
            branch, root = merkle.branch_and_root(hashes[:n + 1], m)
            assert root == roots[n]
            root = merkle.root_from_proof(hashes[m], branch, m)
            assert root == roots[n]


def test_branch_bad():
    with pytest.raises(TypeError):
        merkle.branch_and_root(0, 0)
    with pytest.raises(ValueError):
        merkle.branch_and_root([], 0)
    with pytest.raises(TypeError):
        merkle.branch_and_root(hashes, 0.0)
    with pytest.raises(ValueError):
        merkle.branch_and_root(hashes[:2], -1)
    with pytest.raises(ValueError):
        merkle.branch_and_root(hashes[:2], 2)
    merkle.branch_and_root(hashes, 0, 3)
    with pytest.raises(TypeError):
        merkle.branch_and_root(hashes, 0, 3.0)
    with pytest.raises(ValueError):
        merkle.branch_and_root(hashes, 0, 2)


def test_root_from_proof_bad():
    with pytest.raises(TypeError):
        merkle.root_from_proof(0, hashes[:2], 0)
    with pytest.raises(TypeError):
        merkle.root_from_proof(hashes[0], hashes[0], 0)
    with pytest.raises(ValueError):
        merkle.root_from_proof(hashes[0], hashes[:3], -1)
    with pytest.raises(ValueError):
        merkle.root_from_proof(hashes[0], hashes[:3], 8)


def test_level():
    for n in range(len(hashes)):
        depth = merkle.tree_depth(n + 1)
        for depth_higher in range(0, depth):
            level = merkle.level(hashes[:n + 1], depth_higher)
            if depth_higher == 0:
                assert level == hashes[:n + 1]
            if depth_higher == depth:
                assert level == [roots[n]]
            # Check raising from level to root works
            assert merkle.root(level) == roots[n]


def test_branch_and_root_from_level():
    # For all sub-trees
    for n in range(0, len(hashes)):
        part = hashes[:n + 1]
        # For all depths in sub-tree
        for depth_higher in range(0, merkle.tree_depth(len(part))):
            level = merkle.level(part, depth_higher)
            # For each hash in sub-tree
            for index, hash in enumerate(part):
                leaf_index = (index >> depth_higher) << depth_higher
                leaf_hashes = part[leaf_index:
                                   leaf_index + (1 << depth_higher)]
                branch = merkle.branch_and_root(part, index)
                branch2 = merkle.branch_and_root_from_level(
                    level, leaf_hashes, index, depth_higher)
                assert branch == branch2


def test_branch_and_root_from_level_bad():
    with pytest.raises(TypeError):
        merkle.branch_and_root_from_level(hashes[0], hashes, 0, 0)
    with pytest.raises(TypeError):
        merkle.branch_and_root_from_level(hashes, hashes[0], 0, 0)
    merkle.branch_and_root_from_level(hashes, [hashes[0]], 0, 0)
    with pytest.raises(ValueError):
        merkle.branch_and_root_from_level(hashes, [hashes[0]], -1, 0)
    with pytest.raises(TypeError):
        merkle.branch_and_root_from_level(hashes, hashes, 0.0, 0)
    with pytest.raises(ValueError):
        merkle.branch_and_root_from_level(hashes, [hashes[0]], 0, -1)
    with pytest.raises(ValueError):
        merkle.branch_and_root_from_level(hashes, [hashes[0]], 0, 1)
    with pytest.raises(ValueError):
        # Inconsistent hash
        merkle.branch_and_root_from_level(hashes, [hashes[1]], 0, 0)
    with pytest.raises(ValueError):
        # Inconsistent hash
        merkle.branch_and_root_from_level(hashes, [hashes[0]], 1, 0)


class Source(object):

    def __init__(self, length):
        self._hashes = [os.urandom(32) for _ in range(length)]

    async def hashes(self, start, count):
        assert start >= 0
        assert start + count <= len(self._hashes)
        return self._hashes[start: start + count]


@pytest.mark.asyncio
async def test_merkle_cache():
    lengths = (*range(1, 18), 31, 32, 33, 57)
    source = Source(max(lengths)).hashes
    for length in lengths:
        cache = MerkleCache(merkle, source)
        await cache.initialize(length)
        # Simulate all possible checkpoints
        for cp_length in range(1, length + 1):
            cp_hashes = await source(0, cp_length)
            # All possible indices
            for index in range(cp_length):
                # Compare correct answer with cache
                branch, root = merkle.branch_and_root(cp_hashes, index)
                branch2, root2 = await cache.branch_and_root(cp_length, index)
                assert branch == branch2
                assert root == root2


@pytest.mark.asyncio
async def test_merkle_cache_extension():
    source = Source(64).hashes
    for length in range(14, 18):
        for cp_length in range(30, 36):
            cache = MerkleCache(merkle, source)
            await cache.initialize(length)
            cp_hashes = await source(0, cp_length)
            # All possible indices
            for index in range(cp_length):
                # Compare correct answer with cache
                branch, root = merkle.branch_and_root(cp_hashes, index)
                branch2, root2 = await cache.branch_and_root(cp_length, index)
                assert branch == branch2
                assert root == root2


@pytest.mark.asyncio
async def test_merkle_cache_truncation():
    max_length = 33
    source = Source(max_length).hashes
    for length in range(max_length - 2, max_length + 1):
        for trunc_length in range(1, 20, 3):
            cache = MerkleCache(merkle, source)
            await cache.initialize(length)
            cache.truncate(trunc_length)
            assert cache.length <= trunc_length
            for cp_length in range(1, length + 1, 3):
                cp_hashes = await source(0, cp_length)
                # All possible indices
                for index in range(cp_length):
                    # Compare correct answer with cache
                    branch, root = merkle.branch_and_root(cp_hashes, index)
                    branch2, root2 = await cache.branch_and_root(cp_length,
                                                                 index)
                    assert branch == branch2
                    assert root == root2

    # Truncation is a no-op if longer
    cache = MerkleCache(merkle, source)
    await cache.initialize(10)
    level = cache.level.copy()
    for length in range(10, 13):
        cache.truncate(length)
        assert cache.level == level
        assert cache.length == 10


@pytest.mark.asyncio
async def test_truncation_bad():
    cache = MerkleCache(merkle, Source(10).hashes)
    await cache.initialize(10)
    with pytest.raises(TypeError):
        cache.truncate(1.0)
    for n in (-1, 0):
        with pytest.raises(ValueError):
            cache.truncate(n)


@pytest.mark.asyncio
async def test_merkle_cache_bad():
    length = 23
    source = Source(length).hashes
    cache = MerkleCache(merkle, source)
    await cache.initialize(length)
    await cache.branch_and_root(5, 3)
    with pytest.raises(TypeError):
        await cache.branch_and_root(5.0, 3)
    with pytest.raises(TypeError):
        await cache.branch_and_root(5, 3.0)
    with pytest.raises(ValueError):
        await cache.branch_and_root(0, -1)
    with pytest.raises(ValueError):
        await cache.branch_and_root(3, 3)


@pytest.mark.asyncio
async def test_bad_extension():
    length = 5
    source = Source(length).hashes
    cache = MerkleCache(merkle, source)
    await cache.initialize(length)
    level = cache.level.copy()
    with pytest.raises(AssertionError):
        await cache.branch_and_root(8, 0)
    # The bad extension should not destroy the cache
    assert cache.level == level
    assert cache.length == length


async def time_it():
    source = Source(500000).hashes
    cp_length = 492000
    import time
    cache = MerkleCache(merkle, source)
    await cache.initialize(cp_length)
    cp_hashes = await source(0, cp_length)
    brs2 = []
    t1 = time.time()
    for index in range(5, 400000, 500):
        brs2.append(await cache.branch_and_root(cp_length, index))
    t2 = time.time()
    print(t2 - t1)
    assert False
