import pytest

from electrumx.lib.merkle import Merkle


Merkle = Merkle()
hashes = [Merkle.hash_func(bytes([x])) for x in range(8)]
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
    assert Merkle.branch_length(1) == 0
    assert Merkle.branch_length(2) == 1
    for n in range(3, 5):
        assert Merkle.branch_length(n) == 2
    for n in range(5, 9):
        assert Merkle.branch_length(n) == 3


def test_branch_length_bad():
    with pytest.raises(TypeError):
        Merkle.branch_length(1.0)
    for n in (-1, 0):
        with pytest.raises(ValueError):
            Merkle.branch_length(n)


def test_tree_depth():
    for n in range(1, 10):
        assert Merkle.tree_depth(n) == Merkle.branch_length(n) + 1


def test_root():
    for n in range(len(hashes)):
        assert Merkle.root(hashes[:n + 1]) == roots[n]


def test_root_bad():
    with pytest.raises(TypeError):
        Merkle.root(0)
    with pytest.raises(ValueError):
        Merkle.root([])


def test_branch_and_root_from_proof():
    for n in range(len(hashes)):
        for m in range(n + 1):
            branch, root = Merkle.branch(hashes[:n + 1], m)
            assert root == roots[n]
            root = Merkle.root_from_proof(hashes[m], branch, m)
            assert root == roots[n]


def test_branch_bad():
    with pytest.raises(TypeError):
        Merkle.branch(0, 0)
    with pytest.raises(ValueError):
        Merkle.branch([], 0)
    with pytest.raises(TypeError):
        Merkle.branch(hashes, 0.0)
    with pytest.raises(ValueError):
        Merkle.branch(hashes[:2], -1)
    with pytest.raises(ValueError):
        Merkle.branch(hashes[:2], 2)
    Merkle.branch(hashes, 0, 3)
    with pytest.raises(TypeError):
        Merkle.branch(hashes, 0, 3.0)
    with pytest.raises(ValueError):
        Merkle.branch(hashes, 0, 2)


def test_root_from_proof_bad():
    with pytest.raises(TypeError):
        Merkle.root_from_proof(0, hashes[:2], 0)
    with pytest.raises(TypeError):
        Merkle.root_from_proof(hashes[0], hashes[0], 0)
    with pytest.raises(ValueError):
        Merkle.root_from_proof(hashes[0], hashes[:3], -1)
    with pytest.raises(ValueError):
        Merkle.root_from_proof(hashes[0], hashes[:3], 8)


def test_level():
    for n in range(len(hashes)):
        depth = Merkle.tree_depth(n + 1)
        for depth_higher in range(0, depth):
            level = Merkle.level(hashes[:n + 1], depth_higher)
            if depth_higher == 0:
                assert level == hashes[:n + 1]
            if depth_higher == depth:
                assert level == [roots[n]]
            # Check raising from level to root works
            assert Merkle.root(level) == roots[n]


def test_branch_from_level():
    # For all sub-trees
    for n in range(0, len(hashes)):
        part = hashes[:n + 1]
        # For all depths in sub-tree
        for depth_higher in range(0, Merkle.tree_depth(len(part))):
            level = Merkle.level(part, depth_higher)
            # For each hash in sub-tree
            for index, hash in enumerate(part):
                leaf_index = (index >> depth_higher) << depth_higher
                leaf_hashes = part[leaf_index:
                                   leaf_index + (1 << depth_higher)]
                branch = Merkle.branch(part, index)
                branch2 = Merkle.branch_from_level(level, leaf_hashes,
                                                   index, depth_higher)
                assert branch == branch2


def test_branch_from_level_bad():
    with pytest.raises(TypeError):
        Merkle.branch_from_level(hashes[0], hashes, 0, 0)
    with pytest.raises(TypeError):
        Merkle.branch_from_level(hashes, hashes[0], 0, 0)
    Merkle.branch_from_level(hashes, [hashes[0]], 0, 0)
    with pytest.raises(ValueError):
        Merkle.branch_from_level(hashes, [hashes[0]], -1, 0)
    with pytest.raises(TypeError):
        Merkle.branch_from_level(hashes, hashes, 0.0, 0)
    with pytest.raises(ValueError):
        Merkle.branch_from_level(hashes, [hashes[0]], 0, -1)
    with pytest.raises(ValueError):
        Merkle.branch_from_level(hashes, [hashes[0]], 0, 1)
    with pytest.raises(ValueError):
        # Inconsistent hash
        Merkle.branch_from_level(hashes, [hashes[1]], 0, 0)
    with pytest.raises(ValueError):
        # Inconsistent hash
        Merkle.branch_from_level(hashes, [hashes[0]], 1, 0)
