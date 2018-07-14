# Copyright (c) 2018, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# and warranty status of this software.

'''Merkle trees, branches, proofs and roots.'''

from math import ceil, log

from electrumx.lib.hash import double_sha256


class Merkle(object):
    '''Perform merkle tree calculations on binary hashes using a given hash
    function.

    If the hash count is not even, the final hash is repeated when
    calculating the next merkle layer up the tree.
    '''

    def __init__(self, hash_func=double_sha256):
        self.hash_func = hash_func

    def tree_depth(self, hash_count):
        return self.branch_length(hash_count) + 1

    def branch_length(self, hash_count):
        '''Return the length of a merkle branch given the number of hashes.'''
        if not isinstance(hash_count, int):
            raise TypeError('hash_count must be an integer')
        if hash_count < 1:
            raise ValueError('hash_count must be at least 1')
        return ceil(log(hash_count, 2))

    def branch(self, hashes, index, length=None):
        '''Return a (merkle branch, merkle_root) pair given hashes, and the
        index of one of those hashes.
        '''
        hashes = list(hashes)
        if not isinstance(index, int):
            raise TypeError('index must be an integer')
        # This also asserts hashes is not empty
        if not 0 <= index < len(hashes):
            raise ValueError('index out of range')
        natural_length = self.branch_length(len(hashes))
        if length is None:
            length = natural_length
        else:
            if not isinstance(length, int):
                raise TypeError('length must be an integer')
            if length < natural_length:
                raise ValueError('length out of range')

        hash_func = self.hash_func
        branch = []
        for _ in range(length):
            if len(hashes) & 1:
                hashes.append(hashes[-1])
            branch.append(hashes[index ^ 1])
            index >>= 1
            hashes = [hash_func(hashes[n] + hashes[n + 1])
                      for n in range(0, len(hashes), 2)]

        return branch, hashes[0]

    def root(self, hashes, length=None):
        '''Return the merkle root of a non-empty iterable of binary hashes.'''
        branch, root = self.branch(hashes, 0, length)
        return root

    def root_from_proof(self, hash, branch, index):
        '''Return the merkle root given a hash, a merkle branch to it, and
        its index in the hashes array.

        branch is an iterable sorted deepest to shallowest.  If the
        returned root is the expected value then the merkle proof is
        verified.

        The caller should have confirmed the length of the branch with
        branch_length().  Unfortunately this is not easily done for
        bitcoin transactions as the number of transactions in a block
        is unknown to an SPV client.
        '''
        hash_func = self.hash_func
        for elt in branch:
            if index & 1:
                hash = hash_func(elt + hash)
            else:
                hash = hash_func(hash + elt)
            index >>= 1
        if index:
            raise ValueError('index out of range for branch')
        return hash

    def level(self, hashes, depth_higher):
        '''Return a level of the merkle tree of hashes the given depth
        higher than the bottom row of the original tree.'''
        size = 1 << depth_higher
        root = self.root
        return [root(hashes[n: n + size], depth_higher)
                for n in range(0, len(hashes), size)]

    def branch_from_level(self, level, leaf_hashes, index, depth_higher):
        '''Return a (merkle branch, merkle_root) pair when a merkle-tree has a
        level cached.

        To maximally reduce the amount of data hashed in computing a
        markle branch, cache a tree of depth N at level N // 2.

        level is a list of hashes in the middle of the tree (returned
        by level())

        leaf_hashes are the leaves needed to calculate a partial branch
        up to level.

        depth_higher is how much higher level is than the leaves of the tree

        index is the index in the full list of hashes of the hash whose
        merkle branch we want.
        '''
        if not isinstance(level, list):
            raise TypeError("level must be a list")
        if not isinstance(leaf_hashes, list):
            raise TypeError("level must be a list")
        leaf_index = (index >> depth_higher) << depth_higher
        leaf_branch, leaf_root = self.branch(leaf_hashes, index - leaf_index,
                                             depth_higher)
        index >>= depth_higher
        level_branch, root = self.branch(level, index)
        # Check last so that we know index is in-range
        if leaf_root != level[index]:
            raise ValueError('leaf hashes inconsistent with level')
        return leaf_branch + level_branch, root
