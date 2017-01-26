# Copyright (c) 2016-2017, Neil Booth
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

'''Transaction-related classes and functions.'''


from collections import namedtuple
from struct import unpack_from

from lib.util import cachedproperty
from lib.hash import double_sha256, hash_to_str


class Tx(namedtuple("Tx", "version inputs outputs locktime")):
    '''Class representing a transaction.'''

    @cachedproperty
    def is_coinbase(self):
        return self.inputs[0].is_coinbase

    # FIXME: add hash as a cached property?

class TxInput(namedtuple("TxInput", "prev_hash prev_idx script sequence")):
    '''Class representing a transaction input.'''

    ZERO = bytes(32)
    MINUS_1 = 4294967295

    @cachedproperty
    def is_coinbase(self):
        return (self.prev_hash == TxInput.ZERO
                and self.prev_idx == TxInput.MINUS_1)

    @cachedproperty
    def script_sig_info(self):
        # No meaning for coinbases
        if self.is_coinbase:
            return None
        return Script.parse_script_sig(self.script)

    def __str__(self):
        script = self.script.hex()
        prev_hash = hash_to_str(self.prev_hash)
        return ("Input({}, {:d}, script={}, sequence={:d})"
                .format(prev_hash, self.prev_idx, script, self.sequence))


class TxOutput(namedtuple("TxOutput", "value pk_script")):
    '''Class representing a transaction output.'''

    @cachedproperty
    def pay_to(self):
        return Script.parse_pk_script(self.pk_script)


class Deserializer(object):
    '''Deserializes blocks into transactions.

    External entry points are read_tx() and read_block().

    This code is performance sensitive as it is executed 100s of
    millions of times during sync.
    '''

    def __init__(self, binary):
        assert isinstance(binary, bytes)
        self.binary = binary
        self.cursor = 0

    def read_tx(self):
        '''Return a (Deserialized TX, TX_HASH) pair.

        The hash needs to be reversed for human display; for efficiency
        we process it in the natural serialized order.
        '''
        start = self.cursor
        return Tx(
            self._read_le_int32(),  # version
            self._read_inputs(),    # inputs
            self._read_outputs(),   # outputs
            self._read_le_uint32()  # locktime
        ), double_sha256(self.binary[start:self.cursor])

    def read_block(self):
        '''Returns a list of (deserialized_tx, tx_hash) pairs.'''
        read_tx = self.read_tx
        txs = [read_tx() for n in range(self._read_varint())]
        assert self.cursor == len(self.binary)
        return txs

    def _read_inputs(self):
        read_input = self._read_input
        return [read_input() for i in range(self._read_varint())]

    def _read_input(self):
        return TxInput(
            self._read_nbytes(32),  # prev_hash
            self._read_le_uint32(), # prev_idx
            self._read_varbytes(),  # script
            self._read_le_uint32()  # sequence
        )

    def _read_outputs(self):
        read_output = self._read_output
        return [read_output() for i in range(self._read_varint())]

    def _read_output(self):
        return TxOutput(
            self._read_le_int64(),  # value
            self._read_varbytes(),  # pk_script
        )

    def _read_nbytes(self, n):
        cursor = self.cursor
        self.cursor = end = cursor + n
        assert len(self.binary) >= end
        return self.binary[cursor:end]

    def _read_varbytes(self):
        return self._read_nbytes(self._read_varint())

    def _read_varint(self):
        n = self.binary[self.cursor]
        self.cursor += 1
        if n < 253:
            return n
        if n == 253:
            return self._read_le_uint16()
        if n == 254:
            return self._read_le_uint32()
        return self._read_le_uint64()

    def _read_le_int32(self):
        result, = unpack_from('<i', self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_int64(self):
        result, = unpack_from('<q', self.binary, self.cursor)
        self.cursor += 8
        return result

    def _read_le_uint16(self):
        result, = unpack_from('<H', self.binary, self.cursor)
        self.cursor += 2
        return result

    def _read_le_uint32(self):
        result, = unpack_from('<I', self.binary, self.cursor)
        self.cursor += 4
        return result

    def _read_le_uint64(self):
        result, = unpack_from('<Q', self.binary, self.cursor)
        self.cursor += 8
        return result


class TxSegWit(namedtuple("Tx", "version marker flag inputs outputs "
                          "witness locktime")):
    '''Class representing a SegWit transaction.'''

    @cachedproperty
    def is_coinbase(self):
        return self.inputs[0].is_coinbase


class DeserializerSegWit(Deserializer):

    # https://bitcoincore.org/en/segwit_wallet_dev/#transaction-serialization

    def _read_byte(self):
        cursor = self.cursor
        self.cursor += 1
        return self.binary[cursor]

    def _read_witness(self, fields):
        read_witness_field = self._read_witness_field
        return [read_witness_field() for i in range(fields)]

    def _read_witness_field(self):
        read_varbytes = self._read_varbytes
        return [read_varbytes() for i in range(self._read_varint())]

    def read_tx(self):
        '''Return a (Deserialized TX, TX_HASH) pair.

        The hash needs to be reversed for human display; for efficiency
        we process it in the natural serialized order.
        '''
        marker = self.binary[self.cursor + 4]
        if marker:
            return super().read_tx()

        # Ugh, this is nasty.
        start = self.cursor
        version = self._read_le_int32()
        orig_ser = self.binary[start:self.cursor]

        marker = self._read_byte()
        flag = self._read_byte()

        start = self.cursor
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        orig_ser += self.binary[start:self.cursor]

        witness = self._read_witness(len(inputs))

        start = self.cursor
        locktime = self._read_le_uint32()
        orig_ser += self.binary[start:self.cursor]

        return TxSegWit(version, marker, flag, inputs,
                        outputs, witness, locktime), double_sha256(orig_ser)
