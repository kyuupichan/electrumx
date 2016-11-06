# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
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
        return Tx(
            self._read_le_int32(),  # version
            self._read_inputs(),    # inputs
            self._read_outputs(),   # outputs
            self._read_le_uint32()  # locktime
        )

    def read_block(self):
        tx_hashes = []
        txs = []
        binary = self.binary
        hash = double_sha256
        read_tx = self.read_tx
        append_hash = tx_hashes.append
        for n in range(self._read_varint()):
            start = self.cursor
            txs.append(read_tx())
            # Note this hash needs to be reversed for human display
            # For efficiency we store it in the natural serialized order
            append_hash(hash(binary[start:self.cursor]))
        assert self.cursor == len(binary)
        return tx_hashes, txs

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
