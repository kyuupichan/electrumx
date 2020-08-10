# Copyright (c) 2020, the ElectrumX authors
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

'''Deserializer for Bitgreen Segwit + DIP2 special transaction types'''

import codecs
from collections import namedtuple
from electrumx.lib.tx import DeserializerSegWit
from electrumx.lib.tx_dash import (
    TxOutPoint, DashProRegTx, DashProUpServTx, DashProUpRegTx,
    DashProUpRevTx, DashCbTx, DashSubTxRegister,
    DashSubTxTopup, DashSubTxResetKey, DashSubTxCloseAccount
)
from electrumx.lib.util import (pack_le_uint16, pack_le_int32, pack_le_uint32,
                                pack_varint, pack_varbytes,
                                pack_be_uint16)
from electrumx.lib.hash import hash_to_hex_str


# https://github.com/dashpay/dips/blob/master/dip-0002.md
class BitgreenTx(namedtuple("BitgreenTx",
                        "version inputs outputs witness locktime "
                        "tx_type extra_payload")):
    '''Class representing a Bitgreen transaction'''
    def serialize(self):
        nLocktime = pack_le_uint32(self.locktime)
        txins = (pack_varint(len(self.inputs)) +
                 b''.join(tx_in.serialize() for tx_in in self.inputs))
        txouts = (pack_varint(len(self.outputs)) +
                  b''.join(tx_out.serialize() for tx_out in self.outputs))
        nWitness = pack_varbytes(witness)

        if self.tx_type:
            uVersion = pack_le_uint16(self.version)
            uTxType = pack_le_uint16(self.tx_type)
            vExtra = self._serialize_extra_payload()
            return uVersion + uTxType + txins + txouts + nWitness + nLocktime + vExtra
        else:
            nVersion = pack_le_int32(self.version)
            return nVersion + txins + txouts + nWitness + nLocktime

    def _serialize_extra_payload(self):
        extra = self.extra_payload
        spec_tx_class = DeserializerBitgreen.SPEC_TX_HANDLERS.get(self.tx_type)
        if not spec_tx_class:
            assert isinstance(extra, (bytes, bytearray))
            return pack_varbytes(extra)

        if not isinstance(extra, spec_tx_class):
            raise ValueError('Bitgreen tx_type does not conform with extra'
                             ' payload class: %s, %s' % (self.tx_type, extra))
        return pack_varbytes(extra.serialize())

class DeserializerBitgreen(DeserializerSegWit):
    '''Deserializer for Bitgreen SegWit+DIP2 special tx types'''
    # Supported Spec Tx types and corresponding classes mapping
    CB_TX = 0
    PRO_REG_TX = 2
    PRO_UP_SERV_TX = 3
    PRO_UP_REG_TX = 4
    PRO_UP_REV_TX = 5
    SUB_TX_REGISTER = 8
    SUB_TX_TOPUP = 9
    SUB_TX_RESET_KEY = 10
    SUB_TX_CLOSE_ACCOUNT = 11

    SPEC_TX_HANDLERS = {
        CB_TX: DashCbTx,
        PRO_REG_TX: DashProRegTx,
        PRO_UP_SERV_TX: DashProUpServTx,
        PRO_UP_REG_TX: DashProUpRegTx,
        PRO_UP_REV_TX: DashProUpRevTx,
        SUB_TX_REGISTER: DashSubTxRegister,
        SUB_TX_TOPUP: DashSubTxTopup,
        SUB_TX_RESET_KEY: DashSubTxResetKey,
        SUB_TX_CLOSE_ACCOUNT: DashSubTxCloseAccount,
    }

    def _read_outpoint(self):
        return TxOutPoint.read_outpoint(self)

    def _read_tx_parts(self):
        start = self.cursor

        header = self._read_le_int32()
        version = header & 0xffff
        tx_type = (header >> 16) & 0xffff  # DIP2 tx type
        orig_ser = self.binary[start:self.cursor]

        flag = 0
        start = self.cursor

        # Try to read the vin. In case the dummy is there, this will be read as an empty vector.
        inputs = self._read_inputs()
        outputs = b''
        if len(inputs) == 0:
            flag = self._read_byte()
            if flag != 0:
                start = self.cursor
                inputs = self._read_inputs()
                outputs = self._read_outputs()
        else:
            # We read a non-empty vin. Assume a normal vout follows.
            outputs = self._read_outputs()

        orig_ser += self.binary[start:self.cursor]

        base_size = self.cursor - start
        witness = b''

        if flag & 1:
            witness = self._read_witness(len(inputs))

        start = self.cursor
        locktime = self._read_le_uint32()
        orig_ser += self.binary[start:self.cursor]
        vsize = (3 * base_size + self.binary_length) // 4

        start = self.cursor

        if version >= 2 and tx_type != 1:
            extra_payload_size = self._read_varint()
            end = self.cursor + extra_payload_size

            spec_tx_class = DeserializerBitgreen.SPEC_TX_HANDLERS.get(tx_type)
            if spec_tx_class:
                read_method = getattr(spec_tx_class, 'read_tx_extra', None)
                extra_payload = read_method(self)
                assert isinstance(extra_payload, spec_tx_class)
            else:
                extra_payload = self._read_nbytes(extra_payload_size)

            orig_ser += self.binary[start:end]
            assert self.cursor == end
        else:
            extra_payload = b''

        return BitgreenTx(version, inputs, outputs, witness,
                        locktime, tx_type, extra_payload), self.TX_HASH_FN(orig_ser), vsize
