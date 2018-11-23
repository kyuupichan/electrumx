# Copyright (c) 2016-2018, Neil Booth
# Copyright (c) 2018, the ElectrumX authors
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

'''Deserializer for Dash DIP2 special transaction types'''

from collections import namedtuple

from electrumx.lib.tx import Deserializer


# https://github.com/dashpay/dips/blob/master/dip-0002.md
class DashTx(namedtuple("DashTx",
                        "version inputs outputs locktime "
                        "tx_type extra_payload")):
    '''Class representing a Dash transaction'''


# https://github.com/dashpay/dips/blob/master/dip-0002-special-transactions.md
class DashProRegTx(namedtuple("DashProRegTx",
                              "version type mode collateralOutpoint "
                              "ipAddress port KeyIdOwner PubKeyOperator "
                              "KeyIdVoting operatorReward scriptPayout "
                              "inputsHash payloadSig")):
    '''Class representing DIP3 ProRegTx'''


class DashProUpServTx(namedtuple("DashProUpServTx",
                                 "version proTXHash ipAddress port "
                                 "scriptOperatorPayout inputsHash "
                                 "payloadSig")):
    '''Class representing DIP3 ProUpServTx'''


class DashProUpRegTx(namedtuple("DashProUpRegTx",
                                "version proTXHash mode PubKeyOperator "
                                "KeyIdVoting scriptPayout inputsHash "
                                "payloadSig")):
    '''Class representing DIP3 ProUpRegTx'''


class DashProUpRevTx(namedtuple("DashProUpRevTx",
                                "version proTXHash reason "
                                "inputsHash payloadSig")):
    '''Class representing DIP3 ProUpRevTx'''


class DashCbTx(namedtuple("DashCbTx", "version height merkleRootMNList")):
    '''Class representing DIP4 coinbase special tx'''


class DashSubTxRegister(namedtuple("DashSubTxRegister",
                                   "version userName pubKey payloadSig")):
    '''Class representing DIP5 SubTxRegister'''


class DashSubTxTopup(namedtuple("DashSubTxTopup",
                                "version regTxHash")):
    '''Class representing DIP5 SubTxTopup'''


class DashSubTxResetKey(namedtuple("DashSubTxResetKey",
                                   "version regTxHash hashPrevSubTx "
                                   "creditFee newPubKey payloadSig")):
    '''Class representing DIP5 SubTxResetKey'''


class DashSubTxCloseAccount(namedtuple("DashSubTxCloseAccount",
                                       "version regTxHash hashPrevSubTx "
                                       "creditFee payloadSig")):
    '''Class representing DIP5 SubTxCloseAccount'''


# https://dash-docs.github.io/en/developer-reference#outpoint
class TxOutPoint(namedtuple("TxOutPoint", "hash index")):
    '''Class representing tx output outpoint'''


class DeserializerDash(Deserializer):
    '''Deserializer for Dash DIP2 special tx types'''
    PRO_REG_TX = 1
    PRO_UP_SERV_TX = 2
    PRO_UP_REG_TX = 3
    PRO_UP_REV_TX = 4
    CB_TX = 5
    SUB_TX_REGISTER = 8
    SUB_TX_TOPUP = 9
    SUB_TX_RESET_KEY = 10
    SUB_TX_CLOSE_ACCOUNT = 11

    def read_tx(self):
        header = self._read_le_uint32()
        tx_type = header >> 16  # DIP2 tx type
        if tx_type:
            version = header & 0x0000ffff
        else:
            version = header

        if tx_type and version < 3:
            version = header
            tx_type = 0

        inputs = self._read_inputs()
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()
        if tx_type:
            extra_payload_size = self._read_varint()
            end = self.cursor + extra_payload_size
            if tx_type == DeserializerDash.CB_TX:
                extra_payload = self._read_cb_tx()
            elif tx_type == DeserializerDash.PRO_REG_TX:
                extra_payload = self._read_pro_reg_tx()
            elif tx_type == DeserializerDash.PRO_UP_SERV_TX:
                extra_payload = self._read_pro_up_serv_tx()
            elif tx_type == DeserializerDash.PRO_UP_REG_TX:
                extra_payload = self._read_pro_up_reg_tx()
            elif tx_type == DeserializerDash.PRO_UP_REV_TX:
                extra_payload = self._read_pro_up_rev_tx()
            elif tx_type == DeserializerDash.SUB_TX_REGISTER:
                extra_payload = self._read_sub_tx_register()
            elif tx_type == DeserializerDash.SUB_TX_TOPUP:
                extra_payload = self._read_sub_tx_topup()
            elif tx_type == DeserializerDash.SUB_TX_RESET_KEY:
                extra_payload = self._read_sub_tx_reset_key()
            elif tx_type == DeserializerDash.SUB_TX_CLOSE_ACCOUNT:
                extra_payload = self._read_sub_tx_close_account()
            else:
                extra_payload = self._read_nbytes(extra_payload_size)
            assert self.cursor == end
        else:
            extra_payload = b''
        tx = DashTx(version, inputs, outputs, locktime, tx_type, extra_payload)
        return tx

    def _read_outpoint(self):
        return TxOutPoint(
            self._read_nbytes(32),      # hash
            self._read_le_uint32()      # index
        )

    def _read_pro_reg_tx(self):
        return DashProRegTx(
            self._read_le_uint16(),     # version
            self._read_le_uint16(),     # type
            self._read_le_uint16(),     # mode
            self._read_outpoint(),      # collateralOutpoint
            self._read_nbytes(16),      # ipAddress
            self._read_le_uint16(),     # port
            self._read_nbytes(20),      # KeyIdOwner
            self._read_nbytes(48),      # PubKeyOperator
            self._read_nbytes(20),      # KeyIdVoting
            self._read_le_uint16(),     # operatorReward
            self._read_varbytes(),      # scriptPayout
            self._read_nbytes(32),      # inputsHash
            self._read_varbytes()       # payloadSig
        )

    def _read_pro_up_serv_tx(self):
        return DashProUpServTx(
            self._read_le_uint16(),     # version
            self._read_nbytes(32),      # proTXHash
            self._read_nbytes(16),      # ipAddress
            self._read_le_uint16(),     # port
            self._read_varbytes(),      # scriptOperatorPayout
            self._read_nbytes(32),      # inputsHash
            self._read_nbytes(96)       # payloadSig BLSSig
        )

    def _read_pro_up_reg_tx(self):
        return DashProUpRegTx(
            self._read_le_uint16(),     # version
            self._read_nbytes(32),      # proTXHash
            self._read_le_uint16(),     # mode
            self._read_nbytes(48),      # PubKeyOperator
            self._read_nbytes(20),      # KeyIdOwner
            self._read_varbytes(),      # scriptPayout
            self._read_nbytes(32),      # inputsHash
            self._read_varbytes()       # payloadSig
        )

    def _read_pro_up_rev_tx(self):
        return DashProUpRevTx(
            self._read_le_uint16(),     # version
            self._read_nbytes(32),      # proTXHash
            self._read_le_uint16(),     # reason
            self._read_nbytes(32),      # inputsHash
            self._read_nbytes(96)       # payloadSig BLSSig
        )

    def _read_cb_tx(self):
        return DashCbTx(
            self._read_le_uint16(),     # version
            self._read_le_uint32(),     # height
            self._read_nbytes(32)       # merkleRootMNList as bytes
        )

    def _read_sub_tx_register(self):
        return DashSubTxRegister(
            self._read_le_uint16(),     # version
            self._read_varbytes(),      # userName
            self._read_nbytes(48),      # pubKey BLSPubKey
            self._read_nbytes(96)       # payloadSig BLSSig
        )

    def _read_sub_tx_topup(self):
        return DashSubTxTopup(
            self._read_le_uint16(),     # version
            self._read_nbytes(32)       # regTxHash
        )

    def _read_sub_tx_reset_key(self):
        return DashSubTxResetKey(
            self._read_le_uint16(),     # version
            self._read_nbytes(32),      # regTxHash
            self._read_nbytes(32),      # hashPrevSubTx
            self._read_le_int64(),      # creditFee
            self._read_nbytes(48),      # newPubKey BLSPubKey
            self._read_nbytes(96)       # payloadSig BLSSig
        )

    def _read_sub_tx_close_account(self):
        return DashSubTxCloseAccount(
            self._read_le_uint16(),     # version
            self._read_nbytes(32),      # regTxHash
            self._read_nbytes(32),      # hashPrevSubTx
            self._read_le_int64(),      # creditFee
            self._read_nbytes(96)       # payloadSig BLSSig
        )
