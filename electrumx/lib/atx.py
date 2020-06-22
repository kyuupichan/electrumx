from .tx import DeserializerSegWit, Deserializer


class BTCV3KeysDeserializer(DeserializerSegWit):
    def _read_tx_and_hash_segwit(self):
        return DeserializerSegWit.read_tx_and_hash(self)

    def _read_tx_and_hash_no_segwit(self):
        return Deserializer.read_tx_and_hash(self)

    def _check_if_alert_exist(self):
        if self.binary_length > self.cursor:
            return True
        return False

    def _check_if_alert_is_segwit(self):
        # check if maker byte exists by compare it to 0x00
        return self.binary[5] == 0x00

    def read_tx_block(self):
        read = self._read_tx_and_hash_segwit
        tx_no = self._read_varint()
        tx = [read() for _ in range(tx_no)]

        atx = []
        if self._check_if_alert_exist():
            atx_no = self._read_varint()
            if not self._check_if_alert_is_segwit():
                read = self._read_tx_and_hash_no_segwit
            atx = [read() for _ in range(atx_no)]

        return tx + atx
