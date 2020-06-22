from unittest import TestCase
from electrumx.lib.coins import BitcoinVault3Keys
from electrumx.lib.tx import Tx, TxSegWit


HEADER = '000000201004f91b5a85f563092ad7d8f57385db3e64d6276d55be3ff03da45aea394e1d8df1ee43d09ebdadd54fc50f773845d496a43db7191e9e02cb4ec1df62ebcf82e14bc65effff7f2004000000'

SEGWIT_TX = '01020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff26021202203b33883f0610c368bdc263c91e5e14a50a778281624b87d4ef20e9094c44a3c00101ffffffff0200cf14130400000017a9147687c336a779ae92ca3d8c8455333478b4ad2aa8870000000000000000266a24aa21a9ed212f072e2d2b9cfc89c8ee3b352b1ac31f596f2baa3092c752875e1c9ede230f0120000000000000000000000000000000000000000000000000000000000000000000000000'

ATX_NO_SEGWIT = '01020000000128c8882424d6a9b67b5fd3ee28e258fe77c09f5214f8538034335b6e414e008d000000009700473044022048f893031dd53a2c9600936d50611e55ce93185a6bc594eb3d6b9191b56dba4102205784161326ca87899a384347cc592475fb248d6f87aa45991bcf60f1effef54a0101514b63516752682102ecec100acb89f3049285ae01e7f03fb469e6b54d44b0f3c8240b1958e893cb8c2102eb2f0ae336b1a48d890177e68f942fe28165c641e76b54869f7692e54fe7d45852aeffffffff01c0a1fc530200000017a91494a12e081c0153360f943e97c1f9053b08260aaf8700000000'


class TestParsingAlertTransaction(TestCase):
    def setUp(self):
        self.coin = BitcoinVault3Keys()

    def test_no_segwit_atx(self):
        raw_block = bytes.fromhex(
            HEADER +
            SEGWIT_TX +
            ATX_NO_SEGWIT
        )
        block = self.coin.block(raw_block, 0)
        transactions = block.transactions

        self.assertEqual(len(transactions), 2)
        self.assertIsInstance(transactions[1][0], Tx)

    def test_segwit_atx(self):
        raw_block = bytes.fromhex(
            HEADER +
            SEGWIT_TX +
            SEGWIT_TX
        )
        block = self.coin.block(raw_block, 0)
        transactions = block.transactions

        self.assertEqual(len(transactions), 2)
        self.assertIsInstance(transactions[1][0], TxSegWit)

    def test_no_atx(self):
        raw_block = bytes.fromhex(
            HEADER +
            SEGWIT_TX
        )
        block = self.coin.block(raw_block, 0)
        transactions = block.transactions

        self.assertEqual(len(transactions), 1)
        self.assertIsInstance(transactions[0][0], TxSegWit)
