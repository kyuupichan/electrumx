from unittest import TestCase
from electrumx.lib.coins import BitcoinVault
from electrumx.lib.tx import TxSegWit, TxVault, TxVaultSegWit

HEADER = '000000201004f91b5a85f563092ad7d8f57385db3e64d6276d55be3ff03da45aea394e1d8df1ee43d09ebdadd54fc50f773845d496a43db7191e9e02cb4ec1df62ebcf82e14bc65effff7f2004000000'

SEGWIT_TX = '01020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff26021202203b33883f0610c368bdc263c91e5e14a50a778281624b87d4ef20e9094c44a3c00101ffffffff0200cf14130400000017a9147687c336a779ae92ca3d8c8455333478b4ad2aa8870000000000000000266a24aa21a9ed212f072e2d2b9cfc89c8ee3b352b1ac31f596f2baa3092c752875e1c9ede230f0120000000000000000000000000000000000000000000000000000000000000000000000000'

ATX_NO_SEGWIT = '01020000000128c8882424d6a9b67b5fd3ee28e258fe77c09f5214f8538034335b6e414e008d000000009700473044022048f893031dd53a2c9600936d50611e55ce93185a6bc594eb3d6b9191b56dba4102205784161326ca87899a384347cc592475fb248d6f87aa45991bcf60f1effef54a0101514b63516752682102ecec100acb89f3049285ae01e7f03fb469e6b54d44b0f3c8240b1958e893cb8c2102eb2f0ae336b1a48d890177e68f942fe28165c641e76b54869f7692e54fe7d45852aeffffffff01c0a1fc530200000017a91494a12e081c0153360f943e97c1f9053b08260aaf8700000000'

ATX_SEGWIT = '0102000000000101fb3eb31403101482d96897e9de380caff631386df3f4124895844d2a814b5c690000000023220020c042db202486188384024431a2feffc2b642c3b2c554c08e6fa60a3f46a67e34feffffff02c0a1fc530200000017a9141d349c452cd48bb12b17ce0c300402871abdcdd187141d18bf0100000017a9148461d9946342dc93e6117128ff41dc241c43f8f9870400473044022043afdd93725b81dd7606e12b7760108137e247259aef02613bab82ba79792f33022006212dc0dcc428ad2f211f7f8bf52e2011adf0d7597e27328452c6c6834f646d0101014b635167526821022e298782d752bd28f9c430ef5943391db11406e0712331710fbd4908c9aef98e2102ecec100acb89f3049285ae01e7f03fb469e6b54d44b0f3c8240b1958e893cb8c52ae5a010000'

class TestParsingAlertTransaction(TestCase):
    def setUp(self):
        self.coin = BitcoinVault()

    def test_no_segwit_atx(self):
        raw_block = bytes.fromhex(
            HEADER +
            SEGWIT_TX +
            ATX_NO_SEGWIT
        )
        block = self.coin.block(raw_block, 0)
        transactions = block.transactions
        alerts = block.alerts

        self.assertEqual(len(transactions), 1)
        self.assertEqual(len(alerts), 1)
        self.assertIsInstance(alerts[0][0], TxVault)
        self.assertEqual(alerts[0][0].type, 'alert')

    def test_segwit_atx(self):
        raw_block = bytes.fromhex(
            HEADER +
            SEGWIT_TX +
            ATX_SEGWIT
        )
        block = self.coin.block(raw_block, 0)
        transactions = block.transactions
        alerts = block.alerts

        self.assertEqual(len(transactions), 1)
        self.assertEqual(len(alerts), 1)
        self.assertIsInstance(alerts[0][0], TxVaultSegWit)
        self.assertEqual(alerts[0][0].type, 'alert')

    def test_no_atx(self):
        raw_block = bytes.fromhex(
            HEADER +
            SEGWIT_TX
        )
        block = self.coin.block(raw_block, 0)
        transactions = block.transactions
        alerts = block.alerts

        self.assertEqual(len(transactions), 1)
        self.assertEqual(len(alerts), 0)
        self.assertIsInstance(transactions[0][0], TxSegWit)
