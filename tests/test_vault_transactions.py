from unittest import TestCase
from electrumx.lib.coins import BitcoinVault
from electrumx.lib.tx import TxVaultSegWit, VaultTxType, TxVault

HEADER = '000000201004f91b5a85f563092ad7d8f57385db3e64d6276d55be3ff03da45aea394e1d8df1ee43d09ebdadd54fc50f773845d496a43db7191e9e02cb4ec1df62ebcf82e14bc65effff7f2004000000'

TX_SEGWIT = '020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff26021202203b33883f0610c368bdc263c91e5e14a50a778281624b87d4ef20e9094c44a3c00101ffffffff0200cf14130400000017a9147687c336a779ae92ca3d8c8455333478b4ad2aa8870000000000000000266a24aa21a9ed212f072e2d2b9cfc89c8ee3b352b1ac31f596f2baa3092c752875e1c9ede230f0120000000000000000000000000000000000000000000000000000000000000000000000000'

AR_ALERT_SEGWIT = '02000000000101229d36ad2ef39155145bf8a3e5f3416c7ca415ff15887aba6212e41e3c82a54700000000232200209f730fc44efad2ef3d4a38aebed0e0e1c2408f93409540496bc5f5b738ee04e0ffffffff01c08c05130400000017a914a813fae80f93e582122732dce4c3148cacec0dba87040047304402205f9bf6d4c4ed13f43310966d2f9b869439a9fd760399b35fbf923036333f8cfc02200bc87f2ed7297127a76b4d6288af9b5db78821a31c7c5cbe6057f17dc56b30c90101014b63516752682103ef6df4b3e7e0a94ef61c3571ee953574c851959350e4befddd3ccf3f5f8539342102ecec100acb89f3049285ae01e7f03fb469e6b54d44b0f3c8240b1958e893cb8c52ae00000000'
AR_RECOVERY_SEGWIT = '02000000000101ca61e1d9e95eec6c933bbfa80b43949044eade2fa0b032bd09de3c793b4db1f400000000232200205bbc7969b9505c29f636f3cdc9f6e8d89926d06114d5ae94ff1710365250c250ffffffff01d4be14130400000017a9142cc746419d3d43a7fc207bafd01330ad649da3bc8705004730440220606ca8135c04d490ad31559b4c247308fa0f4679ec844c13a75e8a5a2ea6cba902204372eabd0b838c881e7a4cad78dde4d1ac8da78e36a5a4c67cec9b5bf49bb56b01473044022077a667e62e1287703fd3998c8016cad17e1211bdd7d2f68d15144ce7b169b81e0220481a27598e45e5c4ba764baa958d534d9b03751442f9e187e102869092e76ece01004b635167526821025813111f13514b978271140162e20239148009a73f4a84ade8f5dff3e3f64ad42102ecec100acb89f3049285ae01e7f03fb469e6b54d44b0f3c8240b1958e893cb8c52ae00000000'

AR_ALERT_NON_SEGWIT = '0200000001f0461fae7c01202cb1acf5240f27c19042c2b6d7b84a43e289d042527c2ed77400000000960047304402202730a847a3f8a2e7f08af57aea3724c29e9188df8143f8c2822c94c896c5281b022004db4d4302bb0ce550fed358cb201c4331fc061fe9e6d32351e1aa82ecf6201801514b635167526821031bd9624f553f98f6c07aba97a98f113abc48b4dc22910ac1d77e7bb6fbdc7f202102ecec100acb89f3049285ae01e7f03fb469e6b54d44b0f3c8240b1958e893cb8c52aeffffffff01c08c05130400000017a914340d407d281db4948d160ce867be856e33e67f2f8700000000'

AIR_ALERT_SEGWIT = '02000000000101d9864ecdbf38f1d4cbcf08bdadbe061fb529e2fa78d9706405a27f7f99cc4204000000002322002022a869aea58eaec22f77693e5ab603880901384699d8d5ea993605759b197678feffffff02b8f279d70300000017a914d0cf533a5781e2c36ec178ecf4ce33dec1c3d0808700ca9a3b0000000017a914a157d16bc66cf6cd7e5d3daaedb7a2379c54dd3a87040047304402205b224a687f72046fdc58e1e6662700163fe53ae3bb7fef3466c769e2cb93f0c00220744bc1ca8ddbc7106c0ef6cdf9b63d93295b0042892d4c0fc2c7a1801b7ffcf2010101716351676352675368682103a03684a36e33e20e4e11619eb89c379f5d48621dc23428893f7ba373b319ffe3210263451a52f3d3ae6918969e1c5ce934743185578481ef8130336ad1726ba61ddb2102ecec100acb89f3049285ae01e7f03fb469e6b54d44b0f3c8240b1958e893cb8c53aec8000000'
AIR_INSTANT_SEGWIT = '02000000000101c04516f5d32d25741f766fc64fe022413edb8f65fd88ab6f3e50c3c2e6dd73e100000000232200202272d90e83d5973cf09f83b81eeb4a59e5a77e01a7de87f311c21b3c62359d22ffffffff01c08c05130400000017a91455e78174653079683f2f3d064c469177506e670e870600473044022035036d46c4ef714c864089ce4233f14ff8a08c9d9e0716ff89a34f11cd19f2f502201a3d3d359633d8893acbedde9be2000529dbc9246ed3ab3bc00f8043867396ea0147304402202eab1285c1e76cd98e7a6fc200133e72c5eed88d4345003b45745530180bd435022028e42caa13d08c820ada0e9b23c3acde440aaa11738d7eba954f2c3414e684a301010100716351676352675368682103670b6c9b4f7c7d86bf1ec6621b30aeed9b90fb323323f78e688dc442e5eed33d210263451a52f3d3ae6918969e1c5ce934743185578481ef8130336ad1726ba61ddb2102ecec100acb89f3049285ae01e7f03fb469e6b54d44b0f3c8240b1958e893cb8c53ae00000000'
AIR_RECOVERY_SEGWIT = '02000000000101d8fbcabcee7962dc3827b18f7059c446a30a9711f40b89ee17f7bb1d91cd8fe20000000023220020243ad3ec325e433f4d18154df124b67ceb6425033e9dab515d5f66245bed5b24ffffffff01b8bc14130400000017a91493be10a6ea9fa8f7a04638e82fa77980a1a1656887070047304402206b83dd23e3bc90c0f3eed38618ae08218272585c5593cec403fc40bc7df060d8022079fdfee0297c5f67690b992ddeba49e978ddc999474be9f229eb9865fb03c1f00147304402202c1548716fcc3b18209763f858903b18daa0c765b8460f8c3a5b8596e7d5505b022003181f6eab71fb55e3d4e9c7ad12ae44749f50bc259953f421d7f419413c1d3b014730440220269e848d0d095c3324f5a0c785b06044a0839ae2cf963d63a1a8b09a7eb3093402205f176fbab7f579d6f34a29e0062eb74fcbf18221f4583da615fcd620106bdec101000071635167635267536868210249267ea5dffd2352705fa4c12105227fcd045d2ecefb07f009d96ca870cb5511210263451a52f3d3ae6918969e1c5ce934743185578481ef8130336ad1726ba61ddb2102ecec100acb89f3049285ae01e7f03fb469e6b54d44b0f3c8240b1958e893cb8c53ae00000000'

AIR_ALERT_NON_SEGWIT = '0200000001528a5bd018582633521f45bde42c350fc36864eb328b192ca4fa954ac0d5cc7600000000bd0047304402206202bbe65e9495786a170c337c878d1e75609ed43d1684e8f5d2862f81b6f25c02206567951bc4b1e43a014b58366021a7f542a81049c73fbcfc0c2fff782406f96a01514c71635167635267536868210282163aaebde9f9e06913a1781035f4f0ea76bc4b10df86ec212e3dce04e980d9210263451a52f3d3ae6918969e1c5ce934743185578481ef8130336ad1726ba61ddb2102ecec100acb89f3049285ae01e7f03fb469e6b54d44b0f3c8240b1958e893cb8c53aeffffffff01c08c05130400000017a91452c92b0c21d03b5d81b313b8742e40083ab57b958700000000'


class TestParsingAlertTransaction(TestCase):
    def setUp(self):
        self.coin = BitcoinVault()

    def test_no_segwit_atx(self):
        raw_block = bytes.fromhex(
            HEADER +
            '01' + TX_SEGWIT +
            '01' + AR_ALERT_NON_SEGWIT
        )
        block = self.coin.block(raw_block, 0)
        transactions = block.transactions
        alerts = block.alerts

        self.assertEqual(len(transactions), 1)
        self.assertEqual(len(alerts), 1)
        self.assertIsInstance(alerts[0][0], TxVault)
        self.assertEqual(alerts[0][0].type, VaultTxType.ALERT_PENDING)

    def test_segwit_atx(self):
        raw_block = bytes.fromhex(
            HEADER +
            '01' + TX_SEGWIT +
            '01' + AR_ALERT_SEGWIT
        )
        block = self.coin.block(raw_block, 0)
        transactions = block.transactions
        alerts = block.alerts

        self.assertEqual(len(transactions), 1)
        self.assertEqual(len(alerts), 1)
        self.assertIsInstance(alerts[0][0], TxVaultSegWit)
        self.assertEqual(alerts[0][0].type, VaultTxType.ALERT_PENDING)

    def test_no_atx(self):
        raw_block = bytes.fromhex(
            HEADER +
            '01' + TX_SEGWIT
        )
        block = self.coin.block(raw_block, 0)
        transactions = block.transactions
        alerts = block.alerts

        self.assertEqual(len(transactions), 1)
        self.assertEqual(len(alerts), 0)
        self.assertIsInstance(transactions[0][0], TxVaultSegWit)


class TestVaultTxTypeDiscovery(TestCase):
    def setUp(self):
        self.coin = BitcoinVault()

    def test_discover_ar_alert(self):
        raw_block = bytes.fromhex(
            HEADER +
            '01' + AR_ALERT_SEGWIT +
            '01' + AR_ALERT_SEGWIT

        )
        block = self.coin.block(raw_block, 0)
        transactions = block.transactions
        alerts = block.alerts

        self.assertEqual(len(transactions), 1)
        self.assertIsInstance(transactions[0][0], TxVaultSegWit)
        self.assertEqual(transactions[0][0].type, VaultTxType.ALERT_CONFIRMED)

        self.assertEqual(len(alerts), 1)
        self.assertIsInstance(alerts[0][0], TxVaultSegWit)
        self.assertEqual(alerts[0][0].type, VaultTxType.ALERT_PENDING)

    def test_discover_ar_alert_nonsegwit(self):
        raw_block = bytes.fromhex(
            HEADER +
            '01' + TX_SEGWIT +
            '01' + AR_ALERT_NON_SEGWIT

        )
        block = self.coin.block(raw_block, 0)
        alerts = block.alerts

        self.assertEqual(len(alerts), 1)
        self.assertIsInstance(alerts[0][0], TxVault)
        self.assertEqual(alerts[0][0].type, VaultTxType.ALERT_PENDING)

    def test_discover_ar_recovery(self):
        raw_block = bytes.fromhex(
            HEADER +
            '01' + TX_SEGWIT +
            '01' + AR_RECOVERY_SEGWIT

        )
        block = self.coin.block(raw_block, 0)
        alerts = block.alerts

        self.assertEqual(len(alerts), 1)
        self.assertIsInstance(alerts[0][0], TxVaultSegWit)
        self.assertEqual(alerts[0][0].type, VaultTxType.RECOVERY)

    def test_discover_air_alert(self):
        raw_block = bytes.fromhex(
            HEADER +
            '01' + AIR_ALERT_SEGWIT +
            '01' + AIR_ALERT_SEGWIT

        )
        block = self.coin.block(raw_block, 0)
        transactions = block.transactions
        alerts = block.alerts

        self.assertEqual(len(transactions), 1)
        self.assertIsInstance(transactions[0][0], TxVaultSegWit)
        self.assertEqual(transactions[0][0].type, VaultTxType.ALERT_CONFIRMED)

        self.assertEqual(len(alerts), 1)
        self.assertIsInstance(alerts[0][0], TxVaultSegWit)
        self.assertEqual(alerts[0][0].type, VaultTxType.ALERT_PENDING)

    def test_discover_air_alert_nonsegwit(self):
        raw_block = bytes.fromhex(
            HEADER +
            '01' + TX_SEGWIT +
            '01' + AIR_ALERT_NON_SEGWIT

        )
        block = self.coin.block(raw_block, 0)
        alerts = block.alerts

        self.assertEqual(len(alerts), 1)
        self.assertIsInstance(alerts[0][0], TxVault)
        self.assertEqual(alerts[0][0].type, VaultTxType.ALERT_PENDING)

    def test_discover_air_instant(self):
        raw_block = bytes.fromhex(
            HEADER +
            '01' + TX_SEGWIT +
            '01' + AIR_INSTANT_SEGWIT

        )
        block = self.coin.block(raw_block, 0)
        alerts = block.alerts

        self.assertEqual(len(alerts), 1)
        self.assertIsInstance(alerts[0][0], TxVaultSegWit)
        self.assertEqual(alerts[0][0].type, VaultTxType.INSTANT)

    def test_discover_air_recovery(self):
        raw_block = bytes.fromhex(
            HEADER +
            '01' + TX_SEGWIT +
            '01' + AIR_RECOVERY_SEGWIT

        )
        block = self.coin.block(raw_block, 0)
        alerts = block.alerts

        self.assertEqual(len(alerts), 1)
        self.assertIsInstance(alerts[0][0], TxVaultSegWit)
        self.assertEqual(alerts[0][0].type, VaultTxType.RECOVERY)