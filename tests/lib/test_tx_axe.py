import pytest

import electrumx.lib.tx_axe as lib_tx_axe


bfh = bytes.fromhex


V2_TX = (
    '020000000192809f0b234cb850d71d020e678e93f074648ed0df5affd0c46d3bcb177f'
    '9ccf020000008b483045022100c5403bcf86c3ae7b8fd4ca0d1e4df6729cc1af05ff95'
    'd9726b43a64b41dd5d9902207fab615f41871885aa3062fc7d8f8d9d3dcbc2e4867c5d'
    '96dd7a176b99e927924141040baa4271a82c5f1a09a5ea63d763697ca0545b6049c4dd'
    '8e8d099dd91f2da10eb11e829000a82047ac56969fb582433067a21c3171e569d1832c'
    '34fdd793cfc8ffffffff030000000000000000226a20195ce612d20e5284eb78bb28c9'
    'c50d6139b10b77b2d5b2f94711b13162700472bfc53000000000001976a9144a519c63'
    'f985ba5ab8b71bb42f1ecb82a0a0d80788acf6984315000000001976a9148b80536aa3'
    'c460258cda834b86a46787c9a2b0bf88ac00000000')


CB_TX = ( '03000500010000000000000000000000000000000000000000000000000000000000000000ffffffff1303c407040e2f5032506f6f6c2d74444153482fffffffff0448d6a73d000000001976a914293859173a34194d445c2962b97383e2a93d7cb288ac22fc433e000000001976a914bf09c602c6b8f1db246aba5c37ad1cfdcb16b15e88ace9259c00000000004341047559d13c3f81b1fadbd8dd03e4b5a1c73b05e2b980e00d467aa9440b29c7de23664dde6428d75cafed22ae4f0d302e26c5c5a5dd4d3e1b796d7281bdc9430f35ac00000000000000002a6a28be61411c3c79b7fd45923118ba74d340afb248ae2edafe78c15e2d1aa337c942000000000000000000000000260100c407040076629a6e42fb519188f65889fd3ac0201be87aa227462b5643e8bb2ec1d7a82a')

CB_TX_V2 = ( '03000500010000000000000000000000000000000000000000000000000000000000000000ffffffff2603caac04194d696e656420627920416e74506f6f6c52000b03203e009e9457070000441a0000ffffffff02db98d40b000000001976a9141d16d67366c081e6cc6b402667fa8044c4a42e8888ac9d65130d000000001976a9146ca3b3578583b5c73adb302ccb612b9a5fbef17488ac00000000460200caac04002d126055d9cd81da35972dd5f11d8b7d24d23beeb9331d64d93ca74966fff9120000000000000000000000000000000000000000000000000000000000000000')

PRO_REG_TX = ( '03000100013a196f2a59b88dcbadb48b580dd4ef14f6d1dd6f86e8d6cb8942c34837a45448000000006a473044022048b0c1703e7c40750097d770b5f05b8ccdd5a656d24970fd769712830404958702205c63c57cdba86026a0fd58dc7633eb0ae6f66ef43e96915c3b74bb4c7747a885012103542c5d737685944600d238ae5e6abc7e2906e34453d6af5a0fadd84dd8e09242feffffff0121c89a3b000000001976a91435af662851170d5ddebba4e287019a4597dd453d88ac00000000fd12010100000000002181625260614470c020764d56d7a2eb9bedb0a2f65f0168c99a4fdf846573910000000000000000000000000000ffff74cb7f7f26d1c1a9c6453135e83be71635ac840652bbefc607861908c153792530dfe635bdf819ceb7963b624233a3465be94a4651ca36f7c0917d301c1e61485b68debc2f9fe5b7e84bc1a9c6453135e83be71635ac840652bbefc6078600001976a914950c9dea79cee4c4fea859c95fd534bba21f9a3088acf3a95bbe35ccdbe9d8cd3a875e3f80af725422bcf44d35ce79078df357c29bf9412088b70bd05dbbd5a86d51abc78e33658f95ac01b98bc16dd537bcac5c48d3db437ee6c9b1d664e2a192b64b1893b3ce22b4ac47da9c4a0d148440be74527a43d4' )

PRO_UP_SERV_TX = ( '0300020001423cef3af2b56378737de6bf9d1a5055f07bd35d86585770ce0449c7d5062f0a010000006a473044022013390c4c6f4411cbaee91ea49bb12c29b9618f4902c522274b013c5c20f81f77022022cc2ebb97aed1eecaaad17c9dbd4ad0f42a2969e4599f8e4214a008cd51b9f20121034125651548c482a003fb59229898169e8d289b84dc48f6dfbe160c08bfcec144feffffff01fa294209000000001976a914f489af78bc73074aee98082d2876d710aa242e6188ac00000000b50100bef73450cab0889367710dd4ccd80cdb47557ad135dcb0e54f2cd8b9623cd57300000000000000000000ffff2d3f1f37270f00768450381dca4e9888aa7be9a7725e0824696fc24f5a35de62916dc81b3085b3077e02247c17992ba5ee9a2894e03c2e489b07cb9b751207dd51ca5c3dc6b67bada8f82a41c3137dbb203ce185caaccf1565e62c626e5225ff741e01faf4b09d8d7300dfb5c3e6f352120047b2e7b0547e5ea1198b615bf4826eaba252f97007' )

PRO_UP_REG_TX = ( '030003000114b05579c72dc0785130153c35c8e398fcf1c49594800707b42e8beb73e5d76d000000006b483045022100b13e220d2bf1633002cb9d94f33f5bbf974ea0c4380d4497fedad2c422d92fde0220166f6894eb8e778d55f7b86089fd4ef08e481bb4f04bff67ea2bcb07c5dc2cba012102e2f8099a84f13f9e8e5d784567d49df919ec63764966738df83371c66ff534f6feffffff011f320f00000000001976a914bcc00fdff28f1b7b85ec5135b7a2d8c800a5c01888ac00000000e40100454bce26dde61cce5a8190928ed2af0f95c5bc053c88170b1a653028b36a29a300008aba2efc6ef0305e8aadb650a5e5e15f7ea583968b48ea47bcec4bfaab108aa98f2e4ed0bb66946f7b65dff9ee92820dc99a89fcafd3a4729860b2f9cd2ba4a7d965e9271976a9148e124bfba342a13dec4d7a932284179a7f9c9e6188acd2972fcc5557d534cc6a9ed494e6213673521dbccacf4d3637994a5aaad721d34120697182d7c398d4add6c49f0ddc7e71ec0253f0ff0d198b23913f8231ff18140f0b880feed08c267b0e9c70d9136c028c6126f7ae014879442b93c3a538ee6ac6' )

PRO_UP_REV_TX = ( '0300040001fb9e4b60ee4c625820b52f20067e1f7ce652526f3834afe334b010eddf1ac4e8000000006a47304402203386143fa1e39df1936fcc2af593837f9c815deb04440bfc9b877790e4caff4202202cdb7895a9656d3e62dc8ec2eada1de6d3b11acd517ab09c46ec274698cdefd7012103e10e8542bc703af92dc7c66a4a471f8101472b1a37b83a01309227ad2f7ebf14feffffff017b0d0b00000000001976a91493b17c6f50f75069b93864675c7cb1e9b9dbf3cf88ac00000000a40100d1061c3f0f32e332f100f153041797eebd2702a5f419d2d057023f7f7238c922030041a7d06f62ec60981969414d738489e4a0d8d4dcfb74e8a1ad2182f4e3de97d90e4222e82aa968d8d1c6fda6a553d6071897c8985fda438922d773b7aeabdbaa22cb699b248c0e15bfd7b52e230920ab04ac4881aaffe836bfbc53c6e95671ede9a8185fceece5b3ce1480a824a67fd004a15a2bb34fabb82688344d0b6d2669' )

''' No DIP0005 in Axe for Now
SUB_TX_REGISTER = (
    '03000800010931c6b0ad7ce07f3c8aefeeb78e246a4fe6872bbf08ab6e4eb6a7b69acd'
    '64a6010000006b483045022100a2feb698c43c752738fabea281b7e9e5a3aa648a4c54'
    '1171e06d7c372db92c65022061c1ec3c92f2e76bb7fb1b548d854f19a41e6421267231'
    '74150412caf3e98e9601210293360bf2a2e810673412bc6e8e0e358f3fb7bdbe9a667b'
    '3d0103f761cc69a211feffffff0189fa433e000000001976a914551ab8ca96a9142217'
    '4d22769c3a4f90b2dcd0de88ac00000000960100036162638e7042ec88acefcfe3d578'
    '914bb48c6bd71b3459d384e42374e8abfeffffff01570b0000000000001976a91490c5'
    'ce9d8bc992a88ac00000000a40100b67ffbbd095de31ea38446754e8abfeffffff0157'
    '0b0000000000001976a91490c5ce9d8bc992a88ac00000000a40100b67ffbbd095de31'
    'ea38446754e8abfeffffff01570b0000000000001976a91490c5ce9d')


SUB_TX_TOPUP = (
    '03000900010931c6b0ad7ce07f3c8aefeeb78e246a4fe6872bbf08ab6e4eb6a7b69acd'
    '64a6010000006b483045022100a2feb698c43c752738fabea281b7e9e5a3aa648a4c54'
    '1171e06d7c372db92c65022061c1ec3c92f2e76bb7fb1b548d854f19a41e6421267231'
    '74150412caf3e98e9601210293360bf2a2e810673412bc6e8e0e358f3fb7bdbe9a667b'
    '3d0103f761cc69a211feffffff0189fa433e000000001976a914551ab8ca96a9142217'
    '4d22769c3a4f90b2dcd0de88ac00000000220100d384e42374e8abfeffffff01570b00'
    '0000a40100b67ffbbd095de31ea3844675')


SUB_TX_RESET_KEY = (
    '03000a00010931c6b0ad7ce07f3c8aefeeb78e246a4fe6872bbf08ab6e4eb6a7b69acd'
    '64a6010000006b483045022100a2feb698c43c752738fabea281b7e9e5a3aa648a4c54'
    '1171e06d7c372db92c65022061c1ec3c92f2e76bb7fb1b548d854f19a41e6421267231'
    '74150412caf3e98e9601210293360bf2a2e810673412bc6e8e0e358f3fb7bdbe9a667b'
    '3d0103f761cc69a211feffffff0189fa433e000000001976a914551ab8ca96a9142217'
    '4d22769c3a4f90b2dcd0de88ac00000000da0100d384e42374e8abfeffffff01570b00'
    '0000a40100b67ffbbd095de31ea3844675af3e98e9601210293360bf2a2e810673412b'
    'c6e8e0e358f3fb7bdbe9a667b3d0e803000000000000601210293360bf2a2e81067341'
    '2bc6e8e0e358f3fb7bdbe9a667b3d0103f761caf3e98e9601210293360bf2a2e810673'
    '412bc6e8e0e358f3fb7bdbe9a667b3d0103f761caf3e98e9601210293360bf2a2e8106'
    '73412bc6e8e0e358f3fb7bdbe9a667b3d0103f761caf3e98e9601210293360bf2a2e81'
    '0673412bc6e8e0e358f3fb7bdbe9a667b3d0103f761cabcdefab')


SUB_TX_CLOSE_ACCOUNT = (
    '03000b00010931c6b0ad7ce07f3c8aefeeb78e246a4fe6872bbf08ab6e4eb6a7b69acd'
    '64a6010000006b483045022100a2feb698c43c752738fabea281b7e9e5a3aa648a4c54'
    '1171e06d7c372db92c65022061c1ec3c92f2e76bb7fb1b548d854f19a41e6421267231'
    '74150412caf3e98e9601210293360bf2a2e810673412bc6e8e0e358f3fb7bdbe9a667b'
    '3d0103f761cc69a211feffffff0189fa433e000000001976a914551ab8ca96a9142217'
    '4d22769c3a4f90b2dcd0de88ac00000000aa0100d384e42374e8abfeffffff01570b00'
    '0000a40100b67ffbbd095de31ea3844675af3e98e9601210293360bf2a2e810673412b'
    'c6e8e0e358f3fb7bdbe9a12bc6e8e803000000000000a62bc6e8e0e358f3fb7bdbe9a6'
    '67b3d0103f761caf3e98e9601210293360bf2a2e810673412bc6e8e0e358f3fb7bdbe9'
    'a667b3d0103f761caf3e98e9601210293360bf2a2e810673412bc6e8e0e358f3fb7bdb'
    'e9a667b3d0103f761cabcdefab')
'''

UNKNOWN_SPEC_TX = (
    '0300bb00010931c6b0ad7ce07f3c8aefeeb78e246a4fe6872bbf08ab6e4eb6a7b69acd'
    '64a6010000006b483045022100a2feb698c43c752738fabea281b7e9e5a3aa648a4c54'
    '1171e06d7c372db92c65022061c1ec3c92f2e76bb7fb1b548d854f19a41e6421267231'
    '74150412caf3e98e9601210293360bf2a2e810673412bc6e8e0e358f3fb7bdbe9a667b'
    '3d0103f761cc69a211feffffff0189fa433e000000001976a914551ab8ca96a9142217'
    '4d22769c3a4f90b2dcd0de88ac00000000aa0100d384e42374e8abfeffffff01570b00'
    '0000a40100b67ffbbd095de31ea3844675af3e98e9601210293360bf2a2e810673412b'
    'c6e8e0e358f3fb7bdbe9a12bc6e8e0e358f3fb7bdbe9a62bc6e8e0e358f3fb7bdbe9a6'
    '67b3d0103f761caf3e98e9601210293360bf2a2e810673412bc6e8e0e358f3fb7bdbe9'
    'a667b3d0103f761caf3e98e9601210293360bf2a2e810673412bc6e8e0e358f3fb7bdb'
    'e9a667b3d0103f761cabcdefab')


WRONG_SPEC_TX = (  # Tx version < 3
    '0200bb00010931c6b0ad7ce07f3c8aefeeb78e246a4fe6872bbf08ab6e4eb6a7b69acd'
    '64a6010000006b483045022100a2feb698c43c752738fabea281b7e9e5a3aa648a4c54'
    '1171e06d7c372db92c65022061c1ec3c92f2e76bb7fb1b548d854f19a41e6421267231'
    '74150412caf3e98e9601210293360bf2a2e810673412bc6e8e0e358f3fb7bdbe9a667b'
    '3d0103f761cc69a211feffffff0189fa433e000000001976a914551ab8ca96a9142217'
    '4d22769c3a4f90b2dcd0de88ac00000000')


def test_axe_v2_tx():
    test = bfh(V2_TX)
    deser = lib_tx_axe.DeserializerAxe(test)
    tx = deser.read_tx()
    assert tx.version == 2
    assert tx.tx_type == 0
    assert tx.extra_payload == b''
    ser = tx.serialize()
    assert ser == test


def test_axe_tx_cb_tx():
    test = bfh(CB_TX)
    deser = lib_tx_axe.DeserializerAxe(test)
    tx = deser.read_tx()
    assert tx.version == 3
    assert tx.tx_type == 5
    extra = tx.extra_payload
    assert extra.version == 1
    assert extra.height == 264132
    assert len(extra.merkleRootMNList) == 32
    assert extra.merkleRootMNList == bfh(
        '76629a6e42fb519188f65889fd3ac0201be87aa227462b5643e8bb2ec1d7a82a')
    ser = tx.serialize()
    assert ser == test


def test_axe_tx_cb_tx_v2():
    test = bfh(CB_TX_V2)
    deser = lib_tx_axe.DeserializerAxe(test)
    tx = deser.read_tx()
    assert tx.version == 3
    assert tx.tx_type == 5
    extra = tx.extra_payload
    assert extra.version == 2
    assert extra.height == 306378
    assert len(extra.merkleRootMNList) == 32
    assert extra.merkleRootMNList == bfh(
        '2d126055d9cd81da35972dd5f11d8b7d24d23beeb9331d64d93ca74966fff912')
    assert len(extra.merkleRootQuorums) == 32
    assert extra.merkleRootQuorums == bfh(
        '0000000000000000000000000000000000000000000000000000000000000000')
    ser = tx.serialize()
    assert ser == test


def test_axe_tx_pro_reg_tx():
    test = bfh(PRO_REG_TX)
    deser = lib_tx_axe.DeserializerAxe(test)
    tx = deser.read_tx()
    assert tx.version == 3
    assert tx.tx_type == 1
    extra = tx.extra_payload
    assert extra.version == 1
    assert extra.type == 0
    assert extra.mode == 0
    assert len(extra.collateralOutpoint.hash) == 32
    assert extra.collateralOutpoint.hash == bfh(
        '2181625260614470c020764d56d7a2eb9bedb0a2f65f0168c99a4fdf84657391')
    assert extra.collateralOutpoint.index == 0
    assert len(extra.ipAddress) == 16
    assert extra.ipAddress == bfh('00000000000000000000ffff74cb7f7f')
    assert extra.port == 9937
    assert len(extra.KeyIdOwner) == 20
    assert extra.KeyIdOwner == bfh(
        'c1a9c6453135e83be71635ac840652bbefc60786')
    assert len(extra.PubKeyOperator) == 48
    assert extra.PubKeyOperator == bfh(
        '1908c153792530dfe635bdf819ceb7963b624233a3465be94a4651ca36f7c0917d301c1e61485b68debc2f9fe5b7e84b')
    assert len(extra.KeyIdVoting) == 20
    assert extra.KeyIdVoting == bfh(
        'c1a9c6453135e83be71635ac840652bbefc60786')
    assert extra.operatorReward == 0
    assert extra.scriptPayout == bfh(
        '76a914950c9dea79cee4c4fea859c95fd534bba21f9a3088ac')
    assert len(extra.inputsHash) == 32
    assert extra.inputsHash == bfh(
        'f3a95bbe35ccdbe9d8cd3a875e3f80af725422bcf44d35ce79078df357c29bf9')
    assert extra.payloadSig == bfh(
        '2088b70bd05dbbd5a86d51abc78e33658f95ac01b98bc16dd537bcac5c48d3db437ee6c9b1d664e2a192b64b1893b3ce22b4ac47da9c4a0d148440be74527a43d4')
    ser = tx.serialize()
    assert ser == test


def test_axe_tx_pro_up_serv_tx():
    test = bfh(PRO_UP_SERV_TX)
    deser = lib_tx_axe.DeserializerAxe(test)
    tx = deser.read_tx()
    assert tx.version == 3
    assert tx.tx_type == 2
    extra = tx.extra_payload
    assert extra.version == 1
    assert len(extra.proTxHash) == 32
    assert extra.proTxHash == bfh(
        'bef73450cab0889367710dd4ccd80cdb47557ad135dcb0e54f2cd8b9623cd573')
    assert len(extra.ipAddress) == 16
    assert extra.ipAddress == bfh('00000000000000000000ffff2d3f1f37')
    assert extra.port == 9999
    assert extra.scriptOperatorPayout == bfh( '')
    #not present in the test transaction
    assert len(extra.inputsHash) == 32
    assert extra.inputsHash == bfh(
        '768450381dca4e9888aa7be9a7725e0824696fc24f5a35de62916dc81b3085b3')
    assert len(extra.payloadSig) == 96
    assert extra.payloadSig == bfh( '077e02247c17992ba5ee9a2894e03c2e489b07cb9b751207dd51ca5c3dc6b67bada8f82a41c3137dbb203ce185caaccf1565e62c626e5225ff741e01faf4b09d8d7300dfb5c3e6f352120047b2e7b0547e5ea1198b615bf4826eaba252f97007' )
        
    ser = tx.serialize()
    assert ser == test


def test_axe_tx_pro_up_reg_tx():
    test = bfh(PRO_UP_REG_TX)
    deser = lib_tx_axe.DeserializerAxe(test)
    tx = deser.read_tx()
    assert tx.version == 3
    assert tx.tx_type == 3
    extra = tx.extra_payload
    assert extra.version == 1
    assert len(extra.proTxHash) == 32
    assert extra.proTxHash == bfh(
        '454bce26dde61cce5a8190928ed2af0f95c5bc053c88170b1a653028b36a29a3')
    assert extra.mode == 0
    assert len(extra.PubKeyOperator) == 48
    assert extra.PubKeyOperator == bfh(
        '8aba2efc6ef0305e8aadb650a5e5e15f7ea583968b48ea47bcec4bfaab108aa98f2e4ed0bb66946f7b65dff9ee92820d' )
    assert len(extra.KeyIdVoting) == 20
    print(extra.KeyIdVoting)
    #assert extra.KeyIdVoting == bfh(
     #   'c99a89fcafd3a4729860b2f9cd2ba4a7d965e9')
    assert extra.scriptPayout == bfh(
        '76a9148e124bfba342a13dec4d7a932284179a7f9c9e6188ac')
    assert len(extra.inputsHash) == 32
    assert extra.inputsHash == bfh(
        'd2972fcc5557d534cc6a9ed494e6213673521dbccacf4d3637994a5aaad721d3')
    assert extra.payloadSig == bfh( '20697182d7c398d4add6c49f0ddc7e71ec0253f0ff0d198b23913f8231ff18140f0b880feed08c267b0e9c70d9136c028c6126f7ae014879442b93c3a538ee6ac6' )
        
    ser = tx.serialize()
    assert ser == test


def test_axe_tx_pro_up_rev_tx():
    test = bfh(PRO_UP_REV_TX)
    deser = lib_tx_axe.DeserializerAxe(test)
    tx = deser.read_tx()
    assert tx.version == 3
    assert tx.tx_type == 4
    extra = tx.extra_payload
    assert extra.version == 1
    assert len(extra.proTxHash) == 32
    assert extra.proTxHash == bfh(
        'd1061c3f0f32e332f100f153041797eebd2702a5f419d2d057023f7f7238c922')
    assert extra.reason == 3
    assert len(extra.inputsHash) == 32
    assert extra.inputsHash == bfh(
        '41a7d06f62ec60981969414d738489e4a0d8d4dcfb74e8a1ad2182f4e3de97d9')
    assert len(extra.payloadSig) == 96
    assert extra.payloadSig == bfh(
        '0e4222e82aa968d8d1c6fda6a553d6071897c8985fda438922d773b7aeabdbaa22cb699b248c0e15bfd7b52e230920ab04ac4881aaffe836bfbc53c6e95671ede9a8185fceece5b3ce1480a824a67fd004a15a2bb34fabb82688344d0b6d2669' )
    ser = tx.serialize()
    assert ser == test

''' No DIP0005 in Axe
def test_axe_tx_sub_tx_register_tx():
    test = bfh(SUB_TX_REGISTER)
    deser = lib_tx_axe.DeserializerAxe(test)
    tx = deser.read_tx()
    assert tx.version == 3
    assert tx.tx_type == 8
    extra = tx.extra_payload
    assert extra.version == 1
    assert extra.userName == b'abc'
    assert len(extra.pubKey) == 48
    assert extra.pubKey == bfh(
        '8e7042ec88acefcfe3d578914bb48c6bd71b3459d384e42374e8abfeffff'
        'ff01570b0000000000001976a91490c5ce9d')
    assert len(extra.payloadSig) == 96
    assert extra.payloadSig == bfh(
        '8bc992a88ac00000000a40100b67ffbbd095de31ea38446754e8abfeffff'
        'ff01570b0000000000001976a91490c5ce9d8bc992a88ac00000000a4010'
        '0b67ffbbd095de31ea38446754e8abfeffffff01570b0000000000001976'
        'a91490c5ce9d')
    ser = tx.serialize()
    assert ser == test

def test_axe_tx_sub_tx_topup_tx():
    test = bfh(SUB_TX_TOPUP)
    deser = lib_tx_axe.DeserializerAxe(test)
    tx = deser.read_tx()
    assert tx.version == 3
    assert tx.tx_type == 9
    extra = tx.extra_payload
    assert extra.version == 1
    assert len(extra.regTxHash) == 32
    assert extra.regTxHash == bfh(
        'd384e42374e8abfeffffff01570b000000a40100b67ffbbd095de31ea3844675')
    ser = tx.serialize()
    assert ser == test


def test_axe_tx_sub_tx_reset_key_tx():
    test = bfh(SUB_TX_RESET_KEY)
    deser = lib_tx_axe.DeserializerAxe(test)
    tx = deser.read_tx()
    assert tx.version == 3
    assert tx.tx_type == 10
    extra = tx.extra_payload
    assert extra.version == 1
    assert len(extra.regTxHash) == 32
    assert extra.regTxHash == bfh(
        'd384e42374e8abfeffffff01570b000000a40100b67ffbbd095de31ea3844675')
    assert len(extra.hashPrevSubTx) == 32
    assert extra.hashPrevSubTx == bfh(
        'af3e98e9601210293360bf2a2e810673412bc6e8e0e358f3fb7bdbe9a667b3d0')
    assert extra.creditFee == 1000
    assert len(extra.newPubKey) == 48
    assert extra.newPubKey == bfh(
        '601210293360bf2a2e810673412bc6e8e0e358f3fb7bdbe9a667b3d0103f7'
        '61caf3e98e9601210293360bf2a2e810673')
    assert len(extra.payloadSig) == 96
    assert extra.payloadSig == bfh(
        '412bc6e8e0e358f3fb7bdbe9a667b3d0103f761caf3e98e9601210293360b'
        'f2a2e810673412bc6e8e0e358f3fb7bdbe9a667b3d0103f761caf3e98e960'
        '1210293360bf2a2e810673412bc6e8e0e358f3fb7bdbe9a667b3d0103f761'
        'cabcdefab')
    ser = tx.serialize()
    assert ser == test


def test_axe_tx_sub_tx_close_account_tx():
    test = bfh(SUB_TX_CLOSE_ACCOUNT)
    deser = lib_tx_axe.DeserializerAxe(test)
    tx = deser.read_tx()
    assert tx.version == 3
    assert tx.tx_type == 11
    extra = tx.extra_payload
    assert extra.version == 1
    assert len(extra.regTxHash) == 32
    assert extra.regTxHash == bfh(
        'd384e42374e8abfeffffff01570b000000a40100b67ffbbd095de31ea3844675')
    assert len(extra.hashPrevSubTx) == 32
    assert extra.hashPrevSubTx == bfh(
        'af3e98e9601210293360bf2a2e810673412bc6e8e0e358f3fb7bdbe9a12bc6e8')
    assert extra.creditFee == 1000
    assert len(extra.payloadSig) == 96
    assert extra.payloadSig == bfh(
        'a62bc6e8e0e358f3fb7bdbe9a667b3d0103f761caf3e98e9601210293360b'
        'f2a2e810673412bc6e8e0e358f3fb7bdbe9a667b3d0103f761caf3e98e960'
        '1210293360bf2a2e810673412bc6e8e0e358f3fb7bdbe9a667b3d0103f761'
        'cabcdefab')
    ser = tx.serialize()
    assert ser == test
'''

def test_axe_tx_unknown_spec_tx():
    test = bfh(UNKNOWN_SPEC_TX)
    deser = lib_tx_axe.DeserializerAxe(test)
    tx = deser.read_tx()
    assert tx.version == 3
    assert tx.tx_type == 187
    extra = tx.extra_payload
    assert extra == bfh(
        '0100d384e42374e8abfeffffff01570b000000a40100b67ffbbd095de31e'
        'a3844675af3e98e9601210293360bf2a2e810673412bc6e8e0e358f3fb7b'
        'dbe9a12bc6e8e0e358f3fb7bdbe9a62bc6e8e0e358f3fb7bdbe9a667b3d0'
        '103f761caf3e98e9601210293360bf2a2e810673412bc6e8e0e358f3fb7b'
        'dbe9a667b3d0103f761caf3e98e9601210293360bf2a2e810673412bc6e8'
        'e0e358f3fb7bdbe9a667b3d0103f761cabcdefab')
    ser = tx.serialize()
    assert ser == test


def test_axe_tx_wrong_spec_tx():
    test = bfh(WRONG_SPEC_TX)
    deser = lib_tx_axe.DeserializerAxe(test)
    tx = deser.read_tx()
    assert tx.version == 12255234
    assert tx.tx_type == 0
    extra = tx.extra_payload
    assert extra == b''
    ser = tx.serialize()
    assert ser == test


def test_axe_tx_serialize_wrong_tx_type():
    test = bfh(CB_TX)
    deser = lib_tx_axe.DeserializerAxe(test)
    tx = deser.read_tx()
    assert tx.tx_type == 5
    tx = tx._replace(tx_type=4)
    assert tx.tx_type == 4
    with pytest.raises(ValueError) as excinfo:
        ser = tx.serialize()
    assert ('Axe tx_type does not conform'
            ' with extra payload class' in str(excinfo.value))
