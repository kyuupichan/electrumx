import electrumx.lib.coins as coins


def test_bitcoin_cash():
    raw_header = bytes.fromhex(
        "00000020df975c121dcbc18bbb7ddfd0419fc368b45db86b48c87e0"
        "1000000000000000036ae3dd40a10a40d3050de13ca546a2f81589d"
        "e2d2f317925a43a115437e2381f5bf535b94da0118ac8df8c5"
    )
    height = 540000
    electrum_header = {
        'block_height': 540000,
        'version': 536870912,
        'prev_block_hash':
        '0000000000000000017ec8486bb85db468c39f41d0df7dbb8bc1cb1d125c97df',
        'merkle_root':
        '81237e4315a1435a9217f3d2e29d58812f6a54ca13de50300da4100ad43dae36',
        'timestamp': 1532215285,
        'bits': 402774676,
        'nonce': 3321400748
    }

    assert coins.BitcoinCash.electrum_header(
        raw_header, height) == electrum_header
