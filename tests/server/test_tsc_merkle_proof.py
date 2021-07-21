import asyncio
import logging

from electrumx.lib.hash import hash_to_hex_str, hex_str_to_hash
from electrumx.lib.merkle import Merkle
from electrumx.server.session import ElectrumX, SessionManager


async def mock_raw_header(height):
    return bytes.fromhex(
        "00000020841786a5a2649948e62cd1ed87a8e87a3a51a181a0e814b7750cd5c2fd9fee79e71f85ac0118d8c88f5b78d5711f45f84c003d3d551f8e5bfea667b296b548e60b0af860ffff7f2001000000")


async def mock_daemon_request(method, *args):
    assert method == 'getrawtransaction'
    assert args == ("ed5a81e439e1cd9139ddb81da80bfa7cfc31e323aea544ca92a9ee1d84b9fb2f", False)
    rawtx = "020000000103fd0a88731b693b5e61bf5c584f9c0b528816b4592cac35ff191f79fe8a6c6d0000000049483045022100d025934ed22c4de8d2b1750398342020fa7bc2cb64db323144c1a69819e0c27e02202a9e0184b0e7048ba4a4c46eb8dd2b5a40d935cb091f0b1ed62ee0a80845de5041feffffff0200e1f505000000001976a914ef2a6151eb1b86060a28809fccae60915678409988ac40101024010000001976a9149b69bac6a7e888fccaa0b69f5febc81f3d924c8388ac89000000"
    return rawtx


async def mock_tx_hashes_at_blockheight(height):
    COST = 0.2502
    hashes = ["aec10c10352cd6a519f5dc9ceda52aa8ef17570f6730d7d2347dfc1f5c963196",
        "b2378093f853cbc635153950d8f3bcec1a785e3a62deec652533c7d8e8613866",
        "d28df756c9cc2beadce3ef692a9e6419c4ef73a12cbdd56b23acd7452d320022",
        "5c52e28bc0961fb5cc552023d4ab7a68320e4dae567c1d7d58a185bd84e12a3d",
        "ed5a81e439e1cd9139ddb81da80bfa7cfc31e323aea544ca92a9ee1d84b9fb2f"]
    hashes = [hex_str_to_hash(x) for x in hashes]
    return hashes, COST


async def mock_merkle_branch(height, tx_hashes, tx_pos, tsc_format):
    COST = 0.0008
    merkle = Merkle()
    branch, root = merkle.branch_and_root(tx_hashes, tx_pos, tsc_format=tsc_format)

    def converter(hash):
        if hash == b"*":
            return hash.decode()
        else:
            return hash_to_hex_str(hash)

    branch = [converter(hash) for hash in branch]
    return branch, root, COST


class MockSessionManager(SessionManager):
    def __init__(self):
        self.logger = logging.getLogger("mock-session-manager")
        pass


class MockElectrumX(ElectrumX):
    def __init__(self):  # forego complexities of initialization
        self.session_mgr = MockSessionManager()
        pass

    def bump_cost(self, cost):
        pass


def test_tsc_merkle_proof():
    """The test set comprises a block with 5 transactions total and the merkle proof is for the
    5th transaction (at index=4). This should result in two 'duplicate' hashes in the final TSC
    format merkle branch."""

    async def test_transaction_tsc_merkle():
        mock_electrumx = MockElectrumX()
        mock_electrumx.session_mgr.raw_header = mock_raw_header
        mock_electrumx.session_mgr.daemon_request = mock_daemon_request
        mock_electrumx.session_mgr.tx_hashes_at_blockheight = mock_tx_hashes_at_blockheight
        mock_electrumx.session_mgr._merkle_branch = mock_merkle_branch

        # targetType == block_hash
        result = await mock_electrumx.transaction_tsc_merkle(
            tx_hash="ed5a81e439e1cd9139ddb81da80bfa7cfc31e323aea544ca92a9ee1d84b9fb2f", height=1,
            txid_or_tx="txid", target_type="block_hash")
        assert result == {
            'composite': False,
            'index': 4,
            'nodes': [
                '*',
                '*',
                '80c0100bc080eb0d2e205dc687056dc13c2079d0959c70cad8856fea88c74aba'],
            'proofType': 'branch',
            'target': '29442cb6e2ee547fcf5200dfb1b4018f4fc5ce5a220bb5ec3729a686885692fc',
            'targetType': 'block_hash',
            'txOrId': 'ed5a81e439e1cd9139ddb81da80bfa7cfc31e323aea544ca92a9ee1d84b9fb2f'
        }

        # targetType == merkle_root
        result = await mock_electrumx.transaction_tsc_merkle(
            tx_hash="ed5a81e439e1cd9139ddb81da80bfa7cfc31e323aea544ca92a9ee1d84b9fb2f", height=1,
            txid_or_tx="txid", target_type="merkle_root")
        assert result == {
            'composite': False,
            'index': 4,
            'nodes': [
                '*',
                '*',
                '80c0100bc080eb0d2e205dc687056dc13c2079d0959c70cad8856fea88c74aba'],
            'proofType': 'branch',
            'target': 'e648b596b267a6fe5b8e1f553d3d004cf8451f71d5785b8fc8d81801ac851fe7',
            'targetType': 'merkle_root',
            'txOrId': 'ed5a81e439e1cd9139ddb81da80bfa7cfc31e323aea544ca92a9ee1d84b9fb2f'
        }

        # targetType == block_header
        result = await mock_electrumx.transaction_tsc_merkle(
            tx_hash="ed5a81e439e1cd9139ddb81da80bfa7cfc31e323aea544ca92a9ee1d84b9fb2f", height=1,
            txid_or_tx="txid", target_type="block_header")
        assert result == {
            'composite': False,
            'index': 4,
            'nodes': [
                '*',
                '*',
                '80c0100bc080eb0d2e205dc687056dc13c2079d0959c70cad8856fea88c74aba'],
            'proofType': 'branch',
            'target': '00000020841786a5a2649948e62cd1ed87a8e87a3a51a181a0e814b7750cd5c2fd9fee79e71f85ac0118d8c88f5b78d5711f45f84c003d3d551f8e5bfea667b296b548e60b0af860ffff7f2001000000',
            'targetType': 'block_header',
            'txOrId': 'ed5a81e439e1cd9139ddb81da80bfa7cfc31e323aea544ca92a9ee1d84b9fb2f'
        }

        # txOrId == 'tx'
        result = await mock_electrumx.transaction_tsc_merkle(
            tx_hash="ed5a81e439e1cd9139ddb81da80bfa7cfc31e323aea544ca92a9ee1d84b9fb2f", height=1,
            txid_or_tx="tx", target_type="block_header")
        assert result == {
            'composite': False,
            'index': 4,
            'nodes': [
                '*',
                '*',
                '80c0100bc080eb0d2e205dc687056dc13c2079d0959c70cad8856fea88c74aba'],
            'proofType': 'branch',
            'target': '00000020841786a5a2649948e62cd1ed87a8e87a3a51a181a0e814b7750cd5c2fd9fee79e71f85ac0118d8c88f5b78d5711f45f84c003d3d551f8e5bfea667b296b548e60b0af860ffff7f2001000000',
            'targetType': 'block_header',
            'txOrId': '020000000103fd0a88731b693b5e61bf5c584f9c0b528816b4592cac35ff191f79fe8a6c6d0000000049483045022100d025934ed22c4de8d2b1750398342020fa7bc2cb64db323144c1a69819e0c27e02202a9e0184b0e7048ba4a4c46eb8dd2b5a40d935cb091f0b1ed62ee0a80845de5041feffffff0200e1f505000000001976a914ef2a6151eb1b86060a28809fccae60915678409988ac40101024010000001976a9149b69bac6a7e888fccaa0b69f5febc81f3d924c8388ac89000000'
        }

    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.gather(
        *[
            test_transaction_tsc_merkle(),
        ]
    ))
