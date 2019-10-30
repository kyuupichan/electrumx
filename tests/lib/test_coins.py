# Tests of lib/coins.py

import pytest

from electrumx.lib.coins import BitcoinSV
from electrumx.lib.script import OpCodes


coin = BitcoinSV

@pytest.mark.parametrize("script", (
    bytes([OpCodes.OP_RETURN]),
    bytes([OpCodes.OP_RETURN]) + bytes([2, 28, 50]),
    bytes([OpCodes.OP_0, OpCodes.OP_RETURN]),
    bytes([OpCodes.OP_0, OpCodes.OP_RETURN]) + bytes([2, 28, 50]),
))
def test_op_return(script):
    assert coin.hashX_from_script(script) is None


@pytest.mark.parametrize("script", (
    bytes([]),
    bytes([OpCodes.OP_1, OpCodes.OP_RETURN]) + bytes([2, 28, 50]),
    bytes([OpCodes.OP_0]),
    bytes([OpCodes.OP_0, OpCodes.OP_1]),
    bytes([OpCodes.OP_HASH160]),
))
def test_not_op_return(script):
    assert coin.hashX_from_script(script) is not None
