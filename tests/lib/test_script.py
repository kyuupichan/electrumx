import pytest

from electrumx.lib.script import OpCodes, is_unspendable_legacy, is_unspendable_genesis


@pytest.mark.parametrize("script, iug", (
    (bytes([OpCodes.OP_RETURN]), False),
    (bytes([OpCodes.OP_RETURN]) + bytes([2, 28, 50]), False),
    (bytes([OpCodes.OP_0, OpCodes.OP_RETURN]), True),
    (bytes([OpCodes.OP_0, OpCodes.OP_RETURN]) + bytes([2, 28, 50]), True)
))
def test_op_return_legacy(script, iug):
    assert is_unspendable_legacy(script)
    assert is_unspendable_genesis(script) is iug


@pytest.mark.parametrize("script", (
    bytes([]),
    bytes([OpCodes.OP_1, OpCodes.OP_RETURN]) + bytes([2, 28, 50]),
    bytes([OpCodes.OP_0]),
    bytes([OpCodes.OP_0, OpCodes.OP_1]),
    bytes([OpCodes.OP_HASH160]),
))
def test_not_op_return(script):
    assert not is_unspendable_legacy(script)
    assert not is_unspendable_genesis(script)
