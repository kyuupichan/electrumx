import logging
from electrumx.lib.util import unpack_byte, unpack_varint

OP_RETURN = 0x6a
STAKING_TX_HEADER = 0x53
STAKING_TX_DEPOSIT_SUBHEADER = 0x44
STAKING_TX_BURN_SUBHEADER = 0x42
MIN_STAKING_AMOUNT = 500000000

def validate_stake(public_key, tx_outputs, env):
    #TODO: get rid off warrning aiohttp/client.py:977: RuntimeWarning: coroutine 'noop' was never awaited

    try:
        # [op][push_size][header][subheader][ stake_utxo_index ...][stake_type]
        op, = unpack_byte(public_key[0:1])
        push_size, = unpack_byte(public_key[1:2])
        header, = unpack_byte(public_key[2:3])
        subheader, = unpack_byte(public_key[3:4])

        NUM_STAKING_PERIODS = len(env.coin.STAKING_INTEREST_INFO)

        stake_utxo_index = unpack_varint(public_key[4:-1])
        stake_period, = unpack_byte(public_key[-1:])
        
        if not(op == OP_RETURN or header == STAKING_TX_HEADER or subheader == STAKING_TX_DEPOSIT_SUBHEADER or len(public_key)-4 < 2) \
            or stake_utxo_index == 0 or stake_utxo_index >= len(tx_outputs) or tx_outputs[stake_utxo_index].value < MIN_STAKING_AMOUNT \
            or stake_period >= NUM_STAKING_PERIODS:
            return -1

        return stake_utxo_index

    except:
        return -1