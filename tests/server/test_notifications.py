import asyncio

import pytest

from electrumx.server.controller import Notifications


@pytest.mark.asyncio
async def test_simple_mempool():
    n = Notifications()
    notified = []
    async def notify(height, touched):
        notified.append((height, touched))
    await n.start(5, notify)

    mtouched = {'a', 'b'}
    btouched = {'b', 'c'}
    await n.on_mempool(mtouched, 6)
    assert notified == [(5, set())]
    await n.on_block(btouched, 6)
    assert notified == [(5, set()), (6, set.union(mtouched, btouched))]


@pytest.mark.asyncio
async def test_enter_mempool_quick_blocks_2():
    n = Notifications()
    notified = []
    async def notify(height, touched):
        notified.append((height, touched))
    await n.start(5, notify)

    # Suppose a gets in block 6 and blocks 7,8 found right after and
    # the block processer processes them together.
    await n.on_mempool({'a'}, 5)
    assert notified == [(5, set()), (5, {'a'})]
    # Mempool refreshes with daemon on block 6
    await n.on_mempool({'a'}, 6)
    assert notified == [(5, set()), (5, {'a'})]
    # Blocks 6, 7 processed together
    await n.on_block({'a', 'b'}, 7)
    assert notified == [(5, set()), (5, {'a'})]
    # Then block 8 processed
    await n.on_block({'c'}, 8)
    assert notified == [(5, set()), (5, {'a'})]
    # Now mempool refreshes
    await n.on_mempool(set(), 8)
    assert notified == [(5, set()), (5, {'a'}), (8, {'a', 'b', 'c'})]
