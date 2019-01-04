#!/usr/bin/env python3
#
# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Script to compact the history database.  This should save space and
will reset the flush counter to a low number, avoiding overflow when
the flush count reaches 65,536.

This needs to lock the database so ElectrumX must not be running -
shut it down cleanly first.

It is recommended you run this script with the same environment as
ElectrumX.  However it is intended to be runnable with just
DB_DIRECTORY and COIN set (COIN defaults as for ElectrumX).

If you use daemon tools, you might run this script like so:

   envdir /path/to/the/environment/directory ./compact_history.py

Depending on your hardware this script may take up to 6 hours to
complete; it logs progress regularly.

Compaction can be interrupted and restarted harmlessly and will pick
up where it left off.  However, if you restart ElectrumX without
running the compaction to completion, it will not benefit and
subsequent compactions will restart from the beginning.
'''

import asyncio
import logging
import sys
import traceback
from os import environ

from electrumx import Env
from electrumx.server.db import DB


async def compact_history():
    if sys.version_info < (3, 6):
        raise RuntimeError('Python >= 3.6 is required to run ElectrumX')

    environ['DAEMON_URL'] = ''   # Avoid Env erroring out
    env = Env()
    db = DB(env)
    await db.open_for_compacting()

    assert not db.first_sync
    history = db.history
    # Continue where we left off, if interrupted
    if history.comp_cursor == -1:
        history.comp_cursor = 0

    history.comp_flush_count = max(history.comp_flush_count, 1)
    limit = 8 * 1000 * 1000

    while history.comp_cursor != -1:
        history._compact_history(limit)

    # When completed also update the UTXO flush count
    db.set_flush_count(history.flush_count)

def main():
    logging.basicConfig(level=logging.INFO)
    logging.info('Starting history compaction...')
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(compact_history())
    except Exception:
        traceback.print_exc()
        logging.critical('History compaction terminated abnormally')
    else:
        logging.info('History compaction complete')


if __name__ == '__main__':
    main()
