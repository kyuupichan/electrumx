#!/usr/bin/env python3
#
# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Script to kick off the server.'''

import asyncio
import logging
import os
import signal
import traceback
from functools import partial

from server.env import Env
from server.protocol import BlockServer


def close_loop(loop):
    '''Close the loop down cleanly.  Cancel and collect remaining tasks.'''
    tasks = asyncio.Task.all_tasks()
    for task in tasks:
        task.cancel()

    try:
        loop.run_until_complete(asyncio.gather(*tasks))
    except asyncio.CancelledError:
        pass

    loop.close()


def main_loop():
    '''Start the server.'''
    if os.geteuid() == 0:
        raise Exception('DO NOT RUN AS ROOT! Create an unpriveleged user '
                        'account and use that')

    loop = asyncio.get_event_loop()
    #loop.set_debug(True)

    def on_signal(signame):
        '''Call on receipt of a signal to cleanly shutdown.'''
        logging.warning('received {} signal, preparing to shut down'
                        .format(signame))
        loop.stop()

    # Install signal handlers
    for signame in ('SIGINT', 'SIGTERM'):
        loop.add_signal_handler(getattr(signal, signame),
                                partial(on_signal, signame))

    server = BlockServer(Env())
    server.start()
    try:
        loop.run_forever()
    finally:
        server.stop()
    close_loop(loop)


def main():
    '''Set up logging, enter main loop.'''
    logging.basicConfig(level=logging.INFO)
    logging.info('ElectrumX server starting')
    try:
        main_loop()
    except Exception:
        traceback.print_exc()
        logging.critical('ElectrumX server terminated abnormally')
    else:
        logging.info('ElectrumX server terminated normally')


if __name__ == '__main__':
    main()
