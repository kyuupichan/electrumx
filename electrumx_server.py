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
from server.controller import Controller


def cancel_tasks(loop):
    # Cancel and collect the remaining tasks
    tasks = asyncio.Task.all_tasks()
    for task in tasks:
        task.cancel()

    try:
        loop.run_until_complete(asyncio.gather(*tasks))
    except asyncio.CancelledError:
        pass


def main_loop():
    '''Get tasks; loop until complete.'''
    if os.geteuid() == 0:
        raise Exception('DO NOT RUN AS ROOT! Create an unpriveleged user '
                        'account and use that')

    env = Env()
    logging.info('switching current directory to {}'.format(env.db_dir))
    os.chdir(env.db_dir)

    loop = asyncio.get_event_loop()
    #loop.set_debug(True)

    controller = Controller(loop, env)

    # Signal handlers
    def on_signal(signame):
        '''Call on receipt of a signal to cleanly shutdown.'''
        logging.warning('received {} signal, preparing to shut down'
                        .format(signame))
        loop.stop()

    for signame in ('SIGINT', 'SIGTERM'):
        loop.add_signal_handler(getattr(signal, signame),
                                partial(on_signal, signame))

    controller.start()
    try:
        loop.run_forever()
    finally:
        controller.stop()
        cancel_tasks(loop)

    loop.close()


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
