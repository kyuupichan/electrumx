#!/usr/bin/env python3

# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import asyncio
import logging
import os
import traceback

from server.env import Env
from server.controller import Controller


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

    controller = Controller(env)
    controller.start(loop)

    tasks = asyncio.Task.all_tasks(loop)
    try:
        loop.run_until_complete(asyncio.gather(*tasks))
    except asyncio.CancelledError:
        logging.warning('task cancelled; asyncio event loop closing')
    finally:
        controller.stop()
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
