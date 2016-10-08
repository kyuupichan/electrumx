#!/usr/bin/env python3

# See the file "COPYING" for information about the copyright
# and warranty status of this software.

import asyncio
import logging
import os
import traceback

from server.env import Env
from server.server import Server


def main_loop():
    '''Get tasks; loop until complete.'''
    if os.geteuid() == 0:
        raise Exception('DO NOT RUN AS ROOT! Create an unpriveleged user '
                        'account and use that')

    env = Env()
    logging.info('switching current directory to {}'.format(env.db_dir))
    os.chdir(env.db_dir)

    loop = asyncio.get_event_loop()
    try:
        server = Server(env, loop)
        tasks = server.async_tasks()
        loop.run_until_complete(asyncio.gather(*tasks))
    finally:
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
