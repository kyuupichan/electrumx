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


SUPPRESS_MESSAGES = [
    'Fatal read error on socket transport',
    'Fatal write error on socket transport',
]

def main_loop():
    '''Start the server.'''
    if os.geteuid() == 0:
        raise Exception('DO NOT RUN AS ROOT! Create an unpriveleged user '
                        'account and use that')

    loop = asyncio.get_event_loop()
    #loop.set_debug(True)

    def on_signal(signame):
        '''Call on receipt of a signal to cleanly shutdown.'''
        logging.warning('received {} signal, initiating shutdown'
                        .format(signame))
        controller.initiate_shutdown()

    def on_exception(loop, context):
        '''Suppress spurious messages it appears we cannot control.'''
        message = context.get('message')
        if not message in SUPPRESS_MESSAGES:
            if not ('task' in context and
                    'accept_connection2()' in repr(context.get('task'))):
                loop.default_exception_handler(context)

    controller = Controller(Env())
    future = asyncio.ensure_future(controller.main_loop())

    # Install signal handlers
    for signame in ('SIGINT', 'SIGTERM'):
        loop.add_signal_handler(getattr(signal, signame),
                                partial(on_signal, signame))

    # Install exception handler
    loop.set_exception_handler(on_exception)
    loop.run_until_complete(future)
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
