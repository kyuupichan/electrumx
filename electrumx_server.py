#!/usr/bin/env python3
#
# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Script to kick off the server.'''

import logging
import traceback

from server.env import Env
from server.controller import Controller


def main():
    '''Set up logging and run the server.'''
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)-9s %(message)-100s '
                               '%(name)s [%(filename)s:%(lineno)d]')
    logging.info('ElectrumX server starting')
    try:
        controller = Controller(Env())
        controller.run()
    except Exception:
        traceback.print_exc()
        logging.critical('ElectrumX server terminated abnormally')
    else:
        logging.info('ElectrumX server terminated normally')


if __name__ == '__main__':
    main()
