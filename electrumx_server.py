#!/usr/bin/env python3
#
# Copyright (c) 2016, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Script to kick off the server.'''

import sys
import logging
import traceback

from electrumx import Controller, Env


class CompactFormatter(logging.Formatter):
    def format(self, record):
        record.name = record.name.split('.')[-1]
        return super().format(record)


def main():
    '''Set up logging and run the server.'''

    log_fmt = Env.default('LOG_FORMAT', '%(levelname)s:%(name)s:%(message)s')
    log = logging.getLogger('electrumx')
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(CompactFormatter(log_fmt))
    log.addHandler(handler)
    log.setLevel(logging.INFO)

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
