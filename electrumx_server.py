#!/usr/bin/env python3
"""Script to kick off the server."""

import logging
import traceback

from server.controller import Controller
from server.env import Env


def main():
    """Set up logging and run the server."""
    logging.basicConfig(level=logging.INFO)
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
