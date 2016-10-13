# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import logging
from os import environ

from lib.coins import Coin


class Env(object):
    '''Wraps environment configuration.'''

    class Error(Exception):
        pass

    def __init__(self):
        self.logger = logging.getLogger('Env')
        self.logger.setLevel(logging.INFO)
        coin_name = self.default('COIN', 'Bitcoin')
        network = self.default('NETWORK', 'mainnet')
        self.coin = Coin.lookup_coin_class(coin_name, network)
        self.db_dir = self.required('DB_DIRECTORY')
        self.cache_MB = self.integer('CACHE_MB', 1000)
        self.rpc_url = self.build_rpc_url()

    def default(self, envvar, default):
        return environ.get(envvar, default)

    def required(self, envvar):
        value = environ.get(envvar)
        if value is None:
            raise self.Error('required envvar {} not set'.format(envvar))
        return value

    def integer(self, envvar, default):
        value = environ.get(envvar)
        if value is None:
            return default
        try:
            return int(value)
        except:
            raise self.Error('cannot convert envvar {} value {} to an integer'
                             .format(envvar, value))

    def build_rpc_url(self):
        rpc_url = environ.get('RPC_URL')
        if not rpc_url:
            rpc_username = self.required('RPC_USERNAME')
            rpc_password = self.required('RPC_PASSWORD')
            rpc_host = self.required('RPC_HOST')
            rpc_port = self.default('RPC_PORT', self.coin.DEFAULT_RPC_PORT)
            rpc_url = ('http://{}:{}@{}:{}/'
                       .format(rpc_username, rpc_password, rpc_host, rpc_port))
        return rpc_url
