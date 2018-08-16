# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Class for handling environment configuration and defaults.'''


from electrumx.lib.env_base import EnvBase


class Env(EnvBase):
    '''Wraps environment configuration.'''

    def __init__(self):
        super().__init__()
        self.db_dir = self.required('DB_DIRECTORY')
        self.db_engine = self.default('DB_ENGINE', 'leveldb')

        self.ssl_port = self.integer('SSL_PORT', 20214)
        self.ssl_certfile = self.required('SSL_CERTFILE')
        self.ssl_keyfile = self.required('SSL_KEYFILE')

        self.rpc_port = self.integer('RPC_PORT', 8001)

        self.tor_proxy_host = self.default('TOR_PROXY_HOST', 'localhost')
        self.tor_proxy_port = self.integer('TOR_PROXY_PORT', None)

        self.session_timeout = self.integer('SESSION_TIMEOUT', 600)
