# Copyright (c) 2017, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Class for server environment configuration and defaults.'''


from os import environ

import lib.util as lib_util


class EnvBase(lib_util.LoggedClass):
    '''Wraps environment configuration.'''

    class Error(Exception):
        pass

    def __init__(self):
        super().__init__()
        self.allow_root = self.boolean('ALLOW_ROOT', False)
        self.host = self.default('HOST', 'localhost')
        self.rpc_host = self.default('RPC_HOST', 'localhost')
        self.loop_policy = self.event_loop_policy()

    def default(self, envvar, default):
        return environ.get(envvar, default)

    def boolean(self, envvar, default):
        default = 'Yes' if default else ''
        return bool(self.default(envvar, default).strip())

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
        except Exception:
            raise self.Error('cannot convert envvar {} value {} to an integer'
                             .format(envvar, value))

    def obsolete(self, envvars):
        bad = [envvar for envvar in envvars if environ.get(envvar)]
        if bad:
            raise self.Error('remove obsolete environment variables {}'
                             .format(bad))

    def event_loop_policy(self):
        policy = self.default('EVENT_LOOP_POLICY', None)
        if policy is None:
            return None
        if policy == 'uvloop':
            import uvloop
            return uvloop.EventLoopPolicy()
        raise self.Error('unknown event loop policy "{}"'.format(policy))

    def cs_host(self, *, for_rpc):
        '''Returns the 'host' argument to pass to asyncio's create_server
        call.  The result can be a single host name string, a list of
        host name strings, or an empty string to bind to all interfaces.

        If rpc is True the host to use for the RPC server is returned.
        Otherwise the host to use for SSL/TCP servers is returned.
        '''
        host = self.rpc_host if for_rpc else self.host
        result = [part.strip() for part in host.split(',')]
        if len(result) == 1:
            result = result[0]
        # An empty result indicates all interfaces, which we do not
        # permitted for an RPC server.
        if for_rpc and not result:
            result = 'localhost'
        return result
