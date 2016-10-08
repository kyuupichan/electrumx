# See the file "LICENSE" for information about the copyright
# and warranty status of this software.

import logging
import traceback

from aiohttp import web


class ElectrumRPCServer(object):
    '''ElectrumX's RPC server for localhost.'''

    def __init__(self, server):
        self.logger = logging.getLogger('RPCServer')
        self.logger.setLevel(logging.INFO)
        self.server = server

    async def request_handler(self, request):
        json_request = await request.json()
        try:
            err, result = await self.json_handler(json_request)
        except Exception as e:
            traceback.print_exc()
            err, result = 1, 'caught exception: {}'.format(e)

        id_ = request.get('id')
        if err is None:
            response = {
                'id': id_,
                'error': None,
                'result': result,
            }
        else:
            response = {
                'id': id_,
                'error': {'code': err, 'message': result},
                'result': None,
            }

        return web.json_response(response)

    async def json_handler(self, request):
        method = request.get('method')
        id_ = request.get('id')
        params = request.get('params', [])
        handler = getattr(self.server, 'handle_rpc_{}'.format(method), None)
        if not handler:
            return 1, 'unknown method "{}"'.format(method)
        else:
            return await handler(params)

    def tasks(self, port):
        self.logger.info('listening on port {:d}'.format(port))
        app = web.Application()
        app.router.add_post('/', self.request_handler)
        host = '0.0.0.0'
        loop = app.loop
        handler = app.make_handler()
        server = loop.create_server(handler, host, port)
        return [server, app.startup()]
