#!/usr/bin/env python3

from aiohttp import web
import aiohttp
import aiohttp_jinja2
import aioredis
import argparse
import asyncio
import jinja2
import os
import secrets

class ShadyBucksFrontEndDaemon:
    def __init__(self, **kwargs):
        self._app = web.Application(middlewares=[self.ensure_session_cookie])
        aiohttp_jinja2.setup(self._app,
            loader=jinja2.FileSystemLoader(os.path.join(os.getcwd() ,'website/templates')))

        self._app.add_routes([web.get('/app/login', self.get_login)])
        self._app.add_routes([web.post('/app/login', self.post_login)])
        self._app.add_routes([web.static('/static', os.path.join(os.getcwd() ,'website/static'))])

    async def _init_pools(self):
        self._redis_pool = aioredis.from_url("redis://redis", decode_responses=True)
        self._api_client_session = aiohttp.ClientSession()

    def run(self, path):
        asyncio.get_event_loop().run_until_complete(self._init_pools())
        web.run_app(self._app, path=path)

    @web.middleware    
    async def ensure_session_cookie(self, request, handler):
        sid = request.cookies.get('sid')
        nsid = None
        if not sid:
            nsid = sid = secrets.token_urlsafe()
            await self._redis_pool.setex('sid:{}'.format(sid), 2592000, '')
        csrf_token = secrets.token_urlsafe()
        await self._redis_pool.setex('csrf:{}'.format(csrf_token), 86400, sid)
        request['CSRF_TOKEN'] = csrf_token;
        request['SID'] = sid;
        resp = await handler(request)
        if nsid:
            resp.set_cookie('sid', nsid, max_age=2592000, httponly=True)
        return resp

    async def check_csrf_token(self, request, form_data):
        if not 'CSRF_TOKEN' in form_data:
            raise web.HTTPBadRequest()
        csrf_token = form_data['CSRF_TOKEN']
        # This should be a .getdel but aioredis doesn't support that yet
        expected_sid = await self._redis_pool.get('csrf:{}'.format(csrf_token))
        if expected_sid == request['SID']:
            await self._redis_pool.delete('csrf:{}'.format(csrf_token))
        else:
            raise web.HTTPBadRequest()

    async def get_login(self, request, failed = False):
        context = { 'CSRF_TOKEN': request['CSRF_TOKEN'] }
        return aiohttp_jinja2.render_template('frontpage-logged-out.html', request, context)

    async def post_login(self, request):
        data = await request.post()
        await self.check_csrf_token(request, data)
        login_resp = await self._api_client_session.post('http://api-endpoint:8080/api/login', data=data)
        if login_resp.status == 201:
            auth_token = await login_resp.text()
            await self._redis_pool.setex('sid:{}'.format(request['SID']), 2592000, auth_token)
            raise web.HTTPFound('/')
        else:
            return await self.get_login(request, True)

def main():
    arg_parser = argparse.ArgumentParser(description='ShadyBucks frontend server')
    arg_parser.add_argument('-P', '--port', help='TCP port to serve on.', default='8080')
    arg_parser.add_argument('-U', '--path', help='Unix file system path to serve on.')
    args = arg_parser.parse_args()

    daemon = ShadyBucksFrontEndDaemon(**vars(args))
    daemon.run(args.path)

if __name__ == '__main__':
    main()