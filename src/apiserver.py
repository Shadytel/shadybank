#!/usr/bin/env python3

from aiohttp import web
import aiohttp_jinja2
import aioredis
import argparse
import asyncio
import asyncpg
import base64
import hashlib
from passlib.hash import argon2
import os
import secrets
import time

class ShadyBucksAPIDaemon:
    def __init__(self, **kwargs):
        self._app = web.Application()
        #self._app.add_routes([web.post('/api/register', self.post_register)])
        self._app.add_routes([web.post('/api/login', self.post_login)])
        self._app.add_routes([web.post('/api/logout', self.post_logout)])

        self._app.add_routes([web.get('/api/check', self.get_check_credentials)])
        self._app.add_routes([web.get('/api/balance', self.get_balance)])
        #self._app.add_routes([web.get('/api/transactions', self.get_transactions)])

        # Merchant APIs
        #self._app.add_routes([web.post('/api/authorize', self.post_authorize)])
        #self._app.add_routes([web.post('/api/capture', self.post_capture)])
        #self._app.add_routes([web.post('/api/void', self.post_void)])
        #self._app.add_routes([web.post('/api/reverse', self.post_reverse)])
        #self._app.add_routes([web.post('/api/credit', self.post_credit)])

        self._app.add_routes([web.static('/static', '/app/website/static')])

    async def _init_db_pool(self):
        self._psql_pool = await asyncpg.create_pool(database='shadybucks')
        self._redis_pool = aioredis.from_url("redis://redis", decode_responses=True)

    def run(self, path):
        asyncio.get_event_loop().run_until_complete(self._init_db_pool())
        web.run_app(self._app, path=path)

    async def handle_login_success(self, request, auth_row):
        auth_token = secrets.token_urlsafe()
        await self._psql_pool.execute('UPDATE secrets SET last_used = NOW() where id = $1', auth_row['id'])
        await self._redis_pool.setex('auth_token:{}'.format(auth_token), 2592000, auth_row['account_id'])
        resp = web.Response(status=201, text=auth_token)
        return resp

    def get_request_auth_token(self, request):
        if not 'Authorization' in request.headers:
            raise web.HTTPUnauthorized()
        
        tokens = request.headers['Authorization'].split(' ')
        if len(tokens) != 2 or tokens[0].lower() != 'bearer':
            raise web.HTTPUnauthorized()
        
        return tokens[1]
        
    async def post_login(self, request):
        args = await request.post()
        auth_rows = None

        if 'pan' in args:
            auth_rows = await self._psql_pool.fetch('SELECT s.account_id, s.id, s.type, s.secret ' \
                'FROM cards c, secrets s where c.pan = $1 AND s.account_id = c.account_id', args['pan'])
        elif 'account_id' in args:
            auth_rows = await self._psql_pool.fetch('SELECT s.account_id, s.id, s.type, s.secret ' \
                'FROM secrets s where s.account_id = $1', int(args['account_id']))
        else:
            raise web.HTTPBadRequest()
        if auth_rows:
            for auth_row in auth_rows:
                if 'password' in args and auth_row['type'] == 'password':
                    if argon2.verify(args['password'], auth_row['secret']):
                        return await self.handle_login_success(request, auth_row)
        raise web.HTTPUnauthorized()

    async def post_logout(self, request):
        try:
            auth_token = self.get_request_auth_token(request)
            # TODO: Check for valid auth_token format?
            if auth_token:
                await self._redis_pool.delete('auth_token:{}'.format(auth_token))
        except:
            pass
        resp = web.Response(status=204)
        return resp

    async def get_check_credentials(self, request):
        await self.get_auth_account(request)
        return web.Response(status=204)

    async def get_auth_account(self, request):
        auth_token = self.get_request_auth_token(request)
        if auth_token:
            aid = await self._redis_pool.get('auth_token:{}'.format(auth_token))
            return int(aid)
        raise web.HTTPUnauthorized()

    async def get_balance(self, request):
        acct = await self.get_auth_account(request)
        balance = await self._psql_pool.fetchval('SELECT balance FROM accounts WHERE id = $1', acct);
        return web.json_response({ 'account': acct, 'balance': int(balance * 100) })

    #async def get_transactions(self, request):
    #    acct = await self.get_auth_account()
    #    transactions = await self._psql_pool.fetch('SELECT s')

    async def _get_customer(self, request):
        if 'magstripe' in request:
            # Parse magstripe data into track 1 and track 3
            pass

        if 'track1' in request:
            card_data = parse_track(request.track1)
            card_data = self._psql_pool.fetch()
        raise web.HTTPBadRequest()
    
    #async def post_authorize(self, request):
    #    merchant = await self.get_auth_account()
    #    customer = await self._get_customer(request)

def main():
    arg_parser = argparse.ArgumentParser(description='ShadyBucks API server')
    arg_parser.add_argument('-P', '--port', help='TCP port to serve on.', default='8080')
    arg_parser.add_argument('-U', '--path', help='Unix file system path to serve on.')
    args = arg_parser.parse_args()

    daemon = ShadyBucksAPIDaemon(**vars(args))
    daemon.run(args.path)

if __name__ == '__main__':
    main()
