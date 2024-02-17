#!/usr/bin/env python3

from aiohttp import web
import aioredis
import argparse
import asyncio
import asyncpg
import base64
import hashlib
from passlib.hash import argon2
import pyotp
import os
import re
import secrets
from datetime import datetime
from datetime import timedelta

track1_re = re.compile(r'(?a)%B(?P<pan>\d{8,19})\^(?P<name>.*)\^(?P<exp>\d{4})(?P<svc>\d{3})(?P<dd1>.*?)\?')
track2_re = re.compile(r'(?a);(?P<pan>\d{8,19})=(?P<exp>\d{4})(?P<svc>\d{3})(?P<dd2>.*?)\?')

def parse_track1(track):
    m = track1_re.search(track)
    if not m:
        return None
    return {
        'track': 1,
        'pan': m.group('pan'),
        'name': m.group('name'),
        'exp': m.group('exp'),
        'svc': m.group('svc'),
        'dd1': m.group('dd1')
    }

def parse_track2(track):
    m = track2_re.search(track)
    if not m:
        return None
    return {
        'track': 2,
        'pan': m.group('pan'),
        'exp': m.group('exp'),
        'svc': m.group('svc'),
        'dd2': m.group('dd2')
    }

class ShadyBucksAPIDaemon:
    def __init__(self, **kwargs):
        self._app = web.Application()
        #self._app.add_routes([web.post('/api/register', self.post_register)])
        self._app.add_routes([web.post('/api/login', self.post_login)])
        self._app.add_routes([web.post('/api/logout', self.post_logout)])

        self._app.add_routes([web.get('/api/check', self.get_check_credentials)])
        self._app.add_routes([web.get('/api/balance', self.get_balance)])
        self._app.add_routes([web.get('/api/transactions', self.get_transactions)])
        self._app.add_routes([web.get('/api/authorizations', self.get_authorizations)])

        # Merchant APIs
        self._app.add_routes([web.post('/api/authorize', self.post_authorize)])
        self._app.add_routes([web.post('/api/capture', self.post_capture)])
        self._app.add_routes([web.post('/api/void', self.post_void)])
        self._app.add_routes([web.post('/api/reverse', self.post_reverse)])
        self._app.add_routes([web.post('/api/credit', self.post_credit)])

        # Admin APIs
        self._app.add_routes([web.post('/api/activate', self.post_activate)])

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

    def _get_request_auth_token(self, request):
        if not 'Authorization' in request.headers:
            raise web.HTTPUnauthorized()

        tokens = request.headers['Authorization'].split(' ')
        if len(tokens) != 2 or tokens[0].lower() != 'bearer':
            raise web.HTTPUnauthorized()

        return tokens[1]

    async def _check_ratelimit(self, key, limit, expiration_in_secs):
        key = 'rate_limit:{}'.format(key)
        val = await self._redis_pool.incr(key)
        await self._redis_pool.expire(key, expiration_in_secs)
        if val > limit:
            raise web.HTTPUnauthorized()
        
    async def _check_otp_ratelimit(self, pan):
        key = 'otp:{}'.format(pan)
        await self._check_ratelimit(key, 5, 600)

    async def _check_merchant_ratelimit(self, account_id):
        await self._check_ratelimit('merchant:{}'.format(account_id), 3, 30)
    
    async def post_login(self, request):
        args = await request.post()
        auth_rows = None

        if ('magstripe' in args and len(args['magstripe'])) or \
            ('track1' in args and len(args['track1'])) or \
            ('track2' in args and len(args['track2'])):
            card_data = self._get_account_from_magstripe(args)
            args['pan'] = card_data['card']['pan']

        if 'pan' in args:
            auth_rows = await self._psql_pool.fetch('SELECT s.account_id, s.id, s.type, s.secret ' \
                'FROM cards c, secrets s where c.pan = $1 AND s.account_id = c.account_id', args['pan'])
            if len(args['otp']):
                self._check_otp_ratelimit(args['pan'])
        elif 'account_id' in args:
            auth_rows = await self._psql_pool.fetch('SELECT s.account_id, s.id, s.type, s.secret ' \
                'FROM secrets s where s.account_id = $1', int(args['account_id']))
            if len(args['otp']):
                self._check_otp_ratelimit(args['account_id'])
        else:
            raise web.HTTPBadRequest()

        if auth_rows:
            for auth_row in auth_rows:
                if 'password' in args and len(args['password']) and auth_row['type'] == 'password':
                    if argon2.verify(args['password'], auth_row['secret']):
                        return await self.handle_login_success(request, auth_row)
                if 'pin' in args and len(args['pin']) and auth_row['type'] == 'password':
                    if args['pin'] == auth_row['secret']:
                        return await self.handle_login_success(request, auth_row)
                if 'otp' in args and len(args['otp']) and auth_row['type'] == 'totp':
                    # Try Google Authenticator codes first, which ignore the interval we specify
                    otp_obj = pyotp.TOTP(auth_row['secret'], interval=30)
                    if otp_obj.verify(args['otp'], valid_window=2):
                        return await self.handle_login_success(request, auth_row)
                    # Try the interval we specified
                    otp_obj = pyotp.TOTP(auth_row['secret'], interval=60)
                    if otp_obj.verify(args['otp'], valid_window=1):
                        return await self.handle_login_success(request, auth_row)
        raise web.HTTPUnauthorized()

    async def post_logout(self, request):
        try:
            auth_token = self._get_request_auth_token(request)
            # TODO: Check for valid auth_token format?
            if auth_token:
                await self._redis_pool.delete('auth_token:{}'.format(auth_token))
        except:
            pass
        resp = web.Response(status=204)
        return resp

    async def get_check_credentials(self, request):
        await self._get_auth_account(request)
        return web.Response(status=204)

    async def _get_auth_account(self, request):
        auth_token = self._get_request_auth_token(request)
        if auth_token:
            aid = await self._redis_pool.get('auth_token:{}'.format(auth_token))
            return int(aid)
        raise web.HTTPUnauthorized()

    async def _get_account_data(self, account_id):
        return await self._psql_pool.fetchrow('SELECT * FROM accounts WHERE id = $1', account_id);

    async def get_balance(self, request):
        acct = await self._get_auth_account(request)
        name, balance, available = await self._psql_pool.fetchrow('SELECT name, balance, available FROM accounts WHERE id = $1', acct);
        return web.json_response({ 'account': acct, 'name': name, 'balance': float(balance), 'available': float(available) })

    async def get_transactions(self, request):
        acct = await self._get_auth_account(request)
        transaction_rows = await self._psql_pool.fetch('SELECT t.*, ca.name as cname, da.name as dname FROM transactions t, accounts ca, accounts da ' \
            'WHERE (credit_account = $1 OR debit_account = $1) AND ca.id = t.credit_account AND da.id = t.debit_account ORDER BY t.timestamp DESC', acct);
        transactions = []
        for transaction in transaction_rows:
            if transaction['debit_account'] == acct:
                transactions.append({ 'timestamp': str(transaction['timestamp']), 'amount': float(transaction['amount']),
                    'type': 'debit', 'subtype': transaction['type'], 'counterparty': transaction['cname'], 
                    'auth_code': transaction['auth_code'], 'description': transaction['description'] or '' })
            else:
                transactions.append({ 'timestamp': str(transaction['timestamp']), 'amount': float(transaction['amount']),
                    'type': 'credit', 'subtype': transaction['type'], 'counterparty': transaction['dname'], 
                    'auth_code': transaction['auth_code'], 'description': transaction['description'] or ''})
        return web.json_response(transactions)

    async def get_authorizations(self, request):
        acct = await self._get_auth_account(request)
        authorization_rows = await self._psql_pool.fetch('SELECT a.*, ca.name as cname, da.name as dname FROM authorizations a, accounts ca, accounts da ' \
            'WHERE (credit_account = $1 OR debit_account = $1) AND a.status = \'pending\' AND ' \
            'ca.id = a.credit_account AND da.id = a.debit_account ORDER BY a.timestamp DESC', acct);
        authorizations = []
        for authorization in authorization_rows:
            if authorization['debit_account'] == acct:
                authorization.append({ 'timestamp': str(authorization['timestamp']), 'expires': str(authorization['expires']),
                    'authorized_debit_amount': float(authorization['authorized_debit_amount']),
                    'type': 'debit', 'counterparty': authorization['cname'], 
                    'auth_code': authorization['auth_code'] })
            else:
                authorizations.append({ 'timestamp': str(authorization['timestamp']), 'expires': str(authorization['expires']),
                    'authorized_debit_amount': float(authorization['authorized_debit_amount']),
                    'type': 'credit', 'counterparty': authorization['dname'], 
                    'auth_code': authorization['auth_code'] })
        return web.json_response(authorizations)

    async def _get_account_from_magstripe(self, args):
        card_data = None

        if 'magstripe' in args:
            card_data = parse_track1(args['magstripe'])
            if not card_data:
                card_data = parse_track2(args['magstripe'])
        elif 'track1' in args:
            card_data = parse_track1(args['track1'])
        elif 'track2' in args:
            card_data = parse_track2(args['track2'])

        if not card_data:
            raise web.HTTPBadRequest()

        card_row = await self._psql_pool.fetchrow('SELECT * FROM cards WHERE pan = $1 AND expires = $2',
            card_data['pan'], card_data['exp'])
        if not card_row:
            raise web.HTTPNotFound()
        if card_data['track'] == 1 and card_data['dd1'] == card_row['dd1']:
            return { 'account': card_row['account_id'], 'status': card_row['status'], 'card': card_data }
        elif card_data['track'] == 2 and card_data['dd2'] == card_row['dd2']:
            return { 'account': card_row['account_id'], 'status': card_row['status'], 'card': card_data }
        else:
            raise web.HTTPNotFound()

    async def post_authorize(self, request):
        args = await request.post()
        if not 'amount' in args:
            raise web.HTTPBadRequest()
        amount = round(float(args['amount']), 2)
        if amount <= 0:
            raise web.HTTPBadRequest()
        merchant_data = await self._get_account_data(await self._get_auth_account(request))

        card_data = {}

        if ('magstripe' in args and len(args['magstripe'])) or \
            ('track1' in args and len(args['track1'])) or \
            ('track2' in args and len(args['track2'])):
            card_data = await self._get_account_from_magstripe(args)
        elif ('pan' in args and len(args['pan'])) and \
            (('otp' in args and len(args['otp'])) or ('shotp' in args and len(args['shotp']))):
            card_row = await self._psql_pool.fetchrow('SELECT * FROM cards WHERE pan = $1', args['pan'])
            if not card_row:
                raise web.HTTPNotFound()
            card_data = { 'account': card_row['account_id'], 'status': card_row['status'], 'card': { 'pan': args['pan'] } }
            self._check_otp_ratelimit(args['pan'])
            auth_rows = await self._psql_pool.fetch('SELECT s.account_id, s.id, s.type, s.secret ' \
                'FROM secrets s where s.account_id = $1 and s.type =\'totp\'', card_row['account_id'])
            auth_match = False
            for auth_row in auth_rows:
                # Try Google Authenticator codes first, which ignore the interval we specify
                otp_obj = pyotp.TOTP(auth_row['secret'], interval=30)
                if ('otp' in args and len(args['otp'])) and otp_obj.verify(args['otp'], valid_window=2):
                    auth_match = True
                    break
                elif ('shotp' in args and len(args['shotp'])) and \
                    (otp_obj.now()[0:4] == args['shotp'] or \
                     otp_obj.at(datetime.now() - timedelta(seconds=30))[0:4] == args['shopt'] or \
                     otp_obj.at(datetime.now() - timedelta(seconds=60))[0:4] == args['shopt']):
                    auth_match = True
                    break
                # Try the interval we specified
                otp_obj = pyotp.TOTP(auth_row['secret'], interval=60)
                if ('otp' in args and len(args['otp'])) and otp_obj.verify(args['otp'], valid_window=1):
                    auth_match = True
                    break
                elif ('shotp' in args and len(args['shotp'])) and \
                    (otp_obj.now()[0:4] == args['shotp'] or \
                     otp_obj.at(datetime.now() - timedelta(seconds=60))[0:4] == args['shopt']):
                    auth_match = True
                    break
            if not auth_match:
                raise web.HTTPForbidden()
        else:
            raise web.HTTPBadRequest()

        if card_data['status'] != 'activated':
            raise web.HTTPForbidden()
        cust_data = await self._get_account_data(card_data['account'])
        if amount > cust_data['available']:
            raise web.HTTPForbidden()
        auth_code = str(secrets.randbelow(1000000)).zfill(6)
        async with self._psql_pool.acquire() as con:
            async with con.transaction():
                await con.execute('INSERT INTO authorizations (pan, auth_code, debit_account, credit_account, authorized_debit_amount) ' \
                    'VALUES($1, $2, $3, $4, $5)', card_data['card']['pan'], auth_code, cust_data['id'], merchant_data['id'], amount);
                await con.execute('UPDATE accounts SET available = available - $1, last_updated = NOW() WHERE id = $2',
                    amount, cust_data['id'])
        return web.Response(text=auth_code)

    async def post_capture(self, request):
        args = await request.post()
        if (not 'amount' in args) or (not 'auth_code' in args):
            raise web.HTTPBadRequest()
        amount = round(float(args['amount']), 2)
        if amount <= 0:
            raise web.HTTPBadRequest()
        merchant_data = await self._get_account_data(await self._get_auth_account(request))
        async with self._psql_pool.acquire() as con:
            async with con.transaction():
                auth_row = await con.fetchrow('SELECT * from authorizations WHERE credit_account = $1 ' \
                    'AND auth_code = $2 AND expires > NOW()',
                    merchant_data['id'], args['auth_code'])
                if not auth_row:
                    raise web.HTTPNotFound()
                if amount > auth_row['authorized_debit_amount']:
                    raise web.HTTPForbidden()
                await con.execute('UPDATE authorizations set status = \'posted\' WHERE id = $1', auth_row['id']);
                await con.execute('UPDATE accounts SET balance = balance - $1, ' \
                    'available = available + ($2 - $1), last_updated = NOW() WHERE id = $3',
                    amount, auth_row['authorized_debit_amount'], auth_row['debit_account'])
                await con.execute('UPDATE accounts SET balance = balance + $1, ' \
                    'available = available + $1, last_updated = NOW() WHERE id = $2',
                    amount, auth_row['credit_account'])
                if 'description' in args:
                    description = args['description']
                else:
                    description = None
                await con.execute('INSERT INTO transactions (debit_account, credit_account, amount, pan, auth_code, ' \
                    'type, description) VALUES($1, $2, $3, $4, $5, $6, $7)', auth_row['debit_account'],
                    auth_row['credit_account'], amount, auth_row['pan'], args['auth_code'], "purchase", description)
        return web.Response(status=204)

    async def post_void(self, request):
        args = await request.post()
        if (not 'auth_code' in args):
            raise web.HTTPBadRequest()
        merchant_data = await self._get_account_data(await self._get_auth_account(request))
        async with self._psql_pool.acquire() as con:
            async with con.transaction():
                auth_row = await con.fetchrow('SELECT * from authorizations WHERE credit_account = $1 ' \
                    'AND auth_code = $2 AND status = \'pending\'',
                    merchant_data['id'], args['auth_code'])
                if not auth_row:
                    raise web.HTTPNotFound()
                await con.execute('UPDATE authorizations set status = \'voided\' WHERE id = $1', auth_row['id']);
                await con.execute('UPDATE accounts SET available = available + $1, last_updated = NOW() WHERE id = $2',
                    auth_row['authorized_debit_amount'], auth_row['debit_account'])
        return web.Response(status=204)

    async def post_reverse(self, request):
        args = await request.post()
        if (not 'auth_code' in args):
            raise web.HTTPBadRequest()
        merchant_data = await self._get_account_data(await self._get_auth_account(request))
        async with self._psql_pool.acquire() as con:
            async with con.transaction():
                auth_row = await con.fetchrow('SELECT * from authorizations WHERE credit_account = $1 ' \
                    'AND auth_code = $2 AND status = \'posted\'',
                    merchant_data['id'], args['auth_code'])
                if not auth_row:
                    raise web.HTTPNotFound()
                transaction_row = await con.fetchrow('SELECT * from transactions WHERE credit_account = $1 ' \
                    'AND auth_code = $2',
                    merchant_data['id'], args['auth_code'])
                if not transaction_row:
                    raise web.HTTPNotFound()
                await con.execute('UPDATE authorizations set status = \'reversed\' WHERE credit_account = $1 and auth_code = $2',
                    merchant_data['id'], args['auth_code']);
                await con.execute('UPDATE accounts SET balance = balance + $1, ' \
                    'available = available + $1, last_updated = NOW() WHERE id = $2',
                    transaction_row['amount'], transaction_row['debit_account'])
                await con.execute('UPDATE accounts SET balance = balance - $1, ' \
                    'available = available - $1, last_updated = NOW() WHERE id = $2',
                    transaction_row['amount'], transaction_row['credit_account'])
                if 'description' in args:
                    description = args['description']
                else:
                    description = None
                await con.execute('INSERT INTO transactions (debit_account, credit_account, amount, pan, ' \
                    'related_transaction, type, description) VALUES($1, $2, $3, $4, $5, $6, $7)',
                    transaction_row['credit_account'], transaction_row['debit_account'], transaction_row['amount'],
                    transaction_row['pan'], transaction_row['id'], "refund", description)
        return web.Response(status=204)

    async def post_credit(self, request):
        args = await request.post()
        if not 'amount' in args:
            raise web.HTTPBadRequest()
        amount = round(float(args['amount']), 2)
        if amount <= 0:
            raise web.HTTPBadRequest()
        merchant_data = await self._get_account_data(await self._get_auth_account(request))
        if merchant_data['available'] < amount and (not (merchant_data['partner'] or merchant_data['admin'] or merchant_data['special'])):
            raise web.HTTPForbidden()

        card_data = {}

        if ('magstripe' in args and len(args['magstripe'])) or \
            ('track1' in args and len(args['track1'])) or \
            ('track2' in args and len(args['track2'])):
            card_data = await self._get_account_from_magstripe(args)
        elif ('pan' in args and len(args['pan'])) and \
            ('otp' in args and len(args['otp'])):
            card_row = await self._psql_pool.fetchrow('SELECT * FROM cards WHERE pan = $1', args['pan'])
            if not card_row:
                raise web.HTTPNotFound()
            card_data = { 'account': card_row['account_id'], 'status': card_row['status'], 'card': { 'pan': args['pan'] } }
        else:
            raise web.HTTPBadRequest()

        cust_data = await self._get_account_data(card_data['account'])
        async with self._psql_pool.acquire() as con:
            async with con.transaction():
                await con.execute('UPDATE accounts SET balance = balance - $1, ' \
                    'available = available - $1, last_updated = NOW() WHERE id = $2',
                    amount, merchant_data['id'])
                await con.execute('UPDATE accounts SET balance = balance + $1, ' \
                    'available = available + $1, last_updated = NOW() WHERE id = $2',
                    amount, cust_data['id'])
                if 'description' in args:
                    description = args['description']
                else:
                    description = None
                await con.execute('INSERT INTO transactions (debit_account, credit_account, amount, pan, ' \
                    'type, description) VALUES($1, $2, $3, $4, $5, $6)', merchant_data['id'],
                    cust_data['id'], amount, card_data['card']['pan'], "credit_points", description)
        return web.Response(status=204)

    async def post_activate(self, request):
        args = await request.post()
        if not 'name' in args:
            raise web.HTTPBadRequest()
        name = str(args['name'].upper())
        name_parts = name.split(' ')
        if len(name_parts) > 1:
            name = name_parts[-1] + '/' + name_parts[:-1]
        merchant_data = await self._get_account_data(await self._get_auth_account(request))
        if not merchant_data['admin']:
            raise web.HTTPForbidden()
        card_data = await self._get_account_from_magstripe(args)
        dd1 = base64.b32encode(secrets.token_bytes(5)).decode('utf-8')
        dd2 = secrets.randbelow(100000000)
        await self._psql_pool.execute('UPDATE accounts SET name = $2 WHERE id = $1',
            card_data['account'], name)
        await self._psql_pool.execute('UPDATE cards SET name = $2, dd1 = dd1 || $3, dd2 = $4, status = \'activated\' WHERE pan = $1',
            card_data['card']['pan'], name, str(dd1), dd2)
        return web.json_response({
            'track1': 'B' + str(card_data['card']['pan']) + '^' + name + '^' + \
            str(card_data['card']['exp']) + '101' + str(card_data['card']['dd1']) + dd1,
            'track2': str(card_data['card']['pan']) + '=' + str(card_data['card']['exp']) + \
            '101' + str(dd2) })

def main():
    arg_parser = argparse.ArgumentParser(description='ShadyBucks API server')
    arg_parser.add_argument('-P', '--port', help='TCP port to serve on.', default='8080')
    arg_parser.add_argument('-U', '--path', help='Unix file system path to serve on.')
    args = arg_parser.parse_args()

    daemon = ShadyBucksAPIDaemon(**vars(args))
    daemon.run(args.path)

if __name__ == '__main__':
    main()
