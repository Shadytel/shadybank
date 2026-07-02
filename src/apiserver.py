#!/usr/bin/env python3

from aiohttp import web
import aioredis
import argparse
import asyncio
import asyncpg
import base64
import hashlib
import json
from passlib.hash import argon2
import pyotp
import os
import re
import secrets
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from datetime import datetime
from datetime import timedelta
from onelogin.saml2.auth import OneLogin_Saml2_Auth

from saml_support import SAML_SESSION_TTL, load_saml_settings, prepare_saml_request, saml_attribute_name

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

        # NFC APIs
        self._app.add_routes([web.post('/api/nfc_challenge', self.post_nfc_challenge)])
        self._app.add_routes([web.post('/api/nfc_response', self.post_nfc_response)])
        self._app.add_routes([web.post('/api/nfc_activate', self.post_nfc_activate)])
        self._app.add_routes([web.post('/api/nfc_link', self.post_nfc_link)])

        # Admin APIs
        self._app.add_routes([web.post('/api/activate', self.post_activate)])

        # SAML SP
        self._saml_settings = load_saml_settings()
        self._app.add_routes([web.post('/api/saml/acs', self.post_saml_acs)])
        self._app.add_routes([web.get('/api/saml/accts', self.get_saml_accts)])
        self._app.add_routes([web.post('/api/saml/select_acct', self.post_saml_select_acct)])
        self._app.add_routes([web.post('/api/saml/new_acct', self.post_saml_new_acct)])
        self._app.add_routes([web.post('/api/saml/bind_acct', self.post_saml_bind_acct)])

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
        return web.Response(status=201, text=auth_token)

    async def _upsert_saml_customer(self, shadytel_customer_id, name):
        row = await self._psql_pool.fetchrow(
            'SELECT id, name FROM customers WHERE shadytel_customer_id = $1',
            shadytel_customer_id)
        if row:
            if name and name != row['name']:
                await self._psql_pool.execute(
                    'UPDATE customers SET name = $2, last_updated = NOW() WHERE id = $1',
                    row['id'], name)
                return row['id']
            return row['id']
        row = await self._psql_pool.fetchrow(
            'INSERT INTO customers (shadytel_customer_id, name) VALUES ($1, $2) RETURNING id',
            shadytel_customer_id, name or 'Shadytel Customer %d' % shadytel_customer_id)
        return row['id']

    async def post_saml_acs(self, request):
        post_data = await request.post()
        req = prepare_saml_request(request, post_data)
        auth = OneLogin_Saml2_Auth(req, self._saml_settings)
        auth.process_response()

        errors = auth.get_errors()
        if errors:
            reason = auth.get_last_error_reason() or ''
            raise web.HTTPBadRequest(text='SAML error: %s %s' % (', '.join(errors), reason))

        if not auth.is_authenticated():
            raise web.HTTPUnauthorized(text='SAML authentication failed')

        try:
            shadytel_customer_id = int(auth.get_nameid())
        except (TypeError, ValueError):
            raise web.HTTPBadRequest(text='SAML NameID must be a numeric shadytel_customer_id')

        name = saml_attribute_name(auth)
        customer_id = await self._upsert_saml_customer(shadytel_customer_id, name)

        saml_token = secrets.token_urlsafe()
        await self._redis_pool.setex(
            'saml_token:%s' % saml_token,
            SAML_SESSION_TTL,
            json.dumps({
                'customer_id': customer_id,
                'shadytel_customer_id': shadytel_customer_id,
                'name': name,
            }))

        resp = web.Response(status=201, text=saml_token)
        return resp

    async def _get_saml_customer(self, request):
        saml_token = self._get_request_auth_token(request)
        saml_session = await self._redis_pool.get('saml_token:{}'.format(saml_token))
        if saml_session:
            return json.loads(saml_session)['customer_id']
        raise web.HTTPUnauthorized()

    async def get_saml_accts(self, request):
        customer_id = await self._get_saml_customer(request)
        accts = await self._psql_pool.fetch('SELECT id, name FROM accounts WHERE customer_id = $1', int(customer_id))
        return web.json_response([dict(acct) for acct in accts])

    async def post_saml_select_acct(self, request):
        customer_id = await self._get_saml_customer(request)
        args = await request.post()
        acct_id = int(args['acct_id'])
        acct = await self._psql_pool.fetch('SELECT * FROM accounts WHERE customer_id = $1 AND id = $2', customer_id, acct_id)
        if acct:
            auth_token = secrets.token_urlsafe()
            await self._redis_pool.setex('auth_token:{}'.format(auth_token), 2592000, acct_id)
            return web.Response(status=201, text=auth_token)
        raise web.HTTPUnauthorized()

    def _append_luhn_check_digit(self, payload):
        """Computes and appends the missing Luhn check digit for a given payload string."""
        # Reverse payload because Luhn operates from right to left
        digits = [int(d) for d in reversed(payload)]
        
        total_sum = 0
        for i, digit in enumerate(digits):
            # Since the check digit will be at index 0 of the final number,
            # the payload's rightmost digit becomes the first doubled digit (index 0 here)
            if i % 2 == 0:
                doubled = digit * 2
                # Subtract 9 if the doubled number is greater than 9
                total_sum += doubled if doubled < 10 else doubled - 9
            else:
                total_sum += digit
                
        # Calculate the digit needed to make the total sum a multiple of 10
        luhn_check_digit = (10 - (total_sum % 10)) % 10
        return payload + str(luhn_check_digit)

    async def post_saml_new_acct(self, request):
        customer_id = await self._get_saml_customer(request)
        args = await request.post()
        accts = (await self._psql_pool.fetchrow('SELECT COUNT(*) FROM accounts WHERE customer_id = $1', customer_id))[0]
        if accts:
            raise web.HTTPUnauthorized(text="You already have an existing Shadybucks account. Please contact BUXX for additional accounts.")
        new_acct_id = (await self._psql_pool.fetchrow('INSERT INTO accounts (customer_id, name) VALUES ($1, $2) RETURNING id', customer_id, args['name']))[0]
        new_totp_secret = base64.b32encode(secrets.token_bytes(20)).decode('utf-8')
        await self._psql_pool.execute('INSERT INTO secrets (account_id, type, secret) VALUES ($1, \'totp\', $2)', new_acct_id, new_totp_secret)
        new_acct_pan = self._append_luhn_check_digit(f'899798667{new_acct_id:06d}')
        dd1 = base64.b32encode(secrets.token_bytes(5)).decode('utf-8')
        dd2 = f'{secrets.randbelow(100000000):08d}'
        await self._psql_pool.execute('INSERT INTO cards (pan, account_id, name, expires, status, dd1, dd2) VALUES ($1, $2, $3, $4, $5, $6, $7)', new_acct_pan, new_acct_id, args['name'], '3801', 'activated', dd1, dd2)
        auth_token = secrets.token_urlsafe()
        await self._redis_pool.setex('auth_token:{}'.format(auth_token), 2592000, new_acct_id)
        return web.json_response({ 'pan': new_acct_pan, 'totp_secret': new_totp_secret, 'auth_token': auth_token }, status=201)

    async def post_saml_bind_acct(self, request):
        auth_response = await self.post_login(request)
        if auth_response.status == 201:
            auth_token = auth_response.text
            acct_id = await self._redis_pool.get('auth_token:{}'.format(auth_token))
            customer_id = await self._get_saml_customer(request)
            await self._psql_pool.execute('UPDATE accounts SET customer_id = $2 WHERE id = $1', int(acct_id), customer_id)
            return auth_response
        raise web.HTTPUnauthorized()

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
            raise web.HTTPUnauthorized(text="Rate limit exceeded")
        
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
            if ('otp' in args and len(args['otp'])):
                await self._check_otp_ratelimit(args['pan'])
        elif 'account_id' in args:
            auth_rows = await self._psql_pool.fetch('SELECT s.account_id, s.id, s.type, s.secret ' \
                'FROM secrets s where s.account_id = $1', int(args['account_id']))
            if ('otp' in args and len(args['otp'])):
                await self._check_otp_ratelimit(args['account_id'])
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
        card_row = await self._psql_pool.fetchrow('SELECT pan FROM cards WHERE account_id = $1 ' \
            'ORDER BY (status = \'activated\') DESC LIMIT 1', acct);
        account_pan = card_row['pan'] if card_row else None
        return web.json_response({ 'account': acct, 'name': name, 'balance': float(balance), 'available': float(available), 'account_pan': account_pan })

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
                authorizations.append({ 'timestamp': str(authorization['timestamp']), 'expires': str(authorization['expires']),
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
        elif card_data['track'] == 2 and card_data['dd2'] == str(card_row['dd2']):
            return { 'account': card_row['account_id'], 'status': card_row['status'], 'card': card_data }
        else:
            raise web.HTTPNotFound()

    async def _get_account_from_wristband(self, args):
        uid = None

        if 'nfc_token' in args:
            nfc_token = args['nfc_token']
            uid = await self._redis_pool.get(f'nfc_token:{nfc_token}')
            await self._redis_pool.delete(f'nfc_token:{nfc_token}')
        else:
            raise web.HTTPBadRequest()

        if not uid:
            raise web.HTTPUnauthorized()

        card_row = await self._psql_pool.fetchrow('SELECT * FROM cards WHERE pan = $1', uid)
        if not card_row:
            raise web.HTTPNotFound()

        return { 'account': card_row['account_id'], 'status': card_row['status'],
                'card': { 'pan': uid } }

    async def post_authorize(self, request):
        args = await request.post()
        if not 'amount' in args:
            raise web.HTTPBadRequest()
        amount = round(float(args['amount']), 2)
        if amount <= 0:
            raise web.HTTPBadRequest()
        if amount >= 50000:
            raise web.HTTPBadRequest(text="Voice auth required. Call BUXX.")
        merchant_data = await self._get_account_data(await self._get_auth_account(request))

        card_data = {}

        if ('magstripe' in args and len(args['magstripe'])) or \
            ('track1' in args and len(args['track1'])) or \
            ('track2' in args and len(args['track2'])):
            card_data = await self._get_account_from_magstripe(args)
        elif ('nfc_token' in args and len(args['nfc_token'])):
            card_data = await self._get_account_from_wristband(args)
        elif ('pan' in args and len(args['pan'])) and \
            (('otp' in args and len(args['otp'])) or ('shotp' in args and len(args['shotp']))):
            card_row = await self._psql_pool.fetchrow('SELECT * FROM cards WHERE pan = $1', args['pan'])
            if not card_row:
                raise web.HTTPNotFound()
            card_data = { 'account': card_row['account_id'], 'status': card_row['status'], 'card': { 'pan': args['pan'] } }
            await self._check_otp_ratelimit(args['pan'])
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
                     otp_obj.at(datetime.now() - timedelta(seconds=30))[0:4] == args['shotp'] or \
                     otp_obj.at(datetime.now() - timedelta(seconds=60))[0:4] == args['shotp']):
                    auth_match = True
                    break
                # Try the interval we specified
                otp_obj = pyotp.TOTP(auth_row['secret'], interval=60)
                if ('otp' in args and len(args['otp'])) and otp_obj.verify(args['otp'], valid_window=1):
                    auth_match = True
                    break
                elif ('shotp' in args and len(args['shotp'])) and \
                    (otp_obj.now()[0:4] == args['shotp'] or \
                     otp_obj.at(datetime.now() - timedelta(seconds=60))[0:4] == args['shotp']):
                    auth_match = True
                    break
            if not auth_match:
                raise web.HTTPForbidden()
        else:
            raise web.HTTPBadRequest()

        if card_data['status'] == 'blocked':
            raise web.HTTPForbidden(text="Voice auth required. Call BUXX and ask for a Code 10 authorization.")
        if card_data['status'] != 'activated':
            raise web.HTTPForbidden()
        cust_id = card_data['account']
        auth_code = str(secrets.randbelow(1000000)).zfill(6)
        async with self._psql_pool.acquire() as con:
            async with con.transaction():
                held = await con.fetchrow('UPDATE accounts SET available = available - $1, last_updated = NOW() ' \
                    'WHERE id = $2 AND available >= $1 RETURNING id', amount, cust_id)
                if not held:
                    raise web.HTTPForbidden()
                await con.execute('INSERT INTO authorizations (pan, auth_code, debit_account, credit_account, authorized_debit_amount) ' \
                    'VALUES($1, $2, $3, $4, $5)', card_data['card']['pan'], auth_code, cust_id, merchant_data['id'], amount)
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
                if amount > float(auth_row['authorized_debit_amount']):
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
                released = await con.fetchrow('UPDATE authorizations SET status = \'voided\' ' \
                    'WHERE credit_account = $1 AND auth_code = $2 AND status = \'pending\' ' \
                    'RETURNING debit_account, authorized_debit_amount',
                    merchant_data['id'], args['auth_code'])
                if not released:
                    raise web.HTTPNotFound()
                await con.execute('UPDATE accounts SET available = available + $1, last_updated = NOW() WHERE id = $2',
                    released['authorized_debit_amount'], released['debit_account'])
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
        merchant_id = await self._get_auth_account(request)

        card_data = {}

        if ('magstripe' in args and len(args['magstripe'])) or \
            ('track1' in args and len(args['track1'])) or \
            ('track2' in args and len(args['track2'])):
            card_data = await self._get_account_from_magstripe(args)
        elif ('nfc_token' in args and len(args['nfc_token'])):
            card_data = await self._get_account_from_wristband(args)
        elif ('pan' in args and len(args['pan'])):
            card_row = await self._psql_pool.fetchrow('SELECT * FROM cards WHERE pan = $1', args['pan'])
            if not card_row:
                raise web.HTTPNotFound()
            card_data = { 'account': card_row['account_id'], 'status': card_row['status'], 'card': { 'pan': args['pan'] } }
        else:
            raise web.HTTPBadRequest()

        cust_id = card_data['account']
        async with self._psql_pool.acquire() as con:
            async with con.transaction():
                await con.fetchrow('SELECT id FROM accounts WHERE id = $1 FOR UPDATE', merchant_id)
                debited = await con.fetchrow('UPDATE accounts SET balance = balance - $1, ' \
                    'available = available - $1, last_updated = NOW() WHERE id = $2 AND ' \
                    '(partner OR admin OR special OR available >= $1) RETURNING id',
                    amount, merchant_id)
                if not debited:
                    raise web.HTTPForbidden()
                await con.execute('UPDATE accounts SET balance = balance + $1, ' \
                    'available = available + $1, last_updated = NOW() WHERE id = $2',
                    amount, cust_id)
                if 'description' in args:
                    description = args['description']
                else:
                    description = None
                await con.execute('INSERT INTO transactions (debit_account, credit_account, amount, pan, ' \
                    'type, description) VALUES($1, $2, $3, $4, $5, $6)', merchant_id,
                    cust_id, amount, card_data['card']['pan'], "credit_points", description)
        return web.Response(status=204)

    async def post_nfc_challenge(self, request):
        args = await request.post()
        if not 'uid' in args:
            raise web.HTTPBadRequest()
        if not 'chal' in args:
            raise web.HTTPBadRequest()

        uid = args['uid'].lower()
        if len(uid) != 14:
            raise web.HTTPBadRequest()
        chal = bytes.fromhex(args['chal'])
        if len(chal) != 8:
            raise web.HTTPBadRequest()

        keys = await self._psql_pool.fetchrow('SELECT des_key1, des_key2 from nfc_keys WHERE uid = $1', uid)
        if not keys:
            # NXP default keys
            keys = ['49454D4B41455242', '214E4143554F5946']
        key = bytes.fromhex(''.join(keys))

        des = DES3.new(key, DES3.MODE_CBC, iv=b'\x00' * 8)
        rndB = des.decrypt(chal)
        rndBPrime = rndB[1:] + rndB[0:1]
        des = DES3.new(key, DES3.MODE_CBC, iv=chal)
        rndA = get_random_bytes(8)
        rndAPrime = rndA[1:] + rndA[0:1]
        resp = des.encrypt(rndA + rndBPrime)
        des = DES3.new(key, DES3.MODE_CBC, iv=resp[8:16])
        expectedResp = des.encrypt(rndAPrime)

        await self._redis_pool.setex(f'nfc_auth_expected:{uid}:{chal.hex()}', 300, expectedResp.hex())

        return web.json_response({ 'resp': resp.hex() })

    async def post_nfc_response(self, request):
        args = await request.post()
        if not 'uid' in args:
            raise web.HTTPBadRequest()
        if not 'chal' in args:
            raise web.HTTPBadRequest()
        if not 'resp' in args:
            raise web.HTTPBadRequest()

        uid = args['uid'].lower()
        if len(uid) != 14:
            raise web.HTTPBadRequest()
        chal = args['chal'].lower()
        if len(chal) != 16:
            raise web.HTTPBadRequest()
        resp = args['resp'].lower()
        if len(resp) != 16:
            raise web.HTTPBadRequest()

        expectedResp = await self._redis_pool.get(f'nfc_auth_expected:{uid}:{chal}')
        if not expectedResp:
            raise web.HTTPNotFound()
        if expectedResp != resp:
            raise web.HTTPUnauthorized()

        nfc_token = secrets.token_urlsafe()
        await self._redis_pool.setex('nfc_token:{}'.format(nfc_token), 60, uid)
        return web.json_response({ "nfc_token": nfc_token })

    async def post_nfc_activate(self, request):
        args = await request.post()
        if not 'nfc_token' in args:
            raise web.HTTPBadRequest()

        merchant_data = await self._get_account_data(await self._get_auth_account(request))
        if not merchant_data['admin']:
            raise web.HTTPForbidden()

        nfc_token = args['nfc_token']
        uid = await self._redis_pool.get(f'nfc_token:{nfc_token}')
        if not uid:
            raise web.HTTPUnauthorized()
        # Don't delete the nfc_token here because it's needed for linking immediately after
        
        cmds = []

        key_row = await self._psql_pool.fetchrow('SELECT * FROM nfc_keys WHERE uid = $1', uid)
        if not key_row:
            des_key1 = secrets.token_bytes(8).hex()
            des_key2 = secrets.token_bytes(8).hex()
            aes_key = secrets.token_bytes(16).hex()
            cmds.extend([
                f"a22c{des_key1[14:16]}{des_key1[12:14]}{des_key1[10:12]}{des_key1[8:10]}",
                f"a22d{des_key1[6:8]}{des_key1[4:6]}{des_key1[2:4]}{des_key1[0:2]}",
                f"a22e{des_key2[14:16]}{des_key2[12:14]}{des_key2[10:12]}{des_key2[8:10]}",
                f"a22f{des_key2[6:8]}{des_key2[4:6]}{des_key2[2:4]}{des_key2[0:2]}",
            ])
            await self._psql_pool.execute('INSERT INTO nfc_keys (uid, des_key1, des_key2, aes_key) VALUES ($1, $2, $3, $4)',
                                          uid, des_key1, des_key2, aes_key)

        cmds.extend([
            # Set max readable page without auth
            "a22a25000000",
            "a22b00000000",

            # Write CTF flags
            # "a2246B65793D",
            # "a2257B585858",
            # "a22658585858",
            # "a2275858587D",

            # Write NDEF container
            # "a203e1101000",
            # "a2040304d800",
            # "a2050000fe00",
            "a2040321d101",
            "a2051d550068",
            "a20674747073",
            "a2073a2f2f79",
            "a2086f757475",
            "a2092e62652f",
            "a20a64517734",
            "a20b77395767",
            "a20c586351fe",
            "a20d00000000",

            # OTP (may fail)
            "a203e1101200",

            # Write CTF hint
            # "a21800000068",
            # "a21974747073",
            # "a21a3A2F2F65",
            # "a21b7570686F",
            # "a21c7269612D",
            # "a21d6374662E",
            # "a21e636F6D2F",
            # "a21f7B777231",
            # "a22073746234",
            # "a2216E645F61",
            # "a22263633373",
            # "a223737D2F3F",
        ])
        return web.json_response({ "cmds": cmds })

    async def post_nfc_link(self, request):
        args = await request.post()
        auth_response = await self.post_login(request)
        if auth_response.status == 201:
            auth_token = auth_response.text
            acct_id = await self._redis_pool.get('auth_token:{}'.format(auth_token))

        nfc_token = args['nfc_token']
        uid = await self._redis_pool.get(f'nfc_token:{nfc_token}')
        await self._redis_pool.delete(f'nfc_token:{nfc_token}')

        # amount = 500.00

        # async with self._psql_pool.acquire() as con:
        #     async with con.transaction():
        #         await con.execute('INSERT INTO cards (pan, account_id, name, expires, status) VALUES ($1, $2, $3, $4, $5)',
        #                               uid, acct_id, 'SHADYBUCKS CUSTOMER', '0000', 'activated')
        #         await con.execute('UPDATE accounts SET balance = balance - $1, ' \
        #             'available = available - $1, last_updated = NOW() WHERE id = $2',
        #             amount, 1)
        #         await con.execute('UPDATE accounts SET balance = balance + $1, ' \
        #             'available = available + $1, last_updated = NOW() WHERE id = $2',
        #             amount, acct_id)
        #         description = 'TOORCAMP 2026 WELCOME BONUS'
        #         await con.execute('INSERT INTO transactions (debit_account, credit_account, amount, pan, ' \
        #             'type, description) VALUES($1, $2, $3, $4, $5, $6)', 1,
        #             acct_id, amount, uid, "credit_points", description)

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
