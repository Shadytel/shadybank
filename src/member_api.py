"""Dedicated, service-authenticated member banking API for telephone applications."""

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import uuid
from datetime import datetime, timezone
from decimal import Decimal

from aiohttp import web
from passlib.hash import argon2


PAN = re.compile(r'[0-9]{8,19}')
PIN = re.compile(r'[0-9]{4,8}')
AMOUNT = re.compile(r'(?:0|[1-9][0-9]{0,5})\.[0-9]{2}')
TOKEN = re.compile(r'[A-Za-z0-9_-]{43}')
TTL = 300
MAX_BALANCE = Decimal('999999.99')


def amount_value(value):
    if not isinstance(value, str) or not AMOUNT.fullmatch(value):
        raise ValueError('Expected positive fixed-point amount')
    result = Decimal(value)
    if not Decimal('0') < result <= MAX_BALANCE:
        raise ValueError('Amount outside permitted range')
    return result


def ordinary(row):
    return bool(row and not any(row[k] for k in ('partner', 'admin', 'special')))


def active_card(row, now=None):
    if not row or row['status'] != 'activated':
        return False
    expires = str(row['expires'])
    if not re.fullmatch(r'[0-9]{4}', expires):
        return False
    month = int(expires[2:])
    now = now or datetime.now(timezone.utc)
    return 1 <= month <= 12 and (2000 + int(expires[:2]), month) >= (now.year, now.month)


def fixed(value):
    return format(value, '.2f')


def safe_label(value, limit=100):
    return ' '.join(str(value or '').split())[:limit]


class MemberAPI:
    def __init__(self, daemon):
        self.daemon = daemon
        self.key = os.getenv('SHADYBANK_MEMBER_SERVICE_KEY', '')
        self.dummy = argon2.hash(secrets.token_hex(16)) if len(self.key) >= 32 else None
        app = daemon._app
        app.add_routes([
            web.post('/api/member/login', self.login),
            web.post('/api/member/logout', self.logout),
            web.get('/api/member/balance', self.balance),
            web.get('/api/member/transactions', self.transactions),
            web.get('/api/member/authorizations', self.authorizations),
            web.post('/api/member/transfer', self.transfer),
        ])

    @property
    def db(self):
        return self.daemon._psql_pool

    @property
    def redis(self):
        return self.daemon._redis_pool

    def service(self, request):
        if len(self.key) < 32:
            raise web.HTTPServiceUnavailable(text='Member service unavailable')
        supplied = request.headers.get('X-Shadybank-Member-Key', '')
        if not hmac.compare_digest(supplied.encode(), self.key.encode()):
            raise web.HTTPUnauthorized(text='Member authentication failed')

    @staticmethod
    def unauthorized():
        return web.HTTPUnauthorized(text='Member authentication failed')

    async def limit(self, identifier, maximum, ttl):
        # Increment and establish the fixed expiry atomically; no sliding lockout on rejected calls.
        key = 'member_rate:' + hmac.new(self.key.encode(), identifier.encode(), hashlib.sha256).hexdigest()
        result = await self.redis.eval(
            "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]); end; return n",
            1, key, ttl)
        if int(result) > maximum:
            raise self.unauthorized()

    async def card(self, pan, connection=None):
        db = connection or self.db
        return await db.fetchrow(
            'SELECT c.account_id,c.status,c.expires,a.partner,a.admin,a.special '
            'FROM cards c JOIN accounts a ON a.id=c.account_id WHERE c.pan=$1', pan)

    async def login(self, request):
        self.service(request)
        await self.limit('login-global', 60, 60)
        args = await request.post()
        pan, pin = args.get('pan', ''), args.get('pin', '')
        if not isinstance(pan,str) or not isinstance(pin,str) or not PAN.fullmatch(pan) or not PIN.fullmatch(pin):
            raise self.unauthorized()
        await self.limit('card:' + pan, 5, 600)
        card = await self.card(pan)
        if card:
            await self.limit('account:' + str(card['account_id']), 5, 600)
        eligible = ordinary(card) and active_card(card)
        rows = await self.db.fetch(
            "SELECT id,secret FROM secrets WHERE account_id=$1 AND type='pin' ORDER BY id DESC LIMIT 2",
            card['account_id']) if eligible else []
        row = rows[0] if len(rows) == 1 and str(rows[0]['secret']).startswith('$argon2') else None
        digest = row['secret'] if row else self.dummy
        try:
            verified = await asyncio.get_running_loop().run_in_executor(None, argon2.verify, pin, digest)
        except (ValueError, TypeError):
            verified = False
        if not eligible or not row or not verified:
            raise self.unauthorized()
        token = secrets.token_urlsafe(32)
        await self.redis.setex('member_session:' + token, TTL,
                              json.dumps({'account': card['account_id'], 'pan': pan, 'pin_id': row['id']}))
        await self.db.execute('UPDATE secrets SET last_used=NOW() WHERE id=$1', row['id'])
        return web.json_response({'token': token, 'expires_in': TTL}, status=201)

    def token(self, request):
        self.service(request)
        parts = request.headers.get('Authorization', '').split(' ')
        if len(parts) != 2 or parts[0].lower() != 'bearer' or not TOKEN.fullmatch(parts[1]):
            raise self.unauthorized()
        return parts[1]

    async def session(self, request):
        token = self.token(request)
        try:
            session = json.loads(await self.redis.get('member_session:' + token) or 'null')
            if (not session or not PAN.fullmatch(session['pan']) or type(session['account']) is not int
                    or type(session['pin_id']) is not int):
                raise self.unauthorized()
            card = await self.card(session['pan'])
            if not ordinary(card) or not active_card(card) or card['account_id'] != session['account']:
                raise self.unauthorized()
            pin_exists = await self.db.fetchval("SELECT 1 FROM secrets WHERE id=$1 AND account_id=$2 AND type='pin'",
                                                session['pin_id'],session['account'])
            if not pin_exists:
                raise self.unauthorized()
            return session
        except (ValueError, TypeError, KeyError):
            raise self.unauthorized()

    async def logout(self, request):
        token = self.token(request)
        await self.redis.delete('member_session:' + token)
        return web.Response(status=204)

    async def balance(self, request):
        session = await self.session(request)
        row = await self.db.fetchrow('SELECT balance,available FROM accounts WHERE id=$1', session['account'])
        if not row:
            raise self.unauthorized()
        return web.json_response({'balance': fixed(row['balance']), 'available': fixed(row['available'])})

    async def transactions(self, request):
        session = await self.session(request)
        account = session['account']
        rows = await self.db.fetch(
            'SELECT t.id,t.timestamp,t.amount,t.type,t.debit_account,t.description, '
            'ca.name AS credit_name,da.name AS debit_name FROM transactions t '
            'JOIN accounts ca ON ca.id=t.credit_account JOIN accounts da ON da.id=t.debit_account '
            'WHERE t.credit_account=$1 OR t.debit_account=$1 ORDER BY t.timestamp DESC,t.id DESC LIMIT 10', account)
        return web.json_response([{'timestamp': row['timestamp'].isoformat(), 'amount': fixed(row['amount']),
            'direction': 'debit' if row['debit_account']==account else 'credit', 'type': row['type'],
            'counterparty': safe_label(row['credit_name'] if row['debit_account']==account else row['debit_name']),
            'description': safe_label(row['description'])} for row in rows])

    async def authorizations(self, request):
        session = await self.session(request)
        account = session['account']
        rows = await self.db.fetch(
            'SELECT a.timestamp,a.expires,a.authorized_debit_amount,a.debit_account, '
            'ca.name AS credit_name,da.name AS debit_name FROM authorizations a '
            'JOIN accounts ca ON ca.id=a.credit_account JOIN accounts da ON da.id=a.debit_account '
            "WHERE (a.credit_account=$1 OR a.debit_account=$1) AND a.status='pending' AND a.expires>NOW() AND a.authorized_debit_amount IS NOT NULL "
            'ORDER BY a.timestamp DESC,a.id DESC LIMIT 10', account)
        return web.json_response([{'timestamp': row['timestamp'].isoformat(), 'expires': row['expires'].isoformat(),
            'amount': fixed(row['authorized_debit_amount']), 'direction':'debit' if row['debit_account']==account else 'credit',
            'counterparty': safe_label(row['credit_name'] if row['debit_account']==account else row['debit_name'])}
            for row in rows])

    async def transfer(self, request):
        session = await self.session(request)
        account = session['account']
        await self.limit('transfer:' + str(account), 10, 60)
        args = await request.post()
        recipient = args.get('recipient_pan', '')
        try:
            amount = amount_value(args.get('amount'))
            request_id = uuid.UUID(args.get('request_id', ''))
            if not isinstance(recipient,str) or not PAN.fullmatch(recipient) or recipient == session['pan']:
                raise ValueError('Invalid recipient')
        except (ValueError, TypeError, AttributeError):
            raise web.HTTPBadRequest(text='Invalid transfer request')

        # All eligibility and funds checks occur under the same database transaction as the ledger mutation.
        async with self.db.acquire() as con:
            async with con.transaction():
                cards = await con.fetch(
                    'SELECT pan,account_id,status,expires FROM cards WHERE pan=ANY($1::varchar[]) ORDER BY pan FOR SHARE',
                    [session['pan'], recipient])
                by_pan = {row['pan']:row for row in cards}
                sender, target = by_pan.get(session['pan']), by_pan.get(recipient)
                if not active_card(sender) or sender['account_id'] != account or not active_card(target):
                    raise web.HTTPForbidden(text='Transfer unavailable')
                destination = target['account_id']
                if destination == account:
                    raise web.HTTPBadRequest(text='Invalid transfer request')
                accounts = await con.fetch(
                    'SELECT id,balance,available,partner,admin,special FROM accounts '
                    'WHERE id=ANY($1::int[]) ORDER BY id FOR UPDATE', [account,destination])
                by_id = {row['id']:row for row in accounts}
                source, target = by_id.get(account), by_id.get(destination)
                if not ordinary(source) or not ordinary(target):
                    raise web.HTTPForbidden(text='Transfer unavailable')
                if not await con.fetchval("SELECT 1 FROM secrets WHERE id=$1 AND account_id=$2 AND type='pin'",
                                          session['pin_id'],account):
                    raise self.unauthorized()
                previous = await con.fetchrow(
                    'SELECT recipient_account,amount,transaction_id FROM member_transfers WHERE sender_account=$1 AND request_id=$2',
                    account, request_id)
                if previous:
                    if previous['recipient_account'] != destination or previous['amount'] != amount:
                        raise web.HTTPConflict(text='Transfer request already used')
                    return web.json_response({'status':'posted','transaction_id':previous['transaction_id'],'amount':fixed(amount)})
                if min(source['balance'], source['available']) < amount:
                    raise web.HTTPConflict(text='Insufficient available balance')
                if target['balance'] + amount > MAX_BALANCE or target['available'] + amount > MAX_BALANCE:
                    raise web.HTTPConflict(text='Transfer unavailable')
                await con.execute('UPDATE accounts SET balance=balance-$1, available=available-$1,last_updated=NOW() WHERE id=$2', amount,account)
                await con.execute('UPDATE accounts SET balance=balance+$1, available=available+$1,last_updated=NOW() WHERE id=$2', amount,destination)
                transaction = await con.fetchval(
                    "INSERT INTO transactions(debit_account,credit_account,amount,type,description) VALUES($1,$2,$3,'member_transfer','Member transfer') RETURNING id",
                    account,destination,amount)
                await con.execute('INSERT INTO member_transfers(sender_account,request_id,recipient_account,amount,transaction_id) VALUES($1,$2,$3,$4,$5)',
                                  account,request_id,destination,amount,transaction)
        return web.json_response({'status':'posted','transaction_id':transaction,'amount':fixed(amount)}, status=201)
