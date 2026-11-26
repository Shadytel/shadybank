import asyncio
import json
import os
import sys
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from aiohttp import web
from passlib.hash import argon2

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from member_api import MemberAPI, amount_value, active_card


CARD='9000000000000001'
RECIPIENT='9000000000000002'
PIN='123456'
KEY='synthetic-member-service-key-0000000000'


class Redis:
    def __init__(self):
        self.values={}; self.counts={}

    async def eval(self,script,numkeys,key,ttl):
        self.counts[key]=self.counts.get(key,0)+1
        return self.counts[key]

    async def setex(self,key,ttl,value):
        self.values[key]=value

    async def get(self,key):
        return self.values.get(key)

    async def delete(self,key):
        self.values.pop(key,None)


class Database:
    def __init__(self):
        self.cards={CARD:{'pan':CARD,'account_id':1,'status':'activated','expires':'3801'},
                    RECIPIENT:{'pan':RECIPIENT,'account_id':2,'status':'activated','expires':'3801'}}
        self.accounts={i:{'id':i,'balance':Decimal(value),'available':Decimal(value),'partner':False,'admin':False,'special':False}
                       for i,value in ((1,'100.00'),(2,'5.00'))}
        self.pins={1:{'id':10,'secret':argon2.hash(PIN)},2:{'id':11,'secret':argon2.hash(PIN)}}
        self.receipts={};self.ledger=[];self.lock=asyncio.Lock()

    async def fetchrow(self,sql,*args):
        if 'FROM cards c JOIN' in sql:
            card=self.cards.get(args[0])
            return {**card,**self.accounts[card['account_id']]} if card else None
        if 'FROM accounts WHERE' in sql:
            return self.accounts.get(args[0])
        if 'FROM member_transfers' in sql:
            return self.receipts.get((args[0],args[1]))
        raise AssertionError('Unexpected query')

    async def fetch(self,sql,*args):
        if 'FROM secrets' in sql:
            return [self.pins[args[0]]] if args[0] in self.pins else []
        if 'FROM cards WHERE' in sql:
            return [self.cards[key] for key in args[0] if key in self.cards]
        if 'FROM accounts' in sql:
            assert 'ORDER BY id FOR UPDATE' in sql
            return [self.accounts[key] for key in args[0] if key in self.accounts]
        if 'FROM transactions' in sql or 'FROM authorizations' in sql:
            return []
        raise AssertionError('Unexpected query')

    async def fetchval(self,sql,*args):
        if 'FROM secrets' in sql:
            return int(self.pins.get(args[1],{}).get('id')==args[0])
        if 'INSERT INTO transactions' in sql:
            self.ledger.append(args)
            return len(self.ledger)
        raise AssertionError('Unexpected query')

    async def execute(self,sql,*args):
        if 'UPDATE secrets' in sql:
            return
        if 'UPDATE accounts SET balance' in sql:
            account=self.accounts[args[1]]
            amount=args[0] if 'balance=balance+$1' in sql else -args[0]
            account['balance']+=amount;account['available']+=amount
            return
        if 'INSERT INTO member_transfers' in sql:
            self.receipts[args[:2]]={'recipient_account':args[2],'amount':args[3],'transaction_id':args[4]}
            return
        raise AssertionError('Unexpected query')

    @asynccontextmanager
    async def acquire(self):
        yield self

    @asynccontextmanager
    async def transaction(self):
        async with self.lock:
            yield


def request(form=None,token=None,key=KEY):
    headers={'X-Shadybank-Member-Key':key}
    if token:
        headers['Authorization']='Bearer '+token
    return SimpleNamespace(headers=headers,post=AsyncMock(return_value=form or {}))


class MemberTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.db=Database();self.redis=Redis()
        daemon=SimpleNamespace(_app=web.Application(),_psql_pool=self.db,_redis_pool=self.redis)
        with patch.dict(os.environ,{'SHADYBANK_MEMBER_SERVICE_KEY':KEY}):
            self.api=MemberAPI(daemon)

    async def token(self):
        result=await self.api.login(request({'pan':CARD,'pin':PIN}))
        self.assertEqual(result.status,201)
        return json.loads(result.text)['token']

    async def test_scoped_login_and_rotation(self):
        with self.assertRaises(web.HTTPUnauthorized):
            await self.api.login(request({'pan':CARD,'pin':PIN},key='wrong'))
        with self.assertRaises(web.HTTPUnauthorized):
            await self.api.login(request({'pan':CARD,'pin':'000000'}))
        token=await self.token()
        self.assertNotIn('auth_token:'+token,self.redis.values)
        self.assertEqual(json.loads((await self.api.balance(request(token=token))).text),{'balance':'100.00','available':'100.00'})
        self.db.pins[1]['id']=12
        with self.assertRaises(web.HTTPUnauthorized):
            await self.api.balance(request(token=token))

    async def test_rejected_attempt_budget_and_card_status(self):
        for _ in range(5):
            with self.assertRaises(web.HTTPUnauthorized):
                await self.api.login(request({'pan':CARD,'pin':'000000'}))
        with self.assertRaises(web.HTTPUnauthorized):
            await self.api.login(request({'pan':CARD,'pin':PIN}))
        self.db.cards[RECIPIENT]['status']='blocked'
        with self.assertRaises(web.HTTPUnauthorized):
            await self.api.login(request({'pan':RECIPIENT,'pin':PIN}))

    async def test_transfer_idempotence_and_limits(self):
        token=await self.token()
        form={'recipient_pan':RECIPIENT,'amount':'12.50','request_id':str(uuid4())}
        a,b=await asyncio.gather(self.api.transfer(request(form,token)),self.api.transfer(request(form,token)))
        self.assertEqual(json.loads(a.text),json.loads(b.text))
        self.assertEqual(self.db.accounts[1]['balance'],Decimal('87.50'))
        self.assertEqual(self.db.accounts[2]['balance'],Decimal('17.50'))
        self.assertEqual(len(self.db.ledger),1)
        with self.assertRaises(web.HTTPConflict):
            await self.api.transfer(request({**form,'amount':'13.00'},token))
        with self.assertRaises(web.HTTPConflict):
            await self.api.transfer(request({**form,'amount':'100.00','request_id':str(uuid4())},token))
        with self.assertRaises(web.HTTPBadRequest):
            await self.api.transfer(request({**form,'amount':'-1.00','request_id':str(uuid4())},token))
        self.db.accounts[2]['partner']=True
        with self.assertRaises(web.HTTPForbidden):
            await self.api.transfer(request({**form,'request_id':str(uuid4())},token))
        self.assertEqual(len(self.db.ledger),1)
        self.assertEqual((await self.api.logout(request(token=token))).status,204)
        with self.assertRaises(web.HTTPUnauthorized):
            await self.api.balance(request(token=token))

    def test_schema_value_validation(self):
        self.assertEqual(amount_value('0.01'),Decimal('0.01'))
        for invalid in ('0.00','1','1.000','1e3','NaN','-1.00','1000000.00',None):
            with self.assertRaises(ValueError):
                amount_value(invalid)
        self.assertFalse(active_card({'status':'activated','expires':'2401'},datetime(2026,1,1,tzinfo=timezone.utc)))
