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
import segno

class ShadyBucksFrontEndDaemon:
    def __init__(self, **kwargs):
        self._app = web.Application(middlewares=[self.ensure_session_cookie])
        aiohttp_jinja2.setup(self._app,
            loader=jinja2.FileSystemLoader(os.path.join(os.getcwd() ,'website/templates')))

        self._app.add_routes([web.get('/app/account', self.get_account)])
        self._app.add_routes([web.get('/app/login', self.get_login)])
        self._app.add_routes([web.post('/app/login', self.post_login)])
        self._app.add_routes([web.get('/app/partner-login', self.get_partner_login)])
        self._app.add_routes([web.post('/app/partner-login', self.post_partner_login)])
        self._app.add_routes([web.post('/app/logout', self.post_logout)])
        self._app.add_routes([web.get('/app/saml-login', self.get_saml_login)])
        self._app.add_routes([web.post('/app/saml-login', self.post_saml_login)])
        self._app.add_routes([web.post('/app/saml/acs', self.post_saml_acs)])
        self._app.add_routes([web.post('/app/capture', self.post_capture)])
        self._app.add_routes([web.post('/app/void', self.post_void)])
        self._app.add_routes([web.post('/app/reverse', self.post_reverse)])
        self._app.add_routes([web.get('/app/transact', self.get_transact)])
        self._app.add_routes([web.post('/app/transact', self.post_transact)])
        self._app.add_routes([web.get('/app/activate', self.get_activate)])
        self._app.add_routes([web.post('/app/activate', self.post_activate)])
        self._app.add_routes([web.get('/app/app-login', self.get_app_login)])
        self._app.add_routes([web.get('/app/activate-wristband', self.get_activate_wristband)])
        self._app.add_routes([web.get('/app/payme', self.get_payme)])

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
        if sid:
            request.auth_token = await self._redis_pool.get('sid:{}'.format(sid))
        if not sid or request.auth_token is None:
            nsid = sid = secrets.token_urlsafe()
            request.auth_token = ''
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
        await self._redis_pool.delete('csrf:{}'.format(csrf_token))
        if expected_sid != request['SID']:
            raise web.HTTPBadRequest()

    async def get_login(self, request, failed = False):
        context = { 'CSRF_TOKEN': request['CSRF_TOKEN'], 'failed': failed }    
        return aiohttp_jinja2.render_template('frontpage-logged-out.html', request, context)

    async def post_login(self, request):
        data = await request.post()
        await self.check_csrf_token(request, data)
        if 'pan' in data:
            data['pan'].replace(' ', '')
        if 'otp' in data:
            data['pan'].replace(' ', '')
        login_resp = await self._api_client_session.post('http://api-endpoint:8080/api/login', data=data)
        if login_resp.status == 201:
            auth_token = await login_resp.text()
            await self._redis_pool.setex('sid:{}'.format(request['SID']), 2592000, auth_token)
            raise web.HTTPFound('/app/account')
        else:
            return await self.get_login(request, True)

    async def get_partner_login(self, request, failed = False):
        context = { 'CSRF_TOKEN': request['CSRF_TOKEN'], 'failed': failed }    
        return aiohttp_jinja2.render_template('partner-login.html', request, context)

    async def post_partner_login(self, request):
        data = await request.post()
        await self.check_csrf_token(request, data)
        login_resp = await self._api_client_session.post('http://api-endpoint:8080/api/login', data=data)
        if login_resp.status == 201:
            auth_token = await login_resp.text()
            await self._redis_pool.setex('sid:{}'.format(request['SID']), 2592000, auth_token)
            raise web.HTTPFound('/app/account')
        else:
            return await self.get_login(request, True)

    async def post_logout(self, request):
        data = await request.post()
        await self.check_csrf_token(request, data)
        auth_header = { 'Authorization': 'Bearer ' + request.auth_token }
        logout_resp = await self._api_client_session.post('http://api-endpoint:8080/api/logout', headers=auth_header)
        await self._redis_pool.setex('sid:{}'.format(request['SID']), 2592000, '')
        raise web.HTTPFound('/app/login')

    async def get_saml_login(self, request):
        context = { 'CSRF_TOKEN': request['CSRF_TOKEN'] }
        saml_token = await self._redis_pool.get('sid:{}:saml'.format(request['SID']))
        auth_header = { 'Authorization': 'Bearer ' + saml_token }
        accts_resp = await self._api_client_session.get('http://api-endpoint:8080/api/saml/accts', headers=auth_header)
        if accts_resp.status == 200:
            accts_json = await accts_resp.json()
            context['accts'] = accts_json
        return aiohttp_jinja2.render_template('saml-login.html', request, context)

    async def post_saml_login(self, request):
        data = await request.post()
        await self.check_csrf_token(request, data)
        saml_token = await self._redis_pool.get('sid:{}:saml'.format(request['SID']))
        if not saml_token:
            return aiohttp_jinja2.render_template('status-message.html', request, { 'message': 'SID cookie not set. Are you incognito mode?', 'back_url': 'https://bucks.shady.tel', 'back_text': 'Get a cookie' })
        auth_header = { 'Authorization': 'Bearer ' + saml_token }
        if data['acct_id'] == 'bind':
            saml_resp = await self._api_client_session.post('http://api-endpoint:8080/api/saml/bind_acct', data=data, headers=auth_header)
            if saml_resp.status == 201:
                raise web.HTTPFound('/app/saml-login')
            else:
                return aiohttp_jinja2.render_template('status-message.html', request, { 'message': 'Backend said ' + str(saml_resp.status), 'back_url': 'saml-login', 'back_text': 'Go back' })
        elif data['acct_id'] == 'new':
            saml_resp = await self._api_client_session.post('http://api-endpoint:8080/api/saml/new_acct', data=data, headers=auth_header)
            if saml_resp.status == 201:
                new_acct_data = await saml_resp.json()
                await self._redis_pool.setex('sid:{}'.format(request['SID']), 2592000, new_acct_data['auth_token'])
                qr_code = segno.make('otpauth://totp/{}?secret={}&issuer=Shadybucks'.format(new_acct_data['pan'][-7:], new_acct_data['totp_secret']))
                qr_code_uri = qr_code.png_data_uri(scale=5)
                context = { 'pan': new_acct_data['pan'], 'qr_code': qr_code_uri }
                return aiohttp_jinja2.render_template('new-virtual-account.html', request, context)
        else:
            saml_resp = await self._api_client_session.post('http://api-endpoint:8080/api/saml/select_acct', data=data, headers=auth_header)
            if saml_resp.status == 201:
                auth_token = await saml_resp.text()
                await self._redis_pool.setex('sid:{}'.format(request['SID']), 2592000, auth_token)
                raise web.HTTPFound('/app/account')
            else:
                return aiohttp_jinja2.render_template('status-message.html', request, { 'message': 'Backend said ' + str(saml_resp.status), 'back_url': 'saml-login', 'back_text': 'Go back' })

    async def post_saml_acs(self, request):
        data = await request.post()
        saml_resp = await self._api_client_session.post('http://api-endpoint:8080/api/saml/acs', data=data)
        if saml_resp.status == 201:
            auth_token = await saml_resp.text()
            await self._redis_pool.setex('sid:{}:saml'.format(request['SID']), 2592000, auth_token)
            return await self.get_saml_login(request)

    async def get_account(self, request):
        context = { 'CSRF_TOKEN': request['CSRF_TOKEN'] }
        auth_header = { 'Authorization': 'Bearer ' + request.auth_token }
        balance_resp = await self._api_client_session.get('http://api-endpoint:8080/api/balance', headers=auth_header)
        if balance_resp.status == 200:
            balance_json = await balance_resp.json()
            context = { **context, **balance_json }
        else:
            raise web.HTTPFound('/app/login')
        txns_resp = await self._api_client_session.get('http://api-endpoint:8080/api/transactions', headers=auth_header)
        if txns_resp.status == 200:
            txns_json = await txns_resp.json()
            context['transactions'] = txns_json
        auths_resp = await self._api_client_session.get('http://api-endpoint:8080/api/authorizations', headers=auth_header)
        if auths_resp.status == 200:
            auths_json = await auths_resp.json()
            context['authorizations'] = auths_json
        return aiohttp_jinja2.render_template('transaction-history.html', request, context)
        
    async def post_capture(self, request):
        data = await request.post()
        await self.check_csrf_token(request, data)
        auth_header = { 'Authorization': 'Bearer ' + request.auth_token }
        resp = await self._api_client_session.post('http://api-endpoint:8080/api/capture',
            data=data, headers=auth_header)
        if resp.status == 204:
            message = 'Success!'
        else:
            message = 'Backend said ' + str(resp.status)
        context = { 'message': message, 'back_url': 'account', 'back_text': 'Go back home' }
        return aiohttp_jinja2.render_template('status-message.html', request, context)

    async def post_void(self, request):
        data = await request.post()
        await self.check_csrf_token(request, data)
        auth_header = { 'Authorization': 'Bearer ' + request.auth_token }
        resp = await self._api_client_session.post('http://api-endpoint:8080/api/void',
            data=data, headers=auth_header)
        if resp.status == 204:
            message = 'Success!'
        else:
            message = 'Backend said ' + str(resp.status)
        context = { 'message': message, 'back_url': 'account', 'back_text': 'Go back home' }
        return aiohttp_jinja2.render_template('status-message.html', request, context)

    async def post_reverse(self, request):
        data = await request.post()
        await self.check_csrf_token(request, data)
        auth_header = { 'Authorization': 'Bearer ' + request.auth_token }
        resp = await self._api_client_session.post('http://api-endpoint:8080/api/reverse',
            data=data, headers=auth_header)
        if resp.status == 204:
            message = 'Success!'
        else:
            message = 'Backend said ' + str(resp.status)
        context = { 'message': message, 'back_url': 'account', 'back_text': 'Go back home' }
        return aiohttp_jinja2.render_template('status-message.html', request, context)

    async def get_transact(self, request):
        context = { 'CSRF_TOKEN': request['CSRF_TOKEN'] }    
        auth_header = { 'Authorization': 'Bearer ' + request.auth_token }
        balance_resp = await self._api_client_session.get('http://api-endpoint:8080/api/balance', headers=auth_header)
        if balance_resp.status == 200:
            balance_json = await balance_resp.json()
            context = { **request.query, **context, **balance_json }
        else:
            raise web.HTTPFound('/app/login')
        return aiohttp_jinja2.render_template('transaction-entry.html', request, context)
    
    
    async def get_payme(self, request):
        context = { 'CSRF_TOKEN': request['CSRF_TOKEN'] }    
        auth_header = { 'Authorization': 'Bearer ' + request.auth_token }
        balance_resp = await self._api_client_session.get('http://api-endpoint:8080/api/balance', headers=auth_header)
        if balance_resp.status == 200:
            balance_json = await balance_resp.json()
            context = { **request.query, **context, **balance_json }
        else:
            raise web.HTTPFound('/app/login')
        return aiohttp_jinja2.render_template('pay-me.html', request, context)

    async def post_transact(self, request):
        data = await request.post()
        await self.check_csrf_token(request, data)
        auth_header = { 'Authorization': 'Bearer ' + request.auth_token }
        message = 'Failed'
        if 'txn_type' in data:
            if data['txn_type'] == 'preauth' or data['txn_type'] == 'purchase':
                auth_resp = await self._api_client_session.post('http://api-endpoint:8080/api/authorize',
                    data=data, headers=auth_header)
                if auth_resp.status == 200:
                    auth_code = await auth_resp.text()
                    if data['txn_type'] == 'purchase':
                        cap_resp = await self._api_client_session.post('http://api-endpoint:8080/api/capture',
                            data={'amount': data['amount'], 'auth_code': auth_code}, headers=auth_header)
                        if cap_resp.status == 204:
                            message = 'Success!'
                        else:
                            message = 'Backend said ' + str(cap_resp.status)
                    else:
                        message = 'Success!'
                else:
                    message = 'Backend said ' + str(auth_resp.status)
            elif data['txn_type'] == 'credit':
                credit_resp = await self._api_client_session.post('http://api-endpoint:8080/api/credit',
                    data=data, headers=auth_header)
                if credit_resp.status == 204:
                    message = 'Success!'
                else:
                    message = 'Backend said ' + str(credit_resp.status)
            else:
                message = 'Stop hacking us'
        context = { 'message': message, 'back_url': 'transact', 'back_text': 'Go back to transaction entry' }
        return aiohttp_jinja2.render_template('status-message.html', request, context)

    async def get_activate(self, request):
        context = { 'CSRF_TOKEN': request['CSRF_TOKEN'] }    
        return aiohttp_jinja2.render_template('activate-entry.html', request, context)

    async def post_activate(self, request):
        data = await request.post()
        await self.check_csrf_token(request, data)
        auth_header = { 'Authorization': 'Bearer ' + request.auth_token }
        act_resp = await self._api_client_session.post('http://api-endpoint:8080/api/activate',
            data=data, headers=auth_header)
        if act_resp.status != 200:
            return aiohttp_jinja2.render_template('status-message.html', request,
                { 'message': 'Backend said ' + str(act_resp.status),
                  'back_url': 'activate',
                  'back_text': 'Go back' })    
        return aiohttp_jinja2.render_template('activate-result.html', request, await act_resp.json())

    async def get_app_login(self, request, failed = False):
        context = { 'CSRF_TOKEN': request['CSRF_TOKEN'], 'failed': failed }
        return aiohttp_jinja2.render_template('app-login.html', request, context)

    async def get_activate_wristband(self, request, failed = False):
        context = { 'CSRF_TOKEN': request['CSRF_TOKEN'], 'auth_token': request.auth_token }
        return aiohttp_jinja2.render_template('activate-wristband.html', request, context)

def main():
    arg_parser = argparse.ArgumentParser(description='ShadyBucks frontend server')
    arg_parser.add_argument('-P', '--port', help='TCP port to serve on.', default='8080')
    arg_parser.add_argument('-U', '--path', help='Unix file system path to serve on.')
    args = arg_parser.parse_args()

    daemon = ShadyBucksFrontEndDaemon(**vars(args))
    daemon.run(args.path)

if __name__ == '__main__':
    main()