import json
import os

SAML_DIR = os.path.join(os.path.dirname(__file__), '..', 'srv', 'saml')
SAML_SESSION_TTL = 3600


def load_saml_settings():
    sp_base = os.environ.get('SAML_SP_BASE_URL', 'http://localhost:8021').rstrip('/')
    with open(os.path.join(SAML_DIR, 'settings.json')) as f:
        settings = json.load(f)
    with open(os.path.join(SAML_DIR, 'advanced_settings.json')) as f:
        advanced = json.load(f)
    settings.update(advanced)

    settings['sp']['entityId'] = sp_base + '/saml/metadata'
    settings['sp']['assertionConsumerService']['url'] = sp_base + '/saml/acs'
    settings['sp']['singleLogoutService']['url'] = sp_base + '/saml/sls'

    idp_entity = os.environ.get('SAML_IDP_ENTITY_ID')
    if idp_entity:
        settings['idp']['entityId'] = idp_entity
    idp_sso = os.environ.get('SAML_IDP_SSO_URL')
    if idp_sso:
        settings['idp']['singleSignOnService']['url'] = idp_sso

    cert_path = os.environ.get('SAML_IDP_CERT_FILE')
    if cert_path and os.path.isfile(cert_path):
        with open(cert_path) as cf:
            settings['idp']['x509cert'] = cf.read().strip()
    idp_cert = os.environ.get('SAML_IDP_X509CERT')
    if idp_cert:
        settings['idp']['x509cert'] = idp_cert

    return settings


def prepare_saml_request(request, post_data=None):
    https = 'on' if request.scheme == 'https' else 'off'
    if request.headers.get('X-Forwarded-Proto', '').split(',')[0].strip() == 'https':
        https = 'on'

    host = request.headers.get('X-Forwarded-Host', request.host)
    if ',' in host:
        host = host.split(',')[0].strip()

    http_host = host.rsplit(':', 1)[0] if ':' in host else host
    server_port = request.url.port
    if server_port is None:
        server_port = 443 if https == 'on' else 80

    prepared = {
        'https': https,
        'http_host': http_host,
        'script_name': request.path,
        'server_port': server_port,
        'get_data': dict(request.query),
        'post_data': {},
    }
    if post_data is not None:
        prepared['post_data'] = {k: str(v) for k, v in post_data.items()}
    return prepared


def saml_attribute_name(auth):
    attrs = auth.get_attributes()
    for key in ('name', 'displayName', 'cn', 'givenName'):
        values = attrs.get(key)
        if values:
            return str(values[0])
    return None
