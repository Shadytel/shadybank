import json
import os

SAML_DIR = os.path.join(os.path.dirname(__file__), '..', 'srv', 'saml')
SAML_SESSION_TTL = 3600


def load_saml_settings():
    sp_base = os.environ.get('SAML_SP_BASE_URL', 'https://bucks.shady.tel').rstrip('/')
    with open(os.path.join(SAML_DIR, 'settings.json')) as f:
        settings = json.load(f)
    with open(os.path.join(SAML_DIR, 'advanced_settings.json')) as f:
        advanced = json.load(f)
    settings.update(advanced)

    settings['sp']['entityId'] = sp_base
    settings['sp']['assertionConsumerService']['url'] = sp_base + '/api/saml/acs'

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
    prepared = {
        'https': True,
        'http_host': 'bucks.shady.tel',
        'script_name': '/app/saml/acs',
        'server_port': 443,
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
