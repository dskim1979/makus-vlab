"""Directory credential check for a trusted front end (/api/directory/ldap/*).

Only an API token with admin.settings may ask; a browser session is refused even
for an admin. A wrong user and a wrong password give the same answer, repeated
attempts on one user name are cut off, and nothing is provisioned locally.
"""
import pytest

import pegaprox.api.directory_verify as dv
from pegaprox.utils.auth import create_api_token


def _bearer(tok):
    return {'Authorization': f"Bearer {tok['token']}"}


@pytest.fixture
def directory(monkeypatch):
    users = {'kim': ('S3cret!', {'email': 'kim@example.com', 'display_name': 'Kim', 'groups': ['cn=ops'], 'role': 'viewer'})}

    def fake_auth(username, password):
        u = users.get(username)
        if not u:
            return {'error': 'User not found in LDAP'}
        if password != u[0]:
            return {'error': 'Invalid LDAP credentials'}
        return {'success': True, 'username': username, 'user_dn': f'cn={username},dc=example', **u[1]}

    monkeypatch.setattr(dv, 'ldap_authenticate', fake_auth)
    monkeypatch.setattr(dv, 'get_ldap_settings', lambda: {'enabled': True, 'server': 'ldap.example', 'base_dn': 'dc=example'})
    return users


def test_an_admin_token_verifies_a_directory_user(api, seed, db, directory):
    seed.user('root', role='admin')
    tok = create_api_token('root', 'front', role='admin')
    r = api.anon().post('/api/directory/ldap/verify', json={'username': 'kim', 'password': 'S3cret!'}, headers=_bearer(tok))
    assert r.status_code == 200, r.data
    body = r.get_json()
    assert body['valid'] is True
    assert body['email'] == 'kim@example.com' and body['groups'] == ['cn=ops']
    assert 'password' not in r.get_data(as_text=True).lower()
    assert db.get_user('kim') is None, 'a check must not provision a local user'


def test_wrong_password_and_unknown_user_look_the_same(api, seed, directory):
    seed.user('root', role='admin')
    tok = create_api_token('root', 'front', role='admin')
    c = api.anon()
    a = c.post('/api/directory/ldap/verify', json={'username': 'kim', 'password': 'nope'}, headers=_bearer(tok)).get_json()
    b = c.post('/api/directory/ldap/verify', json={'username': 'ghost1', 'password': 'nope'}, headers=_bearer(tok)).get_json()
    assert a == b == {'valid': False, 'error': 'Invalid credentials'}


def test_a_browser_session_is_refused_even_for_an_admin(api, seed, directory):
    seed.user('root', role='admin')
    r = api.as_user({'username': 'root', 'role': 'admin'}).post('/api/directory/ldap/verify', json={'username': 'kim', 'password': 'S3cret!'})
    assert r.status_code == 403


def test_a_token_without_admin_settings_is_refused(api, seed, directory):
    seed.user('root', role='admin')
    tok = create_api_token('root', 'ro', role='viewer')
    r = api.anon().post('/api/directory/ldap/verify', json={'username': 'kim', 'password': 'S3cret!'}, headers=_bearer(tok))
    assert r.status_code == 403


def test_repeated_attempts_on_one_user_are_cut_off(api, seed, directory):
    seed.user('root', role='admin')
    tok = create_api_token('root', 'front', role='admin')
    c = api.anon()
    codes = [c.post('/api/directory/ldap/verify', json={'username': 'brute1', 'password': f'x{i}'}, headers=_bearer(tok)).status_code
             for i in range(12)]
    assert codes[:10] == [200] * 10
    assert codes[10:] == [429, 429]


def test_status_says_whether_ldap_is_configured(api, seed, directory, monkeypatch):
    seed.user('root', role='admin')
    tok = create_api_token('root', 'front', role='admin')
    c = api.anon()
    assert c.get('/api/directory/ldap/status', headers=_bearer(tok)).get_json() == {'enabled': True}
    monkeypatch.setattr(dv, 'get_ldap_settings', lambda: {'enabled': True, 'server': '', 'base_dn': ''})
    assert c.get('/api/directory/ldap/status', headers=_bearer(tok)).get_json() == {'enabled': False}


# --- OIDC configuration handed to the front end -------------------------------------------

def _oidc(monkeypatch, **cfg):
    base = {'enabled': True, 'provider': 'entra', 'cloud_environment': 'commercial', 'client_id': 'cid',
            'client_secret': 'CSECRET', 'tenant_id': 'tid', 'authority': '', 'scopes': 'openid profile email',
            'button_text': 'Sign in', 'auto_create_users': True, 'default_role': 'viewer',
            'admin_group_id': 'g-admins', 'user_group_id': '', 'viewer_group_id': '', 'group_mappings': []}
    base.update(cfg)
    monkeypatch.setattr(dv, 'get_oidc_settings', lambda: base)


def test_oidc_config_builds_the_issuer_and_carries_the_secret_to_an_admin_token(api, seed, monkeypatch):
    seed.user('root', role='admin')
    h = _bearer(create_api_token('root', 'front', role='admin'))
    _oidc(monkeypatch)
    b = api.anon().get('/api/directory/oidc/config', headers=h).get_json()
    assert b['enabled'] is True and b['issuer'] == 'https://login.microsoftonline.com/tid/v2.0'
    assert b['client_secret'] == 'CSECRET' and b['admin_group_id'] == 'g-admins'
    _oidc(monkeypatch, cloud_environment='gcc_high')
    assert api.anon().get('/api/directory/oidc/config', headers=h).get_json()['issuer'].startswith('https://login.microsoftonline.us/')
    _oidc(monkeypatch, provider='keycloak', authority='https://kc.example/realms/ops/')
    assert api.anon().get('/api/directory/oidc/config', headers=h).get_json()['issuer'] == 'https://kc.example/realms/ops'


def test_oidc_config_is_disabled_when_incomplete_and_never_for_a_session_or_viewer(api, seed, monkeypatch):
    seed.user('root', role='admin')
    h = _bearer(create_api_token('root', 'front', role='admin'))
    _oidc(monkeypatch, tenant_id='')
    assert api.anon().get('/api/directory/oidc/config', headers=h).get_json() == {'enabled': False}
    _oidc(monkeypatch)
    assert api.as_user({'username': 'root', 'role': 'admin'}).get('/api/directory/oidc/config').status_code == 403
    viewer = _bearer(create_api_token('root', 'ro', role='viewer'))
    r = api.anon().get('/api/directory/oidc/config', headers=viewer)
    assert r.status_code == 403 and b'CSECRET' not in r.data
