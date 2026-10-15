"""White label kept for a trusted front end (/api/frontend/branding*).

API token with admin.settings only; values are cleaned (links, colours, image
references); images are checked by content and SVG is refused; a tenant falls
back to the default record; and a stale full-settings save cannot wipe it.
"""
import io

import pytest

import pegaprox.api.frontend_branding as fb
from pegaprox.api.helpers import load_server_settings, save_server_settings
from pegaprox.utils.auth import create_api_token

PNG = b'\x89PNG\r\n\x1a\n' + b'\x00' * 16
ICO = b'\x00\x00\x01\x00\x01\x00\x10\x10'
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'


def _bearer(tok):
    return {'Authorization': f"Bearer {tok['token']}"}


@pytest.fixture
def admin(api, seed, tmp_path, monkeypatch):
    monkeypatch.setattr(fb, 'BRANDING_DIR', str(tmp_path))
    seed.user('root', role='admin')
    return api.anon(), _bearer(create_api_token('root', 'front', role='admin'))


def test_values_are_cleaned_and_unknown_keys_dropped(admin):
    c, h = admin
    r = c.put('/api/frontend/branding', headers=h, json={'tenant': 'default', 'branding': {
        'enabled': True, 'appName': 'ACME', 'primaryColor': '00ECB2', 'docsUrl': 'javascript:alert(1)',
        'supportUrl': 'mailto:help@acme.example', 'logoUrl': 'https://evil.example/x.png', 'extra': 1,
        'loginHighlights': [{'icon': 'ri-shield-line', 'text': 'Safe'}, {'icon': '<img>', 'text': 'x'}]}})
    assert r.status_code == 200, r.data
    b = r.get_json()
    assert b['primaryColor'] == '#00ecb2' and b['docsUrl'] == '' and b['supportUrl'] == 'mailto:help@acme.example'
    assert b['logoUrl'] == '' and 'extra' not in b
    assert b['loginHighlights'] == [{'icon': 'ri-shield-line', 'text': 'Safe'}]


def test_a_tenant_falls_back_to_default_and_disabled_shows_defaults(admin):
    c, h = admin
    c.put('/api/frontend/branding', headers=h, json={'tenant': 'default', 'branding': {'enabled': True, 'appName': 'Provider'}})
    assert c.get('/api/frontend/branding/resolved?tenant=t_a', headers=h).get_json()['appName'] == 'Provider'
    c.put('/api/frontend/branding', headers=h, json={'tenant': 't_a', 'branding': {'enabled': True, 'appName': 'Tenant A'}})
    assert c.get('/api/frontend/branding/resolved?tenant=t_a', headers=h).get_json()['appName'] == 'Tenant A'
    c.put('/api/frontend/branding', headers=h, json={'tenant': 't_a', 'branding': {'enabled': False, 'appName': 'Tenant A'}})
    assert c.get('/api/frontend/branding/resolved?tenant=t_a', headers=h).get_json()['appName'] == 'MAKUS vLAB'


def test_images_are_checked_by_content(admin):
    c, h = admin
    up = lambda slot, data: c.post('/api/frontend/branding/image', headers=h, content_type='multipart/form-data',
                                   data={'tenant': 'default', 'slot': slot, 'file': (io.BytesIO(data), 'x.png')})
    assert up('logo', SVG).status_code == 415
    assert up('logo', ICO).status_code == 415
    r = up('logo', PNG)
    assert r.status_code == 200 and r.get_json()['image_url'].startswith('default/logo.png?v=')
    assert up('favicon', ICO).status_code == 200
    img = c.get('/api/frontend/branding/image/default/logo.png', headers=h)
    assert img.status_code == 200 and img.mimetype == 'image/png' and img.data == PNG
    assert c.get('/api/frontend/branding/image/default/..%2Fx.png', headers=h).status_code == 404
    assert c.delete('/api/frontend/branding/image', headers=h, json={'tenant': 'default', 'slot': 'logo'}).status_code == 200
    assert c.get('/api/frontend/branding/image/default/logo.png', headers=h).status_code == 404


def test_a_bad_tenant_is_refused(admin):
    c, h = admin
    assert c.put('/api/frontend/branding', headers=h, json={'tenant': '../etc', 'branding': {}}).status_code == 400
    assert c.get('/api/frontend/branding?tenant=a/b', headers=h).status_code == 400


def test_only_an_admin_api_token_may_call(api, seed, admin):
    c, _ = admin
    viewer = _bearer(create_api_token('root', 'ro', role='viewer'))
    assert c.get('/api/frontend/branding', headers=viewer).status_code == 403
    assert api.as_user({'username': 'root', 'role': 'admin'}).get('/api/frontend/branding').status_code == 403


def test_a_stale_full_settings_save_keeps_the_record(admin):
    c, h = admin
    stale = load_server_settings()
    c.put('/api/frontend/branding', headers=h, json={'tenant': 'default', 'branding': {'enabled': True, 'appName': 'Kept'}})
    save_server_settings(stale)
    assert c.get('/api/frontend/branding?tenant=default', headers=h).get_json()['appName'] == 'Kept'
