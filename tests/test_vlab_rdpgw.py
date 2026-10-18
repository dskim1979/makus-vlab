# -*- coding: utf-8 -*-
"""보안 게이트웨이 · 장치 연결 방식 (rdpgw): a pool on rdp_route 'devices' gets an .rdp through the
bundled RD Gateway with a token for that desktop only (pegaprox/vlab/rdpgw.py)."""
import base64
import hashlib
import hmac
import json
import time

import pytest

from pegaprox.vlab import rdpgw
from tests.test_vlab_warpgate import (_configure, _connect_env, _lines, _rdp_on, env, fake_wg,  # noqa: F401
                                      guest_agent, no_keyscan)

KEY = 'k' * 32


@pytest.fixture
def gw_on(monkeypatch):
    monkeypatch.setenv('VLAB_RDPGW', '1')
    monkeypatch.setenv('VLAB_RDPGW_KEY', KEY)
    monkeypatch.setenv('VLAB_RDPGW_HOST', 'moavi.example:8443')


def _claims(token, key=KEY):
    head, body, sig = token.split('.')
    want = hmac.new(key.encode(), f'{head}.{body}'.encode(), hashlib.sha256).digest()
    assert base64.urlsafe_b64decode(sig + '=' * (-len(sig) % 4)) == want
    assert json.loads(base64.urlsafe_b64decode(head + '=' * (-len(head) % 4)))['alg'] == 'HS256'
    return json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))


def _devices(admin, d, **policy):
    from pegaprox.vlab import store
    pool = store.get_desktop(d['id'])['pool_id']
    r = admin.put(f'/api/vlab/admin/pools/{pool}/policy', json={'protocols': ['rdp'], 'rdp_route': 'devices', **policy})
    assert r.status_code == 200, r.get_json()


def test_token_is_what_rdpgw_checks():
    now = int(time.time())
    c = _claims(rdpgw.paa_token(KEY, 'alice', '10.0.0.31:3389', '192.168.0.50', now=now))
    assert c['iss'] == 'rdpgw' and c['aud'] == ['rdpgw-paa'] and c['sub'] == 'alice'
    assert c['remoteServer'] == '10.0.0.31:3389' and c['clientIp'] == '192.168.0.50'
    assert c['exp'] == now + rdpgw.TOKEN_MINUTES * 60 and c['nbf'] <= now
    # every token is its own
    assert rdpgw.paa_token(KEY, 'alice', 'h:1', 'ip', now=now) != rdpgw.paa_token(KEY, 'alice', 'h:1', 'ip', now=now)


def test_the_key_must_be_32_characters(monkeypatch):
    monkeypatch.setenv('VLAB_RDPGW', '1')
    monkeypatch.setenv('VLAB_RDPGW_HOST', 'h')
    monkeypatch.setenv('VLAB_RDPGW_KEY', 'short')
    assert rdpgw.config()['enabled'] is False and '32' in rdpgw.config()['problem']


def test_rdp_route_is_record_or_devices(env, monkeypatch):
    admin, _alice, d = _connect_env(env, monkeypatch)
    from pegaprox.vlab import store
    pool = store.get_desktop(d['id'])['pool_id']
    assert admin.put(f'/api/vlab/admin/pools/{pool}/policy', json={'rdp_route': 'usb'}).status_code == 400
    assert admin.put(f'/api/vlab/admin/pools/{pool}/policy', json={'rdp_route': 'devices'}).status_code == 200


def test_devices_pool_gets_an_rdp_through_the_gateway(env, fake_wg, monkeypatch, gw_on):
    admin, alice, d = _connect_env(env, monkeypatch)
    _configure(admin)
    _rdp_on(admin)                          # Warpgate carries the .rdp of the other pools
    _devices(admin, d, client_drives=True, client_printers=True, usb_redirect=True)
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'})
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    lines = _lines(body['rdp'])
    assert body['via'] == 'rdpgw' and body['cert_url'] == '/moavi-gateway.crt'
    assert 'full address:s:10.0.0.31:3389' in lines and 'gatewayhostname:s:moavi.example:8443' in lines
    assert 'gatewayusagemethod:i:1' in lines and 'gatewaycredentialssource:i:5' in lines
    assert 'drivestoredirect:s:*' in lines and 'redirectprinters:i:1' in lines
    assert 'usbdevicestoredirect:s:*' in lines and 'devicestoredirect:s:*' in lines
    assert not any(x.startswith('password') for x in lines)
    token = next(x for x in lines if x.startswith('gatewayaccesstoken:s:')).split(':', 2)[2]
    c = _claims(token)
    assert c['remoteServer'] == '10.0.0.31:3389' and c['sub'] == 'alice' and c['clientIp']
    assert not fake_wg.tickets                # not through Warpgate


def test_devices_pool_without_usb_has_no_usb_lines(env, fake_wg, monkeypatch, gw_on):
    admin, alice, d = _connect_env(env, monkeypatch)
    _devices(admin, d, usb_redirect=False, client_drives=False)
    lines = _lines(alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'}).get_json()['rdp'])
    assert not any(x.startswith(('usbdevicestoredirect', 'devicestoredirect')) for x in lines)
    assert 'drivestoredirect:s:' in lines


def test_the_desktop_itself_keeps_the_device_switches(env, fake_wg, monkeypatch, gw_on, guest_agent):
    import pegaprox.api.vlab_next as nxt
    admin, alice, d = _connect_env(env, monkeypatch)
    nxt._rdp_devices_set.clear()
    _devices(admin, d, client_drives=False, client_printers=True, usb_redirect=True)
    alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'})
    script = [r for r in guest_agent.runs if 'fDisableCdm' in ' '.join(r['command'])]
    assert len(script) == 1
    text = script[0]['command'][-1]
    assert "Name 'fDisableCdm' -Value 1" in text and "Name 'fDisableCpm' -Value 0" in text
    assert "Name 'fDisablePNPRedir' -Value 0" in text
    alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'})   # unchanged: not again
    assert len([r for r in guest_agent.runs if 'fDisableCdm' in ' '.join(r['command'])]) == 1


def test_devices_pool_is_refused_when_the_gateway_is_off_and_warpgate_carries_rdp(env, fake_wg, monkeypatch):
    admin, alice, d = _connect_env(env, monkeypatch)
    _configure(admin)
    _rdp_on(admin)
    _devices(admin, d)
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'})
    body = r.get_json()
    assert r.status_code == 503 and body['code'] == 'RDPGW_OFF' and 'rdp' not in body
    assert '10.0.0.31' not in str(body) and not fake_wg.tickets


def test_devices_pool_goes_direct_when_no_gateway_is_on(env, fake_wg, monkeypatch):
    admin, alice, d = _connect_env(env, monkeypatch)
    _devices(admin, d, usb_redirect=True)
    body = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'}).get_json()
    lines = _lines(body['rdp'])
    assert body.get('via') is None and 'full address:s:10.0.0.31:3389' in lines
    assert 'usbdevicestoredirect:s:*' in lines and not any(x.startswith('gateway') for x in lines)


def test_record_pools_stay_on_warpgate(env, fake_wg, monkeypatch, gw_on):
    admin, alice, d = _connect_env(env, monkeypatch)
    _configure(admin)
    _rdp_on(admin)
    body = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'}).get_json()
    assert body['via'] == 'warpgate' and fake_wg.tickets


def test_admin_status_names_the_devices_pools(env, monkeypatch, gw_on):
    import pegaprox.api.vlab_warpgate as api_wg
    admin, alice, d = _connect_env(env, monkeypatch)
    _devices(admin, d)
    monkeypatch.setattr(api_wg.rdpgw, 'reachable', lambda timeout=2.0: True)
    assert alice.get('/api/vlab/admin/rdpgw').status_code == 403
    body = admin.get('/api/vlab/admin/rdpgw').get_json()
    assert body['config']['enabled'] is True and body['config']['host'] == 'moavi.example:8443'
    assert 'key' not in body['config'] and body['reachable'] is True and len(body['pools']) == 1
