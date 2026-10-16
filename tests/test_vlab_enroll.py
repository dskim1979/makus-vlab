"""MOAVI Desk: LAB 단말 등록 - enrolment codes, the agent's enrolment and heartbeat, the kiosk key
handed out once, rejection, the portal's install file and the client MSI.

pegaprox/api/vlab_enroll.py, pegaprox/vlab/enroll.py.
"""
import io

import pytest

from pegaprox.api import vlab_enroll
from pegaprox.core import ha
from pegaprox.vlab import enroll, store

MAC = '00:11:22:33:44:55'
INFO = {'hostname': 'LAB301-PC01', 'mac': MAC, 'ip': '10.30.1.21', 'os': 'Windows 11 Pro 10.0.26100',
        'client_version': '0.9.1', 'agent_version': '0.9.1', 'user_logged_in': False, 'junk': 'x' * 999}
MSI = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'msi body' * 100
WINDOWS = ('_code_failures', '_enrolments', '_token_failures', '_heartbeats', '_installers')


@pytest.fixture
def env(api, seed, tmp_path, monkeypatch):
    monkeypatch.setattr(vlab_enroll, '_msi_path', lambda: str(tmp_path / 'vlab_client' / 'moavi-desk.msi'))
    for w in WINDOWS:
        getattr(vlab_enroll, w).reset()
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    lab = admin.post('/api/vlab/admin/labs', json={'name': '실습실 301'}).get_json()['lab']
    yield api, admin, alice, lab
    for w in WINDOWS:
        getattr(vlab_enroll, w).reset()


def _code(admin, **body):
    r = admin.post('/api/vlab/admin/enroll-codes', json={'name': '301호 배포', **body})
    assert r.status_code == 201, r.get_json()
    return r.get_json()


def _enrol(api, code, mac=MAC, name='LAB301-PC01'):
    return api.anon().post('/api/vlab/terminals/enroll', json={'mac': mac, 'name': name, 'code': code, 'info': INFO})


def _beat(api, token, info=INFO):
    return api.anon().post('/api/vlab/terminals/heartbeat', json={'info': info}, headers={'X-Agent-Token': token})


def _upload_msi(admin, data=MSI, name='MOAVI-Desk-0.9.1-x64.msi'):
    return admin.post('/api/vlab/admin/terminal-install/msi/upload', data={'file': (io.BytesIO(data), name)},
                      content_type='multipart/form-data')


def test_a_code_is_shown_once_and_kept_as_a_hash(env):
    api, admin, _, lab = env
    made = _code(admin, lab_id=lab['id'], max_uses=40, days=7)
    code = made['code']
    assert code.startswith('MDE-') and len(code) == 18
    (row,) = admin.get('/api/vlab/admin/enroll-codes').get_json()['codes']
    assert 'code' not in row and 'code_hash' not in row and code not in str(row)
    assert row['hint'] == code[-4:] and row['lab_name'] == '실습실 301' and row['status'] == 'active' and row['kind'] == 'admin'
    stored = store.db().query_one('SELECT code_hash FROM vlab_enroll_codes')['code_hash']
    assert len(stored) == 64 and code not in stored


def test_the_agent_enrols_beats_and_gets_its_key_once(env):
    api, admin, _, lab = env
    code = _code(admin, lab_id=lab['id'])['code']
    r = _enrol(api, code.lower().replace('-', ' '))      # typed loosely: case, spaces
    assert r.status_code == 201, r.get_json()
    got = r.get_json()
    assert got['state'] == 'pending' and got['lab']['name'] == '실습실 301' and got['token'].startswith('mda_')
    assert got['heartbeat_seconds'] == enroll.HEARTBEAT_SECONDS
    token = got['token']
    stored = store.db().query_one('SELECT token_hash FROM vlab_terminal_enrollments')['token_hash']
    assert token not in stored and len(stored) == 64

    beat = _beat(api, token).get_json()
    assert beat['state'] == 'pending' and 'key' not in beat
    (t,) = admin.get('/api/vlab/admin/terminals').get_json()['terminals']
    e = t['enrollment']
    assert t['state'] == 'pending' and t['lab_id'] == lab['id'] and t['registered_by'] == 'root'
    assert e['state'] == 'waiting' and e['online'] and e['code'] == '301호 배포'
    assert e['info']['os'].startswith('Windows 11') and 'junk' not in e['info'] and len(e['recent']) == 1

    assert admin.post('/api/vlab/admin/terminals/approve', json={'ids': [t['id']]}).status_code == 200
    beat = _beat(api, token).get_json()
    key = beat['key']
    assert key.startswith('mdt_') and beat['state'] == 'approved'
    assert api.anon().get('/api/vlab/kiosk', headers={'X-Terminal-Key': key}).status_code == 200
    # once: the next heartbeats carry no key, the token keeps working for them
    again = _beat(api, token)
    assert again.status_code == 200 and 'key' not in again.get_json()
    (t,) = admin.get('/api/vlab/admin/terminals').get_json()['terminals']
    assert t['enrollment']['state'] == 'delivered' and t['has_key'] and len(t['enrollment']['recent']) == 3


def test_a_new_key_goes_out_with_the_next_heartbeat_on_request(env):
    api, admin, _, lab = env
    token = _enrol(api, _code(admin, lab_id=lab['id'], auto_approve=True)['code']).get_json()['token']
    first = _beat(api, token).get_json()['key']
    t = store.terminal_by_mac(MAC)
    assert admin.post(f"/api/vlab/admin/terminals/{t['id']}/resend-key").status_code == 200
    second = _beat(api, token).get_json()['key']
    assert second != first
    assert api.anon().get('/api/vlab/kiosk', headers={'X-Terminal-Key': first}).status_code == 401
    assert api.anon().get('/api/vlab/kiosk', headers={'X-Terminal-Key': second}).status_code == 200


def test_rejected_pcs_lose_their_token_and_cannot_enrol_again(env):
    api, admin, _, lab = env
    code = _code(admin, lab_id=lab['id'], auto_approve=True)['code']
    token = _enrol(api, code).get_json()['token']
    key = _beat(api, token).get_json()['key']
    t = store.terminal_by_mac(MAC)
    r = admin.post('/api/vlab/admin/terminals/reject', json={'ids': [t['id']]})
    assert r.status_code == 200 and r.get_json()['terminals'][0]['state'] == 'rejected'
    assert _beat(api, token).status_code == 404               # the token is gone with the refusal
    assert api.anon().get('/api/vlab/kiosk', headers={'X-Terminal-Key': key}).status_code == 401
    r = _enrol(api, code)
    assert r.status_code == 403 and r.get_json()['code'] == 'REJECTED'
    # deleting the terminal lets the PC come back
    admin.delete(f"/api/vlab/admin/terminals/{t['id']}")
    assert _enrol(api, code).status_code == 201


def test_wrong_switched_off_used_up_and_expired_codes_are_refused(env):
    api, admin, _, _ = env
    assert _enrol(api, 'MDE-AAAA-BBBB-CCCC').get_json()['code'] == 'BAD_CODE'
    assert _enrol(api, '').status_code == 403

    one = _code(admin, max_uses=1)
    assert _enrol(api, one['code']).status_code == 201
    r = _enrol(api, one['code'], mac='00:11:22:33:44:66')
    assert r.status_code == 403 and r.get_json()['code'] == 'CODE_USED_UP'

    off = _code(admin)
    assert admin.put(f"/api/vlab/admin/enroll-codes/{off['enroll_code']['id']}", json={'enabled': False}).status_code == 200
    assert _enrol(api, off['code'], mac='00:11:22:33:44:77').get_json()['code'] == 'CODE_DISABLED'

    old = _code(admin, days=1)
    store.db().execute("UPDATE vlab_enroll_codes SET expires_at = '2020-01-01T00:00:00+00:00' WHERE id = ?",
                       (old['enroll_code']['id'],))
    assert _enrol(api, old['code'], mac='00:11:22:33:44:88').get_json()['code'] == 'CODE_EXPIRED'
    statuses = sorted(c['status'] for c in admin.get('/api/vlab/admin/enroll-codes').get_json()['codes'])
    assert statuses == ['disabled', 'expired', 'used_up']
    assert [t['mac'] for t in store.list_terminals()] == [MAC]


def test_no_code_no_terminal(env):
    """A signed-in client cannot put an unknown PC on the list any more."""
    _, _, alice, _ = env
    r = alice.post('/api/vlab/terminals/register', json={'mac': MAC, 'name': 'PC'})
    assert r.get_json()['state'] == 'unknown' and store.list_terminals() == []


def test_guessing_codes_and_tokens_stops_after_a_few_tries(env):
    api, admin, _, _ = env
    good = _code(admin)['code']
    for i in range(vlab_enroll._code_failures.limit):
        assert _enrol(api, f'MDE-AAAA-AAAA-AA{i:02d}').status_code == 403
    r = _enrol(api, good)
    assert r.status_code == 429 and r.get_json()['code'] == 'TOO_MANY'
    assert store.terminal_by_mac(MAC) is None
    for _ in range(vlab_enroll._token_failures.limit):
        assert _beat(api, 'mda_nope').status_code == 404
    assert _beat(api, 'mda_nope').status_code == 429


def test_one_agent_cannot_flood_heartbeats(env):
    api, admin, _, _ = env
    token = _enrol(api, _code(admin)['code']).get_json()['token']
    codes = [_beat(api, token).status_code for _ in range(vlab_enroll._heartbeats.limit + 1)]
    assert codes[-1] == 429 and set(codes[:-1]) == {200}


def test_enrolments_and_decisions_are_audited(env):
    api, admin, _, _ = env
    code = _code(admin)['code']
    _enrol(api, 'MDE-WRON-GGGG-GGGG', mac='00:11:22:33:44:99')
    token = _enrol(api, code).get_json()['token']
    t = store.terminal_by_mac(MAC)
    admin.post('/api/vlab/admin/terminals/approve', json={'ids': [t['id']]})
    _beat(api, token)
    admin.post('/api/vlab/admin/terminals/reject', json={'ids': [t['id']]})
    actions = [r['action'] for r in store.db().query('SELECT action FROM audit_log')]
    for a in ('vlab.enroll_code.create', 'vlab.terminal.enroll_refused', 'vlab.terminal.enroll', 'vlab.terminal.approve',
              'vlab.terminal.key_delivered', 'vlab.terminal.reject'):
        assert a in actions, a


def test_a_pc_that_held_a_key_waits_for_an_admin_again(env):
    api, admin, _, lab = env
    code = _code(admin, lab_id=lab['id'])['code']
    t = admin.post('/api/vlab/admin/terminals', json={'mac': MAC, 'lab_id': lab['id']}).get_json()['terminal']
    old = admin.post(f"/api/vlab/admin/terminals/{t['id']}/key").get_json()['key']
    got = _enrol(api, code).get_json()
    assert got['state'] == 'pending'
    assert api.anon().get('/api/vlab/kiosk', headers={'X-Terminal-Key': old}).status_code == 401
    assert 'key' not in _beat(api, got['token']).get_json()


def test_a_pre_registered_pc_gets_its_key_at_once(env):
    api, admin, _, lab = env
    admin.post('/api/vlab/admin/terminals', json={'mac': MAC, 'lab_id': lab['id']})
    got = _enrol(api, _code(admin)['code']).get_json()
    assert got['state'] == 'approved'
    assert _beat(api, got['token']).get_json()['key'].startswith('mdt_')


def test_a_key_typed_by_hand_is_not_sent_and_a_removed_terminal_ends_the_token(env):
    api, admin, _, _ = env
    code = _code(admin)['code']
    token = _enrol(api, code).get_json()['token']
    t = store.terminal_by_mac(MAC)
    admin.post(f"/api/vlab/admin/terminals/{t['id']}/key")
    assert 'key' not in _beat(api, token).get_json()
    assert admin.get('/api/vlab/admin/terminals').get_json()['terminals'][0]['enrollment']['state'] == 'manual'
    admin.delete(f"/api/vlab/admin/terminals/{t['id']}")
    assert _beat(api, token).status_code == 404


def test_a_pc_left_waiting_too_long_enrols_again(env):
    api, admin, _, _ = env
    token = _enrol(api, _code(admin)['code']).get_json()['token']
    store.db().execute("UPDATE vlab_terminal_enrollments SET created_at = '2020-01-01T00:00:00+00:00'")
    r = _beat(api, token)
    assert r.status_code == 410 and r.get_json()['code'] == 'TOKEN_EXPIRED'
    assert _beat(api, token).status_code == 404


def test_an_agent_gone_quiet_shows_offline(env):
    api, admin, _, _ = env
    _enrol(api, _code(admin)['code'])
    store.db().execute("UPDATE vlab_terminal_enrollments SET last_poll_at = '2020-01-01T00:00:00+00:00'")
    (t,) = admin.get('/api/vlab/admin/terminals').get_json()['terminals']
    assert t['enrollment']['online'] is False


def test_approving_many_into_a_lab(env):
    api, admin, _, lab = env
    code = _code(admin)['code']
    for i in range(3):
        _enrol(api, code, mac=f'00:11:22:33:44:{i:02d}', name=f'PC{i}')
    ids = [t['id'] for t in store.list_terminals()]
    r = admin.post('/api/vlab/admin/terminals/approve', json={'ids': ids + ['term_unknown'], 'lab_id': lab['id']})
    body = r.get_json()
    assert body['missing'] == ['term_unknown'] and len(body['terminals']) == 3
    assert {t['state'] for t in store.list_terminals()} == {'approved'}
    assert {t['lab_id'] for t in store.list_terminals()} == {lab['id']}
    assert admin.post('/api/vlab/admin/terminals/approve', json={'ids': []}).status_code == 400
    assert admin.post('/api/vlab/admin/terminals/approve', json={'ids': ids, 'lab_id': 'nope'}).status_code == 404


# --- the portal's install file -------------------------------------------------------------

def _open_portal(admin, **more):
    r = admin.put('/api/vlab/admin/terminal-install', json={'lab_install_enabled': True, 'lab_install_roles': ['admin', 'user'], **more})
    assert r.status_code == 200, r.get_json()


def test_the_msi_upload_is_checked_and_served_with_its_hash(env):
    api, admin, alice, _ = env
    assert _upload_msi(admin, b'MZ not an msi').status_code == 400
    assert alice.get('/api/vlab/admin/terminal-install').status_code == 403
    r = _upload_msi(admin)
    assert r.status_code == 200
    import hashlib
    assert r.get_json()['msi']['sha256'] == hashlib.sha256(MSI).hexdigest().upper() and r.get_json()['msi']['version'] == '0.9.1'
    got = api.anon().get('/api/vlab/client/msi')
    assert got.status_code == 200 and got.data == MSI
    got.close()
    assert admin.delete('/api/vlab/admin/terminal-install/msi').status_code == 200
    assert api.anon().get('/api/vlab/client/msi').status_code == 404


def test_anyone_allowed_gets_a_one_file_installer_with_a_token_for_them(env):
    api, admin, alice, lab = env
    assert alice.get('/api/vlab/lab-install').get_json()['allowed'] is False
    assert alice.post('/api/vlab/lab-install', json={}).status_code == 403
    _open_portal(admin)
    assert alice.post('/api/vlab/lab-install', json={}).status_code == 409      # no MSI yet
    _upload_msi(admin)
    info = alice.get('/api/vlab/lab-install').get_json()
    assert info['allowed'] and info['labs'][0]['name'] == '실습실 301' and info['auto_approve'] is False

    r = alice.post('/api/vlab/lab-install', json={'lab_id': lab['id'], 'uses': 2})
    assert r.status_code == 200 and 'attachment' in r.headers['Content-Disposition']
    text = r.data.decode()
    import hashlib
    import re
    assert hashlib.sha256(MSI).hexdigest().upper() in text and '/api/vlab/client/msi' in text and 'RunAs' in text
    assert 'SERVER=localhost' in text and 'KIOSK=1' in text and '/qn' in text
    code = re.search(r'ENROLL_TOKEN=(MDE-[A-Z0-9-]+)', text).group(1)
    (row,) = admin.get('/api/vlab/admin/enroll-codes?kind=user').get_json()['codes']
    assert row['created_by'] == 'alice' and row['max_uses'] == 2 and row['lab_id'] == lab['id'] and not row['auto_approve']

    got = _enrol(api, code).get_json()
    assert got['state'] == 'pending'
    (t,) = admin.get('/api/vlab/admin/terminals').get_json()['terminals']
    assert t['registered_by'] == 'alice' and t['enrollment']['requested_by'] == 'alice' and t['enrollment']['code_kind'] == 'user'
    actions = [r['action'] for r in store.db().query('SELECT action FROM audit_log')]
    assert 'vlab.enroll_token.issue' in actions


def test_portal_files_are_limited(env):
    api, admin, alice, _ = env
    _open_portal(admin, user_active_tokens=2, max_uses=5)
    _upload_msi(admin)
    assert alice.post('/api/vlab/lab-install', json={'uses': 6}).status_code == 400
    assert alice.post('/api/vlab/lab-install', json={'lab_id': 'nope'}).status_code == 404
    assert alice.post('/api/vlab/lab-install', json={}).status_code == 200
    assert alice.post('/api/vlab/lab-install', json={}).status_code == 200
    assert alice.post('/api/vlab/lab-install', json={}).status_code == 409     # two unused already


def test_auto_approval_follows_the_role_even_for_admins(env):
    api, admin, alice, lab = env
    _open_portal(admin)
    _upload_msi(admin)
    import re
    text = admin.post('/api/vlab/lab-install', json={'lab_id': lab['id']}).data.decode()
    code = re.search(r'ENROLL_TOKEN=(MDE-[A-Z0-9-]+)', text).group(1)
    assert _enrol(api, code).get_json()['state'] == 'pending'               # admin, but not in the list
    admin.put('/api/vlab/admin/terminal-install', json={'auto_approve_roles': ['admin']})
    text = admin.post('/api/vlab/lab-install', json={'lab_id': lab['id']}).data.decode()
    code = re.search(r'ENROLL_TOKEN=(MDE-[A-Z0-9-]+)', text).group(1)
    assert _enrol(api, code, mac='00:11:22:33:44:66').get_json()['state'] == 'approved'


def test_install_files_for_a_code_and_for_a_personal_pc(env):
    api, admin, alice, _ = env
    code = _code(admin)['code']
    assert admin.post('/api/vlab/admin/installer', json={'code': code}).status_code == 409   # no MSI
    _upload_msi(admin)
    admin.put('/api/vlab/admin/terminal-install', json={'server_url': 'https://desk.example.com:8443',
                                                         'server_cert_sha256': 'ab:' * 31 + 'ab'})
    text = admin.post('/api/vlab/admin/installer', json={'code': code, 'kiosk': True}).data.decode()
    assert f'ENROLL_TOKEN={code}' in text and 'SERVER=desk.example.com PORT=8443 HTTPS=1' in text
    assert 'SERVER_CERT_SHA256=' + 'AB' * 32 in text and 'GetRawCertData' in text
    assert admin.post('/api/vlab/admin/installer', json={'code': 'MDE-NOPE-NOPE-NOPE'}).status_code == 400
    assert alice.post('/api/vlab/admin/installer', json={'code': code}).status_code == 403
    personal = alice.get('/api/vlab/client/installer')
    assert personal.status_code == 200
    body = personal.data.decode()
    assert 'ENROLL_TOKEN' not in body and 'KIOSK' not in body and 'SERVER=desk.example.com' in body


def test_install_settings_are_checked(env):
    _, admin, _, _ = env
    put = lambda **b: admin.put('/api/vlab/admin/terminal-install', json=b).status_code
    assert put(token_hours=0) == 400 and put(max_uses=True) == 400 and put(lab_install_roles='admin') == 400
    assert put(server_url='ftp://x') == 400 and put(server_cert_sha256='xyz') == 400 and put(nope=1) == 400
    assert put(token_hours=48, kiosk=False) == 200
    s = admin.get('/api/vlab/admin/terminal-install').get_json()['settings']
    assert s['token_hours'] == 48 and s['kiosk'] is False and s['msi_ready'] is False and s['pending'] == 0


def test_code_input_is_checked(env):
    _, admin, _, _ = env
    assert admin.post('/api/vlab/admin/enroll-codes', json={'name': ''}).status_code == 400
    assert admin.post('/api/vlab/admin/enroll-codes', json={'name': 'x', 'days': 9999}).status_code == 400
    assert admin.post('/api/vlab/admin/enroll-codes', json={'name': 'x', 'max_uses': -1}).status_code == 400
    assert admin.post('/api/vlab/admin/enroll-codes', json={'name': 'x', 'lab_id': 'nope'}).status_code == 404
    cid = _code(admin)['enroll_code']['id']
    assert admin.delete(f'/api/vlab/admin/enroll-codes/{cid}').status_code == 200
    assert admin.delete(f'/api/vlab/admin/enroll-codes/{cid}').status_code == 404


def test_a_removed_lab_leaves_its_codes_without_one(env):
    _, admin, _, lab = env
    _code(admin, lab_id=lab['id'])
    admin.delete(f"/api/vlab/admin/labs/{lab['id']}")
    assert admin.get('/api/vlab/admin/enroll-codes').get_json()['codes'][0]['lab_id'] is None


def test_only_pool_managers_handle_codes_and_decisions(env):
    api, _, alice, _ = env
    assert alice.get('/api/vlab/admin/enroll-codes').status_code == 403
    assert alice.post('/api/vlab/admin/enroll-codes', json={'name': 'x'}).status_code == 403
    for path in ('approve', 'reject'):
        assert alice.post(f'/api/vlab/admin/terminals/{path}', json={'ids': ['x']}).status_code == 403
    assert alice.post('/api/vlab/admin/terminals/x/resend-key').status_code == 403
    assert api.anon().get('/api/vlab/admin/enroll-codes').status_code == 401
    assert api.anon().get('/api/vlab/lab-install').status_code == 401
    assert api.anon().get('/api/vlab/client/installer').status_code == 401


def test_the_tables_travel_to_the_ha_peers_without_the_heartbeats():
    assert {'vlab_enroll_codes', 'vlab_terminal_enrollments'} <= set(ha.SYNC_TABLES)
    assert set(ha.VOLATILE_COLUMNS['vlab_terminal_enrollments']) == {'last_poll_at', 'info', 'recent'}
