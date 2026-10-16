"""MOAVI Desk: LAB 단말 대량 등록 - enrolment codes, a PC's first start, the key handed out once.

pegaprox/api/vlab_enroll.py, pegaprox/vlab/enroll.py.
"""
import pytest

from pegaprox.api import vlab_enroll
from pegaprox.core import ha
from pegaprox.vlab import enroll, store

MAC = '00:11:22:33:44:55'


@pytest.fixture
def env(api, seed):
    for w in (vlab_enroll._code_failures, vlab_enroll._enrolments, vlab_enroll._token_failures):
        w.reset()
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    lab = admin.post('/api/vlab/admin/labs', json={'name': '실습실 301'}).get_json()['lab']
    yield api, admin, alice, lab
    for w in (vlab_enroll._code_failures, vlab_enroll._enrolments, vlab_enroll._token_failures):
        w.reset()


def _code(admin, **body):
    r = admin.post('/api/vlab/admin/enroll-codes', json={'name': '301호 배포', **body})
    assert r.status_code == 201, r.get_json()
    return r.get_json()


def _enrol(api, code, mac=MAC, name='LAB301-PC01'):
    return api.anon().post('/api/vlab/terminals/enroll', json={'mac': mac, 'name': name, 'code': code})


def _poll(api, token):
    return api.anon().post('/api/vlab/terminals/enroll/status', json={'token': token})


def test_a_code_is_shown_once_and_kept_as_a_hash(env):
    api, admin, _, lab = env
    made = _code(admin, lab_id=lab['id'], max_uses=40, days=7)
    code = made['code']
    assert code.startswith('MDE-') and len(code) == 18
    listed = admin.get('/api/vlab/admin/enroll-codes').get_json()['codes']
    assert len(listed) == 1
    row = listed[0]
    assert 'code' not in row and 'code_hash' not in row and code not in str(row)
    assert row['hint'] == code[-4:] and row['lab_name'] == '실습실 301' and row['status'] == 'active'
    assert row['max_uses'] == 40 and row['expires_at']
    stored = store.db().query_one('SELECT code_hash FROM vlab_enroll_codes')['code_hash']
    assert len(stored) == 64 and code not in stored


def test_a_pc_enrols_waits_and_gets_its_key_once(env):
    api, admin, _, lab = env
    code = _code(admin, lab_id=lab['id'])['code']
    r = _enrol(api, code.lower().replace('-', ' '))      # typed loosely: case, spaces
    assert r.status_code == 201, r.get_json()
    got = r.get_json()
    assert got['state'] == 'pending' and got['lab']['name'] == '실습실 301' and got['token'].startswith('mdp_')
    token = got['token']

    t = store.terminal_by_mac(MAC)
    assert t['state'] == 'pending' and t['lab_id'] == lab['id'] and t['name'] == 'LAB301-PC01'
    assert _poll(api, token).get_json()['state'] == 'pending'
    listed = admin.get('/api/vlab/admin/terminals').get_json()['terminals']
    assert listed[0]['enrollment']['state'] == 'waiting' and listed[0]['enrollment']['code'] == '301호 배포'

    r = admin.post('/api/vlab/admin/terminals/approve', json={'ids': [t['id']]})
    assert r.status_code == 200 and r.get_json()['terminals'][0]['state'] == 'approved'

    r = _poll(api, token)
    assert r.status_code == 200
    key = r.get_json()['key']
    assert key.startswith('mdt_') and r.get_json()['state'] == 'approved'
    # the key works on the kiosk, and the token is spent
    assert api.anon().get('/api/vlab/kiosk', headers={'X-Terminal-Key': key}).status_code == 200
    again = _poll(api, token)
    assert again.status_code == 404 and 'key' not in again.get_json()
    listed = admin.get('/api/vlab/admin/terminals').get_json()['terminals']
    assert listed[0]['enrollment']['state'] == 'delivered' and listed[0]['has_key']


def test_an_auto_approve_code_hands_the_key_on_the_first_poll(env):
    api, admin, _, lab = env
    code = _code(admin, lab_id=lab['id'], auto_approve=True)['code']
    got = _enrol(api, code).get_json()
    assert got['state'] == 'approved'
    r = _poll(api, got['token']).get_json()
    assert r['key'].startswith('mdt_') and r['lab']['id'] == lab['id']


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
    # nothing was made for the refused ones
    assert [t['mac'] for t in store.list_terminals()] == [MAC]


def test_guessing_codes_stops_after_a_few_tries(env):
    api, admin, _, _ = env
    good = _code(admin)['code']
    for i in range(vlab_enroll._code_failures.limit):
        assert _enrol(api, f'MDE-AAAA-AAAA-AA{i:02d}').status_code == 403
    r = _enrol(api, good)
    assert r.status_code == 429 and r.get_json()['code'] == 'TOO_MANY'
    assert store.terminal_by_mac(MAC) is None


def test_guessing_tokens_stops_after_a_few_tries(env):
    api, _, _, _ = env
    for _ in range(vlab_enroll._token_failures.limit):
        assert _poll(api, 'mdp_nope').status_code == 404
    assert _poll(api, 'mdp_nope').status_code == 429


def test_enrolments_and_refusals_are_audited(env):
    api, admin, _, _ = env
    code = _code(admin, auto_approve=True)['code']
    _enrol(api, 'MDE-WRON-GGGG-GGGG', mac='00:11:22:33:44:99')
    token = _enrol(api, code).get_json()['token']
    _poll(api, token)
    actions = [r['action'] for r in store.db().query('SELECT action FROM audit_log')]
    for a in ('vlab.enroll_code.create', 'vlab.terminal.enroll_refused', 'vlab.terminal.enroll',
              'vlab.terminal.key_delivered'):
        assert a in actions, a


def test_a_pc_that_held_a_key_waits_for_an_admin_again(env):
    api, admin, _, lab = env
    code = _code(admin, lab_id=lab['id'])['code']
    t = admin.post('/api/vlab/admin/terminals', json={'mac': MAC, 'lab_id': lab['id']}).get_json()['terminal']
    old = admin.post(f"/api/vlab/admin/terminals/{t['id']}/key").get_json()['key']
    got = _enrol(api, code).get_json()
    assert got['state'] == 'pending'
    # someone sending this MAC does not take over the kiosk: the old key stops until approval
    assert api.anon().get('/api/vlab/kiosk', headers={'X-Terminal-Key': old}).status_code == 401
    assert 'key' not in _poll(api, got['token']).get_json()


def test_a_pre_registered_pc_gets_its_key_at_once(env):
    api, admin, _, lab = env
    admin.post('/api/vlab/admin/terminals', json={'mac': MAC, 'lab_id': lab['id']})
    got = _enrol(api, _code(admin)['code']).get_json()
    assert got['state'] == 'approved'
    assert _poll(api, got['token']).get_json()['key'].startswith('mdt_')


def test_a_key_typed_by_hand_or_a_removed_terminal_ends_the_wait(env):
    api, admin, _, _ = env
    code = _code(admin)['code']
    token = _enrol(api, code).get_json()['token']
    t = store.terminal_by_mac(MAC)
    admin.post(f"/api/vlab/admin/terminals/{t['id']}/key")
    assert _poll(api, token).status_code == 404
    assert admin.get('/api/vlab/admin/terminals').get_json()['terminals'][0]['enrollment']['state'] == 'manual'

    token = _enrol(api, code, mac='00:11:22:33:44:66').get_json()['token']
    t = store.terminal_by_mac('00:11:22:33:44:66')
    admin.delete(f"/api/vlab/admin/terminals/{t['id']}")
    assert _poll(api, token).status_code == 404     # its enrolment went with it


def test_a_waiting_token_runs_out(env):
    api, admin, _, _ = env
    token = _enrol(api, _code(admin)['code']).get_json()['token']
    store.db().execute("UPDATE vlab_terminal_enrollments SET created_at = '2020-01-01T00:00:00+00:00'")
    r = _poll(api, token)
    assert r.status_code == 410 and r.get_json()['code'] == 'TOKEN_EXPIRED'


def test_approving_many_into_a_lab(env):
    api, admin, _, lab = env
    code = _code(admin)['code']
    for i in range(3):
        _enrol(api, code, mac=f'00:11:22:33:44:{i:02d}', name=f'PC{i}')
    ids = [t['id'] for t in store.list_terminals()]
    r = admin.post('/api/vlab/admin/terminals/approve', json={'ids': ids + ['term_unknown'], 'lab_id': lab['id']})
    assert r.status_code == 200
    body = r.get_json()
    assert body['missing'] == ['term_unknown'] and len(body['terminals']) == 3
    assert {t['state'] for t in store.list_terminals()} == {'approved'}
    assert {t['lab_id'] for t in store.list_terminals()} == {lab['id']}
    assert admin.post('/api/vlab/admin/terminals/approve', json={'ids': []}).status_code == 400
    assert admin.post('/api/vlab/admin/terminals/approve', json={'ids': ids, 'lab_id': 'nope'}).status_code == 404


def test_code_input_is_checked(env):
    _, admin, _, _ = env
    assert admin.post('/api/vlab/admin/enroll-codes', json={'name': ''}).status_code == 400
    assert admin.post('/api/vlab/admin/enroll-codes', json={'name': 'x', 'days': 9999}).status_code == 400
    assert admin.post('/api/vlab/admin/enroll-codes', json={'name': 'x', 'max_uses': -1}).status_code == 400
    assert admin.post('/api/vlab/admin/enroll-codes', json={'name': 'x', 'lab_id': 'nope'}).status_code == 404
    made = _code(admin)
    cid = made['enroll_code']['id']
    assert admin.delete(f'/api/vlab/admin/enroll-codes/{cid}').status_code == 200
    assert admin.delete(f'/api/vlab/admin/enroll-codes/{cid}').status_code == 404


def test_a_removed_lab_leaves_its_codes_without_one(env):
    _, admin, _, lab = env
    _code(admin, lab_id=lab['id'])
    admin.delete(f"/api/vlab/admin/labs/{lab['id']}")
    assert admin.get('/api/vlab/admin/enroll-codes').get_json()['codes'][0]['lab_id'] is None


def test_only_pool_managers_handle_codes_and_approvals(env):
    api, _, alice, _ = env
    assert alice.get('/api/vlab/admin/enroll-codes').status_code == 403
    assert alice.post('/api/vlab/admin/enroll-codes', json={'name': 'x'}).status_code == 403
    assert alice.post('/api/vlab/admin/terminals/approve', json={'ids': ['x']}).status_code == 403
    assert api.anon().get('/api/vlab/admin/enroll-codes').status_code == 401
    assert api.anon().put('/api/vlab/admin/enroll-codes/x', json={}).status_code == 401
    assert api.anon().delete('/api/vlab/admin/enroll-codes/x').status_code == 401


def test_the_tables_travel_to_the_ha_peers():
    assert {'vlab_enroll_codes', 'vlab_terminal_enrollments'} <= set(ha.SYNC_TABLES)
    assert enroll.TOKEN_DAYS > 0
