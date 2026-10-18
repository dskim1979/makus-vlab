"""MOAVI Desk next-phase screens (pegaprox/api/vlab_next.py): departments, sign-up review,
the USB device library, external desktops, golden images, the board lab, the
build farm and licence servers. docs/vlab-design.md 4-2, 7-3, 10-2..10-4.
"""
import pytest

from pegaprox.vlab import catalog, store

CID = 'cluster_1'
RES = [
    {'vmid': 300, 'node': 'pve1', 'name': 'lab-win11-01', 'type': 'qemu', 'status': 'running', 'cpu': 0.5, 'maxcpu': 4,
     'mem': 2 * 1024 ** 3, 'maxmem': 8 * 1024 ** 3},
    {'vmid': 301, 'node': 'pve2', 'name': 'lab-win11-02', 'type': 'qemu', 'status': 'stopped', 'maxcpu': 4, 'maxmem': 8 * 1024 ** 3},
    {'vmid': 500, 'node': 'pve1', 'name': 'gold-win11', 'type': 'qemu', 'status': 'stopped'},
    {'vmid': 900, 'node': 'pve1', 'name': 'tpl-ubuntu', 'type': 'qemu', 'status': 'stopped', 'template': 1},
]
SNAPS = [{'name': 'gold-20261001-090000', 'description': 'v1', 'snaptime': 1790000000},
         {'name': 'vlab-base', 'description': '', 'snaptime': 1780000000}, {'name': 'current'}]


@pytest.fixture
def env(api, seed):
    mgr = api.make_fake_manager(
        CID, get_vm_resources=RES, get_snapshots=SNAPS,
        create_snapshot={'success': True, 'data': 'UPID:snap'},
        clone_vm={'success': True, 'data': 'UPID:clone'},
        get_next_vmid={'success': True, 'vmid': 1000},
        update_vm_config={'success': True})
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    bob = api.as_user(seed.user('bob', role='user'))
    viewer = api.as_user(seed.user('vera', role='viewer'))
    return api, mgr, admin, alice, bob, viewer


# --- departments -------------------------------------------------------------------------

def test_departments_tree_and_members(env):
    _, _, admin, alice, _, _ = env
    assert alice.post('/api/vlab/admin/departments', json={'name': '공과대학'}).status_code == 403
    r = admin.post('/api/vlab/admin/departments', json={'name': '공과대학'})
    assert r.status_code == 201, r.get_json()
    top = r.get_json()['department']
    sub = admin.post('/api/vlab/admin/departments', json={'name': '전자공학과', 'parent_id': top['id']}).get_json()['department']
    assert admin.put(f"/api/vlab/admin/departments/{top['id']}", json={'name': '공과대학', 'parent_id': sub['id']}).status_code == 400
    assert admin.post('/api/vlab/admin/departments', json={'name': 'x', 'parent_id': 'dep_nope'}).status_code == 400

    assert admin.put('/api/vlab/admin/users/alice/department', json={'department_id': sub['id']}).status_code == 200
    assert admin.put('/api/vlab/admin/users/nobody/department', json={'department_id': sub['id']}).status_code == 404
    deps = {d['id']: d for d in admin.get('/api/vlab/admin/departments').get_json()['departments']}
    assert deps[sub['id']]['members'] == 1 and deps[top['id']]['members'] == 0
    assert admin.get(f"/api/vlab/admin/departments/{top['id']}/members").get_json()['members'] == []
    got = admin.get(f"/api/vlab/admin/departments/{top['id']}/members?children=1").get_json()['members']
    assert [m['username'] for m in got] == ['alice']

    assert admin.delete(f"/api/vlab/admin/departments/{top['id']}").status_code == 409
    assert admin.delete(f"/api/vlab/admin/departments/{sub['id']}").status_code == 200
    assert catalog.department_of('alice') is None


# --- accounts and roles (thin wrappers over pegaprox/api/users.py) --------------------------

PW = 'Str0ng!Passw0rd#'


def test_accounts_made_changed_and_deleted_through_the_vlab_api(env):
    _, _, admin, alice, _, _ = env
    from pegaprox.utils.auth import load_users
    body = {'username': 'kim', 'password': PW, 'display_name': '김교수', 'email': 'kim@example.com', 'role': 'user'}
    assert alice.post('/api/vlab/admin/users', json=body).status_code == 403
    # only the form's fields: no tenant, no extra permissions, no portal_only
    for extra in ({'tenant_id': 'other'}, {'permissions': ['admin.users']}, {'portal_only': True}):
        r = admin.post('/api/vlab/admin/users', json=dict(body, **extra))
        assert r.status_code == 400 and 'Not accepted' in r.get_json()['error']
    assert admin.post('/api/vlab/admin/users', json=dict(body, password='short')).status_code == 400
    assert admin.post('/api/vlab/admin/users', json=dict(body, department_id='dep_nope')).status_code == 400
    dep = admin.post('/api/vlab/admin/departments', json={'name': '전자공학과'}).get_json()['department']
    r = admin.post('/api/vlab/admin/users', json=dict(body, department_id=dep['id'], must_change_password=True))
    assert r.status_code == 201, r.get_json()
    assert r.get_json()['user']['must_change_password'] is True
    assert admin.post('/api/vlab/admin/users', json=body).status_code == 409
    u = load_users()['kim']
    assert u['force_password_change'] and u['display_name'] == '김교수'
    assert catalog.department_of('kim') == dep['id']
    listed = {x['username']: x for x in admin.get('/api/vlab/admin/users?all=1').get_json()['users']}
    assert listed['kim']['department_id'] == dep['id'] and listed['kim']['must_change_password'] is True
    assert listed['kim']['totp_enabled'] is False

    r = admin.put('/api/vlab/admin/users/kim', json={'display_name': '김 교수', 'enabled': False, 'department_id': None})
    assert r.status_code == 200, r.get_json()
    u = load_users()['kim']
    assert u['display_name'] == '김 교수' and u['enabled'] is False and catalog.department_of('kim') is None
    assert admin.put('/api/vlab/admin/users/kim', json={'password': PW}).status_code == 400
    assert admin.put('/api/vlab/admin/users/kim', json={'enabled': 'no'}).status_code == 400
    assert admin.put('/api/vlab/admin/users/kim', json={'role': 'nope'}).status_code == 400
    assert admin.put('/api/vlab/admin/users/nobody', json={'display_name': 'x'}).status_code == 404
    assert admin.put('/api/vlab/admin/users/root', json={'role': 'user'}).status_code == 403    # own role

    assert admin.delete('/api/vlab/admin/users/root').status_code == 400                      # self
    admin.put('/api/vlab/admin/users/kim/department', json={'department_id': dep['id']})
    assert admin.delete('/api/vlab/admin/users/kim').status_code == 200
    assert 'kim' not in load_users() and catalog.department_of('kim') is None


def test_password_and_2fa_reset_and_unlock(env):
    _, _, admin, alice, _, _ = env
    import time
    from pegaprox.globals import login_attempts_by_user
    from pegaprox.utils.auth import load_users, save_single_user
    assert alice.put('/api/vlab/admin/users/bob/password', json={'password': PW}).status_code == 403
    assert admin.put('/api/vlab/admin/users/bob/password', json={'password': PW, 'role': 'admin'}).status_code == 400
    r = admin.put('/api/vlab/admin/users/bob/password', json={'password': PW, 'must_change_password': True})
    assert r.status_code == 200, r.get_json()
    assert load_users()['bob']['force_password_change'] is True
    admin.put('/api/vlab/admin/users/bob/password', json={'password': PW})
    assert load_users()['bob']['force_password_change'] is False

    ldap = load_users()['vera']
    ldap['auth_source'] = 'ldap'
    save_single_user('vera', ldap)
    assert admin.put('/api/vlab/admin/users/vera/password', json={'password': PW}).status_code == 400

    b = load_users()['bob']
    b.update(totp_enabled=True, totp_secret='JBSWY3DPEHPK3PXP')
    save_single_user('bob', b)
    assert alice.delete('/api/vlab/admin/users/bob/2fa').status_code == 403
    assert admin.delete('/api/vlab/admin/users/bob/2fa').status_code == 200
    assert load_users()['bob']['totp_enabled'] is False

    login_attempts_by_user['bob'] = {'locked_until': time.time() + 600, 'attempts': [1, 2, 3]}
    try:
        assert alice.get('/api/vlab/admin/locked-users').status_code == 403
        locked = admin.get('/api/vlab/admin/locked-users').get_json()['users']
        assert [x['username'] for x in locked] == ['bob'] and locked[0]['attempt_count'] == 3
        assert admin.delete('/api/vlab/admin/locked-users/bob').status_code == 200
        assert admin.get('/api/vlab/admin/locked-users').get_json()['users'] == []
        assert admin.delete('/api/vlab/admin/locked-users/bob').status_code == 404
    finally:
        login_attempts_by_user.pop('bob', None)


def test_custom_roles_through_the_vlab_api(env):
    _, _, admin, alice, _, _ = env
    perms = admin.get('/api/vlab/admin/permissions').get_json()
    assert 'vlab.desk' in {p['permission'] for p in perms} and all('category' in p for p in perms)
    roles = {r['id']: r for r in admin.get('/api/vlab/admin/roles').get_json()}
    assert roles['admin']['builtin'] and roles['user']['builtin']
    assert any(t['id'] == 'tenant_admin' for t in admin.get('/api/vlab/admin/roles/templates').get_json())

    body = {'id': 'ta', 'name': '조교', 'permissions': ['vlab.desk', 'vm.view']}
    assert alice.post('/api/vlab/admin/roles', json=body).status_code == 403
    assert admin.post('/api/vlab/admin/roles', json=dict(body, created_by='x')).status_code == 400
    assert admin.post('/api/vlab/admin/roles', json=dict(body, permissions='vm.view')).status_code == 400
    assert admin.post('/api/vlab/admin/roles', json=dict(body, permissions=['no.such'])).status_code == 400
    r = admin.post('/api/vlab/admin/roles', json=body)
    assert r.status_code == 200, r.get_json()
    assert admin.put('/api/vlab/admin/roles/ta', json={'name': '조교(전자)', 'permissions': ['vlab.desk']}).status_code == 200
    got = {x['id']: x for x in admin.get('/api/vlab/admin/roles').get_json()}['ta']
    assert got['name'] == '조교(전자)' and got['permissions'] == ['vlab.desk']
    assert admin.put('/api/vlab/admin/roles/user', json={'name': 'x'}).status_code == 400       # builtin

    assert admin.post('/api/vlab/admin/users', json={'username': 'cho', 'password': PW, 'role': 'ta'}).status_code == 201
    r = admin.delete('/api/vlab/admin/roles/ta')
    assert r.status_code == 409 and r.get_json()['users'] == ['cho']
    admin.put('/api/vlab/admin/users/cho', json={'role': 'user'})
    assert admin.delete('/api/vlab/admin/roles/ta').status_code == 200

    r = admin.post('/api/vlab/admin/roles/templates/tenant_admin/apply', json={'role_id': 'dept_admin', 'name': '학과 관리자'})
    assert r.status_code == 200, r.get_json()
    assert 'dept_admin' in {x['id'] for x in admin.get('/api/vlab/admin/roles').get_json()}


# --- sign-up review ----------------------------------------------------------------------

def test_signup_closed_by_default_and_reviewed_by_an_admin(env):
    api, _, admin, alice, _, _ = env
    anon = api.anon()
    assert anon.get('/api/vlab/signup/config').get_json() == {'enabled': False, 'departments': []}
    body = {'username': 'newbie', 'password': 'Str0ng!Passw0rd#', 'display_name': '새 학생', 'email': 'n@example.com'}
    assert anon.post('/api/vlab/signup', json=body).status_code == 403

    assert alice.put('/api/vlab/admin/signup-settings', json={'enabled': True}).status_code == 403
    assert admin.put('/api/vlab/admin/signup-settings', json={'enabled': 'yes'}).status_code == 400
    assert admin.put('/api/vlab/admin/signup-settings', json={'enabled': True}).status_code == 200
    dep = admin.post('/api/vlab/admin/departments', json={'name': '컴퓨터공학과'}).get_json()['department']
    cfg = anon.get('/api/vlab/signup/config').get_json()
    assert cfg['enabled'] and cfg['departments'][0]['name'] == '컴퓨터공학과'

    assert anon.post('/api/vlab/signup', json=dict(body, username='A!')).status_code == 400
    assert anon.post('/api/vlab/signup', json=dict(body, username='alice')).status_code == 409
    assert anon.post('/api/vlab/signup', json=dict(body, email='not-mail')).status_code == 400
    r = anon.post('/api/vlab/signup', json=dict(body, department_id=dep['id']))
    assert r.status_code == 201, r.get_json()
    sid = r.get_json()['request']['id']
    assert anon.post('/api/vlab/signup', json=body).status_code == 409          # already waiting

    listed = admin.get('/api/vlab/admin/signups?status=pending').get_json()
    assert listed['pending'] == 1 and 'password_hash' not in listed['signups'][0]
    assert alice.get('/api/vlab/admin/signups').status_code == 403

    r = admin.post(f'/api/vlab/admin/signups/{sid}/approve')
    assert r.status_code == 200, r.get_json()
    from pegaprox.utils.auth import load_users
    u = load_users()['newbie']
    assert u['role'] == 'user' and u['portal_only'] is True and u['display_name'] == '새 학생'
    assert catalog.department_of('newbie') == dep['id']
    assert admin.post(f'/api/vlab/admin/signups/{sid}/approve').status_code == 409
    assert catalog.get_signup(sid, with_secret=True)['password_hash'] == ''      # the hash moved to the account

    sid2 = anon.post('/api/vlab/signup', json=dict(body, username='second')).get_json()['request']['id']
    r = admin.post(f'/api/vlab/admin/signups/{sid2}/reject', json={'reason': '학생 확인 불가'})
    assert r.status_code == 200 and r.get_json()['signup']['status'] == 'rejected'
    assert 'second' not in load_users()


# --- USB device library ------------------------------------------------------------------

def test_usb_library_starts_with_jtag_cables_and_checks_ids(env):
    _, _, admin, _, _, viewer = env
    devs = admin.get('/api/vlab/admin/usb-devices').get_json()['devices']
    assert {d['vid'] for d in devs} == {'03fd', '0403', '1443'} and all(d['builtin'] for d in devs)
    assert admin.post('/api/vlab/admin/usb-devices', json={'name': 'x', 'vid': 'zzzz'}).status_code == 400
    assert admin.post('/api/vlab/admin/usb-devices', json={'name': 'x', 'vid': '03fd', 'pid': '0008'}).status_code == 409
    r = admin.post('/api/vlab/admin/usb-devices', json={'name': 'YubiKey', 'vid': '1050', 'pid': '0407', 'category': 'security-key'})
    assert r.status_code == 201, r.get_json()
    key = r.get_json()['device']
    pool = store.create_pool('보안 랩', 'dedicated', CID)
    store.set_pool_settings(pool['id'], {'usb': {'devices': [key['id']]}})
    listed = {d['id']: d for d in admin.get('/api/vlab/admin/usb-devices').get_json()['devices']}
    assert listed[key['id']]['pools'] == 1
    assert admin.delete(f"/api/vlab/admin/usb-devices/{key['id']}").status_code == 409
    store.set_pool_settings(pool['id'], {})
    assert admin.delete(f"/api/vlab/admin/usb-devices/{key['id']}").status_code == 200


# --- external desktops ------------------------------------------------------------------

def test_external_desktop_rdp_goes_direct_without_the_gateway_catalog(env):
    _, _, admin, alice, bob, _ = env
    # the gateway catalog is gone (보안 게이트웨이 replaced Guacamole and the RD gateways)
    assert admin.get('/api/vlab/admin/gateways').status_code == 404
    assert admin.post('/api/vlab/admin/external-desktops', json={'name': 'PC', 'address': '10.0.0.5', 'assigned_user': 'ghost'}).status_code == 400
    ext = admin.post('/api/vlab/admin/external-desktops', json={'name': '연구실 PC 3', 'address': '10.0.0.5', 'assigned_user': 'alice',
                                                                 'gateway_id': 'gw_old'}).get_json()['desktop']
    assert ext['gateway_id'] is None                              # an old client's gateway_id is ignored
    mine = alice.get('/api/vlab/me/external').get_json()['desktops']
    assert [m['name'] for m in mine] == ['연구실 PC 3'] and bob.get('/api/vlab/me/external').get_json()['desktops'] == []
    rdp = alice.get(f"/api/vlab/me/external/{ext['id']}/rdp").get_json()
    assert rdp['filename'].endswith('.rdp') and 'via' not in rdp
    assert 'full address:s:10.0.0.5:3389' in rdp['rdp'] and 'username:s:alice' in rdp['rdp']
    assert 'gateway' not in rdp['rdp']
    assert bob.get(f"/api/vlab/me/external/{ext['id']}/rdp").status_code == 404
    # no browser path without 보안 게이트웨이
    r = alice.get(f"/api/vlab/me/external/{ext['id']}/web")
    assert r.status_code == 409 and r.get_json()['code'] == 'WG_OFF'
    assert alice.get(f"/api/vlab/me/external/{ext['id']}/guac").status_code == 404

# --- golden images -----------------------------------------------------------------------

def test_golden_image_versions_and_deploy(env):
    _, mgr, admin, _, _, viewer = env
    assert admin.post('/api/vlab/admin/golden-images', json={'cluster_id': CID, 'vmid': 900}).status_code == 409   # a template
    assert admin.post('/api/vlab/admin/golden-images', json={'cluster_id': CID, 'vmid': 777}).status_code == 404
    r = admin.post('/api/vlab/admin/golden-images', json={'cluster_id': CID, 'vmid': 500, 'notes': 'Windows 11 실습'})
    assert r.status_code == 201, r.get_json()
    img = r.get_json()['image']
    assert img['name'] == 'gold-win11'
    assert admin.post('/api/vlab/admin/golden-images', json={'cluster_id': CID, 'vmid': 500}).status_code == 409

    listed = admin.get('/api/vlab/admin/golden-images').get_json()['images']
    assert [v['name'] for v in listed[0]['versions']] == ['gold-20261001-090000']     # only gold-* snapshots

    pool = admin.post('/api/vlab/admin/pools', json={'name': '실습 B', 'type': 'reset', 'cluster_id': CID}).get_json()['pool']
    body = {'pool_id': pool['id'], 'count': 2, 'name_prefix': 'lab-b'}
    assert admin.post(f"/api/vlab/admin/golden-images/{img['id']}/deploy", json=body).status_code == 409   # no version yet

    r = admin.post(f"/api/vlab/admin/golden-images/{img['id']}/versions", json={'description': '보안 패치'})
    assert r.status_code == 201, r.get_json()
    ver = r.get_json()['version']
    assert ver.startswith('gold-') and mgr.create_snapshot.call_args[0][:4] == ('pve1', 500, 'qemu', ver)
    assert admin.put(f"/api/vlab/admin/golden-images/{img['id']}/current", json={'version': 'nope'}).status_code == 404
    assert admin.put(f"/api/vlab/admin/golden-images/{img['id']}/current", json={'version': 'gold-20261001-090000'}).status_code == 200

    r = admin.post(f"/api/vlab/admin/golden-images/{img['id']}/deploy", json=body)
    assert r.status_code == 201, r.get_json()
    assert [c['name'] for c in r.get_json()['created']] == ['lab-b-01', 'lab-b-02']
    kw = mgr.clone_vm.call_args.kwargs
    assert kw['full'] is True and kw['snapname'] == 'gold-20261001-090000'
    assert store.get_pool(pool['id'])['settings']['golden_id'] == img['id']
    assert admin.get('/api/vlab/admin/golden-images').get_json()['images'][0]['pools'] == ['실습 B']


# --- board lab ---------------------------------------------------------------------------

def test_board_attaches_to_a_desktop_on_its_node(env):
    _, mgr, admin, _, _, viewer = env
    pool = store.create_pool('보드 실습', 'dedicated', CID)
    here = store.add_desktop(pool, 'pve1', 300, 'lab-win11-01')
    there = store.add_desktop(pool, 'pve2', 301, 'lab-win11-02')
    assert admin.post('/api/vlab/admin/boards', json={'name': 'ZCU102 #1', 'cluster_id': CID, 'node': 'pve1', 'usb': 'cable'}).status_code == 400
    assert viewer.post('/api/vlab/admin/boards', json={'name': 'x', 'cluster_id': CID, 'node': 'pve1', 'usb': '03fd:0008'}).status_code == 403
    b = admin.post('/api/vlab/admin/boards', json={'name': 'ZCU102 #1', 'cluster_id': CID, 'node': 'pve1', 'usb': '03fd:0008',
                                                    'kind': 'ZCU102'}).get_json()['board']
    assert admin.post(f"/api/vlab/admin/boards/{b['id']}/attach", json={'desktop_id': there['id']}).status_code == 409   # other node
    r = admin.post(f"/api/vlab/admin/boards/{b['id']}/attach", json={'desktop_id': here['id']})
    assert r.status_code == 200, r.get_json()
    assert mgr.update_vm_config.call_args[0] == ('pve1', 300, 'qemu', {'usb4': 'host=03fd:0008'})
    assert admin.delete(f"/api/vlab/admin/boards/{b['id']}").status_code == 409
    listed = admin.get('/api/vlab/admin/boards').get_json()['boards'][0]
    assert listed['desktop']['name'] == 'lab-win11-01'
    assert admin.post(f"/api/vlab/admin/boards/{b['id']}/detach").status_code == 200
    assert mgr.update_vm_config.call_args[0] == ('pve1', 300, 'qemu', {'delete': 'usb4'})
    assert catalog.get_board(b['id'])['attached_desktop'] is None


# --- build farm and licence servers ------------------------------------------------------

def test_buildfarm_summary(env):
    _, _, admin, _, _, viewer = env
    farm = store.create_pool('FPGA 빌드 팜', 'buildfarm', CID)
    d1 = store.add_desktop(farm, 'pve1', 300, 'build-01')
    store.add_desktop(farm, 'pve2', 301, 'build-02')
    store.set_assignment(d1['id'], 'alice')
    store.create_pool('일반', 'dedicated', CID)
    assert viewer.get('/api/vlab/admin/buildfarm').status_code == 403
    pools = admin.get('/api/vlab/admin/buildfarm').get_json()['pools']
    assert [p['name'] for p in pools] == ['FPGA 빌드 팜']
    p = pools[0]
    assert (p['total'], p['running'], p['in_use'], p['free']) == (2, 1, 1, 1)
    assert p['cpu_pct'] == 50.0 and p['mem_used'] == 2 * 1024 ** 3


def test_license_server_ports_are_checked(env, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    _, _, admin, _, _, viewer = env
    assert admin.post('/api/vlab/admin/license-servers', json={'name': 'x', 'host': 'lic', 'ports': []}).status_code == 400
    assert admin.post('/api/vlab/admin/license-servers', json={'name': 'x', 'host': 'lic', 'ports': '2100', 'fixed_mac': 'zz'}).status_code == 400
    r = admin.post('/api/vlab/admin/license-servers', json={'name': 'FlexLM', 'host': 'lic.example.com', 'ports': '27000, 2100',
                                                             'cluster_id': CID, 'vmid': 300, 'fixed_mac': '52:54:00:12:34:56'})
    assert r.status_code == 201, r.get_json()
    s = r.get_json()['server']
    assert s['ports'] == [2100, 27000]
    monkeypatch.setattr(nxt, '_tcp_probe', lambda h, p, timeout=2.0: (p == 27000, 3, '' if p == 27000 else 'refused'))
    r = admin.post(f"/api/vlab/admin/license-servers/{s['id']}/check").get_json()
    assert r['ok'] is False and [d['ok'] for d in r['server']['last_detail']] == [False, True]
    assert r['server']['vm_status'] == 'running'
    assert admin.get('/api/vlab/admin/license-servers').get_json()['servers'][0]['last_ok'] == 0


# =========================================================================================
# access and automation
# =========================================================================================

class _Resp:
    def __init__(self, data, status=200):
        self.status_code, self._data, self.text = status, data, ''

    def json(self):
        return {'data': self._data}


def _granted_pool(admin, name, ptype, subjects):
    pool = store.create_pool(name, ptype, CID)
    r = admin.put(f"/api/vlab/admin/pools/{pool['id']}/grants", json={'grants': subjects})
    assert r.status_code == 200, r.get_json()
    return pool


def test_pool_grants_reach_users_by_name_department_and_group(env, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    _, _, admin, alice, bob, _ = env
    dep = admin.post('/api/vlab/admin/departments', json={'name': '공과대학'}).get_json()['department']
    sub = admin.post('/api/vlab/admin/departments', json={'name': '전자공학과', 'parent_id': dep['id']}).get_json()['department']
    admin.put('/api/vlab/admin/users/bob/department', json={'department_id': sub['id']})
    assert admin.put('/api/vlab/admin/pools/nope/grants', json={'grants': []}).status_code == 404
    pool = store.create_pool('연구원 전용', 'dedicated', CID)
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/grants", json={'grants': [{'subject_type': 'user', 'subject_id': 'ghost'}]}).status_code == 400
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/grants", json={'grants': [{'subject_type': 'team', 'subject_id': 'x'}]}).status_code == 400
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/grants", json={'grants': [{'subject_type': 'department', 'subject_id': dep['id']}]})
    assert [p['name'] for p in bob.get('/api/vlab/me/pools').get_json()['pools']] == ['연구원 전용']        # through the parent department
    assert alice.get('/api/vlab/me/pools').get_json()['pools'] == []
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/grants", json={'grants': [{'subject_type': 'department', 'subject_id': dep['id'], 'include_children': False}]})
    assert bob.get('/api/vlab/me/pools').get_json()['pools'] == []
    monkeypatch.setattr(nxt, '_user_groups', lambda u: {'cn=fpga,ou=groups'} if u == 'alice' else set())
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/grants", json={'grants': [{'subject_type': 'group', 'subject_id': 'CN=FPGA,OU=Groups'}]})
    assert [p['action'] for p in alice.get('/api/vlab/me/pools').get_json()['pools']] == ['claim']


def test_claim_gives_a_free_desktop_once(env, monkeypatch):
    import pegaprox.api.vlab as core
    _, _, admin, alice, bob, _ = env
    monkeypatch.setattr(core, '_acl_set', lambda *a: True)
    pool = _granted_pool(admin, '초기화 실습', 'reset', [{'subject_type': 'user', 'subject_id': 'alice'}, {'subject_type': 'user', 'subject_id': 'bob'}])
    store.add_desktop(store.get_pool(pool['id']), 'pve1', 300, 'lab-01')
    r = alice.post(f"/api/vlab/me/pools/{pool['id']}/claim")
    assert r.status_code == 200 and r.get_json()['new'] is True
    assert alice.post(f"/api/vlab/me/pools/{pool['id']}/claim").get_json()['new'] is False
    r = bob.post(f"/api/vlab/me/pools/{pool['id']}/claim")
    assert r.status_code == 409 and r.get_json()['code'] == 'FULL'
    shared = _granted_pool(admin, '공유', 'shared', [{'subject_type': 'user', 'subject_id': 'alice'}])
    assert alice.post(f"/api/vlab/me/pools/{shared['id']}/claim").status_code == 409


def test_shared_pool_routes_to_the_least_busy_desktop_and_connects(env, monkeypatch):
    import pegaprox.api.vlab as core
    api, mgr, admin, alice, bob, _ = env
    monkeypatch.setattr(core, '_acl_set', lambda *a: True)
    pool = _granted_pool(admin, '빌드 서버', 'shared', [{'subject_type': 'user', 'subject_id': 'alice'}, {'subject_type': 'user', 'subject_id': 'bob'}])
    p = store.get_pool(pool['id'])
    d1 = store.add_desktop(p, 'pve1', 300, 'shared-01')
    store.add_desktop(p, 'pve2', 301, 'shared-02')          # stopped: never picked
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/grants", json={'grants': catalog.pool_grants(pool['id']), 'max_sessions': 1}).get_json()['max_sessions'] == 1
    r = alice.post(f"/api/vlab/me/pools/{pool['id']}/route")
    assert r.status_code == 200 and r.get_json()['desktop']['id'] == d1['id']
    # a shared desktop is open to the pool's members in the core connect route
    mgr.get_vnc_ticket.return_value = {'success': True, 'ticket': 't', 'port': '5900'}
    import pegaprox.utils.rbac as rbac
    monkeypatch.setattr(rbac, 'user_can_access_vm', lambda *a, **k: True)
    r = alice.post(f"/api/vlab/desktops/{d1['id']}/connect", json={'protocol': 'vnc'})
    assert r.status_code == 200, r.get_json()
    r = bob.post(f"/api/vlab/me/pools/{pool['id']}/route")                # alice holds the only seat
    assert r.status_code == 409 and r.get_json()['code'] == 'FULL'


def test_rdp_file_and_browser_rdp_for_a_desktop(env, monkeypatch):
    import pegaprox.api.vlab as core
    import pegaprox.utils.rbac as rbac
    _, mgr, admin, alice, _, _ = env
    monkeypatch.setattr(core, '_acl_set', lambda *a: True)
    monkeypatch.setattr(rbac, 'user_can_access_vm', lambda *a, **k: True)
    pool = store.create_pool('윈도우 실습', 'dedicated', CID)
    store.set_pool_settings(pool['id'], {'protocols': ['vnc', 'rdp']})
    d = store.add_desktop(store.get_pool(pool['id']), 'pve1', 300, 'win-01')
    store.set_assignment(d['id'], 'alice')
    mgr._fetch_qemu_ips.return_value = []
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'})
    assert r.status_code == 409 and r.get_json()['code'] == 'NO_IP'
    mgr._fetch_qemu_ips.return_value = ['127.0.0.1', '10.0.0.9', 'fe80::1']
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'})
    rdp = r.get_json()['rdp']
    assert r.status_code == 200 and 'full address:s:10.0.0.9:3389' in rdp
    # the pool policy: clipboard both, the PC's printers on, its drives off (the defaults)
    assert 'redirectclipboard:i:1' in rdp and 'redirectprinters:i:1' in rdp and 'drivestoredirect:s:\r\n' in rdp
    store.set_pool_settings(pool['id'], {'protocols': ['vnc', 'rdp'],
                                         'policy': {'clipboard': 'to_desktop', 'client_drives': True, 'client_printers': False}})
    rdp = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'}).get_json()['rdp']
    assert 'redirectclipboard:i:0' in rdp and 'redirectprinters:i:0' in rdp and 'drivestoredirect:s:*' in rdp
    # browser RDP is 보안 게이트웨이's (its own route): the old Guacamole 'guac' is no protocol any more
    assert alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'guac'}).status_code == 400


def test_rdp_first_windows_is_made_ready_and_linux_needs_an_rdp_server(env, monkeypatch):
    import pegaprox.api.vlab as core
    import pegaprox.api.vlab_next as nxt
    import pegaprox.utils.rbac as rbac
    _, mgr, _, alice, _, _ = env
    monkeypatch.setattr(core, '_acl_set', lambda *a: True)
    monkeypatch.setattr(rbac, 'user_can_access_vm', lambda *a, **k: True)
    pool = store.create_pool('사무실', 'dedicated', CID)
    d = store.add_desktop(store.get_pool(pool['id']), 'pve1', 300, 'office-01')
    store.set_assignment(d['id'], 'alice')
    mgr._fetch_qemu_ips.return_value = ['10.0.0.31']
    ran = []
    # the RDP setup runs only (the pool's device switches go in their own run: rdp_device_policy)
    monkeypatch.setattr(nxt, '_agent_run', lambda m, n, v, cmd, **k: ('fDisableCdm' in cmd[-1] or ran.append(cmd[-1])) and None or (0, 'changed=1', '', ''))
    nxt._rdp_tuned.clear()
    os_kind = {'v': 'windows'}
    monkeypatch.setattr(nxt, '_guest_os', lambda *a: os_kind['v'])
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'})   # RDP is on by default now
    assert r.status_code == 200, r.get_json()
    rdp = r.get_json()['rdp']
    assert 'networkautodetect:i:1' in rdp and 'connection type:i:7' in rdp
    assert len(ran) == 1 and 'fDenyTSConnections' in ran[0] and 'AVC444ModePreferred' in ran[0] and 'SelectTransport' in ran[0] and 'PartOfDomain' in ran[0] and 'S-1-5-11' in ran[0]
    for n in ('DontDisplayLastUserName', 'DontDisplayLockedUserId', 'DontEnumerateConnectedUsers', 'EnumerateLocalUsers',
              'BlockUserFromShowingAccountDetailsOnSignin', 'HideFastUserSwitching'):   # nobody else on the logon screen
        assert n in ran[0]
    alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'})
    assert len(ran) == 1                                          # once, not at every connect
    os_kind['v'] = 'linux'
    monkeypatch.setattr(nxt, 'rdp_listening', lambda ip, port=3389, timeout=1.5: False)
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'})
    assert r.status_code == 409 and r.get_json()['code'] == 'NO_RDP'
    monkeypatch.setattr(nxt, 'rdp_listening', lambda ip, port=3389, timeout=1.5: True)   # xrdp on the desktop
    assert alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'}).status_code == 200
    assert len(ran) == 1


def test_the_gateway_catalog_is_retired_once_at_start(env):
    """An install from before 보안 게이트웨이: its gateways (Guacamole, RD gateways) and every reference go."""
    _, _, admin, _, _, _ = env
    d = catalog.db()
    d.execute("""CREATE TABLE IF NOT EXISTS vlab_gateways (id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL,
                 address TEXT NOT NULL, port INTEGER NOT NULL, notes TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
                 last_check TEXT, last_ok INTEGER, last_detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
                 secret_key TEXT NOT NULL DEFAULT '')""")
    d.execute("INSERT INTO vlab_gateways (id, name, kind, address, port, created_at) VALUES ('gw_builtin_guac', 'g', 'guacamole', 'x', 443, 'now')")
    d.execute("INSERT INTO vlab_gateways (id, name, kind, address, port, created_at) VALUES ('gw_rd', 'rd', 'msrdgw', 'y', 443, 'now')")
    ext = catalog.save_external(None, '측정실 PC', '10.30.5.21', 3389, 'alice', '')
    d.execute("UPDATE vlab_external_desktops SET gateway_id = 'gw_rd' WHERE id = ?", (ext['id'],))
    only_guac = store.create_pool('브라우저 실습', 'dedicated', CID)
    store.set_pool_settings(only_guac['id'], {'protocols': ['guac'], 'guac_gateway_id': 'gw_builtin_guac',
                                              'policy': {'protocols': ['guac'], 'clipboard': 'off'}})
    mixed = store.create_pool('혼합', 'dedicated', CID)
    store.set_pool_settings(mixed['id'], {'protocols': ['vnc', 'rdp', 'guac'], 'rdp_gateway_id': 'gw_rd'})
    plain = store.create_pool('그대로', 'dedicated', CID)
    store.set_pool_settings(plain['id'], {'protocols': ['vnc']})
    assert catalog.retire_gateways() == {'gateways': 2, 'external': 1, 'pools': 2}
    assert catalog.retire_gateways() is None                      # once
    assert not d.query_one("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vlab_gateways'")
    assert catalog.get_external(ext['id'])['gateway_id'] is None
    s = store.get_pool(only_guac['id'])['settings']
    assert s == {'protocols': ['rdp'], 'policy': {'protocols': ['rdp'], 'clipboard': 'off'}}   # browser-only RDP -> rdp
    s = store.get_pool(mixed['id'])['settings']
    assert s == {'protocols': ['vnc', 'rdp']}
    assert store.get_pool(plain['id'])['settings'] == {'protocols': ['vnc']}
    assert admin.get(f"/api/vlab/admin/pools/{only_guac['id']}/policy").get_json()['policy']['protocols'] == ['rdp']


def test_golden_rollout_moves_users_to_the_new_version(env, monkeypatch):
    import pegaprox.api.vlab as core
    _, mgr, admin, _, _, _ = env
    acl = []
    monkeypatch.setattr(core, '_acl_set', lambda c, vmid, u, grant: acl.append((vmid, u, grant)) or True)
    img = admin.post('/api/vlab/admin/golden-images', json={'cluster_id': CID, 'vmid': 500}).get_json()['image']
    admin.put(f"/api/vlab/admin/golden-images/{img['id']}/current", json={'version': 'gold-20261001-090000'})
    pool = admin.post('/api/vlab/admin/pools', json={'name': '실습 C', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    r = admin.post(f"/api/vlab/admin/golden-images/{img['id']}/deploy", json={'pool_id': pool['id'], 'count': 1, 'name_prefix': 'lab-c'})
    assert r.status_code == 201, r.get_json()
    made = r.get_json()['created']
    old = made[0]
    store.set_assignment(old['id'], 'alice')
    listed = admin.get('/api/vlab/admin/golden-images').get_json()['images'][0]
    assert listed['rollout'] and listed['rollout'][0]['outdated'] == 0, listed
    v = admin.post(f"/api/vlab/admin/golden-images/{img['id']}/versions", json={}).get_json()['version']
    assert admin.get('/api/vlab/admin/golden-images').get_json()['images'][0]['rollout'][0]['outdated'] == 1
    mgr.get_next_vmid.return_value = {'success': True, 'vmid': 2000}
    r = admin.post(f"/api/vlab/admin/golden-images/{img['id']}/rollout", json={'pool_id': pool['id']})
    assert r.get_json()['skipped'] == ['lab-c-01'] and r.get_json()['replaced'] == []     # still being made
    store.set_state(old['id'], 'ready')
    r = admin.post(f"/api/vlab/admin/golden-images/{img['id']}/rollout", json={'pool_id': pool['id']})
    assert r.status_code == 200, r.get_json()
    rep = r.get_json()['replaced'][0]
    assert rep['user'] == 'alice' and rep['old_vmid'] == old['vmid'] and rep['old_deleted'] is False
    desks = store.list_desktops(pool['id'])
    assert len(desks) == 1 and desks[0]['assigned_user'] == 'alice' and desks[0]['vmid'] == rep['new_vmid']
    assert (rep['new_vmid'], 'alice', True) in acl and (old['vmid'], 'alice', False) in acl
    assert mgr.clone_vm.call_args.kwargs['snapname'] == v
    assert admin.post(f"/api/vlab/admin/golden-images/{img['id']}/rollout", json={'pool_id': pool['id']}).get_json()['replaced'] == []


def test_board_loan_ends_on_time(env, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    from pegaprox.core import ha
    _, mgr, admin, _, _, _ = env
    pool = store.create_pool('보드 실습', 'dedicated', CID)
    desk = store.add_desktop(pool, 'pve1', 300, 'lab-win11-01')
    b = admin.post('/api/vlab/admin/boards', json={'name': 'ZCU102 #1', 'cluster_id': CID, 'node': 'pve1', 'usb': '03fd:0008'}).get_json()['board']
    assert admin.post(f"/api/vlab/admin/boards/{b['id']}/attach", json={'desktop_id': desk['id'], 'lease_until': '2020-01-01T00:00'}).status_code == 400
    r = admin.post(f"/api/vlab/admin/boards/{b['id']}/attach", json={'desktop_id': desk['id'], 'lease_user': 'alice', 'lease_until': '2099-01-01T09:00'})
    assert r.status_code == 200 and r.get_json()['board']['lease_until'] == '2099-01-01T09:00'
    monkeypatch.setattr(ha, 'confirm_step', lambda *a, **k: True)
    assert nxt.board_tick('2098-12-31T23:59:00') == (0, 0)
    assert nxt.board_tick('2099-01-01T09:00:01') == (1, 0)
    assert mgr.update_vm_config.call_args[0] == ('pve1', 300, 'qemu', {'delete': 'usb4'})
    assert catalog.get_board(b['id'])['attached_desktop'] is None and catalog.get_board(b['id'])['lease_user'] == ''


def test_license_watch_alerts_once_and_on_recovery(env, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    _, _, admin, _, _, _ = env
    s = admin.post('/api/vlab/admin/license-servers', json={'name': 'FlexLM', 'host': 'lic', 'ports': '27000'}).get_json()['server']
    admin.post('/api/vlab/admin/license-servers', json={'name': '안 봄', 'host': 'lic2', 'ports': '2100', 'watch': False})
    sent = []
    monkeypatch.setattr(nxt, '_alert', lambda title, text, data: sent.append(data['kind']))
    up = [False]
    monkeypatch.setattr(nxt, '_tcp_probe', lambda h, p, timeout=2.0: (up[0], 1, '' if up[0] else 'refused'))
    assert nxt.license_tick(force=True) == 1                 # the unwatched one is skipped
    assert sent == ['license_down'] and catalog.get_license_server(s['id'])['alerted_at']
    nxt.license_tick(force=True)
    assert sent == ['license_down']                           # once, not every 5 minutes
    up[0] = True
    nxt.license_tick(force=True)
    assert sent == ['license_down', 'license_up'] and catalog.get_license_server(s['id'])['alerted_at'] is None
    assert nxt.license_tick() == 0                            # not before 5 minutes have passed


def test_build_jobs_run_on_a_free_build_vm(env, monkeypatch):
    _, mgr, admin, alice, bob, _ = env
    farm = _granted_pool(admin, 'FPGA 빌드 팜', 'buildfarm', [{'subject_type': 'user', 'subject_id': 'alice'}])
    store.add_desktop(store.get_pool(farm['id']), 'pve1', 300, 'build-01')
    assert [p['name'] for p in alice.get('/api/vlab/me/build-jobs').get_json()['pools']] == ['FPGA 빌드 팜']
    assert bob.post('/api/vlab/me/build-jobs', json={'pool_id': farm['id'], 'name': 'x', 'command': 'make'}).status_code == 404
    assert alice.post('/api/vlab/me/build-jobs', json={'pool_id': farm['id'], 'name': 'x'}).status_code == 400
    mgr._api_post.return_value = _Resp({'pid': 4242})
    r = alice.post('/api/vlab/me/build-jobs', json={'pool_id': farm['id'], 'name': 'zcu102 비트스트림', 'command': 'make bit', 'workdir': '/proj/zcu102'})
    assert r.status_code == 201, r.get_json()
    job = r.get_json()['job']
    assert job['status'] == 'running' and job['desktop'] == 'build-01' and job['pid'] == 4242
    assert mgr._api_post.call_args.kwargs['data']['command'] == ['/bin/bash', '-lc', 'cd /proj/zcu102 && make bit']
    second = alice.post('/api/vlab/me/build-jobs', json={'pool_id': farm['id'], 'name': '두 번째', 'command': 'make sim'}).get_json()['job']
    assert second['status'] == 'queued'                       # the only build VM is busy
    mgr._api_get.return_value = _Resp({'exited': 1, 'exitcode': 0, 'out-data': 'bitstream written'})
    mgr._api_post.return_value = _Resp({'pid': 4243})
    jobs = {j['id']: j for j in alice.get('/api/vlab/me/build-jobs').get_json()['jobs']}
    assert jobs[job['id']]['status'] == 'done' and jobs[job['id']]['output'] == 'bitstream written'
    assert jobs[second['id']]['status'] == 'running'          # the freed VM took the next one
    mgr._api_get.return_value = _Resp({'exited': 0})           # the second build is still going
    third = admin.post('/api/vlab/admin/build-jobs', json={'pool_id': farm['id'], 'name': '셋', 'command': 'make', 'username': 'alice'}).get_json()['job']
    assert third['status'] == 'queued'
    assert admin.post(f"/api/vlab/admin/build-jobs/{second['id']}/cancel").status_code == 409
    assert alice.post(f"/api/vlab/me/build-jobs/{third['id']}/cancel").get_json()['job']['status'] == 'cancelled'
    counts = admin.get('/api/vlab/admin/build-jobs').get_json()['counts']
    assert counts['cancelled'] == 1 and counts['done'] == 1


def test_card_usage_report(env):
    _, _, admin, _, _, viewer = env
    a = store.add_lease('card', 'alveo-u250', 'Alveo U250 #1', 'alice', CID, 300, '2099-01-01T00:00:00')
    store.add_lease('card', 'alveo-u250', 'Alveo U250 #1', 'bob', CID, 301, '2099-01-01T00:00:00')
    store.close_lease(a['id'])
    assert viewer.get('/api/vlab/admin/reports/cards').status_code == 403
    rep = admin.get('/api/vlab/admin/reports/cards?days=7').get_json()
    row = rep['cards'][0]
    assert rep['days'] == 7 and row['card'] == 'Alveo U250 #1' and row['loans'] == 2 and row['users'] == ['alice', 'bob'] and row['active'] == 1
    csv = admin.get('/api/vlab/admin/reports/cards?days=7&format=csv')
    assert csv.status_code == 200 and 'Alveo U250 #1' in csv.get_data(as_text=True)


# --- VM build: ISO library and new VMs ----------------------------------------------------

def test_iso_library_lists_and_hands_uploads_downloads_deletes_to_the_core(env, monkeypatch):
    import io

    import pegaprox.api.storage as core_storage
    import pegaprox.api.vms as core_vms
    from flask import jsonify
    _, mgr, admin, alice, _, _ = env
    mgr.get_iso_list.return_value = [
        {'volid': 'local:iso/old.iso', 'size': 10, 'ctime': 1},
        {'volid': 'local:iso/Win11_24H2.iso', 'size': 6 * 1024 ** 3, 'ctime': 9, 'storage': 'local'}]
    r = admin.get(f'/api/vlab/admin/clusters/{CID}/nodes/pve1/isos?storage=local')
    assert r.status_code == 200, r.get_json()
    assert [i['name'] for i in r.get_json()['isos']] == ['Win11_24H2.iso', 'old.iso']
    assert mgr.get_iso_list.call_args[0] == ('pve1', 'local')
    assert admin.get(f'/api/vlab/admin/clusters/{CID}/nodes/bad_node/isos').status_code == 400
    assert alice.get(f'/api/vlab/admin/clusters/{CID}/nodes/pve1/isos').status_code == 403

    seen = {}

    def fake_upload(c, s):
        seen['up'] = (c, s)
        return jsonify({'success': True, 'upid': 'UPID:x'})
    monkeypatch.setattr(core_vms, 'upload_to_datastore', fake_upload)
    base = f'/api/vlab/admin/clusters/{CID}/nodes/pve1/storage/local'

    def up(name, **form):
        return admin.post(f'{base}/upload', data={'file': (io.BytesIO(b'iso'), name), **form},
                          content_type='multipart/form-data')
    assert up('x.iso').status_code == 400                         # the node goes in the form too
    assert up('x.qcow2', node='pve1').status_code == 400          # ISOs only
    assert up('x.iso', node='pve1', content='vztmpl').status_code == 400
    assert up('a b.iso', node='pve1').status_code == 400
    r = up('virtio-win-0.1.262.iso', node='pve1')
    assert r.status_code == 200 and seen['up'] == (CID, 'local')

    monkeypatch.setattr(core_storage, 'download_from_url',
                        lambda c, n, s: jsonify({'success': True, 'upid': f'UPID:{n}:1:2:3:download:local:root@pam:'}))

    def dl(**b):
        return admin.post(f'{base}/download-url', json=b)
    assert dl(url='ftp://x/y.iso', filename='y.iso').status_code == 400
    assert dl(url='https://x/y.iso', filename='y.img').status_code == 400
    assert dl(url='https://x/y.iso', filename='y.iso', checksum='crc:abc').status_code == 400
    assert dl(url='https://x/y.iso', filename='y.iso', extra=1).status_code == 400
    r = dl(url='https://mirror.example.com/ubuntu.iso', filename='ubuntu.iso', content='iso', checksum='sha256:' + 'a' * 64)
    assert r.status_code == 200 and r.get_json()['upid'].startswith('UPID:pve1')

    mgr.get_task_status.return_value = {'status': 'running'}
    mgr.get_task_log.return_value = 'downloading\n42.5% of 5.8 GiB\n'
    t = admin.get(f'/api/vlab/admin/clusters/{CID}/nodes/pve1/tasks/UPID:pve1:1:2:3:download:local:root@pam:').get_json()
    assert t['running'] and t['percent'] == 42.5 and t['type'] == 'download'
    assert admin.get(f'/api/vlab/admin/clusters/{CID}/nodes/pve1/tasks/UPID:pve1:1:2:3:vzdump:100:root@pam:').status_code == 404

    monkeypatch.setattr(core_vms, 'delete_datastore_content', lambda c, s, v: jsonify({'success': True, 'volid': v}))
    assert admin.delete(f'{base}/isos/local:images/vm-1.qcow2?node=pve1').status_code == 400
    assert admin.delete(f'{base}/isos/other:iso/x.iso?node=pve1').status_code == 400
    r = admin.delete(f'{base}/isos/local:iso/old.iso?node=pve1')
    assert r.status_code == 200 and r.get_json()['volid'] == 'local:iso/old.iso'


def test_create_vm_checks_the_wizard_fields_then_the_core_creates(env):
    _, mgr, admin, alice, _, _ = env
    mgr.get_network_list.return_value = [{'iface': 'vmbr1', 'type': 'bridge', 'bridge_vlan_aware': 1},
                                         {'iface': 'vmbr0', 'type': 'bridge'}]
    nets = admin.get(f'/api/vlab/admin/clusters/{CID}/nodes/pve1/networks').get_json()['networks']
    assert [n['iface'] for n in nets] == ['vmbr0', 'vmbr1'] and nets[1]['vlan_aware']
    assert admin.get(f'/api/vlab/admin/clusters/{CID}/nextid').get_json() == {'vmid': 1000}

    mgr.create_vm.return_value = {'success': True, 'vmid': 1000, 'task': 'UPID:pve1:1:2:3:qmcreate:1000:root@pam:'}
    body = {'vmid': 1000, 'name': 'win11-gold', 'ostype': 'win11', 'iso': 'local:iso/Win11_24H2.iso',
            'virtio_iso': 'local:iso/virtio-win.iso', 'cores': 4, 'memory': 8192, 'cpu': 'host',
            'storage': 'local-lvm', 'disk_size': 64, 'disk_type': 'scsi', 'scsihw': 'virtio-scsi-single',
            'net_bridge': 'vmbr0', 'net_model': 'virtio', 'vga': 'qxl', 'agent': True}
    url = f'/api/vlab/admin/clusters/{CID}/nodes/pve1/vms'
    assert admin.post(url, json=body).status_code == 400                        # Windows 11 without UEFI/TPM
    win11 = {**body, 'bios': 'ovmf', 'machine': 'q35', 'efi_storage': 'local-lvm', 'efi_pre_enroll': True,
             'tpm_storage': 'local-lvm', 'tpm_version': 'v2.0'}
    assert admin.post(url, json={**win11, 'storage': 'local-lvm,cache=unsafe'}).status_code == 400
    assert admin.post(url, json={**win11, 'net_bridge': 'vmbr0,tag=5'}).status_code == 400
    assert admin.post(url, json={**win11, 'iso': 'local:images/x.qcow2'}).status_code == 400
    assert admin.post(url, json={**win11, 'hookscript': 'local:snippets/x'}).status_code == 400
    assert admin.post(url, json={**win11, 'vmid': 300}).status_code == 409       # taken
    assert alice.post(url, json=win11).status_code == 403
    r = admin.post(url, json=win11)
    assert r.status_code == 200, r.get_json()
    assert r.get_json()['vmid'] == 1000
    sent = mgr.create_vm.call_args[0]
    assert sent[0] == 'pve1' and sent[1]['tpm_storage'] == 'local-lvm' and sent[1]['vga'] == 'qxl'


def test_build_console_starts_the_vm_then_opens_and_template_needs_it_off(env, monkeypatch):
    import pegaprox.utils.rbac as rbac
    _, mgr, admin, _, _, _ = env
    monkeypatch.setattr(rbac, 'user_can_access_vm', lambda *a, **k: True)
    mgr.vm_action.return_value = {'success': True}
    r = admin.post(f'/api/vlab/admin/clusters/{CID}/vms/500/console')
    assert r.status_code == 409 and r.get_json()['code'] == 'STARTING'
    assert mgr.vm_action.call_args[0] == ('pve1', 500, 'qemu', 'start')
    mgr.get_vnc_ticket.return_value = {'success': True, 'ticket': 't', 'port': '5900'}
    r = admin.post(f'/api/vlab/admin/clusters/{CID}/vms/300/console')
    assert r.status_code == 200 and '/qemu/300/vncwebsocket?token=' in r.get_json()['ws_path']
    assert admin.post(f'/api/vlab/admin/clusters/{CID}/vms/900/console').status_code == 409   # a template

    assert admin.post(f'/api/vlab/admin/clusters/{CID}/vms/300/template').status_code == 409  # running
    mgr.host, mgr.api_port = 'pve', 8006
    mgr._api_post.return_value.status_code = 200
    mgr._api_post.return_value.json.return_value = {'data': 'UPID:pve1:1:2:3:qmtemplate:500:root@pam:'}
    r = admin.post(f'/api/vlab/admin/clusters/{CID}/vms/500/template')
    assert r.status_code == 200, r.get_json()
    assert mgr._api_post.call_args[0][0].endswith('/nodes/pve1/qemu/500/template')


# --- pool edit, ending sessions, notices ------------------------------------------------

def test_pool_edit_changes_name_state_and_settings_but_not_cluster_or_type(env, monkeypatch):
    import pegaprox.api.vlab as core
    _, _, admin, alice, _, _ = env
    monkeypatch.setattr(core, '_acl_set', lambda *a: True)
    pool = _granted_pool(admin, '실습실', 'reset', [{'subject_type': 'user', 'subject_id': 'alice'}])
    url = f"/api/vlab/admin/pools/{pool['id']}"
    r = admin.put(url, json={'name': '  실습실 B ', 'description': '2층', 'enabled': False})
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body['pool']['name'] == '실습실 B' and body['pool']['description'] == '2층' and body['pool']['enabled'] is False
    assert sorted(body['changed']) == ['description', 'enabled', 'name']
    assert admin.put(url, json={'name': '실습실 B'}).get_json()['changed'] == []
    r = admin.put(url, json={'type': 'shared'})
    assert r.status_code == 400 and r.get_json()['code'] == 'IMMUTABLE'
    assert admin.put(url, json={'cluster_id': 'other'}).get_json()['code'] == 'IMMUTABLE'
    assert admin.put(url, json={'type': 'reset', 'cluster_id': CID}).status_code == 200   # the same values pass
    assert admin.put(url, json={'name': ''}).status_code == 400
    assert admin.put(url, json={'enabled': 'no'}).status_code == 400
    assert admin.put(url, json={'settings': {'max_sessions': 3}}).status_code == 400       # shared pools only
    assert admin.put(url, json={'settings': {'policy': {}}}).status_code == 400            # has its own route
    assert alice.put(url, json={'name': 'x'}).status_code == 403
    # a switched-off pool hands out and connects nothing
    store.add_desktop(store.get_pool(pool['id']), 'pve1', 300, 'lab-01')
    r = alice.post(f"/api/vlab/me/pools/{pool['id']}/claim")
    assert r.status_code == 409 and r.get_json()['code'] == 'POOL_DISABLED'
    assert alice.get('/api/vlab/me/pools').get_json()['pools'] == []
    assert admin.put(url, json={'enabled': True}).get_json()['pool']['enabled'] is True
    d = alice.post(f"/api/vlab/me/pools/{pool['id']}/claim").get_json()['desktop']
    admin.put(url, json={'enabled': False})
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'vnc'})
    assert r.status_code == 409 and r.get_json()['code'] == 'POOL_DISABLED'


def test_pool_edit_sets_shared_seats_and_no_gateways(env):
    _, _, admin, _, _, _ = env
    shared = store.create_pool('공유', 'shared', CID)
    url = f"/api/vlab/admin/pools/{shared['id']}"
    r = admin.put(url, json={'settings': {'max_sessions': 4}})
    assert r.status_code == 200, r.get_json()
    assert store.get_pool(shared['id'])['settings']['shared']['max_sessions'] == 4
    assert admin.put(url, json={'settings': {'max_sessions': 0}}).status_code == 400
    for gone in ('rdp_gateway_id', 'guac_gateway_id'):           # the RD / Guacamole gateway settings are gone
        assert admin.put(url, json={'settings': {gone: 'gw_x'}}).status_code == 400
    assert store.get_pool(shared['id'])['settings']['shared']['max_sessions'] == 4


def test_admin_ends_a_vnc_session_and_its_console_token(env, monkeypatch):
    import pegaprox.api.vlab as core
    import pegaprox.utils.rbac as rbac
    from pegaprox.utils import realtime
    _, mgr, admin, alice, bob, _ = env
    monkeypatch.setattr(core, '_acl_set', lambda *a: True)
    monkeypatch.setattr(rbac, 'user_can_access_vm', lambda *a, **k: True)
    pool = _granted_pool(admin, '빌드', 'shared', [{'subject_type': 'user', 'subject_id': 'alice'}])
    d = store.add_desktop(store.get_pool(pool['id']), 'pve1', 300, 'shared-01')
    mgr.get_vnc_ticket.return_value = {'success': True, 'ticket': 't', 'port': '5900'}
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'vnc'})
    assert r.status_code == 200, r.get_json()
    sid = r.get_json()['session_id']
    tag = core.desktop_ws_tag(d)
    assert any(t.get('tag') == tag for t in realtime.ws_tokens.values())
    # a console socket opened with such a token, held on the main port, and another of hers
    realtime._held_ws['k-test'] = ('alice', object())
    realtime._held_ws_tag['k-test'] = tag
    realtime._held_ws['k-other'] = ('alice', object())
    try:
        assert bob.post(f'/api/vlab/admin/sessions/{sid}/end').status_code == 403
        r = admin.post(f'/api/vlab/admin/sessions/{sid}/end')
        assert r.status_code == 200, r.get_json()
        out = r.get_json()['session']
        assert out['protocol'] == 'vnc' and out['record_only'] is False and out['hung_up'] == 2
        assert not any(t.get('tag') == tag for t in realtime.ws_tokens.values())
        assert 'k-test' not in realtime._held_ws and 'k-other' in realtime._held_ws
    finally:
        realtime._held_ws.pop('k-other', None)
        realtime._held_ws.pop('k-test', None)
        realtime._held_ws_tag.pop('k-test', None)
    row = store.get_session(sid)
    assert row['ended_at'] and row['result'] == 'terminated'
    assert admin.post(f'/api/vlab/admin/sessions/{sid}/end').get_json()['code'] == 'ENDED'
    assert admin.post('/api/vlab/admin/sessions/nope/end').status_code == 404


def test_admin_ends_every_session_of_a_user_spice_only_on_record(env):
    _, _, admin, _, _, _ = env
    pool = store.create_pool('개발', 'dedicated', CID)
    d1 = store.add_desktop(pool, 'pve1', 300, 'dev-01')
    d2 = store.add_desktop(pool, 'pve2', 301, 'dev-02')
    s1 = store.start_session('bob', d1, 'spice', '10.0.0.5')
    s2 = store.start_session('bob', d2, 'rdp', '10.0.0.5')
    other = store.start_session('alice', d1, 'vnc', '10.0.0.6')
    r = admin.post('/api/vlab/admin/users/bob/sessions/end')
    assert r.status_code == 200
    ended = {e['id']: e for e in r.get_json()['ended']}
    assert set(ended) == {s1, s2} and all(e['record_only'] for e in ended.values())
    assert store.get_session(other)['ended_at'] is None
    assert admin.post('/api/vlab/admin/users/bob/sessions/end').get_json()['ended'] == []


def test_notices_have_a_start_an_audience_and_a_kind(env):
    from datetime import datetime, timedelta, timezone
    _, _, admin, alice, _, _ = env

    def iso(h):
        return (datetime.now(timezone.utc) + timedelta(hours=h)).strftime('%Y-%m-%dT%H:%M:%SZ')

    def seen(c):
        return {b['id'] for b in c.get('/api/vlab/banners').get_json()['banners']}

    assert alice.get('/api/vlab/admin/banners').status_code == 403
    r = admin.post('/api/vlab/admin/banners', json={'text': '점검 예정', 'severity': 'warning', 'audience': 'all',
                                                    'starts_at': iso(2), 'expires_at': iso(5)})
    assert r.status_code == 201, r.get_json()
    later = r.get_json()['banner']
    assert later['state'] == 'scheduled' and later['audience'] == 'all' and later['starts_at']
    everyone = admin.post('/api/vlab/admin/banners', json={'text': '모두에게', 'audience': 'all'}).get_json()['banner']
    admins = admin.post('/api/vlab/admin/banners', json={'text': '관리자만', 'audience': 'admins'}).get_json()['banner']
    assert admins['audience'] == 'admins' and everyone['state'] == 'running'
    assert seen(alice) == {everyone['id']}
    assert seen(admin) == {everyone['id'], admins['id']}
    # a start after the end is refused; the start can go
    assert admin.put(f"/api/vlab/admin/banners/{later['id']}", json={'starts_at': iso(6)}).status_code == 400
    r = admin.put(f"/api/vlab/admin/banners/{later['id']}", json={'starts_at': None, 'text': '점검 중'})
    assert r.status_code == 200, r.get_json()
    assert r.get_json()['banner']['rev'] == 2 and r.get_json()['banner']['state'] == 'running'
    assert later['id'] in seen(alice)
    r = admin.put(f"/api/vlab/admin/banners/{everyone['id']}", json={'audience': 'admins'})
    assert r.get_json()['banner']['audience'] == 'admins' and everyone['id'] not in seen(alice)
    assert admin.post('/api/vlab/admin/banners', json={'text': 'x', 'audience': 'tenants'}).status_code == 400
    assert admin.post('/api/vlab/admin/banners', json={'text': ''}).status_code == 400
    assert admin.delete(f"/api/vlab/admin/banners/{later['id']}").status_code == 200
    listed = admin.get('/api/vlab/admin/banners').get_json()['banners']
    assert later['id'] not in {b['id'] for b in listed} and len(listed) == 2
    assert admin.delete(f"/api/vlab/admin/banners/{later['id']}").status_code == 404


# --- 가상머신 > 데스크톱(VM) 관리 ----------------------------------------------------------

RAW = {'name': 'lab-win11-01', 'cores': 4, 'sockets': 1, 'memory': 8192, 'ostype': 'win11',
       'scsi0': 'ceph-vm:vm-300-disk-0,iothread=1,size=64G', 'ide2': 'none,media=cdrom',
       'net0': 'virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1,tag=20'}


def _vm_env(env, raw=None):
    api, mgr, admin, alice, bob, viewer = env
    mgr.get_vm_config.return_value = {'success': True, 'config': {'raw': dict(raw or RAW)}}
    mgr.get_network_list.return_value = [{'iface': 'vmbr0'}, {'iface': 'vmbr1'}]
    mgr.get_storage_list.return_value = [{'storage': 'ceph-vm', 'content': 'images,rootdir', 'active': 1, 'shared': 1, 'avail': 10},
                                         {'storage': 'local', 'content': 'iso,vztmpl', 'active': 1}]
    mgr.get_node_status.return_value = {'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}, 'pve3': {'offline': True}}
    for m in ('resize_vm_disk', 'add_disk', 'update_network', 'delete_snapshot', 'rollback_snapshot', 'delete_vm'):
        getattr(mgr, m).return_value = {'success': True}
    mgr.migrate_vm_manual.return_value = {'success': True, 'data': 'UPID:pve1:0001:0002:0003:qmigrate:300:root@pam:'}
    pool = store.create_pool('실습 VM', 'dedicated', CID)
    desk = store.add_desktop(pool, 'pve1', 300, 'lab-win11-01')
    return api, mgr, admin, alice, viewer, desk


def test_desktop_vm_settings_and_changes(env):
    _, mgr, admin, alice, viewer, desk = _vm_env(env)
    base = f"/api/vlab/admin/desktops/{desk['id']}"
    assert alice.get(f'{base}/vm').status_code == 403
    r = admin.get(f'{base}/vm')
    assert r.status_code == 200, r.get_json()
    vm = r.get_json()['vm']
    assert (vm['cores'], vm['memory_mb'], vm['node'], vm['status']) == (4, 8192, 'pve1', 'running')
    assert vm['disks'] == [{'key': 'scsi0', 'storage': 'ceph-vm', 'volume': 'ceph-vm:vm-300-disk-0', 'size_gb': 64.0}]
    assert vm['networks'] == [{'key': 'net0', 'model': 'virtio', 'mac': 'BC:24:11:00:00:01', 'bridge': 'vmbr0', 'tag': 20, 'firewall': True}]
    assert vm['bridges'] == ['vmbr0', 'vmbr1'] and [s['storage'] for s in vm['storages']] == ['ceph-vm']
    assert [(t['node'], t['online']) for t in vm['targets']] == [('pve2', True), ('pve3', False)]
    assert vm['passthrough'] == []

    assert viewer.put(f'{base}/vm/hardware', json={'cores': 8}).status_code == 403
    assert admin.put(f'{base}/vm/hardware', json={'cores': 0}).status_code == 400
    assert admin.put(f'{base}/vm/hardware', json={}).status_code == 400
    r = admin.put(f'{base}/vm/hardware', json={'cores': 8, 'memory_mb': 16384})
    assert r.status_code == 200 and r.get_json()['needs_restart'] is True        # 300 is running
    assert mgr.update_vm_config.call_args[0][3] == {'cores': 8, 'memory': 16384}

    assert admin.post(f'{base}/vm/disks/efi0/resize', json={'grow_gb': 10}).status_code == 400
    assert admin.post(f'{base}/vm/disks/scsi0/resize', json={'grow_gb': 10}).status_code == 200
    assert mgr.resize_vm_disk.call_args[0][3:] == ('scsi0', '+10G')
    assert admin.post(f'{base}/vm/disks', json={'storage': 'ceph-vm,size=1', 'size_gb': 10}).status_code == 400
    r = admin.post(f'{base}/vm/disks', json={'storage': 'ceph-vm', 'size_gb': 20})
    assert r.status_code == 200 and r.get_json()['disk'] == 'scsi1'

    assert admin.put(f'{base}/vm/networks/net0', json={'bridge': 'vmbr1', 'tag': 5000}).status_code == 400
    r = admin.put(f'{base}/vm/networks/net0', json={'bridge': 'vmbr1', 'tag': None})
    assert r.status_code == 200 and r.get_json()['needs_restart'] is True
    cfg = mgr.update_network.call_args[0][4]
    assert cfg == {'bridge': 'vmbr1', 'tag': None, 'firewall': True, 'macaddr': 'BC:24:11:00:00:01', 'model': 'virtio'}
    assert admin.put(f'{base}/vm/networks/net7', json={'bridge': 'vmbr1'}).status_code == 404


def test_desktop_snapshots(env):
    _, mgr, admin, _, viewer, desk = _vm_env(env)
    store.set_base_snap(desk['id'], 'vlab-base')
    base = f"/api/vlab/admin/desktops/{desk['id']}/snapshots"
    got = admin.get(base).get_json()
    assert [s['name'] for s in got['snapshots']] == ['gold-20261001-090000', 'vlab-base']
    assert [s['base'] for s in got['snapshots']] == [False, True] and got['running'] is True
    assert viewer.post(base, json={'name': 'before-update'}).status_code == 403
    assert admin.post(base, json={'name': '../x'}).status_code == 400
    assert admin.post(base, json={'name': 'vlab-base'}).status_code == 400
    r = admin.post(base, json={'name': 'before-update', 'description': '패치 전', 'vmstate': True})
    assert r.status_code == 201, r.get_json()
    assert mgr.create_snapshot.call_args[0][3:] == ('before-update', '패치 전', True)
    assert admin.post(f'{base}/before-update/rollback').status_code == 200
    assert mgr.rollback_snapshot.call_args[0][3] == 'before-update'
    assert admin.delete(f'{base}/vlab-base').status_code == 200
    assert store.get_desktop(desk['id'])['base_snap'] == ''


def test_desktop_migrate_refuses_passthrough_and_follows_the_task(env):
    _, mgr, admin, _, _, desk = _vm_env(env, dict(RAW, hostpci0='mapping=a16,mdev=nvidia-660', usb1='spice'))
    base = f"/api/vlab/admin/desktops/{desk['id']}"
    r = admin.post(f'{base}/migrate', json={'target': 'pve2'})
    assert r.status_code == 409 and r.get_json()['code'] == 'PASSTHROUGH'
    assert [d['key'] for d in r.get_json()['devices']] == ['hostpci0']             # SPICE USB redirection is fine
    assert not mgr.migrate_vm_manual.called

    mgr.get_vm_config.return_value = {'success': True, 'config': {'raw': dict(RAW)}}
    assert admin.post(f'{base}/migrate', json={'target': 'pve1'}).status_code == 400
    r = admin.post(f'{base}/migrate', json={'target': 'pve2'})
    assert r.status_code == 200, r.get_json()
    a = r.get_json()
    assert (a['from'], a['to'], a['online']) == ('pve1', 'pve2', True)
    assert store.get_desktop(desk['id'])['node'] == 'pve2'
    mgr.get_task_status.return_value = {'status': 'stopped', 'exitstatus': 'OK'}
    assert admin.get(f"{base}/task?upid={a['task']}").get_json() == {'status': 'stopped', 'exitstatus': 'OK'}
    assert mgr.get_task_status.call_args[0][0] == 'pve1'
    assert admin.get(f'{base}/task?upid=UPID:pve1:0:0:0:qmigrate:999:root@pam:').status_code == 400


def test_desktop_template_and_delete_leave_the_pool(env, monkeypatch):
    import pegaprox.api.vlab as core
    from pegaprox.core.db import get_db
    _, mgr, admin, _, _, desk = _vm_env(env)
    acl = []
    monkeypatch.setattr(core, '_acl_set', lambda c, vmid, u, grant: acl.append((vmid, u, grant)) or True)
    store.set_assignment(desk['id'], 'alice')
    base = f"/api/vlab/admin/desktops/{desk['id']}"
    assert admin.post(f'{base}/template').status_code == 409                          # running

    other = store.add_desktop(store.get_pool(desk['pool_id']), 'pve2', 301, 'lab-win11-02')
    store.set_assignment(other['id'], 'alice')
    mgr._api_post.return_value = type('R', (), {'status_code': 200, 'text': ''})()
    r = admin.post(f"/api/vlab/admin/desktops/{other['id']}/template")
    assert r.status_code == 200, r.get_json()
    assert mgr._api_post.call_args[0][0].endswith('/nodes/pve2/qemu/301/template')
    assert store.get_desktop(other['id']) is None and acl == [(301, 'alice', False)]

    assert admin.delete(f'{base}/vm', json={'confirm_name': 'lab-win11'}).status_code == 400
    store.start_session('alice', desk, 'vnc', '127.0.0.1')
    r = admin.delete(f'{base}/vm', json={'confirm_name': 'lab-win11-01'})
    assert r.status_code == 409 and r.get_json()['code'] == 'IN_USE'
    get_db().save_vm_acl(CID, '300', {'users': ['alice'], 'permissions': [], 'inherit_role': True})
    r = admin.delete(f'{base}/vm', json={'confirm_name': 'lab-win11-01', 'force': True})
    assert r.status_code == 200, r.get_json()
    assert mgr.delete_vm.call_args[0][:3] == ('pve1', 300, 'qemu') and mgr.delete_vm.call_args[1] == {'purge': True}
    assert store.get_desktop(desk['id']) is None
    assert '300' not in (get_db().get_all_vm_acls().get(CID) or {})


def test_admin_console_is_audited(env, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    _, mgr, admin, alice, _, desk = _vm_env(env)
    seen = []
    monkeypatch.setattr(nxt, 'log_audit', lambda user, action, details, *a, **k: seen.append((user, action, details)))
    mgr.get_vnc_ticket.return_value = {'success': True, 'ticket': 'PVEVNC:t', 'port': '5901'}
    store.set_assignment(desk['id'], 'alice')
    base = f"/api/vlab/admin/desktops/{desk['id']}/console"
    assert alice.post(base).status_code == 403
    r = admin.post(base)
    assert r.status_code == 200, r.get_json()
    a = r.get_json()
    assert a['ws_path'].startswith(f'/api/clusters/{CID}/vms/pve1/qemu/300/vncwebsocket?token=') and a['password'] == 'PVEVNC:t'
    assert not store.open_session_desktops()                                          # support is no session
    assert [(u, act) for u, act, _ in seen] == [('root', 'vlab.desktop.admin_console')] and 'user alice' in seen[0][2]


# --- 운영 기본: 작업 진행 · 노드 유지보수 · Proxmox HA -------------------------------------------

def _upid(node, kind, vmid, n=1):
    return f'UPID:{node}:000{n}:0002:0003:{kind}:{vmid}:root@pam:'


def test_tasks_admins_see_all_users_their_own(env, monkeypatch):
    import pegaprox.api.helpers as helpers
    _, mgr, admin, alice, bob, _ = env
    pool = store.create_pool('실습', 'dedicated', CID)
    mine = store.add_desktop(pool, 'pve1', 300, 'lab-win11-01')
    store.set_assignment(mine['id'], 'alice')
    mgr.get_tasks.return_value = [
        {'upid': _upid('pve1', 'qmigrate', 300), 'node': 'pve1', 'type': 'qmigrate', 'id': '300', 'starttime': 100},
        {'upid': _upid('pve2', 'vzdump', 301, 2), 'node': 'pve2', 'type': 'vzdump', 'id': '301', 'starttime': 90,
         'endtime': 95, 'status': 'job errors'},
        {'upid': _upid('pve1', 'qmclone', 500, 3), 'node': 'pve1', 'type': 'qmclone', 'id': '500', 'starttime': 80,
         'endtime': 85, 'status': 'OK', 'pegaprox_user': 'bob'},
        {'upid': 'not-a-task'}]
    mgr.get_task_log.return_value = 'migration started\n  37% done\n'
    r = admin.get('/api/vlab/tasks')
    assert r.status_code == 200, r.get_json()
    got = r.get_json()
    assert got['scope'] == 'all' and got['running'] == 1
    assert [t['type'] for t in got['tasks']] == ['qmigrate', 'vzdump', 'qmclone']
    first = got['tasks'][0]
    assert first['running'] and first['percent'] == 37.0 and first['desktop']['name'] == 'lab-win11-01'
    assert got['tasks'][1]['ok'] is False and got['tasks'][1]['status'] == 'job errors'
    assert got['tasks'][2]['ok'] is True and got['tasks'][2]['user'] == 'bob'

    a = alice.get('/api/vlab/tasks').get_json()
    assert a['scope'] == 'mine' and [t['vmid'] for t in a['tasks']] == [300]
    assert [t['vmid'] for t in bob.get('/api/vlab/tasks').get_json()['tasks']] == [500]

    mgr.get_task_status.return_value = {'status': 'stopped', 'exitstatus': 'job errors'}
    mgr.get_task_log.return_value = 'INFO: starting\nERROR: backup of 301 failed\n'
    up = _upid('pve2', 'vzdump', 301, 2)
    log = admin.get(f'/api/vlab/tasks/log?cluster={CID}&upid={up}').get_json()
    assert log['ok'] is False and log['lines'][-1] == 'ERROR: backup of 301 failed' and log['node'] == 'pve2'
    assert alice.get(f'/api/vlab/tasks/log?cluster={CID}&upid={up}').status_code == 404
    assert alice.get(f"/api/vlab/tasks/log?cluster={CID}&upid={_upid('pve1', 'qmigrate', 300)}").status_code == 200
    monkeypatch.setattr(helpers, 'get_task_user', lambda u: 'bob')
    assert bob.get(f"/api/vlab/tasks/log?cluster={CID}&upid={_upid('pve1', 'qmclone', 500, 3)}").status_code == 200
    assert admin.get(f'/api/vlab/tasks/log?cluster={CID}&upid=UPID:../x').status_code == 400
    assert admin.get(f'/api/vlab/tasks/log?cluster=nope&upid={up}').status_code == 404


def test_node_maintenance_preview_set_and_power(env, monkeypatch):
    import pegaprox.api.vms as core_vms
    from flask import jsonify, request
    _, mgr, admin, alice, _, viewer = env
    pool = store.create_pool('실습', 'dedicated', CID)
    d1 = store.add_desktop(pool, 'pve1', 300, 'lab-win11-01')
    store.add_desktop(pool, 'pve2', 301, 'lab-win11-02')
    store.set_assignment(d1['id'], 'alice')
    store.start_session('alice', d1, 'vnc', '127.0.0.1')
    monkeypatch.setattr(core_vms, 'maintenance_capacity_preview_api',
                        lambda c, n: jsonify({'ok': False, 'over_threshold': ['pve2'], 'guest_count': 1}))
    monkeypatch.setattr(core_vms, 'maintenance_evacuation_plan',
                        lambda c, n: jsonify({'supported': True, 'templates': [{'vmid': 900}], 'online_nodes': 2,
                                              'negative_rules': [{'rule': 'ad-pair', 'resources': ['vm:1', 'vm:2'], 'blocks': True}]}))
    base = f'/api/vlab/admin/clusters/{CID}/nodes/pve1'
    assert alice.get(f'{base}/maintenance-preview').status_code == 403
    r = admin.get(f'{base}/maintenance-preview')
    assert r.status_code == 200, r.get_json()
    p = r.get_json()
    assert [(d['name'], d['in_use'], d['assigned_user']) for d in p['desktops']] == [('lab-win11-01', True, 'alice')]
    assert [g['vmid'] for g in p['guests']] == [500]                      # the template and the desktop are not in it
    assert p['capacity']['over_threshold'] == ['pve2']
    assert p['plan'] == {'templates': 1, 'blocking_rules': ['ad-pair'], 'online_nodes': 2}
    assert admin.get(f'/api/vlab/admin/clusters/{CID}/nodes/bad_node/maintenance-preview').status_code == 400

    seen = {}

    def fake_set(c, n):
        seen['set'] = (c, n, request.get_json())
        return jsonify({'message': 'ok', 'task': {'status': 'evacuating'}})
    monkeypatch.setattr(core_vms, 'set_maintenance_mode', fake_set)
    assert viewer.put(f'{base}/maintenance', json={'enable': True}).status_code == 403
    assert admin.put(f'{base}/maintenance', json={'enable': 'yes'}).status_code == 400
    assert admin.put(f'{base}/maintenance', json={'skip_evacuation': True}).status_code == 400
    assert admin.put(f'{base}/maintenance', json={'enable': True, 'force': True}).status_code == 400
    r = admin.put(f'{base}/maintenance', json={'enable': True, 'migrate_templates': True})
    assert r.status_code == 200 and seen['set'] == (CID, 'pve1', {'enable': True, 'migrate_templates': True})

    monkeypatch.setattr(core_vms, 'node_action_api', lambda c, n, a: jsonify({'message': f'{a} {n}'}))
    assert admin.post(f'{base}/action', json={'action': 'reboot'}).status_code == 400          # no confirm
    assert admin.post(f'{base}/action', json={'action': 'halt', 'confirm': 'pve1'}).status_code == 400
    r = admin.post(f'{base}/action', json={'action': 'shutdown', 'confirm': 'pve1'})
    assert r.status_code == 200 and r.get_json()['message'] == 'shutdown pve1'


def test_node_log_sensors_and_tasks(env, monkeypatch):
    import pegaprox.api.nodes as core_nodes
    from flask import jsonify
    _, _, admin, alice, _, _ = env
    base = f'/api/vlab/admin/clusters/{CID}/nodes/pve1'
    monkeypatch.setattr(core_nodes, 'get_node_syslog_api', lambda c, n: jsonify(['Oct 16 pvedaemon: started', 'Oct 16 kernel: x']))
    assert alice.get(f'{base}/syslog').status_code == 403
    assert admin.get(f'{base}/syslog').get_json()['lines'][0] == 'Oct 16 pvedaemon: started'

    monkeypatch.setattr(core_nodes, 'get_node_sensors_api', lambda c, n: (jsonify(
        {'error': 'SSH is switched off for this cluster, and sensors are read over SSH'}), 502))
    s = admin.get(f'{base}/sensors').get_json()
    assert s['sensors'] == [] and 'SSH' in s['error']
    monkeypatch.setattr(core_nodes, 'get_node_sensors_api', lambda c, n: jsonify(
        {'sensors': [{'chip': 'coretemp', 'label': 'Package id 0', 'kind': 'temp', 'value': 51.0, 'max': 84, 'crit': 100,
                      'alarm': False, 'extra': 1}], 'count': 1}))
    s = admin.get(f'{base}/sensors').get_json()
    assert s['error'] is None and s['sensors'][0] == {'chip': 'coretemp', 'label': 'Package id 0', 'kind': 'temp',
                                                      'value': 51.0, 'max': 84, 'crit': 100, 'alarm': False}

    monkeypatch.setattr(core_nodes, 'get_node_tasks_api', lambda c, n: jsonify(
        [{'upid': _upid('pve1', 'vzdump', 300), 'type': 'vzdump', 'id': '300', 'starttime': 5, 'endtime': 9, 'status': 'OK'}]))
    t = admin.get(f'{base}/tasks').get_json()['tasks']
    assert [(x['type'], x['node'], x['ok']) for x in t] == [('vzdump', 'pve1', True)]


def test_proxmox_ha_resources_and_groups(env, monkeypatch):
    import pegaprox.api.clusters as core_clusters
    from flask import jsonify, request
    _, mgr, admin, alice, _, viewer = env
    pool = store.create_pool('라이선스', 'dedicated', CID)
    store.add_desktop(pool, 'pve1', 300, 'lab-win11-01')
    monkeypatch.setattr(core_clusters, 'get_proxmox_ha_resources', lambda c: jsonify(
        [{'sid': 'vm:300', 'state': 'started', 'max_restart': 2, 'max_relocate': 1, 'group': 'lab'}, {'sid': 'bogus'}]))
    monkeypatch.setattr(core_clusters, 'get_proxmox_ha_groups', lambda c: jsonify(
        [{'group': 'lab', 'nodes': 'pve1:2,pve2', 'restricted': 0, 'nofailback': 0, '_pve_rule_id': 'lab'}]))
    mgr._api_get.return_value = _Resp([
        {'type': 'quorum', 'status': 'OK'}, {'type': 'master', 'node': 'pve2'},
        {'type': 'service', 'sid': 'vm:300', 'node': 'pve1', 'state': 'started'}])
    base = f'/api/vlab/admin/clusters/{CID}/ha'
    assert alice.get(base).status_code == 403
    r = admin.get(base)
    assert r.status_code == 200, r.get_json()
    h = r.get_json()
    assert h['quorate'] is True and h['master'] == 'pve2'
    assert [(x['sid'], x['node'], x['status'], x['desktop']['name']) for x in h['resources']] == [('vm:300', 'pve1', 'started', 'lab-win11-01')]
    assert h['groups'][0]['nodes'] == 'pve1:2,pve2' and h['groups'][0]['rule'] is True

    mgr.add_vm_to_proxmox_ha.return_value = {'success': True}
    mgr.remove_vm_from_proxmox_ha.return_value = {'success': True}
    assert viewer.post(f'{base}/resources', json={'vmid': 301}).status_code == 403
    assert admin.post(f'{base}/resources', json={'vmid': 301, 'state': 'on'}).status_code == 400
    assert admin.post(f'{base}/resources', json={'vmid': 301, 'group': 'a b'}).status_code == 400
    assert admin.post(f'{base}/resources', json={'vmid': 900}).status_code == 404                # a template
    assert admin.post(f'{base}/resources', json={'vmid': 777}).status_code == 404
    r = admin.post(f'{base}/resources', json={'vmid': 301, 'max_restart': 3, 'comment': '라이선스 서버'})
    assert r.status_code == 201 and r.get_json()['sid'] == 'vm:301'
    assert mgr.add_vm_to_proxmox_ha.call_args[0] == (301, 'vm', None, 3, 1, 'started', '라이선스 서버')
    assert admin.delete(f'{base}/resources/300').status_code == 200
    assert mgr.remove_vm_from_proxmox_ha.call_args[0] == (300, 'vm')

    seen = {}

    def fake_group(c):
        seen['g'] = request.get_json()
        return jsonify({'success': True})
    monkeypatch.setattr(core_clusters, 'create_proxmox_ha_group', fake_group)
    monkeypatch.setattr(core_clusters, 'delete_proxmox_ha_group', lambda c, g: jsonify({'success': True, 'g': g}))
    assert admin.post(f'{base}/groups', json={'group': 'lab', 'nodes': 'pve1;rm -rf'}).status_code == 400
    assert admin.post(f'{base}/groups', json={'group': '1lab', 'nodes': 'pve1'}).status_code == 400
    assert admin.post(f'{base}/groups', json={'group': 'lab', 'nodes': 'pve1', 'resources': 'vm:abc'}).status_code == 400
    body = {'group': 'lab2', 'nodes': 'pve1:2,pve2', 'restricted': True, 'resources': 'vm:300,vm:301'}
    assert admin.post(f'{base}/groups', json=body).status_code == 200 and seen['g'] == body
    assert admin.delete(f'{base}/groups/lab2').get_json()['g'] == 'lab2'
