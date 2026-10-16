"""MOAVI Desk next-phase screens (pegaprox/api/vlab_next.py): departments, sign-up review,
the USB device library, gateways, external desktops, golden images, the board lab, the
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


# --- gateways and external desktops ------------------------------------------------------

def test_gateway_check_and_external_desktop_rdp(env, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    _, _, admin, alice, bob, _ = env
    assert admin.post('/api/vlab/admin/gateways', json={'name': 'gw', 'kind': 'ssh', 'address': 'x'}).status_code == 400
    assert admin.post('/api/vlab/admin/gateways', json={'name': 'gw', 'kind': 'rdpgw', 'address': 'bad host!'}).status_code == 400
    gw = admin.post('/api/vlab/admin/gateways', json={'name': '외부망 RDP', 'kind': 'rdpgw', 'address': 'rdgw.example.com'}).get_json()['gateway']
    assert gw['port'] == 443
    monkeypatch.setattr(nxt, '_tcp_probe', lambda h, p, timeout=2.0: (True, 12, ''))
    r = admin.post(f"/api/vlab/admin/gateways/{gw['id']}/check").get_json()
    assert r['ok'] and r['gateway']['last_ok'] == 1 and r['gateway']['last_detail'] == '12 ms'

    assert admin.post('/api/vlab/admin/external-desktops', json={'name': 'PC', 'address': '10.0.0.5', 'assigned_user': 'ghost'}).status_code == 400
    ext = admin.post('/api/vlab/admin/external-desktops', json={'name': '연구실 PC 3', 'address': '10.0.0.5', 'assigned_user': 'alice',
                                                                 'gateway_id': gw['id']}).get_json()['desktop']
    mine = alice.get('/api/vlab/me/external').get_json()['desktops']
    assert [m['name'] for m in mine] == ['연구실 PC 3'] and bob.get('/api/vlab/me/external').get_json()['desktops'] == []
    rdp = alice.get(f"/api/vlab/me/external/{ext['id']}/rdp").get_json()
    assert rdp['filename'].endswith('.rdp')
    assert 'full address:s:10.0.0.5:3389' in rdp['rdp'] and 'username:s:alice' in rdp['rdp']
    assert 'gatewayhostname:s:rdgw.example.com:443' in rdp['rdp']
    assert bob.get(f"/api/vlab/me/external/{ext['id']}/rdp").status_code == 404

    assert admin.get('/api/vlab/admin/gateways').get_json()['gateways'][0]['external'] == 1
    admin.delete(f"/api/vlab/admin/gateways/{gw['id']}")
    assert catalog.get_external(ext['id'])['gateway_id'] is None
    assert 'gateway' not in alice.get(f"/api/vlab/me/external/{ext['id']}/rdp").get_json()['rdp']


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
