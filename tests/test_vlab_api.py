"""vLAB API (MAKUS): pools, desktops, assignment and the user's own desktops, end to end.

Assigning a desktop must also grant the user on the core VM ACL (and take it away again
on reassign/unassign), because the console, SPICE and snapshot routes authorise through
that ACL. docs/vlab-design.md 3, 5, 6.
"""
import pytest

from pegaprox.utils.rbac import invalidate_vm_acls_cache, load_vm_acls
from pegaprox.vlab import store

CID = 'cluster_1'
RES = [
    {'vmid': 300, 'node': 'pve1', 'name': 'lab-win11-01', 'type': 'qemu', 'status': 'running',
     'maxcpu': 4, 'maxmem': 8 * 1024 ** 3},
    {'vmid': 301, 'node': 'pve1', 'name': 'lab-win11-02', 'type': 'qemu', 'status': 'stopped'},
]


@pytest.fixture
def env(api, seed):
    mgr = api.make_fake_manager(CID, get_vm_resources=RES)
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    bob = api.as_user(seed.user('bob', role='user'))
    viewer = api.as_user(seed.user('vera', role='viewer'))
    return api, admin, alice, bob, viewer


def _acl_users(vmid):
    invalidate_vm_acls_cache()
    return sorted((load_vm_acls().get(CID) or {}).get(str(vmid), {}).get('users') or [])


def _pool_with_desktop(admin, vmid=300):
    r = admin.post('/api/vlab/admin/pools', json={'name': '공용 랩 A', 'type': 'reset', 'cluster_id': CID})
    assert r.status_code == 201, r.get_json()
    pool = r.get_json()['pool']
    r = admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': vmid})
    assert r.status_code == 201, r.get_json()
    return pool, r.get_json()['desktop']


def test_signed_out_callers_get_nothing(env):
    api = env[0]
    for path in ('/api/vlab/info', '/api/vlab/me/desktops', '/api/vlab/admin/pools'):
        assert api.anon().get(path).status_code == 401, path


def test_info_answers_any_signed_in_user(env):
    _, _, alice, _, _ = env
    r = alice.get('/api/vlab/info')
    assert r.status_code == 200
    assert 'reset' in r.get_json()['pool_types']


def test_a_user_without_desktops_sees_an_empty_list(env):
    _, _, alice, _, _ = env
    r = alice.get('/api/vlab/me/desktops')
    assert r.status_code == 200
    assert r.get_json() == {'desktops': []}


def test_viewers_do_not_get_the_portal_by_default(env):
    # the builtin viewer role is hand-maintained and must not widen on an upgrade
    # (test_effective_role_matrix): vlab.desk is granted to a viewer explicitly
    _, _, _, _, viewer = env
    assert viewer.get('/api/vlab/me/desktops').status_code == 403


def test_assignment_shows_the_desktop_and_grants_the_vm_acl(env):
    _, admin, alice, bob, _ = env
    pool, desk = _pool_with_desktop(admin)
    assert desk['name'] == 'lab-win11-01' and desk['node'] == 'pve1'   # taken from the cluster

    r = admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'})
    assert r.status_code == 200, r.get_json()
    assert _acl_users(300) == ['alice']

    mine = alice.get('/api/vlab/me/desktops').get_json()['desktops']
    assert [d['id'] for d in mine] == [desk['id']]
    assert mine[0]['pool'] == '공용 랩 A'
    assert mine[0]['state'] == 'ready'                     # guest is running
    assert mine[0]['spec'] == {'cpu': 4, 'memory_gb': 8}
    assert bob.get('/api/vlab/me/desktops').get_json()['desktops'] == []

    # reassign: bob gains the grant, alice loses it
    assert admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'bob'}).status_code == 200
    assert _acl_users(300) == ['bob']
    assert alice.get('/api/vlab/me/desktops').get_json()['desktops'] == []

    # unassign: no grant left at all
    assert admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': None}).status_code == 200
    assert _acl_users(300) == []


def test_assignment_keeps_other_users_on_the_same_acl(env, seed):
    _, admin, _, _, _ = env
    seed.vm_acl(CID, 300, ['ops'])
    _, desk = _pool_with_desktop(admin)
    admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'})
    assert _acl_users(300) == ['alice', 'ops']
    admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': None})
    assert _acl_users(300) == ['ops']


def test_a_stopped_guest_shows_as_stopped(env):
    _, admin, alice, _, _ = env
    _, desk = _pool_with_desktop(admin, vmid=301)
    admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'})
    assert alice.get('/api/vlab/me/desktops').get_json()['desktops'][0]['state'] == 'stopped'


def test_removing_an_assigned_desktop_takes_the_grant_away(env):
    _, admin, alice, _, _ = env
    pool, desk = _pool_with_desktop(admin)
    admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'})
    assert admin.delete(f"/api/vlab/admin/desktops/{desk['id']}").status_code == 200
    assert _acl_users(300) == []
    assert alice.get('/api/vlab/me/desktops').get_json()['desktops'] == []
    assert admin.delete(f"/api/vlab/admin/pools/{pool['id']}").status_code == 200


def test_pool_input_is_checked(env):
    _, admin, _, _, _ = env
    assert admin.post('/api/vlab/admin/pools', json={'name': 'x', 'type': 'nope', 'cluster_id': CID}).status_code == 400
    assert admin.post('/api/vlab/admin/pools', json={'name': '', 'type': 'reset', 'cluster_id': CID}).status_code == 400
    assert admin.post('/api/vlab/admin/pools', json={'name': 'x', 'type': 'reset', 'cluster_id': 'nowhere'}).status_code == 404


def test_desktop_input_is_checked(env):
    _, admin, _, _, _ = env
    pool, _ = _pool_with_desktop(admin)
    url = f"/api/vlab/admin/pools/{pool['id']}/desktops"
    assert admin.post(url, json={'vmid': 'abc'}).status_code == 400
    assert admin.post(url, json={'vmid': 999}).status_code == 404       # not on the cluster
    assert admin.post(url, json={'vmid': 300}).status_code == 409       # already a desktop
    assert admin.post(url, json={'vmid': 301, 'type': 'xen'}).status_code == 400


def test_a_pool_with_desktops_cannot_be_deleted(env):
    _, admin, _, _, _ = env
    pool, _ = _pool_with_desktop(admin)
    assert admin.delete(f"/api/vlab/admin/pools/{pool['id']}").status_code == 409


def test_assigning_an_unknown_user_is_refused(env):
    _, admin, _, _, _ = env
    _, desk = _pool_with_desktop(admin)
    assert admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'ghost'}).status_code == 404
    assert _acl_users(300) == []


def test_users_and_viewers_cannot_manage_pools(env):
    _, admin, alice, _, viewer = env
    pool, desk = _pool_with_desktop(admin)
    for who in (alice, viewer):
        assert who.get('/api/vlab/admin/pools').status_code == 403
        assert who.post('/api/vlab/admin/pools', json={'name': 'x', 'type': 'reset', 'cluster_id': CID}).status_code == 403
        assert who.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'}).status_code == 403
        assert who.delete(f"/api/vlab/admin/pools/{pool['id']}").status_code == 403
    assert _acl_users(300) == []


def test_admin_lists_pools_and_their_desktops(env):
    _, admin, _, _, _ = env
    pool, desk = _pool_with_desktop(admin)
    admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'})
    pools = admin.get('/api/vlab/admin/pools').get_json()['pools']
    assert [(p['id'], p['desktops'], p['assigned']) for p in pools] == [(pool['id'], 1, 1)]
    desks = admin.get(f"/api/vlab/admin/pools/{pool['id']}/desktops").get_json()['desktops']
    assert [(d['vmid'], d['assigned_user'], d['state']) for d in desks] == [(300, 'alice', 'ready')]


def test_active_loans_are_listed_for_their_user_only(env):
    _, _, alice, bob, _ = env
    store.db().execute(
        "INSERT INTO vlab_leases (id, resource_type, resource_id, resource_name, username, starts_at, ends_at, state) "
        "VALUES ('l1', 'card', 'card-1', 'Alveo U250 #2', 'alice', '2026-10-15T00:00:00+00:00', "
        "'2026-10-31T09:00:00+00:00', 'active')")
    store.db().execute(
        "INSERT INTO vlab_leases (id, resource_type, resource_id, username, starts_at, state) "
        "VALUES ('l2', 'usb', 'jtag-1', 'alice', '2026-10-01T00:00:00+00:00', 'returned')")
    assert alice.get('/api/vlab/me/leases').get_json()['leases'] == [
        {'id': 'l1', 'kind': 'card', 'name': 'Alveo U250 #2', 'ends_at': '2026-10-31T09:00:00+00:00', 'desktop': None,
         'use': None, 'reclaim': None}]
    assert bob.get('/api/vlab/me/leases').get_json()['leases'] == []


# --- what the pool screens pick from ---------------------------------------------

def test_admin_lists_reachable_clusters(env):
    _, admin, _, _, _ = env
    r = admin.get('/api/vlab/admin/clusters')
    assert r.status_code == 200
    assert [(c['id'], c['connected']) for c in r.get_json()['clusters']] == [(CID, True)]


def test_guests_show_which_are_desktops_already(env):
    _, admin, _, _, _ = env
    pool, desk = _pool_with_desktop(admin)
    guests = admin.get(f'/api/vlab/admin/clusters/{CID}/guests').get_json()['guests']
    assert [(g['vmid'], g['desktop_id'], g['pool_id']) for g in guests] == [
        (300, desk['id'], pool['id']), (301, None, None)]
    assert admin.get('/api/vlab/admin/clusters/nowhere/guests').status_code == 404


NODES = {
    'pve1': {'status': 'online', 'offline': False, 'cpu_percent': 12.5, 'mem_used': 8 * 1024 ** 3,
             'mem_total': 64 * 1024 ** 3, 'mem_percent': 12.5, 'disk_used': 10, 'disk_total': 100, 'uptime': 3600,
             'loadavg': ['0.50', '0.40', '0.30'], 'cpuinfo': {'cpus': 32, 'model': 'AMD EPYC 9124'},
             'pveversion': 'pve-manager/8.2.4', 'maintenance_mode': False},
    'pve2': {'status': 'offline', 'offline': True, 'cpu_percent': 0, 'mem_used': 0, 'mem_total': 0},
}


def test_nodes_show_load_guests_and_desktops(env):
    api, admin, alice, _, _ = env
    mgr = api.make_fake_manager(CID, get_vm_resources=RES, get_node_status=NODES)
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    _pool_with_desktop(admin)
    r = admin.get(f'/api/vlab/admin/clusters/{CID}/nodes').get_json()
    one, two = r['nodes']
    assert (one['node'], one['online'], one['cpus'], one['cpu_model'], one['version']) == (
        'pve1', True, 32, 'AMD EPYC 9124', 'pve-manager/8.2.4')
    assert (one['guests'], one['running'], one['desktops'], one['loadavg']) == (2, 1, 1, ['0.50', '0.40', '0.30'])
    assert (two['node'], two['online'], two['guests'], two['cpus']) == ('pve2', False, 0, 0)
    assert admin.get('/api/vlab/admin/clusters/nowhere/nodes').status_code == 404
    assert alice.get(f'/api/vlab/admin/clusters/{CID}/nodes').status_code == 403


def test_storage_lists_shared_storage_once(env, monkeypatch):
    _, admin, alice, _, _ = env
    import pegaprox.api.clusters as core_clusters
    rows = [
        {'storage': 'local-lvm', 'node': 'pve1', 'plugintype': 'lvmthin', 'shared': 0, 'content': 'images,rootdir',
         'status': 'available', 'disk': 100, 'maxdisk': 1000},
        {'storage': 'ceph-vm', 'node': 'pve2', 'plugintype': 'rbd', 'shared': 1, 'content': 'images',
         'status': 'unknown', 'disk': 0, 'maxdisk': 0},
        {'storage': 'ceph-vm', 'node': 'pve1', 'plugintype': 'rbd', 'shared': 1, 'content': 'images',
         'status': 'available', 'disk': 500, 'maxdisk': 4000},
    ]
    monkeypatch.setattr(core_clusters, 'cluster_storage_resources', lambda cid, mgr: rows)
    s = admin.get(f'/api/vlab/admin/clusters/{CID}/storage').get_json()['storage']
    assert [(x['storage'], x['shared'], x['nodes'], x['status'], x['used'], x['total']) for x in s] == [
        ('ceph-vm', True, ['pve1', 'pve2'], 'available', 500, 4000),
        ('local-lvm', False, ['pve1'], 'available', 100, 1000)]
    assert s[1]['content'] == ['images', 'rootdir'] and s[1]['type'] == 'lvmthin'
    monkeypatch.setattr(core_clusters, 'cluster_storage_resources', lambda cid, mgr: None)
    assert admin.get(f'/api/vlab/admin/clusters/{CID}/storage').status_code == 502
    assert alice.get(f'/api/vlab/admin/clusters/{CID}/storage').status_code == 403


def test_templates_are_not_offered_as_desktops(api, seed):
    mgr = api.make_fake_manager(CID, get_vm_resources=RES + [
        {'vmid': 900, 'node': 'pve1', 'name': 'tpl-win11', 'type': 'qemu', 'template': 1, 'status': 'stopped'}])
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    vmids = [g['vmid'] for g in admin.get(f'/api/vlab/admin/clusters/{CID}/guests').get_json()['guests']]
    assert vmids == [300, 301]


def test_assignable_users_skip_disabled_accounts(env, seed):
    _, admin, _, _, _ = env
    seed.user('gone', role='user', enabled=False)
    names = [u['username'] for u in admin.get('/api/vlab/admin/users').get_json()['users']]
    assert 'alice' in names and 'bob' in names and 'gone' not in names


def test_assignable_users_stay_inside_a_tenant(api, seed):
    mgr = api.make_fake_manager(CID, get_vm_resources=RES)
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    seed.tenant('acme', [CID])
    seed.user('acme_admin', role='admin', tenant_id='acme')
    seed.user('acme_user', role='user', tenant_id='acme')
    seed.user('other_user', role='user')
    acme = api.as_user(seed.db.get_user('acme_admin') | {'username': 'acme_admin'})
    names = [u['username'] for u in acme.get('/api/vlab/admin/users').get_json()['users']]
    assert 'acme_user' in names and 'other_user' not in names


def test_all_desktops_lists_every_pool(env):
    _, admin, _, _, _ = env
    pool, desk = _pool_with_desktop(admin)
    admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'})
    desks = admin.get('/api/vlab/admin/desktops').get_json()['desktops']
    assert [(d['id'], d['pool'], d['pool_id'], d['assigned_user'], d['state']) for d in desks] == [
        (desk['id'], '공용 랩 A', pool['id'], 'alice', 'ready')]
    assert desks[0]['usage'] == {'cpu_percent': 0, 'cpus': 4, 'mem': 0, 'maxmem': 8 * 1024 ** 3, 'uptime': 0}


def test_admins_power_any_desktop(connectable):
    admin, alice, bob, _, desk, stopped = connectable
    r = admin.post(f"/api/vlab/admin/desktops/{stopped['id']}/power", json={'action': 'start'})
    assert r.status_code == 200, r.get_json()
    assert _mgr().vm_action.call_args[0] == ('pve1', 301, 'qemu', 'start')
    assert admin.post(f"/api/vlab/admin/desktops/{desk['id']}/power", json={'action': 'explode'}).status_code == 400
    assert admin.post('/api/vlab/admin/desktops/nope/power', json={'action': 'start'}).status_code == 404
    # the assigned user has a route of their own; this one is for pool managers
    assert alice.post(f"/api/vlab/admin/desktops/{desk['id']}/power", json={'action': 'stop'}).status_code == 403


def test_users_cannot_read_the_admin_lists(env):
    _, _, alice, _, _ = env
    for path in ('/api/vlab/admin/clusters', f'/api/vlab/admin/clusters/{CID}/guests',
                 '/api/vlab/admin/users', '/api/vlab/admin/desktops'):
        assert alice.get(path).status_code == 403, path


# --- connecting ------------------------------------------------------------------

@pytest.fixture
def connectable(env):
    api, admin, alice, bob, viewer = env
    mgr = api.make_fake_manager(
        CID, get_vm_resources=RES,
        get_vnc_ticket={'success': True, 'ticket': 'PVEVNC:abc/def', 'port': '5900'},
        vm_action={'success': True, 'data': 'UPID:pve1:0001:start'},
        get_spice_ticket={'success': True, 'data': {
            'type': 'spice', 'host': 'pvespiceproxy:aa:300:pve1::bb', 'password': 'pw', 'proxy': 'http://pve1:3128',
            'ca': '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----'}})
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    _, desk = _pool_with_desktop(admin)
    _, stopped = _pool_with_desktop(admin, vmid=301)
    for d in (desk, stopped):
        admin.put(f"/api/vlab/admin/desktops/{d['id']}/assign", json={'username': 'alice'})
    return admin, alice, bob, viewer, desk, stopped


def test_vnc_connect_hands_out_the_websocket_and_records_a_session(connectable):
    _, alice, _, _, desk, _ = connectable
    r = alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'})
    assert r.status_code == 200, r.get_json()
    a = r.get_json()
    assert a['type'] == 'vnc' and a['password'] == 'PVEVNC:abc/def'
    assert a['ws_path'].startswith(f'/api/clusters/{CID}/vms/pve1/qemu/300/vncwebsocket?token=')
    assert '&pve_ticket=PVEVNC%3Aabc%2Fdef&pve_port=5900' in a['ws_path']
    row = store.db().query_one('SELECT * FROM vlab_sessions WHERE id = ?', (a['session_id'],))
    assert (row['username'], row['desktop_id'], row['protocol'], row['ended_at']) == ('alice', desk['id'], 'vnc', None)


def test_spice_connect_returns_a_virt_viewer_file(connectable):
    _, alice, _, _, desk, _ = connectable
    a = alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'spice'}).get_json()
    assert a['type'] == 'spice' and a['filename'] == 'lab-win11-01.vv'
    lines = a['vv'].splitlines()
    assert lines[0] == '[virt-viewer]'
    assert 'proxy=http://pve1:3128' in lines
    assert r'ca=-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----' in lines   # one line, \n escaped


def test_only_the_assigned_user_connects(connectable):
    _, _, bob, viewer, desk, _ = connectable
    assert bob.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'}).status_code == 404
    assert viewer.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'}).status_code == 403


def test_connect_refuses_a_stopped_desktop_and_an_unknown_protocol(connectable):
    admin, alice, _, _, desk, stopped = connectable
    # the default policy starts it, and the user connects again in a moment
    r = alice.post(f"/api/vlab/desktops/{stopped['id']}/connect", json={'protocol': 'vnc'})
    assert r.status_code == 409 and r.get_json()['code'] == 'STARTING'
    assert _mgr().vm_action.call_args[0] == ('pve1', 301, 'qemu', 'start')
    admin.put(f"/api/vlab/admin/pools/{stopped['pool_id']}/policy", json={'start_on_connect': False})
    r = alice.post(f"/api/vlab/desktops/{stopped['id']}/connect", json={'protocol': 'vnc'})
    assert r.status_code == 409 and r.get_json()['code'] == 'VM_STOPPED'
    assert alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'guac'}).status_code == 400


# --- pool policy -------------------------------------------------------------------

def test_pool_policy_defaults_and_checks(connectable):
    admin, alice, _, _, desk, _ = connectable
    url = f"/api/vlab/admin/pools/{desk['pool_id']}/policy"
    r = admin.get(url).get_json()
    assert r['policy']['clipboard'] == 'both' and r['policy']['protocols'] == ['vnc', 'spice', 'rdp'] and r['policy']['rdp_tune'] is True and r['reset_allowed'] is True
    for bad in ({'clipboard': 'sideways'}, {'protocols': []}, {'protocols': ['ftp']}, {'idle_shutdown_min': -1},
                {'max_session_hours': 'x'}, {'allow_power': 'yes'}, {'colour': 'blue'}):
        assert admin.put(url, json=bad).status_code == 400, bad
    assert alice.put(url, json={'clipboard': 'off'}).status_code == 403
    dedicated = admin.post('/api/vlab/admin/pools', json={'name': '전용', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    r = admin.put(f"/api/vlab/admin/pools/{dedicated['id']}/policy", json={'reset_on_logout': True})
    assert r.status_code == 400 and 'reset' in r.get_json()['error']


def test_the_policy_shapes_the_connection(connectable):
    admin, alice, _, _, desk, _ = connectable
    url = f"/api/vlab/admin/pools/{desk['pool_id']}/policy"
    assert admin.put(url, json={'protocols': ['spice'], 'clipboard': 'off', 'usb_redirect': False,
                                'spice_fullscreen': True}).status_code == 200
    assert alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'}).status_code == 400
    vv = alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'spice'}).get_json()['vv']
    assert 'enable-usbredir=0' in vv and 'enable-usb-autoshare=0' in vv and 'fullscreen=1' in vv and 'delete-this-file=1' in vv
    admin.put(url, json={'clipboard': 'to_desktop'})
    a = alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'}).get_json()
    assert a['clipboard'] == 'to_desktop'
    (mine,) = [d for d in alice.get('/api/vlab/me/desktops').get_json()['desktops'] if d['id'] == desk['id']]
    assert mine['policy'] == {'clipboard': 'to_desktop', 'allow_power': True, 'start_on_connect': True, 'web_ide': []}


def test_the_policy_can_take_power_away(connectable):
    admin, alice, _, _, desk, _ = connectable
    admin.put(f"/api/vlab/admin/pools/{desk['pool_id']}/policy", json={'allow_power': False})
    r = alice.post(f"/api/vlab/desktops/{desk['id']}/power", json={'action': 'reboot'})
    assert r.status_code == 403 and r.get_json()['code'] == 'POWER_OFF'


def test_reset_on_logout(connectable):
    admin, alice, _, _, desk, _ = connectable
    store.set_base_snap(desk['id'], 'vlab-base')
    admin.put(f"/api/vlab/admin/pools/{desk['pool_id']}/policy", json={'reset_on_logout': True})
    _mgr().rollback_snapshot.return_value = {'success': True}
    s1 = alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'}).get_json()['session_id']
    s2 = alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'}).get_json()['session_id']
    alice.post(f'/api/vlab/sessions/{s1}/end')
    assert _mgr().rollback_snapshot.call_count == 0                     # still in use by the second session
    alice.post(f'/api/vlab/sessions/{s2}/end')
    assert _mgr().rollback_snapshot.call_args[0] == ('pve1', 300, 'qemu', 'vlab-base')


def test_policy_tick_expires_long_sessions_and_shuts_idle_desktops(connectable):
    from datetime import datetime, timedelta, timezone
    from pegaprox.api.vlab import policy_tick
    admin, alice, _, _, desk, _ = connectable
    admin.put(f"/api/vlab/admin/pools/{desk['pool_id']}/policy", json={'max_session_hours': 4, 'idle_shutdown_min': 30})
    sid = alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'}).get_json()['session_id']
    now = datetime.now(timezone.utc)
    mgr = _mgr()
    mgr.get_vm_resources.return_value = [dict(RES[0], uptime=7200), RES[1]]
    mgr.vm_action.reset_mock()
    assert policy_tick(now) == {'expired': 0, 'shutdown': 0, 'deferred': 0}             # in use: left alone
    assert policy_tick(now + timedelta(hours=5)) == {'expired': 1, 'shutdown': 0, 'deferred': 0}   # session closed ...
    row = store.db().query_one('SELECT result FROM vlab_sessions WHERE id = ?', (sid,))
    assert row['result'] == 'expired'
    assert policy_tick(now + timedelta(hours=5)) == {'expired': 0, 'shutdown': 0, 'deferred': 0}   # ... it just ended
    assert policy_tick(now + timedelta(hours=6)) == {'expired': 0, 'shutdown': 1, 'deferred': 0}   # 30 min idle: shut down
    assert mgr.vm_action.call_args[0] == ('pve1', 300, 'qemu', 'shutdown')


def test_connect_follows_the_vm_acl_not_only_the_assignment(connectable):
    # the grant was taken away behind vLAB's back: the core ACL has the last word
    _, alice, _, _, desk, _ = connectable
    from pegaprox.core.db import get_db
    get_db().delete_vm_acl(CID, 300)
    invalidate_vm_acls_cache()
    assert alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'}).status_code == 403


def test_a_user_ends_only_their_own_session(connectable):
    _, alice, bob, _, desk, _ = connectable
    sid = alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'}).get_json()['session_id']
    assert bob.post(f'/api/vlab/sessions/{sid}/end').status_code == 404
    assert alice.post(f'/api/vlab/sessions/{sid}/end').status_code == 200
    assert alice.post(f'/api/vlab/sessions/{sid}/end').status_code == 404      # already closed
    assert store.db().query_one('SELECT result FROM vlab_sessions WHERE id = ?', (sid,))['result'] == 'ended'


def test_my_desktops_carry_pool_type_and_last_connect(connectable):
    _, alice, _, _, desk, _ = connectable
    before = {d['id']: d for d in alice.get('/api/vlab/me/desktops').get_json()['desktops']}
    assert before[desk['id']]['pool_type'] == 'reset'
    assert before[desk['id']]['last_connected'] is None
    alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'})
    after = {d['id']: d for d in alice.get('/api/vlab/me/desktops').get_json()['desktops']}
    assert after[desk['id']]['last_connected']


# --- power -----------------------------------------------------------------------

def _mgr():
    import pegaprox.globals as ppg
    return ppg.cluster_managers[CID]


def test_the_assigned_user_starts_their_desktop(connectable):
    _, alice, _, _, _, stopped = connectable
    r = alice.post(f"/api/vlab/desktops/{stopped['id']}/power", json={'action': 'start'})
    assert r.status_code == 200, r.get_json()
    assert r.get_json()['task'] == 'UPID:pve1:0001:start'
    _mgr().vm_action.assert_called_once_with('pve1', 301, 'qemu', 'start')


@pytest.mark.parametrize('action', ['shutdown', 'reboot', 'stop'])
def test_other_power_actions_reach_the_cluster(connectable, action):
    _, alice, _, _, desk, _ = connectable
    assert alice.post(f"/api/vlab/desktops/{desk['id']}/power", json={'action': action}).status_code == 200
    assert _mgr().vm_action.call_args.args[3] == action


def test_power_is_refused_to_others_and_for_unknown_actions(connectable):
    _, alice, bob, viewer, desk, _ = connectable
    assert bob.post(f"/api/vlab/desktops/{desk['id']}/power", json={'action': 'start'}).status_code == 404
    assert viewer.post(f"/api/vlab/desktops/{desk['id']}/power", json={'action': 'start'}).status_code == 403
    assert alice.post(f"/api/vlab/desktops/{desk['id']}/power", json={'action': 'delete'}).status_code == 400
    assert not _mgr().vm_action.called


def test_power_follows_the_vm_acl(connectable):
    _, alice, _, _, desk, _ = connectable
    from pegaprox.core.db import get_db
    get_db().delete_vm_acl(CID, 300)
    invalidate_vm_acls_cache()
    assert alice.post(f"/api/vlab/desktops/{desk['id']}/power", json={'action': 'start'}).status_code == 403
    assert not _mgr().vm_action.called


def test_a_failed_power_action_is_reported(connectable):
    _, alice, _, _, desk, _ = connectable
    _mgr().vm_action.return_value = {'success': False, 'error': 'VM is locked (backup)'}
    r = alice.post(f"/api/vlab/desktops/{desk['id']}/power", json={'action': 'start'})
    assert r.status_code == 502 and 'locked' in r.get_json()['error']


# --- session log -----------------------------------------------------------------

def test_admin_reads_the_session_log(connectable):
    admin, alice, _, _, desk, _ = connectable
    alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'})
    alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'spice'})
    rows = admin.get('/api/vlab/admin/sessions').get_json()['sessions']
    assert [(s['username'], s['desktop'], s['protocol'], s['pool']) for s in rows] == [
        ('alice', 'lab-win11-01', 'spice', '공용 랩 A'), ('alice', 'lab-win11-01', 'vnc', '공용 랩 A')]
    assert admin.get('/api/vlab/admin/sessions?username=bob').get_json()['sessions'] == []
    assert len(admin.get('/api/vlab/admin/sessions?limit=1').get_json()['sessions']) == 1
    assert admin.get('/api/vlab/admin/sessions?limit=x').status_code == 400


def test_users_cannot_read_the_session_log(connectable):
    _, alice, _, _, _, _ = connectable
    assert alice.get('/api/vlab/admin/sessions').status_code == 403


# --- usage report ----------------------------------------------------------------

def _session(user, pool, desk, start, end=None, protocol='vnc'):
    iso = lambda t: t and t.isoformat(timespec='seconds')
    store.db().execute('INSERT INTO vlab_sessions (id, username, desktop_id, pool_id, protocol, started_at, ended_at)'
                       ' VALUES (?, ?, ?, ?, ?, ?, ?)',
                       (store.new_id('sess'), user, desk['id'], pool['id'], protocol, iso(start), iso(end)))


def test_usage_report_counts_hours_peaks_and_utilization(env):
    from datetime import datetime, timedelta, timezone
    _, admin, _, _, _ = env
    pool, desk = _pool_with_desktop(admin)
    now = datetime.now(timezone.utc)
    ago = lambda **kw: now - timedelta(**kw)
    _session('alice', pool, desk, ago(hours=3), ago(hours=1))
    _session('bob', pool, desk, ago(hours=2), protocol='spice')        # still open
    _session('carol', pool, desk, ago(days=40), ago(days=40) + timedelta(hours=1))
    r = admin.get('/api/vlab/admin/usage?days=7').get_json()
    t = r['totals']
    assert (t['sessions'], t['users'], t['peak'], t['open']) == (2, 2, 2, 1)
    assert abs(t['hours'] - 4) < 0.05 and abs(t['avg_minutes'] - 120) < 2
    assert len(r['by_day']) == 7 and sum(d['sessions'] for d in r['by_day']) == 2
    assert abs(sum(d['hours'] for d in r['by_day']) - 4) < 0.05
    (p,) = r['by_pool']
    window_h = (datetime.fromisoformat(r['to']) - datetime.fromisoformat(r['from'])).total_seconds() / 3600
    assert (p['name'], p['desktops'], p['sessions'], p['users']) == ('공용 랩 A', 1, 2, 2)
    assert abs(p['utilization'] - 4 / window_h) < 0.001
    assert [u['username'] for u in r['top_users']] == ['alice', 'bob']
    assert r['by_protocol'] == {'vnc': 1, 'spice': 1}
    assert admin.get('/api/vlab/admin/usage?days=90').get_json()['totals']['users'] == 3


def test_an_open_session_counts_at_most_the_cap(env):
    from datetime import datetime, timedelta, timezone
    _, admin, _, _, _ = env
    pool, desk = _pool_with_desktop(admin)
    _session('alice', pool, desk, datetime.now(timezone.utc) - timedelta(days=2))   # never ended
    t = admin.get('/api/vlab/admin/usage?days=7').get_json()['totals']
    assert abs(t['hours'] - 12) < 0.01 and t['open'] == 1


def test_usage_report_input_and_access(env):
    _, admin, alice, _, _ = env
    assert admin.get('/api/vlab/admin/usage?days=0').status_code == 400
    assert admin.get('/api/vlab/admin/usage?days=x').status_code == 400
    assert admin.get('/api/vlab/admin/usage?pool_id=nope').status_code == 404
    r = admin.get('/api/vlab/admin/usage').get_json()
    assert r['days'] == 7 and r['totals']['sessions'] == 0 and r['by_pool'] == []
    assert alice.get('/api/vlab/admin/usage').status_code == 403


# --- desktops from a template ----------------------------------------------------

TPL = {'vmid': 900, 'node': 'pve1', 'name': 'tpl-win11', 'type': 'qemu', 'template': 1, 'status': 'stopped',
       'maxcpu': 4, 'maxmem': 8 * 1024 ** 3}


@pytest.fixture
def cloning(api, seed):
    mgr = api.make_fake_manager(CID, get_vm_resources=RES + [TPL],
                                get_next_vmid={'success': True, 'vmid': 310},
                                clone_vm={'success': True, 'data': 'UPID:pve1:clone'})
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    pool = admin.post('/api/vlab/admin/pools', json={'name': '공용 랩 B', 'type': 'reset', 'cluster_id': CID}).get_json()['pool']
    return api, admin, mgr, pool


def test_templates_are_listed(cloning):
    _, admin, _, _ = cloning
    tpls = admin.get(f'/api/vlab/admin/clusters/{CID}/templates').get_json()['templates']
    assert [(t['vmid'], t['name'], t['spec']) for t in tpls] == [(900, 'tpl-win11', {'cpu': 4, 'memory_gb': 8})]
    assert 'linked_clone' not in tpls[0]                      # the clone dialog needs no config reads


@pytest.mark.parametrize('disk, plugin, linked', [
    ('local-lvm:base-900-disk-0,size=64G', 'lvmthin', True),
    ('ceph-vm:base-900-disk-0,size=64G', 'rbd', True),
    ('nfs-vm:900/base-900-disk-0.qcow2,size=64G', 'nfs', True),
    ('nfs-vm:900/base-900-disk-0.raw,size=64G', 'nfs', False),
    ('san-lvm:vm-900-disk-0,size=64G', 'lvm', False),
])
def test_template_details_say_whether_a_linked_clone_works(cloning, monkeypatch, disk, plugin, linked):
    _, admin, mgr, pool = cloning
    import pegaprox.api.clusters as core_clusters
    store_name = disk.split(':', 1)[0]
    monkeypatch.setattr(core_clusters, 'cluster_storage_resources',
                        lambda cid, m: [{'storage': store_name, 'plugintype': plugin, 'node': 'pve1'}])
    mgr.get_vm_config.return_value = {'success': True, 'config': {'raw': {
        'scsi0': disk, 'ide2': 'local:iso/virtio.iso,media=cdrom', 'efidisk0': disk.replace('disk-0', 'disk-1'),
        'net0': 'virtio=AA:BB,bridge=vmbr0'}}}
    (t,) = admin.get(f'/api/vlab/admin/clusters/{CID}/templates?details=1').get_json()['templates']
    assert [d['key'] for d in t['disks']] == ['efidisk0', 'scsi0'] and t['disks'][1]['plugin'] == plugin
    assert t['linked_clone'] is linked and t['pools'] == 0


def test_template_details_count_pools_cloned_from_it(cloning, monkeypatch):
    _, admin, mgr, pool = cloning
    import pegaprox.api.clusters as core_clusters
    monkeypatch.setattr(core_clusters, 'cluster_storage_resources', lambda cid, m: None)
    mgr.get_vm_config.return_value = {'success': False, 'error': 'boom'}
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/clone", json={'template_vmid': 900, 'count': 1, 'name_prefix': 'lab'})
    (t,) = admin.get(f'/api/vlab/admin/clusters/{CID}/templates?details=1').get_json()['templates']
    assert (t['pools'], t['disks'], t['linked_clone']) == (1, None, None)      # config unreadable: unknown


def test_clone_creates_provisioning_desktops_with_free_ids(cloning):
    _, admin, mgr, pool = cloning
    r = admin.post(f"/api/vlab/admin/pools/{pool['id']}/clone",
                   json={'template_vmid': 900, 'count': 3, 'name_prefix': 'lab-b'})
    assert r.status_code == 201, r.get_json()
    created = r.get_json()['created']
    assert [(c['vmid'], c['name']) for c in created] == [(310, 'lab-b-01'), (311, 'lab-b-02'), (312, 'lab-b-03')]
    assert mgr.clone_vm.call_count == 3
    args, kw = mgr.clone_vm.call_args_list[0]
    assert args == ('pve1', 900, 'qemu', 310) and kw['name'] == 'lab-b-01' and kw['full'] is False
    desks = admin.get(f"/api/vlab/admin/pools/{pool['id']}/desktops").get_json()['desktops']
    assert {d['state'] for d in desks} == {'provisioning'}


def test_a_finished_clone_turns_ready(cloning):
    api, admin, mgr, pool = cloning
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/clone", json={'template_vmid': 900, 'count': 1, 'name_prefix': 'lab-b'})
    mgr.get_vm_resources.return_value = RES + [TPL, {'vmid': 310, 'node': 'pve1', 'name': 'lab-b-01', 'type': 'qemu',
                                                      'status': 'stopped', 'lock': 'clone'}]
    assert admin.get(f"/api/vlab/admin/pools/{pool['id']}/desktops").get_json()['desktops'][0]['state'] == 'provisioning'
    mgr.get_vm_resources.return_value = RES + [TPL, {'vmid': 310, 'node': 'pve1', 'name': 'lab-b-01', 'type': 'qemu',
                                                      'status': 'stopped'}]
    assert admin.get(f"/api/vlab/admin/pools/{pool['id']}/desktops").get_json()['desktops'][0]['state'] == 'stopped'
    assert store.list_desktops(pool['id'])[0]['state'] == 'ready'      # remembered, not re-derived each time


def test_clone_skips_ids_in_use_and_numbers_after_existing_names(cloning):
    _, admin, mgr, pool = cloning
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/clone", json={'template_vmid': 900, 'count': 2, 'name_prefix': 'lab-b'})
    r = admin.post(f"/api/vlab/admin/pools/{pool['id']}/clone",
                   json={'template_vmid': 900, 'count': 2, 'name_prefix': 'lab-b', 'start_vmid': 299})
    assert [(c['vmid'], c['name']) for c in r.get_json()['created']] == [(299, 'lab-b-03'), (302, 'lab-b-04')]


def test_a_failed_clone_stops_the_run_and_says_where(cloning):
    _, admin, mgr, pool = cloning
    mgr.clone_vm.side_effect = [{'success': True, 'data': 'UPID:1'}, {'success': False, 'error': 'storage full'}]
    r = admin.post(f"/api/vlab/admin/pools/{pool['id']}/clone", json={'template_vmid': 900, 'count': 3, 'name_prefix': 'lab-b'})
    assert r.status_code == 207
    body = r.get_json()
    assert [c['vmid'] for c in body['created']] == [310]
    assert body['failed']['vmid'] == 311 and 'storage full' in body['failed']['error']
    assert mgr.clone_vm.call_count == 2
    assert len(store.list_desktops(pool['id'])) == 1


def test_clone_input_is_checked(cloning):
    _, admin, mgr, pool = cloning
    url = f"/api/vlab/admin/pools/{pool['id']}/clone"
    assert admin.post(url, json={'template_vmid': 300, 'count': 1, 'name_prefix': 'x'}).status_code == 404   # not a template
    assert admin.post(url, json={'template_vmid': 999, 'count': 1, 'name_prefix': 'x'}).status_code == 404
    assert admin.post(url, json={'template_vmid': 900, 'count': 0, 'name_prefix': 'x'}).status_code == 400
    assert admin.post(url, json={'template_vmid': 900, 'count': 101, 'name_prefix': 'x'}).status_code == 400
    assert admin.post(url, json={'template_vmid': 900, 'count': 1, 'name_prefix': '공용'}).status_code == 400
    assert admin.post(url, json={'template_vmid': 'a', 'count': 1, 'name_prefix': 'x'}).status_code == 400
    assert not mgr.clone_vm.called


def test_a_template_cannot_be_added_as_a_desktop(cloning):
    _, admin, _, pool = cloning
    assert admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': 900}).status_code == 400


def test_users_cannot_clone(cloning, seed):
    api, _, mgr, pool = cloning
    alice = api.as_user(seed.user('alice', role='user'))
    assert alice.post(f"/api/vlab/admin/pools/{pool['id']}/clone",
                      json={'template_vmid': 900, 'count': 1, 'name_prefix': 'x'}).status_code == 403
    assert not mgr.clone_vm.called


# --- cluster connections -----------------------------------------------------------

@pytest.fixture
def no_pve(monkeypatch):
    """The manager the core route builds connects to nothing and starts nothing."""
    from pegaprox.core.manager import PegaProxManager
    monkeypatch.setattr(PegaProxManager, 'connect_to_proxmox', lambda self: True)
    monkeypatch.setattr(PegaProxManager, 'start', lambda self: None)


NEW_CLUSTER = {'name': 'LAB-PVE', 'host': '10.9.5.1', 'user': 'root@pam', 'pass': 'pw', 'ssl_verification': False}


def test_admin_connects_a_cluster_through_the_core_route(env, no_pve):
    api, admin, _, _, _ = env
    r = admin.post('/api/vlab/admin/clusters', json=NEW_CLUSTER)
    assert r.status_code == 201, r.get_json()
    cid = r.get_json()['id']
    listed = {c['id']: c for c in admin.get('/api/vlab/admin/clusters').get_json()['clusters']}
    assert listed[cid]['name'] == 'LAB-PVE' and listed[cid]['host'] == '10.9.5.1' and listed[cid]['pools'] == 0
    assert 'pass' not in listed[cid]


def test_cluster_input_is_checked_before_the_core_sees_it(env, no_pve):
    _, admin, _, _, _ = env
    url = '/api/vlab/admin/clusters'
    assert admin.post(url, json={**NEW_CLUSTER, 'ha_enabled': True}).status_code == 400      # no screen for it
    assert admin.post(url, json={**NEW_CLUSTER, 'cluster_type': 'xcpng'}).status_code == 400
    assert admin.post(url, json={k: v for k, v in NEW_CLUSTER.items() if k != 'pass'}).status_code == 400
    assert admin.post(url, json={**NEW_CLUSTER, 'host': ' '}).status_code == 400
    assert admin.post(url, json={**NEW_CLUSTER, 'ssl_verification': 'yes'}).status_code == 400


def test_a_cluster_with_pools_cannot_be_disconnected(env):
    _, admin, _, _, _ = env
    _pool_with_desktop(admin)
    r = admin.delete(f'/api/vlab/admin/clusters/{CID}')
    assert r.status_code == 409
    assert admin.delete('/api/vlab/admin/clusters/nowhere').status_code == 404


def test_an_unused_cluster_is_disconnected(env, no_pve):
    _, admin, _, _, _ = env
    cid = admin.post('/api/vlab/admin/clusters', json=NEW_CLUSTER).get_json()['id']
    r = admin.delete(f'/api/vlab/admin/clusters/{cid}')
    assert r.status_code == 200, r.get_json()
    assert cid not in {c['id'] for c in admin.get('/api/vlab/admin/clusters').get_json()['clusters']}


def test_users_cannot_connect_or_disconnect_clusters(env, no_pve):
    _, _, alice, _, _ = env
    assert alice.post('/api/vlab/admin/clusters', json=NEW_CLUSTER).status_code == 403
    assert alice.delete(f'/api/vlab/admin/clusters/{CID}').status_code == 403


# --- base snapshot and reset ---------------------------------------------------------

@pytest.fixture
def resettable(cloning):
    api, admin, mgr, pool = cloning          # pool type 'reset'
    mgr.create_snapshot.return_value = {'success': True}
    mgr.delete_snapshot.return_value = {'success': True}
    mgr.rollback_snapshot.return_value = {'success': True, 'task': 'UPID:rollback'}
    return api, admin, mgr, pool


def _cloned_and_finished(admin, mgr, pool, n=2):
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/clone", json={'template_vmid': 900, 'count': n, 'name_prefix': 'lab-b'})
    mgr.get_vm_resources.return_value = RES + [TPL] + [
        {'vmid': 310 + i, 'node': 'pve1', 'name': f'lab-b-{i + 1:02d}', 'type': 'qemu', 'status': 'stopped'} for i in range(n)]
    return admin.get(f"/api/vlab/admin/pools/{pool['id']}/desktops").get_json()['desktops']


def test_a_reset_pool_takes_the_base_when_the_clone_finishes(resettable):
    _, admin, mgr, pool = resettable
    desks = _cloned_and_finished(admin, mgr, pool)
    assert mgr.create_snapshot.call_count == 2
    assert mgr.create_snapshot.call_args_list[0].args[:4] == ('pve1', 310, 'qemu', 'vlab-base')
    assert all(d['has_base'] for d in admin.get(f"/api/vlab/admin/pools/{pool['id']}/desktops").get_json()['desktops'])
    assert len(desks) == 2


def test_a_dedicated_pool_takes_no_base_on_its_own(api, seed):
    mgr = api.make_fake_manager(CID, get_vm_resources=RES + [TPL], get_next_vmid={'success': True, 'vmid': 310},
                                clone_vm={'success': True}, create_snapshot={'success': True})
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    pool = admin.post('/api/vlab/admin/pools', json={'name': 'R&D', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    _cloned_and_finished(admin, mgr, pool, n=1)
    assert not mgr.create_snapshot.called


def test_retaking_the_base_replaces_the_old_one(resettable):
    _, admin, mgr, pool = resettable
    desk = _cloned_and_finished(admin, mgr, pool, n=1)[0]
    r = admin.post(f"/api/vlab/admin/desktops/{desk['id']}/base")
    assert r.status_code == 200, r.get_json()
    mgr.delete_snapshot.assert_called_once_with('pve1', 310, 'qemu', 'vlab-base')
    assert mgr.create_snapshot.call_count == 2


def test_reset_rolls_back_to_the_base(resettable):
    _, admin, mgr, pool = resettable
    desk = _cloned_and_finished(admin, mgr, pool, n=1)[0]
    assert admin.post(f"/api/vlab/admin/desktops/{desk['id']}/reset").status_code == 200
    mgr.rollback_snapshot.assert_called_once_with('pve1', 310, 'qemu', 'vlab-base')


def test_reset_is_refused_while_someone_is_connected_unless_forced(resettable):
    _, admin, mgr, pool = resettable
    desk = _cloned_and_finished(admin, mgr, pool, n=1)[0]
    store.start_session('alice', store.get_desktop(desk['id']), 'vnc', '10.0.0.5')
    r = admin.post(f"/api/vlab/admin/desktops/{desk['id']}/reset")
    assert r.status_code == 409 and r.get_json()['code'] == 'IN_USE'
    assert not mgr.rollback_snapshot.called
    assert admin.post(f"/api/vlab/admin/desktops/{desk['id']}/reset", json={'force': True}).status_code == 200


def test_reset_needs_a_base_and_an_idle_vm(resettable):
    _, admin, mgr, pool = resettable
    mgr.create_snapshot.return_value = {'success': False, 'error': 'no snapshot support on this storage'}
    desk = _cloned_and_finished(admin, mgr, pool, n=1)[0]
    assert not desk['has_base']
    assert admin.post(f"/api/vlab/admin/desktops/{desk['id']}/reset").status_code == 409
    r = admin.post(f"/api/vlab/admin/desktops/{desk['id']}/base")
    assert r.status_code == 502 and 'snapshot support' in r.get_json()['error']


def test_pool_reset_reports_each_desktop(resettable):
    _, admin, mgr, pool = resettable
    desks = _cloned_and_finished(admin, mgr, pool, n=3)
    store.start_session('alice', store.get_desktop(desks[1]['id']), 'vnc', '10.0.0.5')
    mgr.rollback_snapshot.side_effect = [{'success': True}, {'success': False, 'error': 'VM is locked (backup)'}]
    body = admin.post(f"/api/vlab/admin/pools/{pool['id']}/reset").get_json()
    assert [d['name'] for d in body['reset']] == ['lab-b-01']
    assert [(d['name'], d['reason']) for d in body['skipped']] == [('lab-b-02', 'in_use')]
    assert [(d['name'], 'locked' in d['error']) for d in body['failed']] == [('lab-b-03', True)]


def test_users_cannot_reset_or_take_bases(resettable, seed):
    api, admin, mgr, pool = resettable
    desk = _cloned_and_finished(admin, mgr, pool, n=1)[0]
    alice = api.as_user(seed.user('alice', role='user'))
    assert alice.post(f"/api/vlab/admin/desktops/{desk['id']}/reset").status_code == 403
    assert alice.post(f"/api/vlab/admin/desktops/{desk['id']}/base").status_code == 403
    assert alice.post(f"/api/vlab/admin/pools/{pool['id']}/reset").status_code == 403
    assert not mgr.rollback_snapshot.called


# --- users and effective access ----------------------------------------------------

def test_the_user_list_counts_desktops_and_shows_disabled_on_request(env, seed):
    _, admin, alice, _, _ = env
    seed.user('gone', role='user', enabled=False)
    _, desk = _pool_with_desktop(admin)
    admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'})
    store.start_session('alice', store.get_desktop(desk['id']), 'vnc', '10.0.0.5')
    users = {u['username']: u for u in admin.get('/api/vlab/admin/users').get_json()['users']}
    assert users['alice']['desktops'] == 1 and users['alice']['last_connected']
    assert users['bob']['desktops'] == 0 and users['bob']['last_connected'] is None
    assert 'gone' not in users
    everyone = {u['username']: u for u in admin.get('/api/vlab/admin/users?all=1').get_json()['users']}
    assert everyone['gone']['enabled'] is False


def test_effective_access_tells_vlab_grants_from_direct_ones(env, seed):
    _, admin, _, _, _ = env
    seed.vm_acl(CID, 301, ['alice'])                       # given outside vLAB
    _, desk = _pool_with_desktop(admin)
    admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'})
    a = admin.get('/api/vlab/admin/users/alice/access').get_json()
    assert a['user']['portal'] is True
    assert [d['name'] for d in a['desktops']] == ['lab-win11-01']
    assert [(g['vmid'], g['source'], g['desktop']) for g in a['vm_acl']] == [(300, 'vlab', 'lab-win11-01'), (301, 'direct', None)]
    # unassigning takes the vLAB grant away; the direct one stays - which is what this screen is for
    admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': None})
    a = admin.get('/api/vlab/admin/users/alice/access').get_json()
    assert a['desktops'] == [] and [(g['vmid'], g['source']) for g in a['vm_acl']] == [(301, 'direct')]


def test_effective_access_of_a_viewer_says_no_portal(env):
    _, admin, _, _, _ = env
    assert admin.get('/api/vlab/admin/users/vera/access').get_json()['user']['portal'] is False


def test_effective_access_stays_inside_a_tenant(api, seed):
    mgr = api.make_fake_manager(CID, get_vm_resources=RES)
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    seed.tenant('acme', [CID])
    seed.user('acme_admin', role='admin', tenant_id='acme')
    seed.user('outsider', role='user')
    acme = api.as_user(seed.db.get_user('acme_admin') | {'username': 'acme_admin'})
    assert acme.get('/api/vlab/admin/users/outsider/access').status_code == 404
    assert acme.get('/api/vlab/admin/users/acme_admin/access').status_code == 200


def test_users_cannot_read_anyones_access(env):
    _, _, alice, _, _ = env
    assert alice.get('/api/vlab/admin/users/bob/access').status_code == 403
    assert alice.get('/api/vlab/admin/users/nobody/access').status_code == 403


# --- directory (AD / LDAP) -----------------------------------------------------------

def test_directory_defaults_and_masked_password(env):
    _, admin, _, _, _ = env
    d = admin.get('/api/vlab/admin/directory').get_json()['directory']
    assert d['ldap_enabled'] is False and d['ldap_port'] == 389 and d['ldap_bind_password'] == ''


def test_directory_is_saved_through_the_core_route(env):
    _, admin, _, _, _ = env
    from pegaprox.api.helpers import load_server_settings
    body = {'ldap_enabled': True, 'ldap_server': 'dc1.lab.example', 'ldap_port': 636, 'ldap_use_ssl': True,
            'ldap_bind_dn': 'CN=svc-vlab,OU=Service,DC=lab,DC=example', 'ldap_bind_password': 'bind-secret',
            'ldap_base_dn': 'DC=lab,DC=example', 'ldap_default_role': 'user', 'ldap_auto_create_users': True,
            'ldap_group_mappings': [{'group_dn': 'CN=vlab-admins,DC=lab,DC=example', 'role': 'admin'}]}
    r = admin.put('/api/vlab/admin/directory', json=body)
    assert r.status_code == 200, r.get_json()
    d = admin.get('/api/vlab/admin/directory').get_json()['directory']
    assert d['ldap_server'] == 'dc1.lab.example' and d['ldap_port'] == 636 and d['ldap_default_role'] == 'user'
    assert d['ldap_bind_password'] == '********'
    assert d['ldap_group_mappings'] == [{'group_dn': 'CN=vlab-admins,DC=lab,DC=example', 'role': 'admin'}]
    stored = load_server_settings()['ldap_bind_password']
    assert stored and stored != 'bind-secret'                      # encrypted by the core route
    # sending the mask back keeps the stored password
    assert admin.put('/api/vlab/admin/directory', json={'ldap_bind_password': '********'}).status_code == 200
    assert load_server_settings()['ldap_bind_password'] == stored


def test_directory_input_is_checked(env):
    _, admin, _, _, _ = env
    url = '/api/vlab/admin/directory'
    assert admin.put(url, json={'domain': 'x'}).status_code == 400                      # not a directory field
    assert admin.put(url, json={'ldap_port': '636'}).status_code == 400
    assert admin.put(url, json={'ldap_enabled': 'yes'}).status_code == 400
    assert admin.put(url, json={'ldap_group_mappings': [{'group_dn': 'CN=x'}]}).status_code == 400
    assert admin.post(url + '/test', json={'test_username': 5}).status_code == 400


def test_directory_test_goes_to_the_core_test(env, monkeypatch):
    _, admin, _, _, _ = env
    import pegaprox.api.settings as settings_api
    from flask import jsonify
    seen = {}

    def fake_test():
        from flask import request
        seen.update(request.get_json())
        return jsonify({'steps': [{'step': 'Server connection', 'status': 'ok'}]})
    monkeypatch.setattr(settings_api, 'test_ldap', fake_test)
    r = admin.post('/api/vlab/admin/directory/test', json={'ldap_server': 'dc1', 'test_username': 'alice'})
    assert r.status_code == 200 and r.get_json()['steps'][0]['status'] == 'ok'
    assert seen == {'ldap_server': 'dc1', 'test_username': 'alice'}


def test_users_cannot_touch_the_directory(env):
    _, _, alice, _, _ = env
    assert alice.get('/api/vlab/admin/directory').status_code == 403
    assert alice.put('/api/vlab/admin/directory', json={'ldap_enabled': True}).status_code == 403


# --- platform settings ---------------------------------------------------------------

def test_platform_settings_defaults(env):
    _, admin, _, _, _ = env
    s = admin.get('/api/vlab/admin/settings').get_json()['settings']
    assert (s['session_timeout'], s['login_max_attempts'], s['password_min_length']) == (28800, 5, 8)
    assert s['air_gap_mode'] is False and s['smtp_password'] == '' and s['alert_email_recipients'] == []


def test_platform_settings_are_saved_through_the_core_route(env):
    _, admin, _, _, _ = env
    from pegaprox.api.helpers import load_server_settings
    body = {'session_timeout': 3600, 'login_max_attempts': 3, 'password_min_length': 10,
            'password_require_special': True, 'audit_retention_days': 365, 'air_gap_mode': True,
            'smtp_enabled': True, 'smtp_host': 'mail.lab.example', 'smtp_password': 'mail-secret',
            'alert_email_recipients': ['ops@lab.example']}
    r = admin.put('/api/vlab/admin/settings', json=body)
    assert r.status_code == 200, r.get_json()
    s = admin.get('/api/vlab/admin/settings').get_json()['settings']
    assert {k: s[k] for k in body if k != 'smtp_password'} == {k: v for k, v in body.items() if k != 'smtp_password'}
    assert s['smtp_password'] == '********'
    stored = load_server_settings()['smtp_password']
    assert stored and stored != 'mail-secret'                       # encrypted by the core route
    assert admin.put('/api/vlab/admin/settings', json={'smtp_password': '********'}).status_code == 200
    assert load_server_settings()['smtp_password'] == stored
    # the core clamps to its ranges
    admin.put('/api/vlab/admin/settings', json={'session_timeout': 10, 'audit_retention_days': 1})
    s = admin.get('/api/vlab/admin/settings').get_json()['settings']
    assert (s['session_timeout'], s['audit_retention_days']) == (300, 30)


def test_platform_settings_input_is_checked(env):
    _, admin, _, _, _ = env
    url = '/api/vlab/admin/settings'
    assert admin.put(url, json={'port': 8443}).status_code == 400                       # not on this screen
    assert admin.put(url, json={'ldap_server': 'dc1'}).status_code == 400               # the directory's
    assert admin.put(url, json={'session_timeout': '3600'}).status_code == 400
    assert admin.put(url, json={'air_gap_mode': 1}).status_code == 400
    assert admin.put(url, json={'login_max_attempts': True}).status_code == 400
    assert admin.put(url, json={'alert_email_recipients': [1]}).status_code == 400
    assert admin.post(url + '/smtp-test', json={'smtp_host': 'mail'}).status_code == 400   # no email
    assert admin.post(url + '/smtp-test', json={'email': 'a@b', 'domain': 'x'}).status_code == 400


def test_smtp_test_goes_to_the_core_test(env, monkeypatch):
    _, admin, _, _, _ = env
    import pegaprox.api.realtime as realtime
    from flask import jsonify
    seen = {}

    def fake_test():
        from flask import request
        seen.update(request.get_json())
        return jsonify({'success': True})
    monkeypatch.setattr(realtime, 'test_smtp', fake_test)
    r = admin.post('/api/vlab/admin/settings/smtp-test', json={'email': 'ops@lab.example', 'smtp_host': 'mail'})
    assert r.status_code == 200 and r.get_json()['success'] is True
    assert seen == {'email': 'ops@lab.example', 'smtp_host': 'mail'}


def test_users_cannot_touch_platform_settings(env):
    _, _, alice, _, _ = env
    assert alice.get('/api/vlab/admin/settings').status_code == 403
    assert alice.put('/api/vlab/admin/settings', json={'air_gap_mode': True}).status_code == 403
    assert alice.post('/api/vlab/admin/settings/smtp-test', json={'email': 'a@b'}).status_code == 403


# --- system summary ------------------------------------------------------------------

def test_summary_counts_what_the_caller_can_reach(env):
    _, admin, _, _, _ = env
    pool, desk = _pool_with_desktop(admin)                       # 300: running
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': 301})   # stopped
    admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'})
    store.start_session('alice', store.get_desktop(desk['id']), 'vnc', '10.0.0.5')
    s = admin.get('/api/vlab/admin/summary').get_json()
    assert s['clusters'] == {'total': 1, 'connected': 1}
    assert s['pools'] == {'total': 1, 'by_type': {'reset': 1}}
    assert s['desktops']['total'] == 2 and s['desktops']['assigned'] == 1 and s['desktops']['in_session'] == 1
    assert s['desktops']['by_state'] == {'ready': 1, 'stopped': 1}
    assert s['users']['total'] >= 4 and s['sessions_today'] == 1
    assert s['versions']['engine'] and s['versions']['vlab_api'] == 1


def test_users_cannot_read_the_summary(env):
    _, _, alice, _, _ = env
    assert alice.get('/api/vlab/admin/summary').status_code == 403


# --- audit log -----------------------------------------------------------------------

def test_admin_reads_vlab_entries_of_the_audit_log(env):
    _, admin, _, _, _ = env
    from pegaprox.utils.audit import log_audit
    log_audit('root', 'cluster.added', 'Added Proxmox cluster: other')        # not vLAB's
    pool, desk = _pool_with_desktop(admin)                                    # vlab.pool.create, vlab.desktop.add
    admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'})
    every = admin.get('/api/vlab/admin/audit').get_json()
    mine = admin.get('/api/vlab/admin/audit?vlab_only=1').get_json()
    actions = [e['action'] for e in mine['entries']]
    assert 'vlab.desktop.assign' in actions and 'vlab.pool.create' in actions
    assert 'cluster.added' not in actions and 'cluster.added' in [e['action'] for e in every['entries']]
    assert mine['total'] == len(mine['entries'])
    page = admin.get('/api/vlab/admin/audit?vlab_only=1&limit=1').get_json()
    assert len(page['entries']) == 1 and page['has_more'] is True
    assert admin.get('/api/vlab/admin/audit?limit=x').status_code == 400


def test_only_admins_read_the_audit_log(env):
    _, _, alice, _, viewer = env
    assert alice.get('/api/vlab/admin/audit').status_code == 403
    assert viewer.get('/api/vlab/admin/audit').status_code == 403


# --- white label (the core's frontend branding, through the console's session) -------

PNG = b'\x89PNG\r\n\x1a\n' + b'\x00' * 16


@pytest.fixture
def branding(env, tmp_path, monkeypatch):
    import pegaprox.api.frontend_branding as fb
    monkeypatch.setattr(fb, 'BRANDING_DIR', str(tmp_path))
    return env


def test_white_label_is_saved_and_shown_to_everyone(branding):
    api, admin, alice, _, _ = branding
    assert api.anon().get('/api/vlab/branding').get_json()['appName'] == 'MOAVI Desk'     # defaults, no sign-in
    r = admin.put('/api/vlab/admin/branding', json={'enabled': True, 'appName': '연구소 VDI', 'primaryColor': 'e63946',
                                                    'footerText': '© 한빛연구원', 'docsUrl': 'javascript:alert(1)',
                                                    'logoUrl': 'http://evil/x.png', 'whatever': 1})
    assert r.status_code == 200, r.get_json()
    b = r.get_json()['branding']
    assert (b['appName'], b['primaryColor'], b['docsUrl'], b['logoUrl']) == ('연구소 VDI', '#e63946', '', '')   # cleaned by the core
    pub = api.anon().get('/api/vlab/branding').get_json()
    assert (pub['appName'], pub['footerText']) == ('연구소 VDI', '© 한빛연구원') and 'whatever' not in pub
    assert alice.put('/api/vlab/admin/branding', json={'appName': 'x'}).status_code == 403


def test_white_label_images(branding):
    import io as _io
    api, admin, _, _, _ = branding
    admin.put('/api/vlab/admin/branding', json={'enabled': True})
    up = lambda slot, data: admin.post('/api/vlab/admin/branding/image', data={'slot': slot, 'file': (_io.BytesIO(data), 'f')},
                                       content_type='multipart/form-data')
    assert up('logo', b'<svg onload=alert(1)>').status_code == 415                      # SVG refused (the core's rule)
    assert up('banner', PNG).status_code == 400
    r = up('logo', PNG)
    assert r.status_code == 200, r.get_json()
    url = api.anon().get('/api/vlab/branding').get_json()['logoUrl']
    assert url.startswith('/api/vlab/branding/image/default/logo.png')
    img = api.anon().get(url.split('?')[0])
    assert img.status_code == 200 and img.mimetype == 'image/png' and img.data == PNG
    assert api.anon().get('/api/vlab/branding/image/default/../../etc.png').status_code == 404
    assert admin.delete('/api/vlab/admin/branding/image/logo').status_code == 200
    assert api.anon().get('/api/vlab/branding').get_json()['logoUrl'] == ''


# --- backup (the core's backup routes, reached per desktop and pool) -----------------

@pytest.fixture
def backups(connectable, monkeypatch):
    import pegaprox.api.storage as core_storage
    import pegaprox.api.vms as core_vms
    from flask import jsonify, request
    calls = []

    def fake(name, answer=None):
        def f(*args):
            calls.append((name, args, request.get_json(silent=True)))
            return jsonify(answer if answer is not None else {'success': True, 'task': 'UPID:x'})
        return f
    monkeypatch.setattr(core_vms, 'get_vm_backups', fake('list', {'backups': [{'volid': 'pbs:backup/vm/300/2026-10-16T01:00:00Z'}]}))
    monkeypatch.setattr(core_vms, 'create_vm_backup', fake('create'))
    monkeypatch.setattr(core_vms, 'restore_vm_backup', fake('restore'))
    monkeypatch.setattr(core_vms, 'delete_vm_backup', fake('delete'))
    monkeypatch.setattr(core_storage, 'create_backup_job', fake('job'))
    monkeypatch.setattr(core_storage, 'get_backup_jobs', fake('jobs', [{'id': 'b1', 'comment': 'vlab-pool:x lab'}, {'id': 'b2'}]))
    return connectable, calls


def test_desktop_backups_go_to_the_core_routes(backups):
    (admin, alice, _, _, desk, _), calls = backups
    base = f"/api/vlab/admin/desktops/{desk['id']}/backups"
    assert admin.get(base).get_json()['backups'][0]['volid'].startswith('pbs:backup/vm/300/')
    assert admin.post(base, json={'storage': 'pbs-lab'}).status_code == 200
    assert admin.post(base, json={}).status_code == 400
    assert admin.post(base, json={'storage': 'pbs-lab', 'mode': 'yolo'}).status_code == 400
    assert [(c[0], c[1]) for c in calls] == [('list', (CID, 'pve1', 'qemu', 300)), ('create', (CID, 'pve1', 'qemu', 300))]
    assert alice.post(base, json={'storage': 'pbs-lab'}).status_code == 403


def test_a_restore_goes_back_into_the_same_desktop(backups):
    (admin, alice, _, _, desk, _), calls = backups
    url = f"/api/vlab/admin/desktops/{desk['id']}/backups/restore"
    store.set_base_snap(desk['id'], 'vlab-base')
    assert admin.post(url, json={'volid': 'pbs:backup/vm/999/2026-10-16T01:00:00Z'}).status_code == 400   # another VM's
    assert admin.post(url, json={'volid': 'pbs:backup/vm/300/x', 'target_vmid': 500}).status_code == 400  # elsewhere
    sid = alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'}).get_json()['session_id']
    r = admin.post(url, json={'volid': 'pbs:backup/vm/300/x'})
    assert r.status_code == 409 and r.get_json()['code'] == 'IN_USE'
    alice.post(f'/api/vlab/sessions/{sid}/end')
    assert admin.post(url, json={'volid': 'local:backup/vzdump-qemu-300-2026_10_16-01_00_00.vma.zst'}).status_code == 200
    assert calls[-1][0] == 'restore' and calls[-1][1] == (CID, 'pve1', 'qemu', 300)
    assert store.get_desktop(desk['id'])['base_snap'] == ''              # the snapshots went with the restore
    assert admin.delete(f"/api/vlab/admin/desktops/{desk['id']}/backups/pbs:backup/vm/999/x").status_code == 400


def test_pool_backup_jobs_name_the_pools_desktops(backups):
    (admin, _, _, _, desk, stopped), calls = backups
    url = f"/api/vlab/admin/pools/{desk['pool_id']}/backup/job"
    ok = {'vmid': '300', 'storage': 'pbs-lab', 'schedule': 'sun 02:00', 'comment': f"vlab-pool:{desk['pool_id']} lab"}
    assert admin.post(url, json={**ok, 'vmid': '300,999'}).status_code == 400          # not the pool's
    assert admin.post(url, json={**ok, 'all': 1}).status_code == 400
    assert admin.post(url, json={**ok, 'comment': 'nightly'}).status_code == 400
    assert admin.post(url, json=ok).status_code == 200
    assert calls[-1][0] == 'job' and calls[-1][1] == (CID,) and calls[-1][2]['vmid'] == '300'
    jobs = admin.get(f'/api/vlab/admin/clusters/{CID}/backup/jobs').get_json()['jobs']
    assert [(j['id'], j['vlab_pool_id']) for j in jobs] == [('b1', 'x'), ('b2', None)]


def test_backup_storages_put_pbs_first(env, monkeypatch):
    _, admin, _, _, _ = env
    import pegaprox.api.clusters as core_clusters
    monkeypatch.setattr(core_clusters, 'cluster_storage_resources', lambda cid, m: [
        {'storage': 'local', 'node': 'pve1', 'plugintype': 'dir', 'content': 'iso,backup', 'status': 'available', 'disk': 1, 'maxdisk': 9},
        {'storage': 'local-lvm', 'node': 'pve1', 'plugintype': 'lvmthin', 'content': 'images', 'status': 'available'},
        {'storage': 'pbs-lab', 'node': 'pve1', 'plugintype': 'pbs', 'shared': 1, 'content': 'backup', 'status': 'available'},
        {'storage': 'pbs-lab', 'node': 'pve2', 'plugintype': 'pbs', 'shared': 1, 'content': 'backup', 'status': 'available'}])
    s = admin.get(f'/api/vlab/admin/clusters/{CID}/backup/storages').get_json()['storages']
    assert [(x['storage'], x['pbs']) for x in s] == [('pbs-lab', True), ('local', False)]


# --- infrastructure dashboard (the core's metrics, health, storage and alerts) ------------

def test_infra_brings_the_core_figures_together(env, monkeypatch):
    _, admin, _, _, _ = env
    import time
    from flask import jsonify
    import pegaprox.api.alerts as core_alerts
    import pegaprox.api.clusters as core_clusters
    import pegaprox.api.helpers as helpers
    from pegaprox.globals import cluster_managers
    mgr = cluster_managers[CID]
    monkeypatch.setattr(type(mgr), 'is_connected', property(lambda self: True), raising=False)
    monkeypatch.setattr(mgr, 'get_node_status', lambda: {
        'pve1': {'status': 'online', 'cpu_percent': 41.5, 'mem_percent': 62.0, 'mem_used': 62, 'mem_total': 100,
                 'disk_percent': 10, 'uptime': 3600, 'netin': 1, 'netout': 2}}, raising=False)
    now = int(time.time()) - 600
    snap = lambda cpu: {CID: {'totals': {'cpu_used': cpu, 'cpu_total': 10, 'mem_used': 5, 'mem_total': 10,
                                         'vms_running': 3, 'cts_running': 1},
                              'nodes': {'pve1': {'cpu': cpu * 10, 'mem_percent': 50}}}}
    monkeypatch.setattr(helpers, 'load_metrics_window', lambda days: [(now - 300, snap(2)), (now, snap(4))])
    monkeypatch.setattr(core_clusters, 'cluster_storage_resources', lambda cid, m: [
        {'storage': 'ceph', 'node': 'pve1', 'shared': 1, 'plugintype': 'rbd', 'status': 'available', 'disk': 8, 'maxdisk': 10},
        {'storage': 'ceph', 'node': 'pve2', 'shared': 1, 'plugintype': 'rbd', 'status': 'available', 'disk': 8, 'maxdisk': 10},
        {'storage': 'local', 'node': 'pve1', 'plugintype': 'dir', 'status': 'available', 'disk': 1, 'maxdisk': 10}])
    monkeypatch.setattr(core_clusters, 'get_cluster_health', lambda cid: jsonify({'score': 88, 'band': 'good', 'issues': ['x']}))
    monkeypatch.setattr(core_alerts, 'get_active_alerts', lambda cid: jsonify({'active_alerts': [
        {'id': 1, 'severity': 'warning', 'message': 'CPU high', 'target_type': 'node', 'target_name': 'pve1'}]}))

    r = admin.get(f'/api/vlab/admin/clusters/{CID}/infra')
    assert r.status_code == 200
    d = r.get_json()
    assert d['range'] == '24h' and d['step'] == 300 and d['health']['score'] == 88
    assert d['nodes'][0]['name'] == 'pve1' and d['nodes'][0]['cpu_pct'] == 41.5
    assert [round(h['cpu_pct']) for h in d['history']] == [20, 40] and d['history'][0]['vms_running'] == 4
    assert [p['cpu'] for p in d['node_history']['pve1']] == [20, 40]
    assert [(s['storage'], s['node']) for s in d['storages']] == [('ceph', None), ('local', 'pve1')]
    assert d['alerts'][0]['message'] == 'CPU high'
    assert d['sessions'] and all(s['sessions'] == 0 for s in d['sessions'])
    assert admin.get(f'/api/vlab/admin/clusters/{CID}/infra?range=7d').get_json()['step'] == 3600
    assert admin.get(f'/api/vlab/admin/clusters/{CID}/infra?range=1y').status_code == 400
    assert admin.get('/api/vlab/admin/clusters/nope/infra').status_code == 404


# --- alerts (the core's rules, incidents, mutes and notification channels) ---------------

@pytest.fixture
def alerting(env, monkeypatch):
    import pegaprox.api.alerts as core_alerts
    from flask import jsonify, request
    calls = []

    def fake(name, answer=None):
        def f(*args):
            calls.append((name, args, request.get_json(silent=True)))
            return jsonify(answer if answer is not None else {'success': True})
        return f
    monkeypatch.setattr(core_alerts, 'get_cluster_alerts', fake('rules', {'alerts': [{'id': 'r1', 'metric': 'cpu'}]}))
    monkeypatch.setattr(core_alerts, 'get_active_alerts', fake('active', {'active_alerts': [{'id': 7, 'severity': 'critical'}]}))
    monkeypatch.setattr(core_alerts, 'list_alert_mutes', fake('mutes', {'mutes': [{'id': 'm1', 'rule_id': 'r1'}]}))
    for name in ('create_cluster_alert', 'update_cluster_alert', 'delete_cluster_alert', 'ack_active_alert',
                 'create_alert_mute', 'delete_alert_mute', 'create_alert_channel', 'update_alert_channel',
                 'delete_alert_channel', 'test_alert_channel'):
        monkeypatch.setattr(core_alerts, name, fake(name))
    monkeypatch.setattr(core_alerts, 'list_alert_channels', fake('channels', [{'id': 'c1', 'type': 'slack', 'url': '********'}]))
    return env, calls


def test_alerts_read_the_core_rules_incidents_and_mutes(alerting):
    (_, admin, alice, _, viewer), calls = alerting
    d = admin.get(f'/api/vlab/admin/clusters/{CID}/alerts').get_json()
    assert d == {'rules': [{'id': 'r1', 'metric': 'cpu'}], 'active': [{'id': 7, 'severity': 'critical'}],
                 'mutes': [{'id': 'm1', 'rule_id': 'r1'}]}
    assert [c[0] for c in calls] == ['rules', 'active', 'mutes']
    assert admin.get('/api/vlab/admin/clusters/nope/alerts').status_code == 404
    assert alice.get(f'/api/vlab/admin/clusters/{CID}/alerts').status_code == 403


def test_alert_writes_go_to_the_core_routes(alerting):
    (_, admin, alice, _, viewer), calls = alerting
    base = f'/api/vlab/admin/clusters/{CID}/alerts'
    rule = {'name': 'CPU', 'metric': 'cpu', 'operator': '>', 'threshold': 90, 'severity': 'warning'}
    assert admin.post(f'{base}/rules', json=rule).status_code == 200
    assert admin.put(f'{base}/rules/r1', json={'enabled': False}).status_code == 200
    assert admin.delete(f'{base}/rules/r1').status_code == 200
    assert admin.post(f'{base}/active/7/ack').status_code == 200
    assert admin.post(f'{base}/mutes', json={'minutes': 60, 'rule_id': 'r1'}).status_code == 200
    assert admin.delete(f'{base}/mutes/m1').status_code == 200
    assert [(c[0], c[1]) for c in calls] == [
        ('create_cluster_alert', (CID,)), ('update_cluster_alert', (CID, 'r1')), ('delete_cluster_alert', (CID, 'r1')),
        ('ack_active_alert', (CID, '7')), ('create_alert_mute', (CID,)), ('delete_alert_mute', (CID, 'm1'))]
    assert calls[0][2] == rule
    assert admin.post('/api/vlab/admin/clusters/nope/alerts/rules', json=rule).status_code == 404
    for client in (alice, viewer):
        assert client.post(f'{base}/rules', json=rule).status_code == 403
        assert client.post(f'{base}/active/7/ack').status_code == 403
    assert len(calls) == 6


def test_notification_channels_go_to_the_core_routes(alerting):
    (_, admin, alice, _, _), calls = alerting
    assert admin.get('/api/vlab/admin/alert-channels').get_json() == {
        'channels': [{'id': 'c1', 'type': 'slack', 'url': '********'}]}
    ch = {'name': 'ops', 'type': 'slack', 'url': 'https://hooks.slack.com/services/x'}
    assert admin.post('/api/vlab/admin/alert-channels', json=ch).status_code == 200
    assert admin.put('/api/vlab/admin/alert-channels/c1', json={'enabled': False}).status_code == 200
    assert admin.post('/api/vlab/admin/alert-channels/c1/test').status_code == 200
    assert admin.delete('/api/vlab/admin/alert-channels/c1').status_code == 200
    assert [(c[0], c[1]) for c in calls] == [('channels', ()), ('create_alert_channel', ()),
                                             ('update_alert_channel', ('c1',)), ('test_alert_channel', ('c1',)),
                                             ('delete_alert_channel', ('c1',))]
    assert alice.get('/api/vlab/admin/alert-channels').status_code == 403
    assert alice.post('/api/vlab/admin/alert-channels/c1/test').status_code == 403


def test_rightsizing_names_the_desktop_behind_each_vm(connectable, monkeypatch):
    admin, _alice, _, _, desk, _ = connectable
    from flask import jsonify, request
    import pegaprox.api.insights as core_insights
    seen = {}

    def fake(cid):
        seen['days'] = request.args.get('days')
        return jsonify({'snapshots_in_window': 300, 'min_samples_required': 24, 'total_vms': 3,
                        'summary': {'undersized_cpu': 1, 'oversized_mem': 1, 'idle': 0, 'ok': 1, 'no_data': 0},
                        'recommendations': [
                            {'vmid': str(desk['vmid']), 'name': 'x', 'flags': [{'kind': 'undersized_cpu'}, {'kind': 'oversized_mem'}]},
                            {'vmid': '999', 'name': 'other', 'flags': [{'kind': 'idle'}]}]})
    monkeypatch.setattr(core_insights, 'right_sizing', fake)
    d = admin.get(f'/api/vlab/admin/clusters/{CID}/rightsizing?days=30').get_json()
    assert seen['days'] == '30' and d['counts'] == {'grow': 1, 'reclaim': 1, 'idle': 0, 'ok': 1, 'no_data': 0}
    first, second = d['recommendations']
    assert first['desktop_id'] == desk['id'] and first['pool'] and first['actions'] == ['grow', 'reclaim']
    assert second['desktop'] is None and second['actions'] == ['idle']
    assert admin.get(f'/api/vlab/admin/clusters/{CID}/rightsizing?days=3').status_code == 400
    assert admin.get('/api/vlab/admin/clusters/nope/rightsizing').status_code == 404


# --- LABs: rooms, terminals, weekly schedules ----------------------------------------------

def test_lab_schedule_rules():
    from datetime import datetime
    from pegaprox.vlab import labs
    ok, e = labs.validate({'weekdays': [0, 2, 4], 'start_time': '09:00', 'end_time': '12:00', 'prepare_min': 15})
    assert e is None and ok['weekdays'] == '0,2,4' and ok['after'] == 'reset'
    assert labs.validate({'weekdays': [], 'start_time': '09:00', 'end_time': '12:00'})[1]
    assert labs.validate({'weekdays': [1], 'start_time': '12:00', 'end_time': '09:00'})[1]
    assert labs.validate({'weekdays': [1], 'start_time': '9:00', 'end_time': '12:00'})[1]
    assert labs.norm_mac('00-11-22-AA-bb-cc') == '00:11:22:aa:bb:cc' and labs.norm_mac('xyz') is None
    s = {'id': 's1', 'pool_id': 'p', 'weekdays': '0', 'start_time': '09:00', 'end_time': '12:00', 'prepare_min': 15,
         'after': 'reset', 'enabled': 1, 'last_prepared': '', 'last_finished': ''}
    mon = datetime(2026, 10, 12, 8, 50)                     # a Monday
    assert labs.due(s, mon) == 'prepare'
    assert labs.due({**s, 'last_prepared': '2026-10-12'}, mon) is None
    assert labs.due(s, mon.replace(hour=8, minute=40)) is None
    assert labs.due(s, mon.replace(hour=12, minute=5)) == 'finish'
    assert labs.due(s, mon.replace(hour=13, minute=30)) is None     # missed by more than an hour
    assert labs.due(s, datetime(2026, 10, 13, 9, 0)) is None         # Tuesday
    assert labs.overlaps(s, {**s, 'start_time': '11:00', 'end_time': '13:00'})
    assert not labs.overlaps(s, {**s, 'start_time': '12:00', 'end_time': '13:00'})
    assert not labs.overlaps(s, {**s, 'weekdays': '1'})
    cur, nxt = labs.state_at([s], mon.replace(hour=10))
    assert cur['schedule_id'] == 's1' and not cur['preparing'] and nxt['start'] == '2026-10-19T09:00'


def test_labs_terminals_and_schedules(connectable, monkeypatch):
    admin, alice, _, _, desk, stopped = connectable
    from datetime import datetime
    import pegaprox.api.vlab as vlab_api
    r = admin.post('/api/vlab/admin/labs', json={'name': '교육장 A', 'location': '3층', 'seats': 30})
    assert r.status_code == 201
    lab = r.get_json()['lab']
    assert admin.post('/api/vlab/admin/labs', json={'name': ''}).status_code == 400

    # a signed-in client on an unknown PC is not taken (PCs come in with an enrolment code,
    # test_vlab_enroll.py); an admin adds this one by its MAC and puts it in the room
    r = alice.post('/api/vlab/terminals/register', json={'mac': '00-11-22-33-44-55', 'name': 'PC-01'})
    assert r.get_json()['state'] == 'unknown'
    assert admin.get('/api/vlab/admin/terminals').get_json()['terminals'] == []
    t = admin.post('/api/vlab/admin/terminals', json={'mac': '00-11-22-33-44-55', 'name': 'PC-01'}).get_json()['terminal']
    r = admin.put(f"/api/vlab/admin/terminals/{t['id']}", json={'state': 'approved', 'lab_id': lab['id']})
    assert r.get_json()['terminal']['state'] == 'approved'
    assert alice.post('/api/vlab/terminals/register', json={'mac': '00:11:22:33:44:55'}).get_json()['lab']['name'] == '교육장 A'
    assert admin.post('/api/vlab/admin/terminals', json={'mac': '00:11:22:33:44:55'}).status_code == 409
    assert alice.get('/api/vlab/admin/terminals').status_code == 403

    pool_id = stopped['pool_id']
    body = {'lab_id': lab['id'], 'pool_id': pool_id, 'weekdays': [0], 'start_time': '09:00', 'end_time': '12:00',
            'prepare_min': 15, 'after': 'off', 'title': '파이썬 기초'}
    r = admin.post('/api/vlab/admin/lab-schedules', json=body)
    assert r.status_code == 201, r.get_json()
    sched = r.get_json()['schedule']
    r = admin.post('/api/vlab/admin/lab-schedules', json={**body, 'start_time': '11:00', 'end_time': '13:00'})
    assert r.status_code == 409 and r.get_json()['code'] == 'OVERLAP'
    (row,) = admin.get('/api/vlab/admin/lab-schedules').get_json()['schedules']
    assert row['weekdays'] == [0] and row['lab'] == '교육장 A' and row['pool']

    # the minute loop: before the session the stopped desktop is started, once
    from pegaprox.globals import cluster_managers
    mgr = cluster_managers[CID]
    mgr.vm_action.reset_mock()
    mon = datetime(2026, 10, 12, 8, 50)
    ((sid, phase, res),) = vlab_api.lab_tick(mon)
    assert (sid, phase) == (sched['id'], 'prepare') and [d['id'] for d in res['done']] == [stopped['id']]
    assert mgr.vm_action.call_args[0][3] == 'start'
    assert vlab_api.lab_tick(mon.replace(minute=55)) == []
    labs_now = admin.get('/api/vlab/admin/labs').get_json()['labs']
    assert labs_now[0]['terminals'] == 1 and labs_now[0]['schedules'] == 1

    # after it: a reset pool goes back to its base (stand-in) when the schedule says reset
    reset_calls = []
    monkeypatch.setattr(vlab_api, '_reset_one', lambda d: reset_calls.append(d['id']))
    assert admin.put(f"/api/vlab/admin/lab-schedules/{sched['id']}", json={**body, 'after': 'reset'}).status_code == 200
    store_desk = vlab_api.store.get_desktop(stopped['id'])
    vlab_api.store.set_base_snap(stopped['id'], 'vlab-base')
    ((_, phase, res),) = vlab_api.lab_tick(datetime(2026, 10, 12, 12, 5))
    assert phase == 'finish' and reset_calls == [stopped['id']] and store_desk

    r = admin.post(f"/api/vlab/admin/lab-schedules/{sched['id']}/run", json={'phase': 'prepare'})
    assert r.status_code == 200 and r.get_json()['phase'] == 'prepare'
    assert admin.delete(f"/api/vlab/admin/labs/{lab['id']}").status_code == 200
    assert admin.get('/api/vlab/admin/lab-schedules').get_json()['schedules'] == []
    assert admin.get('/api/vlab/admin/terminals').get_json()['terminals'][0]['lab_id'] is None


def test_kiosk_hands_out_a_desktop_of_the_session(connectable, api, monkeypatch):
    admin, alice, bob, _, desk, stopped = connectable
    import pegaprox.api.vlab as vlab_api
    from datetime import datetime
    lab = admin.post('/api/vlab/admin/labs', json={'name': '교육장 A'}).get_json()['lab']
    t = admin.post('/api/vlab/admin/terminals', json={'mac': '52:54:00:00:00:01', 'name': 'A-PC-01', 'lab_id': lab['id']}).get_json()['terminal']
    assert t['has_key'] is False and 'key_hash' not in t
    key = admin.post(f"/api/vlab/admin/terminals/{t['id']}/key").get_json()['key']
    hdr = {'X-Terminal-Key': key}

    assert api.anon().get('/api/vlab/kiosk', headers={'X-Terminal-Key': 'mdt_wrong'}).status_code == 401
    info = api.anon().get('/api/vlab/kiosk', headers=hdr).get_json()
    assert info['lab']['name'] == '교육장 A' and info['current'] is None

    # a classroom pool with one free desktop, in session now
    pool = admin.post('/api/vlab/admin/pools', json={'name': '수업용', 'type': 'classroom', 'cluster_id': CID}).get_json()['pool']
    free = admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': 301}).get_json()
    assert 'desktop' in free or free.get('error'), free
    now = datetime(2026, 10, 12, 10, 0)      # Monday
    monkeypatch.setattr(vlab_api, '_local_now', lambda: now)
    monkeypatch.setattr(vlab_api, '_acl_set', lambda *a: True)
    admin.post('/api/vlab/admin/lab-schedules', json={'lab_id': lab['id'], 'pool_id': pool['id'], 'weekdays': [0],
                                                      'start_time': '09:00', 'end_time': '12:00', 'prepare_min': 0, 'after': 'off'})
    assert alice.post('/api/vlab/kiosk/start', headers={'X-Terminal-Key': 'mdt_wrong'}).status_code == 401
    descs = vlab_api.store.list_desktops(pool['id'])
    if not descs:   # vmid 301 sits in another pool of the fixture: give the session pool its own
        vlab_api.store.add_desktop(vlab_api.store.get_pool(pool['id']), 'pve1', 310, 'class-01')
    r = alice.post('/api/vlab/kiosk/start', headers=hdr)
    assert r.status_code == 200, r.get_json()
    got = r.get_json()['desktop']
    assert vlab_api.store.get_desktop(got['id'])['assigned_user'] == 'alice'
    assert alice.post('/api/vlab/kiosk/start', headers=hdr).get_json()['desktop']['id'] == got['id']   # the same one again
    r = bob.post('/api/vlab/kiosk/start', headers=hdr)
    assert r.status_code == 409 and r.get_json()['code'] == 'FULL'
    # the clean-up after the session frees it
    vlab_api.lab_tick(datetime(2026, 10, 12, 12, 5))
    assert vlab_api.store.get_desktop(got['id'])['assigned_user'] is None


# --- MOAVI Desk Client ---------------------------------------------------------------------

def test_client_config_defaults_and_admin_settings(env):
    _, admin, alice, _, _ = env
    r = alice.get('/api/vlab/client/config')
    assert r.status_code == 200, r.get_json()
    c = r.get_json()
    assert c['product'] == 'MOAVI Desk' and c['protocol'] == 'auto' and c['min_version'] == ''
    assert c['support_url'].startswith('https://')

    assert alice.put('/api/vlab/admin/client', json={'protocol': 'vnc'}).status_code == 403
    r = admin.put('/api/vlab/admin/client', json={'latest_version': '1.0.0', 'min_version': '0.9.0',
                                                  'download_url': 'https://desk.example.com/MOAVI-Desk.msi', 'protocol': 'spice'})
    assert r.status_code == 200, r.get_json()
    c = alice.get('/api/vlab/client/config').get_json()
    assert (c['latest_version'], c['min_version'], c['protocol']) == ('1.0.0', '0.9.0', 'spice')
    assert admin.get('/api/vlab/admin/client').get_json()['client']['download_url'].endswith('.msi')


def test_client_settings_input_is_checked(env):
    _, admin, _, _, _ = env
    for body in ({'latest_version': 'one'}, {'protocol': 'guac'}, {'download_url': 'ftp://x'},
                 {'what': 1}, {'min_version': 9}):
        assert admin.put('/api/vlab/admin/client', json=body).status_code == 400, body

