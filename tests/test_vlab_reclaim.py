"""MOAVI Desk 자원 회수 (pegaprox/vlab/reclaim.py, pegaprox/api/vlab_reclaim.py): one list of
what can be taken back - unused assigned desktops, oversized VMs, long-stopped VMs, VMs in no
pool, old snapshots, idle card loans - with why, what it gives back and the recommended step;
an admin keeps an item out of it (제외) or applies one step, by the route that does it.
"""
import time
from datetime import datetime, timedelta, timezone

import pytest

from pegaprox.api import vlab_reclaim
from pegaprox.vlab import reclaim as rc
from pegaprox.vlab import store

CID = 'cluster_1'
GB = 1024 ** 3
AT = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)


def _vm(vmid, name, status='running', cpu=4, mem=8, disk=64, **kw):
    return dict(vmid=vmid, name=name, node='pve1', type='qemu', status=status, maxcpu=cpu, maxmem=mem * GB,
                maxdisk=disk * GB, **kw)


def _iso(days_ago):
    return (AT - timedelta(days=days_ago)).isoformat(timespec='seconds')


# --- the rules -------------------------------------------------------------------------------

def test_an_assigned_desktop_not_used_for_the_window_is_listed_with_its_seat():
    desks = [{'id': 'd1', 'pool_id': 'p', 'vmid': 101, 'name': 'desk-01', 'assigned_user': 'alice', 'created_at': _iso(90)},
             {'id': 'd2', 'pool_id': 'p', 'vmid': 102, 'name': 'desk-02', 'assigned_user': 'bob', 'created_at': _iso(90)},
             {'id': 'd3', 'pool_id': 'p', 'vmid': 103, 'name': 'desk-03', 'assigned_user': 'carol', 'created_at': _iso(3)},
             {'id': 'd4', 'pool_id': 'p', 'vmid': 104, 'name': 'desk-04', 'assigned_user': None, 'created_at': _iso(90)}]
    vms = {101: _vm(101, 'desk-01'), 102: _vm(102, 'desk-02'), 103: _vm(103, 'desk-03'), 104: _vm(104, 'desk-04')}
    seen = {('d1', 'alice'): _iso(45), ('d2', 'bob'): _iso(2)}
    items = rc.unused_desktops(CID, desks, vms, {'p': {'id': 'p', 'name': '실습'}}, seen, AT, 30)
    assert [i['desktop_id'] for i in items] == ['d1']          # bob used it, carol's is new, d4 has no user
    it = items[0]
    assert it['action']['id'] == 'unassign' and it['free'] == {'vcpu': 4, 'ram_gb': 8.0, 'disk_gb': 0.0, 'cards': 0, 'seats': 1}
    assert '45일' in it['reason'] and it['pool'] == '실습' and it['more'][0]['id'] == 'shutdown'


def test_a_desktop_never_connected_to_since_it_was_made_counts_too():
    desks = [{'id': 'd1', 'pool_id': 'p', 'vmid': 101, 'name': 'desk-01', 'assigned_user': 'alice', 'created_at': _iso(40)}]
    items = rc.unused_desktops(CID, desks, {101: _vm(101, 'desk-01', status='stopped')}, {}, {}, AT, 30)
    assert items[0]['reason'] == 'alice 님이 한 번도 접속 안 함'
    assert items[0]['free']['vcpu'] == 0 and items[0]['free']['seats'] == 1     # off: nothing running to give back


def test_right_sizing_gives_the_difference_and_an_idle_running_vm_its_whole_size():
    recs = [{'vmid': '201', 'cpu_avg': 2.0, 'cpu_p95': 10, 'mem_avg': 15, 'mem_max': 30,
             'flags': [{'kind': 'oversized_cpu', 'current': 8, 'recommended': 4},
                       {'kind': 'oversized_mem', 'current_gb': 16.0, 'recommended_gb': 8.0}]},
            {'vmid': '202', 'cpu_avg': 0.2, 'cpu_p95': 1, 'flags': [{'kind': 'idle'}]},
            {'vmid': '203', 'cpu_avg': 70, 'cpu_p95': 95, 'flags': [{'kind': 'undersized_cpu'}]},
            {'vmid': '204', 'cpu_avg': 0.2, 'cpu_p95': 1, 'flags': [{'kind': 'idle'}]}]
    vms = {201: _vm(201, 'big', cpu=8, mem=16), 202: _vm(202, 'idle', cpu=2, mem=4),
           203: _vm(203, 'busy'), 204: _vm(204, 'off', status='stopped')}
    items = {i['vmid']: i for i in rc.oversized(CID, recs, vms, {}, {})}
    assert set(items) == {201, 202}                       # growing is not a reclaim; an idle VM that is off frees nothing
    assert items[201]['action'] == {'id': 'resize', 'label': '크기 줄이기', 'destructive': False,
                                    'params': {'cores': 4, 'memory_mb': 8192}}
    assert items[201]['free']['vcpu'] == 4 and items[201]['free']['ram_gb'] == 8.0
    assert items[202]['action']['id'] == 'shutdown' and items[202]['free']['vcpu'] == 2


def test_a_long_stopped_vm_is_listed_only_when_the_history_reaches_back_that_far():
    vms = {301: _vm(301, 'old', status='stopped', disk=100), 302: _vm(302, 'recent', status='stopped'),
           303: _vm(303, 'tpl', status='stopped', template=1), 304: _vm(304, 'on')}
    hist = [((AT - timedelta(days=40)).timestamp(), {'vms': {'302': {'r': 1}, '304': {'r': 1}}}),
            ((AT - timedelta(days=5)).timestamp(), {'vms': {'302': {'r': 1}, '304': {'r': 1}}})]
    ran, first = rc.last_running(hist)
    items = rc.stopped_vms(CID, vms, {}, {}, set(), ran, first, AT, 30)
    assert [i['vmid'] for i in items] == [301]
    it = items[0]
    assert it['free']['disk_gb'] == 100.0 and it['action']['id'] == 'delete_vm' and it['action']['destructive']
    assert it['action']['params'] == {'confirm': 'old'} and it['reason'].startswith('풀 밖 · 40일 넘게 꺼짐')
    short = [((AT - timedelta(days=10)).timestamp(), {'vms': {}})]
    assert rc.stopped_vms(CID, vms, {}, {}, set(), *rc.last_running(short), AT, 30) == []


def test_a_vm_in_no_pool_and_not_used_by_moavi_desk_is_an_orphan():
    vms = {401: _vm(401, 'stray'), 402: _vm(402, 'golden', status='stopped'), 403: _vm(403, 'tpl', template=1),
           404: _vm(404, 'desk'), 405: _vm(405, 'listed-as-stopped', status='stopped')}
    items = rc.orphans(CID, vms, {404: {'id': 'd'}}, {402}, {405})
    assert [i['vmid'] for i in items] == [401]
    it = items[0]
    assert it['action']['id'] == 'review' and [a['id'] for a in it['more']] == ['shutdown', 'delete_vm']
    assert it['free'] == {'vcpu': 4, 'ram_gb': 8.0, 'disk_gb': 64.0, 'cards': 0, 'seats': 0}


def test_old_snapshots_but_never_the_base_one():
    snaps = {501: [{'name': 'before-update', 'snaptime': (AT - timedelta(days=50)).timestamp(), 'vmstate': 1},
                   {'name': 'vlab-base', 'snaptime': (AT - timedelta(days=200)).timestamp()},
                   {'name': 'golden', 'snaptime': (AT - timedelta(days=200)).timestamp()},
                   {'name': 'yesterday', 'snaptime': (AT - timedelta(days=1)).timestamp()},
                   {'name': 'current'}]}
    desk = {'id': 'd', 'pool_id': 'p', 'vmid': 501, 'name': 'desk-05', 'base_snap': 'golden'}
    items = rc.old_snapshots(CID, snaps, {501: _vm(501, 'desk-05')}, {501: desk}, {}, AT, 30)
    assert [i['snapshot'] for i in items] == ['before-update']
    assert items[0]['key'] == 'snapshot:cluster_1:501:before-update'
    assert items[0]['action']['params'] == {'confirm': 'before-update'} and '메모리 포함' in items[0]['reason']


def test_totals_count_a_vm_once_and_say_how_many_more_desktops_fit():
    a = {'key': 'unused:c:1', 'kind': 'unused', 'cluster_id': 'c', 'vmid': 1, 'exempt': False,
         'free': rc._free(4, 8, 0, seats=1)}
    b = {'key': 'oversized:c:1', 'kind': 'oversized', 'cluster_id': 'c', 'vmid': 1, 'exempt': False,
         'free': rc._free(2, 4)}
    c = {'key': 'stopped:c:2', 'kind': 'stopped', 'cluster_id': 'c', 'vmid': 2, 'exempt': False,
         'free': rc._free(disk_gb=100)}
    d = {'key': 'loan:c:L', 'kind': 'loan', 'cluster_id': 'c', 'vmid': 3, 'lease_id': 'L', 'exempt': False,
         'free': rc._free(cards=1)}
    e = {'key': 'orphan:c:9', 'kind': 'orphan', 'cluster_id': 'c', 'vmid': 9, 'exempt': True,
         'free': rc._free(16, 64, 500)}
    t = rc.totals([a, b, c, d, e], {'vcpu': 2, 'ram_gb': 4})
    assert (t['vcpu'], t['ram_gb'], t['disk_gb'], t['cards'], t['seats']) == (4, 8.0, 100.0, 1, 1)
    assert t['more_desktops'] == 2 and t['items'] == 4
    assert rc.counts([a, b, c, d, e]) == {'unused': 1, 'oversized': 1, 'stopped': 1, 'orphan': 0, 'snapshot': 0, 'loan': 1}


def test_the_typical_spec_is_the_median_of_the_desktops():
    desks = [{'vmid': i} for i in (1, 2, 3)]
    vms = {1: _vm(1, 'a', cpu=2, mem=4), 2: _vm(2, 'b', cpu=4, mem=8), 3: _vm(3, 'c', cpu=8, mem=16)}
    assert rc.typical_spec(desks, vms) == {'vcpu': 4, 'ram_gb': 8.0, 'disk_gb': 64.0, 'from_desktops': 3}
    assert rc.typical_spec([], {})['vcpu'] == rc.FALLBACK_SPEC['vcpu']


def test_the_weekly_summary_is_due_once_a_week_from_its_hour():
    s = rc.effective_settings({'weekly': True, 'weekday': 0, 'hour': 9})
    monday9 = datetime(2026, 11, 30, 9, 5).astimezone()
    assert rc.weekly_due(s, None, monday9)
    assert not rc.weekly_due(s, None, monday9.replace(hour=8))
    assert not rc.weekly_due(s, monday9.isoformat(), monday9 + timedelta(hours=3))
    assert rc.weekly_due(s, (monday9 - timedelta(days=7)).isoformat(), monday9)
    assert not rc.weekly_due(dict(s, weekly=False), None, monday9)
    with pytest.raises(ValueError):
        rc.validate_settings({'days': 45})


# --- the routes ------------------------------------------------------------------------------

RES = [_vm(101, 'desk-01'), _vm(102, 'desk-02'), _vm(401, 'stray'),
       _vm(301, 'old-build', status='stopped', disk=120), _vm(900, 'tpl', status='stopped', template=1)]


@pytest.fixture
def env(api, seed, monkeypatch):
    mgr = api.make_fake_manager(CID, get_vm_resources=[dict(r) for r in RES],
                                vm_action={'success': True, 'data': 'UPID:x'},
                                delete_vm={'success': True}, delete_snapshot={'success': True},
                                update_vm_config={'success': True},
                                get_snapshots=[{'name': 'old-one', 'snaptime': time.time() - 60 * 86400}])
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    seed.user('alice', role='user')
    pool = admin.post('/api/vlab/admin/pools', json={'name': '실습', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    d1 = admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': 101}).get_json()['desktop']
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': 102})
    admin.put(f"/api/vlab/admin/desktops/{d1['id']}/assign", json={'username': 'alice'})
    store.db().execute('UPDATE vlab_desktops SET created_at = ? WHERE id = ?',
                       ((datetime.now(timezone.utc) - timedelta(days=60)).isoformat(timespec='seconds'), d1['id']))
    now = time.time()
    hist = [(now - 40 * 86400, {'vms': {'101': {'r': 1}, '102': {'r': 1}, '401': {'r': 1}}}),
            (now - 60, {'vms': {'101': {'r': 1}, '102': {'r': 1}, '401': {'r': 1}}})]
    monkeypatch.setattr(vlab_reclaim, '_history', lambda cid, days: hist)
    monkeypatch.setattr(vlab_reclaim, '_rightsizing', lambda cid: ([], True))
    vlab_reclaim._snap_cache.clear()
    return {'api': api, 'mgr': mgr, 'admin': admin, 'pool': pool, 'd1': store.get_desktop(d1['id'])}


def _report(e, **q):
    r = e['admin'].get('/api/vlab/admin/reclaim', query_string=q)
    assert r.status_code == 200, r.get_json()
    return r.get_json()


def test_the_report_lists_every_kind_it_finds_with_totals(env):
    rep = _report(env)
    kinds = {(i['kind'], i['vmid']) for i in rep['items']}
    assert ('unused', 101) in kinds and ('stopped', 301) in kinds and ('orphan', 401) in kinds
    assert ('snapshot', 101) in kinds and not any(i['vmid'] == 900 for i in rep['items'])     # no template
    assert ('orphan', 301) not in kinds                         # a long-stopped orphan is listed once
    assert rep['totals']['disk_gb'] >= 120 and rep['totals']['seats'] == 1
    assert rep['spec']['vcpu'] == 4 and rep['pools'] == [{'id': env['pool']['id'], 'name': '실습'}]
    assert env['admin'].get('/api/vlab/admin/reclaim?days=45').status_code == 400


def test_an_exempt_item_leaves_the_list_and_the_totals_until_taken_off(env):
    e = env
    key = f'orphan:{CID}:401'
    before = _report(e)['totals']['vcpu']
    assert e['admin'].post('/api/vlab/admin/reclaim/exempt', json={'key': key, 'target': 'stray', 'note': '빌드 서버'}).status_code == 200
    rep = _report(e)
    assert key not in {i['key'] for i in rep['items']} and rep['exempt_count'] == 1 and rep['totals']['vcpu'] < before
    assert any(i['key'] == key and i['exempt'] for i in _report(e, exempt=1)['items'])
    assert e['admin'].post('/api/vlab/admin/reclaim/exempt', json={'key': 'nonsense'}).status_code == 400
    assert e['admin'].delete('/api/vlab/admin/reclaim/exempt', query_string={'key': key}).status_code == 200
    assert key in {i['key'] for i in _report(e)['items']}


def test_applying_unassign_goes_through_the_assign_route_and_is_audited(env, monkeypatch):
    e = env
    seen = []
    from pegaprox.api import vlab_reclaim as mod
    monkeypatch.setattr(mod, 'log_audit', lambda user, action, detail, ip=None: seen.append(action))
    r = e['admin'].post('/api/vlab/admin/reclaim/apply',
                        json={'key': f"unused:{CID}:101", 'action': 'unassign', 'desktop_id': e['d1']['id']})
    assert r.status_code == 200, r.get_json()
    assert store.get_desktop(e['d1']['id'])['assigned_user'] is None
    assert seen == ['vlab.reclaim.apply']
    again = e['admin'].post('/api/vlab/admin/reclaim/apply',
                            json={'key': f"unused:{CID}:101", 'action': 'unassign', 'desktop_id': e['d1']['id']})
    assert again.status_code == 409


def test_a_delete_needs_the_name_typed_and_a_vm_that_is_off(env):
    e = env
    body = {'key': f'stopped:{CID}:301', 'action': 'delete_vm', 'cluster_id': CID, 'vmid': 301}
    r = e['admin'].post('/api/vlab/admin/reclaim/apply', json=dict(body, confirm_name='wrong'))
    assert r.status_code == 400 and r.get_json()['code'] == 'CONFIRM'
    e['mgr'].delete_vm.assert_not_called()
    r = e['admin'].post('/api/vlab/admin/reclaim/apply', json=dict(body, confirm_name='old-build'))
    assert r.status_code == 200, r.get_json()
    e['mgr'].delete_vm.assert_called_once_with('pve1', 301, 'qemu', purge=True)
    on = {'key': f'orphan:{CID}:401', 'action': 'delete_vm', 'cluster_id': CID, 'vmid': 401, 'confirm_name': 'stray'}
    r = e['admin'].post('/api/vlab/admin/reclaim/apply', json=on)
    assert r.status_code == 409 and r.get_json()['code'] == 'VM_RUNNING'
    desk_vm = {'key': f'orphan:{CID}:101', 'action': 'delete_vm', 'cluster_id': CID, 'vmid': 101, 'confirm_name': 'desk-01'}
    assert e['admin'].post('/api/vlab/admin/reclaim/apply', json=desk_vm).status_code == 409     # a desktop goes by desktop_id


def test_a_snapshot_delete_types_its_name_and_resize_writes_the_config(env):
    e = env
    snap = {'key': f'snapshot:{CID}:401:old-one', 'action': 'delete_snapshot', 'cluster_id': CID, 'vmid': 401,
            'snapshot': 'old-one'}
    assert e['admin'].post('/api/vlab/admin/reclaim/apply', json=snap).status_code == 400
    assert e['admin'].post('/api/vlab/admin/reclaim/apply', json=dict(snap, confirm_name='old-one')).status_code == 200
    e['mgr'].delete_snapshot.assert_called_once_with('pve1', 401, 'qemu', 'old-one')
    rs = {'key': f'oversized:{CID}:401', 'action': 'resize', 'cluster_id': CID, 'vmid': 401, 'cores': 2, 'memory_mb': 4096}
    assert e['admin'].post('/api/vlab/admin/reclaim/apply', json=rs).status_code == 200
    e['mgr'].update_vm_config.assert_called_once_with('pve1', 401, 'qemu', {'cores': 2, 'memory': 4096})
    assert e['admin'].post('/api/vlab/admin/reclaim/apply', json=dict(rs, action='review')).status_code == 400


def test_a_user_cannot_read_or_apply(env, seed):
    bob = env['api'].as_user(seed.user('bob', role='user'))
    assert bob.get('/api/vlab/admin/reclaim').status_code == 403
    assert bob.post('/api/vlab/admin/reclaim/apply', json={'key': 'orphan:x:1', 'action': 'shutdown'}).status_code == 403


def test_the_weekly_summary_goes_once_and_only_when_turned_on(env, monkeypatch):
    sent = []
    from pegaprox.api import vlab_ops_notices
    monkeypatch.setattr(vlab_ops_notices, '_send', lambda title, text, data, s=None: sent.append((title, text)))
    monday = datetime(2026, 11, 30, 10, 0)
    assert vlab_reclaim.reclaim_tick(monday) is False
    assert env['admin'].put('/api/vlab/admin/reclaim/settings', json={'weekly': True, 'weekday': 0, 'hour': 9}).status_code == 200
    assert vlab_reclaim.reclaim_tick(monday) is True and len(sent) == 1
    assert '자원 회수 주간 요약' in sent[0][0] and '운영 > 자원 회수' in sent[0][1]
    assert vlab_reclaim.reclaim_tick(monday + timedelta(hours=1)) is False and len(sent) == 1
