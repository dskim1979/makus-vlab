"""MOAVI Desk work protection and accelerator use (pegaprox/api/vlab_work.py,
pegaprox/vlab/workload.py): a working desktop is not shut down or reset by the idle
shutdown, the session limit, a LAB / booking clean-up or a scheduled stop; GPU / NPU use is
sampled through the guest agent and shows in the card report; an idle loaned card is
suggested for a reclaim and, when asked, given back.
"""
from datetime import timedelta

import pytest

from pegaprox.api import vlab_work
from pegaprox.vlab import policy as pool_policy
from pegaprox.vlab import store
from pegaprox.vlab import workload as wl

CID = 'cluster_1'
RES = [
    {'vmid': 300, 'node': 'pve1', 'name': 'gpu-01', 'type': 'qemu', 'status': 'running', 'uptime': 7200},
    {'vmid': 301, 'node': 'pve1', 'name': 'gpu-02', 'type': 'qemu', 'status': 'stopped'},
]
NVIDIA_BUSY = '##nvidia\n0, NVIDIA A100-SXM4-40GB, 87, 30000, 40960\n##cpu\n16\n0.50 0.40 0.30 1/200 999\n'
NVIDIA_IDLE = '##nvidia\n0, NVIDIA A100-SXM4-40GB, 0, 10, 40960\n##cpu\n16\n0.10 0.10 0.10 1/200 999\n'


# --- what the guest prints ---------------------------------------------------------------

def test_the_probe_reads_every_vendor_it_finds():
    rocm = ('{"card0": {"GPU use (%)": "42", "VRAM Total Memory (B)": "68702699520", '
            '"VRAM Total Used Memory (B)": "1073741824", "Card series": "Instinct MI210"}}')
    rbln = ('+-----+----------+------+------+-------------------+------+\n'
            '| 0   | RBLN-CA22 | 45.0C | 60W | 1.2GiB / 16.0GiB | 33.5% |\n')
    furiosa = '{"devices": [{"arch": "rngd", "utilization": 12.5, "memory": {"used": 2048, "total": 49152}}]}'
    p = wl.parse_probe('##nvidia\n0, NVIDIA L40S, 55, 1000, 46068\n1, NVIDIA L40S, [N/A], 0, 46068\n'
                       f'##amd\n{rocm}\n##rebellions\n{rbln}\n##furiosa\n{furiosa}\n##cpu\n8\n4.00 3.00 2.00 1/2 3\n')
    by = {(c['vendor'], c['idx']): c for c in p['cards']}
    assert by[('nvidia', 0)]['util'] == 55 and by[('nvidia', 0)]['mem_total_mb'] == 46068
    assert by[('nvidia', 1)]['status'] == 'unavailable' and by[('nvidia', 1)]['util'] is None
    assert by[('amd', 0)]['util'] == 42 and by[('amd', 0)]['mem_used_mb'] == 1024 and by[('amd', 0)]['name'] == 'Instinct MI210'
    assert by[('rebellions', 0)]['util'] == 33.5 and by[('rebellions', 0)]['mem_total_mb'] == 16384
    assert by[('furiosa', 0)]['util'] == 12.5 and by[('furiosa', 0)]['mem_used_mb'] == 2048
    assert p['cpu_pct'] == 50.0 and p['tools'] == ['nvidia', 'amd', 'furiosa', 'rebellions']


def test_a_tool_that_prints_nothing_readable_is_unavailable_not_idle():
    p = wl.parse_probe('##rebellions\nsomething went wrong\n##wincpu\n12\n')
    assert p['cards'] == [dict(wl._card('rebellions', 0))] and p['cards'][0]['status'] == 'unavailable'
    assert p['cpu_pct'] == 12
    assert wl.parse_probe('##cpu\n4\n0.2 0.1 0.1 1/1 1\n') == {'cards': [], 'cpu_pct': 5.0, 'tools': []}


def test_busy_follows_the_pool_thresholds():
    pol = pool_policy.effective({})
    assert pol['defer_when_busy'] is True and pol['busy_gpu_pct'] == 10 and pol['defer_max_hours'] == 12
    assert wl.busy_from_probe(wl.parse_probe(NVIDIA_BUSY), pol)['kind'] == 'gpu'
    assert wl.busy_from_probe(wl.parse_probe(NVIDIA_IDLE), pol) is None
    cpu = wl.parse_probe('##cpu\n4\n3.6 1 1 1/1 1\n')
    assert wl.busy_from_probe(cpu, pol) == {'kind': 'cpu', 'value': 90.0, 'threshold': 50}
    assert wl.busy_from_probe(cpu, dict(pol, busy_cpu_pct=0)) is None


def test_the_policy_checks_the_new_fields():
    ok, e = pool_policy.validate({'defer_when_busy': False, 'busy_gpu_pct': 30, 'busy_cpu_pct': 0, 'defer_max_hours': 48}, 'reset')
    assert e is None and ok['defer_max_hours'] == 48
    for bad in ({'defer_when_busy': 'yes'}, {'busy_gpu_pct': 0}, {'defer_max_hours': 500}, {'busy_cpu_pct': 101}):
        assert pool_policy.validate(bad, 'reset')[1], bad


# --- the API -------------------------------------------------------------------------------

@pytest.fixture
def env(api, seed, monkeypatch):
    mgr = api.make_fake_manager(CID, get_vm_resources=[dict(r) for r in RES],
                                vm_action={'success': True, 'data': 'UPID:x'},
                                rollback_snapshot={'success': True, 'data': 'UPID:y'})
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    bob = api.as_user(seed.user('bob', role='user'))
    pool = admin.post('/api/vlab/admin/pools', json={'name': '딥러닝 랩', 'type': 'reset', 'cluster_id': CID}).get_json()['pool']
    desk = admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': 300}).get_json()['desktop']
    admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'})
    said = {'probe': NVIDIA_BUSY, 'mail': [], 'alerts': []}
    monkeypatch.setattr(vlab_work, '_probe', lambda d, vm: (wl.parse_probe(said['probe']), None) if said['probe'] else (None, 'no agent'))
    monkeypatch.setattr(vlab_work, '_mail', lambda user, title, text: said['mail'].append((user, title)))
    monkeypatch.setattr(vlab_work, '_admins', lambda title, text, data: said['alerts'].append(data['kind']))
    return {'api': api, 'mgr': mgr, 'admin': admin, 'alice': alice, 'bob': bob, 'pool': pool,
            'desk': store.get_desktop(desk['id']), 'said': said}


def test_an_idle_shutdown_waits_while_the_gpu_works_and_runs_once_it_stops(env):
    from pegaprox.api.vlab import policy_tick
    e = env
    e['admin'].put(f"/api/vlab/admin/pools/{e['pool']['id']}/policy", json={'idle_shutdown_min': 30, 'defer_max_hours': 2})
    now = wl.utcnow()
    e['mgr'].vm_action.reset_mock()
    assert policy_tick(now) == {'expired': 0, 'shutdown': 0, 'deferred': 1}
    assert e['mgr'].vm_action.call_count == 0
    waiting = wl.deferrals('waiting')
    assert [(d['action'], d['source'], d['username'], d['reason']['kind']) for d in waiting] == [('shutdown', 'idle', 'alice', 'gpu')]
    assert e['said']['mail'] == [('alice', '작업 중이라 미룸: gpu-01')] and e['said']['alerts'] == ['work_deferred']
    # asked again within 5 minutes: no new probe, still waiting
    e['said']['probe'] = NVIDIA_IDLE
    assert policy_tick(now + timedelta(minutes=2))['deferred'] == 1
    # past the recheck the GPU is idle: the shutdown runs
    assert policy_tick(now + timedelta(minutes=6)) == {'expired': 0, 'shutdown': 1, 'deferred': 0}
    assert e['mgr'].vm_action.call_args[0] == ('pve1', 300, 'qemu', 'shutdown')
    assert wl.deferrals('waiting') == [] and wl.deferrals('done')[0]['result'] == 'not working any more'


def test_the_longest_extension_ends_the_wait(env):
    from pegaprox.api.vlab import policy_tick
    e = env
    e['admin'].put(f"/api/vlab/admin/pools/{e['pool']['id']}/policy", json={'idle_shutdown_min': 30, 'defer_max_hours': 1})
    now = wl.utcnow()
    assert policy_tick(now)['deferred'] == 1
    assert policy_tick(now + timedelta(minutes=30))['deferred'] == 1      # still busy
    assert policy_tick(now + timedelta(minutes=61))['shutdown'] == 1      # an hour later it goes anyway
    assert wl.deferrals('forced')[0]['result'] == 'longest extension reached'
    assert ('alice', '최대 연장 시간 도달: gpu-01') in e['said']['mail']


def test_a_pool_that_does_not_defer_shuts_down_at_once(env):
    from pegaprox.api.vlab import policy_tick
    e = env
    e['admin'].put(f"/api/vlab/admin/pools/{e['pool']['id']}/policy", json={'idle_shutdown_min': 30, 'defer_when_busy': False})
    assert policy_tick(wl.utcnow()) == {'expired': 0, 'shutdown': 1, 'deferred': 0}


def test_the_session_limit_waits_for_a_working_desktop(env):
    from pegaprox.api.vlab import policy_tick
    e = env
    e['admin'].put(f"/api/vlab/admin/pools/{e['pool']['id']}/policy", json={'max_session_hours': 4})
    sid = store.start_session('alice', e['desk'], 'vnc', '10.0.0.1')
    later = wl.utcnow() + timedelta(hours=5)
    assert policy_tick(later)['deferred'] == 1
    assert store.get_session(sid)['ended_at'] is None
    e['said']['probe'] = NVIDIA_IDLE
    assert policy_tick(later + timedelta(minutes=6))['expired'] == 1


def test_the_users_hold_keeps_the_desktop_and_only_on_their_own_desktop(env):
    from pegaprox.api.vlab import policy_tick
    e = env
    e['said']['probe'] = NVIDIA_IDLE
    url = f"/api/vlab/me/desktops/{e['desk']['id']}/hold"
    assert e['bob'].post(url, json={'hours': 4}).status_code == 404
    assert e['alice'].post(url, json={'hours': 0}).status_code == 400
    assert e['alice'].post(url, json={'hours': 100}).status_code == 400          # over hold_max_hours (72)
    r = e['alice'].post(url, json={'hours': 4, 'note': 'ResNet 학습'})
    assert r.status_code == 200 and r.get_json()['hold']['note'] == 'ResNet 학습'
    mine = e['alice'].get('/api/vlab/me/work').get_json()
    assert mine['hold_max_hours'] == 72 and mine['desktops'][0]['hold']['note'] == 'ResNet 학습'
    assert e['alice'].get('/api/vlab/me/desktops').get_json()['desktops'][0]['work']['hold']['username'] == 'alice'
    e['admin'].put(f"/api/vlab/admin/pools/{e['pool']['id']}/policy", json={'idle_shutdown_min': 30})
    assert policy_tick(wl.utcnow())['deferred'] == 1
    assert wl.deferrals('waiting')[0]['reason']['kind'] == 'hold'
    assert e['alice'].delete(url).status_code == 200
    assert policy_tick(wl.utcnow() + timedelta(minutes=6))['shutdown'] == 1


def test_a_running_build_job_counts_as_working(env):
    from pegaprox.vlab import catalog
    e = env
    e['said']['probe'] = NVIDIA_IDLE
    job = catalog.add_build_job(e['pool']['id'], 'alice', 'synth top', 'make', '') if hasattr(catalog, 'add_build_job') else None
    if job is None:
        pytest.skip('no build job helper')
    catalog.update_build_job(job['id'], status='running', desktop_id=e['desk']['id'], pid=42)
    pol = pool_policy.effective(e['pool'].get('settings'))
    assert vlab_work.busy_reason(e['desk'], pol, RES[0])['kind'] == 'job'


def test_a_lab_clean_up_waits_and_the_minute_loop_runs_it_later(env):
    from pegaprox.api.vlab import _lab_phase
    e = env
    store.set_base_snap(e['desk']['id'], 'vlab-base')
    desk = store.get_desktop(e['desk']['id'])
    pool = store.get_pool(e['pool']['id'])
    result = _lab_phase({'id': 'sched_1'}, pool, 'finish', after='reset', desks=[desk])
    assert result['skipped'] == [{'id': desk['id'], 'name': 'gpu-01', 'reason': 'working'}]
    assert e['mgr'].rollback_snapshot.call_count == 0
    d = wl.deferrals('waiting')[0]
    assert (d['action'], d['source'], d['source_id']) == ('reset', 'lab', 'sched_1')
    now = wl.utcnow()
    assert vlab_work.deferral_tick(now + timedelta(minutes=1))['done'] == 0      # too soon to ask again
    assert vlab_work.deferral_tick(now + timedelta(minutes=6))['done'] == 0      # still working
    e['said']['probe'] = NVIDIA_IDLE
    assert vlab_work.deferral_tick(now + timedelta(minutes=12))['done'] == 1
    assert e['mgr'].rollback_snapshot.call_args[0] == ('pve1', 300, 'qemu', 'vlab-base')
    assert wl.deferrals('done')[0]['result'] == 'work finished'


def test_the_next_class_drops_what_the_last_one_put_off(env):
    from pegaprox.api.vlab import _lab_phase
    e = env
    pool = store.get_pool(e['pool']['id'])
    _lab_phase({'id': 'sched_1'}, pool, 'finish', after='off', desks=[e['desk']])
    assert len(wl.deferrals('waiting')) == 1
    _lab_phase({'id': 'sched_1'}, pool, 'prepare', desks=[e['desk']])
    assert wl.deferrals('waiting') == [] and wl.deferrals('dropped')[0]['result'] == 'the next session started'
    assert 'work_dropped' in e['said']['alerts']


def test_a_scheduled_shutdown_of_a_working_desktop_waits(env):
    e = env
    assert vlab_work.defer_scheduled(CID, 300, 'shutdown', 'sa_1') is True
    assert vlab_work.defer_scheduled(CID, 301, 'shutdown', 'sa_1') is False     # stopped
    assert vlab_work.defer_scheduled(CID, 999, 'shutdown', 'sa_1') is False     # no desktop
    e['said']['probe'] = NVIDIA_IDLE
    e['mgr'].vm_action.reset_mock()
    assert vlab_work.deferral_tick(wl.utcnow() + timedelta(minutes=6))['done'] == 1
    assert e['mgr'].vm_action.call_args[0] == ('pve1', 300, 'qemu', 'shutdown')


def test_admins_see_release_and_cancel_what_waits(env):
    e = env
    assert vlab_work.defer_scheduled(CID, 300, 'stop', 'sa_2') is True
    assert e['alice'].get('/api/vlab/admin/work').status_code == 403
    got = e['admin'].get('/api/vlab/admin/work').get_json()
    assert got['waiting'] == 1 and got['deferrals'][0]['desktop'] == 'gpu-01'
    did = got['deferrals'][0]['id']
    assert e['alice'].post(f'/api/vlab/admin/deferrals/{did}/release').status_code == 403
    assert e['admin'].post(f'/api/vlab/admin/deferrals/{did}/release').status_code == 200
    assert vlab_work.deferral_tick()['forced'] == 1                        # the deadline is now: it runs
    assert e['admin'].post(f'/api/vlab/admin/deferrals/{did}/cancel').status_code == 409
    vlab_work.defer_scheduled(CID, 300, 'stop', 'sa_3')
    did = wl.deferrals('waiting')[0]['id']
    assert e['admin'].post(f'/api/vlab/admin/deferrals/{did}/cancel').status_code == 200
    assert wl.get_deferral(did)['state'] == 'cancelled'
    assert e['admin'].post('/api/vlab/admin/deferrals/defer_nope/release').status_code == 404


def test_an_admin_takes_a_hold_off(env):
    e = env
    h = e['alice'].post(f"/api/vlab/me/desktops/{e['desk']['id']}/hold", json={'hours': 2}).get_json()['hold']
    assert e['admin'].get('/api/vlab/admin/work').get_json()['holds'][0]['desktop'] == 'gpu-01'
    assert e['bob'].delete(f"/api/vlab/admin/holds/{h['id']}").status_code == 403
    assert e['admin'].delete(f"/api/vlab/admin/holds/{h['id']}").status_code == 200
    assert wl.active_hold(e['desk']['id']) is None


# --- GPU / NPU use, the card report, reclaims ---------------------------------------------------

def _lend(hours_ago=30):
    start = wl.iso(wl.utcnow() - timedelta(hours=hours_ago))
    store.db().execute("INSERT INTO vlab_leases (id, resource_type, resource_id, resource_name, username, cluster_id, vmid, "
                       "starts_at, ends_at, state) VALUES ('lease_a', 'pci', 'a100', 'A100 #1', 'alice', ?, 300, ?, NULL, 'active')",
                       (CID, start))
    return store.get_lease('lease_a')


def test_samples_are_written_for_card_desktops_and_show_on_the_screens(env):
    e = env
    _lend()
    assert vlab_work.sample_now() == 1
    row = wl.samples(wl.iso(wl.utcnow() - timedelta(hours=1)))[0]
    assert (row['lease_id'], row['username'], row['vendor'], row['util'], row['card']) == ('lease_a', 'alice', 'nvidia', 87, 'A100 #1')
    leases = e['admin'].get('/api/vlab/admin/leases').get_json()['leases']
    assert leases[0]['use']['util'] == 87 and leases[0]['reclaim'] is None
    assert e['alice'].get('/api/vlab/me/leases').get_json()['leases'][0]['use']['util'] == 87
    desks = e['admin'].get('/api/vlab/admin/desktops').get_json()['desktops']
    assert desks[0]['work']['use']['vendor'] == 'nvidia'
    e['said']['probe'] = ''
    vlab_work.sample_now(wl.utcnow() + timedelta(minutes=5))
    assert wl.samples(wl.iso(wl.utcnow()))[-1]['status'] == 'no_agent'
    u = e['admin'].get(f"/api/vlab/admin/accel-usage?desktop_id={e['desk']['id']}").get_json()
    assert [p['util'] for p in u['series']] == [87, None] and u['summary']['util_avg'] == 87
    assert e['admin'].get('/api/vlab/admin/accel-usage').status_code == 400
    assert e['admin'].get('/api/vlab/admin/accel-usage?lease_id=nope').status_code == 404
    rep = e['admin'].get('/api/vlab/admin/reports/cards?days=7').get_json()
    card = rep['cards'][0]
    assert card['util_avg'] == 87 and card['measured_hours'] == round(5 / 60, 1) and rep['idle_threshold_pct'] == 5
    csv = e['admin'].get('/api/vlab/admin/reports/cards?days=7&format=csv').get_data(as_text=True)
    assert csv.splitlines()[0].endswith('util_avg,idle_hours,measured_hours,users,lent_now')


def test_a_stopped_desktop_holding_a_card_counts_as_idle(env):
    e = env
    e['admin'].post(f"/api/vlab/admin/pools/{e['pool']['id']}/desktops", json={'vmid': 301})
    store.db().execute("INSERT INTO vlab_leases (id, resource_type, resource_id, resource_name, username, cluster_id, vmid, "
                       "starts_at, state) VALUES ('lease_b', 'pci', 'a100', 'A100 #2', 'bob', ?, 301, ?, 'active')",
                       (CID, store.now()))
    vlab_work.sample_now()
    rows = wl.samples(wl.iso(wl.utcnow() - timedelta(minutes=1)), lease_id='lease_b')
    assert [r['status'] for r in rows] == ['off']
    assert wl.summarize(rows, 5)['idle_hours'] == round(5 / 60, 1)


def _idle_day(lease, util=1.0, hours=24, minutes=5):
    now = wl.utcnow()
    rows = []
    for i in range(int(hours * 60 / minutes)):
        rows.append({'at': wl.iso(now - timedelta(minutes=i * minutes)), 'minutes': minutes, 'cluster_id': CID, 'vmid': 300,
                     'desktop_id': '', 'username': lease['username'], 'lease_id': lease['id'], 'card': 'A100 #1',
                     'vendor': 'nvidia', 'idx': 0, 'name': 'A100', 'util': util, 'mem_used_mb': 10, 'mem_total_mb': 40960,
                     'status': 'ok'})
    wl.add_samples(rows)


def test_an_idle_loaned_card_is_suggested_then_dismissed(env):
    e = env
    lease = _lend()
    assert vlab_work.reclaim_tick() == {'suggested': 0, 'returned': 0, 'cleared': 0}    # no samples yet: unknown
    _idle_day(lease)
    assert vlab_work.reclaim_tick()['suggested'] == 1
    assert ('alice', '대여한 카드가 쓰이지 않고 있습니다: A100 #1') in e['said']['mail'] and 'card_reclaim' in e['said']['alerts']
    assert vlab_work.reclaim_tick()['suggested'] == 0                                  # once
    assert e['alice'].get('/api/vlab/admin/reclaims').status_code == 403
    got = e['admin'].get('/api/vlab/admin/reclaims').get_json()
    assert got['reclaims'][0]['card'] == 'A100 #1' and got['reclaims'][0]['summary']['util_avg'] == 1.0
    assert e['alice'].get('/api/vlab/me/leases').get_json()['leases'][0]['reclaim']['state'] == 'suggested'
    assert e['admin'].post('/api/vlab/admin/reclaims/lease_a/dismiss').status_code == 200
    assert wl.reclaim('lease_a')['state'] == 'dismissed'
    # used again: the suggestion goes
    wl.add_samples([{'at': wl.iso(wl.utcnow()), 'minutes': 5, 'cluster_id': CID, 'vmid': 300, 'desktop_id': '',
                     'username': 'alice', 'lease_id': 'lease_a', 'card': 'A100 #1', 'vendor': 'nvidia', 'idx': 0,
                     'name': '', 'util': 90, 'mem_used_mb': 0, 'mem_total_mb': 0, 'status': 'ok'}])
    assert vlab_work.reclaim_tick()['cleared'] == 1 and wl.reclaim('lease_a') is None


def test_an_idle_card_goes_back_by_itself_when_asked(env, monkeypatch):
    from pegaprox.api import vlab as core
    e = env
    monkeypatch.setattr(core, 'return_lease', lambda lease, by='system': store.close_lease(lease['id']))
    lease = _lend()
    _idle_day(lease)
    assert e['alice'].put('/api/vlab/admin/work-settings', json={'reclaim': {'auto_return': True}}).status_code == 403
    assert e['admin'].put('/api/vlab/admin/work-settings', json={'reclaim': {'auto_return': 'yes'}}).status_code == 400
    assert e['admin'].put('/api/vlab/admin/work-settings', json={'colour': 1}).status_code == 400
    r = e['admin'].put('/api/vlab/admin/work-settings', json={'reclaim': {'auto_return': True, 'auto_return_hours': 2}})
    assert r.status_code == 200 and r.get_json()['settings']['reclaim'] == {
        'enabled': True, 'idle_hours': 24, 'threshold_pct': 5, 'auto_return': True, 'auto_return_hours': 2}
    assert vlab_work.reclaim_tick()['suggested'] == 1
    assert vlab_work.reclaim_tick(wl.utcnow() + timedelta(hours=1))['returned'] == 0
    _idle_day(dict(lease), hours=3)        # samples keep coming in while it waits
    assert vlab_work.reclaim_tick(wl.utcnow() + timedelta(minutes=125))['returned'] == 1
    assert store.get_lease('lease_a')['state'] == 'returned'
    assert ('alice', '쓰이지 않던 카드를 반납했습니다: A100 #1') in e['said']['mail']


def test_a_hold_keeps_an_idle_card(env):
    e = env
    lease = _lend()
    _idle_day(lease)
    e['alice'].post(f"/api/vlab/me/desktops/{e['desk']['id']}/hold", json={'hours': 8})
    assert vlab_work.reclaim_tick()['suggested'] == 0


def test_samples_older_than_the_retention_go(env):
    _lend()
    old = wl.iso(wl.utcnow() - timedelta(days=100))
    wl.add_samples([{'at': old, 'minutes': 5, 'cluster_id': CID, 'vmid': 300, 'desktop_id': '', 'username': 'alice',
                     'lease_id': 'lease_a', 'card': '', 'vendor': '', 'idx': 0, 'name': '', 'util': 1,
                     'mem_used_mb': None, 'mem_total_mb': None, 'status': 'ok'}])
    vlab_work.sample_now()
    assert wl.samples(wl.iso(wl.utcnow() - timedelta(days=200)), until_iso=wl.iso(wl.utcnow() - timedelta(days=95))) == []
