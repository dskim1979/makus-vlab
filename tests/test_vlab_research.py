"""MOAVI Desk for AI · GPU research (pegaprox/vlab/research.py, pegaprox/api/vlab_research.py):
GPU jobs on the build farm with quotas and a fair queue, the GPU-hours report, web IDEs behind
vlab-proxy, and who may reach each route."""
from datetime import timedelta

import pytest

from pegaprox.vlab import catalog, research, store

CID = 'cluster_1'
GB = 1024 ** 3
RES = [
    {'vmid': 700, 'node': 'pve1', 'name': 'gpu-build-01', 'type': 'qemu', 'status': 'running', 'maxmem': 256 * GB},
    {'vmid': 701, 'node': 'pve2', 'name': 'gpu-build-02', 'type': 'qemu', 'status': 'running', 'maxmem': 256 * GB},
    {'vmid': 710, 'node': 'pve1', 'name': 'ws-alice', 'type': 'qemu', 'status': 'running', 'maxmem': 64 * GB},
]


class _Resp:
    def __init__(self, data, status=200):
        self.status_code, self._data, self.text = status, data, ''

    def json(self):
        return {'data': self._data}


class Agent:
    """The guest agents of the fake cluster: every exec gets a pid, exec-status says what
    `done` holds for it (still running otherwise), get-osinfo answers `os`."""
    def __init__(self):
        self.calls, self.done, self.os, self.next = [], {}, 'ubuntu', 5000

    def post(self, url, data=None, **kw):
        self.next += 1
        self.calls.append((url, data, self.next))
        return _Resp({'pid': self.next})

    def get(self, url, params=None, **kw):
        if url.endswith('get-osinfo'):
            return _Resp({'result': {'id': self.os}})
        return _Resp(self.done.get(int((params or {}).get('pid') or 0), {'exited': 0}))

    def scripts(self):
        return [(c[1]['command'], c[1].get('input-data'), c[2]) for c in self.calls]


@pytest.fixture
def env(api, seed, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    mgr = api.make_fake_manager(CID, get_vm_resources=RES, update_vm_config={'success': True})
    mgr.is_connected = True
    agent = Agent()
    mgr._api_post.side_effect = agent.post
    mgr._api_get.side_effect = agent.get
    api.set_manager(CID, mgr)
    monkeypatch.setattr(nxt, '_guest_ipv4', lambda m, n, v: f'10.0.0.{int(v) % 256}')
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    bob = api.as_user(seed.user('bob', role='user'))
    viewer = api.as_user(seed.user('vera', role='viewer'))
    return api, mgr, agent, admin, alice, bob, viewer


def _gpu_farm(admin, gpus_per_vm=4, kind='A100', users=('alice', 'bob')):
    pool = store.create_pool('GPU 학습 팜', 'buildfarm', CID)
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/grants",
                     json={'grants': [{'subject_type': 'user', 'subject_id': u} for u in users]}).status_code == 200
    r = admin.put(f"/api/vlab/admin/pools/{pool['id']}/gpu-jobs", json={'gpus_per_vm': gpus_per_vm, 'kind': kind})
    assert r.status_code == 200, r.get_json()
    for vmid, name in ((700, 'gpu-build-01'), (701, 'gpu-build-02')):
        store.add_desktop(store.get_pool(pool['id']), 'pve1', vmid, name)
    return pool


def _job(c, **kw):
    body = {'name': kw.pop('name', 'train'), 'command': kw.pop('command', 'python train.py'), 'gpus': kw.pop('gpus', 1)}
    body.update(kw)
    return c.post('/api/vlab/me/build-jobs', json=body)


# --- the queue, pure -----------------------------------------------------------------------

def _vm(i, gpus=4, mem=0, **kw):
    return dict({'desktop_id': f'd{i}', 'pool_id': 'p', 'gpus': gpus, 'mem_gb': mem, 'used': set(), 'mem_used': 0,
                 'cpu_job': False, 'busy': False}, **kw)


def _q(jid, user, gpus=1, at='2026-10-16T09:00:00+00:00', **kw):
    return dict({'id': jid, 'username': user, 'gpus': gpus, 'created_at': at, 'candidates': ['p'], 'memory_gb': 0}, **kw)


def test_the_queue_is_fair_and_packs_gpus():
    none = lambda j: []   # noqa: E731
    jobs = [_q('a1', 'alice', 2, '2026-10-16T09:00:00+00:00'), _q('a2', 'alice', 2, '2026-10-16T09:01:00+00:00'),
            _q('b1', 'bob', 2, '2026-10-16T09:05:00+00:00')]
    placed, why, order = research.plan(jobs, [_vm(1)], {}, none)
    # each user's first job before anyone's second: bob's goes ahead of alice's second
    assert order == ['a1', 'b1', 'a2']
    assert [(j['id'], idx) for j, _, idx in placed] == [('a1', [0, 1]), ('b1', [2, 3])]
    assert why == {'a2': 'no_free_gpu'}
    # best fit: a 1-GPU job goes where it leaves the fewest GPUs over, the 4-GPU VM stays whole
    placed, _, _ = research.plan([_q('x', 'alice', 1)], [_vm(1, 4), _vm(2, 4, used={0, 1, 2})], {}, none)
    assert placed[0][1]['desktop_id'] == 'd2' and placed[0][2] == [3]
    # memory: a VM without room for it is passed over
    placed, why, _ = research.plan([_q('m', 'alice', 1, memory_gb=200)], [_vm(1, 4, mem=128)], {}, none)
    assert placed == [] and why == {'m': 'no_free_gpu'}
    # a plain build takes a whole free VM and none that holds GPU jobs
    placed, why, _ = research.plan([_q('c', 'alice', 0)], [_vm(1, used={0}), _vm(2)], {}, none)
    assert placed[0][1]['desktop_id'] == 'd2'


def test_quotas_hold_and_push_back():
    q = {'max_gpus': 2, 'monthly_gpu_hours': 10, 'hard': False}
    quotas_of = lambda j: [('user', j['username'], q)] if j['username'] == 'alice' else []   # noqa: E731
    used = {('user', 'alice'): {'gpus': 2, 'hours': 1}}
    placed, why, _ = research.plan([_q('a', 'alice', 1)], [_vm(1)], used, quotas_of)
    assert placed == [] and why == {'a': 'quota_gpus'}
    # over the month (soft): last in line, still runs when there is room
    used = {('user', 'alice'): {'gpus': 0, 'hours': 12}}
    jobs = [_q('a', 'alice', 2, '2026-10-16T08:00:00+00:00'), _q('b', 'bob', 2, '2026-10-16T09:00:00+00:00')]
    placed, why, order = research.plan(jobs, [_vm(1)], used, quotas_of)
    assert order == ['b', 'a'] and len(placed) == 2
    q['hard'] = True
    placed, why, _ = research.plan(jobs, [_vm(1)], used, quotas_of)
    assert [j['id'] for j, _, _ in placed] == ['b'] and why == {'a': 'quota_hours'}
    # a department's quota counts everyone in it
    dq = {'max_gpus': 3, 'monthly_gpu_hours': 0, 'hard': False}
    of = lambda j: [('department', 'lab', dq)]   # noqa: E731
    placed, why, _ = research.plan([_q('a', 'alice', 2), _q('b', 'bob', 2)], [_vm(1)], {}, of)
    assert [j['id'] for j, _, _ in placed] == ['a'] and why == {'b': 'quota_gpus_department'}


def test_an_old_job_keeps_its_gpus_from_later_small_ones():
    at = research.parse('2026-10-16T12:00:00+00:00')
    big = _q('big', 'alice', 4, '2026-10-16T10:00:00+00:00')
    small = _q('small', 'bob', 1, '2026-10-16T11:59:00+00:00')
    vm = _vm(1, used={0})
    placed, why, _ = research.plan([big, small], [vm], {}, lambda j: [], starve_minutes=60, at=at)
    assert placed == [] and why == {'big': 'no_free_gpu', 'small': 'held_for_older'}
    placed, _, _ = research.plan([big, small], [vm], {}, lambda j: [], starve_minutes=0, at=at)
    assert [j['id'] for j, _, _ in placed] == ['small']


def test_the_job_script():
    job = {'id': 'job_1', 'command': 'python train.py --epochs 3', 'max_minutes': 90, 'env': ''}
    s = research.job_script(job, '/nas/scratch/alice/job_1', [2, 3])
    assert "wd=/nas/scratch/alice/job_1" in s and 'export CUDA_VISIBLE_DEVICES=2,3 HIP_VISIBLE_DEVICES=2,3' in s
    assert "timeout -k 60 5400 bash -lc 'python train.py --epochs 3' >\"$wd/moavi-job.log\" 2>&1" in s
    assert 'tail -c 20000 "$wd/moavi-job.log"' in s
    s = research.job_script(dict(job, env='{"kind": "conda", "name": "torch"}', max_minutes=0), '/w', [0])
    assert 'conda run --no-capture-output -n torch bash -lc' in s and 'timeout' not in s.split('conda run')[1].split('\n')[0]
    s = research.job_script(dict(job, env='{"kind": "container", "image": "nvcr.io/nvidia/pytorch:24.08-py3"}'), '/w', [0, 1])
    assert "docker run --rm --name moavi-job_1 --gpus '\"device=0,1\"'" in s and 'docker rm -f moavi-job_1' in s
    s = research.job_script(dict(job, env='{"kind": "container", "image": "x/y:1"}'), '/w', [1], runtime='podman')
    assert '--device nvidia.com/gpu=1' in s
    assert research.job_argv('S', 'alice') == ['setsid', '-w', 'runuser', '-u', 'alice', '--', '/bin/bash', '-lc', 'S']
    assert research.stop_argv(77)[2].startswith('pkill -TERM -s 77; sleep 15; pkill -KILL -s 77')
    for bad in ({'gpus': 17}, {'gpus': 1, 'env': {'kind': 'conda', 'name': 'a b'}},
                {'gpus': 1, 'env': {'kind': 'container', 'image': 'x;rm -rf /'}}, {'gpus': 1, 'notify': {'sms': True}},
                {'gpus': 1, 'gpu_kind': 'a$b'}):
        with pytest.raises(ValueError):
            research.job_extra(bad)
    assert research.job_extra({'gpus': 1, 'max_minutes': 600}, pool_cap=120)['max_minutes'] == 120
    assert research.job_extra({'gpus': 1}, default_minutes=1440)['max_minutes'] == 1440
    assert research.job_extra({'name': 'x'}) == {}


# --- GPU jobs through the API ----------------------------------------------------------------

def test_gpu_jobs_take_free_gpus_of_any_granted_pool(env):
    _, mgr, agent, admin, alice, bob, _ = env
    farm = _gpu_farm(admin)
    me = alice.get('/api/vlab/me/gpu').get_json()
    assert [p['name'] for p in me['pools']] == ['GPU 학습 팜'] and me['pools'][0]['gpus_per_vm'] == 4
    assert _job(alice, gpus=8).status_code == 409                         # no VM has 8
    assert _job(alice, gpus=1, gpu_kind='H100').get_json()['code'] == 'NO_GPU_POOL'
    r = _job(alice, gpus=2, gpu_kind='a100', memory_gb=64, max_minutes=30,
             env={'kind': 'conda', 'name': 'torch'}, notify={'mail': True})
    assert r.status_code == 201, r.get_json()
    j1 = r.get_json()['job']
    assert j1['status'] == 'running' and j1['pool'] == 'GPU 학습 팜' and j1['gpu_index'] == [0, 1]
    assert j1['workdir'] == f"/var/tmp/moavi-jobs/{j1['id']}" and j1['env'] == {'kind': 'conda', 'name': 'torch'}
    argv, _, pid1 = agent.scripts()[-1]
    assert argv[:3] == ['setsid', '-w', '/bin/bash'] and 'CUDA_VISIBLE_DEVICES=0,1' in argv[-1]
    assert 'timeout -k 60 1800 conda run' in argv[-1]
    j2 = _job(bob, gpus=2).get_json()['job']
    assert j2['desktop'] == j1['desktop'] and j2['gpu_index'] == [2, 3]   # packed on the same VM
    j3 = _job(bob, gpus=4).get_json()['job']
    assert j3['status'] == 'running' and j3['desktop'] != j1['desktop']
    j4 = _job(alice, gpus=1).get_json()['job']
    assert j4['status'] == 'queued'
    q = admin.get('/api/vlab/admin/gpu-queue').get_json()
    assert [r['id'] for r in q['queued']] == [j4['id']] and q['queued'][0]['wait_reason'] == 'no_free_gpu'
    assert q['pools'][0]['gpus'] == 8 and q['pools'][0]['gpus_used'] == 8
    # the first ends: its owner hears of it, and its GPUs go to the waiting job
    sent = []
    import pegaprox.utils.email as email
    orig = email.send_email
    email.send_email = lambda to, title, text, html=None: sent.append((to, title)) or (True, '')
    try:
        from pegaprox.utils.auth import load_users, save_single_user
        u = load_users()['alice']
        save_single_user('alice', dict(u, email='alice@lab.example'))
        agent.done[pid1] = {'exited': 1, 'exitcode': 0, 'out-data': 'epoch 3 loss 0.12'}
        jobs = {j['id']: j for j in alice.get('/api/vlab/me/build-jobs').get_json()['jobs']}
    finally:
        email.send_email = orig
    assert jobs[j1['id']]['status'] == 'done' and jobs[j1['id']]['output'] == 'epoch 3 loss 0.12'
    assert sent == [(['alice@lab.example'], '[MOAVI Desk] 작업 완료: train')]
    assert jobs[j4['id']]['status'] == 'running' and jobs[j4['id']]['gpu_index'] == [0]
    assert catalog.get_build_job(j1['id'])['notified_at']
    # a running job is stopped on its VM; another user's is not theirs to stop
    assert alice.post(f"/api/vlab/me/build-jobs/{j2['id']}/stop").status_code == 404
    r = bob.post(f"/api/vlab/me/build-jobs/{j2['id']}/stop")
    assert r.status_code == 200 and r.get_json()['job']['status'] == 'cancelled'
    assert agent.scripts()[-1][0][2].startswith(f"pkill -TERM -s {catalog.get_build_job(j2['id'])['pid']}")
    assert bob.post(f"/api/vlab/me/build-jobs/{j2['id']}/stop").status_code == 409
    # the plain build path is unchanged: a pool is still required without GPUs
    assert alice.post('/api/vlab/me/build-jobs', json={'name': 'x', 'command': 'make'}).status_code == 404


def test_quota_routes_and_the_queue_holds_a_user_at_their_quota(env):
    _, _, agent, admin, alice, bob, viewer = env
    _gpu_farm(admin)
    dep = admin.post('/api/vlab/admin/departments', json={'name': 'AI 연구실'}).get_json()['department']
    admin.put('/api/vlab/admin/users/alice/department', json={'department_id': dep['id']})
    assert viewer.put('/api/vlab/admin/gpu-quotas', json={'subject_type': 'user', 'subject_id': 'alice', 'max_gpus': 1}).status_code == 403
    assert admin.put('/api/vlab/admin/gpu-quotas', json={'subject_type': 'user', 'subject_id': 'nobody', 'max_gpus': 1}).status_code == 404
    assert admin.put('/api/vlab/admin/gpu-quotas', json={'subject_type': 'team', 'subject_id': 'x'}).status_code == 400
    r = admin.put('/api/vlab/admin/gpu-quotas', json={'subject_type': 'user', 'subject_id': 'alice', 'max_gpus': 2,
                                                      'monthly_gpu_hours': 100, 'note': '박사과정'})
    assert r.status_code == 200 and r.get_json()['quota']['max_gpus'] == 2
    admin.put('/api/vlab/admin/gpu-quotas', json={'subject_type': 'department', 'subject_id': dep['id'], 'max_gpus': 6})
    admin.put('/api/vlab/admin/gpu-quotas', json={'subject_type': 'default', 'max_gpus': 4})
    a1 = _job(alice, gpus=2).get_json()['job']
    a2 = _job(alice, gpus=1).get_json()['job']
    assert a1['status'] == 'running' and a2['status'] == 'queued'
    assert catalog.get_build_job(a2['id'])['wait_reason'] == 'quota_gpus'
    assert _job(bob, gpus=4).get_json()['job']['status'] == 'running'    # bob has the default 4
    got = admin.get('/api/vlab/admin/gpu-quotas').get_json()
    by = {(q['subject_type'], q['subject_id']): q for q in got['quotas']}
    assert by[('user', 'alice')]['gpus_now'] == 2 and by[('department', dep['id'])]['name'] == 'AI 연구실'
    assert by[('default', '')]['gpus_now'] is None
    mine = alice.get('/api/vlab/me/gpu').get_json()
    assert mine['gpus_now'] == 2 and {q['applies_as'] for q in mine['quotas']} == {'user', 'department'}
    assert admin.delete('/api/vlab/admin/gpu-quotas?subject_type=user&subject_id=alice').status_code == 200
    assert admin.delete('/api/vlab/admin/gpu-quotas?subject_type=user&subject_id=alice').status_code == 404
    # with the default (4 at once) alice's second job fits now
    assert {j['id']: j for j in alice.get('/api/vlab/me/build-jobs').get_json()['jobs']}[a2['id']]['status'] == 'running'


def test_the_minute_loop_starts_only_with_a_confirmed_lease_and_stops_overdue_jobs(env, monkeypatch):
    import pegaprox.api.vlab_research as rsch
    from pegaprox.core import ha
    _, _, agent, admin, alice, _, _ = env
    farm = _gpu_farm(admin)
    job = catalog.add_build_job('', 'alice', 'late', 'python a.py', '', gpus=1, max_minutes=5)
    monkeypatch.setattr(ha, 'confirm_step', lambda *a, **k: False)
    rsch.gpu_tick()
    assert catalog.get_build_job(job['id'])['status'] == 'queued' and agent.calls == []
    monkeypatch.setattr(ha, 'confirm_step', lambda *a, **k: True)
    rsch.gpu_tick()
    j = catalog.get_build_job(job['id'])
    assert j['status'] == 'running' and j['pool_id'] == farm['id']
    long_ago = (research.utcnow() - timedelta(minutes=30)).isoformat(timespec='seconds')
    catalog.db().execute('UPDATE vlab_build_jobs SET started_at = ? WHERE id = ?', (long_ago, job['id']))
    rsch.gpu_tick()
    j = catalog.get_build_job(job['id'])
    assert j['status'] == 'failed' and j['error'].startswith('time limit reached')
    assert agent.scripts()[-1][0][2].startswith(f"pkill -TERM -s {j['pid']}")


# --- GPU-hours report -------------------------------------------------------------------------

def test_gpu_usage_report_by_user_and_department(env):
    _, _, _, admin, alice, bob, viewer = env
    top = admin.post('/api/vlab/admin/departments', json={'name': '공과대학'}).get_json()['department']
    lab = admin.post('/api/vlab/admin/departments', json={'name': 'AI 연구실', 'parent_id': top['id']}).get_json()['department']
    admin.put('/api/vlab/admin/users/alice/department', json={'department_id': lab['id']})
    now = research.utcnow()
    iso = lambda h: (now - timedelta(hours=h)).isoformat(timespec='seconds')   # noqa: E731
    j = catalog.add_build_job('', 'alice', 'a', 'x', '', gpus=2, department_id=lab['id'])
    catalog.update_build_job(j['id'], status='done', started_at=iso(5), finished_at=iso(2))        # 2 GPUs x 3 h
    j = catalog.add_build_job('', 'bob', 'b', 'x', '', gpus=1)
    catalog.update_build_job(j['id'], status='running', started_at=iso(4))                          # 1 x 4 h
    l = store.add_lease('gpu', 'rtx-pool', 'RTX 6000', 'alice', CID, 710, iso(-10))
    catalog.db().execute('UPDATE vlab_leases SET starts_at = ? WHERE id = ?', (iso(10), l['id']))   # 10 h, active
    store.add_lease('fpga', 'alveo', 'Alveo', 'bob', CID, 711, iso(-1))                             # not a GPU
    assert viewer.get('/api/vlab/admin/reports/gpu-usage').status_code == 403
    rep = admin.get('/api/vlab/admin/reports/gpu-usage?days=7').get_json()
    by = {r['username']: r for r in rep['rows']}
    assert by['alice']['job_gpu_hours'] == pytest.approx(6, abs=0.05) and by['alice']['loan_gpu_hours'] == pytest.approx(10, abs=0.05)
    assert by['alice']['department'] == '공과대학 > AI 연구실'
    assert by['bob']['total_gpu_hours'] == pytest.approx(4, abs=0.05) and by['bob']['loans'] == 0
    assert rep['total_gpu_hours'] == pytest.approx(20, abs=0.1)
    deps = admin.get('/api/vlab/admin/reports/gpu-usage?days=7&group=department').get_json()['rows']
    assert {r['department'] for r in deps} == {'공과대학 > AI 연구실', '(부서 없음)'}
    up = admin.get('/api/vlab/admin/reports/gpu-usage?days=7&group=department&rollup=1').get_json()['rows']
    assert {r['department'] for r in up} == {'공과대학', '(부서 없음)'}
    csv = admin.get('/api/vlab/admin/reports/gpu-usage?days=7&format=csv')
    text = csv.get_data(as_text=True)
    assert csv.mimetype == 'text/csv' and 'user,name,department,job_gpu_hours' in text and 'alice' in text
    assert admin.get('/api/vlab/admin/reports/gpu-usage?month=2026-13').status_code == 400
    assert admin.get(f"/api/vlab/admin/reports/gpu-usage?month={now.astimezone().strftime('%Y-%m')}").status_code == 200


# --- web IDE ----------------------------------------------------------------------------------

def _ide_desk(admin, kinds=('jupyter', 'vscode')):
    pool = store.create_pool('GPU 워크스테이션', 'dedicated', CID)
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'web_ide': list(kinds)}).status_code == 200
    desk = store.add_desktop(store.get_pool(pool['id']), 'pve1', 710, 'ws-alice')
    store.set_assignment(desk['id'], 'alice')
    return pool, desk


def _auth(api, uri, cookie=None, sub='1'):
    """What vlab-proxy's auth_request sends: a fresh client, as a browser holds only its cookie."""
    c = api.app.test_client()
    if cookie:
        c.set_cookie('moavi_ide', cookie, domain='localhost')
    headers = {'X-Original-URI': uri}
    if sub:
        headers['X-Moavi-Ide-Subrequest'] = sub
    return c.get('/api/vlab/ide/auth', headers=headers, base_url='http://localhost')


def test_web_ide_starts_as_the_user_and_is_reached_only_through_the_proxy(env, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    api, _, agent, admin, alice, bob, _ = env
    pool, desk = _ide_desk(admin, kinds=('jupyter',))
    up = {'ok': False}
    monkeypatch.setattr(nxt, '_tcp_probe', lambda h, p, timeout=2.0: (up['ok'], 1, ''))
    got = alice.get('/api/vlab/me/ide').get_json()
    assert [d['name'] for d in got['desktops']] == ['ws-alice'] and got['desktops'][0]['kinds'] == ['jupyter']
    assert alice.post('/api/vlab/me/ide', json={'desktop_id': desk['id'], 'kind': 'vscode'}).status_code == 403
    assert bob.post('/api/vlab/me/ide', json={'desktop_id': desk['id'], 'kind': 'jupyter'}).status_code == 404
    assert alice.post('/api/vlab/me/ide', json={'desktop_id': desk['id'], 'kind': 'jupyter', 'folder': 'scratch'}).get_json()['code'] == 'NO_SCRATCH'
    r = alice.post('/api/vlab/me/ide', json={'desktop_id': desk['id'], 'kind': 'jupyter'})
    assert r.status_code == 201, r.get_json()
    s = r.get_json()['session']
    sid = s['id']
    assert s['state'] == 'starting' and s['path'] == f'/ide/{sid}/lab'
    argv, stdin, pid = agent.scripts()[-1]
    assert argv[:6] == ['setsid', '-w', 'runuser', '-u', 'alice', '--']
    script = argv[-1]
    token = stdin.strip()
    assert len(token) == 48 and token not in script                      # the token never on a command line
    assert f'--ServerApp.base_url=/ide/{sid}/' in script and '--port=8890' in script and 'exec jupyter lab' in script
    assert 'CUDA_VISIBLE_DEVICES=' not in script                          # a GPU desktop keeps its GPUs
    # starting, then running once the port answers; opening twice reuses it
    assert alice.post(f'/api/vlab/me/ide/{sid}/open').status_code == 409
    up['ok'] = True
    assert alice.get(f'/api/vlab/me/ide/{sid}').get_json()['session']['state'] == 'running'
    again = alice.post('/api/vlab/me/ide', json={'desktop_id': desk['id'], 'kind': 'jupyter'})
    assert again.status_code == 200 and again.get_json()['reused'] and again.get_json()['session']['id'] == sid
    assert bob.get(f'/api/vlab/me/ide/{sid}').status_code == 404
    url = alice.post(f'/api/vlab/me/ide/{sid}/open').get_json()['url']
    assert url.startswith(f'/ide/{sid}/lab?moavi_ide=')
    tok = url.split('moavi_ide=')[1]
    # the proxy's check: only as a subrequest, the link once, then the cookie it set
    assert _auth(api, url, sub=None).status_code == 404
    assert _auth(api, f'/ide/{sid}/lab?moavi_ide=wrong').status_code == 401
    ok = _auth(api, url)
    assert ok.status_code == 200
    assert ok.headers['X-Ide-Upstream'] == '10.0.0.198:8890' and ok.headers['X-Ide-Authorization'] == f'token {token}'
    cookie = ok.headers['X-Ide-Set-Cookie'].split(';')[0].split('=', 1)[1]
    assert f'Path=/ide/{sid}/' in ok.headers['X-Ide-Set-Cookie'] and 'HttpOnly' in ok.headers['X-Ide-Set-Cookie']
    assert _auth(api, url).status_code == 401                             # the link is spent
    assert _auth(api, f'/ide/{sid}/api/kernels', cookie=cookie).status_code == 200
    assert _auth(api, f'/ide/ide_000000000000/lab', cookie=cookie).status_code == 401
    # stopped: the session ends on the desktop and the cookie stops working
    assert alice.delete(f'/api/vlab/me/ide/{sid}').get_json()['session']['state'] == 'stopped'
    assert agent.scripts()[-1][0][2].startswith(f'pkill -TERM -s {pid}')
    assert _auth(api, f'/ide/{sid}/lab', cookie=cookie).status_code == 401


def test_web_ide_on_a_build_vm_hides_the_gpus_and_says_what_is_missing(env, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    _, _, agent, admin, alice, _, viewer = env
    farm = _gpu_farm(admin)
    admin.put(f"/api/vlab/admin/pools/{farm['id']}/policy", json={'web_ide': ['vscode']})
    monkeypatch.setattr(nxt, '_tcp_probe', lambda h, p, timeout=2.0: (False, 1, 'refused'))
    assert [p['name'] for p in alice.get('/api/vlab/me/ide').get_json()['pools']] == ['GPU 학습 팜']
    r = alice.post('/api/vlab/me/ide', json={'pool_id': farm['id'], 'kind': 'vscode'})
    assert r.status_code == 201, r.get_json()
    s = r.get_json()['session']
    argv, _, pid = agent.scripts()[-1]
    assert 'export CUDA_VISIBLE_DEVICES= HIP_VISIBLE_DEVICES=' in argv[-1] and 'exec jupyter server' in argv[-1]
    assert 'command -v code-server' in argv[-1] and s['path'].endswith('/vscode/')
    agent.done[pid] = {'exited': 1, 'exitcode': research.EXIT_NO_CODE_SERVER}
    s = alice.get(f"/api/vlab/me/ide/{s['id']}").get_json()['session']
    assert s['state'] == 'failed' and 'code-server is not installed' in s['error']
    assert len(admin.get('/api/vlab/admin/ide-sessions').get_json()['sessions']) == 1
    assert viewer.get('/api/vlab/admin/ide-sessions').status_code == 403
    agent.os = 'mswindows'
    pool, desk = _ide_desk(admin)
    assert alice.post('/api/vlab/me/ide', json={'desktop_id': desk['id'], 'kind': 'jupyter'}).get_json()['code'] == 'WINDOWS'


# --- who may reach what (authz contract) -----------------------------------------------------

ADMIN_READS = ['/api/vlab/admin/gpu-queue', '/api/vlab/admin/gpu-quotas', '/api/vlab/admin/gpu-settings',
               '/api/vlab/admin/ide-sessions']
ADMIN_WRITES = [('put', '/api/vlab/admin/gpu-quotas', {'subject_type': 'default', 'max_gpus': 1}),
                ('delete', '/api/vlab/admin/gpu-quotas?subject_type=default', None),
                ('put', '/api/vlab/admin/gpu-settings', {'mail': False}),
                ('post', '/api/vlab/admin/build-jobs/job_x/stop', {}),
                ('delete', '/api/vlab/admin/ide-sessions/ide_x', None)]


def test_routes_ask_for_the_right_permission(env):
    api, _, _, admin, alice, _, viewer = env
    pool = store.create_pool('팜', 'buildfarm', CID)
    anon = api.anon()
    for url in ADMIN_READS + ['/api/vlab/me/gpu', '/api/vlab/me/ide', f"/api/vlab/admin/pools/{pool['id']}/gpu-jobs",
                              '/api/vlab/admin/reports/gpu-usage']:
        assert anon.get(url).status_code == 401, url
    for url in ADMIN_READS + [f"/api/vlab/admin/pools/{pool['id']}/gpu-jobs"]:
        assert alice.get(url).status_code == 403, url
        assert viewer.get(url).status_code == 403, url
        assert admin.get(url).status_code == 200, url
    assert alice.get('/api/vlab/admin/reports/gpu-usage').status_code == 403
    for method, url, body in ADMIN_WRITES + [('put', f"/api/vlab/admin/pools/{pool['id']}/gpu-jobs", {'gpus_per_vm': 1})]:
        kw = {'json': body} if body is not None else {}
        assert getattr(viewer, method)(url, **kw).status_code == 403, url
        assert getattr(alice, method)(url, **kw).status_code == 403, url
    # a portal-only viewer has no vlab.desk: no portal routes either
    assert viewer.get('/api/vlab/me/gpu').status_code == 403 and viewer.post('/api/vlab/me/ide', json={}).status_code == 403
    # the pool setting itself
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/gpu-jobs", json={'gpus_per_vm': 99}).status_code == 400
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/gpu-jobs", json={'gpus_per_vm': 2, 'runtime': 'lxc'}).status_code == 400
    r = admin.put(f"/api/vlab/admin/pools/{pool['id']}/gpu-jobs", json={'gpus_per_vm': 2, 'kind': 'L40S', 'max_minutes': 600, 'runtime': 'apptainer'})
    assert r.get_json()['gpu_jobs'] == {'gpus_per_vm': 2, 'kind': 'L40S', 'max_minutes': 600, 'runtime': 'apptainer'}
    dedicated = store.create_pool('개인', 'dedicated', CID)
    assert admin.put(f"/api/vlab/admin/pools/{dedicated['id']}/gpu-jobs", json={'gpus_per_vm': 1}).status_code == 400
    assert admin.put(f"/api/vlab/admin/pools/{dedicated['id']}/policy", json={'web_ide': ['emacs']}).status_code == 400
    assert admin.put('/api/vlab/admin/gpu-settings', json={'starve_minutes': -1}).status_code == 400
    assert admin.put('/api/vlab/admin/gpu-settings', json={'channels': ['ch1'], 'starve_minutes': 30}).get_json()['settings']['starve_minutes'] == 30
