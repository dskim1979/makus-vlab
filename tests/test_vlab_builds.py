"""MOAVI Desk build results kept (pegaprox/vlab/artifacts.py) and CI connections (pegaprox/vlab/ci.py,
pegaprox/api/vlab_builds.py)."""
import base64

from pegaprox.vlab import artifacts, catalog, ci, store
from test_vlab_research import CID, env  # noqa: F401 - the shared fixture


def _farm(admin, users=('alice',)):
    pool = store.create_pool('FPGA 빌드 팜', 'buildfarm', CID)
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/grants",
                     json={'grants': [{'subject_type': 'user', 'subject_id': u} for u in users]}).status_code == 200
    store.add_desktop(store.get_pool(pool['id']), 'pve1', 700, 'vivado-build-01')
    return store.get_pool(pool['id'])


def test_the_collect_script_and_its_output():
    s = dict(artifacts.DEFAULTS, patterns=['*.bit', 'reports/*.rpt'], max_files=10, max_mb=5)
    sh = artifacts.collect_script('/nas/scratch/alice/job1', '/nas/artifacts/alice/job1', '/nas/artifacts/alice', s)
    assert "-name '*.bit'" in sh and "-path '*/reports/*.rpt'" in sh and 'head -n 10' in sh
    assert f'-size -{5 * 1024 * 1024 + 1}c' in sh and '-mtime +90' in sh
    kept, files = artifacts.parse_collect('kept=/nas/artifacts/alice/job1\nf\t1200\tout/top.bit\nf\tx\tbad\nf\t3\t../etc/passwd\nnoise\n')
    assert kept == '/nas/artifacts/alice/job1' and files == [{'path': 'out/top.bit', 'size': 1200}]
    assert artifacts.dest_for({'linux_path': '/nas'}, 'alice', 'job1') == ('/nas/artifacts/alice/job1', '/nas/artifacts/alice')
    assert artifacts.dest_for(None, 'alice', 'job1') == ('', '')


def test_artifact_settings_default_and_per_pool(env):
    api, mgr, agent, admin, alice, bob, viewer = env
    pool = _farm(admin)
    body = admin.get('/api/vlab/admin/build-artifacts').get_json()
    assert body['default']['keep_days'] == 90 and body['pools'][0]['own'] is False
    assert admin.put('/api/vlab/admin/build-artifacts/_default', json={'patterns': ['$(rm)']}).status_code == 400
    assert admin.put('/api/vlab/admin/build-artifacts/_default', json={'keep_days': 0}).status_code == 400
    assert alice.put('/api/vlab/admin/build-artifacts/_default', json={'keep_days': 30}).status_code == 403
    r = admin.put(f"/api/vlab/admin/build-artifacts/{pool['id']}", json={'patterns': ['*.xclbin'], 'keep_days': 30})
    assert r.status_code == 200
    assert artifacts.get(pool['id'])['patterns'] == ['*.xclbin'] and artifacts.get(None)['patterns'] == artifacts.DEFAULTS['patterns']
    assert admin.put(f"/api/vlab/admin/build-artifacts/{pool['id']}", data='null', content_type='application/json').status_code == 200
    assert artifacts.get(pool['id'])['keep_days'] == 90                           # back to the default


def test_results_are_listed_at_the_end_and_downloaded(env, monkeypatch):
    api, mgr, agent, admin, alice, bob, viewer = env
    import pegaprox.api.vlab_next as vn
    pool = _farm(admin)
    r = alice.post('/api/vlab/me/build-jobs', json={'pool_id': pool['id'], 'name': 'top', 'command': 'make bit', 'workdir': '/work/top'})
    assert r.status_code == 201
    job = catalog.get_build_job(r.get_json()['job']['id'])
    assert job['status'] == 'running'
    ran = []

    def fake_run(m, node, vmid, argv, stdin=None, wait=0):
        ran.append(argv)
        if 'base64 -w0' in argv[-1]:
            return 0, base64.b64encode(b'BITSTREAM').decode(), '', None
        return 0, 'kept=/work/top\nf\t9\tbuild/top.bit\nf\t120\treports/timing.rpt\n', '', None
    monkeypatch.setattr(vn, '_agent_run', fake_run)
    agent.done[int(job['pid'])] = {'exited': 1, 'exitcode': 0, 'out-data': 'done'}
    vn.refresh_jobs(pool['id'])
    job = catalog.get_build_job(job['id'])
    assert job['status'] == 'done' and job['artifacts_dir'] == '/work/top'
    mine = alice.get('/api/vlab/me/build-jobs').get_json()['jobs'][0]
    assert [f['path'] for f in mine['artifacts']] == ['build/top.bit', 'reports/timing.rpt'] and mine['artifacts_kept'] == 'workdir'
    d = alice.get(f"/api/vlab/me/build-jobs/{job['id']}/artifacts/0")
    assert d.status_code == 200 and d.data == b'BITSTREAM'
    assert 'P=/work/top/build/top.bit;' in ran[-1][-1]
    assert alice.get(f"/api/vlab/me/build-jobs/{job['id']}/artifacts/5").status_code == 404
    assert bob.get(f"/api/vlab/me/build-jobs/{job['id']}/artifacts/0").status_code == 404     # not his job
    from pegaprox.vlab import datasets
    datasets.save_policy(pool['id'], dict(datasets.get_policy(pool['id']), export='approval'))
    assert alice.get(f"/api/vlab/me/build-jobs/{job['id']}/artifacts/0").status_code == 403   # export control applies


def test_ci_connection_tokens_and_builds(env, monkeypatch):
    api, mgr, agent, admin, alice, bob, viewer = env
    pool = _farm(admin)
    assert admin.post('/api/vlab/admin/ci-links', json={'name': 'x', 'pool_id': pool['id'], 'owner': 'bob',
                                                        'command': 'make'}).status_code == 409        # bob has no grant
    r = admin.post('/api/vlab/admin/ci-links', json={'name': 'FPGA팀 GitLab', 'kind': 'gitlab', 'pool_id': pool['id'],
                                                    'owner': 'alice', 'command': 'git checkout "$MOAVI_CI_COMMIT" && make bit'})
    assert r.status_code == 201
    token, link = r.get_json()['token'], r.get_json()['link']
    assert token.startswith('mci_') and 'token_hash' not in link and link['token_hint'] == token[-4:]
    ci_api = api.anon()
    assert ci_api.post('/api/vlab/ci/jobs', json={}).status_code == 401
    assert ci_api.post('/api/vlab/ci/jobs', json={}, headers={'Authorization': 'Bearer mci_nope'}).status_code == 401
    h = {'Authorization': f'Bearer {token}'}
    assert ci_api.post('/api/vlab/ci/jobs', json={'command': 'rm -rf /'}, headers=h).status_code == 403
    assert ci_api.post('/api/vlab/ci/jobs', json={'commit': 'not-hex'}, headers=h).status_code == 400
    r = ci_api.post('/api/vlab/ci/jobs', json={'repo': 'fpga/top', 'ref': 'main', 'commit': 'a1b2c3d4e5', 'pipeline': '981'}, headers=h)
    assert r.status_code == 201, r.get_json()
    j = r.get_json()['job']
    job = catalog.get_build_job(j['id'])
    assert job['username'] == 'alice' and "MOAVI_CI_COMMIT=a1b2c3d4e5" in job['command'] and job['command'].endswith('make bit')
    assert ci.source_of(job)['repo'] == 'fpga/top' and ci.source_of(job)['link'] == link['id']
    s = ci_api.get(f"/api/vlab/ci/jobs/{j['id']}", headers=h).get_json()['job']
    assert s['source']['commit'] == 'a1b2c3d4e5' and s['done'] is False
    other = catalog.add_build_job(pool['id'], 'alice', 'by hand', 'make', '')
    assert ci_api.get(f"/api/vlab/ci/jobs/{other['id']}", headers=h).status_code == 404      # not a job of this connection
    # a real CI sends no Origin: the examples add X-Requested-With (the CSRF gate stays as it is)
    raw = api.app.test_client()
    assert raw.post('/api/vlab/ci/jobs', json={'ref': 'dev'}, headers=h, base_url='http://localhost').status_code == 403
    r = raw.post('/api/vlab/ci/jobs', json={'ref': 'dev'}, headers=dict(h, **{'X-Requested-With': 'XMLHttpRequest'}),
                 base_url='http://localhost')
    assert r.status_code == 201, r.get_json()
    # the portal shows where a job came from
    assert alice.get('/api/vlab/me/build-jobs').get_json()['jobs'][-1]['source']['kind'] == 'gitlab'
    # a new token: the old one stops; switched off: refused
    t2 = admin.post(f"/api/vlab/admin/ci-links/{link['id']}/token").get_json()['token']
    assert ci_api.get(f"/api/vlab/ci/jobs/{j['id']}", headers=h).status_code == 401
    h2 = {'X-Moavi-CI-Token': t2}
    assert ci_api.get(f"/api/vlab/ci/jobs/{j['id']}", headers=h2).status_code == 200
    assert admin.put(f"/api/vlab/admin/ci-links/{link['id']}", json={'enabled': False}).status_code == 200
    assert ci_api.get(f"/api/vlab/ci/jobs/{j['id']}", headers=h2).status_code == 403
    assert alice.post('/api/vlab/admin/ci-links', json={}).status_code == 403
    assert admin.delete(f"/api/vlab/admin/ci-links/{link['id']}").status_code == 200
