"""MOAVI Desk: the automatic domain join (pegaprox/api/vlab_directory.py autojoin_round, the queue in
pegaprox/vlab/directory.py, the pool policy switch auto_domain_join). The DC is the ldap3 MOCK_SYNC
directory of tests/test_vlab_directory.py, the guest agent a fake."""
from pegaprox.api import vlab_directory as vd
from pegaprox.vlab import directory, store
from test_vlab_directory import CID, JOIN_DN, dc, env  # noqa: F401

WIN_OK = 'sid=S-1-5-21-111\ndomain=moavi.lan\ncomputer=MD-{vmid}\njoined=1\nreboot=1\nrdp_group=1\nrestarting=1\n'


class _Resp:
    def __init__(self, data, status=200):
        self.status_code, self._data, self.text = status, data, ''

    def json(self):
        return {'data': self._data}


class Guest:
    """One fake guest agent for the cluster: up or not, its OS, what the join script answers."""

    def __init__(self, mgr):
        self.up, self.os_id, self.code, self.out = False, 'mswindows', 0, WIN_OK
        self.runs = []
        mgr._api_get.side_effect = self.get
        mgr._api_post.side_effect = self.post

    def get(self, url, params=None):
        if not self.up:
            return _Resp(None, 500)
        if url.endswith('/agent/get-osinfo'):
            return _Resp({'result': {'id': self.os_id}})
        if url.endswith('/agent/exec-status'):
            vmid = url.split('/qemu/')[1].split('/')[0]
            return _Resp({'exited': 1, 'exitcode': self.code, 'out-data': self.out.replace('{vmid}', vmid), 'err-data': 'x'})
        return _Resp({}, 404)

    def post(self, url, data=None):
        self.runs.append((url, data))
        return _Resp({'pid': 9})

    def scripts(self):
        return [d['command'][-1] for u, d in self.runs if u.endswith('/agent/exec')]


def _setup(env, statuses=('running', 'running')):
    api, seed, admin, dc, _ = env
    res = [{'vmid': 300 + i, 'node': 'pve1', 'name': f'win-{i}', 'type': 'qemu', 'status': s} for i, s in enumerate(statuses)]
    mgr = api.make_fake_manager(CID, get_vm_resources=res)
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    g = Guest(mgr)
    pool = admin.post('/api/vlab/admin/pools', json={'name': '사무', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    desks = [admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': 300 + i}).get_json()['desktop']
             for i in range(len(statuses))]
    return admin, g, pool, desks


def _due_now():
    directory.db().execute('UPDATE vlab_directory_autojoin SET next_at = 0')


def test_a_new_desktop_waits_for_its_agent_then_joins_and_restarts(env):
    admin, g, pool, (d1, d2) = _setup(env)
    assert set(directory.autojoin_waiting()) == {d1['id'], d2['id']}           # queued when made
    out = vd.autojoin_round()
    assert out['waiting'] == 2 and out['joined'] == 0
    row = directory.autojoin_waiting()[d1['id']]
    assert row['attempts'] == 1 and row['next_at'] > 0
    j = directory.join_of(d1['id'])
    assert j['state'] == 'pending' and j['code'] == 'NO_AGENT'
    assert vd.autojoin_round()['joined'] == 0                                   # not due yet: nothing asked
    g.up = True
    _due_now()
    out = vd.autojoin_round()
    assert out['joined'] == 2 and directory.autojoin_waiting() == {}
    j = directory.join_of(d1['id'])
    assert j['state'] == 'joined' and j['code'] == 'RESTARTING' and j['machine_sid'] == 'S-1-5-21-111'
    assert 'shutdown.exe /r' in g.scripts()[0]                                  # nobody signed in: restart now
    rows = {r['desktop_id']: r for r in admin.get(f"/api/vlab/admin/bundled-directory/joins?pool_id={pool['id']}").get_json()['joins']}
    assert rows[d1['id']]['state'] == 'joined'


def test_a_clone_with_another_desktops_sid_is_not_joined(env):
    admin, g, pool, (d1, d2) = _setup(env)
    g.up = True
    directory.autojoin_done(d2['id'])
    vd.autojoin_round()
    assert directory.join_of(d1['id'])['machine_sid'] == 'S-1-5-21-111'
    directory.enqueue(d2['id'], 'new')
    g.code, g.out = 26, 'sid=S-1-5-21-111\n'
    vd.autojoin_round()
    assert "$taken = @('S-1-5-21-111')" in g.scripts()[-1] and 'exit 26' in g.scripts()[-1]
    j = directory.join_of(d2['id'])
    assert j['state'] == 'failed' and j['code'] == 'NOT_SYSPREPPED' and 'sysprep' in j['detail']
    assert d2['id'] not in directory.autojoin_waiting()                         # stopped, not retried
    assert directory.taken_sids(d1['id']) == []                                 # d2 did not take d1's SID


def test_it_gives_up_after_the_limit_and_a_stopped_vm_only_waits(env):
    admin, g, pool, (d1, d2) = _setup(env, ('running', 'stopped'))
    for _ in range(directory.AUTO_MAX_ATTEMPTS):
        _due_now()
        vd.autojoin_round()
    j = directory.join_of(d1['id'])
    assert j['state'] == 'failed' and j['code'] == 'GAVE_UP' and d1['id'] not in directory.autojoin_waiting()
    off = directory.autojoin_waiting()[d2['id']]
    assert off['attempts'] == 0 and directory.join_of(d2['id'])['code'] == 'NOT_RUNNING'   # off: waits, not counted


def test_the_policy_switch(env):
    admin, g, pool, (d1, d2) = _setup(env)
    pol = admin.get(f"/api/vlab/admin/pools/{pool['id']}/policy").get_json()['policy']
    assert pol['auto_domain_join'] is None                                      # follows the bundled directory
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'auto_domain_join': 'yes'}).status_code == 400
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'auto_domain_join': False}).status_code == 200
    assert vd.autojoin_round()['dropped'] == 2 and directory.autojoin_waiting() == {}
    d3 = store.add_desktop(store.get_pool(pool['id']), 'pve1', 302, 'win-2')
    assert d3['id'] not in directory.autojoin_waiting()                          # off: not queued
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'auto_domain_join': True}).status_code == 200
    assert set(directory.autojoin_waiting()) == {d1['id'], d2['id'], d3['id']}  # turned on: the ones not joined
    g.up = True
    vd.autojoin_round()
    # a reset puts it back in the queue even though it was joined
    directory.queue_new(store.get_desktop(d1['id']), 'reset')
    assert directory.autojoin_waiting()[d1['id']]['reason'] == 'reset'
    _due_now()
    vd.autojoin_round()
    assert directory.join_of(d1['id'])['state'] == 'joined' and d1['id'] not in directory.autojoin_waiting()


def test_off_without_the_bundled_directory(api, seed, monkeypatch):
    monkeypatch.delenv('VLAB_DIRECTORY', raising=False)
    admin = api.as_user(seed.user('root', role='admin'))
    mgr = api.make_fake_manager(CID, get_vm_resources=[{'vmid': 300, 'node': 'pve1', 'name': 'w', 'type': 'qemu', 'status': 'running'}])
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    pool = admin.post('/api/vlab/admin/pools', json={'name': 'x', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': 300})
    assert directory.autojoin_waiting() == {} and vd.autojoin_round() == {'joined': 0, 'waiting': 0, 'failed': 0, 'dropped': 0}
