"""MOAVI Desk research data (연구 데이터): the dataset catalog and its read-only mount on the
desktops, files between the portal and a user's folders (parts that resume, Range downloads),
export control (allow / approval / deny, one-time links), the transfer log, the report and the
support bundle. pegaprox/vlab/datasets.py, pegaprox/api/vlab_data.py.

Every path a client sends is checked: '..', absolute paths, backslashes, NUL, drive letters and
symbolic links that point out of the folder are refused."""
import base64
import hashlib
import os

import pytest

from pegaprox.vlab import datasets as dsm
from pegaprox.vlab import nas

CID = 'cluster_1'
RES = [{'vmid': 300, 'node': 'pve1', 'name': 'ai-dev-01', 'type': 'qemu', 'status': 'running', 'maxcpu': 4, 'maxmem': 8 * 1024 ** 3},
       {'vmid': 301, 'node': 'pve1', 'name': 'ai-dev-02', 'type': 'qemu', 'status': 'running', 'maxcpu': 4, 'maxmem': 8 * 1024 ** 3}]
NFS = {'enabled': True, 'kind': 'nfs', 'server': 'nas.lab', 'share': '/export/eda'}
DS = {'name': 'imagenet', 'title': 'ImageNet 2012', 'description': '1000 classes\nCC', 'version': '2012', 'license': 'research only',
      'source': 'image-net.org', 'kind': 'nfs', 'server': 'nas.lab', 'share': '/export/datasets/imagenet', 'tags': ['vision']}
OCTET = {'Content-Type': 'application/offset+octet-stream'}


# --- paths ---------------------------------------------------------------------------------

@pytest.mark.parametrize('bad', ['..', '../bob', 'a/../../b', '/etc/passwd', 'C:/Windows', 'c:x', 'a\\..\\b', 'a\x00b',
                                 'a\nb', 'x' * 1025, 'a/' + 'y' * 256])
def test_a_path_that_could_leave_the_folder_is_refused(bad):
    with pytest.raises(ValueError):
        dsm.clean_rel(bad)


def test_paths_are_cleaned_and_resolved_under_their_root(tmp_path):
    assert dsm.clean_rel('') == '' and dsm.clean_rel(None) == ''
    assert dsm.clean_rel('a//b/./c/') == 'a/b/c'
    assert dsm.clean_rel('실험/결과 1.csv') == '실험/결과 1.csv'
    (tmp_path / 'root' / 'a').mkdir(parents=True)
    root = str(tmp_path / 'root')
    assert dsm.resolve(root, 'a') == os.path.realpath(os.path.join(root, 'a'))
    assert dsm.resolve(root, '') == os.path.realpath(root)
    with pytest.raises(ValueError):
        dsm.resolve(root, '../root2')
    # a sibling whose name starts like the root is outside too
    (tmp_path / 'rootx').mkdir()
    with pytest.raises(ValueError):
        dsm.resolve(root, '../rootx')
    for bad_name in ('', 'a/b', '..', '.', dsm.PART + 'x'):
        with pytest.raises(ValueError):
            dsm.clean_name(bad_name)
    assert dsm.clean_name('model.pt') == 'model.pt'


def test_a_symbolic_link_out_of_the_folder_is_refused(tmp_path):
    root = tmp_path / 'home'
    root.mkdir()
    (tmp_path / 'secret').mkdir()
    try:
        os.symlink(tmp_path / 'secret', root / 'escape', target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip('this system does not let the test make a symbolic link')
    with pytest.raises(ValueError):
        dsm.resolve(str(root), 'escape')
    with pytest.raises(ValueError):
        dsm.resolve(str(root), 'escape/file.txt')


# --- the catalog, without the API ----------------------------------------------------------

def test_a_dataset_is_checked():
    ok, err = dsm.validate_dataset(dict(DS, name='ImageNet', access=[{'subject_type': 'group', 'subject_id': 'ai-lab'}]))
    assert err is None and ok['name'] == 'imagenet' and ok['export'] == 'approval' and ok['access'][0]['subject_id'] == 'ai-lab'
    bad = lambda **kw: dsm.validate_dataset(dict(DS, **kw))[1]
    for case in ({'name': '../x'}, {'name': 'a b'}, {'name': ''}, {'server': 'nas;reboot'}, {'share': '/export/../etc'},
                 {'share': '/'}, {'kind': 'ftp'}, {'export': 'maybe'}, {'admin_path': '/etc'}, {'admin_path': 'rel/path'},
                 {'access': [{'subject_type': 'role', 'subject_id': 'x'}]}, {'pool_ids': 'p1'}, {'surprise': 1},
                 {'title': 'a\x07b'}, {'tags': ['x' * 41]}, {'enabled': 'yes'}, {'nfs_version': '2'}):
        assert bad(**case), case
    smb, err = dsm.validate_dataset(dict(DS, kind='smb', share='\\datasets\\coco\\'))
    assert err is None and smb['share'] == 'datasets/coco'


def test_who_may_use_a_dataset():
    desc = lambda d: {d, d + '-sub'}
    ds = {'access': [{'subject_type': 'user', 'subject_id': 'alice'}, {'subject_type': 'department', 'subject_id': 'ai'},
                     {'subject_type': 'group', 'subject_id': 'GPU-Users'}]}
    assert dsm.may_use(ds, 'alice', None, set(), desc)
    assert dsm.may_use(ds, 'bob', 'ai-sub', set(), desc)            # a sub-department
    assert dsm.may_use(ds, 'carol', None, {'gpu-users'}, desc)
    assert not dsm.may_use(ds, 'dave', 'hr', {'staff'}, desc)
    assert dsm.may_use({'access': []}, 'anyone', None, set(), desc)


def test_the_desktops_mount_datasets_read_only():
    a = dict(dsm.validate_dataset(DS)[0])
    b = dict(dsm.validate_dataset(dict(DS, name='coco', kind='smb', share='datasets/coco', nfs_version='3'))[0])
    line = dsm.autofs_entry([b, a])
    assert line == ('datasets /coco -fstype=cifs,ro,sec=krb5,multiuser,cruid=0 ://nas.lab/datasets/coco '
                    '/imagenet -fstype=nfs,ro,vers=3,hard nas.lab:/export/datasets/imagenet')
    assert dsm.autofs_entry([]) is None
    cfg, _, _ = nas.validate(NFS, nas.get('pool_x'))
    _, amap = nas.autofs_files(cfg, line)
    rows = [r for r in amap.splitlines() if not r.startswith('#')]
    assert rows[0].startswith('datasets ') and rows[1].startswith('* ')          # the key before the wildcard
    script = nas.linux_script(cfg, 'alice', {'home': 'home/alice'}, datasets_line=line)
    assert base64.b64encode(amap.rstrip('\n').encode()).decode() in script
    ps = '\n'.join(dsm.windows_links([a, b]))
    assert "'coco' = '\\\\nas.lab\\datasets\\coco'" in ps and 'imagenet' not in ps       # Windows: SMB datasets only
    assert 'SymbolicLink' in ps and dsm.WINDOWS_ROOT in ps
    smb_cfg, _, _ = nas.validate(dict(NFS, kind='smb', share='eda'), nas.get('pool_x'))
    assert "'coco' = " in nas.windows_script(smb_cfg, {}, extra=dsm.windows_links([b]))
    assert dsm.desktop_paths(b, '/nas') == {'linux': '/nas/datasets/coco', 'windows': 'D:\\datasets\\coco'}


def test_an_export_rule_is_checked():
    cur = dsm.get_policy('pool_x')
    assert cur['export'] == 'allow' and cur['upload'] and cur['link_hours'] == 24
    ok, err = dsm.validate_policy({'export': 'approval', 'max_file_gb': 0, 'sftp': {'host': 'sftp.lab', 'port': 2222}}, cur)
    assert err is None and ok['export'] == 'approval' and ok['sftp'] == {'host': 'sftp.lab', 'port': 2222, 'note': ''}
    for bad in ({'export': 'sometimes'}, {'link_hours': 0}, {'link_hours': 721}, {'max_file_gb': -1}, {'upload': 1},
                {'sftp': {'host': 'a b'}}, {'sftp': {'port': 70000}}, {'sftp': {'user': 'x'}}, {'other': 1}):
        assert dsm.validate_policy(bad, cur)[1], bad


# --- through the API ----------------------------------------------------------------------

class _Resp:
    def __init__(self, data, status=200):
        self.status_code, self._data, self.text = status, data, ''

    def json(self):
        return {'data': self._data}


class Guest:
    """A Linux guest agent: exec answers by what the script asks for; file-write is kept."""

    def __init__(self, mgr):
        self.runs, self.files, self.answers = [], {}, []
        mgr._api_get.side_effect = self.get
        mgr._api_post.side_effect = self.post
        self.last = None

    def get(self, url, params=None):
        if url.endswith('/agent/get-osinfo'):
            return _Resp({'result': {'id': 'ubuntu'}})
        if url.endswith('/agent/exec-status'):
            code, out, err = self.last
            return _Resp({'exited': 1, 'exitcode': code, 'out-data': out, 'err-data': err})
        return _Resp({}, 404)

    def post(self, url, data=None):
        if url.endswith('/agent/file-write'):
            self.files[data['file']] = base64.b64decode(data['content'])
            return _Resp(None)
        self.runs.append(data['command'])
        script = data['command'][-1]
        self.last = (0, 'uid=1501\ngid=1500\nlocal=0\nchanged=0\n', '')
        for needle, answer in self.answers:
            if needle in script:
                self.last = answer(script) if callable(answer) else answer
                break
        return _Resp({'pid': len(self.runs)})


@pytest.fixture
def env(api, seed, tmp_path, monkeypatch):
    mgr = api.make_fake_manager(CID, get_vm_resources=RES)
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    guest = Guest(mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    bob = api.as_user(seed.user('bob', role='user'))
    keeper = api.as_user(seed.user('keeper', role='user', permissions=['vlab.data.manage']))
    import pegaprox.api.vlab_next as vn
    alerts = []
    monkeypatch.setattr(vn, '_alert', lambda title, text, data: alerts.append(data['kind']))
    monkeypatch.setattr(os, 'chown', lambda *a: None, raising=False)
    pool = admin.post('/api/vlab/admin/pools', json={'name': 'AI 연구', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    desks = []
    for vmid, user in ((300, 'alice'), (301, 'bob')):
        d = admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': vmid}).get_json()['desktop']
        admin.put(f"/api/vlab/admin/desktops/{d['id']}/assign", json={'username': user})
        desks.append(d)
    nas_root = tmp_path / 'nas'
    for u in ('alice', 'bob'):
        (nas_root / 'home' / u).mkdir(parents=True)
        (nas_root / 'scratch' / u).mkdir(parents=True)
    (nas_root / 'home' / 'bob' / 'secret.txt').write_text('bob only')
    cfg, _, err = nas.validate(dict(NFS, create_by='engine', admin_path='/srv/nas'), nas.get(pool['id']))
    assert err is None
    nas.save(pool['id'], dict(cfg, admin_path=str(nas_root)))          # a Windows tmp_path is no POSIX path
    return {'api': api, 'mgr': mgr, 'guest': guest, 'admin': admin, 'alice': alice, 'bob': bob, 'keeper': keeper, 'pool': pool,
            'desks': desks, 'nas': nas_root, 'alerts': alerts, 'tmp': tmp_path}


def _q(e, **kw):
    return '&'.join(f'{k}={v}' for k, v in dict({'pool_id': e['pool']['id'], 'folder': 'home'}, **kw).items())


def test_who_may_use_the_routes(env):
    e = env
    assert e['alice'].get('/api/vlab/admin/datasets').status_code == 403
    assert e['alice'].post('/api/vlab/admin/datasets', json=DS).status_code == 403
    assert e['alice'].get('/api/vlab/admin/data/requests').status_code == 403
    assert e['alice'].get('/api/vlab/admin/reports/data-transfers').status_code == 403
    assert e['keeper'].get('/api/vlab/admin/datasets').status_code == 200          # 데이터 담당 (vlab.data.manage)
    assert e['keeper'].get('/api/vlab/admin/data/policies').status_code == 200
    assert e['alice'].get('/api/vlab/me/data').status_code == 200


def test_the_catalog_and_who_sees_a_dataset(env):
    e = env
    r = e['keeper'].post('/api/vlab/admin/datasets', json=dict(DS, access=[{'subject_type': 'user', 'subject_id': 'alice'}]))
    assert r.status_code == 201, r.get_json()
    ds = r.get_json()['dataset']
    assert ds['linux'] == '/nas/datasets/imagenet' and ds['nas'] == 'nas.lab:/export/datasets/imagenet'
    assert e['keeper'].post('/api/vlab/admin/datasets', json=DS).status_code == 409          # the name is taken
    assert e['keeper'].post('/api/vlab/admin/datasets', json=dict(DS, name='x', share='/export/../etc')).status_code == 400
    mine = e['alice'].get('/api/vlab/datasets').get_json()['datasets']
    assert [d['name'] for d in mine] == ['imagenet']
    assert mine[0]['paths'] == [{'linux': '/nas/datasets/imagenet', 'windows': None, 'pool_id': e['pool']['id'], 'pool': 'AI 연구'}]
    assert e['bob'].get('/api/vlab/datasets').get_json()['datasets'] == []
    assert e['alice'].get('/api/vlab/datasets?q=vision').get_json()['datasets'] and not e['alice'].get('/api/vlab/datasets?q=audio').get_json()['datasets']
    assert e['bob'].get(f"/api/vlab/datasets/{ds['id']}/files").status_code == 404          # not even its existence
    # the desktop's map carries it for alice's desktop only
    import pegaprox.api.vlab_next as vn
    from pegaprox.vlab import store
    assert [d['name'] for d in vn._desk_datasets(e['pool'], {'alice'})] == ['imagenet']
    assert vn._desk_datasets(e['pool'], {'bob'}) == []
    vn.ensure_storage(store.get_desktop(e['desks'][0]['id']), e['pool'], 'alice', force=True)
    script = [c for c in e['guest'].runs if 'auto.moavi' in c[-1]][-1][-1]
    written = [base64.b64decode(x.split(' ')[0].strip("'")).decode() for x in script.split('printf %s ')[1:]]
    assert any('\ndatasets /imagenet -fstype=nfs,ro,vers=3,hard nas.lab:/export/datasets/imagenet\n* ' in w for w in written)
    pool_view = e['admin'].get(f"/api/vlab/admin/pools/{e['pool']['id']}/storage").get_json()
    assert 'datasets /imagenet -fstype=nfs,ro' in pool_view['autofs'][nas.AUTOFS_MAP]
    assert e['keeper'].put(f"/api/vlab/admin/datasets/{ds['id']}", json={'export': 'deny'}).get_json()['dataset']['export'] == 'deny'
    assert e['keeper'].delete(f"/api/vlab/admin/datasets/{ds['id']}").status_code == 200
    assert e['alice'].get('/api/vlab/datasets').get_json()['datasets'] == []


def test_browsing_stays_in_the_callers_own_folder(env):
    e = env
    (e['nas'] / 'home' / 'alice' / 'runs').mkdir()
    (e['nas'] / 'home' / 'alice' / 'notes.txt').write_text('hello')
    r = e['alice'].get(f'/api/vlab/me/data/files?{_q(e)}')
    assert r.status_code == 200, r.get_json()
    assert [(x['name'], x['type']) for x in r.get_json()['entries']] == [('runs', 'dir'), ('notes.txt', 'file')]
    assert r.get_json()['mode'] == 'engine'
    for bad in ('..', '../bob', '../../home/bob', '/etc', 'runs/../../bob', '..%2Fbob', 'C:/x', 'a%5C..%5Cb', '%00'):
        r = e['alice'].get(f'/api/vlab/me/data/files?{_q(e, path=bad)}')
        assert r.status_code in (400, 404), (bad, r.status_code)
        r = e['alice'].get(f'/api/vlab/me/data/download?{_q(e, path=bad + "/secret.txt")}')
        assert r.status_code in (400, 404), (bad, r.status_code)
    assert e['alice'].get(f'/api/vlab/me/data/files?{_q(e, folder="project")}').status_code == 404        # not turned on
    assert e['alice'].get(f'/api/vlab/me/data/files?pool_id=nope&folder=home').status_code == 404
    data = e['alice'].get('/api/vlab/me/data').get_json()
    (sp,) = data['spaces']
    assert sp['mode'] == 'engine' and sp['folders']['home']['linux'] == '/nas/home/alice' and sp['policy']['export'] == 'allow'
    r = e['alice'].post('/api/vlab/me/data/mkdir', json={'pool_id': e['pool']['id'], 'folder': 'home', 'path': 'runs', 'name': '../x'})
    assert r.status_code == 400
    r = e['alice'].post('/api/vlab/me/data/mkdir', json={'pool_id': e['pool']['id'], 'folder': 'home', 'path': 'runs', 'name': 'exp1'})
    assert r.status_code == 201 and (e['nas'] / 'home' / 'alice' / 'runs' / 'exp1').is_dir()


def test_an_upload_comes_in_parts_resumes_and_is_hashed(env, db):
    e = env
    blob = os.urandom(300_000)
    start = lambda **kw: e['alice'].post('/api/vlab/me/data/uploads', json=dict(
        {'pool_id': e['pool']['id'], 'folder': 'scratch', 'path': '', 'name': 'weights.bin', 'size': len(blob)}, **kw))
    for bad in ({'name': '../weights.bin'}, {'name': 'a/b'}, {'path': '../bob'}, {'path': '/tmp'}, {'size': -1}, {'size': 'big'}):
        assert start(**bad).status_code in (400, 404), bad
    r = start()
    assert r.status_code == 201, r.get_json()
    up = r.get_json()
    assert up['offset'] == 0 and up['chunk'] == dsm.CHUNK
    url = f"/api/vlab/me/data/uploads/{up['id']}"
    part = lambda off, data: e['alice'].patch(url, data=data, headers=dict(OCTET, **{'Upload-Offset': str(off)}))
    assert part(0, blob[:100_000]).get_json()['offset'] == 100_000
    # a part sent again from a stale offset is refused with the right one
    r = part(0, blob[:100_000])
    assert r.status_code == 409 and r.get_json()['offset'] == 100_000
    assert e['bob'].get(url).status_code == 404                                    # another user's upload
    assert e['bob'].patch(url, data=b'x', headers=dict(OCTET, **{'Upload-Offset': '100000'})).status_code == 404
    # the browser comes back later: the offset is asked, it goes on
    assert e['alice'].get(url).get_json()['offset'] == 100_000
    assert [u['id'] for u in e['alice'].get('/api/vlab/me/data/uploads').get_json()['uploads']] == [up['id']]
    assert part(100_000, blob[100_000:] + b'extra').status_code == 400              # more than the size
    r = part(100_000, blob[100_000:])
    assert r.status_code == 201 and r.get_json()['done']
    digest = hashlib.sha256(blob).hexdigest()
    assert r.get_json()['sha256'] == digest
    final = e['nas'] / 'scratch' / 'alice' / 'weights.bin'
    assert final.read_bytes() == blob
    assert not [p for p in os.listdir(e['nas'] / 'scratch' / 'alice') if p.startswith(dsm.PART)]
    (row,) = dsm.transfers(direction='upload')
    assert (row['username'], row['size'], row['sha256'], row['path'], row['ok']) == ('alice', len(blob), digest, 'scratch/alice/weights.bin', True)
    from pegaprox.core.db import get_db
    (details,) = get_db().conn.execute("SELECT details FROM audit_log WHERE action = 'vlab.data.upload'").fetchone()
    assert digest in details and 'scratch/alice/weights.bin' in details
    # the same name again: refused unless overwrite
    assert start().status_code == 409
    r = start(overwrite=True, size=3)
    r2 = e['alice'].patch(f"/api/vlab/me/data/uploads/{r.get_json()['id']}", data=b'abc', headers=dict(OCTET, **{'Upload-Offset': '0'}))
    assert r2.status_code == 201 and final.read_bytes() == b'abc'
    # without the tus content type the engine's guard refuses the part
    r = start(name='x.bin', size=1)
    assert e['alice'].patch(f"/api/vlab/me/data/uploads/{r.get_json()['id']}", data=b'x',
                            headers={'Content-Type': 'text/plain', 'Upload-Offset': '0'}).status_code == 415
    assert e['alice'].delete(f"/api/vlab/me/data/uploads/{r.get_json()['id']}").status_code == 200


def test_upload_rules_size_and_quota(env):
    e = env
    pid = e['pool']['id']
    body = {'pool_id': pid, 'folder': 'home', 'path': '', 'name': 'big.tar', 'size': 3 * 1024 ** 3}
    assert e['keeper'].put(f'/api/vlab/admin/data/policies/{pid}', json={'max_file_gb': 2}).status_code == 200
    assert e['alice'].post('/api/vlab/me/data/uploads', json=body).get_json()['code'] == 'TOO_BIG'
    assert e['keeper'].put(f'/api/vlab/admin/data/policies/{pid}', json={'upload': False}).status_code == 200
    assert e['alice'].post('/api/vlab/me/data/uploads', json=dict(body, size=10)).get_json()['code'] == 'UPLOAD_OFF'
    e['keeper'].put(f'/api/vlab/admin/data/policies/{pid}', json={'upload': True, 'max_file_gb': 0, 'quota_block': True})
    cfg = nas.get(pid)
    cfg['folders']['home']['quota_gb'] = 1
    nas.save(pid, {k: v for k, v in cfg.items() if k != 'has_password'})
    nas.record(e['desks'][0]['id'], 'alice', pid, True, 'OK', '', '', False, 'linux', usage={'home': 900 * 1024})
    r = e['alice'].post('/api/vlab/me/data/uploads', json=dict(body, size=200 * 1024 ** 2))
    assert r.status_code == 413 and r.get_json()['code'] == 'QUOTA'
    e['keeper'].put(f'/api/vlab/admin/data/policies/{pid}', json={'quota_block': False})
    r = e['alice'].post('/api/vlab/me/data/uploads', json=dict(body, size=200 * 1024 ** 2))
    assert r.status_code == 201 and r.get_json()['warning'] == 'OVER_QUOTA'
    usage = e['keeper'].get('/api/vlab/admin/data/usage').get_json()
    (row,) = [f for f in usage['folders'] if f['username'] == 'alice']
    assert row['folder'] == 'home' and row['quota_gb'] == 1 and row['state'] is None
    nas.record(e['desks'][0]['id'], 'alice', pid, True, 'OK', '', '', False, 'linux', usage={'home': 1000 * 1024})
    assert e['alice'].get('/api/vlab/me/data').get_json()['spaces'][0]['folders']['home']['quota_state'] == 'near'


def test_downloads_answer_range_and_are_logged(env):
    e = env
    blob = bytes(range(256)) * 400
    (e['nas'] / 'home' / 'alice' / 'data.bin').write_bytes(blob)
    r = e['alice'].get(f'/api/vlab/me/data/download?{_q(e, path="data.bin")}&probe=1')
    assert r.get_json() == {'ok': True, 'size': len(blob)} and dsm.transfers() == []       # asked first, nothing sent
    r = e['alice'].get(f'/api/vlab/me/data/download?{_q(e, path="data.bin")}')
    assert r.status_code == 200 and r.data == blob
    digest = hashlib.sha256(blob).hexdigest()
    assert r.headers['X-Content-SHA256'] == digest and r.headers['Accept-Ranges'] == 'bytes'
    r = e['alice'].get(f'/api/vlab/me/data/download?{_q(e, path="data.bin")}', headers={'Range': 'bytes=1000-1999'})
    assert r.status_code == 206 and r.data == blob[1000:2000]
    rows = dsm.transfers(direction='download')
    assert [x['size'] for x in rows] == [1000, len(blob)] and rows[1]['sha256'] == digest
    # bob's file is not alice's to take, whatever the path says
    assert e['alice'].get(f'/api/vlab/me/data/download?{_q(e, path="../bob/secret.txt")}').status_code == 400
    assert e['alice'].get(f'/api/vlab/me/data/download?{_q(e, path="nope.bin")}').status_code == 404


def test_export_control_approval_and_a_one_time_link(env):
    e = env
    pid = e['pool']['id']
    (e['nas'] / 'home' / 'alice' / 'result.csv').write_bytes(b'a,b\n1,2\n')
    dl = f'/api/vlab/me/data/download?{_q(e, path="result.csv")}'
    e['keeper'].put(f'/api/vlab/admin/data/policies/{pid}', json={'export': 'deny'})
    assert e['alice'].get(dl).get_json()['code'] == 'EXPORT_DENIED'
    ask = {'pool_id': pid, 'folder': 'home', 'path': 'result.csv', 'reason': '학회 발표 자료'}
    assert e['alice'].post('/api/vlab/me/data/requests', json=ask).status_code == 403
    e['keeper'].put(f'/api/vlab/admin/data/policies/{pid}', json={'export': 'approval', 'link_hours': 2})
    assert e['alice'].get(dl).get_json()['code'] == 'APPROVAL_REQUIRED'
    assert e['alice'].post('/api/vlab/me/data/requests', json=dict(ask, reason='')).status_code == 400
    assert e['alice'].post('/api/vlab/me/data/requests', json=dict(ask, path='../bob/secret.txt')).status_code == 400
    r = e['alice'].post('/api/vlab/me/data/requests', json=ask)
    assert r.status_code == 201, r.get_json()
    req = r.get_json()['request']
    assert req['status'] == 'pending' and req['size'] == 8 and 'token_hash' not in req
    assert e['alerts'] == ['data_export_request']
    assert e['alice'].post('/api/vlab/me/data/requests', json=ask).get_json()['code'] == 'PENDING'
    assert e['alice'].post(f"/api/vlab/me/data/requests/{req['id']}/link").get_json()['code'] == 'NOT_APPROVED'
    (p,) = e['keeper'].get('/api/vlab/admin/data/requests?status=pending').get_json()['requests']
    assert p['id'] == req['id'] and p['pool'] == 'AI 연구'
    assert e['bob'].post(f"/api/vlab/admin/data/requests/{req['id']}/approve", json={}).status_code == 403
    r = e['keeper'].post(f"/api/vlab/admin/data/requests/{req['id']}/approve", json={'note': 'ok'})
    assert r.status_code == 200 and r.get_json()['request']['status'] == 'approved'
    assert e['keeper'].post(f"/api/vlab/admin/data/requests/{req['id']}/reject", json={'note': 'x'}).status_code == 409
    assert e['bob'].post(f"/api/vlab/me/data/requests/{req['id']}/link").status_code == 404
    link = e['alice'].post(f"/api/vlab/me/data/requests/{req['id']}/link").get_json()
    assert link['url'].startswith('/api/vlab/data/links/')
    assert e['bob'].get(link['url']).status_code == 404                          # the requester only
    r = e['alice'].get(link['url'])
    assert r.status_code == 200 and r.data == b'a,b\n1,2\n'
    assert e['alice'].get(link['url']).get_json()['code'] == 'USED'               # once
    assert e['alice'].get(link['url'], headers={'Range': 'bytes=4-'}).status_code == 206     # a broken download goes on
    assert e['alice'].post(f"/api/vlab/me/data/requests/{req['id']}/link").get_json()['code'] == 'USED'
    rows = dsm.transfers(direction='download')
    assert rows and all(x['request_id'] == req['id'] for x in rows)
    # an expired approval does not open
    r2 = dsm.create_request('alice', pid, '', 'home', 'result.csv', 8, 'again')
    dsm.approve(r2['id'], 'keeper', 1)
    dsm.db().execute("UPDATE vlab_data_requests SET expires_at = '2020-01-01T00:00:00+00:00' WHERE id = ?", (r2['id'],))
    tok = dsm.issue_link(r2['id'])
    assert e['alice'].get(f'/api/vlab/data/links/{tok}').get_json()['code'] in ('EXPIRED', 'NOT_APPROVED')
    # a rejection says why; the user may not approve their own
    r3 = e['alice'].post('/api/vlab/me/data/requests', json=dict(ask, reason='세 번째')).get_json()['request']
    assert e['keeper'].post(f"/api/vlab/admin/data/requests/{r3['id']}/reject", json={}).status_code == 400
    r = e['keeper'].post(f"/api/vlab/admin/data/requests/{r3['id']}/reject", json={'note': '개인정보 포함'})
    assert r.get_json()['request']['status'] == 'rejected' and r.get_json()['request']['note'] == '개인정보 포함'
    # allow: no request needed
    e['keeper'].put(f'/api/vlab/admin/data/policies/{pid}', json={'export': 'allow'})
    assert e['alice'].post('/api/vlab/me/data/requests', json=ask).get_json()['code'] == 'NOT_NEEDED'


def test_a_dataset_download_follows_its_own_rule(env):
    e = env
    root = e['tmp'] / 'imagenet'
    (root / 'train').mkdir(parents=True)
    (root / 'train' / 'n01.jpg').write_bytes(b'\xff\xd8jpeg')
    (root / 'LICENSE').write_text('research')
    fields, _ = dsm.validate_dataset(dict(DS, admin_path='/srv/imagenet', export='allow'))
    ds = dsm.save_dataset(None, dict(fields, admin_path=str(root)), 'keeper')
    files = e['alice'].get(f"/api/vlab/datasets/{ds['id']}/files").get_json()
    assert [x['name'] for x in files['entries']] == ['train', 'LICENSE']
    assert e['alice'].get(f"/api/vlab/datasets/{ds['id']}/files?path=../").status_code == 400
    assert e['alice'].get(f"/api/vlab/datasets/{ds['id']}/download?path=../../nas/home/bob/secret.txt").status_code == 400
    r = e['alice'].get(f"/api/vlab/datasets/{ds['id']}/download?path=train/n01.jpg")
    assert r.status_code == 200 and r.data == b'\xff\xd8jpeg'
    (row,) = dsm.transfers(direction='download')
    assert row['dataset_id'] == ds['id'] and row['path'] == 'imagenet/train/n01.jpg'
    dsm.save_dataset(ds['id'], dict(fields, admin_path=str(root), export='approval'), 'keeper')   # past the POSIX path check
    assert e['alice'].get(f"/api/vlab/datasets/{ds['id']}/download?path=LICENSE").get_json()['code'] == 'APPROVAL_REQUIRED'
    r = e['alice'].post('/api/vlab/me/data/requests', json={'dataset_id': ds['id'], 'path': 'LICENSE', 'reason': '라이선스 확인'})
    assert r.status_code == 201 and r.get_json()['request']['dataset'] == 'imagenet'
    m = e['keeper'].post(f"/api/vlab/admin/datasets/{ds['id']}/measure").get_json()['dataset']
    assert (m['size_bytes'], m['files']) == (len(b'\xff\xd8jpeg') + len('research'), 2) and m['measured_at']


def test_without_the_engine_mount_files_go_through_the_desktop(env):
    e = env
    pid = e['pool']['id']
    cfg = nas.get(pid)
    nas.save(pid, dict({k: v for k, v in cfg.items() if k != 'has_password'}, create_by='user', admin_path=''))
    g = e['guest']
    g.answers = [("-printf", (0, 'd\t4096\t1760000000.0\truns\nf\t12\t1760000000.5\tnotes.txt\nf\t3\t1.0\t.moavi-upload-x\n', ''))]
    r = e['alice'].get(f'/api/vlab/me/data/files?{_q(e)}')
    assert r.status_code == 200, r.get_json()
    assert r.get_json()['mode'] == 'agent' and [x['name'] for x in r.get_json()['entries']] == ['runs', 'notes.txt']
    script = g.runs[-1][-1]
    assert "B=/nas/home/alice" in script and 'runuser -u "$U"' in script and 'readlink -f' in script
    # a path that leaves the folder never reaches the guest
    n = len(g.runs)
    assert e['alice'].get(f'/api/vlab/me/data/files?{_q(e, path="../bob")}').status_code == 400 and len(g.runs) == n
    # the guest's own check refuses a link that points out (exit 20)
    g.answers = [("-printf", (20, '', 'outside the folder'))]
    assert e['alice'].get(f'/api/vlab/me/data/files?{_q(e, path="link")}').get_json()['code'] == 'OUTSIDE'
    # download: base64 through exec
    g.answers = [('base64 -w0', (0, 'size=5\n' + base64.b64encode(b'hello').decode(), ''))]
    r = e['alice'].get(f'/api/vlab/me/data/download?{_q(e, path="notes.txt")}')
    assert r.status_code == 200 and r.data == b'hello'
    assert dsm.transfers(direction='download')[0]['via'] == 'agent'
    g.answers = [('base64 -w0', (22, 'size=999999999\n', 'larger than 10 MB'))]
    assert e['alice'].get(f'/api/vlab/me/data/download?{_q(e, path="big.iso")}').status_code == 413
    # uploads: small only
    big = {'pool_id': pid, 'folder': 'home', 'path': '', 'name': 'a.iso', 'size': dsm.AGENT_MAX_BYTES + 1}
    assert e['alice'].post('/api/vlab/me/data/uploads', json=big).get_json()['code'] == 'TOO_BIG'
    blob = os.urandom(100_000)
    digest = hashlib.sha256(blob).hexdigest()
    g.answers = [('sha256sum', (0, f'sha256={digest}\n', ''))]
    up = e['alice'].post('/api/vlab/me/data/uploads', json=dict(big, name='w.bin', size=len(blob))).get_json()
    assert up['via'] == 'agent'
    r = e['alice'].patch(f"/api/vlab/me/data/uploads/{up['id']}", data=blob, headers=dict(OCTET, **{'Upload-Offset': '0'}))
    assert r.status_code == 201, r.get_json()
    parts = sorted(k for k in g.files if k.startswith(f"/tmp/moavi-up-{up['id']}/"))
    assert len(parts) == 3 and b''.join(g.files[k] for k in parts) == blob
    assert 'F="$R"/w.bin' in g.runs[-1][-1]
    # a hash that differs on the guest fails the upload and is logged
    g.answers = [('sha256sum', (0, 'sha256=0000\n', ''))]
    up = e['alice'].post('/api/vlab/me/data/uploads', json=dict(big, name='v.bin', size=10)).get_json()
    r = e['alice'].patch(f"/api/vlab/me/data/uploads/{up['id']}", data=b'0123456789', headers=dict(OCTET, **{'Upload-Offset': '0'}))
    assert r.get_json()['code'] == 'HASH_MISMATCH'
    assert dsm.transfers(ok=False)[0]['error'].startswith('HASH_MISMATCH')


def test_the_report_and_the_support_bundle(env):
    e = env
    dsm.log_transfer('alice', 'download', pool_id=e['pool']['id'], folder='home', path='home/alice/a', size=100, sha256='ab')
    dsm.log_transfer('alice', 'upload', pool_id=e['pool']['id'], folder='scratch', path='scratch/alice/b', size=50)
    dsm.log_transfer('bob', 'download', pool_id=e['pool']['id'], folder='home', path='home/bob/c', ok=False, error='NOT_FOUND: x')
    r = e['admin'].get('/api/vlab/admin/reports/data-transfers?days=7').get_json()
    assert r['totals']['download_bytes'] == 100 and r['totals']['upload_bytes'] == 50 and r['totals']['failed'] == 1
    assert r['by_user'][0]['username'] == 'alice' and r['by_source'][0]['name'] == 'AI 연구 · home'
    csv_text = e['admin'].get('/api/vlab/admin/reports/data-transfers?days=7&format=csv').data.decode('utf-8-sig')
    assert csv_text.splitlines()[0].startswith('at,username,direction') and 'home/alice/a' in csv_text
    from pegaprox.api import vlab_support
    from datetime import datetime, timedelta
    act = vlab_support._activity(datetime.now() - timedelta(hours=1), datetime.now() + timedelta(minutes=1))
    (fail,) = act['data_transfer_failures.json']
    assert fail['username'] == 'bob' and fail['error'].startswith('NOT_FOUND')
