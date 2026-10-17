"""MOAVI Desk shared storage (공유 저장소): the pool's NAS setting with home / project / scratch
folders (pegaprox/vlab/nas.py), and how the engine checks it through the QEMU guest agent on
connect, on a shared pool's routing, before a build job starts and on a grant
(pegaprox/api/vlab_next.py ensure_storage).
"""
import base64
import os
import re

import pytest

from pegaprox.vlab import nas, store

CID = 'cluster_1'
RES = [
    {'vmid': 300, 'node': 'pve1', 'name': 'fpga-dev-01', 'type': 'qemu', 'status': 'running', 'maxcpu': 4, 'maxmem': 8 * 1024 ** 3},
    {'vmid': 301, 'node': 'pve2', 'name': 'build-01', 'type': 'qemu', 'status': 'running', 'maxcpu': 4, 'maxmem': 8 * 1024 ** 3},
]
NFS = {'enabled': True, 'kind': 'nfs', 'server': 'nas.lab', 'share': '/export/eda'}
OUT_OK = 'uid=1501\ngid=1500\nlocal=0\nchanged=1\n'


class _Resp:
    def __init__(self, data, status=200):
        self.status_code, self._data, self.text = status, data, ''

    def json(self):
        return {'data': self._data}


class Guest:
    """The guest agent of the fake cluster: get-osinfo, exec and exec-status."""

    def __init__(self, mgr, os_id='rocky', code=0, out=OUT_OK, err=''):
        self.os_id, self.code, self.out, self.err = os_id, code, out, err
        self.runs = []
        self.agent = True
        mgr._api_get.side_effect = self.get
        mgr._api_post.side_effect = self.post

    def get(self, url, params=None):
        if not self.agent:
            return _Resp(None, 500)
        if url.endswith('/agent/get-osinfo'):
            return _Resp({'result': {'id': self.os_id}})
        if url.endswith('/agent/exec-status'):
            return _Resp({'exited': 1, 'exitcode': self.code, 'out-data': self.out, 'err-data': self.err})
        return _Resp({}, 404)

    def post(self, url, data=None):
        if not self.agent:
            return _Resp(None, 500)
        self.runs.append((url, data))
        return _Resp({'pid': 100 + len(self.runs)})

    def commands(self):
        return [d['command'] for u, d in self.runs if u.endswith('/agent/exec')]


@pytest.fixture
def env(api, seed):
    mgr = api.make_fake_manager(CID, get_vm_resources=RES,
                                get_vnc_ticket={'success': True, 'ticket': 'PVEVNC:x', 'port': '5900'})
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    bob = api.as_user(seed.user('bob', role='user'))
    return api, mgr, admin, alice, bob


def _pool(admin, ptype='dedicated', name='FPGA 개발'):
    r = admin.post('/api/vlab/admin/pools', json={'name': name, 'type': ptype, 'cluster_id': CID})
    assert r.status_code == 201, r.get_json()
    return r.get_json()['pool']


def _desk(admin, pool, vmid=300, user='alice'):
    d = admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': vmid}).get_json()['desktop']
    if user:
        admin.put(f"/api/vlab/admin/desktops/{d['id']}/assign", json={'username': user})
    return d


def _cfg(**over):
    cfg, _, err = nas.validate(dict(NFS, **over), nas.get('pool_x'))
    assert err is None, err
    return cfg


# --- the setting -------------------------------------------------------------------------

def test_validate_refuses_unsafe_values():
    cur = nas.get('pool_x')
    cfg = _cfg()
    assert cfg['folders']['home']['rule'] == 'home/{username}' and cfg['folders']['project']['enabled'] is False
    assert cfg['create_by'] == 'user' and cfg['nfs_version'] == '3' and cfg['linux_path'] == '/nas'
    for bad in ({'server': 'nas;rm -rf /'}, {'share': '/export/../etc'}, {'share': 'no-slash'},
                {'linux_path': '/etc'}, {'linux_path': '/mnt'}, {'options': 'vers=4.1'}, {'options': 'credentials=/x'},
                {'nfs_version': '2'}, {'kind': 'ftp'}, {'private': 'yes'}, {'surprise': 1},
                {'folders': {'home': {'rule': 'home/{department}'}}},             # home and scratch are the user's
                {'folders': {'project': {'rule': 'projects/{username}'}}},       # project is the team's
                {'folders': {'scratch': {'rule': '../{username}'}}},
                {'folders': {'home': {'drive': 'C'}}}, {'folders': {'scratch': {'retention_days': -1}}},
                {'folders': {k: {'enabled': False} for k in ('home', 'project', 'scratch')}},
                {'create_by': 'engine'},                                           # needs admin_path
                {'create_by': 'engine', 'admin_path': '/srv/nas', 'kind': 'smb', 'share': 'eda'}):
        _, _, err = nas.validate(dict(NFS, **bad), cur)
        assert err, bad
    _, _, err = nas.validate(dict(NFS, kind='smb', share='eda', smb_auth='service', smb_user='svc-nas'), cur)
    assert 'password' in err
    ok, pw, err = nas.validate(dict(NFS, kind='smb', share='\\eda\\', smb_auth='service', smb_user='svc-nas', smb_password='s3cret!',
                                    folders={'project': {'enabled': True, 'drive': 'q:'}}), cur)
    assert err is None and ok['share'] == 'eda' and ok['folders']['project']['drive'] == 'Q' and pw == 's3cret!'
    assert nas.validate({'enabled': False}, cur)[2] is None


def test_folders_and_paths():
    cfg = _cfg(folders={'project': {'enabled': True}})
    f = nas.folders_for(cfg, 'CORP\\alice', '전자 설계팀', 'p')
    assert f == {'home': 'home/alice', 'project': 'projects/전자_설계팀', 'scratch': 'scratch/alice'}
    assert nas.folders_for(cfg, 'alice@corp.example.com', '', 'p')['project'] == 'projects/no-department'
    with pytest.raises(ValueError):
        nas.folders_for(cfg, 'a b', '', 'p')
    assert nas.paths(cfg, {'home': 'home/alice'}) == {'home': {'linux': '/nas/home/alice', 'windows': None, 'nas': 'nas.lab:/export/eda/home/alice'}}
    smb = _cfg(kind='smb', share='eda')
    assert nas.paths(smb, {'scratch': 'scratch/alice'})['scratch'] == {'linux': '/nas/scratch/alice', 'windows': 'S:\\',
                                                                       'nas': '\\\\nas.lab\\eda\\scratch\\alice'}


def test_autofs_map_and_the_linux_script():
    cfg = _cfg(options='nconnect=4')
    master, amap = nas.autofs_files(cfg)
    assert '/nas /etc/auto.moavi --timeout=600' in master
    assert '* -fstype=nfs,vers=3,hard,nconnect=4 nas.lab:/export/eda/&' in amap
    assert 'vers=4.1,sec=krb5p' in nas.autofs_files(_cfg(nfs_version='krb5'))[1]
    assert 'sec=krb5,multiuser' in nas.autofs_files(_cfg(kind='smb', share='eda'))[1]
    folders = nas.folders_for(cfg, 'alice')
    s = nas.linux_script(cfg, 'alice', folders, users={'alice': folders}, measure=True, cleanup_days=14)
    assert '/etc/auto.moavi' in s and 'systemctl restart autofs' in s and 'echo autofs=missing' in s
    assert 'runuser -u "$U" -- mkdir -p "$P"' in s and 'exit 11' in s
    assert not re.search(r'^\s*mkdir -p "\$P"', s, re.M)        # never as root
    assert 'grep -q "^$U:" /etc/passwd' in s and 'du -sk' in s and '-mtime +14' in s and '-name "job_*"' in s
    assert nas.PROFILE_SCRIPT in s
    eng = nas.linux_script(_cfg(create_by='engine', admin_path='/srv/nas'), 'alice', folders)
    assert 'echo missing=home' in eng and 'runuser -u "$U" -- mkdir' not in eng
    prof = nas.profile_script(cfg, {'alice': folders, 'bob': nas.folders_for(cfg, 'bob')})
    assert "alice) for d in /nas/home/alice /nas/scratch/alice" in prof and 'bob)' in prof
    svc = nas.linux_script(_cfg(kind='smb', share='eda', smb_auth='service', smb_user='svc', smb_password='x'), 'alice', folders)
    assert '/etc/moavi/nas.cred' in svc and 'cat;' in svc and 'dir_mode=0700' in svc and 'x' not in svc.split('cat;')[0][-3:]


def test_windows_sign_in_script_maps_drives_in_the_users_session():
    cfg = _cfg(kind='smb', share='eda', folders={'project': {'enabled': True}})
    users = {'alice': nas.folders_for(cfg, 'alice', '설계팀'), 'bob': nas.folders_for(cfg, 'bob', '검증팀')}
    logon = nas.windows_logon_script(cfg, users)
    assert 'if /i "%USERNAME%"=="bob" (set "HOME=home\\bob" & set "PROJECT=projects\\검증팀" & set "SCRATCH=scratch\\bob")' in logon
    assert 'net use H: "\\\\nas.lab\\eda\\%HOME%" /persistent:no' in logon and 'net use P:' in logon and 'net use S:' in logon
    assert 'mkdir "\\\\nas.lab\\eda\\%HOME%"' in logon and 'mkdir "\\\\nas.lab\\eda\\%PROJECT%"' not in logon
    ps = nas.windows_script(cfg, users)
    assert 'net use' not in ps                                    # SYSTEM maps nothing itself
    assert 'exit 15' in nas.windows_script(_cfg(), users)


def test_office_folders_go_to_the_home_drive_and_c_is_hidden_only_with_them():
    cfg = _cfg(kind='smb', share='office')
    users = {'alice': nas.folders_for(cfg, 'alice')}
    assert 'User Shell Folders' not in nas.windows_logon_script(cfg, users)
    ps = nas.windows_script(cfg, users)
    assert "Remove-ItemProperty -Path $pk -Name $n" in ps and 'if ($v -eq 4)' in ps    # takes back only its own value
    cfg = dict(cfg, win_redirect=True, win_block_local=True)
    logon = nas.windows_logon_script(cfg, users)
    assert '/v "Personal" /t REG_EXPAND_SZ /d "H:\\Documents"' in logon and 'mkdir "H:\\Desktop"' in logon
    assert '{374DE290-123F-4565-9164-39C4925E467B}' in logon                        # 다운로드
    ps = nas.windows_script(cfg, users)
    assert "Set-ItemProperty -Path $pk -Name $n -Value 4 -Type DWord" in ps and 'NoViewOnDrive' in ps
    base = dict(nas.DEFAULTS, enabled=True, kind='smb', server='nas.lab', share='office')
    assert 'needs win_redirect' in nas.validate(dict(base, win_block_local=True), {})[2]
    no_home = dict(base, win_redirect=True, folders={'home': {'enabled': False}})
    assert 'needs the home folder' in nas.validate(no_home, {})[2]
    out, _, err = nas.validate(dict(base, win_redirect=True, win_block_local=True), {})
    assert err is None and out['win_redirect'] and out['win_block_local']


def test_setting_is_saved_and_the_password_never_read_back(env):
    _, _, admin, alice, _ = env
    pool = _pool(admin)
    r = admin.get(f"/api/vlab/admin/pools/{pool['id']}/storage")
    assert r.status_code == 200 and r.get_json()['storage']['enabled'] is False
    body = dict(NFS, kind='smb', share='eda', smb_auth='service', smb_user='svc-nas', smb_domain='CORP', smb_password='s3cret!')
    assert alice.put(f"/api/vlab/admin/pools/{pool['id']}/storage", json=body).status_code == 403
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/storage", json=dict(body, smb_password='')).status_code == 400
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/storage", json=body).status_code == 200
    got = admin.get(f"/api/vlab/admin/pools/{pool['id']}/storage")
    assert got.get_json()['storage']['has_password'] is True and 's3cret' not in got.get_data(as_text=True)
    row = nas.db().query_one('SELECT password_encrypted FROM vlab_pool_storage WHERE id = ?', (pool['id'],))
    assert row['password_encrypted'] and 's3cret' not in row['password_encrypted']
    assert nas.password(pool['id']) == 's3cret!'
    r = admin.put(f"/api/vlab/admin/pools/{pool['id']}/storage", json={'folders': {'scratch': {'quota_gb': 500}}})
    assert r.status_code == 200 and nas.password(pool['id']) == 's3cret!'
    assert nas.get(pool['id'])['folders']['scratch'] == dict(nas.FOLDER_DEFAULTS['scratch'], quota_gb=500)
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/storage", json={'clear_password': True}).status_code == 400
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/storage", json={'clear_password': True, 'smb_auth': 'kerberos'}).status_code == 200
    assert nas.password(pool['id']) == ''
    for path in ('/api/vlab/admin/pools', f"/api/vlab/admin/pools/{pool['id']}"):
        assert 's3cret' not in admin.get(path).get_data(as_text=True)


# --- applying it -------------------------------------------------------------------------

def test_connect_checks_once_and_the_portal_shows_the_folders(env):
    _, mgr, admin, alice, _ = env
    pool = _pool(admin, 'reset', '설계 실습')
    desk = _desk(admin, pool)
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/storage", json=dict(NFS, folders={'scratch': {'quota_gb': 1}}))
    guest = Guest(mgr, out=OUT_OK + 'usage=home:2048\nusage=scratch:2000000\n')
    r = alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'})
    assert r.status_code == 200, r.get_json()
    st = r.get_json()['storage']
    assert st['ok'] is True and st['path'] == '/nas/home/alice' and st['changed'] is True
    assert st['warnings'] == ['OVER_QUOTA'] and st['usage'] == {'home': 2048, 'scratch': 2000000}
    assert st['paths']['folders']['scratch']['nas'] == 'nas.lab:/export/eda/scratch/alice'
    assert len(guest.commands()) == 1 and guest.commands()[0][:2] == ['/bin/sh', '-c']
    assert nas.ids_of('alice')['uid'] == 1501
    alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'})
    assert len(guest.commands()) == 1                            # fresh: the guest is left alone
    mine = alice.get('/api/vlab/me/desktops').get_json()['desktops'][0]['storage']
    assert mine['folders']['home']['linux'] == '/nas/home/alice' and mine['data_on_nas_only'] is True
    f = alice.get('/api/vlab/me/storage').get_json()['folders']
    assert [(x['pool'], x['usage']['scratch'], x['data_on_nas_only']) for x in f] == [('설계 실습', 2000000, True)]
    a = admin.get(f"/api/vlab/admin/pools/{pool['id']}/storage").get_json()
    assert a['status']['ok'] == 1 and a['status']['warnings'] == 1 and a['results'][0]['usage']['home'] == 2048
    assert '/nas /etc/auto.moavi' in a['autofs']['/etc/auto.master.d/moavi.autofs']


def test_local_accounts_and_missing_project_folders_are_warnings(env):
    _, mgr, admin, alice, _ = env
    pool = _pool(admin)
    desk = _desk(admin, pool)
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/storage", json=dict(NFS, folders={'project': {'enabled': True}}))
    Guest(mgr, out='uid=1000\ngid=1000\nlocal=1\nmissing=project\nautofs=missing\nchanged=0\n')
    st = alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'}).get_json()['storage']
    assert st['ok'] is True and st['warnings'] == ['LOCAL_ACCOUNT', 'NO_AUTOFS', 'PROJECT_MISSING']
    from pegaprox.core.db import get_db
    assert get_db().conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'vlab.storage.warn'").fetchone()[0] == 1


def test_a_failure_warns_but_never_stops_the_connect(env, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    _, mgr, admin, alice, _ = env
    sent = []
    monkeypatch.setattr(nxt, '_alert', lambda title, text, data: sent.append(data['code']))
    monkeypatch.setattr(nxt, '_storage_alerted', {})
    pool = _pool(admin)
    desk = _desk(admin, pool)
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/storage", json=NFS)
    guest = Guest(mgr, code=11, out='', err='home/alice: alice may not make it (the top folder needs mode 1777)')
    r = alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'})
    assert r.status_code == 200 and r.get_json()['type'] == 'vnc'
    st = r.get_json()['storage']
    assert st['ok'] is False and st['code'] == 'FOLDER_DENIED' and '1777' in st['detail']
    guest.agent = False
    st = alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'}).get_json()['storage']
    assert st['code'] == 'NO_AGENT'
    assert sent == ['FOLDER_DENIED']                             # one alert an hour per pool
    from pegaprox.core.db import get_db
    assert get_db().conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'vlab.storage.fail'").fetchone()[0] == 2


def test_engine_makes_the_folders_on_its_own_mount_of_the_export(env, tmp_path, monkeypatch):
    _, mgr, admin, alice, _ = env
    owners = []
    monkeypatch.setattr(os, 'chown', lambda p, u, g: owners.append((os.path.relpath(p, tmp_path), u, g)), raising=False)
    pool = _pool(admin)
    desk = _desk(admin, pool)
    # saved past the API's check: on a Windows test run tmp_path is no POSIX path
    nas.save(pool['id'], dict(_cfg(create_by='engine', admin_path='/srv/nas'), admin_path=str(tmp_path)))
    Guest(mgr, out='uid=1501\ngid=1500\nlocal=0\nmissing=home\nmissing=scratch\nchanged=0\n')
    st = alice.post(f"/api/vlab/desktops/{desk['id']}/connect", json={'protocol': 'vnc'}).get_json()['storage']
    assert st['ok'] is True and st['changed'] is True
    assert (tmp_path / 'home' / 'alice').is_dir() and (tmp_path / 'scratch' / 'alice').is_dir()
    assert sorted(o[0].replace('\\', '/') for o in owners) == ['home/alice', 'scratch/alice'] and owners[0][1:] == (1501, 1500)
    # a grant later makes bob's folders at once when a guest told the engine his ids
    nas.remember_ids('bob', 1502, 1500, False)
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/grants", json={'grants': [{'subject_type': 'user', 'subject_id': 'bob'}]})
    assert (tmp_path / 'home' / 'bob').is_dir()


def test_windows_desktop_gets_the_sign_in_script_for_each_user(env):
    _, mgr, admin, alice, bob = env
    pool = _pool(admin, 'shared', '공유 데스크톱')
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/grants", json={'grants': [
        {'subject_type': 'user', 'subject_id': 'alice'}, {'subject_type': 'user', 'subject_id': 'bob'}]})
    _desk(admin, pool, user=None)
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/storage", json=dict(NFS, kind='smb', share='eda'))
    guest = Guest(mgr, os_id='mswindows', out='changed=1\r\n')
    r = alice.post(f"/api/vlab/me/pools/{pool['id']}/route")
    assert r.status_code == 200, r.get_json()
    st = r.get_json()['storage']
    assert st['path'] == 'H:\\' and st['os'] == 'windows' and st['warnings'] == ['AT_SIGN_IN']
    bob.post(f"/api/vlab/me/pools/{pool['id']}/route")
    cmd = guest.commands()[-1]
    assert cmd[0] == 'powershell.exe'
    logon = base64.b64decode(re.search(r"FromBase64String\('([^']+)'\)", cmd[-1]).group(1)).decode('utf-8')
    assert '"%USERNAME%"=="alice"' in logon and '"%USERNAME%"=="bob"' in logon     # folders kept apart


def test_build_jobs_run_as_the_user_in_scratch(env):
    _, mgr, admin, alice, _ = env
    farm = _pool(admin, 'buildfarm', 'FPGA 빌드 팜')
    admin.put(f"/api/vlab/admin/pools/{farm['id']}/grants", json={'grants': [{'subject_type': 'user', 'subject_id': 'alice'}]})
    _desk(admin, farm, vmid=301, user=None)
    admin.put(f"/api/vlab/admin/pools/{farm['id']}/storage", json=NFS)
    assert alice.get('/api/vlab/me/build-jobs').get_json()['pools'][0]['workdir'] == '/nas/scratch/alice'
    guest = Guest(mgr)
    r = alice.post('/api/vlab/me/build-jobs', json={'pool_id': farm['id'], 'name': 'zcu102', 'command': 'make bit'})
    assert r.status_code == 201, r.get_json()
    job = r.get_json()['job']
    assert job['workdir'] == f"/nas/scratch/alice/{job['id']}" and job['status'] == 'running'
    cmds = guest.commands()
    assert 'U=alice' in cmds[0][-1]                              # the check came first
    assert cmds[1] == ['runuser', '-u', 'alice', '--', '/bin/bash', '-lc',
                       f"mkdir -p /nas/scratch/alice/{job['id']} && cd /nas/scratch/alice/{job['id']} && make bit"]


def test_a_build_on_the_share_fails_clearly_when_the_check_failed(env):
    _, mgr, admin, alice, _ = env
    farm = _pool(admin, 'buildfarm', 'FPGA 빌드 팜')
    admin.put(f"/api/vlab/admin/pools/{farm['id']}/grants", json={'grants': [{'subject_type': 'user', 'subject_id': 'alice'}]})
    _desk(admin, farm, vmid=301, user=None)
    admin.put(f"/api/vlab/admin/pools/{farm['id']}/storage", json=NFS)
    guest = Guest(mgr, code=10, out='', err='mount.nfs: Connection timed out')
    job = alice.post('/api/vlab/me/build-jobs', json={'pool_id': farm['id'], 'name': 'x', 'command': 'make'}).get_json()['job']
    assert job['status'] == 'failed' and 'MOUNT_FAILED' in job['error']
    job = alice.post('/api/vlab/me/build-jobs', json={'pool_id': farm['id'], 'name': 'y', 'command': 'make', 'workdir': '/proj'}).get_json()['job']
    assert job['status'] == 'running' and guest.commands()[-1] == ['/bin/bash', '-lc', 'cd /proj && make']


def test_check_applies_it_on_running_vms_and_the_support_bundle_has_it(env):
    _, mgr, admin, alice, _ = env
    pool = _pool(admin)
    _desk(admin, pool)
    assert admin.post(f"/api/vlab/admin/pools/{pool['id']}/storage/check").status_code == 409     # off
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/storage", json=NFS)
    guest = Guest(mgr, out='uid=1501\ngid=1500\nlocal=0\nchanged=0\n')
    assert alice.post(f"/api/vlab/admin/pools/{pool['id']}/storage/check").status_code == 403
    r = admin.post(f"/api/vlab/admin/pools/{pool['id']}/storage/check")
    assert r.status_code == 200, r.get_json()
    assert [(c['desktop'], c['username'], c['ok'], c['changed']) for c in r.get_json()['checked']] == [('fpga-dev-01', 'alice', True, False)]
    assert 'du -sk' in guest.commands()[0][-1]                   # a check measures
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/storage/check")
    assert len(guest.commands()) == 2
    from pegaprox.api import vlab_support
    rows = vlab_support._storage_rows()
    assert rows[0]['username'] == 'alice' and rows[0]['ok'] is True
    assert vlab_support._pool_storage()[pool['id']]['server'] == 'nas.lab'


def test_pool_delete_forgets_the_setting(env):
    _, _, admin, _, _ = env
    pool = _pool(admin)
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/storage", json=NFS)
    assert admin.delete(f"/api/vlab/admin/pools/{pool['id']}").status_code == 200
    assert nas.get(pool['id'])['enabled'] is False and store.get_pool(pool['id']) is None
