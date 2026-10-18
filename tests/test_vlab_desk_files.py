# -*- coding: utf-8 -*-
"""The portal's 파일 panel (pegaprox/api/vlab_desk_files.py): files into and out of the user's own
desktop through the guest agent. The guest is simulated: a small file tree, the agent's exec
(the scripts' operation is recognised, their stdin read) and file-write."""
import base64
import hashlib
import io

import pytest

from pegaprox.api import vlab_desk_files as df
from pegaprox.vlab import store

CID = 'cluster_1'
RES = [{'vmid': 300, 'node': 'pve1', 'name': 'win-01', 'type': 'qemu', 'status': 'running',
        'cpu': 0.1, 'maxcpu': 4, 'mem': 2 * 1024 ** 3, 'maxmem': 8 * 1024 ** 3}]


# --- paths -------------------------------------------------------------------------------

@pytest.mark.parametrize('bad', ['..', 'a/../b', '/etc/passwd', 'C:/Windows', 'c:x', 'a\\..\\b', 'CON', 'con.txt', 'lpt1',
                                 'a:b', 'x.', ' x', 'x ', 'a\x00b', 'a\nb', 'q?.txt', 'big.moavi-part', '/'.join(['a'] * 40)])
def test_paths_that_would_leave_the_root_are_refused(bad):
    assert df.safe_rel(bad) is None


def test_good_paths_are_normalised():
    assert df.safe_rel('') == '' and df.safe_rel('/') is None
    assert df.safe_rel('보고서/2026 결과.xlsx') == '보고서/2026 결과.xlsx'
    assert df.safe_rel('a//b/') == 'a/b' and df.safe_rel('a\\b') == 'a/b'
    assert df.safe_name('console.log') == 'console.log'          # only the device name itself is reserved


def test_guest_scripts_take_their_arguments_on_stdin_and_stay_in_the_root():
    sh, ps = df.guest_script('linux', 'delete'), df.guest_script('windows', 'delete')
    assert 'read -r U; read -r P64' in sh and 'realpath -e' in sh and 'runuser -u "$U"' in sh and '/MOAVI' in sh
    assert '[Console]::In.ReadLine()' in ps and 'Win32_UserProfile' in ps and 'ReparsePoint' in ps and 'Desktop\\MOAVI' in ps
    assert 'setowner' in df.guest_script('windows', 'mkdir')


# --- a simulated desktop ---------------------------------------------------------------------

class Guest:
    def __init__(self):
        self.files = {}          # rel -> bytes
        self.dirs = {''}
        self.pieces = {}         # piece path -> bytes
        self.runs = []
        self.blocked = False

    def op_of(self, script):
        for os_ in ('linux', 'windows'):
            for op in df._SH_OPS:
                if script == df.guest_script(os_, op).split(' ', 0)[0] or script.endswith(df.guest_script(os_, op)[-200:]):
                    return op
        raise AssertionError('unknown script')

    def run(self, mgr, node, vmid, command, stdin=None, wait=0):
        if self.blocked:
            return None, '', '', 'Agent error: Command guest-exec has been disabled: the command is not allowed'
        op = self.op_of(command[-1])
        user, p64, arg = (stdin or '\n\n\n').split('\n')[:3]
        rel = base64.b64decode(p64).decode('utf-8')
        self.runs.append((op, user, rel, arg, command))
        parent = rel.rsplit('/', 1)[0] if '/' in rel else ''
        if op == 'list':
            if rel not in self.dirs:
                return 24, '', '', ''
            out = []
            for d in sorted(self.dirs):
                if d and (d.rsplit('/', 1)[0] if '/' in d else '') == rel:
                    out.append(f"d\t0\t1700000000\t{d.rsplit('/', 1)[-1]}")
            for f, data in sorted(self.files.items()):
                if (f.rsplit('/', 1)[0] if '/' in f else '') == rel:
                    out.append(f"f\t{len(data)}\t1700000000\t{f.rsplit('/', 1)[-1]}")
            return 0, '\0'.join(out) + '\0', '', ''
        if op == 'stat':
            return (0, f'{len(self.files[rel])}\n', '', '') if rel in self.files else (24, '', '', '')
        if op == 'read':
            off, n = (int(x) for x in arg.split())
            return 0, base64.b64encode(self.files[rel][off:off + n]).decode(), '', ''
        if op == 'mkdir':
            if parent not in self.dirs:
                return 24, '', '', ''
            if rel in self.dirs or rel in self.files:
                return 23, '', '', ''
            self.dirs.add(rel)
            return 0, '', '', ''
        if op == 'delete':
            self.files = {k: v for k, v in self.files.items() if k != rel and not k.startswith(rel + '/')}
            self.dirs = {d for d in self.dirs if d != rel and not d.startswith(rel + '/')}
            return 0, '', '', ''
        if op == 'up-start':
            if parent not in self.dirs:
                return 24, '', '', ''
            if rel in self.files:
                return 23, '', '', ''
            self.files[rel + df.PART_SUFFIX] = b''
            return 0, '', '', ''
        if op == 'up-join':
            mine = sorted(k for k in self.pieces if arg in k)
            self.files[rel + df.PART_SUFFIX] += b''.join(self.pieces.pop(k) for k in mine)
            return 0, '', '', ''
        if op == 'up-finish':
            data = self.files.pop(rel + df.PART_SUFFIX)
            self.files[rel] = data
            return 0, f'sha256={hashlib.sha256(data).hexdigest()}\n', '', ''
        if op == 'up-abort':
            self.files.pop(rel + df.PART_SUFFIX, None)
            return 0, '', '', ''
        raise AssertionError(op)

    def api_post(self, url, data=None, **kw):
        assert url.endswith('/agent/file-write')

        class R:
            status_code = 200
            text = ''
        self.pieces[data['file']] = base64.b64decode(data['content'])
        return R()


@pytest.fixture
def env(api, seed, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    mgr = api.make_fake_manager(CID, get_vm_resources=RES)
    mgr.is_connected = True
    guest = Guest()
    mgr._api_post.side_effect = guest.api_post
    api.set_manager(CID, mgr)
    monkeypatch.setattr(nxt, '_agent_run', guest.run)
    monkeypatch.setattr(nxt, '_guest_os', lambda *a: 'windows')
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    bob = api.as_user(seed.user('bob', role='user'))
    pool = store.create_pool('사무실', 'dedicated', CID)
    d = store.add_desktop(store.get_pool(pool['id']), 'pve1', 300, 'win-01')
    store.set_assignment(d['id'], 'alice')
    return api, guest, admin, alice, bob, pool, d


def _policy(admin, pool, **kw):
    r = admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json=kw)
    assert r.status_code == 200, r.get_json()


def _upload(client, d, data, name='a.bin', path='', part=df.PART_MAX):
    base = f"/api/vlab/me/desktops/{d['id']}/files/uploads"
    r = client.post(base, json={'path': path, 'name': name, 'size': len(data)})
    if r.status_code != 201:
        return r
    uid = r.get_json()['upload_id']
    for off in range(0, len(data), part):
        chunk = data[off:off + part]
        r = client.patch(f'{base}/{uid}', data=chunk, headers={'Upload-Offset': str(off), 'Content-Type': 'application/offset+octet-stream'})
        assert r.status_code == 200, r.get_json()
    return client.post(f'{base}/{uid}/finish')


# --- policy and access -------------------------------------------------------------------------

def test_off_by_default_and_only_for_the_desktops_own_user(env):
    _, guest, admin, alice, bob, pool, d = env
    url = f"/api/vlab/me/desktops/{d['id']}/files"
    r = alice.get(url)
    assert r.status_code == 403 and r.get_json()['code'] == 'OFF'
    _policy(admin, pool, desktop_files='both')
    assert alice.get(url).status_code == 200
    assert bob.get(url).status_code == 404                     # not his desktop
    assert admin.get(url).status_code == 404                   # an administrator does not reach her files here
    assert guest.runs[-1][1] == 'alice'                          # the guest steps run for her account


def test_directions_follow_the_policy(env):
    _, guest, admin, alice, _, pool, d = env
    base = f"/api/vlab/me/desktops/{d['id']}/files"
    _policy(admin, pool, desktop_files='down')
    assert _upload(alice, d, b'x').status_code == 403
    assert alice.post(f'{base}/mkdir', json={'path': 'new'}).status_code == 403
    guest.files['r.txt'] = b'hello'
    assert alice.delete(f'{base}?path=r.txt').status_code == 403
    assert alice.get(f'{base}/download?path=r.txt').data == b'hello'
    _policy(admin, pool, desktop_files='up')
    assert alice.get(f'{base}/download?path=r.txt').status_code == 403
    assert _upload(alice, d, b'x').status_code == 200


def test_size_cap_and_daily_quota(env):
    _, guest, admin, alice, _, pool, d = env
    _policy(admin, pool, desktop_files='both', desktop_files_max_mb=1, desktop_files_day_mb=2)
    r = _upload(alice, d, b'0' * (1024 * 1024 + 1))
    assert r.status_code == 413 and r.get_json()['code'] == 'TOO_BIG'
    assert _upload(alice, d, b'1' * 1024 * 1024, name='one.bin').status_code == 200
    assert _upload(alice, d, b'2' * 1024 * 1024, name='two.bin').status_code == 200
    r = _upload(alice, d, b'3', name='three.bin')
    assert r.status_code == 409 and r.get_json()['code'] == 'QUOTA'
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'desktop_files': 'sideways'}).status_code == 400


# --- moving files ----------------------------------------------------------------------------

def test_upload_in_parts_lands_whole_and_is_logged(env):
    _, guest, admin, alice, _, pool, d = env
    _policy(admin, pool, desktop_files='both')
    data = bytes(range(256)) * 1000                             # 256 000 bytes: several pieces, two parts
    r = _upload(alice, d, data, name='데이터.bin', part=200_000)
    assert r.status_code == 200, r.get_json()
    assert r.get_json()['sha256'] == hashlib.sha256(data).hexdigest()
    assert guest.files['데이터.bin'] == data and not guest.pieces
    joins = [x for x in guest.runs if x[0] == 'up-join']
    assert len(joins) == 2                                       # one join per part, not per piece
    assert all('데이터' not in ' '.join(x[4]) for x in guest.runs)   # the path never on a command line
    row = df.db().query_one("SELECT * FROM vlab_desktop_file_log WHERE direction = 'up'")
    assert row['username'] == 'alice' and row['size'] == len(data) and row['result'] == 'ok'
    # the same name again: refused, nothing overwritten
    r = alice.post(f"/api/vlab/me/desktops/{d['id']}/files/uploads", json={'path': '', 'name': '데이터.bin', 'size': 1})
    assert r.status_code == 409 and r.get_json()['code'] == 'EXISTS'


def test_an_upload_part_must_follow_on(env):
    _, guest, admin, alice, bob, pool, d = env
    _policy(admin, pool, desktop_files='both')
    base = f"/api/vlab/me/desktops/{d['id']}/files/uploads"
    uid = alice.post(base, json={'path': '', 'name': 'x.bin', 'size': 10}).get_json()['upload_id']
    hdr = {'Content-Type': 'application/offset+octet-stream'}
    r = alice.patch(f'{base}/{uid}', data=b'12345', headers=dict(hdr, **{'Upload-Offset': '3'}))
    assert r.status_code == 409 and r.get_json()['received'] == 0
    assert alice.post(f'{base}/{uid}/finish').status_code == 409          # not complete
    assert bob.patch(f'{base}/{uid}', data=b'1', headers=dict(hdr, **{'Upload-Offset': '0'})).status_code == 404
    assert alice.delete(f'{base}/{uid}').status_code == 200
    assert 'x.bin' + df.PART_SUFFIX not in guest.files


def test_download_streams_in_reads_and_list_mkdir_delete(env, monkeypatch):
    _, guest, admin, alice, _, pool, d = env
    _policy(admin, pool, desktop_files='both')
    monkeypatch.setattr(df, 'READ_CHUNK', 1000)
    base = f"/api/vlab/me/desktops/{d['id']}/files"
    assert alice.post(f'{base}/mkdir', json={'path': '결과'}).status_code == 201
    assert alice.post(f'{base}/mkdir', json={'path': '결과'}).status_code == 409
    guest.files['결과/r.csv'] = b'a,b\n' * 700
    listed = alice.get(f'{base}?path=결과').get_json()
    assert listed['entries'] == [{'name': 'r.csv', 'kind': 'file', 'size': 2800, 'mtime': 1700000000}]
    assert [e['name'] for e in alice.get(base).get_json()['entries']] == ['결과']
    r = alice.get(f'{base}/download?path=결과/r.csv')
    assert r.status_code == 200 and r.data == b'a,b\n' * 700 and r.headers['Content-Length'] == '2800'
    assert "filename*=UTF-8''r.csv" in r.headers['Content-Disposition']
    assert len([x for x in guest.runs if x[0] == 'read']) == 3              # 2800 bytes in 1000-byte reads
    assert df.db().query_one("SELECT * FROM vlab_desktop_file_log WHERE direction = 'down'")['result'] == 'ok'
    assert alice.get(f'{base}?path=../etc').status_code == 400
    assert alice.delete(f'{base}?path=').status_code == 400                # never the root
    assert alice.delete(f'{base}?path=결과').status_code == 200 and '결과/r.csv' not in guest.files


def test_a_blocked_guest_agent_says_so(env):
    _, guest, admin, alice, _, pool, d = env
    _policy(admin, pool, desktop_files='both')
    guest.blocked = True
    r = alice.get(f"/api/vlab/me/desktops/{d['id']}/files")
    assert r.status_code == 409 and r.get_json()['code'] == 'AGENT_EXEC_DISABLED' and 'guest-file' in r.get_json()['error']


def test_a_desktop_without_the_users_account(env):
    _, guest, admin, alice, _, pool, d = env
    _policy(admin, pool, desktop_files='both')
    real = guest.run
    guest.run = lambda *a, **k: (3, '', 'no profile', '')
    import pegaprox.api.vlab_next as nxt
    nxt._agent_run = guest.run
    r = alice.get(f"/api/vlab/me/desktops/{d['id']}/files")
    assert r.status_code == 409 and r.get_json()['code'] == 'NO_ACCOUNT' and "'alice'" in r.get_json()['error']
    nxt._agent_run = real
