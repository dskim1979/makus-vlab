# -*- coding: utf-8 -*-
"""MOAVI Desk Warpgate 접근 게이트웨이(bastion) (pegaprox/api/vlab_warpgate.py,
pegaprox/vlab/warpgate.py): 관리자 설정(토큰 봉인), 데스크톱 접속 시 그 사용자+그 대상에만
쓸 수 있는 1회용·단시간 티켓 발급과 접속 좌표 반환. 사용자 비밀번호는 저장·전달하지 않는다.

Warpgate 관리자 API는 wg._api를 가로채 흉내낸다(네트워크 없음)."""
import json
import re

import pytest

from pegaprox.vlab import store
from pegaprox.vlab import warpgate as wg

CID = 'cluster_1'
RES = [{'vmid': 300, 'node': 'pve1', 'name': 'win-01', 'type': 'qemu', 'status': 'running',
        'cpu': 0.1, 'maxcpu': 4, 'mem': 2 * 1024 ** 3, 'maxmem': 8 * 1024 ** 3}]


# --- pure helpers ------------------------------------------------------------------------

def test_target_options_never_carry_a_user_password():
    # SSH: Warpgate 공개키, RDP: interactive_logon(자동 로그인 안 함), VNC: None 인증
    assert wg.ssh_target_options('10.0.0.5', 22, 'moavi')['auth'] == {'kind': 'PublicKey'}
    rdp = wg.rdp_target_options('10.0.0.5', 3389, 'svc', 'nlapw')
    assert rdp['interactive_logon'] is True and rdp['auth'] == {'kind': 'Password', 'password': 'nlapw'}
    assert wg.vnc_target_options('10.0.0.5', 5900)['auth'] == {'kind': 'None'}
    assert wg.vnc_target_options('10.0.0.5', 5900, 'v')['auth'] == {'kind': 'Password', 'password': 'v'}


def test_ticket_login_and_coordinates():
    assert wg.ticket_login('SEC') == 'ticket-SEC'
    cfg = {'base_url': 'https://wg.example:443', 'ssh_port': 2222, 'rdp_port': 3389, 'vnc_port': 5900}
    c = wg.connection_coordinates(cfg, 'rdp', 'moavi-x', 'SEC')
    assert c['username'] == 'ticket-SEC' and c['full_address'] == 'wg.example:3389'
    # browser = Warpgate's web UI, never the ticket (Warpgate opens no web session from a ticket
    # for an RDP/SSH target - checked against a live Warpgate)
    assert c['browser_url'] == 'https://wg.example:443/@warpgate#/' and 'SEC' not in c['browser_url']
    assert wg.connection_coordinates(cfg, 'ssh', 'moavi-x', 'SEC')['ssh'] == 'ssh ticket-SEC@wg.example -p 2222'


def test_target_name_is_stable_and_safe():
    assert wg.target_name_for('dsk_1', '윈도우 PC!') == 'moavi-pc-dsk_1'


# --- a fake Warpgate admin API -----------------------------------------------------------

class FakeWarpgate:
    """wg._api를 대신한다. (method, path)로 라우팅하고 호출을 기록한다."""

    def __init__(self):
        self.calls = []
        self.targets = {}   # name -> uuid
        self.users = {}     # username -> uuid
        self.roles = {}     # name -> uuid
        self.next = 1
        self.tickets = []
        self.keys = {}      # uid -> [ {id,label,openssh_public_key} ]
        self.kinds = {}     # target uuid -> options.kind
        self.known_hosts = []
        self.sso = {}       # uid -> [ {id, provider, email} ]
        self.user_desc = {}     # uid -> description
        self.admin_roles = {}   # uid -> [ {id, name} ]
        self.user_roles = {}    # uid -> [role uuid]

    def _id(self, p):
        self.next += 1
        return f'{p}-{self.next:04d}'

    def __call__(self, method, path, token, base_url, verify_tls, body=None, timeout=15):
        self.calls.append((method, path, body))
        assert token == 'secret-admin-token' and base_url == 'https://wg.example'
        if method == 'GET' and path == '/targets':
            return 200, [{'id': v, 'name': k} for k, v in self.targets.items()]
        if method == 'GET' and path == '/roles':
            return 200, [{'id': v, 'name': k} for k, v in self.roles.items()]
        if method == 'GET' and path == '/users':
            return 200, [{'id': v, 'username': k, 'description': self.user_desc.get(v, '')}
                         for k, v in self.users.items()]
        m = re.match(r'^/users/([^/]+)/admin-roles$', path)
        if m and method == 'GET':
            return 200, list(self.admin_roles.get(m.group(1), []))
        m = re.match(r'^/users/([^/]+)/roles(?:/([^/]+))?$', path)
        if m:
            uid, rid = m.group(1), m.group(2)
            have = self.user_roles.setdefault(uid, [])
            if method == 'GET' and not rid:
                return 200, [{'id': r, 'name': next((k for k, v in self.roles.items() if v == r), '')} for r in have]
            if method == 'POST':
                if body is None:
                    return 400, 'ExpectContentType'        # the real API wants a JSON body here
                if rid not in have:
                    have.append(rid)
                return 201, {}
            if method == 'DELETE':
                self.user_roles[uid] = [r for r in have if r != rid]
                return 204, ''
        if method == 'POST' and path == '/roles':
            uid = self.roles.setdefault(body['name'], self._id('role'))
            return 201, {'id': uid, 'name': body['name']}
        if method == 'POST' and path == '/users':
            if body['username'] in self.users:
                return 409, 'exists'
            uid = self.users[body['username']] = self._id('user')
            self.user_desc[uid] = body.get('description', '')
            return 201, {'id': uid, 'username': body['username']}
        if method == 'POST' and path == '/targets':
            if body['name'] in self.targets:          # like the real API
                return 409, 'Name already exists'
            uid = self.targets[body['name']] = self._id('tgt')
            self.kinds[uid] = body['options']['kind']
            return 201, {'id': uid, 'name': body['name']}
        if method == 'POST' and re.match(r'^/users/[^/]+/roles/[^/]+$', path) and body is None:
            return 400, 'ExpectContentType'                # the real API wants a JSON body here
        if method == 'POST' and path.endswith('/roles') or '/roles/' in path:
            return 201, {}
        if method == 'POST' and path == '/tickets':
            self.tickets.append(body)
            return 201, {'ticket': {'id': self._id('tk'), 'username': body['username']},
                         'secret': 'TKT-SECRET-123'}
        if method == 'GET' and path.startswith('/targets/'):
            uid = path.rsplit('/', 1)[1]
            names = [k for k, v in self.targets.items() if v == uid]
            if not names:
                return 404, 'not found'
            return 200, {'id': uid, 'name': names[0], 'options': {'kind': self.kinds.get(uid, 'Ssh'), 'host': 'h'}}
        if method == 'PUT' and path.startswith('/targets/'):
            uid = path.rsplit('/', 1)[1]
            if self.kinds.get(uid, body['options']['kind']) != body['options']['kind']:
                return 400, 'cannot change the target kind'     # like the real API
            self.kinds[uid] = body['options']['kind']
            self.targets = {(body['name'] if v == uid else k): v for k, v in self.targets.items()}
            return 200, {}
        if path == '/ssh/known-hosts' and method == 'GET':
            return 200, list(self.known_hosts)
        if path == '/ssh/known-hosts' and method == 'POST':
            row = dict(body, id=self._id('kh'))
            self.known_hosts.append(row)
            return 200, row
        if path.startswith('/ssh/known-hosts/') and method == 'DELETE':
            kid = path.rsplit('/', 1)[1]
            self.known_hosts = [k for k in self.known_hosts if k['id'] != kid]
            return 204, ''
        if method == 'DELETE' and path.startswith('/targets/'):
            uid = path.rsplit('/', 1)[1]
            if uid not in self.targets.values():
                return 404, 'not found'
            self.targets = {k: v for k, v in self.targets.items() if v != uid}
            return 204, ''
        m = re.match(r'^/users/([^/]+)/credentials/sso/([^/]+)$', path)
        if m and method == 'DELETE':
            self.sso[m.group(1)] = [c for c in self.sso.get(m.group(1), []) if c['id'] != m.group(2)]
            return 204, ''
        m = re.match(r'^/users/([^/]+)/credentials/sso$', path)
        if m:
            lst = self.sso.setdefault(m.group(1), [])
            if method == 'GET':
                return 200, list(lst)
            row = dict(body, id=self._id('sso'))
            lst.append(row)
            return 201, row
        # public-key credentials: /users/<uid>/credentials/public-keys[/<id>]
        m = re.match(r'^/users/([^/]+)/credentials/public-keys(?:/([^/]+))?$', path)
        if m:
            uid, kid = m.group(1), m.group(2)
            lst = self.keys.setdefault(uid, [])
            if method == 'GET':
                return 200, list(lst)
            if method == 'POST':
                row = {'id': self._id('key'), 'label': body['label'], 'openssh_public_key': body['openssh_public_key']}
                lst.append(row)
                return 201, row
            if method == 'DELETE' and kid:
                self.keys[uid] = [k for k in lst if k['id'] != kid]
                return 200, {}
        return 404, 'not found'


@pytest.fixture
def fake_wg(monkeypatch):
    fake = FakeWarpgate()
    monkeypatch.setattr(wg, '_api', fake)
    return fake


REAL_SCAN = wg.scan_host_keys
HOST_KEY = ('ssh-ed25519', 'AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyOfTheDesktop')


@pytest.fixture(autouse=True)
def no_keyscan(monkeypatch):
    """ssh-keyscan of a desktop: no network in tests."""
    scans = []

    def scan(host, port=22, timeout=5):
        scans.append((host, port))
        return [HOST_KEY]
    monkeypatch.setattr(wg, 'scan_host_keys', scan)
    return scans


@pytest.fixture
def env(api, seed):
    mgr = api.make_fake_manager(CID, get_vm_resources=RES)
    mgr.is_connected = True
    mgr._fetch_qemu_ips.return_value = ['10.0.0.31']
    api.set_manager(CID, mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    bob = api.as_user(seed.user('bob', role='user'))
    return api, mgr, admin, alice, bob


def _configure(admin, enabled=True):
    return admin.put('/api/vlab/admin/warpgate', json={
        'base_url': 'https://wg.example', 'admin_token': 'secret-admin-token',
        'ssh_port': 2222, 'rdp_port': 3389, 'vnc_port': 5900,
        'rdp_nla_user': 'moavi-nla', 'rdp_nla_password': 'nlapw', 'enabled': enabled})


# --- admin config ------------------------------------------------------------------------

def test_admin_config_seals_the_token_and_never_reads_it_back(env, db):
    _, _, admin, alice, _ = env
    assert alice.put('/api/vlab/admin/warpgate', json={'base_url': 'https://x'}).status_code == 403
    r = _configure(admin)
    assert r.status_code == 200, r.get_json()
    cfg = r.get_json()['config']
    assert cfg['enabled'] is True and cfg['has_token'] is True and cfg['has_nla_password'] is True
    assert 'admin_token' not in cfg and 'rdp_nla_password' not in cfg
    # GET도 토큰을 돌려주지 않는다
    got = admin.get('/api/vlab/admin/warpgate').get_json()['config']
    assert got['base_url'] == 'https://wg.example' and 'admin_token' not in got
    # DB에는 평문이 아니라 봉인된 값이 들어간다
    row = db.query_one('SELECT admin_token_encrypted, rdp_nla_password_encrypted FROM vlab_warpgate WHERE id = ?', ('wg',))
    assert row['admin_token_encrypted'] and 'secret-admin-token' not in row['admin_token_encrypted']
    assert row['rdp_nla_password_encrypted'] and 'nlapw' not in row['rdp_nla_password_encrypted']
    # 내부 복호화는 원래 값을 돌려준다
    assert wg.config(secret=True)['admin_token'] == 'secret-admin-token'


def test_admin_test_connection_uses_the_api(env, fake_wg):
    _, _, admin, _, _ = env
    assert admin.post('/api/vlab/admin/warpgate/test').status_code == 409   # 설정 전
    _configure(admin)
    r = admin.post('/api/vlab/admin/warpgate/test')
    assert r.status_code == 200 and r.get_json()['ok'] is True
    assert ('GET', '/targets', None) in fake_wg.calls
    assert r.get_json()['config']['last_ok'] is True


def test_sessions_link(env):
    _, _, admin, _, _ = env
    _configure(admin)
    url = admin.get('/api/vlab/admin/warpgate/sessions?session_id=abc').get_json()['url']
    assert url == 'https://wg.example/@warpgate/admin/sessions/abc'


# --- portal connect ----------------------------------------------------------------------

def _assign(pool_type='dedicated'):
    pool = store.create_pool('사무실', pool_type, CID)
    d = store.add_desktop(store.get_pool(pool['id']), 'pve1', 300, 'win-01')
    store.set_assignment(d['id'], 'alice')
    return pool, d


def test_connect_issues_a_single_use_ticket_scoped_to_user_and_target(env, fake_wg, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    _, _, admin, alice, _ = env
    _configure(admin)
    _pool, d = _assign()
    monkeypatch.setattr(nxt, '_guest_os', lambda *a: 'windows')
    monkeypatch.setattr(nxt, 'rdp_prepare', lambda *a, **k: 0)
    r = alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'rdp'})
    assert r.status_code == 200, r.get_json()
    conn = r.get_json()['connection']
    assert conn['proto'] == 'rdp' and conn['username'] == 'ticket-TKT-SECRET-123'
    assert conn['host'] == 'wg.example' and conn['port'] == 3389
    # the web link opens this desktop in Warpgate's web UI (sign-in there), never with the ticket
    assert conn['browser_url'] == f"https://wg.example/@warpgate#/web-desktop/start/{wg.get_mapping(d['id'])['target_uuid']}"
    assert 'TKT' not in conn['browser_url']
    # 티켓은 그 사용자+그 대상, 1회용, 만료시간
    t = fake_wg.tickets[-1]
    assert t['username'] == 'moavi-alice' and t['number_of_uses'] == 1 and t['expiry']
    assert t['target_name'].startswith('moavi-win-01-') and t['target_name'] == wg.get_mapping(d['id'])['target_name']
    # 대상 동기화 매핑이 저장됐다
    assert wg.get_mapping(d['id'])['proto'] == 'rdp'
    # RDP 대상에 사용자 비번은 없다(interactive_logon + NLA 서비스 계정만)
    tgt = [b for (m, p, b) in fake_wg.calls if m == 'POST' and p == '/targets'][0]
    assert tgt['options']['interactive_logon'] is True
    assert tgt['options']['auth']['password'] == 'nlapw'   # 서비스 계정, 사용자 비번 아님


def test_connect_ssh_uses_warpgate_public_key(env, fake_wg, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    _, _, admin, alice, _ = env
    _configure(admin)
    pool, d = _assign()
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'browser_ssh': True})
    monkeypatch.setattr(nxt, 'rdp_listening', lambda ip, port=3389, timeout=1.5: True)
    r = alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'ssh'})
    assert r.status_code == 200, r.get_json()
    assert r.get_json()['connection']['ssh'] == 'ssh ticket-TKT-SECRET-123@wg.example -p 2222'
    tgt = [b for (m, p, b) in fake_wg.calls if m == 'POST' and p == '/targets'][0]
    assert tgt['options']['kind'] == 'Ssh' and tgt['options']['auth'] == {'kind': 'PublicKey'}


def test_portal_status_reflects_enabled(env):
    _, _, admin, alice, _ = env
    assert alice.get('/api/vlab/me/warpgate').get_json() == {'enabled': False, 'protocols': ['rdp', 'ssh', 'vnc']}
    _configure(admin)
    assert alice.get('/api/vlab/me/warpgate').get_json()['enabled'] is True


def test_connect_is_refused_when_warpgate_is_off(env, monkeypatch):
    _, _, admin, alice, _ = env
    _configure(admin, enabled=False)
    _pool, d = _assign()
    r = alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'rdp'})
    assert r.status_code == 409 and r.get_json()['code'] == 'WG_OFF'


def test_connect_only_for_the_assigned_user(env, fake_wg):
    _, _, admin, _, bob = env
    _configure(admin)
    _pool, d = _assign()
    r = bob.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'rdp'})
    assert r.status_code == 404


def test_connect_needs_a_guest_ip(env, fake_wg, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    _, mgr, admin, alice, _ = env
    _configure(admin)
    _pool, d = _assign()
    mgr._fetch_qemu_ips.return_value = []
    monkeypatch.setattr(nxt, '_guest_os', lambda *a: 'windows')
    r = alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'rdp'})
    assert r.status_code == 409 and r.get_json()['code'] == 'NO_IP'


def test_second_connect_reuses_the_target(env, fake_wg, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    _, _, admin, alice, _ = env
    _configure(admin)
    _pool, d = _assign()
    monkeypatch.setattr(nxt, '_guest_os', lambda *a: 'windows')
    monkeypatch.setattr(nxt, 'rdp_prepare', lambda *a, **k: 0)
    alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'rdp'})
    alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'rdp'})
    posts = [p for (m, p, b) in fake_wg.calls if m == 'POST' and p == '/targets']
    puts = [p for (m, p, b) in fake_wg.calls if m == 'PUT' and p.startswith('/targets/')]
    assert len(posts) == 1 and len(puts) == 1   # 두 번째는 생성이 아니라 갱신
    assert len(fake_wg.tickets) == 2            # 티켓은 매번 새로


# --- researcher native SSH: keys, config, policy, provider -------------------------------

def test_public_key_validation_rejects_private_keys():
    assert wg.is_public_key('ssh-ed25519 AAAAC3NzaC1lZDI1 user@host') is True
    assert wg.is_public_key('ssh-rsa AAAAB3NzaC1yc2E=') is True
    assert wg.is_public_key('-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----') is False
    assert wg.is_public_key('not a key') is False and wg.is_public_key('') is False


def test_ssh_username_and_config_entry_use_warpgate_not_proxyjump():
    cfg = {'base_url': 'https://wg.example:8888', 'ssh_port': 2222}
    assert wg.ssh_username('alice', 'moavi-x') == 'moavi-alice:moavi-x'
    e = wg.ssh_config_entry(cfg, 'moavi-pc', 'alice', 'moavi-x')
    assert e['hostname'] == 'wg.example' and e['port'] == 2222 and e['user'] == 'moavi-alice:moavi-x'
    assert 'ProxyJump' not in e['config_snippet'] and 'User moavi-alice:moavi-x' in e['config_snippet']
    assert e['ssh_command'] == 'ssh moavi-pc'


def test_my_ssh_keys_add_list_delete(env, fake_wg):
    _, _, admin, alice, _ = env
    _configure(admin)
    assert alice.get('/api/vlab/me/ssh-keys').get_json()['keys'] == []
    # a private key is refused, never sent to Warpgate
    bad = alice.post('/api/vlab/me/ssh-keys', json={'openssh_public_key': '-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----'})
    assert bad.status_code == 400 and bad.get_json()['code'] == 'PRIVATE_KEY' and not any(fake_wg.keys.values())
    assert 'openssh_public_key' not in bad.get_json()['error']           # a user message, not a field name
    junk = alice.post('/api/vlab/me/ssh-keys', json={'openssh_public_key': 'hello'})
    assert junk.status_code == 400 and junk.get_json()['code'] == 'BAD_PUBLIC_KEY'
    ppk = alice.post('/api/vlab/me/ssh-keys', json={'openssh_public_key': 'PuTTY-User-Key-File-3: ssh-ed25519'})
    assert ppk.get_json()['code'] == 'PRIVATE_KEY'
    r = alice.post('/api/vlab/me/ssh-keys', json={'label': '노트북', 'openssh_public_key': 'ssh-ed25519 AAAAC3NzaC1 alice@pc'})
    assert r.status_code == 201
    keys = r.get_json()['keys']
    assert len(keys) == 1 and keys[0]['label'] == '노트북'
    assert alice.delete(f"/api/vlab/me/ssh-keys/{keys[0]['id']}").get_json()['keys'] == []


def test_ssh_config_lists_researcher_ssh_desktops(env, fake_wg):
    _, _, admin, alice, _ = env
    _configure(admin)
    # off by default
    assert alice.get('/api/vlab/me/ssh-config').get_json()['entries'] == []
    pool = store.create_pool('연구실', 'dedicated', CID)
    d = store.add_desktop(store.get_pool(pool['id']), 'pve1', 300, 'ai-box')
    store.set_assignment(d['id'], 'alice')
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'researcher_ssh': True})
    r = alice.get('/api/vlab/me/ssh-config').get_json()
    assert r['enabled'] is True and r['warpgate_host'] == 'wg.example' and r['login'] == 'moavi-alice' and r['ssh_port'] == 2222
    assert len(r['entries']) == 1
    e = r['entries'][0]
    assert e['user'] == f"moavi-alice:moavi-ai-box-{d['id']}-ssh" and e['hostname'] == 'wg.example'
    assert 'User moavi-alice:moavi-ai-box-' in r['managed_block'] and 'ProxyJump' not in r['managed_block']


def test_policy_has_researcher_ssh_toggle():
    from pegaprox.vlab import policy as pool_policy
    assert pool_policy.effective({})['researcher_ssh'] is False
    ok, err = pool_policy.validate({'researcher_ssh': True}, 'dedicated')
    assert err is None and ok['researcher_ssh'] is True
    assert pool_policy.validate({'researcher_ssh': 'yes'}, 'dedicated')[1]


def test_web_rdp_provider_is_gone_with_guacamole(env):
    """Browser RDP is 보안 게이트웨이's alone now: no provider to pick; an old console's field is ignored."""
    _, _, admin, alice, _ = env
    _configure(admin)
    assert 'web_rdp_provider' not in admin.get('/api/vlab/admin/warpgate').get_json()['config']
    assert 'web_rdp_provider' not in alice.get('/api/vlab/me/warpgate').get_json()
    r = admin.put('/api/vlab/admin/warpgate', json={'base_url': 'https://wg.example', 'ssh_port': 2222, 'rdp_port': 3389,
                                                    'vnc_port': 5900, 'enabled': True, 'web_rdp_provider': 'guac'})
    assert r.status_code == 200


def _connect_env(env, monkeypatch):
    import pegaprox.api.vlab as core
    import pegaprox.api.vlab_next as nxt
    import pegaprox.utils.rbac as rbac
    _, _, admin, alice, _ = env
    monkeypatch.setattr(core, '_acl_set', lambda *a: True)
    monkeypatch.setattr(rbac, 'user_can_access_vm', lambda *a, **k: True)
    monkeypatch.setattr(nxt, '_guest_os', lambda *a: 'windows')
    monkeypatch.setattr(nxt, 'rdp_prepare', lambda *a, **k: 0)
    pool, d = _assign()
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'protocols': ['rdp']})
    return admin, alice, d


# --- external desktops (physical PCs) through 보안 게이트웨이, or direct -------------------------

def _external(admin, user='alice'):
    from pegaprox.vlab import catalog
    return catalog.save_external(None, '측정실 PC', '10.30.5.21', 3389, user, '')


def test_external_rdp_goes_through_warpgate_when_its_switch_is_on(env, fake_wg):
    _, _, admin, alice, _ = env
    _configure(admin)
    ext = _external(admin)
    # switch off: the direct file
    r = alice.get(f"/api/vlab/me/external/{ext['id']}/rdp").get_json()
    assert 'full address:s:10.30.5.21:3389' in r['rdp'] and 'via' not in r and not fake_wg.tickets
    _rdp_on(admin)
    r = alice.get(f"/api/vlab/me/external/{ext['id']}/rdp")
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    lines = _lines(body['rdp'])
    assert body['via'] == 'warpgate' and body['filename'].endswith('.rdp')
    assert 'full address:s:wg.example:3389' in lines and 'username:s:ticket-TKT-SECRET-123' in lines
    assert '10.30.5.21' not in body['rdp'] and not any(x.startswith('gateway') for x in lines)
    tgt = [b for (m, p, b) in fake_wg.calls if m == 'POST' and p == '/targets'][0]
    assert tgt['options']['host'] == '10.30.5.21' and tgt['options']['kind'] == 'Rdp' and tgt['description'] == '측정실 PC (RDP)'
    assert fake_wg.tickets[-1]['username'] == 'moavi-alice'


def test_external_rdp_fails_closed_when_warpgate_is_down(env, fake_wg, monkeypatch):
    _, _, admin, alice, _ = env
    _configure(admin)
    _rdp_on(admin)
    ext = _external(admin)
    monkeypatch.setattr(wg, '_api', lambda *a, **k: (500, 'down'))
    r = alice.get(f"/api/vlab/me/external/{ext['id']}/rdp")
    assert r.status_code == 503 and r.get_json()['code'] == 'WG_DOWN'


def test_external_browser_rdp_is_warpgates_web_ui(env, fake_wg, monkeypatch):
    _, _, admin, alice, bob = env
    _configure(admin)
    ext = _external(admin)
    r = alice.get(f"/api/vlab/me/external/{ext['id']}/web")
    assert r.status_code == 200, r.get_json()
    uid = wg.get_mapping(ext['id'])['target_uuid']
    assert r.get_json() == {'url': f'https://wg.example/@warpgate#/web-desktop/start/{uid}', 'via': 'warpgate'}
    assert not fake_wg.tickets                                   # the browser path signs in to Warpgate itself
    assert bob.get(f"/api/vlab/me/external/{ext['id']}/web").status_code == 404
    monkeypatch.setattr(wg, '_api', lambda *a, **k: (500, 'down'))
    r = alice.get(f"/api/vlab/me/external/{ext['id']}/web")
    assert r.status_code == 503 and r.get_json()['code'] == 'WG_DOWN'


def test_an_external_desktop_given_away_or_deleted_loses_its_warpgate_target(env, fake_wg, monkeypatch):
    _, _, admin, alice, _ = env
    _configure(admin)
    real = wg.forget_desktop
    monkeypatch.setattr(wg, 'forget_desktop', lambda did, background=True: real(did, background=False))
    ext = _external(admin)
    assert alice.get(f"/api/vlab/me/external/{ext['id']}/web").status_code == 200
    uid = wg.get_mapping(ext['id'])['target_uuid']
    body = {'name': '측정실 PC', 'address': '10.30.5.21', 'assigned_user': 'bob'}
    assert admin.put(f"/api/vlab/admin/external-desktops/{ext['id']}", json=body).status_code == 200
    assert uid not in fake_wg.targets.values() and wg.get_mapping(ext['id']) is None
    assert alice.get(f"/api/vlab/me/external/{ext['id']}/web").status_code == 404
    admin.put(f"/api/vlab/admin/external-desktops/{ext['id']}", json=dict(body, assigned_user='alice'))
    assert alice.get(f"/api/vlab/me/external/{ext['id']}/web").status_code == 200
    uid = wg.get_mapping(ext['id'])['target_uuid']
    assert admin.delete(f"/api/vlab/admin/external-desktops/{ext['id']}").status_code == 200
    assert uid not in fake_wg.targets.values() and wg.get_mapping(ext['id']) is None


def test_remove_target_deletes_it_and_forgets_the_mapping(env, fake_wg):
    _, _, admin, _, _ = env
    _configure(admin)
    cfg = wg.config(secret=True)
    uid, _name = wg.sync_target(cfg, 'dsk_x', 'gone-soon', 'ssh', wg.ssh_target_options('10.0.0.9', 22, 'moavi'))
    assert wg.remove_target(cfg, 'dsk_x', 'ssh') == uid
    assert ('DELETE', f'/targets/{uid}', None) in fake_wg.calls and uid not in fake_wg.targets.values()
    assert wg.get_mapping(wg.target_ref('dsk_x', 'ssh')) is None
    assert wg.remove_target(cfg, 'dsk_x', 'ssh') is None   # nothing left to remove
    # already gone on the Warpgate side (404): the stale mapping is still dropped
    uid2, _ = wg.sync_target(cfg, 'dsk_y', 'stale', 'ssh', wg.ssh_target_options('10.0.0.8', 22, 'moavi'))
    fake_wg.targets = {}
    assert wg.remove_target(cfg, 'dsk_y', 'ssh') == uid2 and wg.get_mapping(wg.target_ref('dsk_y', 'ssh')) is None


def test_sync_adopts_an_existing_target_when_the_mapping_is_gone(env, fake_wg):
    """Found against a live Warpgate: a restored / standby DB has no mapping but Warpgate has the
    target - POST answers 409; the engine takes the existing one over instead of failing."""
    _, _, admin, _, _ = env
    _configure(admin)
    cfg = wg.config(secret=True)
    uid, name = wg.sync_target(cfg, 'dsk_r', 'restored', 'ssh', wg.ssh_target_options('10.0.0.7', 22, 'moavi'))
    wg.delete_mapping(wg.target_ref('dsk_r', 'ssh'))
    uid2, name2 = wg.sync_target(cfg, 'dsk_r', 'restored', 'ssh', wg.ssh_target_options('10.0.0.8', 22, 'moavi'))
    assert (uid2, name2) == (uid, name) and wg.get_mapping(wg.target_ref('dsk_r', 'ssh'))['address'] == '10.0.0.8'
    assert any(c[:2] == ('PUT', f'/targets/{uid}') for c in fake_wg.calls)   # brought up to date


# --- the client's / mstsc's .rdp through Warpgate ----------------------------------------

def _rdp_on(admin, on=True):
    admin.put('/api/vlab/admin/warpgate', json={'base_url': 'https://wg.example', 'ssh_port': 2222, 'rdp_port': 3389,
                                                'vnc_port': 5900, 'enabled': True, 'rdp_via_warpgate': on})


def _lines(rdp):
    return rdp.replace('\r\n', '\n').strip().split('\n')


def test_rdp_file_stays_direct_while_the_switch_is_off(env, fake_wg, monkeypatch):
    admin, alice, d = _connect_env(env, monkeypatch)
    _configure(admin)                                     # Warpgate on, "RDP through Warpgate" off
    body = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'}).get_json()
    assert body.get('via') is None and 'full address:s:10.0.0.31:3389' in _lines(body['rdp'])
    assert not fake_wg.tickets


def test_rdp_file_points_at_warpgate_with_a_single_use_ticket(env, fake_wg, monkeypatch):
    admin, alice, d = _connect_env(env, monkeypatch)
    _configure(admin)
    _rdp_on(admin)
    assert admin.get('/api/vlab/admin/warpgate').get_json()['config']['rdp_via_warpgate'] is True
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'})
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    lines = _lines(body['rdp'])
    assert body['via'] == 'warpgate' and body['filename'] == 'win-01.rdp'
    assert 'full address:s:wg.example:3389' in lines and 'username:s:ticket-TKT-SECRET-123' in lines
    assert 'enablecredsspsupport:i:0' in lines and 'prompt for credentials:i:0' in lines
    assert not any(x.startswith('password') for x in lines)               # nothing to store or leak
    assert '10.0.0.31' not in body['rdp']                                 # the desktop's address stays hidden
    assert any(x.startswith('redirectclipboard:i:') for x in lines)       # the pool policy's redirects kept
    assert 'networkautodetect:i:1' in lines
    assert [x for x in lines if x.startswith('autoreconnection')] == ['autoreconnection enabled:i:0']
    t = fake_wg.tickets[-1]
    assert t['username'] == 'moavi-alice' and t['number_of_uses'] == 1
    tgt = [b for (m, p, b) in fake_wg.calls if m == 'POST' and p == '/targets'][-1]
    assert tgt['options']['kind'] == 'Rdp' and tgt['options']['host'] == '10.0.0.31' and tgt['options']['interactive_logon'] is True


def test_rdp_file_fails_closed_when_warpgate_is_down(env, fake_wg, monkeypatch):
    admin, alice, d = _connect_env(env, monkeypatch)
    _configure(admin)
    _rdp_on(admin)
    assert admin.get('/api/vlab/admin/warpgate').get_json()['config']['allow_direct_fallback'] is False   # default
    monkeypatch.setattr(wg, '_api', lambda *a, **k: (502, 'down'))
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'})
    body = r.get_json()
    assert r.status_code == 503 and body['code'] == 'WG_DOWN' and '보안 게이트웨이' in body['error']
    assert 'rdp' not in body and '10.0.0.31' not in str(body)      # no direct .rdp around the bastion


def test_rdp_file_goes_direct_only_when_the_admin_allowed_the_fallback(env, fake_wg, monkeypatch):
    admin, alice, d = _connect_env(env, monkeypatch)
    _configure(admin)
    _rdp_on(admin)
    admin.put('/api/vlab/admin/warpgate', json={'base_url': 'https://wg.example', 'ssh_port': 2222, 'rdp_port': 3389,
                                                'vnc_port': 5900, 'enabled': True, 'allow_direct_fallback': True})
    monkeypatch.setattr(wg, '_api', lambda *a, **k: (502, 'down'))
    body = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'}).get_json()
    assert body.get('via') is None and 'full address:s:10.0.0.31:3389' in _lines(body['rdp'])


def test_allow_direct_fallback_must_be_a_boolean(env):
    _, _, admin, _, _ = env
    _configure(admin)
    r = admin.put('/api/vlab/admin/warpgate', json={'base_url': 'https://wg.example', 'allow_direct_fallback': 'yes'})
    assert r.status_code == 400


def test_rdp_via_warpgate_must_be_a_boolean(env):
    _, _, admin, _, _ = env
    _configure(admin)
    r = admin.put('/api/vlab/admin/warpgate', json={'base_url': 'https://wg.example', 'rdp_via_warpgate': 'yes'})
    assert r.status_code == 400


# --- found on the real cluster (VM 117) -------------------------------------------------

def test_b_target_ref_and_names_keep_the_protocol():
    assert wg.target_ref('dsk_1', 'rdp') == 'dsk_1'
    assert wg.target_ref('dsk_1', 'ssh') == 'dsk_1-ssh' and wg.target_ref('dsk_1', 'vnc') == 'dsk_1-vnc'
    # a long label is cut, never the ref: the RDP and SSH targets of one desktop stay apart
    long = 'x' * 80
    rdp, ssh = wg.target_name_for('dsk_0123456789ab', long), wg.target_name_for('dsk_0123456789ab-ssh', long)
    assert rdp.endswith('-dsk_0123456789ab') and ssh.endswith('-dsk_0123456789ab-ssh') and rdp != ssh
    assert len(rdp) <= 63 and len(ssh) <= 63


def test_one_desktop_gets_an_rdp_and_an_ssh_target(env, fake_wg, monkeypatch):
    """B: one target per desktop meant PUT ssh->rdp (400 from Warpgate) and then a misleading WG_DOWN."""
    import pegaprox.api.vlab_next as nxt
    _, _, admin, alice, _ = env
    _configure(admin)
    pool, d = _assign()
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'browser_ssh': True})
    monkeypatch.setattr(nxt, 'rdp_listening', lambda ip, port=3389, timeout=1.5: True)
    monkeypatch.setattr(nxt, '_guest_os', lambda *a: 'windows')
    monkeypatch.setattr(nxt, 'rdp_prepare', lambda *a, **k: 0)
    assert alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'ssh'}).status_code == 200
    r = alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'rdp'})
    assert r.status_code == 200, r.get_json()
    ssh, rdp = wg.get_mapping(wg.target_ref(d['id'], 'ssh')), wg.get_mapping(d['id'])
    assert ssh['proto'] == 'ssh' and rdp['proto'] == 'rdp' and ssh['target_uuid'] != rdp['target_uuid']
    assert fake_wg.kinds[ssh['target_uuid']] == 'Ssh' and fake_wg.kinds[rdp['target_uuid']] == 'Rdp'
    assert fake_wg.tickets[-1]['target_name'] == rdp['target_name']
    assert r.get_json()['connection']['browser_url'].endswith(f"#/web-desktop/start/{rdp['target_uuid']}")


def test_b_old_mixed_mappings_move_to_their_protocol_ref(env, fake_wg):
    """An old engine kept the SSH target under the plain desktop id; it moves to <id>-ssh and the next
    RDP sync makes a new target instead of trying to turn the SSH one into RDP."""
    _, _, admin, _, _ = env
    _configure(admin)
    cfg = wg.config(secret=True)
    wg.save_mapping('dsk_old', 'desktop', 'tgt-old', 'moavi-old-dsk_old', 'ssh', '10.0.0.4', 22)
    wg.save_mapping('dsk_rdp', 'desktop', 'tgt-rdp', 'moavi-r-dsk_rdp', 'rdp', '10.0.0.5', 3389)
    d = wg.db()
    wg._migrate_target_refs(d)
    wg._migrate_target_refs(d)          # idempotent
    assert wg.get_mapping('dsk_old') is None
    assert wg.get_mapping('dsk_old-ssh')['target_uuid'] == 'tgt-old'
    assert wg.get_mapping('dsk_rdp')['target_uuid'] == 'tgt-rdp'
    fake_wg.targets['moavi-old-dsk_old'] = 'tgt-old'
    fake_wg.kinds['tgt-old'] = 'Ssh'
    uid, name = wg.sync_target(cfg, 'dsk_old', 'old', 'rdp', wg.rdp_target_options('10.0.0.4', 3389, 'svc', 'pw'))
    assert uid != 'tgt-old' and wg.get_mapping('dsk_old')['proto'] == 'rdp' and name == 'moavi-old-dsk_old'
    # the old SSH target gave the name up: renamed to its own, options kept
    assert fake_wg.targets['moavi-old-dsk_old-ssh'] == 'tgt-old' and fake_wg.kinds['tgt-old'] == 'Ssh'
    assert wg.get_mapping('dsk_old-ssh')['target_name'] == 'moavi-old-dsk_old-ssh'
    # the SSH target is still found under its new ref and is updated in place
    uid2, name2 = wg.sync_target(cfg, 'dsk_old', 'old', 'ssh', wg.ssh_target_options('10.0.0.4', 22, 'moavi'))
    assert uid2 == 'tgt-old' and name2.endswith('-dsk_old-ssh')


def test_b_ssh_config_uses_the_synced_ssh_target_name(env, fake_wg):
    _, _, admin, alice, _ = env
    _configure(admin)
    pool = store.create_pool('연구실', 'dedicated', CID)
    d = store.add_desktop(store.get_pool(pool['id']), 'pve1', 300, 'ai-box')
    store.set_assignment(d['id'], 'alice')
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'researcher_ssh': True})
    # migrated from an old engine: the Warpgate target keeps its old name until its next sync
    wg.save_mapping(wg.target_ref(d['id'], 'ssh'), 'desktop', 'tgt-1', f"moavi-ai-box-{d['id']}", 'ssh', '10.0.0.4', 22)
    e = alice.get('/api/vlab/me/ssh-config').get_json()['entries'][0]
    assert e['user'] == f"moavi-alice:moavi-ai-box-{d['id']}"


def test_c_ssh_sync_puts_the_host_key_into_warpgate_known_hosts(env, fake_wg, no_keyscan):
    _, _, admin, _, _ = env
    _configure(admin)
    cfg = wg.config(secret=True)
    wg.sync_target(cfg, 'dsk_k', 'keys', 'ssh', wg.ssh_target_options('10.0.0.9', 22, 'moavi'))
    assert no_keyscan == [('10.0.0.9', 22)]
    assert [(k['host'], k['port'], k['key_type'], k['key_base64']) for k in fake_wg.known_hosts] == [('10.0.0.9', 22, *HOST_KEY)]
    wg.sync_target(cfg, 'dsk_k', 'keys', 'ssh', wg.ssh_target_options('10.0.0.9', 22, 'moavi'))
    assert len(fake_wg.known_hosts) == 1                  # already trusted: not added twice
    # a stale key of the same type on a reused address is replaced
    fake_wg.known_hosts[0]['key_base64'] = 'AAAAold'
    wg.sync_target(cfg, 'dsk_k', 'keys', 'ssh', wg.ssh_target_options('10.0.0.9', 22, 'moavi'))
    assert [k['key_base64'] for k in fake_wg.known_hosts] == [HOST_KEY[1]]
    # RDP targets need no host key
    wg.sync_target(cfg, 'dsk_k', 'keys', 'rdp', wg.rdp_target_options('10.0.0.9', 3389, 'svc', 'pw'))
    assert len(no_keyscan) == 3


def test_c_host_key_failure_does_not_break_the_sync(env, fake_wg, monkeypatch, caplog):
    _, _, admin, _, _ = env
    _configure(admin)
    cfg = wg.config(secret=True)

    def boom(*a, **k):
        raise OSError('connection refused')
    monkeypatch.setattr(wg, 'scan_host_keys', boom)
    uid, _ = wg.sync_target(cfg, 'dsk_n', 'nokey', 'ssh', wg.ssh_target_options('10.0.0.9', 22, 'moavi'))
    assert uid and wg.get_mapping('dsk_n-ssh')['target_uuid'] == uid
    assert 'not added to known hosts' in caplog.text
    monkeypatch.setattr(wg, 'scan_host_keys', lambda *a, **k: [])
    assert wg.sync_target(cfg, 'dsk_n', 'nokey', 'ssh', wg.ssh_target_options('10.0.0.9', 22, 'moavi'))[0] == uid


def test_c_scan_host_keys_reads_each_key_type(monkeypatch):
    """The real keyscan (paramiko) over a fake transport: one key per offered type, no duplicates."""
    import paramiko
    import socket

    class Key:
        def __init__(self, name):
            self.name = name

        def get_name(self):
            return self.name

        def get_base64(self):
            return 'B64-' + self.name

    class Opts:
        key_types = ()

    class T:
        def __init__(self, sock):
            self.opts = Opts()

        def get_security_options(self):
            return self.opts

        def start_client(self, timeout=None):
            if self.opts.key_types == ('ecdsa-sha2-nistp256',):
                raise paramiko.SSHException('no matching host key type')

        def get_remote_server_key(self):
            alg = self.opts.key_types[0]
            return Key('ssh-rsa' if alg.startswith('rsa-') else alg)

        def close(self):
            pass

    monkeypatch.setattr(socket, 'create_connection', lambda addr, timeout=None: object())
    monkeypatch.setattr(paramiko, 'Transport', T)
    assert REAL_SCAN('10.0.0.9') == [('ssh-ed25519', 'B64-ssh-ed25519'), ('ssh-rsa', 'B64-ssh-rsa')]


def test_d_unreachable_warpgate_answers_wg_down_without_the_internal_url(env, fake_wg, monkeypatch, caplog):
    import pegaprox.api.vlab_next as nxt
    from pegaprox.api.vlab_warpgate import WG_DOWN_TEXT
    _, _, admin, alice, _ = env
    _configure(admin)
    _pool, d = _assign()
    monkeypatch.setattr(nxt, '_guest_os', lambda *a: 'windows')
    monkeypatch.setattr(nxt, 'rdp_prepare', lambda *a, **k: 0)

    def down(*a, **k):
        raise ConnectionError("HTTPSConnectionPool(host='warpgate.internal', port=8888): Max retries exceeded")
    monkeypatch.setattr(wg, '_api', down)
    r = alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'rdp'})
    assert r.status_code == 503 and r.get_json() == {'error': WG_DOWN_TEXT, 'code': 'WG_DOWN'}
    assert 'warpgate.internal' in caplog.text          # the detail is in the server log only


def test_e_deleting_or_unassigning_a_desktop_removes_its_targets(env, fake_wg, monkeypatch):
    _, _, admin, _, _ = env
    _configure(admin)
    real = wg.forget_desktop
    monkeypatch.setattr(wg, 'forget_desktop', lambda did, background=True: real(did, background=False))
    cfg = wg.config(secret=True)
    _pool, d = _assign()
    rdp, _ = wg.sync_target(cfg, d['id'], d['name'], 'rdp', wg.rdp_target_options('10.0.0.3', 3389, 'svc', 'pw'))
    ssh, _ = wg.sync_target(cfg, d['id'], d['name'], 'ssh', wg.ssh_target_options('10.0.0.3', 22, 'moavi'))
    store.set_assignment(d['id'], 'alice')              # same user: nothing to do
    assert {rdp, ssh} <= set(fake_wg.targets.values())
    store.set_assignment(d['id'], None)                 # taken from alice
    assert not ({rdp, ssh} & set(fake_wg.targets.values()))
    assert wg.get_mapping(d['id']) is None and wg.get_mapping(wg.target_ref(d['id'], 'ssh')) is None
    vnc, _ = wg.sync_target(cfg, d['id'], d['name'], 'vnc', wg.vnc_target_options('10.0.0.3', 5900))
    store.remove_desktop(d['id'])
    assert vnc not in fake_wg.targets.values() and wg.list_mappings() == []


def test_e_forget_runs_off_the_request_thread_and_skips_when_off(env, fake_wg, monkeypatch):
    _, _, admin, _, _ = env
    _configure(admin, enabled=False)
    wg.save_mapping('dsk_z', 'desktop', 'tgt-z', 'n', 'rdp', '', 0)
    started = []

    class NoThread:
        def __init__(self, **k):
            started.append(k)

        def start(self):
            pass
    monkeypatch.setattr(wg.threading, 'Thread', NoThread)
    wg.forget_desktop('dsk_z')
    assert started == [] and wg.get_mapping('dsk_z')   # Warpgate off: left alone
    _configure(admin)
    wg.forget_desktop('dsk_z')
    assert len(started) == 1 and started[0]['daemon'] is True


def _alerts_env(api, seed, monkeypatch, saved):
    from pegaprox.api import alerts as alerts_api
    monkeypatch.setattr(alerts_api, 'load_cluster_alerts', lambda: saved)
    monkeypatch.setattr(alerts_api, 'save_cluster_alerts', lambda a: None)
    api.set_manager(CID, api.make_fake_manager(CID))
    return api.as_user(seed.user('root', role='admin'))


@pytest.mark.parametrize('sev', ['auto', 'critical', 'warning', 'info'])
def test_g_alert_rule_accepts_known_severities(api, seed, sev, monkeypatch):
    admin = _alerts_env(api, seed, monkeypatch, {})
    r = admin.post(f'/api/clusters/{CID}/alerts', json={'name': 'cpu', 'metric': 'cpu', 'threshold': 90, 'severity': sev})
    assert r.status_code == 200, r.get_json()
    assert r.get_json()['alert']['severity'] == sev


def test_g_alert_rule_refuses_an_unknown_severity(api, seed, monkeypatch):
    saved = {CID: [{'id': 'a1', 'name': 'cpu', 'metric': 'cpu', 'operator': '>', 'threshold': 90, 'severity': 'info',
                    'cluster_id': CID, 'target_type': 'cluster', 'channels': [], 'enabled': True}]}
    admin = _alerts_env(api, seed, monkeypatch, saved)
    for bad in ('panic', '<script>', 3, None):
        r = admin.post(f'/api/clusters/{CID}/alerts', json={'name': 'x', 'metric': 'cpu', 'severity': bad})
        assert r.status_code == 400 and 'severity' in r.get_json()['error']
        r = admin.put(f'/api/clusters/{CID}/alerts/a1', json={'severity': bad})
        assert r.status_code == 400
    assert saved[CID][0]['severity'] == 'info'
    assert admin.put(f'/api/clusters/{CID}/alerts/a1', json={'severity': 'critical'}).status_code == 200


# --- first start: auto-connect -----------------------------------------------------------

class FakeSession:
    instances = []

    def __init__(self):
        self.verify = True
        self.posts = []
        FakeSession.instances.append(self)

    def post(self, url, json=None, timeout=None, allow_redirects=None):
        self.posts.append((url, json))

        class R:
            status_code = 201
        r = R()
        r.json = lambda: {'secret': 'secret-admin-token'} if url.endswith('/api-tokens') else {}
        if url.endswith('/auth/login') and json['password'] != 'wg-admin-pw':
            r.status_code = 401
        return r


@pytest.fixture
def wg_env(monkeypatch):
    import requests
    FakeSession.instances = []
    monkeypatch.setattr(requests, 'Session', FakeSession)
    for k, v in {'VLAB_WARPGATE': '1', 'VLAB_WARPGATE_URL': 'https://wg.example/',
                 'VLAB_WARPGATE_ADMIN_PASSWORD': 'wg-admin-pw', 'VLAB_WARPGATE_RDP_PORT': '13389'}.items():
        monkeypatch.setenv(k, v)
    return monkeypatch


def test_auto_connect_at_first_start(env, fake_wg, wg_env, caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    assert wg.auto_connect() is True
    cfg = wg.config()
    assert cfg['base_url'] == 'https://wg.example' and cfg['enabled'] and cfg['has_token']
    assert (cfg['ssh_port'], cfg['rdp_port'], cfg['vnc_port']) == (2222, 13389, 5900)
    assert 'web_rdp_provider' not in cfg and cfg['last_ok'] is True
    s = FakeSession.instances[0]
    assert s.verify is False
    assert s.posts[0] == ('https://wg.example/@warpgate/api/auth/login', {'username': 'admin', 'password': 'wg-admin-pw'})
    url, body = s.posts[1]
    assert url == 'https://wg.example/@warpgate/api/profile/api-tokens' and body['label'] and body['expiry'] > '2027'
    # sealed in the DB, never logged
    row = wg._row()
    assert row['admin_token_encrypted'] and 'secret-admin-token' not in row['admin_token_encrypted']
    assert wg.config(secret=True)['admin_token'] == 'secret-admin-token'
    assert 'secret-admin-token' not in caplog.text and 'wg-admin-pw' not in caplog.text
    assert wg.auto_connect() is False and len(FakeSession.instances) == 1   # second start: nothing


def test_auto_connect_never_overwrites_and_needs_the_switch(env, fake_wg, wg_env):
    _, _, admin, _, _ = env
    wg_env.setenv('VLAB_WARPGATE', '0')
    assert wg.auto_connect() is False and wg._row() is None          # Warpgate off: nothing
    assert wg.start_auto_connect() is None
    wg_env.setenv('VLAB_WARPGATE', '1')
    wg_env.delenv('VLAB_WARPGATE_ADMIN_PASSWORD')
    assert wg.auto_connect() is False and wg._row() is None          # no password: nothing
    wg_env.setenv('VLAB_WARPGATE_ADMIN_PASSWORD', 'wg-admin-pw')
    admin.put('/api/vlab/admin/warpgate', json={'base_url': 'https://mine.example', 'admin_token': 'mine',
                                                'ssh_port': 22, 'rdp_port': 3389, 'vnc_port': 5900, 'enabled': False})
    assert wg.auto_connect() is False and FakeSession.instances == []
    assert wg.config()['base_url'] == 'https://mine.example' and wg.config(secret=True)['admin_token'] == 'mine'


def test_auto_connect_bad_password_raises_without_saving(env, wg_env):
    wg_env.setenv('VLAB_WARPGATE_ADMIN_PASSWORD', 'wrong')
    with pytest.raises(wg.WarpgateError) as e:
        wg.auto_connect()
    assert 'wrong' not in str(e.value) and wg._row() is None


def test_web_ui_links_per_protocol():
    cfg = {'base_url': 'https://wg.example/'}
    assert wg.web_ui_url(cfg) == 'https://wg.example/@warpgate#/'
    assert wg.web_ui_url(cfg, 'rdp', 'u1') == 'https://wg.example/@warpgate#/web-desktop/start/u1'
    assert wg.web_ui_url(cfg, 'vnc', 'u1') == 'https://wg.example/@warpgate#/web-desktop/start/u1'
    assert wg.web_ui_url(cfg, 'ssh', 'u1') == 'https://wg.example/@warpgate#/web-ssh/start/u1'
    assert wg.web_ui_url(cfg, 'ssh') == 'https://wg.example/@warpgate#/'


def test_remove_target_without_a_protocol_removes_every_target_of_the_desktop(env, fake_wg):
    _, _, admin, _, _ = env
    _configure(admin)
    cfg = wg.config(secret=True)
    a, _ = wg.sync_target(cfg, 'dsk_all', 'all', 'rdp', wg.rdp_target_options('10.0.0.2', 3389, 'svc', 'pw'))
    b, _ = wg.sync_target(cfg, 'dsk_all', 'all', 'ssh', wg.ssh_target_options('10.0.0.2', 22, 'moavi'))
    assert sorted(wg.remove_target(cfg, 'dsk_all')) == sorted([a, b])
    assert wg.list_mappings() == [] and not ({a, b} & set(fake_wg.targets.values()))
    assert wg.remove_target(cfg, 'dsk_all') == []


# --- Warpgate signs in with the portal session (OIDC provider, pegaprox/vlab/wg_oidc.py) ---

RETURN = 'https://wg.example/@warpgate/api/sso/return'


def _pkce():
    import base64
    import hashlib
    import secrets
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    return verifier, challenge


def _basic(cid, secret):
    import base64
    return {'Authorization': 'Basic ' + base64.b64encode(f'{cid}:{secret}'.encode()).decode()}


@pytest.fixture
def oidc_on(monkeypatch):
    monkeypatch.setenv('VLAB_WARPGATE_OIDC_SECRET', 'oidc-client-secret')
    monkeypatch.setenv('VLAB_WARPGATE_OIDC_ISSUER', 'http://vlab-engine:5000/api/vlab/oidc')
    monkeypatch.setenv('VLAB_HOSTNAME', 'vlab.example')
    monkeypatch.setenv('VLAB_HTTPS_PORT', '443')


def _authorize(client, challenge, **over):
    q = {'response_type': 'code', 'client_id': 'warpgate', 'redirect_uri': RETURN, 'scope': 'openid email profile',
         'state': 'st-1', 'nonce': 'n-1', 'code_challenge': challenge, 'code_challenge_method': 'S256'}
    q.update(over)
    return client.get('/api/vlab/oidc/authorize', query_string={k: v for k, v in q.items() if v is not None})


def test_oidc_is_off_without_a_client_secret(env, monkeypatch):
    _, _, _, alice, _ = env
    monkeypatch.delenv('VLAB_WARPGATE_OIDC_SECRET', raising=False)
    assert alice.get('/api/vlab/oidc/.well-known/openid-configuration').status_code == 404
    assert alice.post('/api/vlab/oidc/token', data={}).status_code == 404


def test_warpgate_signs_a_portal_user_in_without_a_password(env, fake_wg, oidc_on):
    import jwt
    from urllib.parse import parse_qs, urlparse
    api, _, admin, alice, _ = env
    _configure(admin)
    meta = alice.get('/api/vlab/oidc/.well-known/openid-configuration').get_json()
    assert meta['issuer'] == 'http://vlab-engine:5000/api/vlab/oidc'
    assert meta['authorization_endpoint'] == 'https://vlab.example/api/vlab/oidc/authorize'
    assert meta['token_endpoint'] == meta['issuer'] + '/token' and meta['code_challenge_methods_supported'] == ['S256']
    verifier, challenge = _pkce()
    r = _authorize(alice, challenge)
    assert r.status_code == 302, r.get_data(as_text=True)
    loc = urlparse(r.headers['Location'])
    assert f'{loc.scheme}://{loc.netloc}{loc.path}' == RETURN
    q = parse_qs(loc.query)
    assert q['state'] == ['st-1'] and q['code'][0]
    # Warpgate knows alice by her MOAVI Desk SSO credential - no password anywhere
    uid = fake_wg.users['moavi-alice']
    assert [(c['provider'], c['email']) for c in fake_wg.sso[uid]] == [('moavi-desk', 'alice@moavi-desk.invalid')]
    # Warpgate (no portal session, no browser headers) trades the code
    anon = api.anon()
    raw = api.app.test_client()
    tok = raw.post('/api/vlab/oidc/token', headers=_basic('warpgate', 'oidc-client-secret'),
                    data={'grant_type': 'authorization_code', 'code': q['code'][0], 'redirect_uri': RETURN,
                          'code_verifier': verifier})
    assert tok.status_code == 200, tok.get_json()
    t = tok.get_json()
    assert tok.headers['Cache-Control'] == 'no-store'
    keys = anon.get('/api/vlab/oidc/jwks').get_json()['keys']
    pub = jwt.PyJWK(keys[0]).key
    claims = jwt.decode(t['id_token'], pub, algorithms=['RS256'], audience='warpgate', issuer=meta['issuer'])
    assert claims['sub'] == 'alice' and claims['nonce'] == 'n-1' and claims['email'] == 'alice@moavi-desk.invalid'
    assert claims['email_verified'] is True and 'warpgate_roles' not in claims   # Warpgate keeps the user's roles
    assert jwt.get_unverified_header(t['id_token'])['kid'] == keys[0]['kid']
    ui = anon.get('/api/vlab/oidc/userinfo', headers={'Authorization': 'Bearer ' + t['access_token']}).get_json()
    assert ui['email'] == 'alice@moavi-desk.invalid' and ui['preferred_username'] == 'alice'
    # a code is single use
    again = anon.post('/api/vlab/oidc/token', headers=_basic('warpgate', 'oidc-client-secret'),
                      data={'grant_type': 'authorization_code', 'code': q['code'][0], 'redirect_uri': RETURN,
                            'code_verifier': verifier})
    assert again.status_code == 400 and again.get_json()['error'] == 'invalid_grant'
    # a second sign-in does not add the credential twice; the key stays the same
    _authorize(alice, _pkce()[1])
    assert len(fake_wg.sso[uid]) == 1
    assert anon.get('/api/vlab/oidc/jwks').get_json()['keys'][0]['kid'] == keys[0]['kid']


def test_oidc_refuses_what_is_not_warpgate(env, fake_wg, oidc_on):
    from urllib.parse import parse_qs, urlparse
    api, _, admin, alice, _ = env
    _configure(admin)
    anon = api.anon()
    verifier, challenge = _pkce()
    # not signed in to the portal: no code
    assert _authorize(anon, challenge).status_code == 401
    # an unknown client or a return URL that is not Warpgate's: no redirect at all
    assert _authorize(alice, challenge, client_id='other').status_code == 400
    assert _authorize(alice, challenge, redirect_uri='https://evil.example/@warpgate/api/sso/return').status_code == 400
    assert _authorize(alice, challenge, redirect_uri='https://wg.example/steal').status_code == 400
    # PKCE is required
    r = _authorize(alice, None)
    assert r.status_code == 302 and 'error=invalid_request' in r.headers['Location'] and 'code=' not in r.headers['Location']
    # the token endpoint wants the client secret, the right verifier and the same redirect URI
    code = parse_qs(urlparse(_authorize(alice, challenge).headers['Location']).query)['code'][0]
    data = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': RETURN, 'code_verifier': verifier}
    assert anon.post('/api/vlab/oidc/token', headers=_basic('warpgate', 'wrong'), data=data).status_code == 401
    bad = dict(data, code_verifier='x' * 50)
    assert anon.post('/api/vlab/oidc/token', headers=_basic('warpgate', 'oidc-client-secret'), data=bad).status_code == 400
    # (the failed try spent the code)
    assert anon.post('/api/vlab/oidc/token', headers=_basic('warpgate', 'oidc-client-secret'), data=data).status_code == 400
    assert anon.get('/api/vlab/oidc/userinfo', headers={'Authorization': 'Bearer nope'}).status_code == 401


def test_oidc_code_expires(env, fake_wg, oidc_on, monkeypatch):
    from pegaprox.vlab import wg_oidc
    _, _, admin, _, _ = env
    _configure(admin)
    verifier, challenge = _pkce()
    code = wg_oidc.issue_code('alice', RETURN, 'n', challenge)
    real = wg_oidc.time.time
    monkeypatch.setattr(wg_oidc.time, 'time', lambda: real() + wg_oidc.CODE_TTL + 1)
    assert wg_oidc.redeem_code(code, RETURN, verifier) is None


def test_warpgate_yaml_snippet_carries_no_secret(oidc_on):
    from pegaprox.vlab import wg_oidc
    snip = wg_oidc.warpgate_yaml_snippet()
    assert 'oidc-client-secret' not in snip and 'name: moavi-desk' in snip and 'type: custom' in snip
    assert 'issuer_url: http://vlab-engine:5000/api/vlab/oidc' in snip


# --- engine users never become Warpgate's own accounts (found live: portal 'admin' -> Warpgate superadmin) ---

def test_a_portal_user_gets_a_prefixed_managed_warpgate_user(env, fake_wg, oidc_on):
    _, _, admin, _, _ = env
    _configure(admin)
    cfg = wg.config(secret=True)
    fake_wg.users['admin'] = 'wg-superadmin'                       # Warpgate's own superadmin
    fake_wg.admin_roles['wg-superadmin'] = [{'id': 'ar-1', 'name': 'warpgate:admin'}]
    uid = wg.ensure_user(cfg, 'admin', wg.ensure_role(cfg))
    assert uid != 'wg-superadmin' and fake_wg.users['moavi-admin'] == uid
    assert fake_wg.user_desc[uid].startswith(wg.MANAGED_DESC)
    # nothing was put on Warpgate's own admin
    assert fake_wg.sso.get('wg-superadmin', []) == [] and fake_wg.user_roles.get('wg-superadmin', []) == []
    assert [c['email'] for c in fake_wg.sso[uid]] == ['admin@moavi-desk.invalid']
    # keys of the portal 'admin' go to moavi-admin too
    wg.add_user_key(cfg, 'admin', 'pc', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey admin@pc')
    assert uid in fake_wg.keys and 'wg-superadmin' not in fake_wg.keys


def test_ensure_user_refuses_a_warpgate_user_the_engine_did_not_make(env, fake_wg, oidc_on):
    _, _, admin, _, _ = env
    _configure(admin)
    cfg = wg.config(secret=True)
    fake_wg.users['moavi-bob'] = 'hand-made'                        # made by hand in Warpgate
    with pytest.raises(wg.WarpgateError):
        wg.ensure_user(cfg, 'bob', wg.ensure_role(cfg))
    assert fake_wg.sso.get('hand-made', []) == [] and fake_wg.user_roles.get('hand-made', []) == []
    with pytest.raises(wg.WarpgateError):
        wg.add_user_key(cfg, 'bob', 'pc', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey bob@pc')
    assert 'hand-made' not in fake_wg.keys


def test_ensure_user_refuses_a_managed_user_that_got_an_admin_role(env, fake_wg, oidc_on):
    _, _, admin, _, _ = env
    _configure(admin)
    cfg = wg.config(secret=True)
    uid = wg.ensure_user(cfg, 'carol')
    fake_wg.admin_roles[uid] = [{'id': 'ar-1', 'name': 'warpgate:admin'}]
    fake_wg.sso[uid] = []
    with pytest.raises(wg.WarpgateError):
        wg.ensure_user(cfg, 'carol', wg.ensure_role(cfg))
    assert fake_wg.sso[uid] == []


def test_portal_connect_refuses_when_the_warpgate_user_is_not_ours(env, fake_wg, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    _, _, admin, alice, _ = env
    _configure(admin)
    _pool, d = _assign()
    monkeypatch.setattr(nxt, '_guest_os', lambda *a: 'windows')
    monkeypatch.setattr(nxt, 'rdp_prepare', lambda *a, **k: 0)
    fake_wg.users['moavi-alice'] = 'hand-made'
    r = alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'rdp'})
    assert r.status_code == 502 and fake_wg.tickets == []


def test_oidc_sign_in_never_lands_on_a_warpgate_admin(env, fake_wg, oidc_on, seed):
    """The portal 'admin' signs in through MOAVI Desk: the SSO credential goes on moavi-admin, never on
    Warpgate's superadmin 'admin'."""
    api, _, root, _, _ = env
    _configure(root)
    admin = api.as_user(seed.user('admin', role='admin'))
    fake_wg.users['admin'] = 'wg-superadmin'
    fake_wg.admin_roles['wg-superadmin'] = [{'id': 'ar-1', 'name': 'warpgate:admin'}]
    r = _authorize(admin, _pkce()[1])
    assert r.status_code == 302 and 'code=' in r.headers['Location']
    assert fake_wg.sso.get('wg-superadmin', []) == []
    assert [c['email'] for c in fake_wg.sso[fake_wg.users['moavi-admin']]] == ['admin@moavi-desk.invalid']


def test_migration_takes_back_only_what_the_engine_put_on_old_users(env, fake_wg, oidc_on):
    _, _, admin, _, _ = env
    _configure(admin)
    cfg = wg.config(secret=True)
    role = wg.ensure_role(cfg)
    other_role = fake_wg.roles['ops'] = 'role-ops'
    # what 5216bdb and earlier left: the superadmin 'admin' and an old unprefixed 'alice'
    fake_wg.users.update({'admin': 'wg-superadmin', 'alice': 'old-alice'})
    fake_wg.sso['wg-superadmin'] = [{'id': 'c1', 'provider': 'moavi-desk', 'email': 'admin@moavi-desk.invalid'},
                                    {'id': 'c2', 'provider': 'google', 'email': 'boss@example.com'}]
    fake_wg.sso['old-alice'] = [{'id': 'c3', 'provider': 'moavi-desk', 'email': 'alice@moavi-desk.invalid'}]
    fake_wg.user_roles['wg-superadmin'] = [role, other_role]
    fake_wg.user_roles['old-alice'] = [role]
    # a managed user keeps everything
    keep = wg.ensure_user(cfg, 'dave', role)
    assert wg.migrate_legacy_users(cfg) == (2, 2)
    assert [c['id'] for c in fake_wg.sso['wg-superadmin']] == ['c2']          # only the one the engine added
    assert fake_wg.sso['old-alice'] == []
    assert fake_wg.user_roles['wg-superadmin'] == [other_role] and fake_wg.user_roles['old-alice'] == []
    assert fake_wg.user_roles[keep] == [role] and len(fake_wg.sso[keep]) == 1
    # once is enough
    fake_wg.sso['old-alice'] = [{'id': 'c9', 'provider': 'moavi-desk', 'email': 'alice@moavi-desk.invalid'}]
    assert wg.migrate_legacy_users(cfg) == (0, 0)


# --- a Windows desktop's own RDP NLA service account (moavi-nla) ---------------------------

def _configure_no_nla(admin):
    return admin.put('/api/vlab/admin/warpgate', json={
        'base_url': 'https://wg.example', 'admin_token': 'secret-admin-token',
        'ssh_port': 2222, 'rdp_port': 3389, 'vnc_port': 5900, 'enabled': True})


@pytest.fixture
def agent(monkeypatch):
    """The guest agent: records what ran and answers like the script would."""
    import pegaprox.api.vlab_next as nxt
    runs = []
    reply = {'value': (0, 'nla=ok\r\n', '', '')}

    def run(mgr, node, vmid, command, stdin=None, wait=0):
        runs.append({'vmid': vmid, 'command': command, 'stdin': stdin})
        return reply['value']
    monkeypatch.setattr(nxt, '_agent_run', run)
    return runs, reply


def test_nla_password_is_per_desktop_sealed_and_new_for_a_new_vm(env, db):
    pw = wg.nla_password('dsk_a', 300)
    assert wg.nla_password('dsk_a', 300) == pw and wg.nla_password('dsk_b', 301) != pw
    assert len(pw) >= 20 and any(c.isupper() for c in pw) and any(c.islower() for c in pw) and any(c.isdigit() for c in pw)
    row = wg.db().query_one('SELECT * FROM vlab_warpgate_nla WHERE desktop_id = ?', ('dsk_a',))
    assert row['password_encrypted'] and pw not in row['password_encrypted']
    assert wg.nla_password('dsk_a', 999) != pw                       # the VM was recreated
    wg.nla_forget('dsk_b')
    assert wg.db().query_one('SELECT * FROM vlab_warpgate_nla WHERE desktop_id = ?', ('dsk_b',)) is None


def test_nla_script_takes_the_password_on_stdin_only():
    s = wg.nla_account_script()
    assert '[Console]::In.ReadToEnd()' in s and 'moavi-nla' in s
    assert "fPromptForPassword' -Value 1" in s and 'S-1-5-32-555' in s
    assert 'DomainRole -ge 4' in s and 'PasswordNeverExpires' in s and 'SeDenyInteractiveLogonRight' in s


def test_windows_connect_sets_up_the_nla_account_and_warpgate_uses_it(env, fake_wg, agent, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    runs, _reply = agent
    _, _, admin, alice, _ = env
    _configure_no_nla(admin)
    _pool, d = _assign()
    monkeypatch.setattr(nxt, '_guest_os', lambda *a: 'windows')
    monkeypatch.setattr(nxt, 'rdp_prepare', lambda *a, **k: 0)
    r = alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'rdp'})
    assert r.status_code == 200, r.get_json()
    pw = wg.nla_password(d['id'], d['vmid'])
    assert len(runs) == 1 and runs[0]['stdin'].strip() == pw
    assert all(pw not in part for part in runs[0]['command'])       # never on the command line
    tgt = [b for (m, p, b) in fake_wg.calls if m == 'POST' and p == '/targets'][0]
    assert tgt['options']['username'] == 'moavi-nla' and tgt['options']['auth']['password'] == pw
    assert tgt['options']['interactive_logon'] is True
    assert pw not in json.dumps(r.get_json())                       # never to the user
    # the next connect does not run it again (until NLA_REAPPLY)
    alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'rdp'})
    assert len(runs) == 1


def test_a_failed_nla_setup_is_not_remembered(env, fake_wg, agent, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    from pegaprox.api import vlab_warpgate as api_wg
    runs, reply = agent
    _, mgr, admin, _, _ = env
    _configure_no_nla(admin)
    _pool, d = _assign()
    reply['value'] = (None, '', '', 'guest agent refused')
    assert api_wg.prepare_windows_nla(d, mgr, 'pve1') is False
    assert wg.nla_applied_credentials(d['id'], d['vmid']) is None
    reply['value'] = (0, 'nla=dc', '', '')                            # a domain controller: no local account
    assert api_wg.prepare_windows_nla(d, mgr, 'pve1') is False and len(runs) == 2
    reply['value'] = (0, 'nla=ok', '', '')
    assert api_wg.prepare_windows_nla(d, mgr, 'pve1') is True
    assert wg.nla_applied_credentials(d['id'], d['vmid'])[0] == 'moavi-nla'


def test_the_console_nla_account_still_wins(env, fake_wg, agent):
    from pegaprox.api import vlab_warpgate as api_wg
    runs, _reply = agent
    _, mgr, admin, _, _ = env
    _configure(admin)                                                # sets rdp_nla_user / password
    _pool, d = _assign()
    assert api_wg.prepare_windows_nla(d, mgr, 'pve1') is False and runs == []
    opts = api_wg._desktop_target_options(wg.config(secret=True), 'rdp', '10.0.0.31', d)
    assert opts['username'] == 'moavi-nla' and opts['auth']['password'] == 'nlapw'


def test_reset_and_delete_drop_the_nla_password(env, fake_wg, agent, monkeypatch):
    from pegaprox.api import vlab as core_api
    from pegaprox.api import vlab_warpgate as api_wg
    _, mgr, admin, _, _ = env
    _configure_no_nla(admin)
    _pool, d = _assign()
    assert api_wg.prepare_windows_nla(d, mgr, 'pve1') is True
    first = wg.nla_password(d['id'], d['vmid'])
    mgr.rollback_snapshot.return_value = {'success': True}
    monkeypatch.setattr(core_api, '_live_node', lambda desk: ({'status': 'running'}, 'pve1'))
    assert core_api._reset_one(dict(d, base_snap='base')) is None
    assert wg.nla_applied_credentials(d['id'], d['vmid']) is None    # set again on the next connect
    assert wg.nla_password(d['id'], d['vmid']) != first
    store.remove_desktop(d['id'])
    assert wg.db().query_one('SELECT * FROM vlab_warpgate_nla WHERE desktop_id = ?', (d['id'],)) is None


def test_nla_script_fits_windows_limits():
    """Found live on VM 116: New-LocalUser refuses a description over 48 characters."""
    s = wg.nla_account_script()
    desc = re.search(r"-Description '([^']*)'", s).group(1)
    assert len(desc) <= 48
    assert '[Console]::OutputEncoding = [Text.Encoding]::UTF8' in s.split('\n')[1]


def test_a_failed_nla_setup_logs_windows_words_but_not_the_password(env, fake_wg, agent, caplog):
    from pegaprox.api import vlab_warpgate as api_wg
    runs, reply = agent
    _, mgr, admin, _, _ = env
    _configure_no_nla(admin)
    _pool, d = _assign()
    pw = wg.nla_password(d['id'], d['vmid'])
    reply['value'] = (1, '', f"New-LocalUser : 'Description' too long (48) {pw}", '')
    assert api_wg.prepare_windows_nla(d, mgr, 'pve1') is False
    assert "'Description' too long (48)" in caplog.text and '(exit 1)' in caplog.text
    assert pw not in caplog.text


def test_an_admin_rotates_a_desktops_nla_password(env, fake_wg, agent, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    runs, _reply = agent
    _, _, admin, alice, _ = env
    _configure_no_nla(admin)
    _pool, d = _assign()
    monkeypatch.setattr(nxt, '_guest_os', lambda *a: 'windows')
    monkeypatch.setattr(nxt, 'rdp_prepare', lambda *a, **k: 0)
    assert alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'rdp'}).status_code == 200
    old = wg.nla_password(d['id'], d['vmid'])
    r = admin.post(f"/api/vlab/admin/desktops/{d['id']}/warpgate-nla/rotate")
    assert r.status_code == 200 and r.get_json() == {'rotated': True, 'applied': True, 'target_updated': True}
    new = wg.nla_password(d['id'], d['vmid'])
    assert new != old and runs[-1]['stdin'].strip() == new
    put = [b for (m, p, b) in fake_wg.calls if m == 'PUT' and p.startswith('/targets/')][-1]
    assert put['options']['auth']['password'] == new and put['options']['username'] == 'moavi-nla'
    assert old not in r.get_data(as_text=True) and new not in r.get_data(as_text=True)
    # users may not
    assert alice.post(f"/api/vlab/admin/desktops/{d['id']}/warpgate-nla/rotate").status_code == 403


def test_rotating_a_stopped_desktop_waits_for_its_next_connect(env, fake_wg, agent):
    runs, _reply = agent
    api, mgr, admin, _, _ = env
    _configure_no_nla(admin)
    _pool, d = _assign()
    wg.nla_password(d['id'], d['vmid'])
    wg.nla_mark_applied(d['id'])
    mgr.get_vm_resources.return_value = [dict(RES[0], status='stopped')]
    r = admin.post(f"/api/vlab/admin/desktops/{d['id']}/warpgate-nla/rotate")
    assert r.get_json() == {'rotated': True, 'applied': False, 'target_updated': False} and runs == []
    assert wg.nla_applied_credentials(d['id'], d['vmid']) is None and wg.nla_needs_apply(d['id'], d['vmid'])


# --- the gateway's web-SSH file panel follows the pool's ssh_files policy (Warpgate fork moavi4) ---

def _ssh_connect(env, monkeypatch, ssh_files):
    import pegaprox.api.vlab_next as nxt
    _, _, admin, alice, _ = env
    _configure(admin)
    pool, d = _assign()
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'browser_ssh': True, 'ssh_files': ssh_files})
    monkeypatch.setattr(nxt, 'rdp_listening', lambda ip, port=3389, timeout=1.5: True)
    r = alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'ssh'})
    assert r.status_code == 200, r.get_json()
    return pool, d


@pytest.mark.parametrize('ssh_files,on', [('off', False), ('down', True), ('both', True)])
def test_ssh_target_file_panel_follows_the_pool_policy(env, fake_wg, monkeypatch, ssh_files, on):
    _ssh_connect(env, monkeypatch, ssh_files)
    tgt = [b for (m, p, b) in fake_wg.calls if m == 'POST' and p == '/targets'][0]
    assert tgt['options']['kind'] == 'Ssh' and tgt['options']['web_file_transfer'] is on


def test_changing_the_policy_resyncs_existing_ssh_targets(env, fake_wg, monkeypatch):
    real = wg.resync_ssh_file_transfer
    monkeypatch.setattr(wg, 'resync_ssh_file_transfer', lambda desks, on, background=True: real(desks, on, background=False))
    pool, d = _ssh_connect(env, monkeypatch, 'both')
    _, _, admin, _, _ = env
    uid = wg.get_mapping(wg.target_ref(d['id'], 'ssh'))['target_uuid']
    n = len(fake_wg.calls)
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'browser_ssh': True, 'ssh_files': 'off'})
    puts = [b for (m, p, b) in fake_wg.calls[n:] if m == 'PUT' and p == f'/targets/{uid}']
    assert puts and puts[-1]['options']['web_file_transfer'] is False and puts[-1]['options']['host'] == '10.0.0.31'
    # no change of the on/off state: nothing sent
    n = len(fake_wg.calls)
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'browser_ssh': True, 'ssh_files': 'off', 'clipboard': 'none'})
    assert not [c for c in fake_wg.calls[n:] if c[1].startswith('/targets/')]


def test_an_image_without_the_file_panel_still_gets_the_target(env, fake_wg, monkeypatch):
    real = fake_wg.__call__

    class Strict:
        def __call__(self, method, path, token, base_url, verify_tls, body=None, timeout=15):
            if path.startswith('/targets') and isinstance(body, dict) and 'web_file_transfer' in body.get('options', {}):
                return 400, 'unknown field web_file_transfer'
            return real(method, path, token, base_url, verify_tls, body, timeout)
    monkeypatch.setattr(wg, '_api', Strict())
    _ssh_connect(env, monkeypatch, 'both')
    tgt = [b for (m, p, b) in fake_wg.calls if m == 'POST' and p == '/targets'][0]
    assert 'web_file_transfer' not in tgt['options']


def test_targets_carry_the_portal_desktop_name_as_their_description(env, fake_wg, monkeypatch):
    """The browser tab of a web session (Warpgate fork) shows the description, not moavi-...-desk_x-ssh."""
    import pegaprox.api.vlab_next as nxt
    _, _, admin, alice, _ = env
    _configure(admin)
    pool, d = _assign()
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'browser_ssh': True})
    monkeypatch.setattr(nxt, 'rdp_listening', lambda ip, port=3389, timeout=1.5: True)
    monkeypatch.setattr(nxt, '_guest_os', lambda *a: 'windows')
    monkeypatch.setattr(nxt, 'rdp_prepare', lambda *a, **k: 0)
    alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'ssh'})
    alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'rdp'})
    alice.post(f"/api/vlab/me/desktops/{d['id']}/warpgate", json={'protocol': 'rdp'})
    sent = [(m, b['description']) for (m, p, b) in fake_wg.calls if p.startswith('/targets') and isinstance(b, dict) and 'options' in b]
    assert ('POST', 'win-01 (SSH)') in sent and ('POST', 'win-01 (RDP)') in sent and ('PUT', 'win-01 (RDP)') in sent


def test_renaming_an_old_target_sends_a_full_target_request(env, fake_wg):
    _, _, admin, _, _ = env
    _configure(admin)
    cfg = wg.config(secret=True)
    wg.save_mapping('dsk_old-ssh', 'desktop', 'tgt-old', 'moavi-old-dsk_old', 'ssh', '10.0.0.4', 22)
    fake_wg.targets['moavi-old-dsk_old'] = 'tgt-old'
    fake_wg.kinds['tgt-old'] = 'Ssh'
    wg.sync_target(cfg, 'dsk_old', 'old', 'rdp', wg.rdp_target_options('10.0.0.4', 3389, 'svc', 'pw'))
    put = [b for (m, p, b) in fake_wg.calls if m == 'PUT' and p == '/targets/tgt-old'][-1]
    assert put['name'] == 'moavi-old-dsk_old-ssh'
    assert {'ticket_requests_disabled', 'ticket_require_approval', 'require_approval'} <= set(put)
