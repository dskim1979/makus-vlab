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
            return 200, [{'id': v, 'username': k} for k, v in self.users.items()]
        if method == 'POST' and path == '/roles':
            uid = self.roles.setdefault(body['name'], self._id('role'))
            return 201, {'id': uid, 'name': body['name']}
        if method == 'POST' and path == '/users':
            uid = self.users.setdefault(body['username'], self._id('user'))
            return 201, {'id': uid, 'username': body['username']}
        if method == 'POST' and path == '/targets':
            if body['name'] in self.targets:          # like the real API
                return 409, 'Name already exists'
            uid = self.targets[body['name']] = self._id('tgt')
            return 201, {'id': uid, 'name': body['name']}
        if method == 'POST' and re.match(r'^/users/[^/]+/roles/[^/]+$', path) and body is None:
            return 400, 'ExpectContentType'                # the real API wants a JSON body here
        if method == 'POST' and path.endswith('/roles') or '/roles/' in path:
            return 201, {}
        if method == 'POST' and path == '/tickets':
            self.tickets.append(body)
            return 201, {'ticket': {'id': self._id('tk'), 'username': body['username']},
                         'secret': 'TKT-SECRET-123'}
        if method == 'PUT' and path.startswith('/targets/'):
            return 200, {}
        if method == 'DELETE' and path.startswith('/targets/'):
            uid = path.rsplit('/', 1)[1]
            if uid not in self.targets.values():
                return 404, 'not found'
            self.targets = {k: v for k, v in self.targets.items() if v != uid}
            return 204, ''
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
    assert conn['browser_url'] == 'https://wg.example/@warpgate#/' and 'TKT' not in conn['browser_url']
    # 티켓은 그 사용자+그 대상, 1회용, 만료시간
    t = fake_wg.tickets[-1]
    assert t['username'] == 'alice' and t['number_of_uses'] == 1 and t['expiry']
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
    assert alice.get('/api/vlab/me/warpgate').get_json() == {'enabled': False, 'protocols': ['rdp', 'ssh', 'vnc'], 'web_rdp_provider': 'guac'}
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
    assert wg.ssh_username('alice', 'moavi-x') == 'alice:moavi-x'
    e = wg.ssh_config_entry(cfg, 'moavi-pc', 'alice', 'moavi-x')
    assert e['hostname'] == 'wg.example' and e['port'] == 2222 and e['user'] == 'alice:moavi-x'
    assert 'ProxyJump' not in e['config_snippet'] and 'User alice:moavi-x' in e['config_snippet']
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
    assert r['enabled'] is True and r['warpgate_host'] == 'wg.example' and r['login'] == 'alice' and r['ssh_port'] == 2222
    assert len(r['entries']) == 1
    e = r['entries'][0]
    assert e['user'].startswith('alice:moavi-ai-box-') and e['hostname'] == 'wg.example'
    assert 'User alice:moavi-ai-box-' in r['managed_block'] and 'ProxyJump' not in r['managed_block']


def test_policy_has_researcher_ssh_toggle():
    from pegaprox.vlab import policy as pool_policy
    assert pool_policy.effective({})['researcher_ssh'] is False
    ok, err = pool_policy.validate({'researcher_ssh': True}, 'dedicated')
    assert err is None and ok['researcher_ssh'] is True
    assert pool_policy.validate({'researcher_ssh': 'yes'}, 'dedicated')[1]


def test_web_rdp_provider_defaults_to_guac_and_switches(env):
    _, _, admin, alice, _ = env
    _configure(admin)
    assert admin.get('/api/vlab/admin/warpgate').get_json()['config']['web_rdp_provider'] == 'guac'
    assert alice.get('/api/vlab/me/warpgate').get_json()['web_rdp_provider'] == 'guac'
    admin.put('/api/vlab/admin/warpgate', json={'base_url': 'https://wg.example', 'ssh_port': 2222, 'rdp_port': 3389, 'vnc_port': 5900, 'enabled': True, 'web_rdp_provider': 'warpgate'})
    assert admin.get('/api/vlab/admin/warpgate').get_json()['config']['web_rdp_provider'] == 'warpgate'
    assert admin.put('/api/vlab/admin/warpgate', json={'base_url': 'https://wg.example', 'ssh_port': 2222, 'rdp_port': 3389, 'vnc_port': 5900, 'enabled': True, 'web_rdp_provider': 'bogus'}).status_code == 400


# --- coexistence: the engine decides who serves the portal's browser RDP ------------------

def _guac_connect_env(env, monkeypatch):
    import pegaprox.api.vlab as core
    import pegaprox.api.vlab_next as nxt
    import pegaprox.utils.rbac as rbac
    _, _, admin, alice, _ = env
    monkeypatch.setattr(core, '_acl_set', lambda *a: True)
    monkeypatch.setattr(rbac, 'user_can_access_vm', lambda *a, **k: True)
    monkeypatch.setattr(nxt, '_guest_os', lambda *a: 'windows')
    monkeypatch.setattr(nxt, 'rdp_prepare', lambda *a, **k: 0)
    pool, d = _assign()
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'protocols': ['rdp', 'guac']})
    key = '00112233445566778899aabbccddeeff'
    admin.post('/api/vlab/admin/gateways', json={'name': 'g', 'kind': 'guacamole', 'address': 'guac.example.com', 'secret_key': key})
    return admin, alice, d


def test_browser_rdp_stays_on_guacamole_by_default(env, fake_wg, monkeypatch):
    admin, alice, d = _guac_connect_env(env, monkeypatch)
    _configure(admin)                                   # Warpgate on, provider left at guac
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'guac'})
    assert r.status_code == 200, r.get_json()
    assert '/guacamole/?data=' in r.get_json()['url'] and r.get_json().get('via') is None
    assert not fake_wg.tickets


def test_browser_rdp_goes_through_warpgate_once_switched(env, fake_wg, monkeypatch):
    admin, alice, d = _guac_connect_env(env, monkeypatch)
    _configure(admin)
    admin.put('/api/vlab/admin/warpgate', json={'base_url': 'https://wg.example', 'ssh_port': 2222, 'rdp_port': 3389,
                                                'vnc_port': 5900, 'enabled': True, 'web_rdp_provider': 'warpgate'})
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'guac'})
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body['via'] == 'warpgate' and body['url'] == 'https://wg.example/@warpgate#/'
    assert not fake_wg.tickets                           # no ticket for the browser path
    assert wg.get_mapping(d['id'])['proto'] == 'rdp'     # the desktop is in the user's Warpgate list


def test_browser_rdp_fails_closed_when_warpgate_is_down(env, fake_wg, monkeypatch):
    admin, alice, d = _guac_connect_env(env, monkeypatch)
    _configure(admin)
    admin.put('/api/vlab/admin/warpgate', json={'base_url': 'https://wg.example', 'ssh_port': 2222, 'rdp_port': 3389,
                                                'vnc_port': 5900, 'enabled': True, 'web_rdp_provider': 'warpgate'})
    monkeypatch.setattr(wg, '_api', lambda *a, **k: (500, 'down'))
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'guac'})
    # switched to Warpgate and Warpgate is down: refused, not quietly around the bastion
    assert r.status_code == 503 and r.get_json()['code'] == 'WG_DOWN', r.get_json()
    assert 'guacamole' not in str(r.get_json())


def test_browser_rdp_uses_guacamole_only_when_the_admin_allowed_the_fallback(env, fake_wg, monkeypatch):
    admin, alice, d = _guac_connect_env(env, monkeypatch)
    _configure(admin)
    admin.put('/api/vlab/admin/warpgate', json={'base_url': 'https://wg.example', 'ssh_port': 2222, 'rdp_port': 3389,
                                                'vnc_port': 5900, 'enabled': True, 'web_rdp_provider': 'warpgate',
                                                'allow_direct_fallback': True})
    assert admin.get('/api/vlab/admin/warpgate').get_json()['config']['allow_direct_fallback'] is True
    monkeypatch.setattr(wg, '_api', lambda *a, **k: (500, 'down'))
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'guac'})
    assert r.status_code == 200 and '/guacamole/?data=' in r.get_json()['url'], r.get_json()


def test_remove_target_deletes_it_and_forgets_the_mapping(env, fake_wg):
    _, _, admin, _, _ = env
    _configure(admin)
    cfg = wg.config(secret=True)
    uid, _name = wg.sync_target(cfg, 'dsk_x', 'gone-soon', 'ssh', wg.ssh_target_options('10.0.0.9', 22, 'moavi'))
    assert wg.remove_target(cfg, 'dsk_x') == uid
    assert ('DELETE', f'/targets/{uid}', None) in fake_wg.calls and uid not in fake_wg.targets.values()
    assert wg.get_mapping('dsk_x') is None
    assert wg.remove_target(cfg, 'dsk_x') is None          # nothing left to remove
    # already gone on the Warpgate side (404): the stale mapping is still dropped
    uid2, _ = wg.sync_target(cfg, 'dsk_y', 'stale', 'ssh', wg.ssh_target_options('10.0.0.8', 22, 'moavi'))
    fake_wg.targets = {}
    assert wg.remove_target(cfg, 'dsk_y') == uid2 and wg.get_mapping('dsk_y') is None


def test_sync_adopts_an_existing_target_when_the_mapping_is_gone(env, fake_wg):
    """Found against a live Warpgate: a restored / standby DB has no mapping but Warpgate has the
    target - POST answers 409; the engine takes the existing one over instead of failing."""
    _, _, admin, _, _ = env
    _configure(admin)
    cfg = wg.config(secret=True)
    uid, name = wg.sync_target(cfg, 'dsk_r', 'restored', 'ssh', wg.ssh_target_options('10.0.0.7', 22, 'moavi'))
    wg.delete_mapping('dsk_r')
    uid2, name2 = wg.sync_target(cfg, 'dsk_r', 'restored', 'ssh', wg.ssh_target_options('10.0.0.8', 22, 'moavi'))
    assert (uid2, name2) == (uid, name) and wg.get_mapping('dsk_r')['address'] == '10.0.0.8'
    assert any(c[:2] == ('PUT', f'/targets/{uid}') for c in fake_wg.calls)   # brought up to date


# --- the client's / mstsc's .rdp through Warpgate ----------------------------------------

def _rdp_on(admin, on=True):
    admin.put('/api/vlab/admin/warpgate', json={'base_url': 'https://wg.example', 'ssh_port': 2222, 'rdp_port': 3389,
                                                'vnc_port': 5900, 'enabled': True, 'rdp_via_warpgate': on})


def _lines(rdp):
    return rdp.replace('\r\n', '\n').strip().split('\n')


def test_rdp_file_stays_direct_while_the_switch_is_off(env, fake_wg, monkeypatch):
    admin, alice, d = _guac_connect_env(env, monkeypatch)
    _configure(admin)                                     # Warpgate on, "RDP through Warpgate" off
    body = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'}).get_json()
    assert body.get('via') is None and 'full address:s:10.0.0.31:3389' in _lines(body['rdp'])
    assert not fake_wg.tickets


def test_rdp_file_points_at_warpgate_with_a_single_use_ticket(env, fake_wg, monkeypatch):
    admin, alice, d = _guac_connect_env(env, monkeypatch)
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
    assert t['username'] == 'alice' and t['number_of_uses'] == 1
    tgt = [b for (m, p, b) in fake_wg.calls if m == 'POST' and p == '/targets'][-1]
    assert tgt['options']['kind'] == 'Rdp' and tgt['options']['host'] == '10.0.0.31' and tgt['options']['interactive_logon'] is True


def test_rdp_file_fails_closed_when_warpgate_is_down(env, fake_wg, monkeypatch):
    admin, alice, d = _guac_connect_env(env, monkeypatch)
    _configure(admin)
    _rdp_on(admin)
    assert admin.get('/api/vlab/admin/warpgate').get_json()['config']['allow_direct_fallback'] is False   # default
    monkeypatch.setattr(wg, '_api', lambda *a, **k: (502, 'down'))
    r = alice.post(f"/api/vlab/desktops/{d['id']}/connect", json={'protocol': 'rdp'})
    body = r.get_json()
    assert r.status_code == 503 and body['code'] == 'WG_DOWN' and '보안 게이트웨이' in body['error']
    assert 'rdp' not in body and '10.0.0.31' not in str(body)      # no direct .rdp around the bastion


def test_rdp_file_goes_direct_only_when_the_admin_allowed_the_fallback(env, fake_wg, monkeypatch):
    admin, alice, d = _guac_connect_env(env, monkeypatch)
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
