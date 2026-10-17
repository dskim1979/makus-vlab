# -*- coding: utf-8 -*-
"""MOAVI Desk Warpgate 접근 게이트웨이(bastion) (pegaprox/api/vlab_warpgate.py,
pegaprox/vlab/warpgate.py): 관리자 설정(토큰 봉인), 데스크톱 접속 시 그 사용자+그 대상에만
쓸 수 있는 1회용·단시간 티켓 발급과 접속 좌표 반환. 사용자 비밀번호는 저장·전달하지 않는다.

Warpgate 관리자 API는 wg._api를 가로채 흉내낸다(네트워크 없음)."""
import json

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
    assert c['browser_url'] == 'https://wg.example:443/?warpgate-target=moavi-x&warpgate-ticket=SEC'
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
            uid = self.targets.setdefault(body['name'], self._id('tgt'))
            return 201, {'id': uid, 'name': body['name']}
        if method == 'POST' and path.endswith('/roles') or '/roles/' in path:
            return 201, {}
        if method == 'POST' and path == '/tickets':
            self.tickets.append(body)
            return 201, {'ticket': {'id': self._id('tk'), 'username': body['username']},
                         'secret': 'TKT-SECRET-123'}
        if method == 'PUT' and path.startswith('/targets/'):
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
    assert 'warpgate-ticket=TKT-SECRET-123' in conn['browser_url']
    # 티켓은 그 사용자+그 대상, 1회용, 만료시간
    t = fake_wg.tickets[-1]
    assert t['username'] == 'alice' and t['number_of_uses'] == 1 and t['expiry']
    assert t['target_name'].startswith('moavi-win-01-') and t['target_name'] == conn['browser_url'].split('warpgate-target=')[1].split('&')[0]
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
