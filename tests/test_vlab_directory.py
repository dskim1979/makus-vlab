"""MOAVI Desk bundled directory (pegaprox/vlab/directory.py, pegaprox/api/vlab_directory.py): the
portal's accounts, departments and passwords on a Samba AD DC, sign-in through the core LDAP
sign-in, and the domain join of desktops through the guest agent.

The DC is ldap3's MOCK_SYNC strategy: a real in-memory directory the engine's own LDAP calls
(add, modify, member, unicodePwd, delete, search) run against. A small proxy adds what AD does on
its own and the mock does not: pwdLastSet 0 on a new account, set once a password is.
"""
import json
import re

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, SUBTREE, Connection, Server

from pegaprox.vlab import catalog, directory, store

CID = 'cluster_1'
BASE = 'DC=moavi,DC=lan'
OU = f'OU=MOAVI,{BASE}'
USERS = f'OU=Users,{OU}'
GROUPS = f'OU=Groups,{OU}'
SVC_DN = f'CN=vlab-svc,OU=Service,{OU}'
JOIN_DN = f'CN=vlab-join,OU=Service,{OU}'
SVC_PW = 'svc-Secret-1!'


class _AdLike:
    """An ldap3 mock connection with AD's pwdLastSet bookkeeping."""

    def __init__(self, conn, dc):
        self._c, self._dc = conn, dc

    def __getattr__(self, name):
        return getattr(self._c, name)

    def add(self, dn, object_class=None, attributes=None):
        attributes = dict(attributes or {})
        if 'user' in (object_class or []):
            attributes.setdefault('pwdLastSet', '0')
        return self._c.add(dn, object_class, attributes)

    def modify(self, dn, changes):
        from ldap3 import MODIFY_REPLACE
        ok = self._c.modify(dn, changes)
        if ok and 'unicodePwd' in changes:
            self._dc.sets.append(dn)
            self._c.modify(dn, {'pwdLastSet': [(MODIFY_REPLACE, ['133000000000000000'])]})
            self._c.result['result'] = 0
        return ok


class DC:
    def __init__(self):
        self.server = Server('dc1.moavi.lan', get_info=OFFLINE_AD_2012_R2)
        self.down = False
        self.sets = []
        c = Connection(self.server, user=SVC_DN, password=SVC_PW, client_strategy=MOCK_SYNC)
        c.strategy.add_entry(SVC_DN, {'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
                                      'sAMAccountName': 'vlab-svc', 'userPassword': SVC_PW})
        c.strategy.add_entry(JOIN_DN, {'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
                                       'sAMAccountName': 'vlab-join', 'info': 'service'})
        for dn in (OU, USERS, GROUPS, f'OU=Desktops,{OU}', f'OU=Service,{OU}'):
            c.strategy.add_entry(dn, {'objectClass': ['top', 'organizationalUnit']})

    def open(self):
        if self.down:
            raise directory.DirectoryError('UNREACHABLE', 'dc1.moavi.lan:636 - socket')
        c = Connection(self.server, user=SVC_DN, password=SVC_PW, client_strategy=MOCK_SYNC, raise_exceptions=False)
        assert c.bind()
        return _AdLike(c, self)

    def conn(self):
        c = Connection(self.server, user=SVC_DN, password=SVC_PW, client_strategy=MOCK_SYNC, raise_exceptions=False)
        c.bind()
        return c

    def entry(self, username):
        c = self.conn()
        c.search(USERS, f'(sAMAccountName={username})', SUBTREE,
                 attributes=['userAccountControl', 'unicodePwd', 'displayName', 'mail', 'description', 'info'])
        rows = [e for e in c.response if e.get('type') == 'searchResEntry']
        if not rows:
            return None
        raw = rows[0]['raw_attributes']
        one = lambda k: (raw.get(k) or [b''])[0].decode('utf-16-le' if k == 'unicodePwd' else 'utf-8')
        return {'dn': rows[0]['dn'], 'uac': int(one('userAccountControl') or 0), 'password': one('unicodePwd').strip('"'),
                'display': one('displayName'), 'mail': one('mail'), 'description': one('description'), 'info': one('info')}

    def members(self, group_cn):
        c = self.conn()
        c.search(GROUPS, f'(cn={group_cn})', SUBTREE, attributes=['member'])
        rows = [e for e in c.response if e.get('type') == 'searchResEntry']
        return None if not rows else sorted(m.decode().lower() for m in rows[0]['raw_attributes'].get('member') or [])

    def has_password(self, dn, password):
        c = self.conn()
        c.search(dn, '(objectClass=*)', SUBTREE, attributes=['unicodePwd'])
        rows = [e for e in c.response if e.get('type') == 'searchResEntry' and e['dn'].lower() == dn.lower()]
        return bool(rows) and (rows[0]['raw_attributes'].get('unicodePwd') or [b''])[0] == ('"%s"' % password).encode('utf-16-le')


def enabled(e):
    return not (e['uac'] & directory.UAC_DISABLED)


@pytest.fixture
def dc(monkeypatch, tmp_path):
    monkeypatch.setenv('VLAB_DIRECTORY', '1')
    monkeypatch.setenv('VLAB_DIRECTORY_REALM', 'moavi.lan')
    monkeypatch.setenv('VLAB_DIRECTORY_DOMAIN', 'MOAVI')
    monkeypatch.setenv('VLAB_DIRECTORY_HOSTNAME', 'dc1')
    monkeypatch.setenv('VLAB_DIRECTORY_IP', '10.20.0.5')
    monkeypatch.setenv('VLAB_DIRECTORY_FILES', str(tmp_path))
    (tmp_path / 'engine-bind').write_text(SVC_PW, encoding='utf-8')
    d = DC()
    monkeypatch.setattr(directory, '_open', d.open)
    monkeypatch.setattr(directory, '_user_bind', d.has_password)
    directory._last_reconcile[0] = 0.0
    return d


@pytest.fixture
def env(api, seed, dc, monkeypatch):
    import pegaprox.utils.email as email_mod
    from pegaprox.api import vlab_accounts
    vlab_accounts.reset_limits()
    sent = []
    monkeypatch.setattr(email_mod, 'send_email',
                        lambda to, subject, body, html=None, smtp_settings=None: sent.append({'to': list(to), 'body': body}) or (True, None))
    admin = api.as_user(seed.user('root', role='admin'))
    yield api, seed, admin, dc, sent
    vlab_accounts.reset_limits()


def _make(admin, name='alice', password='Passw0rd!x', **kw):
    r = admin.post('/api/vlab/admin/users', json=dict({'username': name, 'password': password, 'display_name': name.title(),
                                                       'email': f'{name}@univ.ac.kr'}, **kw))
    assert r.status_code == 201, r.get_json()
    return r.get_json()['user']


def _no_password_anywhere(seed, *passwords):
    """No table of the engine holds any of these, in clear or as a substring."""
    cur = seed.db.conn.cursor()
    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()]
    for t in tables:
        for row in cur.execute(f'SELECT * FROM "{t}"').fetchall():
            text = ' '.join(str(v) for v in tuple(row))
            for p in passwords:
                assert p not in text, f'{t} holds a password'


# --- the core sign-in points at the bundled DC ---------------------------------------------------

def test_ldap_settings_point_at_the_dc_only_without_an_own_ldap(env):
    api, seed, admin, dc, _ = env
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    from pegaprox.utils.ldap import get_ldap_settings
    c = get_ldap_settings()
    assert c['enabled'] and c['server'] == 'dc1.moavi.lan' and c['port'] == 636 and c['use_ssl']
    assert c['base_dn'] == USERS and c['bind_dn'] == SVC_DN and c['bind_password'] == SVC_PW
    assert c['auto_create_users'] is False and c['default_role'] == 'user'
    s = load_server_settings()
    s.update(ldap_enabled=True, ldap_server='ad.corp.example', ldap_base_dn='DC=corp')
    save_server_settings(s)
    assert get_ldap_settings()['server'] == 'ad.corp.example' and directory.active() is False


def test_a_bundled_row_keeps_its_portal_role_at_sign_in(dc):
    from pegaprox.utils.ldap import ldap_build_user_row
    row = {'auth_source': 'ldap', 'ldap_dn': f'CN=alice,{USERS}', 'role': 'pool-manager', 'tenant_id': 't1', 'permissions': ['x']}
    out = ldap_build_user_row({'username': 'alice', 'role': 'viewer', 'groups': [f'CN=moavi-users,{GROUPS}'],
                               'user_dn': f'CN=alice,{USERS}'}, row)
    assert out['role'] == 'pool-manager' and out['tenant_id'] == 't1' and out['permissions'] == ['x']
    assert out['groups'] == [f'CN=moavi-users,{GROUPS}'] and out['ldap_dn'] == f'CN=alice,{USERS}'


# --- accounts follow the portal ---------------------------------------------------------------

def test_an_account_made_in_the_portal_is_made_in_the_directory_with_its_password(env):
    api, seed, admin, dc, _ = env
    user = _make(admin)
    assert user['directory'] is True
    e = dc.entry('alice')
    assert e and enabled(e) and e['password'] == 'Passw0rd!x' and e['info'] == directory.MARK
    assert e['display'] == 'Alice' and e['mail'] == 'alice@univ.ac.kr'
    row = seed.db.get_user('alice')
    assert row['auth_source'] == 'ldap' and directory.owns(row) and not row.get('password_hash')
    assert dc.members('moavi-users') == [e['dn'].lower()]
    _no_password_anywhere(seed, 'Passw0rd!x')
    # an administrator stays a portal account (the console works without the DC)
    _make(admin, 'boss', role='admin')
    assert dc.entry('boss') is None and seed.db.get_user('boss')['auth_source'] in (None, 'local')


def test_disable_rename_department_and_delete_are_pushed(env):
    api, seed, admin, dc, _ = env
    _make(admin)
    dep = admin.post('/api/vlab/admin/departments', json={'name': '전자공학과'}).get_json()['department']
    sub = admin.post('/api/vlab/admin/departments', json={'name': '회로 연구실', 'parent_id': dep['id']}).get_json()['department']
    assert dc.members(directory.group_cn(dep['id'])) == [f"cn={directory.group_cn(sub['id'])},{GROUPS}".lower()]
    assert admin.put('/api/vlab/admin/users/alice', json={'enabled': False, 'display_name': '앨리스',
                                                          'department_id': sub['id']}).status_code == 200
    e = dc.entry('alice')
    assert not enabled(e) and e['display'] == '앨리스'
    assert dc.members(directory.group_cn(sub['id'])) == [e['dn'].lower()]
    assert admin.put('/api/vlab/admin/users/alice', json={'enabled': True}).status_code == 200
    assert enabled(dc.entry('alice'))
    # a pool grant to the department's group matches the user's directory groups
    g = admin.get('/api/vlab/admin/bundled-directory/groups').get_json()
    assert {x['name']: x['dn'] for x in g['groups']}['회로 연구실'] == f"CN={directory.group_cn(sub['id'])},{GROUPS}"
    assert admin.delete(f"/api/vlab/admin/departments/{sub['id']}").status_code == 200
    assert dc.members(directory.group_cn(sub['id'])) is None
    assert admin.delete('/api/vlab/admin/users/alice').status_code == 200
    assert dc.entry('alice') is None


def test_admin_reset_and_my_account_change_go_to_the_directory(env, monkeypatch):
    api, seed, admin, dc, _ = env
    _make(admin)
    r = admin.put('/api/vlab/admin/users/alice/password', json={'password': 'Reset-Pass1', 'must_change_password': True})
    assert r.status_code == 200, r.get_json()
    assert dc.entry('alice')['password'] == 'Reset-Pass1'
    row = seed.db.get_user('alice')
    assert row['force_password_change'] is True and not row.get('password_hash')
    alice = api.as_user(dict(seed.db.get_user('alice'), username='alice'))
    bad = alice.post('/api/auth/change-password', json={'current_password': 'nope-Nope1', 'new_password': 'Mine-Pass22'})
    assert bad.status_code == 401
    alice = api.as_user(dict(seed.db.get_user('alice'), username='alice'))
    ok = alice.post('/api/auth/change-password', json={'current_password': 'Reset-Pass1', 'new_password': 'Mine-Pass22'})
    assert ok.status_code == 200 and ok.get_json()['relogin_required'] is True
    assert dc.entry('alice')['password'] == 'Mine-Pass22'
    assert seed.db.get_user('alice')['force_password_change'] is False
    _no_password_anywhere(seed, 'Reset-Pass1', 'Mine-Pass22', 'Passw0rd!x')


def test_the_reset_link_sets_the_directory_password(env):
    api, seed, admin, dc, sent = env
    _make(admin)
    anon = api.anon()
    assert anon.post('/api/vlab/password-reset', json={'login': 'alice'}).status_code == 200
    tok = re.search(r'token=([\w-]+)', sent[-1]['body']).group(1)
    r = anon.post('/api/vlab/password-reset/confirm', json={'token': tok, 'password': 'From-Link9'})
    assert r.status_code == 200, r.get_json()
    assert dc.entry('alice')['password'] == 'From-Link9'
    # the DC away: the link is not spent and the answer says so
    anon.post('/api/vlab/password-reset', json={'login': 'alice@univ.ac.kr'})
    tok = re.search(r'token=([\w-]+)', sent[-1]['body']).group(1)
    dc.down = True
    r = anon.post('/api/vlab/password-reset/confirm', json={'token': tok, 'password': 'Later-Pass1'})
    assert r.status_code == 503
    dc.down = False
    assert anon.post('/api/vlab/password-reset/confirm', json={'token': tok, 'password': 'Later-Pass1'}).status_code == 200
    _no_password_anywhere(seed, 'From-Link9', 'Later-Pass1')


def test_signup_keeps_no_hash_and_the_review_enables_or_deletes(env):
    api, seed, admin, dc, _ = env
    assert admin.put('/api/vlab/admin/signup-settings', json={'enabled': True}).status_code == 200
    anon = api.anon()
    r = anon.post('/api/vlab/signup', json={'username': 'newbie', 'password': 'Signup-Pw1', 'display_name': '새내기'})
    assert r.status_code == 201, r.get_json()
    sid = r.get_json()['request']['id']
    e = dc.entry('newbie')
    assert e and not enabled(e) and e['password'] == 'Signup-Pw1' and e['description'] == 'signup:' + sid
    req = catalog.get_signup(sid, with_secret=True)
    assert req['password_hash'] == '' and req['password_salt'] == directory.SIGNUP_SALT
    # the reconcile leaves a waiting sign-up alone
    directory.reconcile()
    assert dc.entry('newbie') is not None
    assert admin.post(f'/api/vlab/admin/signups/{sid}/approve', json={}).status_code == 200
    e = dc.entry('newbie')
    assert enabled(e) and e['description'] == ''
    row = seed.db.get_user('newbie')
    assert directory.owns(row) and not row.get('password_hash')
    r = anon.post('/api/vlab/signup', json={'username': 'spammer', 'password': 'Signup-Pw2'})
    sid2 = r.get_json()['request']['id']
    assert dc.entry('spammer') is not None
    assert admin.post(f'/api/vlab/admin/signups/{sid2}/reject', json={}).status_code == 200
    assert dc.entry('spammer') is None
    _no_password_anywhere(seed, 'Signup-Pw1', 'Signup-Pw2')


def test_csv_import_puts_the_one_time_passwords_on_the_dc(env):
    api, seed, admin, dc, _ = env
    r = admin.post('/api/vlab/admin/users/import', json={'csv': 'username,display_name\nstu01,학생1\nstu02,학생2\n', 'deliver': 'csv'})
    assert r.status_code == 200
    rows = list(__import__('csv').reader(r.get_json()['csv'].lstrip('﻿').splitlines()))
    head = rows[0]
    for line in rows[1:]:
        rec = dict(zip(head, line))
        e = dc.entry(rec['username'])
        assert e and enabled(e) and e['password'] == rec['password']
        assert directory.owns(seed.db.get_user(rec['username']))


def test_the_dc_away_leaves_a_local_account_that_moves_at_its_next_sign_in(env, monkeypatch):
    api, seed, admin, dc, _ = env
    dc.down = True
    user = _make(admin, 'carol', password='Carol-Pass1')
    assert user['directory'] is False
    assert seed.db.get_user('carol').get('password_hash')
    assert directory.account_states()['carol']['ok'] is False
    dc.down = False
    from pegaprox.api import auth as auth_api
    monkeypatch.setattr(auth_api, 'ldap_authenticate', lambda u, p: {'error': 'User not found in LDAP'})
    r = api.anon().post('/api/auth/login', json={'username': 'carol', 'password': 'Carol-Pass1'})
    assert r.status_code == 200, r.get_json()
    row = seed.db.get_user('carol')
    assert directory.owns(row) and not row.get('password_hash')
    assert dc.entry('carol')['password'] == 'Carol-Pass1'
    _no_password_anywhere(seed, 'Carol-Pass1')


def test_reconcile_puts_back_drift_and_deletes_only_its_own_orphans(env):
    api, seed, admin, dc, _ = env
    _make(admin)
    _make(admin, 'bob')
    c = dc.conn()
    from ldap3 import MODIFY_REPLACE
    c.modify(f'CN=alice,{USERS}', {'userAccountControl': [(MODIFY_REPLACE, ['66050'])]})   # disabled behind our back
    c.add(f'CN=manual,{USERS}', ['top', 'person', 'organizationalPerson', 'user'], {'sAMAccountName': 'manual'})
    seed.db.delete_user('bob')                                                              # gone without the hook
    out = directory.reconcile()
    assert out['deleted'] == 1 and out['errors'] == 0
    assert enabled(dc.entry('alice')) and dc.entry('bob') is None and dc.entry('manual') is not None
    # the tick runs it only every RECONCILE_EVERY seconds
    assert directory.directory_tick() is None


def test_status_routes(env):
    api, seed, admin, dc, _ = env
    _make(admin)
    d = admin.get('/api/vlab/admin/bundled-directory').get_json()['directory']
    assert d['active'] and d['realm'] == 'moavi.lan' and d['domain'] == 'MOAVI' and d['service_account'] is True
    assert admin.post('/api/vlab/admin/bundled-directory/check').get_json()['check']['code'] == 'OK'
    accts = {a['username']: a for a in admin.get('/api/vlab/admin/bundled-directory/accounts').get_json()['accounts']}
    assert accts['alice']['where'] == 'directory' and accts['root']['where'] == 'local'
    assert admin.post('/api/vlab/admin/bundled-directory/sync').get_json()['sync']['accounts'] == 1
    assert admin.put('/api/vlab/admin/bundled-directory', json={'computer_name': 'LAB-{vmid}', 'desktop_dns': ['10.20.0.5']}).status_code == 200
    assert admin.put('/api/vlab/admin/bundled-directory', json={'computer_name': 'much-too-long-name-{vmid}'}).status_code == 400
    assert admin.put('/api/vlab/admin/bundled-directory', json={'surprise': 1}).status_code == 400
    # the join account: a new password set on the DC and sealed, never shown
    r = admin.post('/api/vlab/admin/bundled-directory/join-account/rotate')
    assert r.status_code == 200
    pw = directory.join_password()
    assert dc.has_password(JOIN_DN, pw) and pw not in r.get_data(as_text=True)
    row = directory.db().query_one("SELECT secret_encrypted FROM vlab_directory_secrets WHERE id = 'join'")
    assert row['secret_encrypted'] and pw not in row['secret_encrypted']


def test_off_by_default(api, seed, monkeypatch):
    monkeypatch.delenv('VLAB_DIRECTORY', raising=False)
    admin = api.as_user(seed.user('root', role='admin'))
    assert directory.active() is False
    r = admin.post('/api/vlab/admin/users', json={'username': 'dave', 'password': 'Passw0rd!x'})
    assert r.status_code == 201 and r.get_json()['user']['directory'] is False
    assert admin.post('/api/vlab/admin/bundled-directory/sync').status_code == 409
    from pegaprox.utils.ldap import get_ldap_settings
    assert get_ldap_settings()['enabled'] is False


# --- domain join through the guest agent -------------------------------------------------------

class _Resp:
    def __init__(self, data, status=200):
        self.status_code, self._data, self.text = status, data, ''

    def json(self):
        return {'data': self._data}


class Guest:
    def __init__(self, mgr, os_id='mswindows', code=0, out='domain=moavi.lan\ncomputer=MD-300\njoined=1\nreboot=1\nrdp_group=1\nrestarting=0\n'):
        self.os_id, self.code, self.out = os_id, code, out
        self.runs = []
        mgr._api_get.side_effect = self.get
        mgr._api_post.side_effect = self.post

    def get(self, url, params=None):
        if url.endswith('/agent/get-osinfo'):
            return _Resp({'result': {'id': self.os_id}})
        if url.endswith('/agent/exec-status'):
            return _Resp({'exited': 1, 'exitcode': self.code, 'out-data': self.out, 'err-data': 'Add-Computer: access denied'})
        return _Resp({}, 404)

    def post(self, url, data=None):
        self.runs.append((url, data))
        return _Resp({'pid': 7})


@pytest.fixture
def desk_env(env):
    api, seed, admin, dc, _ = env
    mgr = api.make_fake_manager(CID, get_vm_resources=[
        {'vmid': 300, 'node': 'pve1', 'name': 'win-01', 'type': 'qemu', 'status': 'running'},
        {'vmid': 301, 'node': 'pve1', 'name': 'rocky-01', 'type': 'qemu', 'status': 'running'}])
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    pool = admin.post('/api/vlab/admin/pools', json={'name': '사무', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    d1 = admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': 300}).get_json()['desktop']
    d2 = admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': 301}).get_json()['desktop']
    return api, seed, admin, dc, mgr, pool, d1, d2


def test_windows_join_with_the_sealed_join_account_on_stdin(desk_env):
    api, seed, admin, dc, mgr, pool, d1, d2 = desk_env
    g = Guest(mgr)
    r = admin.post(f"/api/vlab/admin/desktops/{d1['id']}/domain-join", json={})
    assert r.status_code == 200, r.get_json()
    j = r.get_json()['join']
    assert j['state'] == 'joined' and j['code'] == 'RESTART_NEEDED' and j['computer'] == 'MD-300' and j['os'] == 'windows'
    runs = [d for u, d in g.runs if u.endswith('/agent/exec')]
    pw = directory.join_password()
    assert runs[-1]['input-data'] == pw
    script = runs[-1]['command'][-1]
    assert pw not in script and 'Add-Computer' in script and f'OU=Desktops,{OU}' in script and "'MD-300'" in script
    assert "'10.20.0.5'" in script and 'S-1-5-32-555' in script and 'shutdown.exe' not in script
    assert dc.has_password(JOIN_DN, pw)
    # the RDP sign-in of a directory account on a joined desktop is DOMAIN\user
    _make(admin)
    assert directory.desktop_login(d1['id'], 'alice') == 'MOAVI\\alice'
    assert directory.desktop_login(d2['id'], 'alice') == 'alice'
    # a restart asked for: the script schedules it
    admin.post(f"/api/vlab/admin/desktops/{d1['id']}/domain-join", json={'restart': True})
    assert 'shutdown.exe /r /t 15' in [d for u, d in g.runs if u.endswith('/agent/exec')][-1]['command'][-1]


def test_linux_join_failure_and_the_pool_list(desk_env):
    api, seed, admin, dc, mgr, pool, d1, d2 = desk_env
    g = Guest(mgr, os_id='rocky', code=23, out='')
    j = admin.post(f"/api/vlab/admin/desktops/{d2['id']}/domain-join", json={}).get_json()['join']
    assert j['state'] == 'failed' and j['code'] == 'JOIN_FAILED' and 'access denied' in j['detail']
    script = [d for u, d in g.runs if u.endswith('/agent/exec')][-1]['command'][-1]
    assert 'realm join --user="$JOINER"' in script and 'PW=$(cat)' in script and 'realm permit -g moavi-users' in script
    assert 'use_fully_qualified_names = False' in script
    g.code, g.out = 0, 'domain=moavi.lan\ncomputer=md-301\njoined=1\n'
    out = admin.post(f"/api/vlab/admin/pools/{pool['id']}/domain-join", json={}).get_json()
    assert out['joined'] == 2 and out['remaining'] == 0
    rows = {r['vmid']: r for r in admin.get(f"/api/vlab/admin/bundled-directory/joins?pool_id={pool['id']}").get_json()['joins']}
    assert rows[301]['state'] == 'joined' and rows[301]['code'] == 'OK'
    # in another domain already: said, not touched
    g.out = 'domain=corp.example\ncomputer=x\n'
    g.code = 21
    j = admin.post(f"/api/vlab/admin/desktops/{d2['id']}/domain-join/check", json={}).get_json()['join']
    assert j['state'] == 'other' and 'corp.example' in j['detail']


def test_tables_are_synced_and_the_secret_column_sealed():
    from pegaprox.core import ha
    for t in directory.TABLES:
        assert t in ha.SYNC_TABLES
    assert ha.ENCRYPTED_COLUMNS['vlab_directory_secrets'] == ('secret_encrypted',)
    with open('version.json', encoding='utf-8') as f:
        files = json.load(f)['update_files']
    assert 'pegaprox/vlab/directory.py' in files and 'pegaprox/api/vlab_directory.py' in files
