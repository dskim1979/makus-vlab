"""MOAVI Desk: one password for the portal and the desktops (pegaprox/vlab/directory.py
password_policy), and AD 디렉터리 - the objects of the bundled DC or of the site's AD from the
console (pegaprox/vlab/adobjects.py, pegaprox/api/vlab_adobjects.py). The DC is the ldap3
MOCK_SYNC directory of tests/test_vlab_directory.py.
"""
from ldap3 import MODIFY_REPLACE

from pegaprox.vlab import directory
from test_vlab_directory import BASE, GROUPS, OU, USERS, _make, _no_password_anywhere, dc, enabled, env  # noqa: F401


# --- the password policy: the portal's and the directory's together ----------------------------

def test_the_policy_is_the_portals_and_the_directorys_together(env):
    api, seed, admin, dc, _ = env
    pol = api.anon().get('/api/vlab/password-policy').get_json()['policy']
    assert pol['unified'] is True and pol['domain'] == 'MOAVI' and pol['min_length'] == 8 and pol['complexity'] is False
    dc.conn().modify(BASE, {'minPwdLength': [(MODIFY_REPLACE, ['12'])], 'pwdProperties': [(MODIFY_REPLACE, ['1'])]})
    directory._policy_cache.update(at=0.0, dc=None)
    pol = api.anon().get('/api/vlab/password-policy').get_json()['policy']
    assert pol['min_length'] == 12 and pol['complexity'] is True
    r = admin.post('/api/vlab/admin/users', json={'username': 'alice', 'password': 'Passw0rd!x', 'display_name': 'Alice'})
    assert r.status_code == 400 and r.get_json()['code'] == 'PASSWORD_POLICY' and '12' in r.get_json()['error']
    r = admin.post('/api/vlab/admin/users', json={'username': 'alice', 'password': 'Alice-Passw0rd', 'display_name': 'Alice'})
    assert r.status_code == 400 and 'account name' in r.get_json()['error']
    assert seed.db.get_user('alice') is None
    assert _make(admin, password='Long-Passw0rd-9')['directory'] is True
    # sign-up config carries the rule; a short one is refused before the DC is touched
    assert admin.put('/api/vlab/admin/signup-settings', json={'enabled': True}).status_code == 200
    cfg = api.anon().get('/api/vlab/signup/config').get_json()
    assert cfg['password_policy']['min_length'] == 12 and cfg['password_policy']['unified'] is True
    r = api.anon().post('/api/vlab/signup', json={'username': 'newbie', 'password': 'Short-Pw1'})
    assert r.status_code == 400 and dc.entry('newbie') is None
    # 내 계정: refused with the rule, the directory keeps the old password
    alice = api.as_user(dict(seed.db.get_user('alice'), username='alice'))
    r = alice.post('/api/auth/change-password', json={'current_password': 'Long-Passw0rd-9', 'new_password': 'Short-Pw1'})
    assert r.status_code == 400 and r.get_json()['code'] == 'PASSWORD_POLICY'
    assert dc.entry('alice')['password'] == 'Long-Passw0rd-9'
    # CSV passwords are made to fit the stricter rule
    r = admin.post('/api/vlab/admin/users/import', json={'csv': 'username\nstu01\n', 'deliver': 'csv'}).get_json()
    pw = r['csv'].splitlines()[1].split(',')[6]
    assert len(pw) >= 12 and directory.policy_error(pw, 'stu01') is None and dc.entry('stu01')['password'] == pw


def test_without_the_directory_the_policy_is_the_portals(api, monkeypatch):
    monkeypatch.delenv('VLAB_DIRECTORY', raising=False)
    pol = api.anon().get('/api/vlab/password-policy').get_json()['policy']
    assert pol['unified'] is False and pol['complexity'] is False and pol['min_length'] == 8


# --- AD 디렉터리 ---------------------------------------------------------------------------------

def _ad(admin, method, path, **kw):
    r = getattr(admin, method)(f'/api/vlab/admin/ad/{path}', **kw)
    return r.status_code, r.get_json()


def test_tree_objects_members_and_changes(env):
    api, seed, admin, dc, _ = env
    _make(admin)                                                       # alice: a portal account, kept by the portal
    assert [x['id'] for x in _ad(admin, 'get', 'sources')[1]['sources']] == ['bundled']
    code, out = _ad(admin, 'post', 'test', json={'source': 'bundled'})
    assert code == 200 and out['test']['base_dn'] == BASE
    assert [c['name'] for c in _ad(admin, 'get', 'tree?source=bundled')[1]['children']] == ['MOAVI']
    kids = {c['name'] for c in _ad(admin, 'get', f'tree?source=bundled&dn={OU}')[1]['children']}
    assert {'Users', 'Groups', 'Desktops', 'Service'} <= kids
    # an OU with two groups and a user
    code, ou = _ad(admin, 'post', 'ous', json={'source': 'bundled', 'parent_dn': OU, 'name': '연구소'})
    assert code == 201, ou
    lab = ou['object']['dn']
    code, g1 = _ad(admin, 'post', 'groups', json={'source': 'bundled', 'parent_dn': lab, 'name': 'lab-all', 'scope': 'universal'})
    assert code == 201 and g1['object']['type'] == 'security' and g1['object']['scope'] == 'universal'
    code, g2 = _ad(admin, 'post', 'groups', json={'source': 'bundled', 'parent_dn': lab, 'name': 'lab-mail',
                                                   'type': 'distribution', 'scope': 'domain_local'})
    assert g2['object']['type'] == 'distribution' and g2['object']['scope'] == 'domain_local'
    code, u = _ad(admin, 'post', 'users', json={'source': 'bundled', 'parent_dn': lab, 'sam': 'kiosk1',
                                                 'display_name': 'Kiosk 1', 'password': 'Kiosk-Pass1'})
    assert code == 201 and u['object']['enabled'] is True
    udn = u['object']['dn']
    assert dc.has_password(udn, 'Kiosk-Pass1')
    _no_password_anywhere(seed, 'Kiosk-Pass1')
    # members: direct and nested; itself and loops refused
    G1, G2 = g1['object']['dn'], g2['object']['dn']
    assert _ad(admin, 'post', 'members', json={'source': 'bundled', 'group_dn': G2, 'member_dn': udn})[0] == 200
    assert _ad(admin, 'post', 'members', json={'source': 'bundled', 'group_dn': G1, 'member_dn': G2})[0] == 200
    obj = _ad(admin, 'get', f'object?source=bundled&dn={G1}')[1]['object']
    assert obj['members'] == [G2] and obj['nested_members'] == [udn]
    code, out = _ad(admin, 'post', 'members', json={'source': 'bundled', 'group_dn': G2, 'member_dn': G1})
    assert code == 409 and out['code'] == 'CYCLE'
    code, out = _ad(admin, 'post', 'members', json={'source': 'bundled', 'group_dn': G1, 'member_dn': G1})
    assert code == 409 and out['code'] == 'SELF'
    assert _ad(admin, 'post', 'members', json={'source': 'bundled', 'group_dn': G2, 'member_dn': udn, 'action': 'remove'})[1]['object']['members'] == []
    # change, disable, search
    code, out = _ad(admin, 'put', 'object', json={'source': 'bundled', 'dn': udn, 'changes': {'description': '로비 키오스크'}})
    assert code == 200 and out['object']['description'] == '로비 키오스크'
    assert _ad(admin, 'put', 'object', json={'source': 'bundled', 'dn': udn, 'changes': {'userAccountControl': '512'}})[0] == 400
    assert _ad(admin, 'put', 'object/enabled', json={'source': 'bundled', 'dn': udn, 'enabled': False})[1]['object']['enabled'] is False
    assert [o['dn'] for o in _ad(admin, 'get', 'objects?source=bundled&kind=users&q=kios')[1]['objects']] == [udn]
    assert {o['name'] for o in _ad(admin, 'get', f'objects?source=bundled&dn={lab}&kind=groups')[1]['objects']} == {'lab-all', 'lab-mail'}
    assert _ad(admin, 'put', 'object/password', json={'source': 'bundled', 'dn': udn, 'password': 'New-Kiosk-2'})[0] == 200
    assert dc.has_password(udn, 'New-Kiosk-2')
    # what the portal keeps is read-only here; nothing outside the base
    code, out = _ad(admin, 'put', 'object/enabled', json={'source': 'bundled', 'dn': f'CN=alice,{USERS}', 'enabled': False})
    assert code == 409 and out['code'] == 'MANAGED' and enabled(dc.entry('alice'))
    out = _ad(admin, 'post', 'members', json={'source': 'bundled', 'group_dn': f'CN=moavi-users,{GROUPS}', 'member_dn': udn})[1]
    assert out['code'] == 'MANAGED'
    assert _ad(admin, 'post', 'users', json={'source': 'bundled', 'parent_dn': USERS, 'sam': 'sneaky'})[1]['code'] == 'MANAGED'
    assert _ad(admin, 'get', 'object?source=bundled&dn=CN=x,DC=other,DC=org')[1]['code'] == 'OUTSIDE'
    # an OU goes only when it is empty
    assert _ad(admin, 'delete', 'object', json={'source': 'bundled', 'dn': lab})[1]['code'] == 'NOT_EMPTY'
    for dn in (udn, G1, G2, lab):
        assert _ad(admin, 'delete', 'object', json={'source': 'bundled', 'dn': dn})[0] == 200, dn
    assert '연구소' not in {c['name'] for c in _ad(admin, 'get', f'tree?source=bundled&dn={OU}')[1]['children']}
    # every change is in the audit log, no password in it
    rows = seed.db.conn.execute("SELECT action, details FROM audit_log WHERE action LIKE 'vlab.ad.%'").fetchall()
    acts = {r[0] for r in rows}
    assert {'vlab.ad.ou.create', 'vlab.ad.group.create', 'vlab.ad.user.create', 'vlab.ad.member.add', 'vlab.ad.member.remove',
            'vlab.ad.object.update', 'vlab.ad.object.disable', 'vlab.ad.object.password', 'vlab.ad.object.delete'} <= acts
    assert not any('Kiosk' in (r[1] or '') and 'Pass' in (r[1] or '') for r in rows)


def test_a_regular_user_cannot_and_the_sites_ad_is_a_source(env, monkeypatch):
    api, seed, admin, dc, _ = env
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    from pegaprox.vlab import adobjects
    bob = api.as_user(seed.user('bob', role='user'))
    assert bob.get('/api/vlab/admin/ad/sources').status_code == 403
    s = load_server_settings()
    s.update(ldap_enabled=True, ldap_server='ad.corp.example', ldap_base_dn=BASE, ldap_port=636, ldap_use_ssl=True)
    save_server_settings(s)
    monkeypatch.setattr(adobjects, '_ldap_open', dc.open)
    assert [x['id'] for x in _ad(admin, 'get', 'sources')[1]['sources']] == ['bundled', 'ldap']
    code, out = _ad(admin, 'post', 'ous', json={'source': 'ldap', 'parent_dn': BASE, 'name': 'Corp'})
    assert code == 201
    # on the site's own AD nothing is held back for the portal
    assert _ad(admin, 'put', 'object', json={'source': 'ldap', 'dn': out['object']['dn'], 'changes': {'description': 'x'}})[0] == 200
    assert _ad(admin, 'get', 'tree?source=nope')[1]['code'] == 'BAD_SOURCE'


def test_ad_page_passwords_meet_the_dc_rule_before_the_dc_sees_them(env):
    api, seed, admin, dc, _ = env
    dc.conn().modify(BASE, {'pwdProperties': [(MODIFY_REPLACE, ['1'])]})      # Samba's default: complexity on
    directory._policy_cache.update(at=0.0, dc=None)
    assert api.anon().get('/api/vlab/password-policy').get_json()['policy']['complexity'] is True
    for bad in ('abc', 'kiosk1-Pass9', 'Lobby-Desk9-x'):                      # short; the account name; the full name
        code, out = _ad(admin, 'post', 'users', json={'source': 'bundled', 'parent_dn': OU, 'sam': 'kiosk1',
                                                       'display_name': 'Lobby Desk', 'password': bad})
        assert code == 400 and out['code'] == 'PASSWORD_POLICY', bad
    assert _ad(admin, 'get', 'objects?source=bundled&kind=users&q=kiosk1')[1]['objects'] == []   # nothing half made
    code, out = _ad(admin, 'post', 'users', json={'source': 'bundled', 'parent_dn': OU, 'sam': 'kiosk1',
                                                   'display_name': 'Lobby Desk', 'password': 'Front-Hall-42'})
    assert code == 201
    udn = out['object']['dn']
    code, out = _ad(admin, 'put', 'object/password', json={'source': 'bundled', 'dn': udn, 'password': 'kiosk1kiosk1'})
    assert code == 400 and out['code'] == 'PASSWORD_POLICY' and dc.has_password(udn, 'Front-Hall-42')
