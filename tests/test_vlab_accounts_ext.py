"""MOAVI Desk account extras (pegaprox/api/vlab_accounts.py, pegaprox/vlab/accounts.py):
password reset by mail, sign-up mail verification and institution auto approval, bulk import
from CSV, account expiry on the minute loop, and the terms / privacy consent.
"""
import csv
import io
import re
from datetime import date, timedelta

import pytest

from pegaprox.vlab import accounts, catalog, store

CID = 'cluster_1'


@pytest.fixture
def env(api, seed, monkeypatch):
    import pegaprox.utils.email as email_mod
    from pegaprox.api import vlab_accounts
    vlab_accounts.reset_limits()
    sent = []

    def fake_send(to, subject, body, html=None, smtp_settings=None):
        sent.append({'to': list(to), 'subject': subject, 'body': body})
        return True, None
    monkeypatch.setattr(email_mod, 'send_email', fake_send)
    mgr = api.make_fake_manager(CID, get_vm_resources=[
        {'vmid': 300, 'node': 'pve1', 'name': 'lab-01', 'type': 'qemu', 'status': 'running'}])
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    _set(seed.db, 'alice', email='alice@univ.ac.kr', display_name='앨리스')
    yield api, seed, admin, alice, sent
    vlab_accounts.reset_limits()


def _set(db, username, **fields):
    u = db.get_user(username)
    u.update(fields)
    db.save_user(username, u)


def _token(mail):
    return re.search(r'token=([\w-]+)', mail['body']).group(1)


# --- 1) password reset ---------------------------------------------------------------------

def test_password_reset_by_mail_link_once_and_ends_sessions(env):
    from pegaprox.utils.auth import verify_password
    api, seed, admin, alice, sent = env
    anon = api.anon()
    same = anon.post('/api/vlab/password-reset', json={'login': 'nobody'}).get_json()
    r = anon.post('/api/vlab/password-reset', json={'login': 'ALICE@univ.ac.kr'})
    assert r.status_code == 200 and r.get_json() == same            # no hint whether it matched
    assert len(sent) == 1 and sent[0]['to'] == ['alice@univ.ac.kr'] and '/reset-password?token=' in sent[0]['body']
    tok = _token(sent[0])
    assert accounts.reset_for(tok)['username'] == 'alice'
    assert accounts.db().query_one('SELECT token_hash FROM vlab_password_resets')['token_hash'] != tok   # only the hash
    chk = anon.post('/api/vlab/password-reset/check', json={'token': tok}).get_json()
    assert chk['valid'] and chk['username'] == 'alice' and chk['policy']['min_length'] >= 8
    assert anon.post('/api/vlab/password-reset/check', json={'token': 'x' * 40}).get_json()['valid'] is False
    assert anon.post('/api/vlab/password-reset/confirm', json={'token': tok, 'password': 'short'}).status_code == 400
    assert alice.get('/api/vlab/me/pools').status_code == 200
    r = anon.post('/api/vlab/password-reset/confirm', json={'token': tok, 'password': 'NewPassw0rd!'})
    assert r.status_code == 200 and r.get_json()['username'] == 'alice'
    u = seed.db.get_user('alice')
    assert verify_password('NewPassw0rd!', u['password_salt'], u['password_hash'])
    assert alice.get('/api/vlab/me/pools').status_code == 401        # the old session ended
    again = anon.post('/api/vlab/password-reset/confirm', json={'token': tok, 'password': 'Another1Pass'})
    assert again.status_code == 400 and again.get_json()['code'] == 'LINK_INVALID'


def test_a_new_link_replaces_the_old_one_and_links_expire(env):
    api, seed, admin, alice, sent = env
    anon = api.anon()
    anon.post('/api/vlab/password-reset', json={'login': 'alice'})
    anon.post('/api/vlab/password-reset', json={'login': 'alice'})
    first, second = _token(sent[0]), _token(sent[1])
    assert accounts.reset_for(first) is None and accounts.reset_for(second)
    accounts.db().execute("UPDATE vlab_password_resets SET expires_at = '2000-01-01T00:00:00+00:00'")
    assert anon.post('/api/vlab/password-reset/check', json={'token': second}).get_json()['valid'] is False


def test_reset_is_rate_limited_and_directory_accounts_are_pointed_away(env):
    api, seed, admin, alice, sent = env
    anon = api.anon()
    for _ in range(5):
        assert anon.post('/api/vlab/password-reset', json={'login': 'alice'}).status_code == 200
    assert len(sent) == 3                                              # 3 per login per 15 minutes
    seed.user('dora', role='user')
    _set(seed.db, 'dora', email='dora@univ.ac.kr', auth_source='ldap')
    anon.post('/api/vlab/password-reset', json={'login': 'dora'})
    assert '기관 포털' in sent[-1]['body'] and 'token=' not in sent[-1]['body']
    assert not accounts.db().query_one("SELECT id FROM vlab_password_resets WHERE username = 'dora'")
    codes = [anon.post('/api/vlab/password-reset', json={'login': f'u{i}'}).status_code for i in range(6)]
    assert codes[-1] == 429                                            # 10 per address


# --- 2) / 3) sign-up mail verification and auto approval -------------------------------------

def _open_signup(admin, **extra):
    r = admin.put('/api/vlab/admin/signup-settings', json=dict({'enabled': True}, **extra))
    assert r.status_code == 200, r.get_json()
    return r.get_json()['signup']


def _ask(anon, name, email, **kw):
    return anon.post('/api/vlab/signup', json=dict({'username': name, 'password': 'Passw0rd!x', 'display_name': name,
                                                    'email': email}, **kw))


def test_mail_verification_marks_the_request_and_admin_still_reviews(env):
    api, seed, admin, alice, sent = env
    anon = api.anon()
    assert admin.put('/api/vlab/admin/signup-settings', json={'verify_email': 'sometimes'}).status_code == 400
    s = _open_signup(admin, verify_email='required')
    assert s['verify_email'] == 'required' and s['enabled'] is True
    cfg = anon.get('/api/vlab/signup/config').get_json()
    assert cfg['verify_email'] == 'required' and cfg['terms']['enabled'] is False
    assert _ask(anon, 'nomail', '').status_code == 400
    r = _ask(anon, 'kim.minji', 'minji@gmail.com')
    assert r.status_code == 201 and r.get_json()['request']['verify'] == 'sent' and r.get_json()['request']['auto'] is False
    sid = r.get_json()['request']['id']
    code = re.search(r'\b(\d{6})\b', sent[-1]['body']).group(1)
    row = admin.get('/api/vlab/admin/signups?status=pending').get_json()['signups'][0]
    assert row['email_verified'] is False and row['verify_sent'] is True
    bad = anon.post('/api/vlab/signup/verify', json={'id': sid, 'code': '000000' if code != '000000' else '111111'})
    assert bad.status_code == 400 and bad.get_json()['code'] == 'WRONG'
    ok = anon.post('/api/vlab/signup/verify', json={'id': sid, 'code': code}).get_json()
    assert ok == {'verified': True, 'approved': False}                 # not an institution address: review
    assert admin.get('/api/vlab/admin/signups?status=pending').get_json()['signups'][0]['email_verified'] is True
    r = admin.post(f'/api/vlab/admin/signups/{sid}/approve', json={'expires_at': (date.today() + timedelta(days=90)).isoformat()})
    assert r.status_code == 200 and r.get_json()['signup']['status'] == 'approved'
    assert accounts.get_expiry('kim.minji')['expires_at'] == (date.today() + timedelta(days=90)).isoformat()
    assert anon.post('/api/vlab/signup/resend', json={'id': sid}).status_code in (404, 429)


def test_codes_lock_after_five_wrong_tries_and_resend_waits(env):
    api, seed, admin, alice, sent = env
    anon = api.anon()
    _open_signup(admin, verify_email='optional')
    sid = _ask(anon, 'park', 'park@gmail.com').get_json()['request']['id']
    for _ in range(5):
        anon.post('/api/vlab/signup/verify', json={'id': sid, 'code': 'abcdef'})
    assert anon.post('/api/vlab/signup/verify', json={'id': sid, 'code': 'abcdef'}).get_json()['code'] == 'LOCKED'
    r = anon.post('/api/vlab/signup/resend', json={'id': sid})
    assert r.status_code == 200 and r.get_json()['sent'] is True
    assert anon.post('/api/vlab/signup/resend', json={'id': sid}).status_code == 429     # once a minute
    link_token = re.search(r'token=([\w-]+)', sent[-1]['body']).group(1)
    assert anon.post('/api/vlab/signup/verify', json={'id': sid, 'token': link_token}).get_json()['verified'] is True


def test_institution_mail_is_approved_on_verification_with_defaults(env):
    api, seed, admin, alice, sent = env
    anon = api.anon()
    dep = admin.post('/api/vlab/admin/departments', json={'name': '컴퓨터공학과'}).get_json()['department']
    pool = store.create_pool('실습', 'reset', CID)
    assert admin.put('/api/vlab/admin/signup-settings', json={'auto_domains': ['not a domain']}).status_code == 400
    assert admin.put('/api/vlab/admin/signup-settings', json={'auto_role': 'admin'}).status_code == 400
    s = _open_signup(admin, auto_domains='univ.ac.kr, @lab.re.kr', auto_department_id=dep['id'],
                     auto_pool_ids=[pool['id']], auto_expires_at='2099-02-28')
    assert s['auto_domains'] == ['univ.ac.kr', 'lab.re.kr'] and s['verify_email'] == 'off'
    # an institution address is checked even while the check is off for the others
    r = _ask(anon, 'lee', 'lee@cs.univ.ac.kr').get_json()['request']
    assert r['verify'] == 'sent' and r['auto'] is True
    other = _ask(anon, 'choi', 'choi@gmail.com').get_json()['request']
    assert other['verify'] == 'none'
    code = re.search(r'\b(\d{6})\b', sent[-1]['body']).group(1)
    out = anon.post('/api/vlab/signup/verify', json={'id': r['id'], 'code': code}).get_json()
    assert out == {'verified': True, 'approved': True}
    u = seed.db.get_user('lee')
    assert u['role'] == 'user' and u['enabled'] and u['portal_only']
    assert catalog.department_of('lee') == dep['id']
    assert any(g['subject_id'] == 'lee' for g in catalog.pool_grants(pool['id']))
    assert accounts.get_expiry('lee')['expires_at'] == '2099-02-28'
    assert catalog.get_signup(r['id'])['reviewed_by'] == 'auto'
    assert catalog.get_signup(other['id'])['status'] == 'pending'


# --- 4) bulk import ------------------------------------------------------------------------

def test_bulk_import_preview_then_create_with_one_time_passwords(env):
    api, seed, admin, alice, sent = env
    dep = admin.post('/api/vlab/admin/departments', json={'name': '전자공학과'}).get_json()['department']
    assert admin.get('/api/vlab/admin/users/import/example').data.decode('utf-8-sig').startswith('아이디,이름')
    text = ('﻿아이디,이름,메일,부서,역할,사용 기한\n'
            'stu01,학생1,stu01@univ.ac.kr,전자공학과,user,2099-02-28\n'
            'stu02,학생2,,전자공학과,,\n'
            'alice,중복,,,,\n'
            'stu01,또,,,,\n'
            'stu03,학생3,bad-mail,없는과,admin,2001-01-01\n'
            'stu04,=cmd(),,,,\n')
    pv = admin.post('/api/vlab/admin/users/import/preview', json={'csv': text}).get_json()
    assert pv['ok'] == 3 and pv['errors'] == 3
    byline = {r['line']: r for r in pv['rows']}
    assert byline[2]['department_id'] == dep['id'] and byline[2]['expires_at'] == '2099-02-28'
    assert byline[4]['duplicate'] and byline[5]['duplicate']
    assert len(byline[6]['errors']) == 4                                # mail, department, role, past day
    assert alice.post('/api/vlab/admin/users/import/preview', json={'csv': text}).status_code == 403
    assert admin.post('/api/vlab/admin/users/import/preview', json={'csv': 'a,b\n1,2\n'}).status_code == 400
    r = admin.post('/api/vlab/admin/users/import', json={'csv': text, 'deliver': 'csv'}).get_json()
    assert [c['username'] for c in r['created']] == ['stu01', 'stu02', 'stu04'] and len(r['skipped']) == 3
    rows = list(csv.DictReader(io.StringIO(r['csv'].lstrip('﻿'))))
    assert all(len(x['password']) >= 12 for x in rows)
    assert rows[2]['display_name'] == "'=cmd()"                         # no formula in a spreadsheet
    from pegaprox.utils.auth import verify_password
    u = seed.db.get_user('stu01')
    assert verify_password(rows[0]['password'], u['password_salt'], u['password_hash'])
    assert u['force_password_change'] and u['portal_only'] and catalog.department_of('stu01') == dep['id']
    assert accounts.get_expiry('stu01')['expires_at'] == '2099-02-28'
    # by mail: the password goes to the person, the CSV keeps it only for those without mail
    r = admin.post('/api/vlab/admin/users/import', json={'csv': 'username,email\nstu10,s10@univ.ac.kr\nstu11,\n', 'deliver': 'mail'}).get_json()
    rows = list(csv.DictReader(io.StringIO(r['csv'].lstrip('﻿'))))
    assert r['mailed'] == 1 and rows[0]['password'] == '' and rows[0]['mailed'] == 'yes' and rows[1]['password']
    assert '초기 비밀번호' in sent[-1]['body'] and sent[-1]['to'] == ['s10@univ.ac.kr']


# --- 5) expiry -----------------------------------------------------------------------------

def test_expiry_from_the_user_form_and_the_list(env):
    api, seed, admin, alice, sent = env
    assert admin.put('/api/vlab/admin/users/alice', json={'expires_at': '31/12/2099'}).status_code == 400
    assert admin.put('/api/vlab/admin/users/alice', json={'expires_at': '2099-12-31'}).status_code == 200
    users = {u['username']: u for u in admin.get('/api/vlab/admin/users?all=1').get_json()['users']}
    assert users['alice']['expires_at'] == '2099-12-31' and users['alice']['expired'] is False
    assert users['root']['expires_at'] is None
    assert admin.put('/api/vlab/admin/users/root/expiry', json={'expires_at': '2099-01-01'}).status_code == 400
    assert admin.put('/api/vlab/admin/users/alice/expiry', json={'expires_at': None}).get_json()['expires_at'] is None
    r = admin.post('/api/vlab/admin/users', json={'username': 'temp1', 'password': 'Passw0rd!x', 'role': 'user',
                                                  'expires_at': '2099-03-01'})
    assert r.status_code == 201 and r.get_json()['user']['expires_at'] == '2099-03-01'


def test_tick_notices_expires_reclaims_and_deletes(env, monkeypatch):
    import pegaprox.api.vlab as core
    from pegaprox.api import vlab_accounts as va
    from pegaprox.core import ha
    api, seed, admin, alice, sent = env
    acl, resets = [], []
    monkeypatch.setattr(core, '_acl_set', lambda c, v, u, g: acl.append((v, u, g)) or True)
    monkeypatch.setattr(core, '_reset_one', lambda d: resets.append(d['id']))
    pool = store.create_pool('초기화', 'reset', CID)
    desk = store.add_desktop(store.get_pool(pool['id']), 'pve1', 300, 'lab-01')
    store.set_base_snap(desk['id'], 'vlab-base')
    store.set_assignment(desk['id'], 'alice')
    today = date.today()
    accounts.set_expiry('alice', today + timedelta(days=5), 'root')
    assert admin.put('/api/vlab/admin/account-settings', json={'notice_days': 99}).status_code == 400
    assert admin.put('/api/vlab/admin/account-settings', json={'notice_days': 7, 'delete_after_days': 30}).status_code == 200
    assert va.accounts_tick(today) == {'noticed': 1, 'expired': 0, 'deleted': 0}
    assert '사용 기한' in sent[-1]['subject'] and va.accounts_tick(today)['noticed'] == 0     # told once
    # a lost lease stops before the account changes
    monkeypatch.setattr(ha, 'confirm_step', lambda what: False)
    assert va.accounts_tick(today + timedelta(days=6))['expired'] == 0
    assert seed.db.get_user('alice')['enabled']
    monkeypatch.undo()
    monkeypatch.setattr(core, '_acl_set', lambda c, v, u, g: acl.append((v, u, g)) or True)
    monkeypatch.setattr(core, '_reset_one', lambda d: resets.append(d['id']))
    assert va.accounts_tick(today + timedelta(days=6))['expired'] == 1
    assert not seed.db.get_user('alice')['enabled']
    assert alice.get('/api/vlab/me/pools').status_code == 401
    assert store.get_desktop(desk['id'])['assigned_user'] is None and resets == [desk['id']] and (300, 'alice', False) in acl
    listed = {u['username']: u for u in admin.get('/api/vlab/admin/users?all=1').get_json()['users']}
    assert listed['alice']['expired'] is True and listed['alice']['enabled'] is False
    # a new day to come brings it back
    assert admin.put('/api/vlab/admin/users/alice/expiry', json={'expires_at': (today + timedelta(days=30)).isoformat()}).status_code == 200
    assert seed.db.get_user('alice')['enabled']
    accounts.set_expiry('alice', today - timedelta(days=1), 'root')
    va.accounts_tick(today)
    accounts.mark_expiry('alice', expired_at=(today - timedelta(days=31)).isoformat() + 'T00:00:00+00:00')
    assert va.accounts_tick(today)['deleted'] == 1
    assert seed.db.get_user('alice') is None and accounts.get_expiry('alice') is None


# --- 6) terms ------------------------------------------------------------------------------

def test_terms_at_signup_first_login_and_again_on_a_new_version(env):
    api, seed, admin, alice, sent = env
    anon = api.anon()
    assert anon.get('/api/vlab/terms').get_json() == {'enabled': False}
    assert admin.put('/api/vlab/admin/terms', json={'enabled': True}).status_code == 400          # no version
    assert admin.put('/api/vlab/admin/terms', json={'version': 'bad version!'}).status_code == 400
    assert alice.put('/api/vlab/admin/terms', json={'enabled': False}).status_code == 403
    r = admin.put('/api/vlab/admin/terms', json={'enabled': True, 'version': '2026-10', 'terms': '# 이용 약관\n...', 'privacy': '수집 항목: 이름, 메일'})
    assert r.status_code == 200 and r.get_json()['terms']['enabled'] is True
    assert anon.get('/api/vlab/terms').get_json()['version'] == '2026-10'
    # the portal waits for the consent
    r = alice.get('/api/vlab/me/pools')
    assert r.status_code == 403 and r.get_json()['code'] == 'TERMS_REQUIRED'
    me = alice.get('/api/vlab/me/terms').get_json()
    assert me['required'] is True and me['privacy'].startswith('수집')
    assert alice.post('/api/vlab/me/terms', json={'version': '2026-09'}).status_code == 409
    assert alice.post('/api/vlab/me/terms', json={'version': '2026-10'}).get_json()['required'] is False
    assert alice.get('/api/vlab/me/pools').status_code == 200
    # sign-up agrees for the new account
    _open_signup(admin)
    assert _ask(anon, 'newbie', '').get_json()['code'] == 'TERMS_REQUIRED'
    assert _ask(anon, 'newbie', '', terms_version='2026-10').status_code == 201
    # a new version asks everyone again
    admin.put('/api/vlab/admin/terms', json={'version': '2026-11'})
    assert alice.get('/api/vlab/me/pools').status_code == 403
    rows = admin.get('/api/vlab/admin/terms/consents').get_json()
    assert {(c['username'], c['version'], c['via']) for c in rows['consents']} == {('alice', '2026-10', 'login'), ('newbie', '2026-10', 'signup')}
    assert 'alice' in rows['not_yet']
    text = admin.get('/api/vlab/admin/terms/consents?format=csv&version=2026-10').data.decode('utf-8-sig')
    assert text.splitlines()[0] == 'username,display_name,version,via,agreed_at,client_ip' and 'alice' in text
    assert alice.get('/api/vlab/admin/terms/consents').status_code == 403
