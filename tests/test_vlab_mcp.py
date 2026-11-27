"""MOAVI Desk MCP server for administrators (pegaprox/vlab/mcp.py, pegaprox/api/vlab_mcp.py)."""
import hashlib
from datetime import datetime

import pytest

import pegaprox.api.vlab_mcp as vm
from pegaprox.utils import audit
from pegaprox.vlab import mcp, store
from test_vlab_api import CID, _pool_with_desktop, env  # noqa: F401 - the shared fixture

PW = 'Root-pass-1234'
INSIDE = '192.168.0.50'


@pytest.fixture
def net(monkeypatch, env):
    """The caller's address (as get_client_ip reads it) and the alerts sent; root has a real password."""
    from pegaprox.core.db import get_db
    from pegaprox.utils.auth import hash_password
    salt, h = hash_password(PW)
    get_db().save_user('root', dict(get_db().get_user('root'), password_salt=salt, password_hash=h))
    where = {'ip': INSIDE}
    monkeypatch.setattr(vm, 'get_client_ip', lambda: where['ip'])
    told = []
    import pegaprox.api.vlab_notices as notices
    monkeypatch.setattr(notices, 'admins', lambda title, text, data: told.append((title, text, data)))
    vm._told.clear()
    vm._reauth_attempts.reset()
    return where, told


def _rpc(api, token, method, params=None, mid=1, **kw):
    raw = api.app.test_client()
    msg = {'jsonrpc': '2.0', 'id': mid, 'method': method}
    if params is not None:
        msg['params'] = params
    h = {'Authorization': f'Bearer {token}'} if token else {}
    h.update(kw.pop('headers', {}))
    return raw.post('/api/vlab/mcp', json=msg, headers=h, base_url='http://localhost', **kw)


def _call(api, token, name, **args):
    r = _rpc(api, token, 'tools/call', {'name': name, 'arguments': args})
    assert r.status_code == 200, r.get_data(as_text=True)
    return r.get_json()['result']


def _on(admin):
    r = admin.put('/api/vlab/admin/mcp', json={'enabled': True, 'user_password': PW})
    assert r.status_code == 200, r.get_json()


def _token(admin, scope='manage', name='Claude Desktop', **kw):
    r = admin.post('/api/vlab/admin/mcp/tokens', json=dict({'name': name, 'scope': scope, 'user_password': PW}, **kw))
    assert r.status_code == 201, r.get_json()
    return r.get_json()['token'], r.get_json()['record']


def _days(r):
    return (datetime.fromisoformat(r['expires_at']) - datetime.fromisoformat(r['created_at'])).days


def _events(told, event):
    return [t for t in told if t[2]['event'] == event]


def test_tokens_are_shown_once_and_kept_as_a_hash(env, net):
    api, admin, alice, bob, viewer = env
    token, rec = _token(admin, 'read')
    assert token.startswith('mcp_') and rec['token_hint'] == token[-4:] and 'token_hash' not in rec
    assert rec['owner'] == 'root' and rec['scope'] == 'read' and rec['active']
    row = mcp.db().query_one('SELECT * FROM vlab_mcp_tokens WHERE id = ?', (rec['id'],))
    assert row['token_hash'] == hashlib.sha256(token.encode()).hexdigest()
    assert token not in str(dict(row))                                         # never the token itself
    listing = admin.get('/api/vlab/admin/mcp').get_json()
    assert token not in str(listing) and 'token_hash' not in str(listing)
    assert listing['enabled'] is False and listing['tokens'][0]['id'] == rec['id']
    assert listing['networks'] == ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] and listing['inside'] is True
    assert admin.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'all', 'user_password': PW}).status_code == 400
    assert admin.post('/api/vlab/admin/mcp/tokens', json={'name': '', 'scope': 'read', 'user_password': PW}).status_code == 400
    assert alice.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'read'}).status_code == 403
    assert alice.put('/api/vlab/admin/mcp', json={'enabled': True}).status_code == 403


def test_making_a_token_and_switching_on_need_the_password_again(env, net):
    api, admin, alice, bob, viewer = env
    r = admin.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'read'})
    assert r.status_code == 403 and r.get_json()['code'] == 'MCP_REAUTH' and r.get_json()['needs'] == ['password']
    r = admin.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'read', 'user_password': 'wrong'})
    assert r.status_code == 403 and r.get_json()['code'] == 'MCP_REAUTH'
    assert admin.put('/api/vlab/admin/mcp', json={'enabled': True}).get_json()['code'] == 'MCP_REAUTH'
    assert admin.put('/api/vlab/admin/mcp', json={'networks': ['192.168.0.0/16']}).get_json()['code'] == 'MCP_REAUTH'
    assert mcp.settings()['enabled'] is False and mcp.list_tokens() == []
    # five wrong passwords: then even the right one waits
    for _ in range(4):
        admin.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'read', 'user_password': 'wrong'})
    assert admin.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'read', 'user_password': PW}).status_code == 429
    vm._reauth_attempts.reset()
    # switching off only takes access away: no password
    _on(admin)
    assert admin.put('/api/vlab/admin/mcp', json={'enabled': False}).status_code == 200
    # an account with 2FA gives the code as well
    import pyotp
    from pegaprox.core.db import get_db
    secret = pyotp.random_base32()
    get_db().save_user('root', dict(get_db().get_user('root'), totp_enabled=True, totp_secret=secret))
    r = admin.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'read', 'user_password': PW})
    assert r.status_code == 403 and r.get_json()['needs'] == ['password', 'otp']
    r = admin.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'read', 'user_password': PW, 'otp': '000000'})
    assert r.status_code == 403
    r = admin.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'read', 'user_password': PW,
                                                       'otp': pyotp.TOTP(secret).now()})
    assert r.status_code == 201, r.get_json()


def test_allowed_networks(env, net):
    api, admin, alice, bob, viewer = env
    where, told = net
    _on(admin)
    token, rec = _token(admin)
    assert rec['sources'] == ['192.168.0.0/24'] and rec['seen_ips'] == [INSIDE]
    # never an empty list, never everything, never one that leaves the admin outside
    for bad in ([], ['0.0.0.0/0'], ['nonsense']):
        assert admin.put('/api/vlab/admin/mcp', json={'networks': bad, 'user_password': PW}).status_code == 400
    r = admin.put('/api/vlab/admin/mcp', json={'networks': ['10.0.0.0/8'], 'user_password': PW})
    assert r.status_code == 400 and r.get_json()['code'] == 'MCP_NETWORK_SELF'
    r = admin.put('/api/vlab/admin/mcp', json={'networks': ['192.168.0.0/24', '10.1.0.0/16'], 'user_password': PW})
    assert r.status_code == 200 and mcp.settings()['networks'] == ['192.168.0.0/24', '10.1.0.0/16']
    # a call from outside: 403 and an alert, once an hour per address
    where['ip'] = '203.0.113.9'
    for _ in range(3):
        r = _rpc(api, token, 'ping')
        assert r.status_code == 403 and r.get_json()['code'] == 'MCP_NETWORK'
    assert len(_events(told, 'mcp.denied')) == 1
    assert api.app.test_client().get('/api/vlab/mcp/moavi-desk.mcpb', base_url='http://localhost').status_code == 403
    # an admin session from outside cannot switch on, change the networks or make a token
    r = admin.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'read', 'user_password': PW})
    assert r.status_code == 403 and r.get_json()['code'] == 'MCP_NETWORK'
    assert admin.put('/api/vlab/admin/mcp', json={'enabled': True, 'user_password': PW}).get_json()['code'] == 'MCP_NETWORK'
    assert admin.get('/api/vlab/admin/mcp').get_json()['inside'] is False
    assert admin.delete(f"/api/vlab/admin/mcp/tokens/{rec['id']}").status_code == 200       # revoking works anywhere


def test_a_token_works_only_from_its_own_sources(env, net):
    api, admin, alice, bob, viewer = env
    where, told = net
    _on(admin)
    token, rec = _token(admin)
    assert _rpc(api, token, 'ping').status_code == 200
    where['ip'] = '10.9.9.9'                                   # an allowed network, not this token's
    r = _rpc(api, token, 'ping')
    assert r.status_code == 403 and r.get_json()['code'] == 'TOKEN_SOURCE'
    assert any('10.9.9.9' in t[1] for t in _events(told, 'mcp.source'))
    where['ip'] = INSIDE
    t2, _ = _token(admin, 'read', 'LM Studio', sources=['192.168.0.0/24', '10.9.9.0/24'])
    assert _rpc(api, t2, 'ping').status_code == 200
    assert _events(told, 'mcp.new_ip') == []                                     # the issuing PC is known
    where['ip'] = '10.9.9.9'
    assert _rpc(api, t2, 'ping').status_code == 200
    assert _rpc(api, t2, 'ping').status_code == 200
    assert len(_events(told, 'mcp.new_ip')) == 1 and '10.9.9.9' in _events(told, 'mcp.new_ip')[0][1]


def test_lifetimes_and_idle_tokens(env, net):
    api, admin, alice, bob, viewer = env
    _on(admin)
    assert _days(_token(admin, 'manage')[1]) == 7 and _days(_token(admin, 'read')[1]) == 30
    assert admin.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'manage', 'days': 91, 'user_password': PW}).status_code == 400
    assert admin.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'read', 'days': 366, 'user_password': PW}).status_code == 400
    assert _days(_token(admin, 'manage', days=90)[1]) == 90 and _days(_token(admin, 'read', days=365)[1]) == 365
    t, r = _token(admin, 'read')
    mcp.db().execute("UPDATE vlab_mcp_tokens SET expires_at = '2000-01-01T00:00:00+00:00' WHERE id = ?", (r['id'],))
    assert _rpc(api, t, 'ping').get_json()['code'] == 'TOKEN_EXPIRED'
    # unused for 30 days: revoked, when used and when the list is read
    t, r = _token(admin, 'read', 'old')
    mcp.db().execute("UPDATE vlab_mcp_tokens SET created_at = '2026-01-01T00:00:00+00:00', last_used_at = NULL WHERE id = ?", (r['id'],))
    assert _rpc(api, t, 'ping').get_json()['code'] == 'TOKEN_IDLE'
    assert mcp.get(r['id'])['revoked_by'] == 'idle'
    _, r2 = _token(admin, 'read', 'old2')
    mcp.db().execute("UPDATE vlab_mcp_tokens SET created_at = '2026-01-01T00:00:00+00:00' WHERE id = ?", (r2['id'],))
    admin.get('/api/vlab/admin/mcp')
    assert mcp.get(r2['id'])['revoked_by'] == 'idle'


def test_tokens_made_before_the_rules_are_revoked_and_old_rows_go(env, net):
    api, admin, alice, bob, viewer = env
    where, told = net
    _on(admin)
    # as the first release made them: no sources; a manage token for a year
    t1, r1 = _token(admin, 'manage', '노트북')
    mcp.db().execute("UPDATE vlab_mcp_tokens SET sources = '[]' WHERE id = ?", (r1['id'],))
    _, r2 = _token(admin, 'manage', '관리')
    mcp.db().execute("UPDATE vlab_mcp_tokens SET expires_at = '2027-10-22T10:34:00+00:00' WHERE id = ?", (r2['id'],))
    _, r3 = _token(admin, 'read', 'fine')
    r = _rpc(api, t1, 'ping')
    assert r.status_code == 401 and r.get_json()['code'] == 'TOKEN_LEGACY'
    listing = admin.get('/api/vlab/admin/mcp').get_json()
    by_id = {t['id']: t for t in listing['tokens']}
    assert by_id[r1['id']]['revoked_by'] == 'legacy' and not by_id[r1['id']]['active']
    assert by_id[r2['id']]['revoked_by'] == 'legacy' and by_id[r3['id']]['active']
    assert any('legacy' in str(t[2]['event']) for t in told)
    # revoked or run out more than 90 days ago: the row goes, the audit lines stay
    mcp.db().execute("UPDATE vlab_mcp_tokens SET revoked_at = '2026-01-01T00:00:00+00:00' WHERE id = ?", (r1['id'],))
    mcp.db().execute("UPDATE vlab_mcp_tokens SET expires_at = '2026-01-01T00:00:00+00:00', revoked_at = NULL WHERE id = ?", (r3['id'],))
    ids = {t['id'] for t in admin.get('/api/vlab/admin/mcp').get_json()['tokens']}
    assert r1['id'] not in ids and r3['id'] not in ids and r2['id'] in ids


def test_manage_tokens_are_for_platform_administrators(env, net, seed):
    api, admin, alice, bob, viewer = env
    from pegaprox.core.db import get_db
    from pegaprox.utils.auth import hash_password
    pooladm = api.as_user(seed.user('pam', role='user', permissions=['vlab.pool.view', 'vlab.pool.manage']))
    salt, h = hash_password(PW)
    get_db().save_user('pam', dict(get_db().get_user('pam'), password_salt=salt, password_hash=h))
    r = pooladm.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'manage', 'user_password': PW})
    assert r.status_code == 403 and r.get_json()['code'] == 'MISSING_PERMISSION'
    r = pooladm.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'read', 'user_password': PW})
    assert r.status_code == 201, r.get_json()
    assert pooladm.get('/api/vlab/admin/mcp').get_json()['can_manage'] is False


def test_the_endpoint_wants_a_live_token_and_the_server_on(env, net):
    api, admin, alice, bob, viewer = env
    token, rec = _token(admin)
    r = _rpc(api, None, 'initialize')
    assert r.status_code == 401 and r.headers['WWW-Authenticate'].startswith('Bearer ')
    assert _rpc(api, 'mcp_nope', 'initialize').get_json()['code'] == 'TOKEN_UNKNOWN'
    r = _rpc(api, token, 'initialize')
    assert r.status_code == 403 and r.get_json()['code'] == 'MCP_OFF'
    _on(admin)
    r = _rpc(api, token, 'initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                                        'clientInfo': {'name': 'claude-code', 'version': '2'}})
    assert r.status_code == 200 and r.get_json()['result']['protocolVersion'] == '2025-06-18'
    raw = api.app.test_client()
    h = {'Authorization': f'Bearer {token}'}
    assert raw.post('/api/vlab/mcp', json={'jsonrpc': '2.0', 'method': 'notifications/initialized'}, headers=h,
                    base_url='http://localhost').status_code == 202
    assert raw.get('/api/vlab/mcp', headers=h, base_url='http://localhost').status_code == 405
    assert _rpc(api, token, 'nope/nope').get_json()['error']['code'] == -32601
    assert _rpc(api, token, 'ping', headers={'Origin': 'https://evil.example'}).status_code == 403
    assert admin.delete(f"/api/vlab/admin/mcp/tokens/{rec['id']}").status_code == 200
    assert _rpc(api, token, 'ping').get_json()['code'] == 'TOKEN_REVOKED'


def test_a_read_token_sees_and_runs_the_read_tools_only(env, net):
    api, admin, alice, bob, viewer = env
    _on(admin)
    pool, desk = _pool_with_desktop(admin)
    read, _ = _token(admin, 'read', 'Ollama')
    manage, _ = _token(admin, 'manage')
    names = {t['name'] for t in _rpc(api, read, 'tools/list').get_json()['result']['tools']}
    every = {t['name']: t for t in _rpc(api, manage, 'tools/list').get_json()['result']['tools']}
    assert 'list_desktops' in names and 'assign_desktop' not in names and 'delete_desktop' not in names
    assert names < set(every) and every['delete_desktop']['annotations']['destructiveHint'] is True
    out = _call(api, read, 'list_desktops')
    assert out['isError'] is False and [d['id'] for d in out['structuredContent']['desktops']] == [desk['id']]
    out = _call(api, read, 'assign_desktop', desktop_id=desk['id'], username='alice')
    assert out['isError'] and '"SCOPE"' in out['content'][0]['text']
    from pegaprox.utils.auth import MCP_SESSION_ENVIRON
    r = api.app.test_client().put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'},
                                  headers={'X-Requested-With': 'XMLHttpRequest'}, base_url='http://localhost',
                                  environ_base={MCP_SESSION_ENVIRON: {'user': 'root', 'role': 'admin', 'mcp_scope': 'read'}})
    assert r.status_code == 403 and r.get_json()['code'] == 'MCP_READ_ONLY'
    out = _call(api, manage, 'assign_desktop', desktop_id=desk['id'], username='alice')
    assert out['isError'] is False and store.get_desktop(desk['id'])['assigned_user'] == 'alice'
    out = _call(api, manage, 'assign_desktop', desktop_id='../pools', username='bob')
    assert out['isError'] and 'desktop_id' in out['content'][0]['text']


def test_the_owner_permissions_apply(env, net):
    api, admin, alice, bob, viewer = env
    _on(admin)
    _pool_with_desktop(admin)
    token, _ = mcp.issue('alice', 'alice', 'manage', 7, sources=['192.168.0.0/24'], ip=INSIDE)
    out = _call(api, token, 'list_pools')
    assert out['isError'] and '"status": 403' in out['content'][0]['text']
    from pegaprox.core.db import get_db
    admin_token, _ = _token(admin, 'read')
    assert _call(api, admin_token, 'list_pools')['isError'] is False
    get_db().save_user('root', dict(get_db().get_user('root'), enabled=False))
    assert _rpc(api, admin_token, 'ping').get_json()['code'] == 'ACCOUNT_DISABLED'


def test_destructive_tools_need_confirm(env, net):
    api, admin, alice, bob, viewer = env
    _on(admin)
    pool, desk = _pool_with_desktop(admin)
    token, _ = _token(admin)
    for name, args in (('delete_desktop', {'desktop_id': desk['id'], 'confirm_name': desk['name']}),
                       ('rollback_snapshot', {'desktop_id': desk['id'], 'snapshot': 'before'}),
                       ('delete_snapshot', {'desktop_id': desk['id'], 'snapshot': 'before'}),
                       ('delete_vm', {'cluster_id': CID, 'vmid': 300, 'confirm_vmid': 300}),
                       ('cancel_template_build', {'build_id': 'dtb_x'}),
                       ('power_desktop', {'desktop_id': desk['id'], 'action': 'stop'})):
        out = _call(api, token, name, **args)
        assert out['isError'] and 'CONFIRM_REQUIRED' in out['content'][0]['text'], name
        out = _call(api, token, name, **dict(args, confirm='yes'))
        assert out['isError'] and 'CONFIRM_REQUIRED' in out['content'][0]['text'], name
    assert store.get_desktop(desk['id']) is not None
    out = _call(api, token, 'delete_vm', cluster_id=CID, vmid=300, confirm_vmid=300, confirm=True)
    assert out['isError'] and 'IS_DESKTOP' in out['content'][0]['text']


def test_every_call_is_audited_and_changes_are_told(env, net):
    api, admin, alice, bob, viewer = env
    where, told = net
    _on(admin)
    pool, desk = _pool_with_desktop(admin)
    token, rec = _token(admin, name='Gemini CLI')
    assert any('Gemini CLI' in t[1] for t in _events(told, 'mcp.issued'))
    audit.audit_log.clear()
    told.clear()
    _call(api, token, 'list_pools')
    _call(api, token, 'assign_desktop', desktop_id=desk['id'], username='bob')
    _call(api, token, 'delete_desktop', desktop_id=desk['id'], confirm_name=desk['name'])
    calls = [e for e in audit.audit_log if e['action'] == 'vlab.mcp.call']
    assert {e['user'] for e in calls} == {'root'} and len(calls) == 3
    details = ' | '.join(e['details'] for e in calls)
    assert 'list_pools (Gemini CLI, manage): ok' in details
    assert 'delete_desktop (Gemini CLI, manage): confirm_required' in details
    assign = [e for e in audit.audit_log if e['action'] == 'vlab.desktop.assign']
    assert assign and assign[0]['details'].endswith('(MCP: Gemini CLI)')
    ran = [t[1].split(' ran ')[1].split(' ')[0] for t in _events(told, 'mcp.manage')]
    assert ran == ['assign_desktop', 'delete_desktop']                                # not the read one
    admin.delete(f"/api/vlab/admin/mcp/tokens/{rec['id']}")
    assert _events(told, 'mcp.revoked')


def test_passwords_are_not_handed_to_the_ai_client():
    out = vm._scrub({'build': {'id': 'b'}, 'admin_password': 'S3cret!', 'admin_user': 'moavi',
                     'list': [{'ticket': 'PVEVNC:x', 'token_hint': 'ab12'}]})
    assert 'S3cret!' not in str(out) and 'PVEVNC:x' not in str(out)
    assert out['admin_user'] == 'moavi' and out['list'][0]['token_hint'] == 'ab12'


def test_network_helpers():
    assert mcp.parse_networks(['192.168.1.7', '10.0.0.0/8', '10.0.0.0/8'])[0] == ['192.168.1.7/32', '10.0.0.0/8']
    assert mcp.ip_in('::ffff:192.168.3.4', ['192.168.0.0/16']) and not mcp.ip_in('8.8.8.8', mcp.DEFAULT_NETWORKS)
    assert not mcp.ip_in('127.0.0.1', mcp.DEFAULT_NETWORKS) and not mcp.ip_in('bogus', ['10.0.0.0/8'])
    assert mcp.own_network('192.168.0.50') == '192.168.0.0/24' and mcp.own_network('fd00::5') == 'fd00::/64'


def test_the_downloads_are_served_inside(env, net):
    import io
    import json
    import zipfile
    api, admin, alice, bob, viewer = env
    raw = api.app.test_client()
    r = raw.get('/api/vlab/mcp/stdio.py', base_url='http://localhost')
    assert r.status_code == 200 and b'MOAVI_MCP_TOKEN' in r.data
    r = raw.get('/api/vlab/mcp/moavi-desk.mcpb', base_url='http://192.168.0.9:8443', headers={'X-Forwarded-Proto': 'https'})
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.data))
    assert sorted(z.namelist()) == ['manifest.json', 'server/index.js']
    m = json.loads(z.read('manifest.json'))
    assert m['user_config']['server_url']['default'] == 'https://192.168.0.9:8443/api/vlab/mcp'
    assert m['user_config']['token']['sensitive'] is True and 'default' not in m['user_config']['token']
