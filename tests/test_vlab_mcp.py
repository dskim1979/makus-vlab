"""MOAVI Desk MCP server for administrators (pegaprox/vlab/mcp.py, pegaprox/api/vlab_mcp.py)."""
import hashlib

from pegaprox.utils import audit
from pegaprox.vlab import mcp, store
from test_vlab_api import CID, _pool_with_desktop, env  # noqa: F401 - the shared fixture


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
    assert admin.put('/api/vlab/admin/mcp', json={'enabled': True}).status_code == 200


def _token(admin, scope='manage', name='Claude Code', days=30):
    r = admin.post('/api/vlab/admin/mcp/tokens', json={'name': name, 'scope': scope, 'days': days})
    assert r.status_code == 201, r.get_json()
    return r.get_json()['token'], r.get_json()['record']


def test_tokens_are_shown_once_and_kept_as_a_hash(env):
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
    assert admin.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'all'}).status_code == 400
    assert admin.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'read', 'days': 400}).status_code == 400
    assert admin.post('/api/vlab/admin/mcp/tokens', json={'name': '', 'scope': 'read'}).status_code == 400
    # an account without the admin screens cannot make one, nor switch the server on
    assert alice.post('/api/vlab/admin/mcp/tokens', json={'name': 'x', 'scope': 'read'}).status_code == 403
    assert alice.put('/api/vlab/admin/mcp', json={'enabled': True}).status_code == 403


def test_the_endpoint_wants_a_live_token_and_the_server_on(env):
    api, admin, alice, bob, viewer = env
    token, rec = _token(admin)
    r = _rpc(api, None, 'initialize')
    assert r.status_code == 401 and r.headers['WWW-Authenticate'].startswith('Bearer ')
    assert _rpc(api, 'mcp_nope', 'initialize').get_json()['code'] == 'TOKEN_UNKNOWN'
    assert _rpc(api, 'pgx_other', 'initialize').status_code == 401
    r = _rpc(api, token, 'initialize')
    assert r.status_code == 403 and r.get_json()['code'] == 'MCP_OFF'
    _on(admin)
    r = _rpc(api, token, 'initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                                        'clientInfo': {'name': 'claude-code', 'version': '2'}})
    body = r.get_json()
    assert r.status_code == 200 and body['id'] == 1
    assert body['result']['protocolVersion'] == '2025-06-18' and 'tools' in body['result']['capabilities']
    assert _rpc(api, token, 'initialize', {'protocolVersion': '1999-01-01'}).get_json()['result']['protocolVersion'] == '2025-11-25'
    # a notification has no answer; GET opens no stream
    raw = api.app.test_client()
    h = {'Authorization': f'Bearer {token}'}
    assert raw.post('/api/vlab/mcp', json={'jsonrpc': '2.0', 'method': 'notifications/initialized'}, headers=h,
                    base_url='http://localhost').status_code == 202
    assert raw.get('/api/vlab/mcp', headers=h, base_url='http://localhost').status_code == 405
    assert _rpc(api, token, 'nope/nope').get_json()['error']['code'] == -32601
    assert raw.post('/api/vlab/mcp', data='{', content_type='application/json', headers=h,
                    base_url='http://localhost').get_json()['error']['code'] == -32700
    # a browser page of another site may not drive it
    assert _rpc(api, token, 'ping', headers={'Origin': 'https://evil.example'}).status_code == 403
    assert _rpc(api, token, 'ping', headers={'Origin': 'http://localhost'}).status_code == 200
    # revoked or run out: refused
    assert admin.delete(f"/api/vlab/admin/mcp/tokens/{rec['id']}").status_code == 200
    assert _rpc(api, token, 'ping').get_json()['code'] == 'TOKEN_REVOKED'
    t2, rec2 = _token(admin)
    mcp.db().execute("UPDATE vlab_mcp_tokens SET expires_at = '2000-01-01T00:00:00+00:00' WHERE id = ?", (rec2['id'],))
    assert _rpc(api, t2, 'ping').get_json()['code'] == 'TOKEN_EXPIRED'


def test_a_read_token_sees_and_runs_the_read_tools_only(env):
    api, admin, alice, bob, viewer = env
    _on(admin)
    pool, desk = _pool_with_desktop(admin)
    read, _ = _token(admin, 'read', 'Ollama')
    manage, _ = _token(admin, 'manage')
    names = {t['name'] for t in _rpc(api, read, 'tools/list').get_json()['result']['tools']}
    every = {t['name']: t for t in _rpc(api, manage, 'tools/list').get_json()['result']['tools']}
    assert 'list_desktops' in names and 'assign_desktop' not in names and 'delete_desktop' not in names
    assert names < set(every) and {'create_vm_from_iso', 'delete_desktop', 'start_template_build'} <= set(every)
    assert every['delete_desktop']['annotations']['destructiveHint'] is True
    assert every['list_pools']['annotations']['readOnlyHint'] is True
    out = _call(api, read, 'list_desktops')
    assert out['isError'] is False and [d['id'] for d in out['structuredContent']['desktops']] == [desk['id']]
    out = _call(api, read, 'assign_desktop', desktop_id=desk['id'], username='alice')
    assert out['isError'] and '"SCOPE"' in out['content'][0]['text']
    assert store.get_desktop(desk['id'])['assigned_user'] is None
    # and the routes refuse a change for a read token themselves
    from pegaprox.utils.auth import MCP_SESSION_ENVIRON
    r = api.app.test_client().put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'},
                                  headers={'X-Requested-With': 'XMLHttpRequest'}, base_url='http://localhost',
                                  environ_base={MCP_SESSION_ENVIRON: {'user': 'root', 'role': 'admin', 'mcp_scope': 'read'}})
    assert r.status_code == 403 and r.get_json()['code'] == 'MCP_READ_ONLY'
    # a manage token changes things
    out = _call(api, manage, 'assign_desktop', desktop_id=desk['id'], username='alice')
    assert out['isError'] is False and store.get_desktop(desk['id'])['assigned_user'] == 'alice'
    # an id is an id, not a path
    out = _call(api, manage, 'assign_desktop', desktop_id='../pools', username='bob')
    assert out['isError'] and 'desktop_id' in out['content'][0]['text']


def test_the_owner_permissions_apply(env):
    api, admin, alice, bob, viewer = env
    _on(admin)
    _pool_with_desktop(admin)
    # alice (role user) has no admin screens: her token gets the routes' 403, nothing else
    token, _ = mcp.issue('alice', 'alice', 'manage', 30)
    out = _call(api, token, 'list_pools')
    assert out['isError'] and '"status": 403' in out['content'][0]['text']
    out = _call(api, token, 'list_desktops')
    assert out['isError'] and '"status": 403' in out['content'][0]['text']
    # the owner's role is read at each call: a disabled owner stops the token
    from pegaprox.core.db import get_db
    admin_token, _ = _token(admin, 'read')
    assert _call(api, admin_token, 'list_pools')['isError'] is False
    get_db().save_user('root', dict(get_db().get_user('root'), enabled=False))
    assert _rpc(api, admin_token, 'ping').get_json()['code'] == 'ACCOUNT_DISABLED'


def test_destructive_tools_need_confirm(env):
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
    # a pool desktop is not deleted as a bare VM
    out = _call(api, token, 'delete_vm', cluster_id=CID, vmid=300, confirm_vmid=300, confirm=True)
    assert out['isError'] and 'IS_DESKTOP' in out['content'][0]['text']
    out = _call(api, token, 'delete_vm', cluster_id=CID, vmid=300, confirm_vmid=301, confirm=True)
    assert out['isError'] and 'confirm_vmid' in out['content'][0]['text']


def test_every_call_is_audited(env):
    api, admin, alice, bob, viewer = env
    _on(admin)
    pool, desk = _pool_with_desktop(admin)
    token, _ = _token(admin, name='Gemini CLI')
    audit.audit_log.clear()
    _call(api, token, 'list_pools')
    _call(api, token, 'assign_desktop', desktop_id=desk['id'], username='bob')
    _call(api, token, 'delete_desktop', desktop_id=desk['id'], confirm_name=desk['name'])
    calls = [e for e in audit.audit_log if e['action'] == 'vlab.mcp.call']
    assert {e['user'] for e in calls} == {'root'} and len(calls) == 3
    details = ' | '.join(e['details'] for e in calls)
    assert 'list_pools (Gemini CLI, manage): ok' in details and 'assign_desktop' in details
    assert 'delete_desktop (Gemini CLI, manage): confirm_required' in details
    # the route's own line says it came through MCP
    assign = [e for e in audit.audit_log if e['action'] == 'vlab.desktop.assign']
    assert assign and assign[0]['details'].endswith('(MCP: Gemini CLI)') and assign[0]['user'] == 'root'
    rec = mcp.list_tokens('root')[0]
    assert rec['uses'] >= 3 and rec['last_used_at']


def test_passwords_are_not_handed_to_the_ai_client():
    from pegaprox.api.vlab_mcp import _scrub
    out = _scrub({'build': {'id': 'b'}, 'admin_password': 'S3cret!', 'admin_user': 'moavi',
                  'list': [{'ticket': 'PVEVNC:x', 'token_hint': 'ab12'}]})
    assert 'S3cret!' not in str(out) and 'PVEVNC:x' not in str(out)
    assert out['admin_user'] == 'moavi' and out['list'][0]['token_hint'] == 'ab12'


def test_the_stdio_bridge_is_served(env):
    api, admin, alice, bob, viewer = env
    r = api.app.test_client().get('/api/vlab/mcp/stdio.py', base_url='http://localhost')
    assert r.status_code == 200 and b'MOAVI_MCP_TOKEN' in r.data
