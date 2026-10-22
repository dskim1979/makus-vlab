"""MOAVI Desk: MCP access (플랫폼 설정 > MCP 연동) - an MCP client on the admin's PC or an internal server
(Claude Desktop, Claude Code, Gemini CLI, Codex CLI, a local LLM app) manages VMs through the engine's MCP
server at its internal address; the server is not meant to be opened to the Internet.

The server is off until an admin switches it on. Each token belongs to the account that made it and
acts as that account: the same roles, the same clusters, the same permission checks as in the
console. A token is `read` (the list and status tools only) or `manage` (those and the tools that
change things); it always runs out (at most a year) and can be revoked. It is shown once and kept as
a SHA-256 hash (`mcp_...`).

The routes and the tools are in pegaprox/api/vlab_mcp.py.
"""
import hashlib
import secrets
import threading
from datetime import datetime, timedelta, timezone

from pegaprox.core.db import get_db
from pegaprox.vlab.store import db as _store_db, new_id, now

KEY = 'vlab_mcp'
TOKEN_PREFIX = 'mcp_'
SCOPES = ('read', 'manage')
MAX_DAYS = 365
MAX_TOKENS_PER_USER = 20

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_mcp_tokens (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        owner TEXT NOT NULL,
        scope TEXT NOT NULL DEFAULT 'read',
        token_hash TEXT NOT NULL,
        token_hint TEXT NOT NULL DEFAULT '',
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked_at TEXT,
        revoked_by TEXT NOT NULL DEFAULT '',
        last_used_at TEXT,
        last_ip TEXT NOT NULL DEFAULT '',
        uses INTEGER NOT NULL DEFAULT 0
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_mcp_token ON vlab_mcp_tokens(token_hash)',
)
TABLES = ('vlab_mcp_tokens',)
_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_mcp', False):
        with _lock:
            if not getattr(d, '_vlab_mcp', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_mcp = True
    return d


# --- on / off ------------------------------------------------------------------------------

def settings():
    raw = get_db().get_server_setting(KEY, None)
    raw = raw if isinstance(raw, dict) else {}
    return {'enabled': bool(raw.get('enabled')), 'by': raw.get('by') or '', 'at': raw.get('at') or ''}


def set_enabled(on, by=''):
    get_db().save_server_setting(KEY, {'enabled': bool(on), 'by': by, 'at': now()})
    return settings()


# --- tokens --------------------------------------------------------------------------------

def _hash(token):
    return hashlib.sha256(str(token).encode()).hexdigest() if token else ''


def _view(r):
    if not r:
        return None
    v = dict(r)
    v.pop('token_hash', None)
    v['active'] = not v['revoked_at'] and v['expires_at'] > now()
    return v


def list_tokens(owner=None):
    if owner is not None:
        rows = db().query('SELECT * FROM vlab_mcp_tokens WHERE owner = ? ORDER BY created_at DESC', (owner,))
    else:
        rows = db().query('SELECT * FROM vlab_mcp_tokens ORDER BY created_at DESC')
    return [_view(r) for r in rows]


def get(token_id):
    return _view(db().query_one('SELECT * FROM vlab_mcp_tokens WHERE id = ?', (token_id,)))


def issue(owner, name, scope, days, by=''):
    """(token, record) - the token itself is in this answer only."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    tid = new_id('mcp')
    expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec='seconds')
    db().execute('INSERT INTO vlab_mcp_tokens (id, name, owner, scope, token_hash, token_hint, created_by, created_at, expires_at) '
                 'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                 (tid, name, owner, scope, _hash(token), token[-4:], by or owner, now(), expires))
    return token, get(tid)


def revoke(token_id, by=''):
    db().execute('UPDATE vlab_mcp_tokens SET revoked_at = ?, revoked_by = ? WHERE id = ? AND revoked_at IS NULL',
                 (now(), by, token_id))
    return get(token_id)


def active_count(owner):
    r = db().query_one('SELECT COUNT(*) AS n FROM vlab_mcp_tokens WHERE owner = ? AND revoked_at IS NULL AND expires_at > ?',
                       (owner, now()))
    return int(r['n'] or 0) if r else 0


def by_token(token):
    """(record, None) or (None, why): UNKNOWN, REVOKED, EXPIRED."""
    if not token or not str(token).startswith(TOKEN_PREFIX):
        return None, 'UNKNOWN'
    r = db().query_one('SELECT * FROM vlab_mcp_tokens WHERE token_hash = ?', (_hash(token),))
    if not r:
        return None, 'UNKNOWN'
    if r['revoked_at']:
        return None, 'REVOKED'
    if r['expires_at'] <= now():
        return None, 'EXPIRED'
    return _view(r), None


def used(token_id, ip=''):
    db().execute('UPDATE vlab_mcp_tokens SET last_used_at = ?, last_ip = ?, uses = uses + 1 WHERE id = ?',
                 (now(), str(ip or '')[:64], token_id))
