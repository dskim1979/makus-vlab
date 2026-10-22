"""MOAVI Desk: MCP access (플랫폼 설정 > MCP 연동) - an MCP client on the admin's PC or an internal server
(Claude Desktop, Claude Code, Gemini CLI, Codex CLI, a local LLM app) manages VMs through the engine's MCP
server at its internal address; the server is not meant to be opened to the Internet.

The server is off until an admin switches it on. Each token belongs to the account that made it and
acts as that account: the same roles, the same clusters, the same permission checks as in the
console. A token is `read` (the list and status tools only) or `manage` (those and the tools that
change things). It is shown once and kept as a SHA-256 hash (`mcp_...`).

Internal-network rules: calls come only from the allowed networks (private ranges by default, never
an empty list), and a token only from its own sources (by default the network of the PC that made
it). A manage token lives at most 90 days (7 by default), a read token 365 (30); a token unused for 30
days is revoked. Every address a token was used from is kept, so a new one can be told about.

The routes and the tools are in pegaprox/api/vlab_mcp.py.
"""
import hashlib
import ipaddress
import json
import secrets
import threading
from datetime import datetime, timedelta, timezone

from pegaprox.core.db import get_db
from pegaprox.vlab.store import db as _store_db, new_id, now

KEY = 'vlab_mcp'
TOKEN_PREFIX = 'mcp_'
SCOPES = ('read', 'manage')
# scope -> (default days, most days)
LIFETIME = {'manage': (7, 90), 'read': (30, 365)}
IDLE_DAYS = 30
MAX_TOKENS_PER_USER = 20
MAX_NETWORKS = 50
MAX_SEEN = 50
DEFAULT_NETWORKS = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')

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
# added after the first release: a table made before has them added
_COLUMNS = {
    'sources': "TEXT NOT NULL DEFAULT '[]'",     # the networks the token may be used from
    'seen_ips': "TEXT NOT NULL DEFAULT '[]'",    # the addresses it was used from
    'created_ip': "TEXT NOT NULL DEFAULT ''",
}
TABLES = ('vlab_mcp_tokens',)
_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_mcp', False):
        with _lock:
            if not getattr(d, '_vlab_mcp', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                have = {r['name'] for r in d.query('PRAGMA table_info(vlab_mcp_tokens)')}
                for col, decl in _COLUMNS.items():
                    if col not in have:
                        d.execute(f'ALTER TABLE vlab_mcp_tokens ADD COLUMN {col} {decl}')
                d._vlab_mcp = True
    return d


# --- networks ------------------------------------------------------------------------------

def parse_networks(values):
    """(['10.0.0.0/8', ...], None) or (None, error). A bare address is a /32 (/128); a catch-all is refused."""
    if not isinstance(values, list) or not values:
        return None, 'networks: at least one network (an empty list would let nobody in - switch MCP off instead)'
    if len(values) > MAX_NETWORKS:
        return None, f'networks: at most {MAX_NETWORKS}'
    out = []
    for v in values:
        try:
            n = ipaddress.ip_network(str(v).strip(), strict=False)
        except ValueError:
            return None, f'networks: {str(v)[:60]} is not an address or a network (CIDR)'
        if n.prefixlen == 0:
            return None, 'networks: a network for every address (/0) is not allowed'
        if str(n) not in out:
            out.append(str(n))
    return out, None


def ip_in(ip, networks):
    try:
        a = ipaddress.ip_address(str(ip or '').strip())
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    for n in networks or ():
        try:
            if a in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def own_network(ip):
    """The network a token is limited to by default: the /24 (IPv4) or /64 (IPv6) of the PC that made it."""
    try:
        a = ipaddress.ip_address(str(ip or '').strip())
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return str(ipaddress.ip_network(f'{a}/{24 if a.version == 4 else 64}', strict=False))


# --- on / off ------------------------------------------------------------------------------

def settings():
    raw = get_db().get_server_setting(KEY, None)
    raw = raw if isinstance(raw, dict) else {}
    nets, err = parse_networks(raw.get('networks') or list(DEFAULT_NETWORKS))
    return {'enabled': bool(raw.get('enabled')), 'networks': nets if not err else list(DEFAULT_NETWORKS),
            'by': raw.get('by') or '', 'at': raw.get('at') or ''}


def save_settings(enabled=None, networks=None, by=''):
    cur = settings()
    if enabled is not None:
        cur['enabled'] = bool(enabled)
    if networks is not None:
        cur['networks'] = networks
    cur.update(by=by, at=now())
    get_db().save_server_setting(KEY, cur)
    return settings()


def set_enabled(on, by=''):
    return save_settings(enabled=on, by=by)


# --- tokens --------------------------------------------------------------------------------

def _hash(token):
    return hashlib.sha256(str(token).encode()).hexdigest() if token else ''


def _list(text):
    try:
        v = json.loads(text or '[]')
    except ValueError:
        return []
    return v if isinstance(v, list) else []


def _view(r):
    if not r:
        return None
    v = dict(r)
    v.pop('token_hash', None)
    v['sources'] = _list(v.get('sources'))
    v['seen_ips'] = _list(v.get('seen_ips'))
    v['active'] = not v['revoked_at'] and v['expires_at'] > now()
    return v


def _days_ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec='seconds')


def revoke_idle():
    """Revoke the live tokens not used for IDLE_DAYS (counted from their making when never used). The ones revoked."""
    cut = _days_ago(IDLE_DAYS)
    rows = db().query('SELECT * FROM vlab_mcp_tokens WHERE revoked_at IS NULL AND expires_at > ? '
                      'AND COALESCE(last_used_at, created_at) < ?', (now(), cut))
    for r in rows:
        db().execute("UPDATE vlab_mcp_tokens SET revoked_at = ?, revoked_by = 'idle' WHERE id = ? AND revoked_at IS NULL",
                     (now(), r['id']))
    return [_view(r) for r in rows]


def list_tokens(owner=None):
    if owner is not None:
        rows = db().query('SELECT * FROM vlab_mcp_tokens WHERE owner = ? ORDER BY created_at DESC', (owner,))
    else:
        rows = db().query('SELECT * FROM vlab_mcp_tokens ORDER BY created_at DESC')
    return [_view(r) for r in rows]


def get(token_id):
    return _view(db().query_one('SELECT * FROM vlab_mcp_tokens WHERE id = ?', (token_id,)))


def issue(owner, name, scope, days, by='', sources=(), ip=''):
    """(token, record) - the token itself is in this answer only."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    tid = new_id('mcp')
    expires = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec='seconds')
    seen = [ip] if ip else []
    db().execute('INSERT INTO vlab_mcp_tokens (id, name, owner, scope, token_hash, token_hint, created_by, created_at, expires_at, '
                 'sources, seen_ips, created_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                 (tid, name, owner, scope, _hash(token), token[-4:], by or owner, now(), expires,
                  json.dumps(list(sources)), json.dumps(seen), str(ip or '')[:64]))
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
    """(record, None) or (None, why): UNKNOWN, REVOKED, EXPIRED, IDLE (revoked now: unused for IDLE_DAYS)."""
    if not token or not str(token).startswith(TOKEN_PREFIX):
        return None, 'UNKNOWN'
    r = db().query_one('SELECT * FROM vlab_mcp_tokens WHERE token_hash = ?', (_hash(token),))
    if not r:
        return None, 'UNKNOWN'
    if r['revoked_at']:
        return None, 'REVOKED'
    if r['expires_at'] <= now():
        return None, 'EXPIRED'
    if (r['last_used_at'] or r['created_at']) < _days_ago(IDLE_DAYS):
        db().execute("UPDATE vlab_mcp_tokens SET revoked_at = ?, revoked_by = 'idle' WHERE id = ?", (now(), r['id']))
        return None, 'IDLE'
    return _view(r), None


def used(token_id, ip=''):
    """Count a use. True when `ip` was not seen with this token before."""
    r = db().query_one('SELECT seen_ips FROM vlab_mcp_tokens WHERE id = ?', (token_id,))
    seen = _list(r['seen_ips']) if r else []
    new = bool(ip) and ip not in seen
    if new:
        seen = (seen + [ip])[-MAX_SEEN:]
    db().execute('UPDATE vlab_mcp_tokens SET last_used_at = ?, last_ip = ?, uses = uses + 1, seen_ips = ? WHERE id = ?',
                 (now(), str(ip or '')[:64], json.dumps(seen), token_id))
    return new
