"""MOAVI Desk: CI connections (GPU · FPGA · NPU > 빌드 팜 > CI 연동) - GitLab CI, Jenkins or any tool that
can call a URL puts a build into the build farm queue and reads its result.

A connection belongs to one build farm pool and runs its jobs as one MOAVI Desk user (the
owner: their scratch folder, their quota, their notices). It has a token (shown once, kept as
a SHA-256 hash, `mci_...`) that can do one thing: send that connection's builds and read them.
The command is the connection's own; the CI may send its own command only when the connection
allows it. What the CI says about the build (repository, branch or tag, commit, pipeline link)
is kept on the job (source) and handed to the command as MOAVI_CI_* environment variables.

The routes are in pegaprox/api/vlab_builds.py.
"""
import hashlib
import json
import re
import secrets
import shlex
import threading
from datetime import datetime, timezone

from pegaprox.vlab.store import db as _store_db, new_id, now

KINDS = ('gitlab', 'jenkins', 'generic')
TOKEN_PREFIX = 'mci_'

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_ci_links (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        kind TEXT NOT NULL DEFAULT 'generic',
        pool_id TEXT NOT NULL,
        owner TEXT NOT NULL,
        command TEXT NOT NULL,
        workdir TEXT NOT NULL DEFAULT '',
        allow_command INTEGER NOT NULL DEFAULT 0,
        enabled INTEGER NOT NULL DEFAULT 1,
        expires_at TEXT,
        token_hash TEXT NOT NULL DEFAULT '',
        token_hint TEXT NOT NULL DEFAULT '',
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        uses INTEGER NOT NULL DEFAULT 0
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_ci_token ON vlab_ci_links(token_hash)',
)
TABLES = ('vlab_ci_links',)
_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_ci', False):
        with _lock:
            if not getattr(d, '_vlab_ci', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_ci = True
    return d


def _hash(token):
    return hashlib.sha256(str(token).encode()).hexdigest() if token else ''


def _view(r):
    if not r:
        return None
    v = dict(r)
    v.pop('token_hash', None)
    v['allow_command'] = bool(v['allow_command'])
    v['enabled'] = bool(v['enabled'])
    return v


def list_links(pool_id=None):
    if pool_id:
        rows = db().query('SELECT * FROM vlab_ci_links WHERE pool_id = ? ORDER BY created_at', (pool_id,))
    else:
        rows = db().query('SELECT * FROM vlab_ci_links ORDER BY created_at')
    return [_view(r) for r in rows]


def get(link_id):
    return _view(db().query_one('SELECT * FROM vlab_ci_links WHERE id = ?', (link_id,)))


_NAME = re.compile(r'^.{1,80}$', re.S)


def clean(data, current=None):
    """The fields of a create / update body over `current`. ValueError when wrong; the pool and
    the owner are checked by the route."""
    if not isinstance(data, dict):
        raise ValueError('A JSON object is required')
    out = dict(current or {'kind': 'generic', 'workdir': '', 'allow_command': False, 'enabled': True, 'expires_at': None})
    for k in ('name', 'pool_id', 'owner', 'command'):
        if k in data:
            v = str(data[k] or '').strip()
            if not v or len(v) > (2000 if k == 'command' else 120):
                raise ValueError(f'{k}: required' + (' (at most 2000 characters)' if k == 'command' else ''))
            out[k] = v
    if 'kind' in data:
        if data['kind'] not in KINDS:
            raise ValueError('kind: ' + ', '.join(KINDS))
        out['kind'] = data['kind']
    if 'workdir' in data:
        v = str(data['workdir'] or '').strip()
        if len(v) > 300 or (v and not v.startswith('/')):
            raise ValueError('workdir: an absolute folder on the build VM, or empty for the scratch folder')
        out['workdir'] = v
    for k in ('allow_command', 'enabled'):
        if k in data:
            if not isinstance(data[k], bool):
                raise ValueError(f'{k}: true or false')
            out[k] = data[k]
    if 'expires_at' in data:
        v = data['expires_at']
        if v in (None, ''):
            out['expires_at'] = None
        else:
            try:
                d = datetime.fromisoformat(str(v))
            except ValueError:
                raise ValueError('expires_at: an ISO date, or empty')
            out['expires_at'] = (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).isoformat(timespec='seconds')
    for k in ('name', 'pool_id', 'owner', 'command'):
        if not out.get(k):
            raise ValueError(f'{k}: required')
    return out


def save(link_id, fields, by=''):
    d = db()
    if link_id:
        d.execute('UPDATE vlab_ci_links SET name = ?, kind = ?, pool_id = ?, owner = ?, command = ?, workdir = ?, allow_command = ?, '
                  'enabled = ?, expires_at = ? WHERE id = ?',
                  (fields['name'], fields['kind'], fields['pool_id'], fields['owner'], fields['command'], fields['workdir'],
                   int(fields['allow_command']), int(fields['enabled']), fields['expires_at'], link_id))
        return get(link_id)
    lid = new_id('ci')
    d.execute('INSERT INTO vlab_ci_links (id, name, kind, pool_id, owner, command, workdir, allow_command, enabled, expires_at, '
              'created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
              (lid, fields['name'], fields['kind'], fields['pool_id'], fields['owner'], fields['command'], fields['workdir'],
               int(fields['allow_command']), int(fields['enabled']), fields['expires_at'], by, now()))
    return get(lid)


def delete(link_id):
    db().execute('DELETE FROM vlab_ci_links WHERE id = ?', (link_id,))


def new_token(link_id):
    """A fresh token for the connection (the old one stops working). Shown once."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    db().execute('UPDATE vlab_ci_links SET token_hash = ?, token_hint = ? WHERE id = ?', (_hash(token), token[-4:], link_id))
    return token


def by_token(token, at=None):
    """(link, None) or (None, why): UNKNOWN, OFF, EXPIRED."""
    if not token or not str(token).startswith(TOKEN_PREFIX):
        return None, 'UNKNOWN'
    r = db().query_one('SELECT * FROM vlab_ci_links WHERE token_hash = ?', (_hash(token),))
    if not r:
        return None, 'UNKNOWN'
    if not r['enabled']:
        return None, 'OFF'
    if r['expires_at'] and r['expires_at'] <= (at or datetime.now(timezone.utc)).isoformat(timespec='seconds'):
        return None, 'EXPIRED'
    return _view(r), None


def used(link_id):
    db().execute('UPDATE vlab_ci_links SET last_used_at = ?, uses = uses + 1 WHERE id = ?', (now(), link_id))


# --- what the CI says ----------------------------------------------------------------------

_SOURCE_LIMITS = {'repo': 300, 'ref': 200, 'commit': 64, 'url': 500, 'pipeline': 80, 'author': 120, 'message': 300}


def clean_source(data):
    """{repo, ref, commit, url, pipeline, author, message} from the CI's body (all optional)."""
    out = {}
    for k, n in _SOURCE_LIMITS.items():
        v = data.get(k)
        if v is None or v == '':
            continue
        v = str(v).strip().replace('\n', ' ')[:n]
        if k == 'commit' and not re.match(r'^[0-9A-Fa-f]{4,64}$', v):
            raise ValueError('commit: a hex commit id')
        if k == 'url' and not re.match(r'^https?://', v):
            raise ValueError('url: an http(s) link')
        out[k] = v
    return out


def command_with_source(command, source, link):
    """The command with the MOAVI_CI_* variables set before it."""
    env = {'MOAVI_CI': '1', 'MOAVI_CI_LINK': link['name'], 'MOAVI_CI_KIND': link['kind'],
           'MOAVI_CI_REPO': source.get('repo', ''), 'MOAVI_CI_REF': source.get('ref', ''),
           'MOAVI_CI_COMMIT': source.get('commit', ''), 'MOAVI_CI_URL': source.get('url', ''),
           'MOAVI_CI_PIPELINE': source.get('pipeline', '')}
    exports = ' '.join(f'{k}={shlex.quote(v)}' for k, v in env.items())
    return f'export {exports}; {command}'


def source_of(job):
    try:
        return json.loads(job.get('source') or '{}') or {}
    except ValueError:
        return {}
