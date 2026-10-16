# -*- coding: utf-8 -*-
"""
MOAVI Desk - research data (연구 데이터): the dataset catalog, moving files between the portal and
a user's folders on the shared storage, and export control (반출 통제).

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

Datasets (vlab_datasets): a folder on a NAS registered by a data steward (vlab.data.manage) -
name (the folder name the desktops see), title, description, version, licence, source, who
may use it (users, departments with their sub-departments, directory groups; nobody listed =
everyone in its pools) and its export rule. Desktops of its pools see it read-only:

  Linux     /nas/datasets/<name> - one multi-mount entry `datasets` in the pool's autofs map
            (pegaprox/vlab/nas.py autofs_files), each dataset an offset with `ro`. The key wins
            over the map's wildcard, so a share's own top folder called datasets is hidden.
  Windows   D:\\datasets\\<name> (C:\\datasets when D: is not a fixed disk) - a symbolic link
            to the dataset's SMB path, made by the agent as SYSTEM; SMB datasets only.

The map line on a desktop carries only the datasets one of its users may use; the NAS's own
permissions (a read-only export, read for the users group) are the boundary that holds.

Files (portal > 데이터): the user's own home and scratch folders and their team's project
folder, through the pool's admin mount on the engine host (nas admin_path) - or, when the pool
has none, through the guest agent of one of the user's running Linux desktops (small files
only, AGENT_MAX_BYTES). Uploads come in parts (a tus-like protocol: create, PATCH with
Upload-Offset, HEAD/GET for the offset to resume), are hashed (SHA-256) when the last part is
in and only then take the file's name. Downloads answer Range requests.

Export control (vlab_data_policies per pool, export on each dataset): allow / approval / deny.
With approval the user asks with a reason, a data steward approves, and the user gets a link
that works once (the first request starts it; later requests may only resume with a Range)
until it expires. Every upload, download, request and decision is in vlab_data_transfers or
vlab_data_requests and the audit log (path, size, SHA-256).

Paths: every path a client sends is relative, '/' separated, without '..', NUL, control
characters, backslashes or a drive, and is resolved under its root with realpath - a
symbolic link that points out of the folder is refused too (resolve).
"""

import hashlib
import json
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone

from pegaprox.vlab import nas
from pegaprox.vlab.store import db as _store_db, new_id, now

EXPORT = ('allow', 'approval', 'deny')
SUBJECTS = ('user', 'department', 'group')
FOLDERS = ('home', 'project', 'scratch')
STATUSES = ('pending', 'approved', 'rejected', 'cancelled', 'expired')
WINDOWS_ROOT = 'D:\\datasets'
MOUNT_DIR = 'datasets'               # /nas/datasets/<name>
AGENT_MAX_BYTES = 10 * 1024 * 1024   # through the guest agent (its exec output stops at 16 MiB, base64 adds a third)
CHUNK = 8 * 1024 * 1024              # what the portal sends per part
MAX_CHUNK = 9 * 1024 * 1024          # under the engine's 10 MB request limit
HASH_INLINE_MAX = 2 * 1024 ** 3      # a download of a file not hashed yet is hashed first up to this size
RESUME_HOURS = 6                     # a one-time link may resume this long after it started
PART = '.moavi-upload-'              # the name of a file still coming in

POLICY_DEFAULTS = {
    'export': 'allow',       # downloads from the pool's folders
    'upload': True,
    'max_file_gb': 100,      # 0: no limit
    'link_hours': 24,        # how long an approved download link works
    'quota_block': False,    # refuse an upload that would go over the folder's quota
    'sftp': {'host': '', 'port': 22, 'note': ''},
}

DATASET_FIELDS = ('name', 'title', 'description', 'version', 'license', 'source', 'kind', 'server', 'share',
                  'nfs_version', 'admin_path', 'pool_ids', 'access', 'export', 'tags', 'enabled')
DATASET_DEFAULTS = {'title': '', 'description': '', 'version': '', 'license': '', 'source': '', 'kind': 'nfs',
                    'server': '', 'share': '', 'nfs_version': '3', 'admin_path': '', 'pool_ids': [], 'access': [],
                    'export': 'approval', 'tags': [], 'enabled': True}

_NAME = re.compile(r'^[a-z0-9][a-z0-9._-]{0,63}$')
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_datasets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        version TEXT NOT NULL DEFAULT '',
        license TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL DEFAULT 'nfs',
        server TEXT NOT NULL DEFAULT '',
        share TEXT NOT NULL DEFAULT '',
        nfs_version TEXT NOT NULL DEFAULT '3',
        admin_path TEXT NOT NULL DEFAULT '',
        pool_ids TEXT NOT NULL DEFAULT '[]',
        access TEXT NOT NULL DEFAULT '[]',
        export TEXT NOT NULL DEFAULT 'approval',
        tags TEXT NOT NULL DEFAULT '[]',
        enabled INTEGER NOT NULL DEFAULT 1,
        size_bytes INTEGER,
        files INTEGER,
        measured_at TEXT,
        measure_error TEXT NOT NULL DEFAULT '',
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_data_policies (
        pool_id TEXT PRIMARY KEY,
        config TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT NOT NULL
    )''',
    # export requests and the one-time link of an approved one (only its hash is kept)
    '''CREATE TABLE IF NOT EXISTS vlab_data_requests (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        pool_id TEXT NOT NULL DEFAULT '',
        dataset_id TEXT NOT NULL DEFAULT '',
        folder TEXT NOT NULL DEFAULT '',
        path TEXT NOT NULL,
        size INTEGER NOT NULL DEFAULT 0,
        reason TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        reviewed_by TEXT NOT NULL DEFAULT '',
        reviewed_at TEXT,
        note TEXT NOT NULL DEFAULT '',
        token_hash TEXT NOT NULL DEFAULT '',
        expires_at TEXT,
        started_at TEXT,
        created_at TEXT NOT NULL
    )''',
    # every upload and download, good or failed: the export report and the support bundle read it
    '''CREATE TABLE IF NOT EXISTS vlab_data_transfers (
        id TEXT PRIMARY KEY,
        at TEXT NOT NULL,
        username TEXT NOT NULL,
        direction TEXT NOT NULL,
        pool_id TEXT NOT NULL DEFAULT '',
        dataset_id TEXT NOT NULL DEFAULT '',
        folder TEXT NOT NULL DEFAULT '',
        path TEXT NOT NULL DEFAULT '',
        size INTEGER NOT NULL DEFAULT 0,
        sha256 TEXT NOT NULL DEFAULT '',
        ok INTEGER NOT NULL DEFAULT 1,
        error TEXT NOT NULL DEFAULT '',
        via TEXT NOT NULL DEFAULT 'engine',
        request_id TEXT NOT NULL DEFAULT '',
        ip TEXT NOT NULL DEFAULT ''
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_data_transfers_at ON vlab_data_transfers(at)',
    # uploads in progress: the part file sits on this host (agent) or next to the target (engine)
    '''CREATE TABLE IF NOT EXISTS vlab_data_uploads (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        pool_id TEXT NOT NULL,
        folder TEXT NOT NULL,
        path TEXT NOT NULL DEFAULT '',
        name TEXT NOT NULL,
        size INTEGER NOT NULL,
        received INTEGER NOT NULL DEFAULT 0,
        via TEXT NOT NULL DEFAULT 'engine',
        temp TEXT NOT NULL DEFAULT '',
        overwrite INTEGER NOT NULL DEFAULT 0,
        desktop_id TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )''',
    # a file's SHA-256 by where it is, its size and its time: a download does not hash it again
    '''CREATE TABLE IF NOT EXISTS vlab_data_hashes (
        path TEXT PRIMARY KEY,
        size INTEGER NOT NULL,
        mtime REAL NOT NULL,
        sha256 TEXT NOT NULL,
        at TEXT NOT NULL
    )''',
)
TABLES = ('vlab_datasets', 'vlab_data_policies', 'vlab_data_requests', 'vlab_data_transfers')
LOCAL = ('vlab_data_uploads', 'vlab_data_hashes')

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_data', False):
        with _lock:
            if not getattr(d, '_vlab_data', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_data = True
    return d


def _loads(text, empty):
    try:
        v = json.loads(text or '')
    except (TypeError, ValueError):
        return empty
    return v if isinstance(v, type(empty)) else empty


# --- paths -------------------------------------------------------------------------------

def clean_rel(rel):
    """A client's relative path as 'a/b/c' ('' is the folder itself). ValueError for anything
    that could leave the folder or mean something else on another system."""
    if rel is None:
        return ''
    if not isinstance(rel, str) or len(rel) > 1024:
        raise ValueError('path: text of at most 1024 characters')
    if _CONTROL.search(rel) or '\\' in rel:
        raise ValueError('path: no control characters or backslashes')
    if rel.startswith('/') or re.match(r'^[A-Za-z]:', rel):
        raise ValueError('path: relative to the folder, not absolute')
    parts = [p for p in rel.split('/') if p not in ('', '.')]
    for p in parts:
        if p == '..':
            raise ValueError('path: .. is not allowed')
        if len(p) > 255:
            raise ValueError('path: a name of at most 255 characters')
    return '/'.join(parts)


def clean_name(name):
    """One file or folder name."""
    if not isinstance(name, str) or not name or '/' in name:
        raise ValueError('name: one file name without /')
    n = clean_rel(name)
    if n != name or n.startswith(PART):
        raise ValueError(f'name: {name!r} cannot be a file name here')
    return n


def resolve(root, rel):
    """The real path of `rel` under `root`. ValueError when it is not under it - also through a
    symbolic link that points out."""
    rel = clean_rel(rel)
    base = os.path.realpath(root)
    target = os.path.realpath(os.path.join(base, *rel.split('/'))) if rel else base
    if target != base and not target.startswith(base.rstrip(os.sep) + os.sep):
        raise ValueError('path: outside the folder')
    return target


def join_rel(*parts):
    return '/'.join(p for p in parts if p)


# --- datasets ----------------------------------------------------------------------------

def _view(r):
    v = dict(r)
    for k in ('pool_ids', 'access', 'tags'):
        v[k] = _loads(v.get(k), [])
    v['enabled'] = bool(v['enabled'])
    return v


def list_datasets():
    return [_view(r) for r in db().query('SELECT * FROM vlab_datasets ORDER BY name')]


def get_dataset(ds_id):
    r = db().query_one('SELECT * FROM vlab_datasets WHERE id = ?', (ds_id,))
    return _view(r) if r else None


def by_name(name):
    r = db().query_one('SELECT * FROM vlab_datasets WHERE name = ?', (name,))
    return _view(r) if r else None


def _text(data, k, limit, out, multiline=False):
    v = data.get(k)
    if not isinstance(v, str):
        return f'{k} must be text'
    v = v.strip()
    probe = re.sub(r'[\r\n\t]', '', v) if multiline else v
    if len(v) > limit or _CONTROL.search(probe):
        return f'{k}: at most {limit} characters' + ('' if multiline else ' on one line')
    out[k] = v
    return None


def _subjects(v, field='access'):
    if not isinstance(v, list) or len(v) > 200:
        return None, f'{field}: a list of at most 200 entries'
    out, seen = [], set()
    for s in v:
        if not isinstance(s, dict) or s.get('subject_type') not in SUBJECTS or not isinstance(s.get('subject_id'), str) \
                or not s['subject_id'].strip() or len(s['subject_id']) > 200:
            return None, f'{field}: each entry is {{subject_type: user|department|group, subject_id}}'
        key = (s['subject_type'], s['subject_id'].strip())
        if key not in seen:
            seen.add(key)
            out.append({'subject_type': key[0], 'subject_id': key[1]})
    return out, None


def validate_dataset(data, current=None):
    """(dataset fields, None) or (None, error); fields left out keep `current`'s."""
    if not isinstance(data, dict):
        return None, 'JSON object required'
    unknown = sorted(set(data) - set(DATASET_FIELDS) - {'id', 'size_bytes', 'files', 'measured_at', 'measure_error',
                                                          'created_by', 'created_at', 'updated_at'})
    if unknown:
        return None, f"unknown fields: {', '.join(unknown)}"
    out = dict(DATASET_DEFAULTS, **{k: v for k, v in (current or {}).items() if k in DATASET_FIELDS})
    for k in ('title', 'version', 'license', 'source', 'server', 'share', 'admin_path', 'name'):
        if k in data:
            err = _text(data, k, {'title': 120, 'version': 40, 'license': 200, 'source': 500, 'name': 64}.get(k, 255), out)
            if err:
                return None, err
    if 'description' in data:
        err = _text(data, 'description', 4000, out, multiline=True)
        if err:
            return None, err
    for k in ('kind', 'nfs_version', 'export'):
        if k in data:
            out[k] = data[k]
    if 'enabled' in data:
        if not isinstance(data['enabled'], bool):
            return None, 'enabled must be true or false'
        out['enabled'] = data['enabled']
    if 'pool_ids' in data:
        v = data['pool_ids']
        if not isinstance(v, list) or len(v) > 200 or not all(isinstance(x, str) and 0 < len(x) <= 64 for x in v):
            return None, 'pool_ids: a list of pool ids (none = every pool with shared storage)'
        out['pool_ids'] = sorted(set(v))
    if 'access' in data:
        out['access'], err = _subjects(data['access'])
        if err:
            return None, err
    if 'tags' in data:
        v = data['tags']
        if not isinstance(v, list) or len(v) > 20 or not all(isinstance(x, str) and 0 < len(x.strip()) <= 40 and not _CONTROL.search(x) for x in v):
            return None, 'tags: at most 20, each at most 40 characters'
        out['tags'] = sorted({x.strip() for x in v})
    out['name'] = out.get('name', '').lower()
    if not _NAME.match(out['name']):
        return None, 'name: lower-case letters, digits, . _ - (the folder name on the desktops)'
    if out['kind'] not in nas.KINDS:
        return None, 'kind must be nfs or smb'
    if out['nfs_version'] not in nas.NFS_VERSIONS:
        return None, 'nfs_version must be 3, 4.1 or krb5'
    if out['export'] not in EXPORT:
        return None, 'export must be allow, approval or deny'
    out['server'] = out['server'].strip('[]')
    if not out['server'] or not nas._HOST.match(out['server']):
        return None, 'server must be a host name or an IP address'
    if out['kind'] == 'nfs':
        if not nas._NFS_EXPORT.match(out['share']) or '..' in out['share'] or out['share'] == '/':
            return None, 'share: the dataset folder on the NAS, like /export/datasets/imagenet'
        out['share'] = out['share'].rstrip('/')
    else:
        out['share'] = out['share'].replace('\\', '/').strip('/')
        if not nas._SMB_SHARE.match(out['share']) or '..' in out['share']:
            return None, 'share: the SMB share and folder, like datasets/imagenet'
    if out['admin_path'] and (not nas._ABS_PATH.match(out['admin_path']) or '..' in out['admin_path']
                              or out['admin_path'] in nas._RESERVED):
        return None, 'admin_path: where the dataset is mounted on the engine host, like /srv/moavi-data/imagenet'
    return out, None


def save_dataset(ds_id, fields, user):
    """Insert (ds_id None) or update. Returns the dataset; ValueError when the name is taken."""
    other = by_name(fields['name'])
    if other and other['id'] != ds_id:
        raise ValueError(f"a dataset called {fields['name']} exists")
    cols = {k: (json.dumps(fields[k], ensure_ascii=False) if k in ('pool_ids', 'access', 'tags') else
                int(fields[k]) if k == 'enabled' else fields[k]) for k in DATASET_FIELDS}
    if ds_id:
        db().execute(f"UPDATE vlab_datasets SET {', '.join(f'{k} = ?' for k in cols)}, updated_at = ? WHERE id = ?",
                     tuple(cols.values()) + (now(), ds_id))
    else:
        ds_id = new_id('ds')
        db().execute(f"INSERT INTO vlab_datasets (id, {', '.join(cols)}, created_by, created_at, updated_at) "
                     f"VALUES (?, {', '.join('?' for _ in cols)}, ?, ?, ?)",
                     (ds_id,) + tuple(cols.values()) + (user, now(), now()))
    return get_dataset(ds_id)


def delete_dataset(ds_id):
    db().execute('DELETE FROM vlab_datasets WHERE id = ?', (ds_id,))
    db().execute("UPDATE vlab_data_requests SET status = 'cancelled' WHERE dataset_id = ? AND status IN ('pending', 'approved')", (ds_id,))


def set_measure(ds_id, size_bytes, files, error=''):
    db().execute('UPDATE vlab_datasets SET size_bytes = ?, files = ?, measured_at = ?, measure_error = ? WHERE id = ?',
                 (size_bytes, files, now(), (error or '')[:300], ds_id))


def may_use(ds, username, dep, groups, descendants):
    """Does the dataset's access list reach the user? Nobody listed: everyone in its pools."""
    if not ds['access']:
        return True
    for s in ds['access']:
        if s['subject_type'] == 'user' and s['subject_id'] == username:
            return True
        if s['subject_type'] == 'department' and dep and dep in descendants(s['subject_id']):
            return True
        if s['subject_type'] == 'group' and s['subject_id'].lower() in groups:
            return True
    return False


def in_pool(ds, pool_id):
    return ds['enabled'] and (not ds['pool_ids'] or pool_id in ds['pool_ids'])


def desktop_paths(ds, linux_root='/nas'):
    return {'linux': f"{linux_root.rstrip('/') or ''}/{MOUNT_DIR}/{ds['name']}",
            'windows': f"{WINDOWS_ROOT}\\{ds['name']}" if ds['kind'] == 'smb' else None}


def nas_path(ds):
    if ds['kind'] == 'smb':
        return f"\\\\{ds['server']}\\{ds['share'].replace('/', chr(92))}"
    return f"{ds['server']}:{ds['share']}"


def autofs_entry(datasets):
    """The `datasets` multi-mount line of the pool's autofs map: each dataset an offset,
    read-only. None without datasets."""
    offs = []
    for ds in sorted(datasets, key=lambda d: d['name']):
        if ds['kind'] == 'nfs':
            ver = {'3': 'vers=3', '4.1': 'vers=4.1', 'krb5': 'vers=4.1,sec=krb5p'}[ds['nfs_version']]
            offs.append(f"/{ds['name']} -fstype=nfs,ro,{ver},hard {ds['server']}:{ds['share']}")
        else:
            offs.append(f"/{ds['name']} -fstype=cifs,ro,sec=krb5,multiuser,cruid=0 ://{ds['server']}/{ds['share']}")
    return f"{MOUNT_DIR} " + ' '.join(offs) if offs else None


def windows_links(datasets):
    """PowerShell lines (inside nas.windows_script, as SYSTEM): D:\\datasets\\<name> links to each
    SMB dataset, stale links removed. $changed is set when something changed."""
    smb = sorted((d for d in datasets if d['kind'] == 'smb'), key=lambda d: d['name'])
    pairs = '; '.join(f"'{d['name']}' = '{nas_path(d)}'" for d in smb)
    return [
        "$dsRoot = 'C:\\datasets'",
        "try { if (([IO.DriveInfo]'D:\\').DriveType -eq 'Fixed') { $dsRoot = '" + WINDOWS_ROOT + "' } } catch { }",
        '$dsWant = @{' + pairs + '}',
        'if ($dsWant.Count -gt 0 -or (Test-Path -LiteralPath $dsRoot)) {',
        '  New-Item -ItemType Directory -Force -Path $dsRoot | Out-Null',
        '  foreach ($k in $dsWant.Keys) {',
        '    $p = Join-Path $dsRoot $k; $i = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue',
        '    if ($i -and ([string]$i.Target) -ne $dsWant[$k]) { cmd /c rmdir "$p" | Out-Null; $i = $null }',
        '    if (-not $i) { New-Item -ItemType SymbolicLink -Path $p -Target $dsWant[$k] | Out-Null; $changed = 1 }',
        '  }',
        "  Get-ChildItem -LiteralPath $dsRoot | Where-Object { $_.LinkType -eq 'SymbolicLink' -and -not $dsWant.ContainsKey($_.Name) } |"
        ' ForEach-Object { cmd /c rmdir "$($_.FullName)" | Out-Null; $changed = 1 }',
        '  "datasets=$dsRoot"',
        '}',
    ]


# --- export policy per pool --------------------------------------------------------------

def get_policy(pool_id):
    r = db().query_one('SELECT config FROM vlab_data_policies WHERE pool_id = ?', (pool_id,))
    out = dict(POLICY_DEFAULTS, sftp=dict(POLICY_DEFAULTS['sftp']))
    stored = _loads(r['config'], {}) if r else {}
    out.update({k: v for k, v in stored.items() if k in POLICY_DEFAULTS and k != 'sftp'})
    out['sftp'].update({k: v for k, v in (stored.get('sftp') or {}).items() if k in POLICY_DEFAULTS['sftp']})
    return out


def validate_policy(data, current):
    if not isinstance(data, dict):
        return None, 'JSON object required'
    unknown = sorted(set(data) - set(POLICY_DEFAULTS))
    if unknown:
        return None, f"unknown fields: {', '.join(unknown)}"
    out = dict(current, sftp=dict(current['sftp']))
    for k, v in data.items():
        if k == 'export':
            if v not in EXPORT:
                return None, 'export must be allow, approval or deny'
        elif k in ('upload', 'quota_block'):
            if not isinstance(v, bool):
                return None, f'{k} must be true or false'
        elif k in ('max_file_gb', 'link_hours'):
            top = 100000 if k == 'max_file_gb' else 24 * 30
            if not isinstance(v, int) or isinstance(v, bool) or not (0 if k == 'max_file_gb' else 1) <= v <= top:
                return None, f'{k} must be a whole number' + (' (0 for no limit)' if k == 'max_file_gb' else ' of hours, 1 to 720')
        elif k == 'sftp':
            if not isinstance(v, dict) or set(v) - set(POLICY_DEFAULTS['sftp']):
                return None, 'sftp: {host, port, note}'
            s = dict(out['sftp'])
            for x, y in v.items():
                if x == 'port' and (not isinstance(y, int) or isinstance(y, bool) or not 1 <= y <= 65535):
                    return None, 'sftp.port: 1 to 65535'
                if x in ('host', 'note') and (not isinstance(y, str) or len(y) > (255 if x == 'host' else 500) or _CONTROL.search(y)):
                    return None, f'sftp.{x}: text on one line'
                s[x] = y.strip() if isinstance(y, str) else y
            if s['host'] and not nas._HOST.match(s['host']):
                return None, 'sftp.host must be a host name or an IP address'
            v = s
        out[k] = v
    return out, None


def save_policy(pool_id, cfg):
    db().execute('INSERT OR REPLACE INTO vlab_data_policies (pool_id, config, updated_at) VALUES (?, ?, ?)',
                 (pool_id, json.dumps(cfg, ensure_ascii=False), now()))
    return get_policy(pool_id)


def forget_pool(pool_id):
    db().execute('DELETE FROM vlab_data_policies WHERE pool_id = ?', (pool_id,))


# --- export requests and one-time links --------------------------------------------------

def _req_view(r):
    v = dict(r)
    v.pop('token_hash', None)
    return v


def token_hash(token):
    return hashlib.sha256(str(token).encode('utf-8')).hexdigest()


def _parse(iso):
    try:
        t = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _expire():
    for r in db().query("SELECT id, expires_at FROM vlab_data_requests WHERE status = 'approved'"):
        t = _parse(r['expires_at'])
        if t and t < datetime.now(timezone.utc):
            db().execute("UPDATE vlab_data_requests SET status = 'expired' WHERE id = ?", (r['id'],))


def create_request(username, pool_id, dataset_id, folder, path, size, reason):
    rid = new_id('dreq')
    db().execute('INSERT INTO vlab_data_requests (id, username, pool_id, dataset_id, folder, path, size, reason, status, created_at) '
                 "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)",
                 (rid, username, pool_id or '', dataset_id or '', folder or '', path, int(size or 0), reason, now()))
    return get_request(rid)


def get_request(rid, raw=False):
    r = db().query_one('SELECT * FROM vlab_data_requests WHERE id = ?', (rid,))
    return (dict(r) if raw else _req_view(r)) if r else None


def list_requests(username=None, status=None, limit=500):
    _expire()
    where, args = [], []
    if username is not None:
        where.append('username = ?')
        args.append(username)
    if status:
        where.append('status = ?')
        args.append(status)
    sql = 'SELECT * FROM vlab_data_requests' + (' WHERE ' + ' AND '.join(where) if where else '') + ' ORDER BY created_at DESC LIMIT ?'
    return [_req_view(r) for r in db().query(sql, tuple(args) + (int(limit),))]


def pending_like(username, pool_id, dataset_id, folder, path):
    r = db().query_one("SELECT id FROM vlab_data_requests WHERE username = ? AND pool_id = ? AND dataset_id = ? AND folder = ? "
                       "AND path = ? AND status = 'pending'", (username, pool_id or '', dataset_id or '', folder or '', path))
    return r['id'] if r else None


def approve(rid, reviewer, hours, note=''):
    exp = (datetime.now(timezone.utc) + timedelta(hours=int(hours))).isoformat(timespec='seconds')
    db().execute("UPDATE vlab_data_requests SET status = 'approved', reviewed_by = ?, reviewed_at = ?, note = ?, "
                 "expires_at = ? WHERE id = ? AND status = 'pending'", (reviewer, now(), note, exp, rid))


def issue_link(rid):
    """A new token for an approved request that has not started: the requester asks for it when
    they download, so nobody else - the approver neither - ever sees it. Only its hash is kept;
    asking again replaces the earlier one."""
    token = secrets.token_urlsafe(32)
    db().execute("UPDATE vlab_data_requests SET token_hash = ? WHERE id = ? AND status = 'approved' AND started_at IS NULL",
                 (token_hash(token), rid))
    return token


def reject(rid, reviewer, note):
    db().execute("UPDATE vlab_data_requests SET status = 'rejected', reviewed_by = ?, reviewed_at = ?, note = ? "
                 "WHERE id = ? AND status = 'pending'", (reviewer, now(), note, rid))


def cancel(rid):
    db().execute("UPDATE vlab_data_requests SET status = 'cancelled', token_hash = '' WHERE id = ? AND status IN ('pending', 'approved')", (rid,))


def by_token(token):
    if not isinstance(token, str) or not 20 <= len(token) <= 100:
        return None
    r = db().query_one('SELECT * FROM vlab_data_requests WHERE token_hash = ?', (token_hash(token),))
    return dict(r) if r else None


def link_state(req, resume):
    """None when the link may be used now (marks it started), else why not: EXPIRED, USED, NOT_APPROVED.
    resume: the request carries a Range that does not start at 0."""
    if req['status'] != 'approved':
        return 'NOT_APPROVED'
    t = _parse(req['expires_at'])
    if not t or t < datetime.now(timezone.utc):
        db().execute("UPDATE vlab_data_requests SET status = 'expired' WHERE id = ?", (req['id'],))
        return 'EXPIRED'
    if req['started_at']:
        s = _parse(req['started_at'])
        if not resume or not s or (datetime.now(timezone.utc) - s) > timedelta(hours=RESUME_HOURS):
            return 'USED'
        return None
    db().execute('UPDATE vlab_data_requests SET started_at = ? WHERE id = ?', (now(), req['id']))
    return None


# --- the transfer log --------------------------------------------------------------------

def log_transfer(username, direction, pool_id='', dataset_id='', folder='', path='', size=0, sha256='', ok=True,
                 error='', via='engine', request_id='', ip=''):
    db().execute('INSERT INTO vlab_data_transfers (id, at, username, direction, pool_id, dataset_id, folder, path, size, sha256, ok, '
                 'error, via, request_id, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                 (new_id('dx'), now(), username, direction, pool_id or '', dataset_id or '', folder or '', path[:1024], int(size or 0),
                  sha256 or '', int(bool(ok)), (error or '')[:500], via, request_id or '', ip or ''))


def transfers(since=None, username=None, direction=None, ok=None, limit=5000):
    where, args = [], []
    for col, val in (('username', username), ('direction', direction)):
        if val:
            where.append(f'{col} = ?')
            args.append(val)
    if since:
        where.append('at >= ?')
        args.append(since)
    if ok is not None:
        where.append('ok = ?')
        args.append(int(bool(ok)))
    sql = 'SELECT * FROM vlab_data_transfers' + (' WHERE ' + ' AND '.join(where) if where else '') + ' ORDER BY at DESC LIMIT ?'
    out = []
    for r in db().query(sql, tuple(args) + (int(limit),)):
        v = dict(r)
        v['ok'] = bool(v['ok'])
        out.append(v)
    return out


def report(rows, dataset_names, pool_names):
    """Downloads (exports) and uploads added up per user and per dataset or pool."""
    users, sources = {}, {}
    totals = {'downloads': 0, 'download_bytes': 0, 'uploads': 0, 'upload_bytes': 0, 'failed': 0, 'approved_links': 0}
    for r in rows:
        if not r['ok']:
            totals['failed'] += 1
            continue
        down = r['direction'] == 'download'
        totals['downloads' if down else 'uploads'] += 1
        totals['download_bytes' if down else 'upload_bytes'] += r['size']
        if down and r['request_id']:
            totals['approved_links'] += 1
        u = users.setdefault(r['username'], {'username': r['username'], 'downloads': 0, 'download_bytes': 0, 'uploads': 0, 'upload_bytes': 0})
        u['downloads' if down else 'uploads'] += 1
        u['download_bytes' if down else 'upload_bytes'] += r['size']
        if r['dataset_id']:
            key, name, kind = r['dataset_id'], dataset_names.get(r['dataset_id'], r['dataset_id']), 'dataset'
        else:
            key, name, kind = f"{r['pool_id']}/{r['folder']}", f"{pool_names.get(r['pool_id'], r['pool_id'])} · {r['folder']}", 'folder'
        s = sources.setdefault(key, {'key': key, 'name': name, 'kind': kind, 'downloads': 0, 'download_bytes': 0, 'uploads': 0,
                                     'upload_bytes': 0, 'users': set()})
        s['downloads' if down else 'uploads'] += 1
        s['download_bytes' if down else 'upload_bytes'] += r['size']
        s['users'].add(r['username'])
    for s in sources.values():
        s['users'] = len(s['users'])
    return {'totals': totals, 'by_user': sorted(users.values(), key=lambda x: -x['download_bytes']),
            'by_source': sorted(sources.values(), key=lambda x: -x['download_bytes'])}


# --- hashes, sizes -----------------------------------------------------------------------

def sha256_file(path, limit=None):
    """The file's SHA-256 (cached by path, size and time), '' when larger than `limit`."""
    st = os.stat(path)
    r = db().query_one('SELECT * FROM vlab_data_hashes WHERE path = ?', (path,))
    if r and r['size'] == st.st_size and abs(r['mtime'] - st.st_mtime) < 0.001:
        return r['sha256']
    if limit is not None and st.st_size > limit:
        return ''
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(block)
    remember_hash(path, st.st_size, st.st_mtime, h.hexdigest())
    return h.hexdigest()


def remember_hash(path, size, mtime, digest):
    db().execute('INSERT OR REPLACE INTO vlab_data_hashes (path, size, mtime, sha256, at) VALUES (?, ?, ?, ?, ?)',
                 (path, int(size), float(mtime), digest, now()))


def measure(root, budget_s=20.0, max_entries=2_000_000):
    """(bytes, files, complete) of a folder tree, walked with a time budget; symbolic links not followed."""
    import time
    end, total, files, complete = time.monotonic() + budget_s, 0, 0, True
    stack = [root]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
                    elif e.is_file(follow_symlinks=False):
                        try:
                            total += e.stat(follow_symlinks=False).st_size
                        except OSError:
                            continue
                        files += 1
                    if files >= max_entries or time.monotonic() > end:
                        return total, files, False
        except OSError:
            complete = False
    return total, files, complete


def listing(path, limit=2000):
    """The entries of a folder: [{name, type: dir|file|link, size, mtime}], folders first; part files left out."""
    out = []
    with os.scandir(path) as it:
        for e in it:
            if e.name.startswith(PART):
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            kind = 'link' if e.is_symlink() else 'dir' if e.is_dir(follow_symlinks=False) else 'file'
            out.append({'name': e.name, 'type': kind, 'size': st.st_size if kind == 'file' else 0,
                        'mtime': datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(timespec='seconds')})
            if len(out) >= limit:
                break
    return sorted(out, key=lambda x: (x['type'] != 'dir', x['name'].lower()))


# --- uploads -----------------------------------------------------------------------------

def _up_view(r):
    v = dict(r)
    v['overwrite'] = bool(v['overwrite'])
    v.pop('temp', None)
    return v


def new_upload(username, pool_id, folder, path, name, size, via, temp, overwrite, desktop_id=''):
    uid = new_id('up')
    db().execute('INSERT INTO vlab_data_uploads (id, username, pool_id, folder, path, name, size, received, via, temp, overwrite, '
                 'desktop_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)',
                 (uid, username, pool_id, folder, path, name, int(size), via, temp.replace('{id}', uid), int(bool(overwrite)),
                  desktop_id, now(), now()))
    return get_upload(uid, raw=True)


def get_upload(uid, raw=False):
    r = db().query_one('SELECT * FROM vlab_data_uploads WHERE id = ?', (uid,))
    return (dict(r) if raw else _up_view(r)) if r else None


def uploads_of(username):
    return [_up_view(r) for r in db().query('SELECT * FROM vlab_data_uploads WHERE username = ? ORDER BY created_at DESC', (username,))]


def set_received(uid, n):
    db().execute('UPDATE vlab_data_uploads SET received = ?, updated_at = ? WHERE id = ?', (int(n), now(), uid))


def drop_upload(uid):
    db().execute('DELETE FROM vlab_data_uploads WHERE id = ?', (uid,))


def stale_uploads(days=7):
    cut = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec='seconds')
    return [dict(r) for r in db().query('SELECT * FROM vlab_data_uploads WHERE updated_at < ?', (cut,))]
