# -*- coding: utf-8 -*-
"""
MOAVI Desk - the next-phase catalogues: departments, sign-up requests, the USB device
library, gateways, external desktops, golden images, board lab boards and licence servers.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

Tables live in the core DB beside the other vlab_* tables and are made on first use, like
store.py's. Each list here is small (tens to hundreds of rows), so reads load whole tables.
"""

import json
import os
import re
import threading

from pegaprox.vlab.store import db as _store_db, new_id, now

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_departments (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        parent_id TEXT,
        sort INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_user_departments (
        username TEXT PRIMARY KEY,
        department_id TEXT NOT NULL
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_signups (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        display_name TEXT NOT NULL DEFAULT '',
        email TEXT NOT NULL DEFAULT '',
        department_id TEXT,
        note TEXT NOT NULL DEFAULT '',
        password_salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        reviewed_by TEXT NOT NULL DEFAULT '',
        reviewed_at TEXT,
        reason TEXT NOT NULL DEFAULT '',
        client_ip TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_usb_devices (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        vid TEXT NOT NULL,
        pid TEXT NOT NULL DEFAULT '',
        category TEXT NOT NULL DEFAULT 'other',
        notes TEXT NOT NULL DEFAULT '',
        builtin INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        UNIQUE (vid, pid)
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_gateways (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        kind TEXT NOT NULL,
        address TEXT NOT NULL,
        port INTEGER NOT NULL,
        notes TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1,
        last_check TEXT,
        last_ok INTEGER,
        last_detail TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_external_desktops (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        address TEXT NOT NULL,
        port INTEGER NOT NULL DEFAULT 3389,
        assigned_user TEXT,
        gateway_id TEXT,
        notes TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_golden_images (
        id TEXT PRIMARY KEY,
        cluster_id TEXT NOT NULL,
        node TEXT NOT NULL,
        vmid INTEGER NOT NULL,
        vm_type TEXT NOT NULL DEFAULT 'qemu',
        name TEXT NOT NULL,
        current_version TEXT NOT NULL DEFAULT '',
        notes TEXT NOT NULL DEFAULT '',
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        UNIQUE (cluster_id, vmid)
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_boards (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        cluster_id TEXT NOT NULL,
        node TEXT NOT NULL,
        usb TEXT NOT NULL,
        kind TEXT NOT NULL DEFAULT '',
        attached_desktop TEXT,
        attached_vmid INTEGER,
        attached_by TEXT NOT NULL DEFAULT '',
        attached_at TEXT,
        notes TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_desktop_versions (
        desktop_id TEXT PRIMARY KEY,
        golden_id TEXT NOT NULL,
        version TEXT NOT NULL,
        at TEXT NOT NULL
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_build_jobs (
        id TEXT PRIMARY KEY,
        pool_id TEXT NOT NULL,
        username TEXT NOT NULL,
        name TEXT NOT NULL,
        command TEXT NOT NULL,
        workdir TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'queued',
        desktop_id TEXT,
        pid INTEGER,
        exit_code INTEGER,
        output TEXT NOT NULL DEFAULT '',
        error TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_license_servers (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        ports TEXT NOT NULL DEFAULT '[]',
        cluster_id TEXT NOT NULL DEFAULT '',
        vmid INTEGER,
        fixed_mac TEXT NOT NULL DEFAULT '',
        notes TEXT NOT NULL DEFAULT '',
        last_check TEXT,
        last_ok INTEGER,
        last_detail TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL
    )''',
)

TABLES = ('vlab_departments', 'vlab_user_departments', 'vlab_signups', 'vlab_usb_devices', 'vlab_gateways',
          'vlab_external_desktops', 'vlab_golden_images', 'vlab_boards', 'vlab_license_servers',
          'vlab_desktop_versions', 'vlab_build_jobs')

# columns added after a table first shipped: (table, column, definition)
_COLUMNS = (
    ('vlab_gateways', 'secret_key', "TEXT NOT NULL DEFAULT ''"),          # Guacamole (guacamole-auth-json)
    ('vlab_boards', 'lease_user', "TEXT NOT NULL DEFAULT ''"),
    # who hears of the department's GPU quota steps (pegaprox/api/vlab_notices.py)
    ('vlab_departments', 'manager', "TEXT NOT NULL DEFAULT ''"),
    ('vlab_boards', 'lease_until', 'TEXT'),
    ('vlab_license_servers', 'watch', 'INTEGER NOT NULL DEFAULT 1'),
    ('vlab_license_servers', 'alerted_at', 'TEXT'),
    # licence seats (pegaprox/vlab/license_usage.py): how they are read, thresholds, the last read
    ('vlab_license_servers', 'usage_mode', "TEXT NOT NULL DEFAULT 'off'"),
    ('vlab_license_servers', 'lm_ports', "TEXT NOT NULL DEFAULT '[]'"),
    ('vlab_license_servers', 'lmutil_path', "TEXT NOT NULL DEFAULT ''"),
    ('vlab_license_servers', 'debug_log', "TEXT NOT NULL DEFAULT ''"),
    ('vlab_license_servers', 'seat_threshold', 'INTEGER NOT NULL DEFAULT 90'),
    ('vlab_license_servers', 'feature_thresholds', "TEXT NOT NULL DEFAULT '{}'"),
    ('vlab_license_servers', 'alert_channels', 'TEXT'),
    ('vlab_license_servers', 'seat_alerted', "TEXT NOT NULL DEFAULT '{}'"),
    ('vlab_license_servers', 'usage_at', 'TEXT'),
    ('vlab_license_servers', 'usage_ok', 'INTEGER'),
    ('vlab_license_servers', 'usage_error', "TEXT NOT NULL DEFAULT ''"),
    # GPU jobs (pegaprox/vlab/research.py): what a build job asks for, where it got its GPUs, who hears of its end
    ('vlab_build_jobs', 'gpus', 'INTEGER NOT NULL DEFAULT 0'),
    ('vlab_build_jobs', 'gpu_kind', "TEXT NOT NULL DEFAULT ''"),
    ('vlab_build_jobs', 'memory_gb', 'INTEGER NOT NULL DEFAULT 0'),
    ('vlab_build_jobs', 'max_minutes', 'INTEGER NOT NULL DEFAULT 0'),
    ('vlab_build_jobs', 'env', "TEXT NOT NULL DEFAULT ''"),
    ('vlab_build_jobs', 'notify', "TEXT NOT NULL DEFAULT ''"),
    ('vlab_build_jobs', 'gpu_index', "TEXT NOT NULL DEFAULT ''"),
    ('vlab_build_jobs', 'wait_reason', "TEXT NOT NULL DEFAULT ''"),
    ('vlab_build_jobs', 'department_id', "TEXT NOT NULL DEFAULT ''"),
    ('vlab_build_jobs', 'notified_at', 'TEXT'),
)

# USB library entries every install starts with: the JTAG cables of FPGA boards. Generic names
# (the vendor ids identify them); confirm the exact product ids on the real cables.
BUILTIN_USB = (
    ('FPGA 플랫폼 케이블 (USB JTAG)', '03fd', '0008', 'jtag', '벤더 03fd · 실물로 PID 확인'),
    ('FTDI 기반 JTAG (보드 내장)', '0403', '', 'jtag', 'VID 0403 전체 · 보드마다 PID가 다름'),
    ('Digilent JTAG', '1443', '', 'jtag', 'VID 1443 전체'),
)

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_catalog', False):
        with _lock:
            if not getattr(d, '_vlab_catalog', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                for table, col, definition in _COLUMNS:
                    have = {r['name'] for r in d.query(f'PRAGMA table_info({table})')}
                    if col not in have:
                        d.execute(f'ALTER TABLE {table} ADD COLUMN {col} {definition}')
                d._vlab_catalog = True
    return d


def _rows(sql, args=()):
    return [dict(r) for r in db().query(sql, args)]


def _one(sql, args=()):
    r = db().query_one(sql, args)
    return dict(r) if r else None


# --- departments -------------------------------------------------------------------------

def list_departments():
    deps = _rows('SELECT * FROM vlab_departments ORDER BY sort, name')
    counts = {}
    for r in _rows('SELECT department_id, COUNT(*) AS n FROM vlab_user_departments GROUP BY department_id'):
        counts[r['department_id']] = r['n']
    for d in deps:
        d['members'] = counts.get(d['id'], 0)
    return deps


def get_department(dep_id):
    return _one('SELECT * FROM vlab_departments WHERE id = ?', (dep_id,))


def save_department(dep_id, name, parent_id=None, sort=0, manager=None):
    """manager: the user who hears of the department's GPU quota (None keeps it, '' clears it)."""
    if dep_id:
        db().execute('UPDATE vlab_departments SET name = ?, parent_id = ?, sort = ? WHERE id = ?', (name, parent_id, sort, dep_id))
    else:
        dep_id = new_id('dep')
        db().execute('INSERT INTO vlab_departments (id, name, parent_id, sort, created_at) VALUES (?, ?, ?, ?, ?)',
                     (dep_id, name, parent_id, sort, now()))
    if manager is not None:
        db().execute('UPDATE vlab_departments SET manager = ? WHERE id = ?', (manager, dep_id))
    return get_department(dep_id)


def descendants(dep_id):
    """The department and every department under it."""
    deps = _rows('SELECT id, parent_id FROM vlab_departments')
    out, todo = {dep_id}, [dep_id]
    while todo:
        cur = todo.pop()
        for d in deps:
            if d['parent_id'] == cur and d['id'] not in out:
                out.add(d['id'])
                todo.append(d['id'])
    return out


def delete_department(dep_id):
    db().execute('DELETE FROM vlab_user_departments WHERE department_id = ?', (dep_id,))
    db().execute('DELETE FROM vlab_departments WHERE id = ?', (dep_id,))


def members(dep_ids):
    ids = list(dep_ids)
    if not ids:
        return []
    marks = ','.join('?' * len(ids))
    return _rows(f'SELECT username, department_id FROM vlab_user_departments WHERE department_id IN ({marks}) ORDER BY username', ids)


def department_of(username):
    r = _one('SELECT department_id FROM vlab_user_departments WHERE username = ?', (username,))
    return r['department_id'] if r else None


def user_departments():
    return {r['username']: r['department_id'] for r in _rows('SELECT * FROM vlab_user_departments')}


def set_department(username, dep_id):
    if dep_id:
        db().execute('INSERT OR REPLACE INTO vlab_user_departments (username, department_id) VALUES (?, ?)', (username, dep_id))
    else:
        db().execute('DELETE FROM vlab_user_departments WHERE username = ?', (username,))


# --- sign-up requests --------------------------------------------------------------------

def _signup_row(r):
    if not r:
        return None
    s = dict(r)
    s.pop('password_salt', None)
    s.pop('password_hash', None)
    return s


def list_signups(status=None):
    if status:
        rows = db().query('SELECT * FROM vlab_signups WHERE status = ? ORDER BY created_at DESC', (status,))
    else:
        rows = db().query('SELECT * FROM vlab_signups ORDER BY created_at DESC LIMIT 500')
    return [_signup_row(r) for r in rows]


def get_signup(sid, with_secret=False):
    r = _one('SELECT * FROM vlab_signups WHERE id = ?', (sid,))
    return r if with_secret else _signup_row(r)


def pending_signup_for(username):
    return _one("SELECT id FROM vlab_signups WHERE username = ? AND status = 'pending'", (username,))


def count_pending():
    r = _one("SELECT COUNT(*) AS n FROM vlab_signups WHERE status = 'pending'")
    return r['n'] if r else 0


def add_signup(username, display_name, email, department_id, note, salt, password_hash, client_ip):
    sid = new_id('sig')
    db().execute('INSERT INTO vlab_signups (id, username, display_name, email, department_id, note, password_salt, password_hash, '
                 'status, client_ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                 (sid, username, display_name, email, department_id, note, salt, password_hash, 'pending', client_ip, now()))
    return get_signup(sid)


def review_signup(sid, status, reviewer, reason=''):
    db().execute("UPDATE vlab_signups SET status = ?, reviewed_by = ?, reviewed_at = ?, reason = ?, "
                 "password_salt = CASE WHEN ? = 'pending' THEN password_salt ELSE '' END, "
                 "password_hash = CASE WHEN ? = 'pending' THEN password_hash ELSE '' END WHERE id = ?",
                 (status, reviewer, now(), reason, status, status, sid))
    return get_signup(sid)


# --- USB device library ------------------------------------------------------------------

HEX4 = re.compile(r'^[0-9a-f]{4}$')
USB_CATEGORIES = ('jtag', 'security-key', 'storage', 'serial', 'camera', 'other')


def list_usb_devices():
    rows = _rows('SELECT * FROM vlab_usb_devices ORDER BY builtin DESC, name')
    if not rows and not _one("SELECT id FROM vlab_usb_devices LIMIT 1"):
        for name, vid, pid, cat, notes in BUILTIN_USB:
            db().execute('INSERT OR IGNORE INTO vlab_usb_devices (id, name, vid, pid, category, notes, builtin, created_at) '
                         'VALUES (?, ?, ?, ?, ?, ?, 1, ?)', (new_id('usb'), name, vid, pid, cat, notes, now()))
        rows = _rows('SELECT * FROM vlab_usb_devices ORDER BY builtin DESC, name')
    return rows


def get_usb_device(uid):
    return _one('SELECT * FROM vlab_usb_devices WHERE id = ?', (uid,))


def usb_device_by_ids(vid, pid):
    return _one('SELECT * FROM vlab_usb_devices WHERE vid = ? AND pid = ?', (vid, pid))


def save_usb_device(uid, name, vid, pid, category, notes):
    if uid:
        db().execute('UPDATE vlab_usb_devices SET name = ?, vid = ?, pid = ?, category = ?, notes = ? WHERE id = ?',
                     (name, vid, pid, category, notes, uid))
    else:
        uid = new_id('usb')
        db().execute('INSERT INTO vlab_usb_devices (id, name, vid, pid, category, notes, builtin, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)',
                     (uid, name, vid, pid, category, notes, now()))
    return get_usb_device(uid)


def delete_usb_device(uid):
    db().execute('DELETE FROM vlab_usb_devices WHERE id = ?', (uid,))


# --- gateways ----------------------------------------------------------------------------

GATEWAY_KINDS = {'guacamole': 8080, 'rdpgw': 443, 'msrdgw': 443}


def _gateway_row(r, secret=False):
    if not r:
        return None
    g = dict(r)
    key = g.pop('secret_key', '')
    g['has_key'] = bool(key)
    if secret:
        g['secret_key'] = key
    return g


def list_gateways(secret=False):
    return [_gateway_row(r, secret) for r in db().query('SELECT * FROM vlab_gateways ORDER BY name')]


def get_gateway(gid, secret=False):
    return _gateway_row(db().query_one('SELECT * FROM vlab_gateways WHERE id = ?', (gid,)), secret)


def save_gateway(gid, name, kind, address, port, notes, enabled, secret_key=None):
    if gid:
        db().execute('UPDATE vlab_gateways SET name = ?, kind = ?, address = ?, port = ?, notes = ?, enabled = ? WHERE id = ?',
                     (name, kind, address, port, notes, int(enabled), gid))
    else:
        gid = new_id('gw')
        db().execute('INSERT INTO vlab_gateways (id, name, kind, address, port, notes, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                     (gid, name, kind, address, port, notes, int(enabled), now()))
    if secret_key is not None:
        db().execute('UPDATE vlab_gateways SET secret_key = ? WHERE id = ?', (secret_key, gid))
    return get_gateway(gid)


# The Guacamole bundled with the docker compose install (deploy/docker-compose.yml in
# makus-vlab-console): served by vlab-proxy at /guacamole/ on the console's own address, its
# key made on first start in a file both containers mount. VLAB_GUAC_BUILTIN=0 turns it off.
BUILTIN_GUAC_ID = 'gw_builtin_guac'


def sync_builtin_guacamole():
    """Create or refresh the bundled Guacamole gateway from the environment, at start.
    The key file wins over whatever is stored (the file is what Guacamole itself reads)."""
    on = os.environ.get('VLAB_GUAC_BUILTIN', '').strip() not in ('', '0', 'false', 'no')
    row = get_gateway(BUILTIN_GUAC_ID)
    key = ''
    path = os.environ.get('VLAB_GUAC_KEY_FILE', '/etc/vlab/guac/json-secret-key')
    if on:
        try:
            with open(path, encoding='ascii') as f:
                key = f.read().strip().lower()
        except OSError:
            key = ''
        if not re.match(r'^[0-9a-f]{32}$', key):
            on = False
    if not on:
        if row and row['enabled']:
            db().execute('UPDATE vlab_gateways SET enabled = 0 WHERE id = ?', (BUILTIN_GUAC_ID,))
        return get_gateway(BUILTIN_GUAC_ID)
    if not row:
        port = os.environ.get('VLAB_HTTPS_PORT', '443')
        db().execute('INSERT INTO vlab_gateways (id, name, kind, address, port, notes, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)',
                     (BUILTIN_GUAC_ID, 'MOAVI Desk 내장 Guacamole', 'guacamole', os.environ.get('VLAB_HOSTNAME') or 'vlab.local',
                      int(port) if port.isdigit() else 443, '설치 묶음에 함께 들어 있는 브라우저 RDP (/guacamole/, 콘솔과 같은 주소)', now()))
    elif not row['enabled']:
        db().execute('UPDATE vlab_gateways SET enabled = 1 WHERE id = ?', (BUILTIN_GUAC_ID,))
    db().execute('UPDATE vlab_gateways SET secret_key = ? WHERE id = ?', (key, BUILTIN_GUAC_ID))
    return get_gateway(BUILTIN_GUAC_ID)


def mark_gateway(gid, ok, detail):
    db().execute('UPDATE vlab_gateways SET last_check = ?, last_ok = ?, last_detail = ? WHERE id = ?', (now(), int(ok), detail[:300], gid))
    return get_gateway(gid)


def delete_gateway(gid):
    db().execute('UPDATE vlab_external_desktops SET gateway_id = NULL WHERE gateway_id = ?', (gid,))
    db().execute('DELETE FROM vlab_gateways WHERE id = ?', (gid,))


# --- external desktops (physical PCs reached over RDP) -----------------------------------

def list_external(username=None):
    if username:
        return _rows('SELECT * FROM vlab_external_desktops WHERE assigned_user = ? ORDER BY name', (username,))
    return _rows('SELECT * FROM vlab_external_desktops ORDER BY name')


def get_external(eid):
    return _one('SELECT * FROM vlab_external_desktops WHERE id = ?', (eid,))


def save_external(eid, name, address, port, assigned_user, gateway_id, notes):
    if eid:
        db().execute('UPDATE vlab_external_desktops SET name = ?, address = ?, port = ?, assigned_user = ?, gateway_id = ?, notes = ? WHERE id = ?',
                     (name, address, port, assigned_user, gateway_id, notes, eid))
    else:
        eid = new_id('ext')
        db().execute('INSERT INTO vlab_external_desktops (id, name, address, port, assigned_user, gateway_id, notes, created_at) '
                     'VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (eid, name, address, port, assigned_user, gateway_id, notes, now()))
    return get_external(eid)


def delete_external(eid):
    db().execute('DELETE FROM vlab_external_desktops WHERE id = ?', (eid,))


# --- golden images -----------------------------------------------------------------------

def list_golden():
    return _rows('SELECT * FROM vlab_golden_images ORDER BY name')


def get_golden(gid):
    return _one('SELECT * FROM vlab_golden_images WHERE id = ?', (gid,))


def golden_for_vm(cluster_id, vmid):
    return _one('SELECT * FROM vlab_golden_images WHERE cluster_id = ? AND vmid = ?', (cluster_id, int(vmid)))


def add_golden(cluster_id, node, vmid, vm_type, name, notes, created_by):
    gid = new_id('gold')
    db().execute('INSERT INTO vlab_golden_images (id, cluster_id, node, vmid, vm_type, name, notes, created_by, created_at) '
                 'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', (gid, cluster_id, node, int(vmid), vm_type, name, notes, created_by, now()))
    return get_golden(gid)


def set_golden(gid, **fields):
    keys = [k for k in fields if k in ('name', 'notes', 'current_version', 'node')]
    if keys:
        db().execute(f"UPDATE vlab_golden_images SET {', '.join(k + ' = ?' for k in keys)} WHERE id = ?",
                     tuple(fields[k] for k in keys) + (gid,))
    return get_golden(gid)


def delete_golden(gid):
    db().execute('DELETE FROM vlab_golden_images WHERE id = ?', (gid,))


# --- board lab ---------------------------------------------------------------------------

def list_boards():
    return _rows('SELECT * FROM vlab_boards ORDER BY name')


def get_board(bid):
    return _one('SELECT * FROM vlab_boards WHERE id = ?', (bid,))


def save_board(bid, name, cluster_id, node, usb, kind, notes):
    if bid:
        db().execute('UPDATE vlab_boards SET name = ?, cluster_id = ?, node = ?, usb = ?, kind = ?, notes = ? WHERE id = ?',
                     (name, cluster_id, node, usb, kind, notes, bid))
    else:
        bid = new_id('brd')
        db().execute('INSERT INTO vlab_boards (id, name, cluster_id, node, usb, kind, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                     (bid, name, cluster_id, node, usb, kind, notes, now()))
    return get_board(bid)


def set_board_attachment(bid, desktop_id, vmid, by, lease_user='', lease_until=None):
    if desktop_id:
        db().execute('UPDATE vlab_boards SET attached_desktop = ?, attached_vmid = ?, attached_by = ?, attached_at = ?, '
                     'lease_user = ?, lease_until = ? WHERE id = ?', (desktop_id, int(vmid), by, now(), lease_user, lease_until, bid))
    else:
        db().execute("UPDATE vlab_boards SET attached_desktop = NULL, attached_vmid = NULL, attached_by = '', attached_at = NULL, "
                     "lease_user = '', lease_until = NULL WHERE id = ?", (bid,))
    return get_board(bid)


def due_boards(at_iso):
    return _rows('SELECT * FROM vlab_boards WHERE attached_desktop IS NOT NULL AND lease_until IS NOT NULL AND lease_until <= ?', (at_iso,))


def delete_board(bid):
    db().execute('DELETE FROM vlab_boards WHERE id = ?', (bid,))


# --- licence servers ---------------------------------------------------------------------

def _license_row(r):
    if not r:
        return None
    s = dict(r)
    for k, empty in (('ports', []), ('last_detail', []), ('lm_ports', []), ('feature_thresholds', {}), ('seat_alerted', {})):
        try:
            s[k] = json.loads(s.get(k) or 'null') or empty
        except ValueError:
            s[k] = empty
    try:
        s['alert_channels'] = json.loads(s['alert_channels']) if s.get('alert_channels') else None
    except ValueError:
        s['alert_channels'] = None
    return s


def list_license_servers():
    return [_license_row(r) for r in db().query('SELECT * FROM vlab_license_servers ORDER BY name')]


def get_license_server(lid):
    return _license_row(db().query_one('SELECT * FROM vlab_license_servers WHERE id = ?', (lid,)))


def save_license_server(lid, name, host, ports, cluster_id, vmid, fixed_mac, notes, watch=True):
    args = (name, host, json.dumps(ports), cluster_id, vmid, fixed_mac, notes, int(watch))
    if lid:
        db().execute('UPDATE vlab_license_servers SET name = ?, host = ?, ports = ?, cluster_id = ?, vmid = ?, fixed_mac = ?, notes = ?, watch = ? '
                     'WHERE id = ?', args + (lid,))
    else:
        lid = new_id('lic')
        db().execute('INSERT INTO vlab_license_servers (id, name, host, ports, cluster_id, vmid, fixed_mac, notes, watch, created_at) '
                     'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (lid,) + args + (now(),))
    return get_license_server(lid)


def mark_license_alerted(lid, at):
    db().execute('UPDATE vlab_license_servers SET alerted_at = ? WHERE id = ?', (at, lid))


def mark_license_server(lid, ok, detail):
    db().execute('UPDATE vlab_license_servers SET last_check = ?, last_ok = ?, last_detail = ? WHERE id = ?',
                 (now(), int(ok), json.dumps(detail), lid))
    return get_license_server(lid)


def save_license_usage_settings(lid, mode, lm_ports, lmutil_path, debug_log, seat_threshold, feature_thresholds, alert_channels):
    db().execute('UPDATE vlab_license_servers SET usage_mode = ?, lm_ports = ?, lmutil_path = ?, debug_log = ?, seat_threshold = ?, '
                 'feature_thresholds = ?, alert_channels = ? WHERE id = ?',
                 (mode, json.dumps(lm_ports), lmutil_path, debug_log, int(seat_threshold), json.dumps(feature_thresholds, ensure_ascii=False),
                  None if alert_channels is None else json.dumps(alert_channels), lid))
    return get_license_server(lid)


def mark_license_usage(lid, ok, error=''):
    db().execute('UPDATE vlab_license_servers SET usage_at = ?, usage_ok = ?, usage_error = ? WHERE id = ?',
                 (now(), int(ok), (error or '')[:300], lid))


def mark_license_seat_alerted(lid, state):
    db().execute('UPDATE vlab_license_servers SET seat_alerted = ? WHERE id = ?', (json.dumps(state, ensure_ascii=False), lid))


def delete_license_server(lid):
    db().execute('DELETE FROM vlab_license_servers WHERE id = ?', (lid,))


# --- pool grants (user / department / directory group): store.py's vlab_pool_grants -------

GRANT_TYPES = ('user', 'department', 'group')


def pool_grants(pool_id=None):
    if pool_id:
        return _rows('SELECT * FROM vlab_pool_grants WHERE pool_id = ? ORDER BY subject_type, subject_id', (pool_id,))
    return _rows('SELECT * FROM vlab_pool_grants')


def set_pool_grants(pool_id, grants):
    db().execute('DELETE FROM vlab_pool_grants WHERE pool_id = ?', (pool_id,))
    for g in grants:
        db().execute('INSERT OR IGNORE INTO vlab_pool_grants (pool_id, subject_type, subject_id, include_children) '
                     'VALUES (?, ?, ?, ?)', (pool_id, g['subject_type'], g['subject_id'], int(g.get('include_children', True))))
    return pool_grants(pool_id)


def delete_pool_grants(pool_id):
    db().execute('DELETE FROM vlab_pool_grants WHERE pool_id = ?', (pool_id,))


# --- which golden image version a desktop was made from ----------------------------------

def set_desktop_version(desktop_id, golden_id, version):
    db().execute('INSERT OR REPLACE INTO vlab_desktop_versions (desktop_id, golden_id, version, at) VALUES (?, ?, ?, ?)',
                 (desktop_id, golden_id, version, now()))


def desktop_versions(golden_id):
    return {r['desktop_id']: r['version'] for r in _rows('SELECT * FROM vlab_desktop_versions WHERE golden_id = ?', (golden_id,))}


def forget_desktop_version(desktop_id):
    db().execute('DELETE FROM vlab_desktop_versions WHERE desktop_id = ?', (desktop_id,))


# --- build jobs --------------------------------------------------------------------------

JOB_STATES = ('queued', 'running', 'done', 'failed', 'cancelled')


JOB_EXTRA = ('gpus', 'gpu_kind', 'memory_gb', 'max_minutes', 'env', 'notify', 'department_id')


def add_build_job(pool_id, username, name, command, workdir, **extra):
    """extra: the GPU job fields (JOB_EXTRA); pool_id '' lets the queue pick a pool."""
    jid = new_id('job')
    db().execute('INSERT INTO vlab_build_jobs (id, pool_id, username, name, command, workdir, status, created_at) '
                 "VALUES (?, ?, ?, ?, ?, ?, 'queued', ?)", (jid, pool_id, username, name, command, workdir, now()))
    keys = [k for k in JOB_EXTRA if k in extra]
    if keys:
        db().execute(f"UPDATE vlab_build_jobs SET {', '.join(k + ' = ?' for k in keys)} WHERE id = ?",
                     tuple(extra[k] for k in keys) + (jid,))
    return get_build_job(jid)


def get_build_job(jid):
    return _one('SELECT * FROM vlab_build_jobs WHERE id = ?', (jid,))


def list_build_jobs(username=None, pool_id=None, limit=200):
    where, args = [], []
    if username:
        where.append('username = ?')
        args.append(username)
    if pool_id:
        where.append('pool_id = ?')
        args.append(pool_id)
    sql = 'SELECT * FROM vlab_build_jobs' + (' WHERE ' + ' AND '.join(where) if where else '') + ' ORDER BY created_at DESC LIMIT ?'
    return _rows(sql, tuple(args) + (int(limit),))


def jobs_in(status, pool_id=None):
    if pool_id:
        return _rows('SELECT * FROM vlab_build_jobs WHERE status = ? AND pool_id = ? ORDER BY created_at', (status, pool_id))
    return _rows('SELECT * FROM vlab_build_jobs WHERE status = ? ORDER BY created_at', (status,))


def update_build_job(jid, **fields):
    keys = [k for k in fields if k in ('status', 'desktop_id', 'pid', 'exit_code', 'output', 'error', 'started_at', 'finished_at',
                                       'workdir', 'pool_id', 'gpu_index', 'wait_reason', 'notified_at')]
    if keys:
        db().execute(f"UPDATE vlab_build_jobs SET {', '.join(k + ' = ?' for k in keys)} WHERE id = ?",
                     tuple(fields[k] for k in keys) + (jid,))
    return get_build_job(jid)

