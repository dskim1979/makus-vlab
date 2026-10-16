# -*- coding: utf-8 -*-
"""
MOAVI Desk - the next-phase catalogues: departments, sign-up requests, the USB device
library, gateways, external desktops, golden images, board lab boards and licence servers.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

Tables live in the core DB beside the other vlab_* tables and are made on first use, like
store.py's. Each list here is small (tens to hundreds of rows), so reads load whole tables.
"""

import json
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
          'vlab_external_desktops', 'vlab_golden_images', 'vlab_boards', 'vlab_license_servers')

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


def save_department(dep_id, name, parent_id=None, sort=0):
    if dep_id:
        db().execute('UPDATE vlab_departments SET name = ?, parent_id = ?, sort = ? WHERE id = ?', (name, parent_id, sort, dep_id))
    else:
        dep_id = new_id('dep')
        db().execute('INSERT INTO vlab_departments (id, name, parent_id, sort, created_at) VALUES (?, ?, ?, ?, ?)',
                     (dep_id, name, parent_id, sort, now()))
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


def list_gateways():
    return _rows('SELECT * FROM vlab_gateways ORDER BY name')


def get_gateway(gid):
    return _one('SELECT * FROM vlab_gateways WHERE id = ?', (gid,))


def save_gateway(gid, name, kind, address, port, notes, enabled):
    if gid:
        db().execute('UPDATE vlab_gateways SET name = ?, kind = ?, address = ?, port = ?, notes = ?, enabled = ? WHERE id = ?',
                     (name, kind, address, port, notes, int(enabled), gid))
    else:
        gid = new_id('gw')
        db().execute('INSERT INTO vlab_gateways (id, name, kind, address, port, notes, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                     (gid, name, kind, address, port, notes, int(enabled), now()))
    return get_gateway(gid)


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


def set_board_attachment(bid, desktop_id, vmid, by):
    if desktop_id:
        db().execute('UPDATE vlab_boards SET attached_desktop = ?, attached_vmid = ?, attached_by = ?, attached_at = ? WHERE id = ?',
                     (desktop_id, int(vmid), by, now(), bid))
    else:
        db().execute("UPDATE vlab_boards SET attached_desktop = NULL, attached_vmid = NULL, attached_by = '', attached_at = NULL WHERE id = ?", (bid,))
    return get_board(bid)


def delete_board(bid):
    db().execute('DELETE FROM vlab_boards WHERE id = ?', (bid,))


# --- licence servers ---------------------------------------------------------------------

def _license_row(r):
    if not r:
        return None
    s = dict(r)
    for k, empty in (('ports', []), ('last_detail', [])):
        try:
            s[k] = json.loads(s.get(k) or 'null') or empty
        except ValueError:
            s[k] = empty
    return s


def list_license_servers():
    return [_license_row(r) for r in db().query('SELECT * FROM vlab_license_servers ORDER BY name')]


def get_license_server(lid):
    return _license_row(db().query_one('SELECT * FROM vlab_license_servers WHERE id = ?', (lid,)))


def save_license_server(lid, name, host, ports, cluster_id, vmid, fixed_mac, notes):
    args = (name, host, json.dumps(ports), cluster_id, vmid, fixed_mac, notes)
    if lid:
        db().execute('UPDATE vlab_license_servers SET name = ?, host = ?, ports = ?, cluster_id = ?, vmid = ?, fixed_mac = ?, notes = ? WHERE id = ?',
                     args + (lid,))
    else:
        lid = new_id('lic')
        db().execute('INSERT INTO vlab_license_servers (id, name, host, ports, cluster_id, vmid, fixed_mac, notes, created_at) '
                     'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', (lid,) + args + (now(),))
    return get_license_server(lid)


def mark_license_server(lid, ok, detail):
    db().execute('UPDATE vlab_license_servers SET last_check = ?, last_ok = ?, last_detail = ? WHERE id = ?',
                 (now(), int(ok), json.dumps(detail), lid))
    return get_license_server(lid)


def delete_license_server(lid):
    db().execute('DELETE FROM vlab_license_servers WHERE id = ?', (lid,))
