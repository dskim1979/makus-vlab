# -*- coding: utf-8 -*-
"""
vLAB tables in the core DB (config/pegaprox.db) - docs/vlab-design.md 5.

The tables are created on first use of each DB handle rather than in PegaProxDB._init_db,
so the core schema code stays as upstream ships it. Phase 0 has pools, desktops, pool
grants, loans and sessions; the other tables of the design arrive with their features.
"""

import json
import threading
import logging
import uuid
from datetime import datetime, timezone

from pegaprox.core.db import get_db

POOL_TYPES = ('dedicated', 'reset', 'shared', 'classroom', 'buildfarm')
DESKTOP_STATES = ('provisioning', 'ready', 'in_use', 'resetting', 'error')

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_pools (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        tenant_id TEXT NOT NULL DEFAULT '',
        cluster_id TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        settings TEXT NOT NULL DEFAULT '{}',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL DEFAULT ''
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_desktops (
        id TEXT PRIMARY KEY,
        pool_id TEXT NOT NULL REFERENCES vlab_pools(id),
        cluster_id TEXT NOT NULL,
        node TEXT NOT NULL,
        vmid INTEGER NOT NULL,
        vm_type TEXT NOT NULL DEFAULT 'qemu',
        name TEXT NOT NULL,
        assigned_user TEXT,
        state TEXT NOT NULL DEFAULT 'ready',
        base_snap TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        UNIQUE (cluster_id, vmid)
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_desktops_user ON vlab_desktops(assigned_user)',
    '''CREATE TABLE IF NOT EXISTS vlab_pool_grants (
        pool_id TEXT NOT NULL REFERENCES vlab_pools(id),
        subject_type TEXT NOT NULL,
        subject_id TEXT NOT NULL,
        include_children INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (pool_id, subject_type, subject_id)
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_leases (
        id TEXT PRIMARY KEY,
        resource_type TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        resource_name TEXT NOT NULL DEFAULT '',
        username TEXT NOT NULL,
        cluster_id TEXT NOT NULL DEFAULT '',
        vmid INTEGER,
        starts_at TEXT NOT NULL,
        ends_at TEXT,
        returned_at TEXT,
        state TEXT NOT NULL DEFAULT 'active'
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_leases_user ON vlab_leases(username, state)',
    '''CREATE TABLE IF NOT EXISTS vlab_sessions (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        desktop_id TEXT,
        pool_id TEXT,
        protocol TEXT NOT NULL DEFAULT '',
        client_ip TEXT NOT NULL DEFAULT '',
        started_at TEXT NOT NULL,
        ended_at TEXT,
        result TEXT NOT NULL DEFAULT '',
        fail_reason TEXT NOT NULL DEFAULT ''
    )''',
    # LABs: rooms, their terminals, and the weekly schedules of their pools (pegaprox/vlab/labs.py)
    '''CREATE TABLE IF NOT EXISTS vlab_labs (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        location TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        seats INTEGER NOT NULL DEFAULT 0,
        tenant_id TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_terminals (
        id TEXT PRIMARY KEY,
        lab_id TEXT,
        name TEXT NOT NULL DEFAULT '',
        mac TEXT NOT NULL UNIQUE,
        ip TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT 'pending',
        registered_by TEXT NOT NULL DEFAULT '',
        last_seen TEXT,
        created_at TEXT NOT NULL,
        key_hash TEXT NOT NULL DEFAULT ''
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_lab_schedules (
        id TEXT PRIMARY KEY,
        lab_id TEXT NOT NULL,
        pool_id TEXT NOT NULL,
        title TEXT NOT NULL DEFAULT '',
        weekdays TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        prepare_min INTEGER NOT NULL DEFAULT 10,
        after TEXT NOT NULL DEFAULT 'reset',
        enabled INTEGER NOT NULL DEFAULT 1,
        last_prepared TEXT NOT NULL DEFAULT '',
        last_finished TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    )''',
)

_lock = threading.Lock()


def db():
    """The core DB handle, with the vLAB tables created on first use."""
    d = get_db()
    # marked on the handle itself: a new DB (another config dir, a test's throwaway DB)
    # is a new handle and gets its tables too
    if not getattr(d, '_vlab_schema', False):
        with _lock:
            if not getattr(d, '_vlab_schema', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                # columns added after a table first shipped
                cols = {r['name'] for r in d.query('PRAGMA table_info(vlab_terminals)')}
                if 'key_hash' not in cols:
                    d.execute("ALTER TABLE vlab_terminals ADD COLUMN key_hash TEXT NOT NULL DEFAULT ''")
                d._vlab_schema = True
    return d


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def new_id(prefix):
    return f'{prefix}_{uuid.uuid4().hex[:12]}'


# --- pools -------------------------------------------------------------------

def _pool_row(r):
    p = dict(r)
    p['enabled'] = bool(p['enabled'])
    try:
        p['settings'] = json.loads(p.get('settings') or '{}')
    except ValueError:
        p['settings'] = {}
    return p


def list_pools():
    d = db()
    rows = d.query('''SELECT p.*,
                             (SELECT COUNT(*) FROM vlab_desktops x WHERE x.pool_id = p.id) AS desktops,
                             (SELECT COUNT(*) FROM vlab_desktops x WHERE x.pool_id = p.id
                                 AND x.assigned_user IS NOT NULL) AS assigned
                      FROM vlab_pools p ORDER BY p.name''')
    return [_pool_row(r) for r in rows]


def get_pool(pool_id):
    r = db().query_one('SELECT * FROM vlab_pools WHERE id = ?', (pool_id,))
    return _pool_row(r) if r else None


def create_pool(name, pool_type, cluster_id, tenant_id='', description='', settings=None, created_by=''):
    pool = {
        'id': new_id('pool'), 'name': name, 'type': pool_type, 'tenant_id': tenant_id or '',
        'cluster_id': cluster_id, 'description': description or '',
        'settings': json.dumps(settings or {}), 'enabled': 1, 'created_at': now(), 'created_by': created_by,
    }
    db().execute('''INSERT INTO vlab_pools (id, name, type, tenant_id, cluster_id, description, settings,
                                            enabled, created_at, created_by)
                    VALUES (:id, :name, :type, :tenant_id, :cluster_id, :description, :settings,
                            :enabled, :created_at, :created_by)''', pool)
    return get_pool(pool['id'])


def set_pool_settings(pool_id, settings):
    db().execute('UPDATE vlab_pools SET settings = ? WHERE id = ?', (json.dumps(settings or {}), pool_id))


def update_pool(pool_id, **fields):
    """Change a pool's name, description or enabled flag (the cluster and type stay)."""
    cols = {k: v for k, v in fields.items() if k in ('name', 'description', 'enabled')}
    if 'enabled' in cols:
        cols['enabled'] = 1 if cols['enabled'] else 0
    if cols:
        db().execute('UPDATE vlab_pools SET ' + ', '.join(f'{k} = ?' for k in cols) + ' WHERE id = ?',
                     tuple(cols.values()) + (pool_id,))
    return get_pool(pool_id)


def delete_pool(pool_id):
    db().execute('DELETE FROM vlab_lab_schedules WHERE pool_id = ?', (pool_id,))
    d = db()
    d.execute('DELETE FROM vlab_pool_grants WHERE pool_id = ?', (pool_id,))
    d.execute('DELETE FROM vlab_pools WHERE id = ?', (pool_id,))


# --- desktops ----------------------------------------------------------------

def get_desktop(desktop_id):
    r = db().query_one('SELECT * FROM vlab_desktops WHERE id = ?', (desktop_id,))
    return dict(r) if r else None


def list_desktops(pool_id=None):
    if pool_id:
        rows = db().query('SELECT * FROM vlab_desktops WHERE pool_id = ? ORDER BY name', (pool_id,))
    else:
        rows = db().query('SELECT * FROM vlab_desktops ORDER BY name')
    return [dict(r) for r in rows]


def add_desktop(pool, node, vmid, name, vm_type='qemu', state='ready'):
    desk = {
        'id': new_id('desk'), 'pool_id': pool['id'], 'cluster_id': pool['cluster_id'], 'node': node,
        'vmid': int(vmid), 'vm_type': vm_type, 'name': name, 'state': state, 'created_at': now(),
    }
    db().execute('''INSERT INTO vlab_desktops (id, pool_id, cluster_id, node, vmid, vm_type, name, state, created_at)
                    VALUES (:id, :pool_id, :cluster_id, :node, :vmid, :vm_type, :name, :state, :created_at)''', desk)
    return get_desktop(desk['id'])


def desktop_for_vm(cluster_id, vmid):
    r = db().query_one('SELECT * FROM vlab_desktops WHERE cluster_id = ? AND vmid = ?', (cluster_id, int(vmid)))
    return dict(r) if r else None


def set_state(desktop_id, state):
    db().execute('UPDATE vlab_desktops SET state = ? WHERE id = ?', (state, desktop_id))


def set_node(desktop_id, node):
    """where the desktop's VM lives after a migration"""
    db().execute('UPDATE vlab_desktops SET node = ? WHERE id = ?', (node, desktop_id))


def set_base_snap(desktop_id, snap):
    db().execute('UPDATE vlab_desktops SET base_snap = ? WHERE id = ?', (snap or '', desktop_id))


def open_session_desktops():
    """ids of desktops someone has an open (not ended) session on"""
    rows = db().query('SELECT DISTINCT desktop_id FROM vlab_sessions WHERE ended_at IS NULL AND desktop_id IS NOT NULL')
    return {r['desktop_id'] for r in rows}


def set_assignment(desktop_id, username):
    prev = db().query_one('SELECT assigned_user FROM vlab_desktops WHERE id = ?', (desktop_id,))
    db().execute('UPDATE vlab_desktops SET assigned_user = ? WHERE id = ?', (username, desktop_id))
    if prev and prev['assigned_user'] and prev['assigned_user'] != username:
        _forget_warpgate(desktop_id)   # the old user keeps no way in through Warpgate


def remove_desktop(desktop_id):
    db().execute('DELETE FROM vlab_desktops WHERE id = ?', (desktop_id,))
    _forget_warpgate(desktop_id)


def _forget_warpgate(desktop_id):
    """Remove the desktop's Warpgate targets (best effort, in the background; pegaprox/vlab/warpgate.py)."""
    try:
        from pegaprox.vlab.warpgate import forget_desktop
        forget_desktop(desktop_id)
    except Exception as e:
        logging.warning(f'[VLAB] Warpgate cleanup for {desktop_id} skipped: {str(e)[:200]}')


def desktops_of_user(username):
    rows = db().query('''SELECT d.*, p.name AS pool_name, p.type AS pool_type, p.settings AS pool_settings
                         FROM vlab_desktops d JOIN vlab_pools p ON p.id = d.pool_id
                         WHERE d.assigned_user = ? AND p.enabled = 1
                         ORDER BY d.name''', (username,))
    return [dict(r) for r in rows]


# --- loans -------------------------------------------------------------------

def active_leases_of_user(username):
    rows = db().query('''SELECT * FROM vlab_leases WHERE username = ? AND state = 'active'
                         ORDER BY ends_at IS NULL, ends_at''', (username,))
    return [dict(r) for r in rows]


def add_lease(resource_type, resource_id, resource_name, username, cluster_id, vmid, ends_at):
    lid = new_id('lease')
    db().execute('''INSERT INTO vlab_leases (id, resource_type, resource_id, resource_name, username, cluster_id,
                    vmid, starts_at, ends_at, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')''',
                 (lid, resource_type, resource_id, resource_name, username, cluster_id, int(vmid), now(), ends_at))
    return get_lease(lid)


def get_lease(lease_id):
    r = db().query_one('SELECT * FROM vlab_leases WHERE id = ?', (lease_id,))
    return dict(r) if r else None


def list_leases(active_only=True, limit=500):
    sql = 'SELECT * FROM vlab_leases' + (" WHERE state = 'active'" if active_only else '')
    rows = db().query(sql + ' ORDER BY starts_at DESC, rowid DESC LIMIT ?', (int(limit),))
    return [dict(r) for r in rows]


def active_leases_on(cluster_id, resource_id):
    rows = db().query("SELECT * FROM vlab_leases WHERE cluster_id = ? AND resource_id = ? AND state = 'active'",
                      (cluster_id, resource_id))
    return [dict(r) for r in rows]


def active_lease_of_vm(cluster_id, vmid):
    r = db().query_one("SELECT * FROM vlab_leases WHERE cluster_id = ? AND vmid = ? AND state = 'active'",
                       (cluster_id, int(vmid)))
    return dict(r) if r else None


def due_leases(at_iso):
    """active loans whose end has passed"""
    rows = db().query("SELECT * FROM vlab_leases WHERE state = 'active' AND ends_at IS NOT NULL AND ends_at <= ?",
                      (at_iso,))
    return [dict(r) for r in rows]


def close_lease(lease_id, state='returned'):
    db().execute('UPDATE vlab_leases SET state = ?, returned_at = ? WHERE id = ?', (state, now(), lease_id))


def extend_lease(lease_id, ends_at):
    db().execute('UPDATE vlab_leases SET ends_at = ? WHERE id = ?', (ends_at, lease_id))


# --- sessions ----------------------------------------------------------------

def start_session(username, desktop, protocol, client_ip):
    sid = new_id('sess')
    db().execute('''INSERT INTO vlab_sessions (id, username, desktop_id, pool_id, protocol, client_ip, started_at, result)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'started')''',
                 (sid, username, desktop['id'], desktop['pool_id'], protocol, client_ip or '', now()))
    return sid


def last_session_per_user():
    """{username: started_at of their latest session}"""
    rows = db().query('SELECT username, MAX(started_at) AS at FROM vlab_sessions GROUP BY username')
    return {r['username']: r['at'] for r in rows}


def last_connected(username):
    """{desktop_id: started_at of the user's latest session on it}"""
    rows = db().query('''SELECT desktop_id, MAX(started_at) AS at FROM vlab_sessions
                         WHERE username = ? AND desktop_id IS NOT NULL GROUP BY desktop_id''', (username,))
    return {r['desktop_id']: r['at'] for r in rows}


def list_sessions(username=None, pool_id=None, limit=200):
    where, args = [], []
    if username:
        where.append('username = ?'); args.append(username)
    if pool_id:
        where.append('pool_id = ?'); args.append(pool_id)
    sql = 'SELECT * FROM vlab_sessions' + (' WHERE ' + ' AND '.join(where) if where else '')
    # rowid breaks ties: started_at has one-second resolution
    rows = db().query(sql + ' ORDER BY started_at DESC, rowid DESC LIMIT ?', tuple(args) + (int(limit),))
    return [dict(r) for r in rows]


def sessions_since(iso):
    """number of sessions started at or after `iso` (UTC ISO text, same format as started_at)"""
    r = db().query_one('SELECT COUNT(*) AS n FROM vlab_sessions WHERE started_at >= ?', (iso,))
    return int(r['n']) if r else 0


def sessions_overlapping(since_iso, until_iso):
    """sessions open at some point in [since, until): started before `until` and not
    ended before `since` (still-open ones included)"""
    rows = db().query('SELECT * FROM vlab_sessions WHERE started_at < ? AND (ended_at IS NULL OR ended_at >= ?)'
                      ' ORDER BY started_at', (until_iso, since_iso))
    return [dict(r) for r in rows]


def get_session(session_id):
    r = db().query_one('SELECT * FROM vlab_sessions WHERE id = ?', (session_id,))
    return dict(r) if r else None


def open_sessions():
    rows = db().query('SELECT * FROM vlab_sessions WHERE ended_at IS NULL ORDER BY started_at')
    return [dict(r) for r in rows]


def close_session(session_id, result='expired', at=None):
    db().execute('UPDATE vlab_sessions SET ended_at = ?, result = ? WHERE id = ? AND ended_at IS NULL',
                 (at or now(), result, session_id))


def last_end_per_desktop():
    # {desktop_id: ended_at of its latest closed session}
    rows = db().query('''SELECT desktop_id, MAX(ended_at) AS at FROM vlab_sessions
                         WHERE ended_at IS NOT NULL AND desktop_id IS NOT NULL GROUP BY desktop_id''')
    return {r['desktop_id']: r['at'] for r in rows}


def end_session(session_id, username):
    """Close one of the user's own open sessions. False when there is none to close."""
    d = db()
    r = d.query_one('SELECT id FROM vlab_sessions WHERE id = ? AND username = ? AND ended_at IS NULL',
                    (session_id, username))
    if not r:
        return False
    d.execute("UPDATE vlab_sessions SET ended_at = ?, result = 'ended' WHERE id = ?", (now(), session_id))
    return True


# --- LABs, terminals, schedules -----------------------------------------------------

def list_labs():
    rows = db().query("""SELECT l.*,
                                (SELECT COUNT(*) FROM vlab_terminals t WHERE t.lab_id = l.id AND t.state = 'approved') AS terminals,
                                (SELECT COUNT(*) FROM vlab_terminals t WHERE t.lab_id = l.id AND t.state = 'pending') AS pending
                         FROM vlab_labs l ORDER BY l.name""")
    return [dict(r) for r in rows]


def get_lab(lab_id):
    r = db().query_one('SELECT * FROM vlab_labs WHERE id = ?', (lab_id,))
    return dict(r) if r else None


def save_lab(lab_id, name, location='', description='', seats=0, tenant_id=''):
    d = db()
    if lab_id:
        d.execute('UPDATE vlab_labs SET name = ?, location = ?, description = ?, seats = ? WHERE id = ?',
                  (name, location, description, int(seats), lab_id))
        return get_lab(lab_id)
    lid = new_id('lab')
    d.execute('INSERT INTO vlab_labs (id, name, location, description, seats, tenant_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
              (lid, name, location, description, int(seats), tenant_id, now()))
    return get_lab(lid)


def delete_lab(lab_id):
    d = db()
    d.execute('DELETE FROM vlab_lab_schedules WHERE lab_id = ?', (lab_id,))
    d.execute('UPDATE vlab_terminals SET lab_id = NULL WHERE lab_id = ?', (lab_id,))
    d.execute('DELETE FROM vlab_labs WHERE id = ?', (lab_id,))


def _terminal_row(r):
    t = dict(r)
    t['has_key'] = bool(t.pop('key_hash', ''))
    return t


def list_terminals(lab_id=None):
    if lab_id:
        rows = db().query('SELECT * FROM vlab_terminals WHERE lab_id = ? ORDER BY name, mac', (lab_id,))
    else:
        rows = db().query('SELECT * FROM vlab_terminals ORDER BY state DESC, name, mac')
    return [_terminal_row(r) for r in rows]


def get_terminal(terminal_id):
    r = db().query_one('SELECT * FROM vlab_terminals WHERE id = ?', (terminal_id,))
    return _terminal_row(r) if r else None


def terminal_by_mac(mac):
    r = db().query_one('SELECT * FROM vlab_terminals WHERE mac = ?', (mac,))
    return _terminal_row(r) if r else None


def add_terminal(mac, name='', lab_id=None, ip='', state='pending', registered_by=''):
    tid = new_id('term')
    db().execute("""INSERT INTO vlab_terminals (id, lab_id, name, mac, ip, state, registered_by, last_seen, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", (tid, lab_id, name, mac, ip, state, registered_by, now(), now()))
    return get_terminal(tid)


def update_terminal(terminal_id, **fields):
    allowed = {k: v for k, v in fields.items() if k in ('lab_id', 'name', 'ip', 'state', 'last_seen')}
    if allowed:
        db().execute(f"UPDATE vlab_terminals SET {', '.join(f'{k} = ?' for k in allowed)} WHERE id = ?",
                     (*allowed.values(), terminal_id))
    return get_terminal(terminal_id)


def delete_terminal(terminal_id):
    db().execute('DELETE FROM vlab_terminals WHERE id = ?', (terminal_id,))


def list_lab_schedules(lab_id=None):
    if lab_id:
        rows = db().query('SELECT * FROM vlab_lab_schedules WHERE lab_id = ? ORDER BY start_time', (lab_id,))
    else:
        rows = db().query('SELECT * FROM vlab_lab_schedules ORDER BY lab_id, start_time')
    return [dict(r) for r in rows]


def get_lab_schedule(schedule_id):
    r = db().query_one('SELECT * FROM vlab_lab_schedules WHERE id = ?', (schedule_id,))
    return dict(r) if r else None


def save_lab_schedule(schedule_id, lab_id, pool_id, clean):
    d = db()
    if schedule_id:
        d.execute("""UPDATE vlab_lab_schedules SET lab_id = ?, pool_id = ?, title = ?, weekdays = ?, start_time = ?,
                     end_time = ?, prepare_min = ?, after = ?, enabled = ? WHERE id = ?""",
                  (lab_id, pool_id, clean['title'], clean['weekdays'], clean['start_time'], clean['end_time'],
                   clean['prepare_min'], clean['after'], clean['enabled'], schedule_id))
        return get_lab_schedule(schedule_id)
    sid = new_id('sch')
    d.execute("""INSERT INTO vlab_lab_schedules (id, lab_id, pool_id, title, weekdays, start_time, end_time, prepare_min,
                 after, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
              (sid, lab_id, pool_id, clean['title'], clean['weekdays'], clean['start_time'], clean['end_time'],
               clean['prepare_min'], clean['after'], clean['enabled'], now()))
    return get_lab_schedule(sid)


def mark_lab_schedule(schedule_id, phase, day):
    col = 'last_prepared' if phase == 'prepare' else 'last_finished'
    db().execute(f'UPDATE vlab_lab_schedules SET {col} = ? WHERE id = ?', (day, schedule_id))


def delete_lab_schedule(schedule_id):
    db().execute('DELETE FROM vlab_lab_schedules WHERE id = ?', (schedule_id,))


def schedules_of_pool(pool_id):
    return [dict(r) for r in db().query('SELECT * FROM vlab_lab_schedules WHERE pool_id = ?', (pool_id,))]


def set_terminal_key(terminal_id, key_hash):
    db().execute("UPDATE vlab_terminals SET key_hash = ?, state = 'approved' WHERE id = ?", (key_hash, terminal_id))


def terminal_by_key(key_hash):
    if not key_hash:
        return None
    r = db().query_one('SELECT * FROM vlab_terminals WHERE key_hash = ?', (key_hash,))
    return dict(r) if r else None
