# -*- coding: utf-8 -*-
"""
MOAVI Desk - enrolling a room's PCs (LAB terminals) through the MOAVI Desk Agent.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

An enrolment code is what lets a PC ask to become a terminal; without one the engine takes no
PC. A code is made by an admin (kind 'admin': LAB, how long, how many PCs, approved at once or
not) or by the portal's "실습실 PC로 설치" for the signed-in user (kind 'user': 24 hours, a few
PCs, the LAB they picked; approved at once only when their role is in the auto-approve list).
The code goes into the installer (msiexec ... ENROLL_CODE= / ENROLL_TOKEN=). The MOAVI Desk
Agent - a Windows service beside the client - enrols with it on the PC's first start and gets
an agent token for that PC alone. With the token it sends a heartbeat every few minutes (name,
MAC, IP, OS, versions, whether someone is signed in to Windows); once an admin approves the
PC, the next heartbeat carries the kiosk key, once.

Codes and agent tokens are kept as SHA-256 hashes. Both tables are configuration and travel to
the HA peers (ha.SYNC_TABLES); the heartbeat columns are left out of the sync's change count
(ha.VOLATILE_COLUMNS).
"""

import hashlib
import json
import secrets
import threading
from datetime import datetime, timedelta, timezone

from pegaprox.vlab.store import db as _store_db, new_id, now

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_enroll_codes (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL DEFAULT '',
        code_hash TEXT NOT NULL UNIQUE,
        hint TEXT NOT NULL DEFAULT '',
        lab_id TEXT,
        auto_approve INTEGER NOT NULL DEFAULT 0,
        max_uses INTEGER NOT NULL DEFAULT 0,
        uses INTEGER NOT NULL DEFAULT 0,
        expires_at TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_by TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        last_used_at TEXT
    )''',
    # one row per terminal that came in with a code: its agent token (hash), how its kiosk key
    # goes out (state waiting | delivered | manual | expired) and what its last heartbeats said
    '''CREATE TABLE IF NOT EXISTS vlab_terminal_enrollments (
        terminal_id TEXT PRIMARY KEY,
        code_id TEXT NOT NULL DEFAULT '',
        token_hash TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT 'waiting',
        created_at TEXT NOT NULL,
        last_poll_at TEXT,
        delivered_at TEXT
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_enroll_token ON vlab_terminal_enrollments(token_hash)',
)
# columns added after the tables first shipped
_COLUMNS = (
    ('vlab_enroll_codes', 'kind', "TEXT NOT NULL DEFAULT 'admin'"),
    ('vlab_terminal_enrollments', 'info', "TEXT NOT NULL DEFAULT '{}'"),
    ('vlab_terminal_enrollments', 'recent', "TEXT NOT NULL DEFAULT '[]'"),
)

# a PC that waits longer than this for approval has to enrol again
TOKEN_DAYS = 30
MAX_DAYS = 365
MAX_USES = 10000
# the agent's heartbeat; a terminal is online while its last one is younger than 3 of them
HEARTBEAT_SECONDS = 120
RECENT = 20
# what the agent may tell about its PC (anything else is dropped), and how long each may be
INFO_FIELDS = {'hostname': 80, 'mac': 17, 'macs': 200, 'ip': 64, 'os': 120, 'client_version': 32,
               'agent_version': 32, 'user_logged_in': None, 'user': 64}
# no 0/O, 1/I/L: the code is read off a screen and typed
_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_enroll', False):
        with _lock:
            if not getattr(d, '_vlab_enroll', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                for table, col, definition in _COLUMNS:
                    have = {r['name'] for r in d.query(f'PRAGMA table_info({table})')}
                    if col not in have:
                        d.execute(f'ALTER TABLE {table} ADD COLUMN {col} {definition}')
                d._vlab_enroll = True
    return d


def _hash(value):
    return hashlib.sha256(str(value).encode()).hexdigest() if value else ''


def norm_code(code):
    """The code as compared: upper case, no dashes or spaces ('mde-ab12-…' == 'MDEAB12…')."""
    return ''.join(c for c in str(code or '').upper() if c.isalnum())


def _utc(text):
    try:
        t = datetime.fromisoformat(str(text))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _now():
    return datetime.now(timezone.utc)


def clean_info(data):
    """What the agent said about its PC, kept to the known fields and lengths."""
    out = {}
    if not isinstance(data, dict):
        return out
    for k, n in INFO_FIELDS.items():
        v = data.get(k)
        if v is None:
            continue
        if n is None:
            out[k] = bool(v)
        elif isinstance(v, (str, int, float)):
            out[k] = str(v)[:n]
    return out


# --- codes -------------------------------------------------------------------------------

def _code_row(r):
    c = dict(r)
    c.pop('code_hash', None)
    c['auto_approve'] = bool(c['auto_approve'])
    c['enabled'] = bool(c['enabled'])
    c['status'] = code_status(c)
    return c


def code_status(c, at=None):
    """active | disabled | expired | used_up"""
    if not c['enabled']:
        return 'disabled'
    exp = _utc(c.get('expires_at')) if c.get('expires_at') else None
    if exp and exp <= (at or _now()):
        return 'expired'
    if c['max_uses'] and c['uses'] >= c['max_uses']:
        return 'used_up'
    return 'active'


def list_codes(kind=None):
    if kind:
        rows = db().query('SELECT * FROM vlab_enroll_codes WHERE kind = ? ORDER BY created_at DESC', (kind,))
    else:
        rows = db().query('SELECT * FROM vlab_enroll_codes ORDER BY created_at DESC')
    return [_code_row(r) for r in rows]


def get_code(code_id):
    r = db().query_one('SELECT * FROM vlab_enroll_codes WHERE id = ?', (code_id,))
    return _code_row(r) if r else None


def make_code(name, lab_id, auto_approve, max_uses, days, created_by, kind='admin', hours=None):
    """A new code; returns (row, the code in clear - shown this once)."""
    body = ''.join(secrets.choice(_ALPHABET) for _ in range(12))
    code = f'MDE-{body[:4]}-{body[4:8]}-{body[8:]}'
    cid = new_id('enc')
    span = timedelta(hours=hours) if hours else timedelta(days=days) if days else None
    expires = (_now() + span).isoformat(timespec='seconds') if span else None
    db().execute("""INSERT INTO vlab_enroll_codes (id, name, code_hash, hint, lab_id, auto_approve, max_uses, expires_at,
                    enabled, created_by, created_at, kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)""",
                 (cid, name, _hash(norm_code(code)), body[8:], lab_id, int(bool(auto_approve)), int(max_uses),
                  expires, created_by, now(), kind))
    return get_code(cid), code


def active_user_codes(username):
    return [c for c in list_codes('user') if c['created_by'] == username and c['status'] == 'active']


def update_code(code_id, **fields):
    allowed = {k: v for k, v in fields.items() if k in ('name', 'enabled', 'lab_id', 'auto_approve')}
    if allowed:
        db().execute(f"UPDATE vlab_enroll_codes SET {', '.join(f'{k} = ?' for k in allowed)} WHERE id = ?",
                     (*allowed.values(), code_id))
    return get_code(code_id)


def delete_code(code_id):
    db().execute('DELETE FROM vlab_enroll_codes WHERE id = ?', (code_id,))


def forget_lab(lab_id):
    """A LAB went away: its codes put new PCs in no LAB."""
    db().execute('UPDATE vlab_enroll_codes SET lab_id = NULL WHERE lab_id = ?', (lab_id,))


def code_for(code):
    """The usable code row for what a PC sent, else (None, reason)."""
    n = norm_code(code)
    if len(n) < 8:
        return None, 'BAD_CODE'
    r = db().query_one('SELECT * FROM vlab_enroll_codes WHERE code_hash = ?', (_hash(n),))
    if not r:
        return None, 'BAD_CODE'
    c = _code_row(r)
    if c['status'] != 'active':
        return None, 'CODE_' + c['status'].upper()
    return c, None


def count_use(code_id):
    db().execute('UPDATE vlab_enroll_codes SET uses = uses + 1, last_used_at = ? WHERE id = ?', (now(), code_id))


# --- terminals that came in through the agent ----------------------------------------------

def start(terminal_id, code_id, info=None):
    """A new agent token for this terminal (an older one stops working); returns it in clear.
    The kiosk key waits for the terminal's approval."""
    token = 'mda_' + secrets.token_urlsafe(32)
    d = db()
    d.execute('DELETE FROM vlab_terminal_enrollments WHERE terminal_id = ?', (terminal_id,))
    d.execute("""INSERT INTO vlab_terminal_enrollments (terminal_id, code_id, token_hash, state, created_at, last_poll_at, info)
                 VALUES (?, ?, ?, 'waiting', ?, ?, ?)""",
              (terminal_id, code_id, _hash(token), now(), now(), json.dumps(clean_info(info), ensure_ascii=False)))
    return token


def by_token(token):
    """The enrolment an agent token belongs to; (row, None) or (None, reason). A PC still not
    approved after TOKEN_DAYS has to enrol again."""
    token = str(token or '').strip()
    if not token.startswith('mda_'):
        return None, 'BAD_TOKEN'
    r = db().query_one('SELECT * FROM vlab_terminal_enrollments WHERE token_hash = ?', (_hash(token),))
    if not r:
        return None, 'BAD_TOKEN'
    return dict(r), None


def waited_too_long(e):
    made = _utc(e['created_at'])
    return e['state'] == 'waiting' and made is not None and made + timedelta(days=TOKEN_DAYS) <= _now()


def heartbeat(terminal_id, info, ip):
    """Keep what the agent said and the last RECENT heartbeats (time, address, signed-in user)."""
    row = db().query_one('SELECT info, recent FROM vlab_terminal_enrollments WHERE terminal_id = ?', (terminal_id,))
    if not row:
        return
    clean = clean_info(info)
    try:
        recent = json.loads(row['recent'] or '[]')
    except ValueError:
        recent = []
    recent = ([{'at': now(), 'ip': ip, 'user': bool(clean.get('user_logged_in'))}] + recent)[:RECENT]
    db().execute('UPDATE vlab_terminal_enrollments SET last_poll_at = ?, info = ?, recent = ? WHERE terminal_id = ?',
                 (now(), json.dumps(clean or json.loads(row['info'] or '{}'), ensure_ascii=False),
                  json.dumps(recent), terminal_id))


def set_key_state(terminal_id, state):
    """delivered (the agent has the key), manual (an admin typed one in), waiting (send a new
    one with the next heartbeat)."""
    db().execute("""UPDATE vlab_terminal_enrollments SET state = ?,
                    delivered_at = CASE WHEN ? = 'delivered' THEN ? ELSE delivered_at END
                    WHERE terminal_id = ?""", (state, state, now(), terminal_id))


def end_token(terminal_id, state='expired'):
    """The token stops: the PC waited too long, or it was rejected."""
    db().execute("UPDATE vlab_terminal_enrollments SET token_hash = '', state = ? WHERE terminal_id = ?",
                 (state, terminal_id))


def forget(terminal_id):
    db().execute('DELETE FROM vlab_terminal_enrollments WHERE terminal_id = ?', (terminal_id,))


def online(e, at=None):
    seen = _utc(e.get('last_poll_at')) if e.get('last_poll_at') else None
    return bool(seen and e.get('token_hash') and seen + timedelta(seconds=3 * HEARTBEAT_SECONDS) > (at or _now()))


def annotate(terminals):
    """Each terminal with its agent: enrollment = {state (of the kiosk key), code, code_kind,
    requested_by, created_at, last_heartbeat_at, delivered_at, online, info, recent} for the ones
    that came in with a code, else None."""
    rows = {r['terminal_id']: dict(r) for r in db().query('SELECT * FROM vlab_terminal_enrollments')}
    codes = {r['id']: dict(r) for r in db().query('SELECT id, name, kind, created_by FROM vlab_enroll_codes')}
    at = _now()
    for t in terminals:
        e = rows.get(t['id'])
        if not e:
            t['enrollment'] = None
            continue
        c = codes.get(e['code_id']) or {}
        try:
            info, recent = json.loads(e.get('info') or '{}'), json.loads(e.get('recent') or '[]')
        except ValueError:
            info, recent = {}, []
        t['enrollment'] = {
            'state': e['state'], 'code_id': e['code_id'], 'code': c.get('name', ''), 'code_kind': c.get('kind', ''),
            'requested_by': c.get('created_by', ''), 'created_at': e['created_at'], 'last_heartbeat_at': e['last_poll_at'],
            'last_poll_at': e['last_poll_at'], 'delivered_at': e['delivered_at'], 'online': online(e, at),
            'heartbeat_seconds': HEARTBEAT_SECONDS, 'info': info, 'recent': recent}
    return terminals


def pending_count():
    return db().query_one("SELECT COUNT(*) AS n FROM vlab_terminals WHERE state = 'pending'")['n']
