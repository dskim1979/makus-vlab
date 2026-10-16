# -*- coding: utf-8 -*-
"""
MOAVI Desk - enrolling a room's PCs (LAB terminals) without signing in on each of them.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

An admin makes an enrolment code (a LAB to put the PCs in, how long it lasts, how many PCs
may use it, whether they are approved at once). The code goes into the client's installer
(msiexec ... ENROLL_CODE=...). On its first start the client sends {mac, name, code}; the
engine makes the terminal (pending, or approved in the code's LAB) and answers with a poll
token for that PC alone. The client asks with the token until the terminal is approved, and
then gets its kiosk key - once: the key is made at that moment, only its hash is kept, and
the token stops working.

Codes and tokens are kept as SHA-256 hashes. Both tables are configuration and travel to the
HA peers (ha.SYNC_TABLES), so a failover keeps the codes and the PCs still waiting.
"""

import hashlib
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
    # one row per terminal that came in with a code: its poll token (hash) while it waits,
    # and whether its key went out (state waiting | delivered | manual)
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

# a PC that waits longer than this for approval has to enrol again
TOKEN_DAYS = 30
MAX_DAYS = 365
MAX_USES = 10000
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


def list_codes():
    return [_code_row(r) for r in db().query('SELECT * FROM vlab_enroll_codes ORDER BY created_at DESC')]


def get_code(code_id):
    r = db().query_one('SELECT * FROM vlab_enroll_codes WHERE id = ?', (code_id,))
    return _code_row(r) if r else None


def make_code(name, lab_id, auto_approve, max_uses, days, created_by):
    """A new code; returns (row, the code in clear - shown this once)."""
    body = ''.join(secrets.choice(_ALPHABET) for _ in range(12))
    code = f'MDE-{body[:4]}-{body[4:8]}-{body[8:]}'
    cid = new_id('enc')
    expires = (_now() + timedelta(days=days)).isoformat(timespec='seconds') if days else None
    db().execute("""INSERT INTO vlab_enroll_codes (id, name, code_hash, hint, lab_id, auto_approve, max_uses, expires_at,
                    enabled, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                 (cid, name, _hash(norm_code(code)), body[8:], lab_id, int(bool(auto_approve)), int(max_uses),
                  expires, created_by, now()))
    return get_code(cid), code


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


# --- enrolments of terminals ---------------------------------------------------------------

def start(terminal_id, code_id):
    """A new poll token for this terminal (an older one stops working); returns it in clear."""
    token = 'mdp_' + secrets.token_urlsafe(32)
    d = db()
    d.execute('DELETE FROM vlab_terminal_enrollments WHERE terminal_id = ?', (terminal_id,))
    d.execute("""INSERT INTO vlab_terminal_enrollments (terminal_id, code_id, token_hash, state, created_at)
                 VALUES (?, ?, ?, 'waiting', ?)""", (terminal_id, code_id, _hash(token), now()))
    return token


def by_token(token):
    """The waiting enrolment for a poll token; (row, None) or (None, reason)."""
    token = str(token or '').strip()
    if not token.startswith('mdp_'):
        return None, 'BAD_TOKEN'
    r = db().query_one("SELECT * FROM vlab_terminal_enrollments WHERE token_hash = ? AND state = 'waiting'",
                       (_hash(token),))
    if not r:
        return None, 'BAD_TOKEN'
    e = dict(r)
    made = _utc(e['created_at'])
    if made and made + timedelta(days=TOKEN_DAYS) <= _now():
        close(e['terminal_id'], 'expired')
        return None, 'TOKEN_EXPIRED'
    return e, None


def polled(terminal_id):
    db().execute('UPDATE vlab_terminal_enrollments SET last_poll_at = ? WHERE terminal_id = ?', (now(), terminal_id))


def close(terminal_id, state):
    """The key went out (delivered), an admin typed one in by hand (manual) or it ran out
    (expired): the token stops working either way."""
    db().execute("""UPDATE vlab_terminal_enrollments SET state = ?, token_hash = '',
                    delivered_at = CASE WHEN ? = 'delivered' THEN ? ELSE delivered_at END
                    WHERE terminal_id = ? AND state = 'waiting'""", (state, state, now(), terminal_id))


def forget(terminal_id):
    db().execute('DELETE FROM vlab_terminal_enrollments WHERE terminal_id = ?', (terminal_id,))


def annotate(terminals):
    """Each terminal with how its key goes out: enrollment = {state, code, created_at,
    last_poll_at, delivered_at} for the ones that came with a code, else None."""
    rows = {r['terminal_id']: dict(r) for r in db().query('SELECT * FROM vlab_terminal_enrollments')}
    names = {r['id']: r['name'] for r in db().query('SELECT id, name FROM vlab_enroll_codes')}
    for t in terminals:
        e = rows.get(t['id'])
        t['enrollment'] = None if not e else {
            'state': e['state'], 'code_id': e['code_id'], 'code': names.get(e['code_id'], ''),
            'created_at': e['created_at'], 'last_poll_at': e['last_poll_at'], 'delivered_at': e['delivered_at']}
    return terminals
