# -*- coding: utf-8 -*-
"""
MOAVI Desk account extras for universities and labs: password reset by mail, mail
verification of sign-up requests, account expiry and the terms / privacy consent record.
docs/vlab-design.md 4-2 (accounts).

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

Tables (core DB, made on first use like store.py's):
  vlab_password_resets   one-time reset links: only the SHA-256 of the token is kept
  vlab_signup_verify     the mail check of a sign-up request (code and link, hashed)
  vlab_account_expiry    per account: last day of use, when it was told, when it expired
  vlab_terms_consents    who agreed to which terms version, when and from where

The pure helpers here (CSV rows, passwords, domains, dates) are what the routes of
pegaprox/api/vlab_accounts.py and the minute loop (accounts_tick) build on.
"""

import csv
import hashlib
import io
import re
import secrets
import string
import threading
from datetime import date, datetime, timedelta, timezone

from pegaprox.vlab.store import db as _store_db, new_id, now

RESET_MINUTES = 30
VERIFY_MINUTES = 30
VERIFY_ATTEMPTS = 5
MAX_IMPORT_ROWS = 1000
VERIFY_MODES = ('off', 'optional', 'required')

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_password_resets (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used_at TEXT,
        client_ip TEXT NOT NULL DEFAULT ''
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_password_resets_user ON vlab_password_resets(username)',
    '''CREATE TABLE IF NOT EXISTS vlab_signup_verify (
        signup_id TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        code_hash TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        sends INTEGER NOT NULL DEFAULT 1,
        sent_at TEXT NOT NULL,
        verified_at TEXT
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_account_expiry (
        username TEXT PRIMARY KEY,
        expires_at TEXT NOT NULL,
        notified_at TEXT,
        expired_at TEXT,
        set_by TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_terms_consents (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        version TEXT NOT NULL,
        via TEXT NOT NULL DEFAULT 'login',
        client_ip TEXT NOT NULL DEFAULT '',
        agreed_at TEXT NOT NULL
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_terms_consents_user ON vlab_terms_consents(username, version)',
)
TABLES = ('vlab_password_resets', 'vlab_signup_verify', 'vlab_account_expiry', 'vlab_terms_consents')

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_accounts', False):
        with _lock:
            if not getattr(d, '_vlab_accounts', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_accounts = True
    return d


def _rows(sql, args=()):
    return [dict(r) for r in db().query(sql, args)]


def _one(sql, args=()):
    r = db().query_one(sql, args)
    return dict(r) if r else None


def _utc(minutes=0):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat(timespec='seconds')


def digest(secret, salt=''):
    return hashlib.sha256(f'{salt}:{secret}'.encode('utf-8')).hexdigest()


# --- password reset links ------------------------------------------------------------------

def new_reset(username, client_ip=''):
    """A fresh link for the account; the earlier unused ones stop working. Returns the token."""
    token = secrets.token_urlsafe(32)
    db().execute('UPDATE vlab_password_resets SET used_at = ? WHERE username = ? AND used_at IS NULL', (now(), username))
    db().execute('INSERT INTO vlab_password_resets (id, username, token_hash, created_at, expires_at, client_ip) '
                 'VALUES (?, ?, ?, ?, ?, ?)',
                 (new_id('pwr'), username, digest(token), _utc(), _utc(RESET_MINUTES), client_ip))
    return token


def reset_for(token):
    """The open reset row of a token, or None (unknown, used or past its 30 minutes)."""
    if not token or len(token) > 200:
        return None
    r = _one('SELECT * FROM vlab_password_resets WHERE token_hash = ?', (digest(token),))
    if not r or r['used_at'] or r['expires_at'] < _utc():
        return None
    return r


def use_reset(rid):
    """Mark the link used; False when someone used it first."""
    stamp = datetime.now(timezone.utc).isoformat(timespec='microseconds')
    db().execute('UPDATE vlab_password_resets SET used_at = ? WHERE id = ? AND used_at IS NULL', (stamp, rid))
    r = _one('SELECT used_at FROM vlab_password_resets WHERE id = ?', (rid,))
    return bool(r) and r['used_at'] == stamp


def drop_resets(username):
    db().execute('DELETE FROM vlab_password_resets WHERE username = ?', (username,))


# --- sign-up mail verification -------------------------------------------------------------

def new_verification(signup_id, email):
    """(code, token) for the request; a resend replaces the previous pair."""
    code = f'{secrets.randbelow(10 ** 6):06d}'
    token = secrets.token_urlsafe(24)
    old = verification(signup_id)
    db().execute('INSERT OR REPLACE INTO vlab_signup_verify (signup_id, email, code_hash, token_hash, expires_at, attempts, '
                 'sends, sent_at, verified_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?, NULL)',
                 (signup_id, email, digest(code, signup_id), digest(token, signup_id), _utc(VERIFY_MINUTES),
                  (old['sends'] + 1) if old else 1, _utc()))
    return code, token


def verification(signup_id):
    return _one('SELECT * FROM vlab_signup_verify WHERE signup_id = ?', (signup_id,))


def verifications():
    return {r['signup_id']: r for r in _rows('SELECT signup_id, verified_at, sent_at, sends FROM vlab_signup_verify')}


def check_verification(signup_id, code=None, token=None):
    """'ok', 'already', 'expired', 'locked', 'wrong' or 'none'."""
    v = verification(signup_id)
    if not v:
        return 'none'
    if v['verified_at']:
        return 'already'
    if v['attempts'] >= VERIFY_ATTEMPTS:
        return 'locked'
    if v['expires_at'] < _utc():
        return 'expired'
    good = (code and hmac_eq(digest(str(code).strip(), signup_id), v['code_hash'])) or \
           (token and hmac_eq(digest(str(token), signup_id), v['token_hash']))
    if not good:
        db().execute('UPDATE vlab_signup_verify SET attempts = attempts + 1 WHERE signup_id = ?', (signup_id,))
        return 'wrong'
    db().execute('UPDATE vlab_signup_verify SET verified_at = ? WHERE signup_id = ?', (now(), signup_id))
    return 'ok'


def hmac_eq(a, b):
    import hmac
    return hmac.compare_digest(str(a), str(b))


def is_verified(signup_id):
    v = verification(signup_id)
    return bool(v and v['verified_at'])


# --- institution domains -------------------------------------------------------------------

_DOMAIN = re.compile(r'^(?=.{3,120}$)([a-z0-9-]+\.)+[a-z]{2,}$')


def clean_domains(v):
    if v in (None, ''):
        return []
    if isinstance(v, str):
        v = re.split(r'[\s,;]+', v)
    if not isinstance(v, list) or len(v) > 50:
        raise ValueError('auto_domains: a list of at most 50 domains')
    out = []
    for d in v:
        d = str(d or '').strip().lower().lstrip('@')
        if not d:
            continue
        if not _DOMAIN.match(d):
            raise ValueError(f'auto_domains: "{d}" is not a domain')
        if d not in out:
            out.append(d)
    return out


def domain_matches(email, domains):
    """univ.ac.kr matches kim@univ.ac.kr and kim@cs.univ.ac.kr."""
    host = str(email or '').rsplit('@', 1)[-1].strip().lower() if '@' in str(email or '') else ''
    return bool(host) and any(host == d or host.endswith('.' + d) for d in domains)


# --- account expiry ------------------------------------------------------------------------

def parse_day(v):
    """'YYYY-MM-DD' -> date; None for empty; ValueError otherwise."""
    if v in (None, ''):
        return None
    try:
        return datetime.strptime(str(v).strip()[:10], '%Y-%m-%d').date()
    except ValueError:
        raise ValueError('expires_at: a date as YYYY-MM-DD')


def expiry_map():
    """{username: row} of the accounts with a last day of use."""
    return {r['username']: r for r in _rows('SELECT * FROM vlab_account_expiry')}


def get_expiry(username):
    return _one('SELECT * FROM vlab_account_expiry WHERE username = ?', (username,))


def set_expiry(username, day, by=''):
    """day: a date or None (no limit). A new day starts the notice and expiry over."""
    if day is None:
        db().execute('DELETE FROM vlab_account_expiry WHERE username = ?', (username,))
        return None
    db().execute('INSERT OR REPLACE INTO vlab_account_expiry (username, expires_at, notified_at, expired_at, set_by, updated_at) '
                 'VALUES (?, ?, NULL, NULL, ?, ?)', (username, day.isoformat(), by, now()))
    return get_expiry(username)


def mark_expiry(username, **fields):
    keys = [k for k in fields if k in ('notified_at', 'expired_at')]
    if keys:
        db().execute(f"UPDATE vlab_account_expiry SET {', '.join(k + ' = ?' for k in keys)} WHERE username = ?",
                     tuple(fields[k] for k in keys) + (username,))


def expiry_state(row, today=None):
    """'active', 'soon' (within notice days is the caller's call), 'expired' or None."""
    if not row:
        return None
    today = today or date.today()
    return 'expired' if row.get('expired_at') or parse_day(row['expires_at']) < today else 'active'


# --- terms consents ------------------------------------------------------------------------

def add_consent(username, version, via, client_ip=''):
    db().execute('INSERT INTO vlab_terms_consents (id, username, version, via, client_ip, agreed_at) VALUES (?, ?, ?, ?, ?, ?)',
                 (new_id('tc'), username, version, via, client_ip, now()))


def has_consent(username, version):
    return bool(_one('SELECT id FROM vlab_terms_consents WHERE username = ? AND version = ? LIMIT 1', (username, version)))


def consents(version=None, username=None, limit=5000):
    sql, args = 'SELECT * FROM vlab_terms_consents WHERE 1 = 1', []
    if version:
        sql += ' AND version = ?'
        args.append(version)
    if username:
        sql += ' AND username = ?'
        args.append(username)
    return _rows(sql + ' ORDER BY agreed_at DESC LIMIT ?', tuple(args) + (int(limit),))


def forget(username):
    """The account is gone: its links, expiry and (not) its consents - those are the record."""
    db().execute('DELETE FROM vlab_password_resets WHERE username = ?', (username,))
    db().execute('DELETE FROM vlab_account_expiry WHERE username = ?', (username,))


# --- bulk import (CSV) ---------------------------------------------------------------------

HEADERS = {
    'username': ('username', 'user', 'id', 'login', '아이디', '사용자', '계정'),
    'display_name': ('display_name', 'name', '이름', '성명', '표시 이름'),
    'email': ('email', 'mail', 'e-mail', '메일', '이메일'),
    'department': ('department', 'department_id', 'dept', '부서', '소속'),
    'role': ('role', '역할'),
    'expires_at': ('expires_at', 'expires', 'expiry', '사용 기한', '사용기한', '만료일', '기한'),
}
EXAMPLE_CSV = ('아이디,이름,메일,부서,역할,사용 기한\r\n'
               'kim.minji,김민지,kim.minji@univ.ac.kr,컴퓨터공학과,user,2027-02-28\r\n'
               'lee.junho,이준호,lee.junho@univ.ac.kr,컴퓨터공학과,user,2027-02-28\r\n')


def _norm(h):
    return re.sub(r'\s+', ' ', str(h or '').replace('﻿', '').strip().lower())


def read_csv(text):
    """[(line, {field: value})] of a CSV with a header row; ValueError when it is not one."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError('csv: the file is empty')
    if len(text) > 2_000_000:
        raise ValueError('csv: at most 2 MB')
    text = text.lstrip('﻿')
    sample = text[:4096]
    delim = '\t' if sample.count('\t') > sample.count(',') else (';' if sample.count(';') > sample.count(',') else ',')
    reader = csv.reader(io.StringIO(text), delimiter=delim)
    try:
        header = next(reader)
    except StopIteration:
        raise ValueError('csv: the file is empty')
    alias = {_norm(a): k for k, names in HEADERS.items() for a in names}
    cols = [alias.get(_norm(h)) for h in header]
    if 'username' not in cols:
        raise ValueError('csv: the first row must name the columns (아이디/username, 이름, 메일, 부서, 역할, 사용 기한)')
    out = []
    for n, row in enumerate(reader, start=2):
        if not any(c.strip() for c in row):
            continue
        rec = {}
        for i, c in enumerate(row):
            if i < len(cols) and cols[i] and cols[i] not in rec:
                rec[cols[i]] = c.strip()
        out.append((n, rec))
        if len(out) > MAX_IMPORT_ROWS:
            raise ValueError(f'csv: at most {MAX_IMPORT_ROWS} accounts at once')
    if not out:
        raise ValueError('csv: no accounts under the header row')
    return out


def make_password(min_length=8, special=False):
    """A random password the default policy accepts: upper, lower, digits (and a sign)."""
    n = max(12, int(min_length or 8))
    pools = [string.ascii_uppercase, string.ascii_lowercase, string.digits] + (['!@#$%^&*-_=+'] if special else [])
    alphabet = ''.join(p for p in pools).replace('l', '').replace('I', '').replace('O', '').replace('0', '')
    while True:
        pw = ''.join(secrets.choice(alphabet) for _ in range(n))
        if all(any(c in p for c in pw) for p in pools):
            return pw


def csv_text(header, rows):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator='\r\n')
    w.writerow(header)
    for r in rows:
        w.writerow(['' if v is None else _cell(v) for v in r])
    return '﻿' + buf.getvalue()


def _cell(v):
    s = str(v)
    # a spreadsheet must not run a formula out of a name somebody typed
    return "'" + s if s[:1] in ('=', '+', '-', '@') and not re.match(r'^-?\d', s) else s
