# -*- coding: utf-8 -*-
"""
MOAVI Desk per-user notices: which mails a user takes, and the record that keeps a notice to once.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

Tables (core DB, made on first use like store.py's; HA-synced so a failover sends nothing twice):
  vlab_notice_prefs  per user: the kinds of notice they turned off ({kind: false}); every kind is on
                     until they do (내 계정 > 알림)
  vlab_notice_sent   a notice that must go once: a quota step this month, the reminder before a
                     loan's end. The key says what it was; rows older than KEEP_DAYS are pruned

A notice is a mail to the account's own address. The webhook events beside it go to the channels
the administrators chose (research settings 'channels'); pegaprox/api/vlab_notices.py has the
routes and the checks of the minute loop.
"""

import json
import logging
import threading
from datetime import datetime, timedelta, timezone

from pegaprox.vlab.store import db as _store_db, now

# kind: (Korean label, English label) - the order is the one 내 계정 shows
KINDS = {
    'gpu_job': ('GPU 작업 시작·종료 (작업을 보낼 때 고른 것)', 'GPU job started / ended (as chosen per job)'),
    'gpu_quota': ('GPU 할당량 경고 (80%·100%)', 'GPU quota warnings (80% / 100%)'),
    'loan': ('카드·보드 대여 만료 알림과 자동 반납', 'Card / board loan reminders and automatic returns'),
    'ide': ('웹 IDE 종료 (유휴·관리자)', 'Web IDE closed (idle / by an administrator)'),
    'work': ('작업 보호 (정리 미룸·쓰이지 않는 카드)', 'Work protection (deferred clean-ups, idle cards)'),
    'desktop': ('데스크톱 배정·회수·교체·이동·접속 끊김', 'Desktop assigned, taken back, replaced, moved or disconnected'),
    'booking': ('LAB 예약 시작 전 알림', 'LAB booking about to start'),
    'storage': ('내 폴더(NAS) 용량 90%·100%', 'My NAS folders at 90% / 100%'),
    'request': ('신청 결과 (가입·대여·반출·예약)', 'Answers to my requests (sign-up, loans, exports, bookings)'),
}
KEEP_DAYS = 120

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_notice_prefs (
        username TEXT PRIMARY KEY,
        prefs TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT NOT NULL
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_notice_sent (
        key TEXT PRIMARY KEY,
        sent_at TEXT NOT NULL
    )''',
)
TABLES = ('vlab_notice_prefs', 'vlab_notice_sent')

_lock = threading.Lock()
_once_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_notices', False):
        with _lock:
            if not getattr(d, '_vlab_notices', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_notices = True
    return d


# --- what each user takes -------------------------------------------------------------------

def prefs(username):
    """{kind: True|False} for every kind; a kind not saved is on."""
    r = db().query_one('SELECT prefs FROM vlab_notice_prefs WHERE username = ?', (username,))
    saved = {}
    if r:
        try:
            saved = json.loads(r['prefs'] or '{}')
        except ValueError:
            saved = {}
    return {k: saved.get(k) is not False for k in KINDS}


def validate_prefs(data):
    if not isinstance(data, dict):
        raise ValueError('JSON object required')
    unknown = sorted(set(data) - set(KINDS))
    if unknown:
        raise ValueError(f"unknown kinds: {', '.join(unknown)}")
    if any(not isinstance(v, bool) for v in data.values()):
        raise ValueError('each kind is true or false')
    return data


def save_prefs(username, data):
    """Keep the kinds left out as they were. Returns prefs(username)."""
    merged = dict(prefs(username), **validate_prefs(data))
    off = {k: False for k, v in merged.items() if not v}
    db().execute('INSERT OR REPLACE INTO vlab_notice_prefs (username, prefs, updated_at) VALUES (?, ?, ?)',
                 (username, json.dumps(off), now()))
    return prefs(username)


def forget_user(username):
    db().execute('DELETE FROM vlab_notice_prefs WHERE username = ?', (username,))


def wants(username, kind):
    return bool(username) and prefs(username).get(kind, True)


# --- once ------------------------------------------------------------------------------------

def once(key):
    """True the first time a key is seen (the caller sends then), False after."""
    d = db()
    with _once_lock:
        if d.query_one('SELECT 1 FROM vlab_notice_sent WHERE key = ?', (key,)):
            return False
        d.execute('INSERT OR IGNORE INTO vlab_notice_sent (key, sent_at) VALUES (?, ?)', (key, now()))
        return True


def was_sent(key):
    return bool(db().query_one('SELECT 1 FROM vlab_notice_sent WHERE key = ?', (key,)))


def prune(at=None):
    cut = ((at or datetime.now(timezone.utc)) - timedelta(days=KEEP_DAYS)).isoformat(timespec='seconds')
    db().execute('DELETE FROM vlab_notice_sent WHERE sent_at < ?', (cut,))


# --- sending ---------------------------------------------------------------------------------

def email_of(username):
    try:
        from pegaprox.utils.auth import load_users
        return ((load_users() or {}).get(username) or {}).get('email') or ''
    except Exception:
        return ''


def mail(username, kind, title, text):
    """A mail to the user's own address when they take this kind. True when one went out."""
    if not wants(username, kind):
        return False
    email = email_of(username)
    if not email:
        return False
    try:
        from pegaprox.utils.email import send_email
        send_email([email], title if title.startswith('[MOAVI Desk]') else f'[MOAVI Desk] {title}', text, None)
        return True
    except Exception as e:
        logging.warning(f'[VLAB] notice mail ({kind}) to {username}: {e}')
        return False


def webhook(channels, event, title, text, severity='info', **data):
    """The same notice as a webhook event on the channels the administrators chose."""
    if not channels:
        return False
    try:
        from pegaprox.utils.webhooks import send_to_channels
        send_to_channels(dict(data, title=title, message=text, source='moavi-desk', severity=severity, kind=event), channels)
        return True
    except Exception as e:
        logging.warning(f'[VLAB] notice webhook ({event}): {e}')
        return False


# --- the pure rules --------------------------------------------------------------------------

def storage_level(kb, quota_gb):
    """'full' at or past the folder's quota, 'warn' at or past 90 %, else None (no quota: None)."""
    if not quota_gb or quota_gb <= 0 or kb is None:
        return None
    pct = 100.0 * kb / (quota_gb * 1024 * 1024)
    return 'full' if pct >= 100 else ('warn' if pct >= 90 else None)


def quota_level(hours, limit, warn_pct):
    """'full' at or past the monthly GPU-hours, 'warn' at or past warn_pct of them, else None."""
    if not limit or limit <= 0:
        return None
    pct = 100.0 * float(hours or 0) / float(limit)
    if pct >= 100:
        return 'full'
    if warn_pct and pct >= warn_pct:
        return 'warn'
    return None


def due_soon(ends_at, hours, at):
    """A loan ending within `hours` of `at` (and not yet past)."""
    if not ends_at or not hours:
        return False
    try:
        end = datetime.fromisoformat(str(ends_at))
    except ValueError:
        return False
    end = end if end.tzinfo else end.replace(tzinfo=timezone.utc)
    return at < end <= at + timedelta(hours=hours)


def local_time(iso):
    """'YYYY-MM-DD HH:MM' on the server's clock, for a mail."""
    try:
        t = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return str(iso or '-')
    t = t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    return t.astimezone().strftime('%Y-%m-%d %H:%M')
