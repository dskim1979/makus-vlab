"""MOAVI Desk: bookings of accelerator cards and boards (GPU · NPU · FPGA 카드, 보드 LAB) on the
reservation calendar.

A user books a card of a PCI resource mapping (any free one of it), or one board (JTAG), for
one of their own desktops, from a start to an end (local time 'YYYY-MM-DDTHH:MM', as the LAB
bookings). With approval on, an approver (vlab.accel.manage) says yes first. At the start
(START_EARLY minutes before) the engine lends it the usual way - a card loan until the end, a
board attached until the end - and the existing returns give it back at the end. A booking
cancelled while it runs is returned at once.

What may be booked at a time: never more cards of a mapping than it has, counting the other
bookings and the loans running now (a loan holds its card until its end); a board one booking
at a time and not while it is attached to someone else; a desktop one card and one board at a
time. The pure rules are here; the routes and the minute loop are in
pegaprox/api/vlab_accel_book.py.
"""
import threading
from datetime import datetime, timedelta

from pegaprox.core.db import get_db
from pegaprox.vlab.store import db as _store_db, new_id, now

KINDS = ('card', 'board')
STATUSES = ('pending', 'approved', 'rejected', 'cancelled')
LIVE = ('pending', 'approved')
FMT = '%Y-%m-%dT%H:%M'
START_EARLY = 5             # minutes before the start the card or board is put on
SETTINGS_KEY = 'vlab_accel_booking'
DEFAULTS = {
    'enabled': True,
    'approval': False,       # bookings wait for vlab.accel.manage
    'max_hours': 72,         # longest booking
    'max_days_ahead': 30,
    'roles': [],             # roles that may book; [] = everyone with the portal
    'remind_min': 30,        # the user hears before the start (0: no); the card needs the desktop restarted
}
_LIMITS = {'max_hours': (1, 24 * 31), 'max_days_ahead': (1, 366), 'remind_min': (0, 24 * 60)}

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_accel_bookings (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        cluster_id TEXT NOT NULL,
        resource TEXT NOT NULL,
        resource_name TEXT NOT NULL DEFAULT '',
        card_kind TEXT NOT NULL DEFAULT '',
        desktop_id TEXT NOT NULL,
        username TEXT NOT NULL,
        start_at TEXT NOT NULL,
        end_at TEXT NOT NULL,
        purpose TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        reason TEXT NOT NULL DEFAULT '',
        reviewed_by TEXT NOT NULL DEFAULT '',
        reviewed_at TEXT,
        lease_id TEXT NOT NULL DEFAULT '',
        started_at TEXT,
        finished_at TEXT,
        error TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_accel_bookings_time ON vlab_accel_bookings(start_at, end_at)',
)
TABLES = ('vlab_accel_bookings',)
_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_accel_bookings', False):
        with _lock:
            if not getattr(d, '_vlab_accel_bookings', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_accel_bookings = True
    return d


# --- settings ------------------------------------------------------------------------------

def get_settings():
    raw = get_db().get_server_setting(SETTINGS_KEY, None)
    out = dict(DEFAULTS)
    if isinstance(raw, dict):
        out.update({k: v for k, v in raw.items() if k in DEFAULTS})
    return out


def save_settings(data):
    if not isinstance(data, dict):
        raise ValueError('A JSON object is required')
    s = get_settings()
    for k, v in data.items():
        if k in ('enabled', 'approval'):
            if not isinstance(v, bool):
                raise ValueError(f'{k}: true or false')
        elif k in _LIMITS:
            lo, hi = _LIMITS[k]
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                raise ValueError(f'{k}: a whole number from {lo} to {hi}')
        elif k == 'roles':
            if not isinstance(v, list) or len(v) > 50 or any(not isinstance(r, str) for r in v):
                raise ValueError('roles: a list of role names')
            v = [r.strip()[:80] for r in v if r.strip()]
        else:
            raise ValueError(f'Unknown setting: {k}')
        s[k] = v
    get_db().save_server_setting(SETTINGS_KEY, s)
    return s


# --- times ---------------------------------------------------------------------------------

def parse(v):
    try:
        return datetime.strptime(str(v)[:16], FMT)
    except (TypeError, ValueError):
        return None


def fmt(t):
    return t.strftime(FMT)


def overlap(a0, a1, b0, b1):
    return a0 < b1 and b0 < a1


def check_times(start, end, settings, at, privileged=False):
    """An error code for the times, or None: BAD_TIME, PAST, TOO_LONG, TOO_FAR."""
    if not start or not end or end <= start:
        return 'BAD_TIME'
    if end <= at:
        return 'PAST'
    if privileged:
        return None
    if start < at - timedelta(minutes=1):
        return 'PAST'
    if (end - start).total_seconds() > settings['max_hours'] * 3600:
        return 'TOO_LONG'
    if start > at + timedelta(days=settings['max_days_ahead']):
        return 'TOO_FAR'
    return None


# --- what collides -------------------------------------------------------------------------

def _peak(start, end, intervals):
    """Most of `intervals` ([(a, b)]) at once inside [start, end)."""
    ev = []
    for a, b in intervals:
        a, b = max(start, a), min(end, b)
        if a < b:
            ev += [(a, 1), (b, -1)]
    ev.sort(key=lambda e: (e[0], e[1]))
    peak = cur = 0
    for _, d in ev:
        cur += d
        peak = max(peak, cur)
    return peak


def conflicts(cand, others, capacity, held, at):
    """Why `cand` ({kind, cluster_id, resource, desktop_id, start, end}) cannot be booked:
    [{why, id?, start?, end?, limit?}]. `others` the live bookings near it (its own left out),
    `capacity` the cards of the mapping (1 for a board), `held` [(desktop_id, until datetime or
    None)] of the loans / attachments running now on that resource."""
    out = []
    s, e = cand['start'], cand['end']
    same = [o for o in others if o['kind'] == cand['kind'] and o['cluster_id'] == cand['cluster_id']
            and o['resource'] == cand['resource'] and overlap(s, e, parse(o['start_at']), parse(o['end_at']))]
    busy = [(at, until or e + timedelta(days=3650)) for _d, until in held]
    if capacity <= 0:
        out.append({'why': 'NO_DEVICES', 'limit': 0})
    elif _peak(s, e, [(parse(o['start_at']), parse(o['end_at'])) for o in same] + busy) + 1 > capacity:
        out += [{'why': 'TAKEN', 'id': o['id'], 'start': o['start_at'], 'end': o['end_at'], 'limit': capacity} for o in same]
        if busy and not same:
            out.append({'why': 'ON_LOAN', 'limit': capacity})
    mine = [o for o in others if o['desktop_id'] == cand['desktop_id'] and o['kind'] == cand['kind']
            and overlap(s, e, parse(o['start_at']), parse(o['end_at']))]
    out += [{'why': 'DESKTOP_BUSY', 'id': o['id'], 'start': o['start_at'], 'end': o['end_at']} for o in mine]
    return out


# --- the rows ------------------------------------------------------------------------------

def add(row):
    bid = new_id('abk')
    t = now()
    db().execute('INSERT INTO vlab_accel_bookings (id, kind, cluster_id, resource, resource_name, card_kind, desktop_id, username, '
                 'start_at, end_at, purpose, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                 (bid, row['kind'], row['cluster_id'], row['resource'], row.get('resource_name', ''), row.get('card_kind', ''),
                  row['desktop_id'], row['username'], row['start_at'], row['end_at'], row.get('purpose', ''), row['status'], t, t))
    return get(bid)


def get(bid):
    r = db().query_one('SELECT * FROM vlab_accel_bookings WHERE id = ?', (bid,))
    return dict(r) if r else None


_FIELDS = ('status', 'reason', 'reviewed_by', 'reviewed_at', 'lease_id', 'started_at', 'finished_at', 'error')


def update(bid, **fields):
    keys = [k for k in fields if k in _FIELDS]
    if keys:
        db().execute(f"UPDATE vlab_accel_bookings SET {', '.join(k + ' = ?' for k in keys)}, updated_at = ? WHERE id = ?",
                     tuple(fields[k] for k in keys) + (now(), bid))
    return get(bid)


def between(t0, t1, statuses=None, username=None):
    sql = 'SELECT * FROM vlab_accel_bookings WHERE start_at < ? AND end_at > ?'
    args = [t1, t0]
    if statuses:
        sql += f" AND status IN ({','.join('?' for _ in statuses)})"
        args += list(statuses)
    if username:
        sql += ' AND username = ?'
        args.append(username)
    return [dict(r) for r in db().query(sql + ' ORDER BY start_at', tuple(args))]


def of_user(username, since):
    return [dict(r) for r in db().query('SELECT * FROM vlab_accel_bookings WHERE username = ? AND end_at > ? ORDER BY start_at',
                                        (username, since))]


def pending():
    return [dict(r) for r in db().query("SELECT * FROM vlab_accel_bookings WHERE status = 'pending' ORDER BY start_at")]


def to_run(at):
    """Approved bookings to start, and the ones to finish, at local time `at`:
    (start [rows], finish [rows]). A cancelled booking that had started finishes at once."""
    t = fmt(at)
    early = fmt(at + timedelta(minutes=START_EARLY))
    start = [dict(r) for r in db().query("SELECT * FROM vlab_accel_bookings WHERE status = 'approved' AND started_at IS NULL "
                                         "AND start_at <= ? AND end_at > ?", (early, t))]
    finish = [dict(r) for r in db().query("SELECT * FROM vlab_accel_bookings WHERE started_at IS NOT NULL AND finished_at IS NULL "
                                          "AND (end_at <= ? OR status = 'cancelled')", (t,))]
    missed = [dict(r) for r in db().query("SELECT * FROM vlab_accel_bookings WHERE status = 'approved' AND started_at IS NULL "
                                          "AND finished_at IS NULL AND end_at <= ?", (t,))]
    return start, finish, missed
