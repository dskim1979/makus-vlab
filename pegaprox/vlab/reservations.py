# -*- coding: utf-8 -*-
"""
MOAVI Desk LAB reservations (LAB > 예약, portal 예약): professors, assistants and researchers
book a whole LAB (a class, a seminar), N seats of a LAB, or N desktops of a pool, once or
weekly for N weeks. docs/vlab-design.md 4 (LAB).

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

Tables (core DB, made on first use like store.py's):
  vlab_reservations          one row per occurrence; a weekly booking is a series (series_id)
  vlab_reservation_settings  per LAB (key = lab id, '_pool' for desktops booked without a LAB,
                             '_global' for the notification choices)

Times are the server's local wall clock like the LAB schedules: 'YYYY-MM-DDTHH:MM', naive.
The pure functions here validate, expand a series and find what a booking collides with;
pegaprox/api/vlab_reserve.py has the routes and runs approved bookings from lab_tick.
"""

import json
import re
import threading
from datetime import datetime, timedelta

from pegaprox.vlab import labs
from pegaprox.vlab.store import db as _store_db, new_id, now

KINDS = ('lab', 'seats', 'desktops')
STATUSES = ('pending', 'approved', 'rejected', 'cancelled')
LIVE = ('pending', 'approved')            # what holds a slot: a request waiting counts too
SUBJECT_TYPES = ('user', 'department', 'group')
POOL_KEY = '_pool'
GLOBAL_KEY = '_global'
MAX_WEEKS = 26
FMT = '%Y-%m-%dT%H:%M'

DEFAULTS = {
    'enabled': True,          # bookable at all
    'approval': False,        # requests wait for vlab.lab.manage
    'open_from': '08:00',     # bookable hours (each day)
    'open_to': '22:00',
    'weekdays': [0, 1, 2, 3, 4, 5, 6],
    'max_minutes': 240,       # longest booking
    'max_days_ahead': 60,     # how far ahead
    'roles': [],              # roles that may book; [] = everyone with the portal
    'pool_ids': [],           # pools a LAB booking may use; [] = the pools of its schedules
    'prepare_min': 10,
    'after': 'reset',
    'banner': False,          # an approved booking also shows as a notice while it runs
}
GLOBAL_DEFAULTS = {'mail': True, 'channels': [], 'remind_min': 30}   # mail the requester; webhook channel ids;
                                                                  # remind the people N minutes before (0: no)

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_reservations (
        id TEXT PRIMARY KEY,
        series_id TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL,
        lab_id TEXT,
        pool_id TEXT NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 0,
        start_at TEXT NOT NULL,
        end_at TEXT NOT NULL,
        purpose TEXT NOT NULL DEFAULT '',
        note TEXT NOT NULL DEFAULT '',
        participants TEXT NOT NULL DEFAULT '[]',
        requester TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        reason TEXT NOT NULL DEFAULT '',
        reviewed_by TEXT NOT NULL DEFAULT '',
        reviewed_at TEXT,
        prepare_min INTEGER NOT NULL DEFAULT 10,
        after TEXT NOT NULL DEFAULT 'reset',
        desktops TEXT NOT NULL DEFAULT '[]',
        handed TEXT NOT NULL DEFAULT '[]',
        prepared_at TEXT,
        finished_at TEXT,
        banner_id TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_reservations_time ON vlab_reservations(start_at, end_at)',
    'CREATE INDEX IF NOT EXISTS idx_vlab_reservations_user ON vlab_reservations(requester)',
    '''CREATE TABLE IF NOT EXISTS vlab_reservation_settings (
        key TEXT PRIMARY KEY,
        settings TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT NOT NULL
    )''',
)

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_reservations', False):
        with _lock:
            if not getattr(d, '_vlab_reservations', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_reservations = True
    return d


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


# --- settings ------------------------------------------------------------------------------

def _hhmm(v, default):
    v = str(v or '')
    return v if labs.HHMM.match(v) or v == '24:00' else default


def clean_settings(data, current=None):
    """(settings, error) from a body over the current settings."""
    s = dict(DEFAULTS, **(current or {}))
    if not isinstance(data, dict):
        return None, 'A JSON body is required'
    for k in ('enabled', 'approval', 'banner'):
        if k in data:
            s[k] = bool(data[k])
    for k in ('open_from', 'open_to'):
        if k in data:
            v = str(data[k] or '')
            if not (labs.HHMM.match(v) or (k == 'open_to' and v == '24:00')):
                return None, f'{k} is HH:MM'
            s[k] = v
    if _mins(s['open_to']) <= _mins(s['open_from']):
        return None, 'open_to must be after open_from'
    if 'weekdays' in data:
        days = data['weekdays'] if isinstance(data['weekdays'], list) else str(data['weekdays']).split(',')
        s['weekdays'] = labs.weekdays(','.join(str(x) for x in days))
        if not s['weekdays']:
            return None, 'Pick at least one weekday'
    for k, lo, hi in (('max_minutes', 15, 24 * 60), ('max_days_ahead', 1, 366), ('prepare_min', 0, 180)):
        if k in data:
            try:
                v = int(data[k])
            except (TypeError, ValueError):
                return None, f'{k} must be a number'
            if not lo <= v <= hi:
                return None, f'{k} must be {lo}-{hi}'
            s[k] = v
    if 'after' in data:
        if data['after'] not in labs.AFTER:
            return None, 'after must be one of ' + ', '.join(labs.AFTER)
        s['after'] = data['after']
    for k in ('roles', 'pool_ids'):
        if k in data:
            v = data[k]
            if not isinstance(v, list) or len(v) > 100:
                return None, f'{k}: a list'
            s[k] = [str(x)[:100] for x in v if str(x).strip()]
    return s, None


def _mins(hhmm):
    return 24 * 60 if hhmm == '24:00' else labs._minutes(hhmm)


def get_settings(key):
    r = db().query_one('SELECT settings FROM vlab_reservation_settings WHERE key = ?', (key,))
    saved = {}
    if r:
        try:
            saved = json.loads(r['settings'] or '{}')
        except ValueError:
            saved = {}
    base = GLOBAL_DEFAULTS if key == GLOBAL_KEY else DEFAULTS
    return {k: saved.get(k, v) for k, v in base.items()}


def all_settings():
    out = {}
    for r in db().query('SELECT key FROM vlab_reservation_settings'):
        out[r['key']] = get_settings(r['key'])
    return out


def save_settings(key, settings):
    db().execute('INSERT OR REPLACE INTO vlab_reservation_settings (key, settings, updated_at) VALUES (?, ?, ?)',
                 (key, json.dumps(settings, ensure_ascii=False), now()))
    return get_settings(key)


def delete_settings(key):
    db().execute('DELETE FROM vlab_reservation_settings WHERE key = ?', (key,))


# --- a request -----------------------------------------------------------------------------

def clean_participants(rows):
    """[{subject_type, subject_id}] or raises ValueError."""
    if rows in (None, ''):
        return []
    if not isinstance(rows, list) or len(rows) > 200:
        raise ValueError('participants: a list of at most 200')
    out, seen = [], set()
    for p in rows:
        if not isinstance(p, dict):
            raise ValueError('participants: objects with subject_type and subject_id')
        t, sid = str(p.get('subject_type') or ''), str(p.get('subject_id') or '').strip()
        if t not in SUBJECT_TYPES or not sid or len(sid) > 300:
            raise ValueError('participants: subject_type is user, department or group, with a subject_id')
        if (t, sid) not in seen:
            seen.add((t, sid))
            out.append({'subject_type': t, 'subject_id': sid})
    return out


def occurrences(start, end, repeat=None):
    """[(start, end)] of a booking: once, or weekly on `repeat.weekdays` for `repeat.weeks`
    weeks from the start's week (occurrences before the first one are left out)."""
    if not repeat:
        return [(start, end)]
    days = repeat.get('weekdays')
    days = labs.weekdays(','.join(str(x) for x in days)) if isinstance(days, list) else labs.weekdays(days)
    days = days or [start.weekday()]
    weeks = int(repeat.get('weeks') or 1)
    length = end - start
    monday = start.date() - timedelta(days=start.weekday())
    out = []
    for w in range(weeks):
        for d in days:
            day = monday + timedelta(days=7 * w + d)
            if day < start.date():
                continue
            s = datetime(day.year, day.month, day.day, start.hour, start.minute)
            out.append((s, s + length))
    return out


def validate(data):
    """(clean dict, occurrences, error) for a request body; the LAB, pool and the settings'
    limits are checked by the route."""
    if not isinstance(data, dict):
        return None, None, 'A JSON body is required'
    kind = data.get('kind')
    if kind not in KINDS:
        return None, None, 'kind must be lab, seats or desktops'
    start, end = parse(data.get('start_at')), parse(data.get('end_at'))
    if not start or not end:
        return None, None, 'start_at and end_at are YYYY-MM-DDTHH:MM'
    if end <= start:
        return None, None, 'The end must be after the start'
    if end.date() != start.date() and not (end.date() == start.date() + timedelta(days=1) and end.hour == 0 and end.minute == 0):
        return None, None, 'A booking ends on the day it starts'
    try:
        quantity = int(data.get('quantity') or 0)
    except (TypeError, ValueError):
        return None, None, 'quantity must be a number'
    if kind != 'lab' and not 1 <= quantity <= 10000:
        return None, None, 'quantity must be at least 1'
    repeat = data.get('repeat') or None
    if repeat is not None:
        if not isinstance(repeat, dict):
            return None, None, 'repeat: {weekdays, weeks}'
        try:
            weeks = int(repeat.get('weeks') or 0)
        except (TypeError, ValueError):
            return None, None, 'repeat.weeks must be a number'
        if not 1 <= weeks <= MAX_WEEKS:
            return None, None, f'repeat.weeks must be 1-{MAX_WEEKS}'
    try:
        participants = clean_participants(data.get('participants'))
    except ValueError as e:
        return None, None, str(e)
    occ = occurrences(start, end, repeat)
    if not occ:
        return None, None, 'The repeat gives no date'
    return {'kind': kind, 'quantity': quantity, 'purpose': str(data.get('purpose') or '').strip()[:120],
            'note': str(data.get('note') or '')[:1000], 'participants': participants}, occ, None


def rule_errors(settings, start, end, at, privileged=False):
    """What the LAB's settings refuse about one occurrence (codes the console words)."""
    out = []
    if not settings.get('enabled', True):
        return ['CLOSED']
    if start < at:
        out.append('PAST')
    if privileged:
        return out
    if (end - start).total_seconds() / 60 > settings['max_minutes']:
        out.append('TOO_LONG')
    if start.date() > (at + timedelta(days=settings['max_days_ahead'])).date():
        out.append('TOO_FAR')
    if start.weekday() not in settings['weekdays']:
        out.append('WEEKDAY')
    s_min = start.hour * 60 + start.minute
    e_min = (end - datetime(start.year, start.month, start.day)).total_seconds() / 60
    if s_min < _mins(settings['open_from']) or e_min > _mins(settings['open_to']):
        out.append('HOURS')
    return out


# --- what a booking collides with ----------------------------------------------------------

def schedule_blocks(schedules, day0, day1):
    """The weekly schedules' occurrences between two dates (inclusive), as dicts."""
    out = []
    d = day0
    while d <= day1:
        for s in schedules:
            if not s.get('enabled'):
                continue
            occ = labs.occurrence(s, d)
            if occ:
                out.append({'type': 'schedule', 'id': s['id'], 'lab_id': s['lab_id'], 'pool_id': s['pool_id'],
                            'title': s.get('title') or '', 'start': occ[0], 'end': occ[1]})
        d += timedelta(days=1)
    return out


def demand(r, seats, pool_size):
    """Desktops a booking takes from its pool: the whole pool for a LAB booking (its seats
    at most when the room has a seat count), else its quantity."""
    if r['kind'] == 'lab':
        return min(seats, pool_size) if seats else pool_size
    return int(r['quantity'] or 0)


def conflicts(cand, start, end, schedules, others, lab, pool_size):
    """What one occurrence of `cand` (kind, lab_id, pool_id, quantity) collides with:
    [{type, id, title, start, end, why}]. `schedules` are every LAB schedule, `others` the
    live bookings near it (the candidate's own rows left out), `lab` its room or None."""
    out = []
    seats = int((lab or {}).get('seats') or 0)
    lab_id = cand.get('lab_id')
    for b in schedule_blocks(schedules, start.date(), end.date()):
        if not overlap(start, end, b['start'], b['end']):
            continue
        if lab_id and b['lab_id'] == lab_id:
            out.append(dict(b, why='lab_schedule'))
        elif b['pool_id'] == cand['pool_id']:
            out.append(dict(b, why='pool_schedule'))
    near = [o for o in others if overlap(start, end, parse(o['start_at']), parse(o['end_at']))]
    if lab_id:
        same = [o for o in near if o.get('lab_id') == lab_id]
        if cand['kind'] == 'lab':
            out += [_row(o, 'lab_booked') for o in same]
        else:
            whole = [o for o in same if o['kind'] == 'lab']
            out += [_row(o, 'lab_booked') for o in whole]
            if seats and not whole:
                if int(cand['quantity']) > seats:
                    out.append({'type': 'limit', 'id': '', 'title': '', 'start': start, 'end': end, 'why': 'seats', 'limit': seats})
                else:
                    peak = _peak_load(start, end, [o for o in same if o['kind'] == 'seats'])
                    if peak + int(cand['quantity']) > seats:
                        out += [_row(o, 'seats', limit=seats) for o in same if o['kind'] == 'seats']
    # the pool: never more desktops at once than it has
    want = demand(cand, seats, pool_size)
    if want > pool_size:
        out.append({'type': 'limit', 'id': '', 'title': '', 'start': start, 'end': end, 'why': 'pool_size', 'limit': pool_size})
    else:
        mine = [o for o in near if o['pool_id'] == cand['pool_id']]
        peak = _peak_load(start, end, mine, pool_size)
        if mine and peak + want > pool_size:
            seen = {x['id'] for x in out}
            out += [_row(o, 'pool_full', limit=pool_size) for o in mine if o['id'] not in seen]
    return out


def _peak_load(start, end, rows, pool_size=0):
    """Most desktops/seats the rows hold at once inside [start, end). A LAB booking holds
    its '_demand' (set by the caller from its room and pool), else the whole pool."""
    events = []
    for o in rows:
        a, b = max(start, parse(o['start_at'])), min(end, parse(o['end_at']))
        if a < b:
            q = int(o['quantity'] or 0) if o['kind'] != 'lab' else (int(o.get('_demand') or pool_size))
            events += [(a, q), (b, -q)]
    events.sort(key=lambda e: (e[0], e[1]))
    peak = cur = 0
    for _, q in events:
        cur += q
        peak = max(peak, cur)
    return peak


def _row(o, why, **extra):
    return dict({'type': 'reservation', 'id': o['id'], 'title': o.get('purpose') or '', 'requester': o.get('requester'),
                 'status': o.get('status'), 'start': parse(o['start_at']), 'end': parse(o['end_at']), 'why': why}, **extra)


def wire(c):
    """A conflict as JSON (times as text)."""
    return {k: (fmt(v) if isinstance(v, datetime) else v) for k, v in c.items()}


# --- running ------------------------------------------------------------------------------

def due(r, at, grace=labs.FINISH_GRACE):
    """'prepare', 'finish', 'skip' (its time passed unrun: only marked) or None for booking r
    at local time `at`. A booking cancelled while it ran is finished at once."""
    start, end = parse(r['start_at']), parse(r['end_at'])
    prepared, finished = bool(r.get('prepared_at')), bool(r.get('finished_at'))
    if finished:
        return None
    if r['status'] == 'cancelled':
        return 'finish' if prepared else None
    if r['status'] != 'approved':
        return None
    if at >= end:
        return 'finish' if prepared and at < end + grace else 'skip'
    if not prepared and start - timedelta(minutes=int(r.get('prepare_min') or 0)) <= at:
        return 'prepare'
    return None


def running(r, at):
    """Is the booking in its time now (from its prepare minutes before the start)?"""
    start, end = parse(r['start_at']), parse(r['end_at'])
    return r['status'] == 'approved' and start - timedelta(minutes=int(r.get('prepare_min') or 0)) <= at < end


def is_participant(r, username, dep=None, groups=None, descendants=None):
    if username == r['requester']:
        return True
    for p in r.get('participants') or []:
        if p['subject_type'] == 'user' and p['subject_id'] == username:
            return True
        if p['subject_type'] == 'department' and dep:
            if dep == p['subject_id'] or (descendants and dep in descendants(p['subject_id'])):
                return True
        if p['subject_type'] == 'group' and groups is not None and p['subject_id'].lower() in groups:
            return True
    return False


# --- store ---------------------------------------------------------------------------------

def _out(r):
    x = dict(r)
    for k in ('participants', 'desktops', 'handed'):
        try:
            x[k] = json.loads(x.get(k) or '[]')
        except ValueError:
            x[k] = []
    return x


def get(rid):
    r = db().query_one('SELECT * FROM vlab_reservations WHERE id = ?', (rid,))
    return _out(r) if r else None


def series(series_id):
    if not series_id:
        return []
    return [_out(r) for r in db().query('SELECT * FROM vlab_reservations WHERE series_id = ? ORDER BY start_at', (series_id,))]


def between(t0, t1, statuses=None, lab_id=None, pool_id=None, requester=None):
    """Bookings that overlap [t0, t1) (local 'YYYY-MM-DDTHH:MM' text compares in order)."""
    sql = 'SELECT * FROM vlab_reservations WHERE start_at < ? AND end_at > ?'
    args = [t1, t0]
    if statuses:
        sql += f" AND status IN ({','.join('?' for _ in statuses)})"
        args += list(statuses)
    for col, v in (('lab_id', lab_id), ('pool_id', pool_id), ('requester', requester)):
        if v:
            sql += f' AND {col} = ?'
            args.append(v)
    return [_out(r) for r in db().query(sql + ' ORDER BY start_at', tuple(args))]


def of_user(username, since):
    return [_out(r) for r in db().query('SELECT * FROM vlab_reservations WHERE requester = ? AND end_at > ? ORDER BY start_at',
                                        (username, since))]


def pending(limit=500):
    return [_out(r) for r in db().query("SELECT * FROM vlab_reservations WHERE status = 'pending' ORDER BY start_at LIMIT ?", (limit,))]


def to_run(at_text):
    """Bookings the minute loop may have to act on: approved ones not finished yet whose time
    came, and cancelled ones that were prepared."""
    return [_out(r) for r in db().query(
        """SELECT * FROM vlab_reservations WHERE finished_at IS NULL AND start_at <= ? AND (
               status = 'approved' OR (status = 'cancelled' AND prepared_at IS NOT NULL))
           ORDER BY start_at""", (at_text,))]


def add(row, occ, series_id=''):
    rid = new_id('rsv')
    t = now()
    db().execute("""INSERT INTO vlab_reservations (id, series_id, kind, lab_id, pool_id, quantity, start_at, end_at, purpose,
                    note, participants, requester, status, prepare_min, after, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                 (rid, series_id, row['kind'], row.get('lab_id'), row['pool_id'], int(row['quantity']), fmt(occ[0]), fmt(occ[1]),
                  row['purpose'], row['note'], json.dumps(row['participants'], ensure_ascii=False), row['requester'],
                  row['status'], int(row['prepare_min']), row['after'], t, t))
    return get(rid)


def update(rid, **fields):
    allowed = ('kind', 'lab_id', 'pool_id', 'quantity', 'start_at', 'end_at', 'purpose', 'note', 'participants', 'status',
               'reason', 'reviewed_by', 'reviewed_at', 'prepare_min', 'after', 'desktops', 'handed', 'prepared_at',
               'finished_at', 'banner_id')
    vals = {}
    for k, v in fields.items():
        if k in allowed:
            vals[k] = json.dumps(v, ensure_ascii=False) if k in ('participants', 'desktops', 'handed') else v
    if vals:
        vals['updated_at'] = now()
        db().execute(f"UPDATE vlab_reservations SET {', '.join(f'{k} = ?' for k in vals)} WHERE id = ?", (*vals.values(), rid))
    return get(rid)


def delete_of_lab(lab_id):
    db().execute("UPDATE vlab_reservations SET status = 'cancelled', reason = 'LAB removed', updated_at = ? "
                 "WHERE lab_id = ? AND status IN ('pending', 'approved') AND prepared_at IS NULL", (now(), lab_id))


def today_range(at=None):
    at = at or datetime.now()
    d0 = datetime(at.year, at.month, at.day)
    return fmt(d0), fmt(d0 + timedelta(days=1))
