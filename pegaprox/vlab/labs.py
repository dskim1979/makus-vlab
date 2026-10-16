# -*- coding: utf-8 -*-
"""
MOAVI Desk LABs: shared rooms of terminals (training rooms, labs, shift offices) and the
weekly schedules that get a pool's desktops ready before a session and clean them after.
docs/vlab-design.md 4 (LAB > 사용 일정).

Tables (created with the other vLAB tables, pegaprox/vlab/store.py):
  vlab_labs           a room: name, place, seats
  vlab_terminals      its PCs / thin clients: MAC, name, state (pending until approved)
  vlab_lab_schedules  room x pool x weekdays x start-end, minutes to prepare before, what to
                      do after (reset = back to the base and off / off / nothing)

Times are the server's local wall clock (the room's timetable), weekdays 0 = Monday.
The pure functions here decide what is due; pegaprox/api/vlab.py lab_tick acts on it.
"""

import re
from datetime import datetime, timedelta

AFTER = ('reset', 'off', 'none')
HHMM = re.compile(r'^([01]\d|2[0-3]):[0-5]\d$')
MAC = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')
FINISH_GRACE = timedelta(minutes=60)   # a finish missed by more than this (engine down) is not done late


def norm_mac(v):
    s = re.sub(r'[^0-9a-fA-F]', '', str(v or '')).lower()
    return ':'.join(s[i:i + 2] for i in range(0, 12, 2)) if len(s) == 12 else None


def _minutes(hhmm):
    h, m = hhmm.split(':')
    return int(h) * 60 + int(m)


def weekdays(s):
    """'0,2,4' -> [0, 2, 4]"""
    out = []
    for x in str(s or '').split(','):
        x = x.strip()
        if x.isdigit() and 0 <= int(x) <= 6 and int(x) not in out:
            out.append(int(x))
    return sorted(out)


def validate(data):
    """(clean dict, error text) for a schedule body (lab and pool are checked by the route)."""
    if not isinstance(data, dict):
        return None, 'A JSON body is required'
    days = data.get('weekdays')
    days = weekdays(','.join(str(d) for d in days)) if isinstance(days, list) else weekdays(days)
    if not days:
        return None, 'Pick at least one weekday'
    start, end = str(data.get('start_time') or ''), str(data.get('end_time') or '')
    if not HHMM.match(start) or not HHMM.match(end):
        return None, 'Times are HH:MM'
    if _minutes(end) <= _minutes(start):
        return None, 'The end must be after the start (same day)'
    try:
        prepare = int(data.get('prepare_min', 10))
    except (TypeError, ValueError):
        return None, 'prepare_min must be a number'
    if not 0 <= prepare <= 180:
        return None, 'prepare_min must be 0-180'
    after = data.get('after', 'reset')
    if after not in AFTER:
        return None, 'after must be one of ' + ', '.join(AFTER)
    return {'weekdays': ','.join(str(d) for d in days), 'start_time': start, 'end_time': end,
            'prepare_min': prepare, 'after': after, 'enabled': 1 if data.get('enabled', True) else 0,
            'title': str(data.get('title') or '')[:80]}, None


def overlaps(a, b):
    """Two schedules of one room that share a weekday and a minute."""
    if not set(weekdays(a['weekdays'])) & set(weekdays(b['weekdays'])):
        return False
    return _minutes(a['start_time']) < _minutes(b['end_time']) and _minutes(b['start_time']) < _minutes(a['end_time'])


def occurrence(s, day):
    """(start, end) datetimes of schedule s on `day` (a date), or None when it does not run then."""
    if day.weekday() not in weekdays(s['weekdays']):
        return None
    base = datetime(day.year, day.month, day.day)
    return base + timedelta(minutes=_minutes(s['start_time'])), base + timedelta(minutes=_minutes(s['end_time']))


def due(s, now):
    """'prepare', 'finish' or None for schedule s at local time `now` (naive datetime).
    Each phase runs once a day: last_prepared / last_finished hold the date it last ran."""
    if not s.get('enabled'):
        return None
    occ = occurrence(s, now.date())
    if not occ:
        return None
    start, end = occ
    today = now.date().isoformat()
    if start - timedelta(minutes=int(s.get('prepare_min') or 0)) <= now < end and s.get('last_prepared') != today:
        return 'prepare'
    if end <= now < end + FINISH_GRACE and s.get('last_finished') != today and s.get('after') != 'none':
        return 'finish'
    return None


def state_at(schedules, now):
    """For one room: the schedule in session now (with its end) and the next one within 7 days."""
    current, upcoming = None, None
    for s in schedules:
        if not s.get('enabled'):
            continue
        occ = occurrence(s, now.date())
        if occ and occ[0] - timedelta(minutes=int(s.get('prepare_min') or 0)) <= now < occ[1]:
            current = {'schedule_id': s['id'], 'pool_id': s['pool_id'], 'title': s.get('title') or '',
                       'start': occ[0].isoformat(timespec='minutes'), 'end': occ[1].isoformat(timespec='minutes'),
                       'preparing': now < occ[0]}
    for i in range(0, 8):
        day = (now + timedelta(days=i)).date()
        for s in sorted(schedules, key=lambda x: x['start_time']):
            if not s.get('enabled'):
                continue
            occ = occurrence(s, day)
            if occ and occ[0] > now and (upcoming is None or occ[0] < datetime.fromisoformat(upcoming['start'])):
                upcoming = {'schedule_id': s['id'], 'pool_id': s['pool_id'], 'title': s.get('title') or '',
                            'start': occ[0].isoformat(timespec='minutes'), 'end': occ[1].isoformat(timespec='minutes')}
        if upcoming:
            break
    return current, upcoming
