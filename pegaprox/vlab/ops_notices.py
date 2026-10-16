"""MOAVI Desk: notices for the administrators about running the service (경보 > 운영 알림).

They go where the other MOAVI Desk alerts go (pegaprox/api/vlab_next.py _alert): the webhook
channels (every one, or the ids chosen here) and the alert mail recipients.

  terminal_pending  lab PCs wait for approval: at most once per `terminal_every_min`, and a
                    warning when the count reaches the install settings' pending_warn
  license_denied    a licence server refused checkouts (the DENIED lines of its debug log)
  pair              a MOAVI Desk standby stopped answering or answers again; this server
                    became the active one (a promotion or a failover)
  task_failed       a long Proxmox task ended in an error: clone, backup, restore, move, ...
                    (not in a cluster with its own enabled 작업 실패 alert rule - that one tells)

The settings and what was already told (the state) are server settings, so a standby that
takes over carries on from them. The pure parts are here; the routes and the checks of the
minute loop are in pegaprox/api/vlab_ops_notices.py.
"""
from datetime import datetime, timedelta, timezone

from pegaprox.core.db import get_db

KEY = 'vlab_ops_notices'
STATE_KEY = 'vlab_ops_notice_state'

# Proxmox task types worth a notice, with what the notice calls them
TASK_TYPES = {
    'qmclone': '복제', 'vzdump': '백업', 'qmrestore': '복원', 'qmigrate': '이동',
    'qmcreate': 'VM 만들기', 'qmtemplate': '템플릿 변환', 'qmmove': '디스크 이동', 'qmdestroy': 'VM 삭제',
}

DEFAULTS = {
    'terminal_pending': True,
    'terminal_every_min': 30,
    'license_denied': True,
    'pair': True,
    'pair_down_min': 10,
    'task_failed': True,
    'task_types': ['qmclone', 'vzdump', 'qmrestore', 'qmigrate'],
    'channels': [],            # webhook channel ids; empty = every channel
}
_LIMITS = {'terminal_every_min': (5, 24 * 60), 'pair_down_min': (2, 24 * 60)}
_BOOLS = ('terminal_pending', 'license_denied', 'pair', 'task_failed')


def _db():
    return get_db()


def get_settings():
    raw = _db().get_server_setting(KEY, None)
    out = dict(DEFAULTS)
    if isinstance(raw, dict):
        for k in DEFAULTS:
            if k in raw:
                out[k] = raw[k]
    return out


def validate(data):
    """The settings from a PUT body (only the keys it has), or ValueError."""
    if not isinstance(data, dict):
        raise ValueError('A JSON object is required')
    out = {}
    for k, v in data.items():
        if k in _BOOLS:
            if not isinstance(v, bool):
                raise ValueError(f'{k}: true or false')
            out[k] = v
        elif k in _LIMITS:
            lo, hi = _LIMITS[k]
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                raise ValueError(f'{k}: a whole number from {lo} to {hi}')
            out[k] = v
        elif k == 'task_types':
            if not isinstance(v, list) or any(t not in TASK_TYPES for t in v):
                raise ValueError('task_types: a list of ' + ', '.join(TASK_TYPES))
            out[k] = sorted(set(v))
        elif k == 'channels':
            if not isinstance(v, list) or any(not isinstance(c, str) or not c or len(c) > 80 for c in v):
                raise ValueError('channels: a list of webhook channel ids')
            out[k] = list(dict.fromkeys(v))
        else:
            raise ValueError(f'Unknown setting: {k}')
    return out


def save_settings(data):
    s = get_settings()
    s.update(validate(data))
    _db().save_server_setting(KEY, s)
    return s


def state():
    raw = _db().get_server_setting(STATE_KEY, None)
    return dict(raw) if isinstance(raw, dict) else {}


def save_state(st):
    try:
        _db().save_server_setting(STATE_KEY, st)
    except Exception:       # a standby refuses writes; the active keeps the state
        pass


def _parse(iso):
    try:
        d = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0)


# --- lab PCs waiting -----------------------------------------------------------------------

def terminal_due(st, pending, warn_at, every_min, at=None):
    """(what to tell | None, new state) for `pending` PCs waiting. 'warn' once when the count
    reaches warn_at (again only after it went under), 'waiting' at most every `every_min`."""
    at = at or utcnow()
    st = dict(st)
    if pending <= 0:
        st.pop('terminal_warned', None)
        return None, st
    if pending >= warn_at and not st.get('terminal_warned'):
        st['terminal_warned'] = True
        st['terminal_last'] = at.isoformat()
        return 'warn', st
    if pending < warn_at:
        st.pop('terminal_warned', None)
    last = _parse(st.get('terminal_last'))
    if last and at - last < timedelta(minutes=every_min):
        return None, st
    st['terminal_last'] = at.isoformat()
    return 'waiting', st


# --- the server pair -----------------------------------------------------------------------

def pair_events(st, members, down_min, at=None):
    """(events, new state) from the standbys as the active knows them: a member whose last
    answer is older than `down_min` (or never answered since it joined that long ago) is
    'down', told once; 'up' when it answers again. A member that left the group is forgotten."""
    at = at or utcnow()
    st = dict(st)
    seen = dict(st.get('pair') or {})
    events = []
    ids = set()
    for m in members:
        mid = m.get('instance_id')
        if not mid:
            continue
        ids.add(mid)
        last = _parse(m.get('last_contact')) or _parse(m.get('joined_at'))
        down = last is None or at - last > timedelta(minutes=down_min)
        was = seen.get(mid)
        if down and was != 'down':
            seen[mid] = 'down'
            events.append({'event': 'down', 'member': m, 'since': last.isoformat() if last else None})
        elif not down and was == 'down':
            seen[mid] = 'up'
            events.append({'event': 'up', 'member': m})
        elif not down and was is None:
            seen[mid] = 'up'
    for mid in list(seen):
        if mid not in ids:
            seen.pop(mid)
    st['pair'] = seen
    return events, st


def promoted(st, role, epoch):
    """(True when this active took over since the last look, new state). The epoch goes up
    at every promotion; the first look only notes it."""
    st = dict(st)
    known = st.get('epoch')
    st['epoch'] = epoch
    if role != 'active' or known is None:
        return False, st
    return int(epoch) > int(known), st


# --- failed tasks --------------------------------------------------------------------------

def failed_tasks(rows, cursor, types):
    """(failed rows to tell, new cursor) from a cluster's task rows (vlab_next._task_row):
    the ones that ended after the cursor (an end time), not OK, of a watched type. Without a
    cursor (the first look) nothing is told, only the cursor set - no flood of old failures."""
    ended = [r for r in rows if not r.get('running') and r.get('endtime')]
    newest = max([int(r['endtime']) for r in ended] + [int(cursor or 0)])
    if cursor is None:
        return [], newest
    out = [r for r in ended if int(r['endtime']) > int(cursor) and not r.get('ok') and r.get('type') in types]
    out.sort(key=lambda r: r['endtime'])
    return out, newest
