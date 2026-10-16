# -*- coding: utf-8 -*-
"""
MOAVI Desk work protection and accelerator use (연구실용 보호 · 측정).

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

Three things a research lab needs from the desktops it trains and synthesises on:

  * a long job is not killed by a clean-up. The idle shutdown, the session limit, the end of a
    LAB class or booking and a scheduled VM action ask first whether the desktop is working:
    a GPU or CPU busy past the pool's thresholds (read through the guest agent), a running
    build job on it, or the user's own "작업 중 - 끄지 마세요" with an end time. A working
    desktop is left alone and the step is put off (vlab_deferrals) up to the pool's longest
    extension; the user and the admins hear of it.
  * what a card is really used for: every 5 minutes the running desktops that hold a card
    (a loan, or the pool's GPU) report GPU / NPU use and memory through the guest agent
    (nvidia-smi, rocm-smi, furiosa-smi, rbln-stat - whatever is installed; none = 'unavailable').
    Kept 90 days in vlab_accel_samples (instance-local, like the metrics history).
  * a loaned card that sits idle: under X % for N hours -> the user is told and the admins see a
    reclaim suggestion (vlab_card_reclaims); optionally given back M hours later.

Tables are made on first use like store.py's. The pure functions here parse what the guest
printed and judge busy / idle; pegaprox/api/vlab_work.py has the routes and the ticks.
"""

import json
import re
import threading
from datetime import datetime, timedelta, timezone

from pegaprox.vlab.store import db as _store_db, new_id, now

SETTINGS_KEY = 'vlab_work'
SETTINGS_DEFAULTS = {
    'sample_minutes': 5,        # how often the card desktops are read
    'retention_days': 90,       # how long the samples are kept
    'hold_max_hours': 72,       # the longest "작업 중" a user may set at once
    'reclaim': {
        'enabled': True,        # tell the user and suggest a reclaim to the admins
        'idle_hours': 24,       # N: this long ...
        'threshold_pct': 5,     # X: ... under this use
        'auto_return': False,   # give the card back by itself
        'auto_return_hours': 12,   # M: this long after the suggestion
    },
}
_SETTING_LIMITS = {'sample_minutes': (1, 60), 'retention_days': (7, 400), 'hold_max_hours': (1, 720)}
_RECLAIM_LIMITS = {'idle_hours': (1, 720), 'threshold_pct': (0, 100), 'auto_return_hours': (1, 720)}

ACTIONS = ('shutdown', 'stop', 'reboot', 'reset', 'expire')
SOURCES = ('idle', 'session_limit', 'lab', 'booking', 'schedule')
ONE_SHOT = ('lab', 'booking', 'schedule')   # the step does not come again: the deferral runs it later
RECHECK_SECONDS = 300                        # a working desktop is asked again at most this often
VENDORS = ('nvidia', 'amd', 'furiosa', 'rebellions')

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_work_holds (
        id TEXT PRIMARY KEY,
        desktop_id TEXT NOT NULL,
        username TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        until TEXT NOT NULL,
        created_at TEXT NOT NULL,
        cleared_at TEXT,
        cleared_by TEXT NOT NULL DEFAULT ''
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_work_holds_desk ON vlab_work_holds(desktop_id, until)',
    '''CREATE TABLE IF NOT EXISTS vlab_deferrals (
        id TEXT PRIMARY KEY,
        desktop_id TEXT NOT NULL,
        action TEXT NOT NULL,
        source TEXT NOT NULL,
        source_id TEXT NOT NULL DEFAULT '',
        username TEXT NOT NULL DEFAULT '',
        reason TEXT NOT NULL DEFAULT '{}',
        first_at TEXT NOT NULL,
        checked_at TEXT NOT NULL,
        deadline TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'waiting',
        ended_at TEXT,
        result TEXT NOT NULL DEFAULT ''
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_deferrals_state ON vlab_deferrals(state, desktop_id)',
    '''CREATE TABLE IF NOT EXISTS vlab_accel_samples (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        at TEXT NOT NULL,
        minutes INTEGER NOT NULL DEFAULT 5,
        cluster_id TEXT NOT NULL,
        vmid INTEGER NOT NULL,
        desktop_id TEXT NOT NULL DEFAULT '',
        username TEXT NOT NULL DEFAULT '',
        lease_id TEXT NOT NULL DEFAULT '',
        card TEXT NOT NULL DEFAULT '',
        vendor TEXT NOT NULL DEFAULT '',
        idx INTEGER NOT NULL DEFAULT 0,
        name TEXT NOT NULL DEFAULT '',
        util REAL,
        mem_used_mb REAL,
        mem_total_mb REAL,
        status TEXT NOT NULL DEFAULT 'ok'
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_accel_samples_at ON vlab_accel_samples(at)',
    'CREATE INDEX IF NOT EXISTS idx_vlab_accel_samples_lease ON vlab_accel_samples(lease_id, at)',
    'CREATE INDEX IF NOT EXISTS idx_vlab_accel_samples_desk ON vlab_accel_samples(desktop_id, at)',
    '''CREATE TABLE IF NOT EXISTS vlab_card_reclaims (
        lease_id TEXT PRIMARY KEY,
        state TEXT NOT NULL DEFAULT 'suggested',
        idle_since TEXT NOT NULL,
        suggested_at TEXT NOT NULL,
        dismissed_by TEXT NOT NULL DEFAULT '',
        dismissed_at TEXT,
        returned_at TEXT,
        avg_util REAL
    )''',
)

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_workload', False):
        with _lock:
            if not getattr(d, '_vlab_workload', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_workload = True
    return d


def ts(iso):
    """store.now() text (or any ISO) -> aware UTC datetime, None when unreadable"""
    try:
        t = datetime.fromisoformat(str(iso).replace('Z', '+00:00'))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def iso(t):
    return t.astimezone(timezone.utc).isoformat(timespec='seconds')


def utcnow():
    return datetime.now(timezone.utc)


# --- settings ------------------------------------------------------------------------------

def effective_settings(saved):
    out = json.loads(json.dumps(SETTINGS_DEFAULTS))
    if isinstance(saved, dict):
        out.update({k: v for k, v in saved.items() if k in SETTINGS_DEFAULTS and k != 'reclaim'})
        if isinstance(saved.get('reclaim'), dict):
            out['reclaim'].update({k: v for k, v in saved['reclaim'].items() if k in SETTINGS_DEFAULTS['reclaim']})
    return out


def _whole(v, lo, hi):
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def validate_settings(data):
    """(settings, None) or (None, error text). Missing keys keep what they were."""
    if not isinstance(data, dict):
        return None, 'JSON object required'
    unknown = sorted(set(data) - set(SETTINGS_DEFAULTS))
    if unknown:
        return None, f"unknown fields: {', '.join(unknown)}"
    out = {}
    for k, (lo, hi) in _SETTING_LIMITS.items():
        if k in data:
            if not _whole(data[k], lo, hi):
                return None, f'{k} must be a whole number from {lo} to {hi}'
            out[k] = data[k]
    if 'reclaim' in data:
        r = data['reclaim']
        if not isinstance(r, dict):
            return None, 'reclaim must be an object'
        bad = sorted(set(r) - set(SETTINGS_DEFAULTS['reclaim']))
        if bad:
            return None, f"unknown reclaim fields: {', '.join(bad)}"
        rec = {}
        for k in ('enabled', 'auto_return'):
            if k in r:
                if not isinstance(r[k], bool):
                    return None, f'reclaim.{k} must be true or false'
                rec[k] = r[k]
        for k, (lo, hi) in _RECLAIM_LIMITS.items():
            if k in r:
                if not _whole(r[k], lo, hi):
                    return None, f'reclaim.{k} must be a whole number from {lo} to {hi}'
                rec[k] = r[k]
        out['reclaim'] = rec
    return out, None


def merge_settings(saved, change):
    cur = effective_settings(saved)
    for k, v in change.items():
        if k == 'reclaim':
            cur['reclaim'].update(v)
        else:
            cur[k] = v
    return cur


# --- what the guest prints ---------------------------------------------------------------
# One script per OS, each tool's output under a '##<vendor>' line (only when the tool is
# there), the CPU under '##cpu'. The parsers below are forgiving: a tool that is installed
# but prints nothing they understand counts as 'unavailable', never as idle.

LINUX_PROBE = r'''
if command -v nvidia-smi >/dev/null 2>&1; then echo '##nvidia'; nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits 2>/dev/null; fi
if command -v rocm-smi >/dev/null 2>&1; then echo '##amd'; rocm-smi --showuse --showmeminfo vram --showproductname --json 2>/dev/null; fi
if command -v furiosa-smi >/dev/null 2>&1; then echo '##furiosa'; furiosa-smi status --format json 2>/dev/null || furiosa-smi status 2>/dev/null; fi
if command -v rbln-stat >/dev/null 2>&1; then echo '##rebellions'; rbln-stat -j 2>/dev/null || rbln-stat 2>/dev/null; fi
echo '##cpu'; nproc 2>/dev/null; cat /proc/loadavg 2>/dev/null
'''

WINDOWS_PROBE = r'''
$ErrorActionPreference = 'SilentlyContinue'
if (Get-Command nvidia-smi) { '##nvidia'; nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total --format=csv,noheader,nounits }
'##wincpu'; (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
'''


def probe_command(os_kind):
    if os_kind == 'windows':
        return ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', WINDOWS_PROBE]
    return ['/bin/sh', '-c', LINUX_PROBE]


def _num(v):
    try:
        f = float(str(v).strip().rstrip('%').strip())
    except (TypeError, ValueError):
        return None
    return f if f == f else None   # NaN


_UNITS = {'b': 1 / 1048576, 'kb': 1 / 1024, 'kib': 1 / 1024, 'mb': 1, 'mib': 1, 'gb': 1024, 'gib': 1024,
          'tb': 1048576, 'tib': 1048576}


def _mb(value, unit='mb'):
    n = _num(value)
    if n is None:
        return None
    return round(n * _UNITS.get(str(unit).lower(), 1), 1)


def _card(vendor, idx, name='', util=None, used=None, total=None):
    ok = util is not None
    return {'vendor': vendor, 'idx': int(idx), 'name': str(name or '')[:80],
            'util': round(max(0.0, min(100.0, util)), 1) if ok else None,
            'mem_used_mb': used, 'mem_total_mb': total, 'status': 'ok' if ok else 'unavailable'}


def _parse_nvidia(lines):
    out = []
    for ln in lines:
        parts = [p.strip() for p in ln.split(',')]
        if len(parts) < 5 or not parts[0].isdigit():
            continue
        out.append(_card('nvidia', parts[0], parts[1], _num(parts[2]), _mb(parts[3]), _mb(parts[4])))
    return out


def _parse_amd(text):
    try:
        data = json.loads(text[text.index('{'):])
    except (ValueError, TypeError):
        return []
    out = []
    for key in sorted(k for k in data if str(k).lower().startswith('card')):
        c = data[key] if isinstance(data[key], dict) else {}
        util = next((_num(v) for k, v in c.items() if 'gpu use' in k.lower()), None)
        total = next((_mb(v, 'b') for k, v in c.items() if k.lower().startswith('vram total memory')), None)
        used = next((_mb(v, 'b') for k, v in c.items() if k.lower().startswith('vram total used memory')), None)
        name = next((v for k, v in c.items() if k.lower() in ('card series', 'card model', 'device name', 'card sku')), '')
        idx = re.sub(r'\D', '', str(key)) or len(out)
        out.append(_card('amd', idx, name, util, used, total))
    return out


_MEM_PAIR = re.compile(r'([\d.]+)\s*([KMGT]i?B|B)\s*/\s*([\d.]+)\s*([KMGT]i?B|B)', re.I)
_PCT = re.compile(r'(\d+(?:\.\d+)?)\s*%')


def _walk_devices(data):
    """dicts in a JSON tree that carry a use figure"""
    if isinstance(data, dict):
        if any('util' in str(k).lower() for k in data):
            yield data
        for v in data.values():
            yield from _walk_devices(v)
    elif isinstance(data, list):
        for v in data:
            yield from _walk_devices(v)


def _mem_of(dev, which):
    for k, v in dev.items():
        kl = str(k).lower()
        if 'mem' in kl and which in kl:
            if isinstance(v, (int, float)):
                return _mb(v, 'b' if v > 1 << 24 else 'mb')
            m = re.match(r'\s*([\d.]+)\s*([KMGT]i?B|B)?', str(v), re.I)
            if m:
                return _mb(m.group(1), m.group(2) or 'mb')
        if 'mem' in kl and isinstance(v, dict):
            got = _mem_of({f'mem_{kk}': vv for kk, vv in v.items()}, which)
            if got is not None:
                return got
    return None


def _parse_npu(vendor, text):
    """furiosa-smi / rbln-stat: JSON when the tool has it, else the table it prints."""
    text = text.strip()
    if text[:1] in '{[':
        try:
            data = json.loads(text)
        except ValueError:
            data = None
        if data is not None:
            out = []
            for i, dev in enumerate(_walk_devices(data)):
                util = next((_num(v) for k, v in dev.items() if 'util' in str(k).lower() and _num(v) is not None), None)
                name = next((v for k, v in dev.items() if str(k).lower() in ('name', 'arch', 'device', 'npu', 'model')
                             and isinstance(v, str)), '')
                out.append(_card(vendor, i, name, util, _mem_of(dev, 'used'), _mem_of(dev, 'total')))
            return out
    out = []
    for ln in text.splitlines():
        mem = _MEM_PAIR.search(ln)
        pct = _PCT.findall(ln)
        if not mem or not pct:
            continue
        name = next((w for w in re.split(r'[|\s]+', ln) if re.match(r'^(RBLN|RNGD|WARBOY|ATOM|REBEL)', w, re.I)), '')
        out.append(_card(vendor, len(out), name, _num(pct[-1]), _mb(mem.group(1), mem.group(2)), _mb(mem.group(3), mem.group(4))))
    return out


def parse_probe(text):
    """{'cards': [...], 'cpu_pct': float|None, 'tools': [vendor, ...]}. A vendor whose tool is
    there but printed nothing readable gets one 'unavailable' entry."""
    sections, cur = {}, None
    for ln in str(text or '').splitlines():
        s = ln.strip()
        if s.startswith('##'):
            cur = s[2:].strip()
            sections.setdefault(cur, [])
        elif cur is not None and s:
            sections[cur].append(s)
    cards, tools = [], []
    for vendor in VENDORS:
        if vendor not in sections:
            continue
        tools.append(vendor)
        lines = sections[vendor]
        got = (_parse_nvidia(lines) if vendor == 'nvidia' else _parse_amd('\n'.join(lines)) if vendor == 'amd'
               else _parse_npu(vendor, '\n'.join(lines)))
        cards += got or [_card(vendor, 0)]
    cpu = None
    if sections.get('cpu'):
        try:
            ncpu = int(sections['cpu'][0])
            load = float(sections['cpu'][1].split()[0])
            cpu = round(min(100.0, 100.0 * load / max(1, ncpu)), 1)
        except (IndexError, ValueError):
            cpu = None
    elif sections.get('wincpu'):
        cpu = _num(sections['wincpu'][0])
    return {'cards': cards, 'cpu_pct': cpu, 'tools': tools}


def busy_from_probe(probe, pol):
    """What makes the desktop count as working by the pool's thresholds, or None."""
    if not probe:
        return None
    utils = [c['util'] for c in probe.get('cards') or [] if c.get('util') is not None]
    gpu_at = pol.get('busy_gpu_pct', 10)
    if utils and max(utils) >= gpu_at:
        return {'kind': 'gpu', 'value': max(utils), 'threshold': gpu_at}
    cpu_at = pol.get('busy_cpu_pct', 0)
    cpu = probe.get('cpu_pct')
    if cpu_at and cpu is not None and cpu >= cpu_at:
        return {'kind': 'cpu', 'value': cpu, 'threshold': cpu_at}
    return None


# --- "작업 중 - 끄지 마세요" ------------------------------------------------------------------

def _hold_row(r):
    return dict(r) if r else None


def active_hold(desktop_id, at_iso=None):
    r = db().query_one('''SELECT * FROM vlab_work_holds WHERE desktop_id = ? AND cleared_at IS NULL AND until > ?
                          ORDER BY until DESC LIMIT 1''', (desktop_id, at_iso or now()))
    return _hold_row(r)


def holds(active_only=True, username=None):
    sql, args = 'SELECT * FROM vlab_work_holds WHERE 1 = 1', []
    if active_only:
        sql += ' AND cleared_at IS NULL AND until > ?'
        args.append(now())
    if username:
        sql += ' AND username = ?'
        args.append(username)
    return [dict(r) for r in db().query(sql + ' ORDER BY created_at DESC LIMIT 500', tuple(args))]


def get_hold(hold_id):
    return _hold_row(db().query_one('SELECT * FROM vlab_work_holds WHERE id = ?', (hold_id,)))


def set_hold(desktop_id, username, until_iso, note=''):
    """One hold per desktop: a new one replaces the one before."""
    clear_holds(desktop_id, username)
    hid = new_id('hold')
    db().execute('''INSERT INTO vlab_work_holds (id, desktop_id, username, note, until, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)''', (hid, desktop_id, username, note[:200], until_iso, now()))
    return get_hold(hid)


def clear_holds(desktop_id, by):
    db().execute('''UPDATE vlab_work_holds SET cleared_at = ?, cleared_by = ?
                    WHERE desktop_id = ? AND cleared_at IS NULL''', (now(), by, desktop_id))


# --- deferrals ---------------------------------------------------------------------------

def _deferral_row(r):
    if not r:
        return None
    d = dict(r)
    try:
        d['reason'] = json.loads(d.get('reason') or '{}')
    except ValueError:
        d['reason'] = {}
    return d


def waiting(desktop_id, action, source, source_id=''):
    r = db().query_one('''SELECT * FROM vlab_deferrals WHERE desktop_id = ? AND action = ? AND source = ?
                          AND source_id = ? AND state = 'waiting' ORDER BY first_at DESC LIMIT 1''',
                       (desktop_id, action, source, source_id or ''))
    return _deferral_row(r)


def get_deferral(did):
    return _deferral_row(db().query_one('SELECT * FROM vlab_deferrals WHERE id = ?', (did,)))


def deferrals(state=None, desktop_ids=None, limit=300):
    sql, args = 'SELECT * FROM vlab_deferrals WHERE 1 = 1', []
    if state:
        sql += ' AND state = ?'
        args.append(state)
    rows = [_deferral_row(r) for r in db().query(sql + ' ORDER BY first_at DESC LIMIT ?', tuple(args + [int(limit)]))]
    if desktop_ids is not None:
        rows = [r for r in rows if r['desktop_id'] in desktop_ids]
    return rows


def add_deferral(desktop_id, action, source, source_id, username, reason, at, deadline):
    did = new_id('defer')
    db().execute('''INSERT INTO vlab_deferrals (id, desktop_id, action, source, source_id, username, reason, first_at,
                    checked_at, deadline, state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'waiting')''',
                 (did, desktop_id, action, source, source_id or '', username or '', json.dumps(reason, ensure_ascii=False),
                  iso(at), iso(at), iso(deadline)))
    return get_deferral(did)


def recheck(did, reason, at):
    db().execute('UPDATE vlab_deferrals SET checked_at = ?, reason = ? WHERE id = ?',
                 (iso(at), json.dumps(reason, ensure_ascii=False), did))


def finish(did, state, result=''):
    db().execute("UPDATE vlab_deferrals SET state = ?, ended_at = ?, result = ? WHERE id = ? AND state = 'waiting'",
                 (state, now(), str(result)[:300], did))


def release(did):
    """An admin lets the step run now: the deadline moves to now."""
    db().execute("UPDATE vlab_deferrals SET deadline = ? WHERE id = ? AND state = 'waiting'", (now(), did))


def drop_waiting(desktop_id, sources, result):
    rows = [d for d in deferrals('waiting', {desktop_id}) if d['source'] in sources]
    for d in rows:
        finish(d['id'], 'dropped', result)
    return rows


def stale_waiting(older_than):
    """repeating sources (idle, session limit) nobody asked about for a while: the step is not due
    any more (the user came back, the VM stopped)"""
    return [d for d in deferrals('waiting') if d['source'] not in ONE_SHOT and ts(d['checked_at']) < older_than]


# --- accelerator samples ----------------------------------------------------------------

_SAMPLE_COLS = ('at', 'minutes', 'cluster_id', 'vmid', 'desktop_id', 'username', 'lease_id', 'card', 'vendor', 'idx',
                'name', 'util', 'mem_used_mb', 'mem_total_mb', 'status')


def add_samples(rows):
    for r in rows:
        db().execute(f"INSERT INTO vlab_accel_samples ({', '.join(_SAMPLE_COLS)}) VALUES ({', '.join('?' * len(_SAMPLE_COLS))})",
                     tuple(r.get(c) for c in _SAMPLE_COLS))


def prune_samples(before_iso):
    db().execute('DELETE FROM vlab_accel_samples WHERE at < ?', (before_iso,))


def samples(since_iso, lease_id=None, desktop_id=None, until_iso=None):
    sql, args = 'SELECT * FROM vlab_accel_samples WHERE at >= ?', [since_iso]
    if until_iso:
        sql += ' AND at <= ?'
        args.append(until_iso)
    if lease_id:
        sql += ' AND lease_id = ?'
        args.append(lease_id)
    if desktop_id:
        sql += ' AND desktop_id = ?'
        args.append(desktop_id)
    return [dict(r) for r in db().query(sql + ' ORDER BY at, idx', tuple(args))]


def latest_per_desktop(since_iso):
    """{desktop_id: [rows of its latest sample time]}"""
    rows = db().query('''SELECT s.* FROM vlab_accel_samples s JOIN (SELECT desktop_id, MAX(at) AS at FROM vlab_accel_samples
                         WHERE at >= ? GROUP BY desktop_id) m ON s.desktop_id = m.desktop_id AND s.at = m.at
                         ORDER BY s.idx''', (since_iso,))
    out = {}
    for r in rows:
        out.setdefault(r['desktop_id'], []).append(dict(r))
    return out


def by_time(rows):
    """sample rows -> [(at, minutes, util or None, status)] one per sample time: the busiest card
    counts (a guest with two cards is in use when either is)."""
    out = {}
    for r in rows:
        cur = out.get(r['at'])
        util = r['util'] if r['status'] == 'ok' else (0.0 if r['status'] == 'off' else None)
        if cur is None:
            out[r['at']] = [r['minutes'] or 5, util, r['status']]
        elif util is not None and (cur[1] is None or util > cur[1]):
            cur[1], cur[2] = util, r['status']
    return [(at, m, u, s) for at, (m, u, s) in sorted(out.items())]


def summarize(rows, threshold):
    """{measured_hours, idle_hours, off_hours, util_avg, util_max, unmeasured_hours} of sample rows"""
    measured = idle = off = unmeasured = 0.0
    total = peak = 0.0
    n = 0
    for _at, minutes, util, status in by_time(rows):
        h = minutes / 60.0
        if status == 'off':
            off += h
            idle += h
        elif util is None:
            unmeasured += h
        else:
            measured += h
            total += util
            n += 1
            peak = max(peak, util)
            if util < threshold:
                idle += h
    return {'measured_hours': round(measured, 1), 'idle_hours': round(idle, 1), 'off_hours': round(off, 1),
            'unmeasured_hours': round(unmeasured, 1), 'util_avg': round(total / n, 1) if n else None,
            'util_max': round(peak, 1) if n else None}


def idle_verdict(rows, threshold, window_hours, sample_minutes):
    """'active' (some sample at or over the threshold), 'unknown' (not enough samples, or the
    use could not be read), or 'idle' (every sample under it, or the VM off)."""
    points = by_time(rows)
    if any(u is not None and u >= threshold for _a, _m, u, _s in points):
        return 'active'
    if any(u is None for _a, _m, u, _s in points):
        return 'unknown'
    expected = window_hours * 60.0 / max(1, sample_minutes)
    if len(points) < 0.8 * expected:
        return 'unknown'
    return 'idle'


# --- reclaim suggestions -------------------------------------------------------------------

def reclaim(lease_id):
    r = db().query_one('SELECT * FROM vlab_card_reclaims WHERE lease_id = ?', (lease_id,))
    return dict(r) if r else None


def reclaims(states=None):
    rows = [dict(r) for r in db().query('SELECT * FROM vlab_card_reclaims ORDER BY suggested_at DESC')]
    return [r for r in rows if not states or r['state'] in states]


def suggest_reclaim(lease_id, idle_since, avg_util):
    db().execute('''INSERT INTO vlab_card_reclaims (lease_id, state, idle_since, suggested_at, avg_util)
                    VALUES (?, 'suggested', ?, ?, ?)''', (lease_id, idle_since, now(), avg_util))
    return reclaim(lease_id)


def set_reclaim(lease_id, **fields):
    allowed = {'state', 'dismissed_by', 'dismissed_at', 'returned_at', 'avg_util'}
    sets = {k: v for k, v in fields.items() if k in allowed}
    if sets:
        db().execute(f"UPDATE vlab_card_reclaims SET {', '.join(f'{k} = ?' for k in sets)} WHERE lease_id = ?",
                     tuple(sets.values()) + (lease_id,))


def forget_reclaim(lease_id):
    db().execute('DELETE FROM vlab_card_reclaims WHERE lease_id = ?', (lease_id,))


def window_start(at, hours):
    return iso(at - timedelta(hours=hours))
