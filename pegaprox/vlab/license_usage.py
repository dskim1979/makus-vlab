# -*- coding: utf-8 -*-
"""
MOAVI Desk - licence seats (라이선스 사용량): who holds the seats of a FlexLM / FlexNet
licence server (Vivado/Vitis, Quartus, Synopsys, Cadence, ...), every 5 minutes.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

How the numbers come in, per licence server (vlab_license_servers.usage_mode):

  off      nothing but the port check (the default)
  engine   the engine runs `lmutil lmstat -a -c <port>@<host>` itself. lmutil is Flexera's and
           comes with every vendor's tools (Vivado bin/unwrapped/lnx64.o/lmutil, Quartus
           linux64/lmutil, the Synopsys SCL and Cadence licence kits); it is NOT shipped in the
           engine image - its licence lets a vendor's customers use it, not a third party hand
           it on. Mount or copy it to /opt/moavi/lmutil/lmutil (or name the path per server, or
           MOAVI_LMUTIL). Most Linux builds load through the LSB loader name: the image links
           /lib64/ld-lsb-x86-64.so.3 to the normal loader.
  agent    the licence server's own VM runs lmstat through the QEMU guest agent (cluster_id +
           vmid of the server). Nothing to install on the engine; lmutil is on that VM anyway.
           With a debug log path (lmgrd -l <file>) the same agent reads its last lines and
           the DENIED / UNSUPPORTED lines are counted (who was refused which feature, when).

What is kept (this module's tables, per instance - ha.LOCAL_TABLES; the active collects and
a standby forwards the reads to it), 90 days:

  vlab_license_samples     one row per feature and check: total, in use, queued
  vlab_license_checkouts   one row per seat held: user, host, display, since (lmstat's start),
                           first and last check it was seen in - the time a user held a seat
  vlab_license_denials     one row per refused checkout from the debug log

The parsers here are pure (tested with lmstat samples in tests/test_vlab_license.py); the routes,
the guest agent call and the alerts are in pegaprox/api/vlab_license.py.
"""

import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timedelta

from pegaprox.vlab.store import db as _store_db

KEEP_DAYS = 90
INTERVAL = 300                    # seconds between two checks (license_tick)
LMUTIL_PATHS = ('/opt/moavi/lmutil/lmutil', '/opt/moavi/lmutil/lmstat', '/usr/local/bin/lmutil', '/usr/bin/lmutil')
LMUTIL_TIMEOUT = 30
MODES = ('off', 'engine', 'agent')

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_license_samples (
        server_id TEXT NOT NULL,
        at INTEGER NOT NULL,
        feature TEXT NOT NULL,
        vendor TEXT NOT NULL DEFAULT '',
        total INTEGER NOT NULL DEFAULT 0,
        in_use INTEGER NOT NULL DEFAULT 0,
        queued INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (server_id, at, feature)
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_license_samples_at ON vlab_license_samples(at)',
    '''CREATE TABLE IF NOT EXISTS vlab_license_checkouts (
        server_id TEXT NOT NULL,
        feature TEXT NOT NULL,
        username TEXT NOT NULL,
        host TEXT NOT NULL DEFAULT '',
        display TEXT NOT NULL DEFAULT '',
        started INTEGER NOT NULL,
        vendor TEXT NOT NULL DEFAULT '',
        version TEXT NOT NULL DEFAULT '',
        count INTEGER NOT NULL DEFAULT 1,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        PRIMARY KEY (server_id, feature, username, host, display, started)
    )''',
    'CREATE INDEX IF NOT EXISTS idx_vlab_license_checkouts_seen ON vlab_license_checkouts(server_id, last_seen)',
    '''CREATE TABLE IF NOT EXISTS vlab_license_denials (
        server_id TEXT NOT NULL,
        at INTEGER NOT NULL,
        feature TEXT NOT NULL,
        username TEXT NOT NULL DEFAULT '',
        host TEXT NOT NULL DEFAULT '',
        vendor TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL DEFAULT 'denied',
        reason TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (server_id, at, feature, username, host)
    )''',
)
TABLES = ('vlab_license_samples', 'vlab_license_checkouts', 'vlab_license_denials')

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_license_usage', False):
        with _lock:
            if not getattr(d, '_vlab_license_usage', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_license_usage = True
    return d


# --- lmstat -a ---------------------------------------------------------------------------

_USERS_OF = re.compile(r'^Users of (?P<feature>[^:]+):\s*\((?P<rest>.*)\)\s*$')
_TOTALS = re.compile(r'Total of (\d+) licenses? issued;\s*Total of (\d+) licenses? in use', re.I)
_FEATURE_LINE = re.compile(r'^\s+"(?P<feature>[^"]+)"\s+v(?P<version>[^,\s]+),\s*vendor:\s*(?P<vendor>[^,\s]+)')
_DAEMON = re.compile(r'^\s+(?P<vendor>[A-Za-z0-9_.-]+): (?P<state>UP|DOWN|The desired vendor daemon is down)\b')
_SERVER = re.compile(r'^\s+(?P<host>\S+): license server (?P<state>UP|DOWN)', re.I)
_USER = re.compile(r'^\s{2,}(?P<user>\S+) (?P<host>\S+) (?P<display>\S+)\s+'
                   r'(?:\((?P<version>v[^)]*)\)\s+)?\((?P<handle>[^)]*)\)'
                   r'(?:\s+queued for (?P<queued>\d+) licenses?)?'
                   r'(?:,\s*start (?P<start>\w{3} \d{1,2}/\d{1,2} \d{1,2}:\d{2}))?'
                   r'(?:,\s*(?P<count>\d+) licenses?)?\s*$')
_FAILURES = ('cannot connect to license server', 'license server machine is down', 'lmgrd is not running',
             'error getting status', 'cannot find license file', 'no such feature exists', 'cannot read data from license server')


def _start_time(text, now):
    """lmstat's 'Wed 10/16 9:03' (no year, the licence server's clock) as an epoch, the year
    the one that puts it at or before now."""
    try:
        md, hm = text.split()[1:3]
        month, day = (int(x) for x in md.split('/'))
        hour, minute = (int(x) for x in hm.split(':'))
        when = datetime(now.year, month, day, hour, minute)
        if when > now + timedelta(days=1):
            when = when.replace(year=now.year - 1)
        return int(time.mktime(when.timetuple()))
    except (ValueError, IndexError):
        return None


def parse_lmstat(text, now=None):
    """The output of `lmutil lmstat -a` as {'servers': [{host, up}], 'daemons': [{vendor, up}],
    'features': [{feature, vendor, total, in_use, queued, holders: [{user, host, display,
    version, handle, start, count}]}], 'error': ''}. Uncounted (node-locked) features and
    features the server reports an error for are left out. One feature over several
    INCREMENT lines (versions) is one row, its holders together."""
    now = now or datetime.now()
    out = {'servers': [], 'daemons': [], 'features': [], 'error': ''}
    feats = {}
    cur = None
    vendor = version = ''
    section = ''
    for raw in (text or '').splitlines():
        line = raw.rstrip()
        low = line.lower().strip()
        if not low:
            continue
        if low.startswith('vendor daemon status'):
            section = 'daemons'
            continue
        if low.startswith('feature usage info'):
            section = 'features'
            continue
        m = _SERVER.match(line)
        if m:
            out['servers'].append({'host': m.group('host'), 'up': m.group('state').upper() == 'UP'})
            continue
        if section == 'daemons':
            m = _DAEMON.match(line)
            if m:
                out['daemons'].append({'vendor': m.group('vendor'), 'up': m.group('state') == 'UP'})
                continue
        m = _USERS_OF.match(line.strip())
        if m:
            section = 'features'
            name, rest = m.group('feature').strip(), m.group('rest')
            t = _TOTALS.search(rest)
            vendor = version = ''
            if not t:                       # Uncounted, node-locked / Error: ...
                cur = None
                continue
            cur = feats.get(name)
            if cur is None:
                cur = feats[name] = {'feature': name, 'vendor': '', 'total': 0, 'in_use': 0, 'queued': 0, 'holders': []}
            cur['total'] += int(t.group(1))
            cur['in_use'] += int(t.group(2))
            continue
        if cur is None:
            if any(f in low for f in _FAILURES) and not out['error']:
                out['error'] = line.strip()[:300]
            continue
        m = _FEATURE_LINE.match(line)
        if m:
            vendor, version = m.group('vendor'), m.group('version')
            cur['vendor'] = cur['vendor'] or vendor
            continue
        m = _USER.match(line)
        if m:
            if m.group('queued'):
                cur['queued'] += int(m.group('queued'))
                continue
            ver = (m.group('version') or '').lstrip('v') or version
            cur['holders'].append({
                'user': m.group('user'), 'host': m.group('host'), 'display': m.group('display'),
                'version': ver, 'handle': m.group('handle'), 'vendor': vendor,
                'start': _start_time(m.group('start'), now) if m.group('start') else None,
                'count': int(m.group('count') or 1)})
    out['features'] = sorted(feats.values(), key=lambda f: f['feature'].lower())
    if not out['features'] and not out['error']:
        if any(d['up'] is False for d in out['daemons']) or any(s['up'] is False for s in out['servers']):
            out['error'] = 'licence server or vendor daemon down'
        elif not out['servers'] and not out['daemons']:
            out['error'] = 'no lmstat output'
    return out


def merge(results):
    """Several lmstat results (one per lmgrd port) as one."""
    out = {'servers': [], 'daemons': [], 'features': [], 'error': ''}
    feats = {}
    for r in results:
        out['servers'] += r['servers']
        out['daemons'] += r['daemons']
        out['error'] = out['error'] or r['error']
        for f in r['features']:
            g = feats.get(f['feature'])
            if g is None:
                feats[f['feature']] = dict(f, holders=list(f['holders']))
            else:
                for k in ('total', 'in_use', 'queued'):
                    g[k] += f[k]
                g['holders'] += f['holders']
                g['vendor'] = g['vendor'] or f['vendor']
    out['features'] = sorted(feats.values(), key=lambda f: f['feature'].lower())
    if out['features']:
        out['error'] = ''
    return out


# --- the lmgrd debug log -----------------------------------------------------------------

_TIMESTAMP = re.compile(r'TIMESTAMP (\d{1,2})/(\d{1,2})/(\d{4})')
_DENIED = re.compile(r'^\s*(?P<h>\d{1,2}):(?P<m>\d{2}):(?P<s>\d{2}) \((?P<vendor>[^)]+)\) (?P<kind>DENIED|UNSUPPORTED): '
                     r'"(?P<feature>[^"]+)" (?P<user>[^@\s]+)@(?P<host>\S+)\s*(?P<reason>.*)$')


def _reason(text):
    text = text.strip()
    if text.startswith('(') and text.endswith(')'):
        text = text[1:-1]
    return text.strip()[:200]


def parse_denials(text, now=None):
    """DENIED and UNSUPPORTED lines of an lmgrd debug log as [{at (epoch), vendor, feature,
    user, host, kind, reason}]. A line carries the time only: the day is the last TIMESTAMP
    line's before it, a time that goes back past midnight the next day; before any TIMESTAMP
    the days are counted back from now (the last line no later than now)."""
    now = now or datetime.now()
    lines = (text or '').splitlines()
    rows = []
    day = None
    last = None
    pending = []                     # lines before the first TIMESTAMP: (time of day, match)
    for line in lines:
        t = _TIMESTAMP.search(line)
        if t:
            try:
                day = datetime(int(t.group(3)), int(t.group(1)), int(t.group(2)))
                last = None
            except ValueError:
                pass
            continue
        m = _DENIED.match(line)
        if not m:
            continue
        tod = timedelta(hours=int(m.group('h')), minutes=int(m.group('m')), seconds=int(m.group('s')))
        if day is None:
            pending.append((tod, m))
            continue
        when = day + tod
        if last is not None and when < last - timedelta(hours=1):
            day += timedelta(days=1)
            when = day + tod
        last = when
        rows.append(_denial(when, m))
    if pending:
        # walk back from now: the last undated line is today (or yesterday when later than now)
        day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        dated = []
        later = None
        for tod, m in reversed(pending):
            when = day + tod
            limit = now if later is None else later + timedelta(hours=1)
            if when > limit:
                day -= timedelta(days=1)
                when = day + tod
            later = when
            dated.append(_denial(when, m))
        rows = list(reversed(dated)) + rows
    return rows


def _denial(when, m):
    return {'at': int(time.mktime(when.timetuple())), 'vendor': m.group('vendor'), 'feature': m.group('feature'),
            'user': m.group('user'), 'host': m.group('host'), 'kind': m.group('kind').lower(),
            'reason': _reason(m.group('reason'))}


# --- settings ------------------------------------------------------------------------------

_BAD_PATH = re.compile(r'[\x00-\x1f"\'`$;|&<>*?]')
_TOOL = re.compile(r'^(lmutil|lmstat)(\.exe)?$', re.I)


def _absolute(path):
    return path.startswith('/') or bool(re.match(r'^[A-Za-z]:[\\/]', path))


def check_tool_path(path):
    """'' or the absolute path of lmutil / lmstat (nothing else runs)."""
    path = str(path or '').strip()
    if not path:
        return ''
    if len(path) > 300 or _BAD_PATH.search(path) or not _absolute(path):
        raise ValueError('lmutil_path must be an absolute path without quotes or shell characters')
    if not _TOOL.match(re.split(r'[\\/]', path)[-1]):
        raise ValueError('lmutil_path must name lmutil or lmstat')
    return path


def check_log_path(path):
    path = str(path or '').strip()
    if not path:
        return ''
    if len(path) > 300 or _BAD_PATH.search(path) or not _absolute(path):
        raise ValueError('debug_log must be an absolute path without quotes or shell characters')
    return path


def find_lmutil(configured=''):
    """The lmutil the engine runs: the server's own path, MOAVI_LMUTIL, /opt/moavi/lmutil, PATH."""
    for p in (configured, os.environ.get('MOAVI_LMUTIL', '')) + LMUTIL_PATHS:
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return shutil.which('lmutil') or ''


def run_lmutil(path, port, host):
    """`lmutil lmstat -a -c port@host` on this host: (exit code, stdout, error text). The
    licence server is outside the clusters; lmstat only reads its status."""
    args = [path, 'lmstat', '-a', '-c', f'{int(port)}@{host}']
    if os.path.basename(path).lower().startswith('lmstat'):
        args = [path, '-a', '-c', f'{int(port)}@{host}']
    try:
        r = subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=LMUTIL_TIMEOUT,
                           stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return None, '', f'lmstat did not answer in {LMUTIL_TIMEOUT} s'
    except OSError as e:
        return None, '', str(e)[:300]
    return r.returncode, r.stdout or '', (r.stderr or '').strip()[:300]


def guest_lmstat_command(path, port, host, os_kind):
    exe = path or ('lmutil.exe' if os_kind == 'windows' else 'lmutil')
    if re.split(r'[\\/]', exe)[-1].lower().startswith('lmstat'):
        return [exe, '-a', '-c', f'{int(port)}@{host}']
    return [exe, 'lmstat', '-a', '-c', f'{int(port)}@{host}']


def guest_log_command(path, os_kind, lines=2000):
    if os_kind == 'windows':
        return ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                f"Get-Content -LiteralPath '{path}' -Tail {int(lines)}"]
    return ['tail', '-n', str(int(lines)), path]


def threshold_of(server, feature):
    per = server.get('feature_thresholds') or {}
    if feature in per:
        try:
            return max(0, min(100, int(per[feature])))
        except (TypeError, ValueError):
            pass
    return int(server.get('seat_threshold') if server.get('seat_threshold') is not None else 90)


def seat_alerts(server, features):
    """(events, new state): a feature at or over its threshold is 'high', every seat taken is
    'full'. An event when a feature goes up a level, and one when it is back under."""
    state = dict(server.get('seat_alerted') or {})
    events = []
    seen = set()
    for f in features:
        name, total, used = f['feature'], f['total'], f['in_use']
        seen.add(name)
        limit = threshold_of(server, name)
        if total <= 0 or limit <= 0:
            if name in state:
                state.pop(name)
            continue
        pct = 100.0 * used / total
        level = 'full' if used >= total else ('high' if pct >= limit else '')
        was = state.get(name, '')
        if level and (not was or (was == 'high' and level == 'full')):
            events.append({'feature': name, 'level': level, 'in_use': used, 'total': total, 'pct': round(pct), 'threshold': limit})
            state[name] = level
        elif not level and was:
            events.append({'feature': name, 'level': 'ok', 'in_use': used, 'total': total, 'pct': round(pct), 'threshold': limit})
            state.pop(name)
        elif level == 'high' and was == 'full':
            state[name] = 'high'
    for name in list(state):
        if name not in seen:
            state.pop(name)
    return events, state


# --- the tables ----------------------------------------------------------------------------

def record(server_id, parsed, at=None):
    """One check: a sample per feature, every holder's checkout seen at `at`."""
    at = int(at or time.time())
    d = db()
    for f in parsed['features']:
        d.execute('INSERT OR REPLACE INTO vlab_license_samples (server_id, at, feature, vendor, total, in_use, queued) '
                  'VALUES (?, ?, ?, ?, ?, ?, ?)', (server_id, at, f['feature'], f['vendor'], f['total'], f['in_use'], f['queued']))
        for h in f['holders']:
            started = h['start'] or at
            d.execute('''INSERT INTO vlab_license_checkouts
                         (server_id, feature, username, host, display, started, vendor, version, count, first_seen, last_seen)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                         ON CONFLICT (server_id, feature, username, host, display, started)
                         DO UPDATE SET last_seen = excluded.last_seen, count = excluded.count''',
                      (server_id, f['feature'], h['user'], h['host'], h['display'], started, h['vendor'] or f['vendor'],
                       h['version'], h['count'], at, at))
    return at


def record_denials(server_id, rows):
    """New refusals only (the log is read again every time). Returns how many were new."""
    d = db()
    before = d.query_one('SELECT COUNT(*) AS n FROM vlab_license_denials WHERE server_id = ?', (server_id,))['n']
    for r in rows:
        d.execute('INSERT OR IGNORE INTO vlab_license_denials (server_id, at, feature, username, host, vendor, kind, reason) '
                  'VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (server_id, r['at'], r['feature'], r['user'], r['host'], r['vendor'], r['kind'], r['reason']))
    return d.query_one('SELECT COUNT(*) AS n FROM vlab_license_denials WHERE server_id = ?', (server_id,))['n'] - before


def prune(now=None, days=KEEP_DAYS):
    cut = int((now or time.time()) - days * 86400)
    d = db()
    d.execute('DELETE FROM vlab_license_samples WHERE at < ?', (cut,))
    d.execute('DELETE FROM vlab_license_checkouts WHERE last_seen < ?', (cut,))
    d.execute('DELETE FROM vlab_license_denials WHERE at < ?', (cut,))


def forget(server_id):
    for t in TABLES:
        db().execute(f'DELETE FROM {t} WHERE server_id = ?', (server_id,))


def latest_at(server_id):
    r = db().query_one('SELECT MAX(at) AS at FROM vlab_license_samples WHERE server_id = ?', (server_id,))
    return r['at'] if r and r['at'] else None


def samples(server_id, since, until=None):
    sql = 'SELECT * FROM vlab_license_samples WHERE server_id = ? AND at >= ?'
    args = [server_id, int(since)]
    if until:
        sql += ' AND at <= ?'
        args.append(int(until))
    return [dict(r) for r in db().query(sql + ' ORDER BY at, feature', tuple(args))]


def holders_at(server_id, at):
    return [dict(r) for r in db().query('SELECT * FROM vlab_license_checkouts WHERE server_id = ? AND last_seen = ? '
                                        'ORDER BY feature, started', (server_id, int(at)))]


def checkouts(server_id, since, until):
    """Checkouts that overlap [since, until]; server_id None means every server."""
    sql = 'SELECT * FROM vlab_license_checkouts WHERE last_seen >= ? AND started <= ?'
    args = [int(since), int(until)]
    if server_id:
        sql += ' AND server_id = ?'
        args.append(server_id)
    return [dict(r) for r in db().query(sql, tuple(args))]


def denials(server_id, since, limit=None):
    sql = 'SELECT * FROM vlab_license_denials WHERE at >= ?'
    args = [int(since)]
    if server_id:
        sql += ' AND server_id = ?'
        args.append(server_id)
    sql += ' ORDER BY at DESC'
    if limit:
        sql += f' LIMIT {int(limit)}'
    return [dict(r) for r in db().query(sql, tuple(args))]


# --- what the numbers say ------------------------------------------------------------------

def feature_stats(rows, interval=INTERVAL):
    """{feature: {total, peak, avg, samples, full_samples, shortage_minutes, shortage_count}}
    from samples in time order. A shortage is a run of checks with every seat taken."""
    out = {}
    for r in rows:
        s = out.setdefault(r['feature'], {'feature': r['feature'], 'vendor': r['vendor'], 'total': 0, 'peak': 0,
                                          'sum': 0, 'samples': 0, 'full_samples': 0, 'shortage_count': 0, '_full': False})
        s['total'] = max(s['total'], r['total'])
        s['peak'] = max(s['peak'], r['in_use'])
        s['sum'] += r['in_use']
        s['samples'] += 1
        full = r['total'] > 0 and r['in_use'] >= r['total']
        if full:
            s['full_samples'] += 1
            if not s['_full']:
                s['shortage_count'] += 1
        s['_full'] = full
    for s in out.values():
        s['avg'] = round(s.pop('sum') / s['samples'], 2) if s['samples'] else 0.0
        s.pop('_full')
        s['shortage_minutes'] = s['full_samples'] * interval // 60
        s['peak_pct'] = round(100.0 * s['peak'] / s['total']) if s['total'] else 0
        s['avg_pct'] = round(100.0 * s['avg'] / s['total']) if s['total'] else 0
    return out


def series(rows, bucket):
    """{feature: [{t, max, avg, total}]} per bucket of `bucket` seconds."""
    acc = {}
    for r in rows:
        t = r['at'] - r['at'] % bucket
        b = acc.setdefault(r['feature'], {}).setdefault(t, [0, 0, 0, 0])
        b[0] = max(b[0], r['in_use'])
        b[1] += r['in_use']
        b[2] += 1
        b[3] = max(b[3], r['total'])
    return {f: [{'t': t, 'max': v[0], 'avg': round(v[1] / v[2], 2), 'total': v[3]} for t, v in sorted(b.items())]
            for f, b in acc.items()}


def advice(stat, denied=0):
    """'add' (seats ran out or were refused), 'reduce' (the peak left a third or more unused
    over at least a week of checks), 'keep'; with the seats that would do."""
    total, peak = stat['total'], stat['peak']
    if stat['shortage_minutes'] or denied:
        return {'action': 'add', 'seats': max(1, -(-total // 10))}
    week = 7 * 86400 // INTERVAL
    if total >= 3 and stat['samples'] >= week and peak <= total * 2 / 3:
        return {'action': 'reduce', 'seats': total - max(peak + 1, 1)}
    return {'action': 'keep', 'seats': 0}


def user_hours(rows, since, until, interval=INTERVAL):
    """[{user, feature, server_id, hours, checkouts, hosts}] from checkouts clipped to the
    window. A seat is held from lmstat's start to the last check that saw it."""
    acc = {}
    for c in rows:
        start = max(int(since), min(c['started'], c['first_seen']))
        end = min(int(until), c['last_seen'])
        if end < start:
            continue
        k = (c['username'], c['feature'], c['server_id'])
        a = acc.setdefault(k, {'user': c['username'], 'feature': c['feature'], 'server_id': c['server_id'],
                               'seconds': 0, 'checkouts': 0, 'hosts': set()})
        a['seconds'] += (end - start) * max(1, c['count'])
        a['checkouts'] += 1
        a['hosts'].add(c['host'])
    out = [{**{k: v for k, v in a.items() if k not in ('seconds', 'hosts')}, 'hours': round(a['seconds'] / 3600, 1),
            'hosts': sorted(a['hosts'])} for a in acc.values()]
    return sorted(out, key=lambda r: (-r['hours'], r['user']))


def match_desktop(holder_host, holder_display, by_name, user_desktops):
    """(desktop, how) for a seat holder: the host name (or the X display's host) against the
    MOAVI desktops' names, else the user's one open session. (None, '') when neither says."""
    for cand in (holder_host, (holder_display or '').split(':')[0]):
        key = str(cand or '').lower().split('.')[0]
        if key and key in by_name:
            return by_name[key], 'host'
    if len(user_desktops) == 1:
        return user_desktops[0], 'user'
    return None, ''
