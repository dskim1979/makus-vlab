"""MOAVI Desk: when will it run short (증설 예측) - a daily snapshot per cluster and a straight-line
trend over it.

Once a day (the minute loop, on the active) each cluster gets one row: average and peak CPU and
memory of the day (the core's metrics history), storage used / total, desktops, the most
sessions open at once, and the accelerator cards in use. The first time, the CPU and memory of
the past days are filled in from the metrics history the core keeps.

The forecast fits a least-squares line through the last `days` of a metric and tells when it
crosses its threshold (CPU 80 %, memory 85 %, storage 85 %, desktops and sessions against what
the pools can hold, cards against what there are). It needs MIN_POINTS days; with a flat or
falling trend there is no date. A loose fit (r² < 0.3) is marked 'low' confidence: a step
change (a new semester, a new project) shows only after a while.

Pure rules here; the routes and the snapshot are in pegaprox/api/vlab_forecast.py.
"""
import json
import threading
from datetime import date, timedelta

from pegaprox.vlab.store import db as _store_db, now

MIN_POINTS = 10
THRESHOLDS = {'cpu_avg': 80.0, 'cpu_peak': 95.0, 'mem_avg': 85.0, 'mem_peak': 95.0, 'storage_pct': 85.0,
              'desktops_pct': 90.0, 'sessions_pct': 90.0, 'cards_pct': 90.0}

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_capacity_daily (
        day TEXT NOT NULL,
        cluster_id TEXT NOT NULL,
        data TEXT NOT NULL DEFAULT '{}',
        at TEXT NOT NULL,
        PRIMARY KEY (day, cluster_id)
    )''',
)
TABLES = ('vlab_capacity_daily',)
_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_forecast', False):
        with _lock:
            if not getattr(d, '_vlab_forecast', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_forecast = True
    return d


def save_day(day, cluster_id, data, merge=True):
    """Keep a day's numbers; with merge, numbers already there for keys not given stay."""
    if merge:
        old = get_day(day, cluster_id) or {}
        data = dict(old, **{k: v for k, v in data.items() if v is not None})
    db().execute('INSERT OR REPLACE INTO vlab_capacity_daily (day, cluster_id, data, at) VALUES (?, ?, ?, ?)',
                 (day, cluster_id, json.dumps(data), now()))


def get_day(day, cluster_id):
    r = db().query_one('SELECT data FROM vlab_capacity_daily WHERE day = ? AND cluster_id = ?', (day, cluster_id))
    try:
        return json.loads(r['data']) if r else None
    except ValueError:
        return None


def series(cluster_id, since_day):
    rows = db().query('SELECT day, data FROM vlab_capacity_daily WHERE cluster_id = ? AND day >= ? ORDER BY day',
                      (cluster_id, since_day))
    out = []
    for r in rows:
        try:
            out.append((r['day'], json.loads(r['data'])))
        except ValueError:
            continue
    return out


def prune(keep_days=800, today=None):
    cut = ((today or date.today()) - timedelta(days=keep_days)).isoformat()
    db().execute('DELETE FROM vlab_capacity_daily WHERE day < ?', (cut,))


# --- the line ------------------------------------------------------------------------------

def fit(points):
    """(slope per day, intercept, r²) of a least-squares line through [(x, y)]; None when
    there are fewer than two distinct x."""
    n = len(points)
    if n < 2:
        return None
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return None
    sxy = sum((x - mx) * (y - my) for x, y in points)
    slope = sxy / sxx
    intercept = my - slope * mx
    syy = sum((y - my) ** 2 for y in ys)
    r2 = 1.0 if syy == 0 else max(0.0, min(1.0, (sxy * sxy) / (sxx * syy)))
    return slope, intercept, r2


def project(rows, key, threshold, today=None, horizon_days=730):
    """What the trend of `key` says: {points, current, trend_30d, eta_day, eta_days, over_now,
    confidence} or None with fewer than MIN_POINTS days. eta_* are None when the line does not
    reach the threshold within the horizon."""
    today = today or date.today()
    pts = []
    for day, data in rows:
        v = data.get(key)
        if isinstance(v, (int, float)):
            pts.append(((date.fromisoformat(day) - today).days, float(v)))
    if len(pts) < MIN_POINTS:
        return {'points': len(pts), 'enough': False}
    f = fit(pts)
    if not f:
        return {'points': len(pts), 'enough': False}
    slope, intercept, r2 = f
    current = pts[-1][1]
    out = {'points': len(pts), 'enough': True, 'current': round(current, 1), 'trend_30d': round(slope * 30, 2),
           'confidence': 'high' if r2 >= 0.6 else 'medium' if r2 >= 0.3 else 'low', 'r2': round(r2, 2),
           'over_now': current >= threshold, 'eta_day': None, 'eta_days': None}
    if out['over_now']:
        out['eta_days'] = 0
        out['eta_day'] = today.isoformat()
    elif slope > 0:
        x = (threshold - intercept) / slope
        if 0 <= x <= horizon_days:
            out['eta_days'] = int(round(x))
            out['eta_day'] = (today + timedelta(days=int(round(x)))).isoformat()
        elif x < 0:
            out['eta_days'] = 0
            out['eta_day'] = today.isoformat()
    return out


def pct(used, total):
    return round(100.0 * used / total, 1) if total else None


def level(p):
    """'now' (over), 'soon' (within 90 days), 'watch' (within a year), 'ok' - for one projection."""
    if not p or not p.get('enough'):
        return 'unknown'
    if p['over_now']:
        return 'now'
    if p['eta_days'] is None:
        return 'ok'
    return 'soon' if p['eta_days'] <= 90 else 'watch' if p['eta_days'] <= 365 else 'ok'
