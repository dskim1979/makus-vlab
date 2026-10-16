"""MOAVI Desk: growth forecast per cluster (pegaprox/vlab/forecast.py) - 대시보드 > 증설 예측.

  GET  /api/vlab/admin/clusters/<cluster_id>/forecast   ?days=30|90|180 (90)   vlab.pool.view

forecast_tick (the minute loop, on the active) updates today's row of every cluster once an
hour, and on its first run fills in the past days from the core's metrics history.
"""
import logging
import time
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import forecast as fc
from pegaprox.vlab import store

bp = Blueprint('vlab_forecast', __name__)

EVERY = 3600
_last = [0.0]
_backfilled = set()


def _bad(msg, status=400):
    return jsonify({'error': msg}), status


# --- the daily numbers ---------------------------------------------------------------------

def _cpu_mem_by_day(cluster_id, days):
    """{day: {cpu_avg, cpu_peak, mem_avg, mem_peak}} from the core's metrics history."""
    from pegaprox.api.helpers import load_metrics_window
    acc = defaultdict(lambda: {'cpu': [], 'mem': []})
    for ts, clusters in load_metrics_window(days) or []:
        t = ((clusters or {}).get(cluster_id) or {}).get('totals') or {}
        if not t.get('cpu_total') or not t.get('mem_total'):
            continue
        day = datetime.fromtimestamp(ts).date().isoformat()
        acc[day]['cpu'].append(100.0 * t.get('cpu_used', 0) / t['cpu_total'])
        acc[day]['mem'].append(100.0 * t.get('mem_used', 0) / t['mem_total'])
    out = {}
    for day, v in acc.items():
        out[day] = {'cpu_avg': round(sum(v['cpu']) / len(v['cpu']), 1), 'cpu_peak': round(max(v['cpu']), 1),
                    'mem_avg': round(sum(v['mem']) / len(v['mem']), 1), 'mem_peak': round(max(v['mem']), 1)}
    return out


def _sessions_peak_by_day(cluster_id, since_day):
    """{day: most sessions open at once} for the desktops of the cluster's pools."""
    pools = {p['id'] for p in store.list_pools() if p['cluster_id'] == cluster_id}
    rows = store.db().query('SELECT pool_id, started_at, ended_at FROM vlab_sessions WHERE started_at >= ?', (since_day,))
    ev = defaultdict(list)
    for r in rows:
        if r['pool_id'] not in pools:
            continue
        try:
            a = datetime.fromisoformat(r['started_at'])
            b = datetime.fromisoformat(r['ended_at']) if r['ended_at'] else min(a + timedelta(hours=12), datetime.now(a.tzinfo))
        except (TypeError, ValueError):
            continue
        ev[a.date().isoformat()] += [(a, 1), (b, -1)]
    out = {}
    for day, e in ev.items():
        e.sort(key=lambda x: (x[0], x[1]))
        cur = peak = 0
        for _, d in e:
            cur += d
            peak = max(peak, cur)
        out[day] = peak
    return out


def _storage(cluster_id, mgr):
    from pegaprox.api import clusters as core_clusters
    used = total = 0
    seen = set()
    for r in core_clusters.cluster_storage_resources(cluster_id, mgr) or []:
        if r.get('status') != 'available' or not r.get('maxdisk'):
            continue
        key = r.get('storage') if r.get('shared') else f"{r.get('node')}/{r.get('storage')}"
        if key in seen:
            continue
        seen.add(key)
        used += r.get('disk') or 0
        total += r.get('maxdisk') or 0
    return used, total


def _cards(cluster_id, mgr):
    """(cards in use - loans and running GPU jobs' GPUs, cards there are)."""
    from pegaprox.vlab import accel, catalog
    total = sum(len(m.get('devices') or []) for m in (accel.pci_mappings(mgr) or []))
    loans = sum(1 for l in store.list_leases(active_only=True) if l['cluster_id'] == cluster_id)
    pools = {p['id'] for p in store.list_pools() if p['cluster_id'] == cluster_id}
    gpus = sum(int(j.get('gpus') or 0) for j in catalog.jobs_in('running') if j.get('pool_id') in pools)
    return loans + gpus, total


def snapshot(cluster_id, mgr, today=None):
    """Today's numbers of one cluster (merged into today's row)."""
    today = today or date.today()
    day = today.isoformat()
    row = dict(_cpu_mem_by_day(cluster_id, 1).get(day) or {})
    used, total = _storage(cluster_id, mgr)
    if total:
        row.update(storage_used=used, storage_total=total, storage_pct=fc.pct(used, total))
    desks = sum(1 for d in store.list_desktops() if d['cluster_id'] == cluster_id)
    row['desktops'] = desks
    peak = _sessions_peak_by_day(cluster_id, day).get(day, 0)
    row['sessions_peak'] = peak
    if desks:
        row['sessions_pct'] = fc.pct(peak, desks)
    try:
        in_use, cards = _cards(cluster_id, mgr)
        if cards:
            row.update(cards_in_use=in_use, cards_total=cards, cards_pct=fc.pct(in_use, cards))
    except Exception as e:
        logging.debug(f'[VLAB] forecast cards {cluster_id}: {e}')
    fc.save_day(day, cluster_id, row)
    return row


def backfill(cluster_id, days=30):
    """Past days' CPU / memory (metrics history) and session peaks, where a day has none yet."""
    since = (date.today() - timedelta(days=days)).isoformat()
    sessions = _sessions_peak_by_day(cluster_id, since)
    for day, v in _cpu_mem_by_day(cluster_id, days).items():
        if day == date.today().isoformat():
            continue
        row = dict(v)
        if day in sessions:
            row['sessions_peak'] = sessions[day]
        row.update(fc.get_day(day, cluster_id) or {})     # what a snapshot of that day saw wins
        fc.save_day(day, cluster_id, row, merge=False)


def forecast_tick(force=False):
    if not force and time.time() - _last[0] < EVERY:
        return 0
    _last[0] = time.time()
    n = 0
    for cid, mgr in list(cluster_managers.items()):
        if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox' or not getattr(mgr, 'is_connected', False):
            continue
        try:
            if cid not in _backfilled:
                backfill(cid)
                _backfilled.add(cid)
            snapshot(cid, mgr)
            n += 1
        except Exception as e:
            logging.warning(f'[VLAB] forecast snapshot {cid}: {e}')
    fc.prune()
    return n


# --- the forecast --------------------------------------------------------------------------

METRICS = (
    # key, Korean label, unit, threshold key
    ('cpu_avg', 'CPU 평균', '%', 'cpu_avg'),
    ('cpu_peak', 'CPU 최대', '%', 'cpu_peak'),
    ('mem_avg', '메모리 평균', '%', 'mem_avg'),
    ('mem_peak', '메모리 최대', '%', 'mem_peak'),
    ('storage_pct', '스토리지', '%', 'storage_pct'),
    ('sessions_pct', '동시 접속 (데스크톱 대비)', '%', 'sessions_pct'),
    ('cards_pct', '가속 카드 사용 (대여 · GPU 작업)', '%', 'cards_pct'),
)


def _advice(key, p):
    if not p.get('enough'):
        return ''
    if p['over_now']:
        return {'cpu_avg': '평소에도 CPU가 모자랍니다. 노드를 늘리거나 데스크톱 vCPU를 줄이세요.',
                'cpu_peak': '바쁜 시간에 CPU가 가득 찹니다. 수업 · 업무 시간을 나누거나 노드를 늘리세요.',
                'mem_avg': '메모리가 모자랍니다. 노드 메모리를 늘리거나 회수 제안을 확인하세요.',
                'mem_peak': '바쁜 시간에 메모리가 가득 찹니다.',
                'storage_pct': '스토리지가 기준을 넘었습니다. 증설하거나 오래된 스냅숏 · 백업을 정리하세요.',
                'sessions_pct': '데스크톱 대부분이 동시에 쓰입니다. 풀에 데스크톱을 늘리세요.',
                'cards_pct': '카드가 거의 늘 쓰입니다. 대기 · 예약이 밀리면 카드를 늘리세요.'}.get(key, '')
    if p['eta_days'] is not None and p['eta_days'] <= 180:
        return f"이 추세면 약 {p['eta_days']}일 뒤({p['eta_day']}) 기준에 닿습니다. 예산 · 구매 기간을 생각해 미리 준비하세요."
    return ''


@bp.route('/api/vlab/admin/clusters/<cluster_id>/forecast', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_forecast(cluster_id):
    if cluster_id not in cluster_managers or not core._can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    try:
        days = int(request.args.get('days') or 90)
    except ValueError:
        return _bad('days: 30, 90 or 180')
    if days not in (30, 90, 180):
        return _bad('days: 30, 90 or 180')
    if cluster_id not in _backfilled:
        try:
            backfill(cluster_id)
            _backfilled.add(cluster_id)
        except Exception as e:
            logging.debug(f'[VLAB] forecast backfill {cluster_id}: {e}')
    rows = fc.series(cluster_id, (date.today() - timedelta(days=days)).isoformat())
    out = []
    for key, label, unit, tk in METRICS:
        p = fc.project(rows, key, fc.THRESHOLDS[tk])
        p.update(key=key, label=label, unit=unit, threshold=fc.THRESHOLDS[tk], level=fc.level(p), advice=_advice(key, p),
                 history=[{'day': d, 'value': v.get(key)} for d, v in rows if isinstance(v.get(key), (int, float))])
        out.append(p)
    order = {'now': 0, 'soon': 1, 'watch': 2, 'ok': 3, 'unknown': 4}
    latest = rows[-1][1] if rows else {}
    return jsonify({'cluster_id': cluster_id, 'days': days, 'from': rows[0][0] if rows else None, 'points': len(rows),
                    'min_points': fc.MIN_POINTS, 'metrics': sorted(out, key=lambda m: order[m['level']]),
                    'latest': {k: latest.get(k) for k in ('desktops', 'sessions_peak', 'storage_used', 'storage_total',
                                                         'cards_in_use', 'cards_total')},
                    'generated_at': datetime.now(timezone.utc).isoformat(timespec='seconds')})
