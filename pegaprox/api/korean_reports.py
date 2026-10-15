# -*- coding: utf-8 -*-
"""
한국형 보고서 (공공기관 보고 양식) — 자료 수집 API

  POST /api/korean-reports/data
    본문: { type: 'ops'|'resource'|'asset', from: 'YYYY-MM-DD', to: 'YYYY-MM-DD',
            clusterIds?: [..], meta?: {org, dept, author, contact, classification},
            thresholds?: {warn, crit}, locale?: 'ko'|'en' }
    응답: 보고서 자료(JSON) — 화면(web/src/korean_reports.js)이 static/js/makus-reports.js 로
          HTML 미리보기·인쇄(PDF)와 한글(HWPX)·워드(DOCX)·엑셀(XLSX) 파일을 만든다 (서버는 자료만)

  보고서 3종: 가상화 인프라 운영 현황 보고(ops) · 자원 사용 현황 및 증설 검토(resource) · 가상서버 자원 현황 대장(asset)
  자료: Proxmox VE /cluster/resources·/cluster/status, 노드 /rrddata(AVERAGE·MAX) 중 보고 기간 값, 노드 /tasks (vzdump, 보고 기간)
        하드웨어(BMC) 상태 이력 (운영 현황 보고서, pegaprox/core/hw_history.py — 5분 수집이 기록)
  권한: 노드 조회(node.view) + 사용자가 볼 수 있는 클러스터만, 가상서버는 VM 조회 권한(ACL)이 있는 것만

원본: 한국형 보고서 (Makus Systems). AGPL-3.0 (LICENSE·NOTICE)
"""

import logging
import time
from datetime import datetime, timezone, timedelta

from flask import Blueprint, jsonify, request, g

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.utils.rbac import get_user_clusters, user_can_access_vm
from pegaprox.utils.concurrent import run_concurrent
from pegaprox.api.helpers import safe_error

bp = Blueprint('korean_reports', __name__)

DAY_MS = 86_400_000
KST = timezone(timedelta(hours=9))
PVE_TIMEOUT = 15
RAW_CACHE_SEC = 30
_raw_cache = {}  # 미리보기가 작성 정보 입력 때마다 다시 요청 → 같은 조건 원자료는 잠시 재사용 (권한 필터는 매번)


class ReportError(Exception):
    """입력 오류 (400) — ko/en 문구"""
    def __init__(self, ko, en):
        super().__init__(ko)
        self.ko, self.en = ko, en


def _kst_start(ymd):
    """한국 날짜(YYYY-MM-DD) → 그날 0시(KST)의 UTC 밀리초"""
    try:
        d = datetime.strptime(str(ymd), '%Y-%m-%d').replace(tzinfo=KST)
    except Exception:
        raise ReportError(f'날짜 형식이 올바르지 않습니다: {ymd}', f'Invalid date: {ymd}')
    return int(d.timestamp() * 1000)


def _timeframe(span_ms, from_ms):
    # rrd 는 '지금부터 거슬러' 보관하므로 시작일이 얼마나 과거인지로 고름
    back = max(span_ms, time.time() * 1000 - from_ms)
    if back <= 1.1 * DAY_MS: return 'day'
    if back <= 7.5 * DAY_MS: return 'week'
    if back <= 32 * DAY_MS: return 'month'
    if back <= 370 * DAY_MS: return 'year'
    return 'decade'


def _fin(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and abs(v) != float('inf') else None


def _stats(points, f):
    vals = [x for x in (f(p) for p in points) if x is not None]
    if not vals:
        return None, None
    return sum(vals) / len(vals), max(vals)


def _cpu_pct(p):
    c = _fin((p or {}).get('cpu'))
    return None if c is None else c * 100


def _mem_pct(p):
    used, total = _fin((p or {}).get('memused')), _fin((p or {}).get('memtotal'))
    return used / total * 100 if used is not None and total else None


def _get(mgr, path):
    """Proxmox API GET → data (실패하면 예외)"""
    r = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json{path}", timeout=PVE_TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f'HTTP {r.status_code} {path}')
    return (r.json() or {}).get('data')


def _try(mgr, path, default):
    try:
        v = _get(mgr, path)
        return default if v is None else v
    except Exception:
        return default


def _collect_cluster(cid, mgr, from_ms, to_ms, want_usage, want_backup):
    from urllib.parse import quote
    res = _get(mgr, '/cluster/resources') or []
    status = _try(mgr, '/cluster/status', [])
    cluster_name = next((x.get('name') for x in status if x.get('type') == 'cluster'), None) or getattr(mgr.config, 'name', cid)
    tf = _timeframe(to_ms - from_ms, from_ms)

    vms = []
    for r in res:
        if r.get('type') not in ('qemu', 'lxc') or r.get('template'):
            continue
        tags = [t for t in str(r.get('tags') or '').replace(';', ' ').replace(',', ' ').split() if t]
        vms.append({
            'connId': cid, 'cluster': cluster_name, 'node': r.get('node'), 'vmid': int(r.get('vmid') or 0),
            'name': r.get('name') or f"{'CT' if r.get('type') == 'lxc' else 'VM'} {r.get('vmid')}",
            'type': r.get('type'), 'status': r.get('status'),
            'cpus': _fin(r.get('maxcpu')) or 0, 'mem': _fin(r.get('maxmem')) or 0, 'disk': _fin(r.get('maxdisk')) or 0,
            'uptime': _fin(r.get('uptime')) or 0, 'tags': ', '.join(tags), 'template': False,
        })

    node_res = [r for r in res if r.get('type') == 'node']

    def node_row(r):
        online = r.get('status') == 'online'
        cpu_avg = cpu_max = mem_avg = mem_max = None
        if online and want_usage:
            path = f"/nodes/{quote(str(r.get('node')), safe='')}/rrddata?timeframe={tf}"
            in_range = lambda pts: [p for p in (pts or []) if from_ms <= (p.get('time') or 0) * 1000 < to_ms]
            a = in_range(_try(mgr, f'{path}&cf=AVERAGE', []))
            m = in_range(_try(mgr, f'{path}&cf=MAX', []))
            cpu_avg, _ = _stats(a, _cpu_pct)
            _, cpu_max = _stats(m or a, _cpu_pct)
            mem_avg, _ = _stats(a, _mem_pct)
            _, mem_max = _stats(m or a, _mem_pct)
        maxmem = _fin(r.get('maxmem'))
        return {
            'connId': cid, 'cluster': cluster_name, 'node': r.get('node'),
            'status': 'online' if online else 'offline',
            'cpuCores': _fin(r.get('maxcpu')) or 0, 'memTotal': maxmem or 0,
            'cpuNow': r['cpu'] * 100 if online and _fin(r.get('cpu')) is not None else None,
            'memNow': (r.get('mem') or 0) / maxmem * 100 if online and maxmem else None,
            'cpuAvg': cpu_avg, 'cpuMax': cpu_max, 'memAvg': mem_avg, 'memMax': mem_max,
            'uptime': _fin(r.get('uptime')) or 0,
            'vms': sum(1 for v in vms if v['node'] == r.get('node')),
        }

    nodes = [x for x in run_concurrent([(lambda r=r: node_row(r)) for r in node_res], timeout=60) if x]

    # 스토리지: 공유 저장소는 클러스터에 한 번만
    storages, seen_shared = [], set()
    for r in res:
        if r.get('type') != 'storage' or r.get('status') != 'available' or not _fin(r.get('maxdisk')):
            continue
        if r.get('shared'):
            if r.get('storage') in seen_shared:
                continue
            seen_shared.add(r.get('storage'))
        used = _fin(r.get('disk')) or 0
        storages.append({
            'connId': cid, 'cluster': cluster_name, 'node': r.get('node'), 'name': r.get('storage'),
            'type': r.get('plugintype') or '-', 'scope': '공유' if r.get('shared') else r.get('node'),
            'total': r.get('maxdisk'), 'used': used, 'pct': used / r['maxdisk'] * 100 if r.get('maxdisk') else None,
        })

    # 백업 작업 (vzdump) — 보고 기간
    tasks = []
    if want_backup:
        since, until = from_ms // 1000, to_ms // 1000

        def node_tasks(n):
            path = f"/nodes/{quote(str(n['node']), safe='')}/tasks?typefilter=vzdump&since={since}&until={until}&limit=1000&source=all"
            out = []
            for t in _try(mgr, path, []):
                if t.get('status') is None:
                    continue  # 진행 중
                out.append({'connId': cid, 'node': n['node'], 'time': (t.get('starttime') or 0) * 1000,
                            'target': f"VM {t['id']}" if t.get('id') else '', 'status': str(t.get('status'))})
            return out

        for lst in run_concurrent([(lambda n=n: node_tasks(n)) for n in nodes if n['status'] == 'online'], timeout=60):
            tasks.extend(lst or [])

    return {'cluster': {'id': cid, 'name': cluster_name, 'connName': getattr(mgr.config, 'name', cid)},
            'nodes': nodes, 'vms': vms, 'storages': storages, 'tasks': tasks}


def _acting_user():
    """require_auth 가 둔 현재 사용자 (API 토큰이면 토큰 권한까지로 낮춤 — check_cluster_access 와 같게)"""
    user = getattr(g, 'current_user', None)
    if user is None:
        from pegaprox.utils.auth import load_users
        user = load_users().get(request.session.get('user'), {}) or {}
    if request.session.get('api_token') and isinstance(user, dict) and 'effective_role' not in user:
        from pegaprox.models.permissions import ROLE_ADMIN, ROLE_USER, ROLE_VIEWER
        lv = {ROLE_ADMIN: 3, ROLE_USER: 2, ROLE_VIEWER: 1}
        eff = min(lv.get(request.session.get('role'), 1), lv.get(user.get('role'), 1))
        user = {**user, 'effective_role': next((r for r, x in lv.items() if x == eff), ROLE_VIEWER)}
    return user


@bp.route('/api/korean-reports/clusters', methods=['GET'])
@require_auth(perms=['node.view'])
def korean_report_clusters():
    """대상 클러스터 고르기용 목록 (Proxmox VE 만, 볼 수 있는 것만)"""
    allowed = get_user_clusters(_acting_user())
    out = []
    for cid, mgr in cluster_managers.items():
        if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
            continue
        if allowed is not None and cid not in allowed:
            continue
        out.append({'id': cid, 'name': getattr(mgr.config, 'name', cid), 'connected': bool(getattr(mgr, 'is_connected', False))})
    out.sort(key=lambda c: c['name'])
    return jsonify(out)


@bp.route('/api/korean-reports/data', methods=['POST'])
@require_auth(perms=['node.view'])
def korean_report_data():
    body = request.get_json(silent=True) or {}
    en = body.get('locale') == 'en'
    try:
        from_ms = _kst_start(body.get('from'))
        to_ms = _kst_start(body.get('to')) + DAY_MS  # 종료일 포함
        if not to_ms > from_ms:
            raise ReportError('보고 기간이 올바르지 않습니다', 'Invalid report period')
        if to_ms - from_ms > 400 * DAY_MS:
            raise ReportError('보고 기간은 최대 1년입니다', 'The report period can be at most one year')
        rtype = body.get('type') if body.get('type') in ('ops', 'resource', 'asset') else 'ops'

        user = _acting_user()
        allowed = get_user_clusters(user)  # None = 전체(관리자)
        want = set(body.get('clusterIds') or [])
        targets = []
        for cid, mgr in cluster_managers.items():
            if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
                continue
            if allowed is not None and cid not in allowed:
                continue
            if want and cid not in want:
                continue
            targets.append((cid, mgr))

        def one(cid, mgr):
            key = f'{cid}|{from_ms}|{to_ms}|{rtype}'
            hit = _raw_cache.get(key)
            if hit and time.time() - hit[0] < RAW_CACHE_SEC:
                return {'ok': True, 'data': hit[1]}
            try:
                if not getattr(mgr, 'is_connected', False):
                    raise RuntimeError(getattr(mgr, 'connection_error', None) or 'not connected')
                data = _collect_cluster(cid, mgr, from_ms, to_ms, rtype != 'asset', rtype == 'ops')
                if len(_raw_cache) > 50:
                    _raw_cache.clear()
                _raw_cache[key] = (time.time(), data)
                return {'ok': True, 'data': data}
            except Exception as e:
                logging.warning(f'[korean-reports] {cid}: {e}')
                return {'ok': False, 'error': {'connection': getattr(mgr.config, 'name', cid), 'error': str(e)[:160]}}

        results = [r for r in run_concurrent([(lambda c=c, m=m: one(c, m)) for c, m in targets], timeout=120) if r]
        ok = [r['data'] for r in results if r.get('ok')]
        errors = [r['error'] for r in results if not r.get('ok')]

        nodes = [n for r in ok for n in r['nodes']]
        # 가상서버: VM 조회 권한(ACL)이 있는 것만
        vms = [v for r in ok for v in r['vms']
               if user_can_access_vm(user, v['connId'], v['vmid'], 'vm.view', 'lxc' if v['type'] == 'lxc' else 'qemu')]
        storages = sorted([s for r in ok for s in r['storages']], key=lambda s: -(s['pct'] or 0))
        tasks = [t for r in ok for t in r['tasks']]
        failures = sorted([t for t in tasks if t['status'] != 'OK' and not t['status'].upper().startswith('WARNINGS')],
                          key=lambda t: -t['time'])

        if not nodes and errors:
            lst = ', '.join(f"{e['connection']} ({e['error']})" for e in errors)
            return jsonify({'error': f'Could not collect data: {lst}' if en else f'정보를 수집하지 못했습니다: {lst}'}), 502

        # 하드웨어(BMC) 상태 이력 — 운영 현황 보고서만, 볼 수 있는 노드만 (pegaprox/core/hw_history.py)
        hardware = None
        if rtype == 'ops':
            try:
                from pegaprox.core import hw_history
                visible = {}
                for n in nodes:
                    visible.setdefault(n['connId'], set()).add(n['node'])
                hardware = hw_history.report_hardware(visible, from_ms, to_ms)
            except Exception as e:
                logging.warning(f'[korean-reports] hardware history: {e}')

        th = body.get('thresholds') or {}
        try:
            warn = min(99, max(1, int(th.get('warn') or 80)))
        except Exception:
            warn = 80
        try:
            crit = min(100, max(warn + 1, int(th.get('crit') or 90)))
        except Exception:
            crit = 90
        meta = body.get('meta') or {}
        cut = lambda k, n: str(meta.get(k) or '')[:n]

        return jsonify({
            'type': rtype,
            'locale': 'en' if en else 'ko',
            'generatedAt': int(time.time() * 1000),
            'period': {'from': from_ms, 'to': to_ms - 1},
            'meta': {'org': cut('org', 60), 'dept': cut('dept', 60), 'author': cut('author', 40),
                     'contact': cut('contact', 40), 'classification': cut('classification', 20)},
            'thresholds': {'warn': warn, 'crit': crit},
            'clusters': [r['cluster'] for r in ok if any(n['connId'] == r['cluster']['id'] for n in nodes)],
            'nodes': sorted(nodes, key=lambda n: f"{n['cluster']}{n['node']}"),
            'vms': vms,
            'storages': storages,
            'backups': {
                'total': len(tasks),
                'ok': sum(1 for t in tasks if t['status'] == 'OK'),
                'warn': sum(1 for t in tasks if t['status'].upper().startswith('WARNINGS')),
                'fail': len(failures),
                'failures': failures,
            } if rtype == 'ops' else None,
            'externalChecks': None,  # 외부 시스템 AI 점검 — 이식 예정
            'hardware': hardware,
            'errors': errors,
        })
    except ReportError as e:
        return jsonify({'error': e.en if en else e.ko}), 400
    except Exception as e:
        logging.exception('[korean-reports] failed')
        return jsonify({'error': safe_error(e, 'Report data collection failed')}), 500
