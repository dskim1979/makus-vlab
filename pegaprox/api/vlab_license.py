# -*- coding: utf-8 -*-
"""
MOAVI Desk - licence seats (가속 자원 › 라이선스 서버 › 사용 현황, 운영 > 사용률 보고서 > 라이선스).

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

  PUT    /api/vlab/admin/license-servers/<id>/usage-settings   {mode: off|engine|agent, lm_ports?, lmutil_path?,
                                                              debug_log?, seat_threshold?, feature_thresholds?,
                                                              alert_channels?}                   vlab.accel.manage
  POST   /api/vlab/admin/license-servers/<id>/usage/collect    read the seats now                 vlab.accel.manage
  GET    /api/vlab/admin/license-servers/<id>/usage            ?hours=24 seats per feature now, who holds them and on
                                                              which MOAVI desktop, use over time, shortages, refusals
                                                                                                 vlab.pool.view
  GET    /api/vlab/admin/reports/licenses                      ?days=30&server_id=&view=features|users&format=csv
                                                              peak and average per feature, shortage time, refusals,
                                                              hours per user - what to add or drop  vlab.report.view

license_tick (pegaprox/api/vlab_next.py, every 5 minutes on the active) calls usage_tick: every
server whose mode is not off is read, a feature over its threshold (90 % unless set per feature)
goes to the alert channels once, and once more when it is back under. The numbers and parsers
are in pegaprox/vlab/license_usage.py. The usage tables are the active's own (ha.LOCAL_TABLES);
a standby forwards the two reads to it (ha.FORWARDED_READS).
"""

import logging
import time
from datetime import datetime

from flask import Blueprint, Response, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.api import vlab_next as nxt
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import catalog, store
from pegaprox.vlab import license_usage as lu

bp = Blueprint('vlab_license', __name__)

_bad = core._bad
_user = core._user
AGENT_WAIT = 20.0
LOG_LINES = 2000
_prune_last = [0.0]


def _server(lid):
    s = catalog.get_license_server(lid)
    if not s or (s['cluster_id'] and not core._can_reach(s['cluster_id'])):
        return None
    return s


def settings_view(s):
    return {'mode': s.get('usage_mode') or 'off', 'lm_ports': s.get('lm_ports') or [], 'lmutil_path': s.get('lmutil_path') or '',
            'debug_log': s.get('debug_log') or '', 'seat_threshold': s.get('seat_threshold', 90),
            'feature_thresholds': s.get('feature_thresholds') or {}, 'alert_channels': s.get('alert_channels'),
            'last_at': s.get('usage_at'), 'last_ok': s.get('usage_ok'), 'last_error': s.get('usage_error') or ''}


# --- reading the seats ---------------------------------------------------------------------

def _ports(s):
    return [int(p) for p in (s.get('lm_ports') or s['ports'][:1])]


def _guest(s):
    """(manager, node, None) of the licence server's VM, or (None, None, error)."""
    if not s.get('cluster_id') or not s.get('vmid'):
        return None, None, 'agent mode needs the licence server VM (cluster and VMID)'
    mgr = cluster_managers.get(s['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return None, None, 'cluster not connected'
    vm = core._vm_states(s['cluster_id']).get(int(s['vmid'])) or {}
    if not vm.get('node'):
        return None, None, f"VM {s['vmid']} not found"
    if vm.get('status') != 'running':
        return None, None, f"VM {s['vmid']} is not running"
    return mgr, vm['node'], None


def _guest_read(mgr, node, s, with_log):
    """lmstat (and the debug log's tail) on the licence server's VM through the guest agent.
    Both only read; the agent's exec is a POST, hence ha.reading()."""
    from pegaprox.core import ha
    outs, errors, log = [], [], None
    with ha.reading():
        os_kind = nxt._guest_os(mgr, node, s['vmid'])
        if os_kind is None:
            return [], 'the guest agent of the licence server VM does not answer', None
        for port in _ports(s):
            cmd = lu.guest_lmstat_command(s.get('lmutil_path') or '', port, s['host'], os_kind)
            code, out, err, fail = nxt._agent_run(mgr, node, s['vmid'], cmd, wait=AGENT_WAIT)
            if fail or (code is None and not out):
                errors.append(fail or f'lmstat on {port} did not finish in {int(AGENT_WAIT)} s')
            outs.append(out or '')
            if code not in (0, None) and not out:
                errors.append((err or f'lmstat exit {code}').strip()[:300])
        if with_log and s.get('debug_log'):
            code, out, err, fail = nxt._agent_run(mgr, node, s['vmid'], lu.guest_log_command(s['debug_log'], os_kind, LOG_LINES),
                                                  wait=AGENT_WAIT)
            log = out if code == 0 else None
            if code not in (0, None) or fail:
                errors.append(f"debug log: {(fail or err or 'not readable').strip()[:200]}")
    return outs, '; '.join(errors), log


def _engine_read(s):
    path = lu.find_lmutil(s.get('lmutil_path') or '')
    if not path:
        return [], 'lmutil not found on the engine: put it at /opt/moavi/lmutil/lmutil or name its path'
    outs, errors = [], []
    for port in _ports(s):
        code, out, err = lu.run_lmutil(path, port, s['host'])
        outs.append(out)
        if code is None or (code != 0 and not out):
            errors.append(err or f'lmstat exit {code}')
    return outs, '; '.join(errors)


def collect(s, now=None):
    """Read one server's seats, keep them, alert on a threshold. Returns (parsed | None, error)."""
    mode = s.get('usage_mode') or 'off'
    if mode == 'off':
        return None, 'off'
    log = None
    if mode == 'engine':
        outs, err = _engine_read(s)
    else:
        mgr, node, err = _guest(s)
        outs = []
        if mgr:
            outs, err, log = _guest_read(mgr, node, s, with_log=True)
    parsed = lu.merge([lu.parse_lmstat(o) for o in outs]) if outs else None
    if parsed and parsed['features']:
        at = lu.record(s['id'], parsed, now)
        new = lu.record_denials(s['id'], lu.parse_denials(log)) if log else 0
        catalog.mark_license_usage(s['id'], True, err if err.startswith('debug log') else '')
        _alerts(s, parsed['features'], new)
        if new:
            from pegaprox.api.vlab_ops_notices import license_denied
            license_denied(s, new)
        return dict(parsed, at=at, denied_new=new), ''
    err = err or (parsed or {}).get('error') or 'lmstat returned no counted features'
    catalog.mark_license_usage(s['id'], False, err)
    return parsed, err


def _alerts(s, features, denied_new):
    events, state = lu.seat_alerts(s, features)
    if state != (s.get('seat_alerted') or {}):
        catalog.mark_license_seat_alerted(s['id'], state)
    for e in events:
        f, n = e['feature'], f"{e['in_use']}/{e['total']}"
        if e['level'] == 'ok':
            title = f"라이선스 여유: {s['name']} {f}"
            text = f"{s['name']} 의 {f} 사용이 {n} ({e['pct']}%) 로 기준 {e['threshold']}% 아래로 내려왔습니다."
        elif e['level'] == 'full':
            title = f"라이선스 없음: {s['name']} {f}"
            text = f"{s['name']} 의 {f} 라이선스가 모두 사용 중입니다 ({n}). 더 받으려는 사용자는 거부됩니다."
        else:
            title = f"라이선스 사용 {e['pct']}%: {s['name']} {f}"
            text = f"{s['name']} 의 {f} 사용이 {n} ({e['pct']}%) 로 기준 {e['threshold']}% 를 넘었습니다."
        nxt._alert(title, text, {'kind': f"license_seats_{e['level']}", 'server': s['name'], 'host': s['host'], 'feature': f,
                                 'in_use': e['in_use'], 'total': e['total'], 'severity': 'info' if e['level'] == 'ok' else 'warning'},
                   channels=s.get('alert_channels'))
        log_audit('system', 'vlab.license.seats', f"licence server '{s['name']}' {f}: {n} ({e['level']})", '')


def usage_tick(now=None):
    """Every server with seats on (license_tick, every 5 minutes). Returns how many were read."""
    n = 0
    for s in catalog.list_license_servers():
        if (s.get('usage_mode') or 'off') == 'off':
            continue
        try:
            collect(s, now)
        except Exception as e:
            logging.warning(f"[VLAB] licence seats of {s['name']}: {e}")
            catalog.mark_license_usage(s['id'], False, str(e)[:300])
        n += 1
    if time.time() - _prune_last[0] > 3600:
        _prune_last[0] = time.time()
        lu.prune()
    return n


# --- settings ------------------------------------------------------------------------------

def _settings_body(s):
    data = nxt._body()
    mode = str(data.get('mode') or 'off')
    if mode not in lu.MODES:
        raise ValueError('mode must be off, engine or agent')
    lm_ports = data.get('lm_ports') or []
    if isinstance(lm_ports, str):
        lm_ports = [p for p in lm_ports.replace(',', ' ').split() if p]
    try:
        lm_ports = sorted({int(p) for p in lm_ports})
    except (TypeError, ValueError):
        raise ValueError('lm_ports must be numbers')
    if len(lm_ports) > 5 or any(not 1 <= p <= 65535 for p in lm_ports):
        raise ValueError('lm_ports: up to 5 ports, 1 to 65535')
    if mode == 'agent' and not (s.get('cluster_id') and s.get('vmid')):
        raise ValueError('agent mode needs the licence server VM: set its cluster and VMID first')
    threshold = nxt._int(data, 'seat_threshold', 0, 100, 90)
    per = data.get('feature_thresholds') or {}
    if not isinstance(per, dict) or len(per) > 200:
        raise ValueError('feature_thresholds: {feature: percent}, at most 200')
    clean = {}
    for k, v in per.items():
        k = str(k).strip()
        if not k or len(k) > 100:
            raise ValueError('feature_thresholds: a feature name of 1 to 100 characters')
        try:
            v = int(v)
        except (TypeError, ValueError):
            raise ValueError(f'feature_thresholds.{k} must be a number')
        if not 0 <= v <= 100:
            raise ValueError(f'feature_thresholds.{k} must be 0 to 100')
        clean[k] = v
    channels = data.get('alert_channels')
    if channels is not None:
        if not isinstance(channels, list) or len(channels) > 50:
            raise ValueError('alert_channels: a list of channel ids, or null for every channel')
        channels = [str(c)[:64] for c in channels]
    return (mode, lm_ports, lu.check_tool_path(data.get('lmutil_path')), lu.check_log_path(data.get('debug_log')),
            threshold, clean, channels)


@bp.route('/api/vlab/admin/license-servers/<lid>/usage-settings', methods=['PUT'])
@require_auth(perms=['vlab.accel.manage'])
def save_usage_settings(lid):
    s = _server(lid)
    if not s:
        return _bad('Licence server not found', 404)
    try:
        args = _settings_body(s)
    except ValueError as e:
        return _bad(str(e))
    s = catalog.save_license_usage_settings(lid, *args)
    log_audit(_user(), 'vlab.license.usage', f"licence server '{s['name']}': seats {args[0]}, threshold {args[4]}%", get_client_ip())
    return jsonify({'settings': settings_view(s), 'lmutil': lu.find_lmutil(s.get('lmutil_path') or '') if args[0] == 'engine' else ''})


@bp.route('/api/vlab/admin/license-servers/<lid>/usage/collect', methods=['POST'])
@require_auth(perms=['vlab.accel.manage'])
def collect_now(lid):
    s = _server(lid)
    if not s:
        return _bad('Licence server not found', 404)
    if (s.get('usage_mode') or 'off') == 'off':
        return _bad('Seat reading is off for this licence server', 409)
    parsed, err = collect(s)
    feats = [{k: f[k] for k in ('feature', 'vendor', 'total', 'in_use', 'queued')} for f in (parsed or {}).get('features') or []]
    return jsonify({'ok': not err, 'error': err, 'features': feats, 'settings': settings_view(catalog.get_license_server(lid))})


# --- the view ------------------------------------------------------------------------------

def _desktop_index():
    pools = {p['id']: p['name'] for p in store.list_pools()}
    by_name, by_user = {}, {}
    desks = {d['id']: d for d in store.list_desktops()}
    for d in desks.values():
        by_name.setdefault(str(d['name']).lower().split('.')[0], d)
    for sess in store.open_sessions():
        d = desks.get(sess.get('desktop_id'))
        if d and d not in by_user.setdefault(sess['username'], []):
            by_user[sess['username']].append(d)
    return by_name, by_user, pools


def _holder_view(h, at, index):
    by_name, by_user, pools = index
    desk, how = lu.match_desktop(h['host'], h['display'], by_name, by_user.get(h['username'], []))
    return {'user': h['username'], 'host': h['host'], 'display': h['display'], 'version': h['version'], 'count': h['count'],
            'since': h['started'], 'minutes': max(0, (at - h['started']) // 60),
            'desktop': {'id': desk['id'], 'name': desk['name'], 'pool': pools.get(desk['pool_id'], ''), 'match': how} if desk else None}


@bp.route('/api/vlab/admin/license-servers/<lid>/usage', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def usage(lid):
    s = _server(lid)
    if not s:
        return _bad('Licence server not found', 404)
    try:
        hours = max(1, min(24 * lu.KEEP_DAYS, int(request.args.get('hours') or 24)))
    except ValueError:
        return _bad('hours must be a number')
    now = int(time.time())
    since = now - hours * 3600
    rows = lu.samples(lid, since)
    stats = lu.feature_stats(rows)
    at = lu.latest_at(lid)
    cur = {r['feature']: r for r in rows if r['at'] == at} if at else {}
    if at and not cur:
        cur = {r['feature']: r for r in lu.samples(lid, at, at)}
    holders = {}
    if at:
        index = _desktop_index()
        for h in lu.holders_at(lid, at):
            holders.setdefault(h['feature'], []).append(_holder_view(h, at, index))
    denied = lu.denials(lid, since)
    denied_by = {}
    for d in denied:
        denied_by[d['feature']] = denied_by.get(d['feature'], 0) + 1
    features = []
    for name in sorted(set(cur) | set(stats), key=str.lower):
        c, st = cur.get(name), stats.get(name) or {}
        total = c['total'] if c else st.get('total', 0)
        in_use = c['in_use'] if c else 0
        features.append({'feature': name, 'vendor': (c or st).get('vendor', ''), 'total': total, 'in_use': in_use,
                         'queued': c['queued'] if c else 0, 'pct': round(100.0 * in_use / total) if total else 0,
                         'threshold': lu.threshold_of(s, name), 'alerted': (s.get('seat_alerted') or {}).get(name, ''),
                         'current': bool(c), 'holders': holders.get(name, []),
                         'peak': st.get('peak', 0), 'avg': st.get('avg', 0.0), 'shortage_count': st.get('shortage_count', 0),
                         'shortage_minutes': st.get('shortage_minutes', 0), 'denied': denied_by.get(name, 0)})
    bucket = 3600 if hours <= 72 else 86400
    out = {'server': {'id': s['id'], 'name': s['name'], 'host': s['host']}, 'settings': settings_view(s), 'at': at, 'hours': hours,
           'bucket': bucket, 'features': features, 'series': lu.series(rows, bucket),
           'denials': [{'at': d['at'], 'feature': d['feature'], 'user': d['username'], 'host': d['host'], 'kind': d['kind'],
                        'reason': d['reason']} for d in denied[:50]],
           'denied_total': len(denied)}
    if out['settings']['mode'] == 'engine':
        out['lmutil'] = lu.find_lmutil(s.get('lmutil_path') or '')
    return jsonify(out)


# --- the report ----------------------------------------------------------------------------

@bp.route('/api/vlab/admin/reports/licenses', methods=['GET'])
@require_auth(perms=['vlab.report.view'])
def license_report():
    """Per feature: seats, peak and average in use, time with every seat taken, refusals and
    what that suggests (add / reduce / keep). Per user: hours a seat was held."""
    try:
        days = max(1, min(lu.KEEP_DAYS, int(request.args.get('days') or 30)))
    except ValueError:
        return _bad('days must be a number')
    view = request.args.get('view') or 'features'
    if view not in ('features', 'users'):
        return _bad('view must be features or users')
    only = request.args.get('server_id') or ''
    servers = {s['id']: s for s in catalog.list_license_servers() if not s['cluster_id'] or core._can_reach(s['cluster_id'])}
    if only and only not in servers:
        return _bad('Licence server not found', 404)
    ids = [only] if only else list(servers)
    now = int(time.time())
    since = now - days * 86400
    features, users = [], []
    for sid in ids:
        name = servers[sid]['name']
        denied = {}
        for d in lu.denials(sid, since):
            denied[d['feature']] = denied.get(d['feature'], 0) + 1
        for f, st in sorted(lu.feature_stats(lu.samples(sid, since)).items(), key=lambda kv: kv[0].lower()):
            features.append({'server_id': sid, 'server': name, **st, 'denied': denied.get(f, 0),
                             'advice': lu.advice(st, denied.get(f, 0))})
        for u in lu.user_hours(lu.checkouts(sid, since, now), since, now):
            users.append({**u, 'server': name})
    users.sort(key=lambda r: (-r['hours'], r['user']))
    if request.args.get('format') == 'csv':
        if view == 'users':
            lines = ['user,server,feature,hours,checkouts,hosts']
            for r in users:
                lines.append(','.join([nxt._csv(r['user']), nxt._csv(r['server']), nxt._csv(r['feature']), str(r['hours']),
                                       str(r['checkouts']), nxt._csv(' '.join(r['hosts']))]))
        else:
            lines = ['server,feature,vendor,seats,peak,peak_pct,average,average_pct,shortage_minutes,shortages,denied,samples,advice,advice_seats']
            for r in features:
                lines.append(','.join([nxt._csv(r['server']), nxt._csv(r['feature']), nxt._csv(r['vendor']), str(r['total']), str(r['peak']),
                                       str(r['peak_pct']), str(r['avg']), str(r['avg_pct']), str(r['shortage_minutes']),
                                       str(r['shortage_count']), str(r['denied']), str(r['samples']), r['advice']['action'],
                                       str(r['advice']['seats'])]))
        stamp = datetime.now().strftime('%Y%m%d')
        return Response('﻿' + '\n'.join(lines) + '\n', mimetype='text/csv; charset=utf-8',
                        headers={'Content-Disposition': f'attachment; filename="license-{view}-{days}d-{stamp}.csv"'})
    return jsonify({'days': days, 'interval': lu.INTERVAL, 'features': features, 'users': users,
                    'servers': [{'id': i, 'name': servers[i]['name'], 'mode': servers[i].get('usage_mode') or 'off'} for i in servers]})
