# -*- coding: utf-8 -*-
"""
하드웨어(BMC) 상태 이력 — 보고서의 '기간 중 하드웨어 이상' 용

5분마다 도는 메트릭 수집(background/metrics.py)이 노드별 하드웨어 요약(in-band ipmitool 우선,
없으면 Redfish — #609)을 캐시에 넣을 때 record() 를 불러, **상태가 바뀐 순간**만 기록한다.
  hw_state   노드별 마지막 상태 (종합 상태·이상 항목·처음 기록 시각)
  hw_events  발생(new) · 등급 상승(escalated) · 복구(recovered)

report_hardware() 가 보고 기간 [from, to) 의 서버별 이상(발생·복구 시각·횟수·기간 전부터 지속 여부)과
지금 상태를 한국형 보고서(api/korean_reports.py) 형식으로 돌려준다.
지난 기간 보고서에는 그 기간에 있었던 이상만, 기간에 지금이 들어 있으면 현재 상태도.

원본: 하드웨어 감시(incidentsInPeriod) 설계를 이식. AGPL-3.0
"""

import json
import logging
import threading
import time

_RANK = {'warning': 1, 'critical': 2}
_ROLLUP = '__rollup__'          # 이상 항목 없이 종합 상태만 나쁠 때의 항목 키
_RETENTION_MS = 400 * 86_400_000  # 보고서 최대 기간(1년) + 여유
_ensured = False
_ensure_lock = threading.Lock()
_last_prune = 0.0


def _db():
    from pegaprox.core.db import get_db
    return get_db()


def _ensure():
    global _ensured
    if _ensured:
        return
    with _ensure_lock:
        if _ensured:
            return
        db = _db()
        db.execute('''CREATE TABLE IF NOT EXISTS hw_state (
            cluster_id TEXT NOT NULL, node TEXT NOT NULL,
            health TEXT NOT NULL, items TEXT NOT NULL, source TEXT,
            first_seen REAL NOT NULL, updated REAL NOT NULL,
            PRIMARY KEY (cluster_id, node))''')
        db.execute('''CREATE TABLE IF NOT EXISTS hw_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL, cluster_id TEXT NOT NULL, node TEXT NOT NULL,
            kind TEXT NOT NULL, severity TEXT NOT NULL, item TEXT NOT NULL, source TEXT)''')
        db.execute('CREATE INDEX IF NOT EXISTS idx_hw_events_cluster_ts ON hw_events(cluster_id, ts)')
        _ensured = True


def _norm_health(h):
    h = str(h or 'ok').lower()
    return h if h in ('ok', 'warning', 'critical') else 'ok'


def item_text(item):
    """이상 항목 키 → {'ko','en'} 문구"""
    s = str(item or '')
    if s == _ROLLUP:
        return {'ko': 'BMC 종합 상태 이상', 'en': 'BMC overall health degraded'}
    if s.lower().startswith('sel:'):
        x = s[4:].strip()
        return {'ko': f'BMC 이벤트 로그: {x}', 'en': f'BMC event log: {x}'}
    if s.lower() == 'chassis intrusion':
        return {'ko': '섀시 열림 감지', 'en': 'Chassis intrusion'}
    return {'ko': f'센서 이상: {s}', 'en': f'Sensor: {s}'}


def record(cluster_id, node, summ, now_ms=None):
    """메트릭 수집이 노드 하드웨어 요약을 갱신할 때마다 — 바뀐 것만 기록. 실패해도 수집에는 영향 없게 호출 쪽이 감쌈"""
    global _last_prune
    if not isinstance(summ, dict) or not summ.get('available'):
        return  # 읽지 못한 회차는 상태를 바꾸지 않음 (일시적인 SSH·BMC 오류로 '복구'가 찍히지 않게)
    _ensure()
    now = float(now_ms if now_ms is not None else time.time() * 1000)
    health = _norm_health(summ.get('health'))
    items = set() if health == 'ok' else {str(x) for x in (summ.get('bad') or []) if x}
    if health != 'ok' and not items:
        items = {_ROLLUP}
    sev = 'critical' if health == 'critical' else 'warning'
    source = summ.get('source') or 'inband'
    db = _db()
    prev = db.query_one('SELECT health, items, first_seen FROM hw_state WHERE cluster_id = ? AND node = ?', (cluster_id, node))
    events = []
    if prev is None:
        events += [('new', sev, it) for it in sorted(items)]
        first_seen = now
    else:
        p_health = _norm_health(prev['health'])
        p_items = set(json.loads(prev['items'] or '[]'))
        p_sev = 'critical' if p_health == 'critical' else 'warning'
        events += [('new', sev, it) for it in sorted(items - p_items)]
        events += [('recovered', p_sev, it) for it in sorted(p_items - items)]
        if p_health == 'warning' and health == 'critical':
            events += [('escalated', 'critical', it) for it in sorted(items & p_items)]
        first_seen = prev['first_seen']
    db.execute('''INSERT INTO hw_state (cluster_id, node, health, items, source, first_seen, updated)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cluster_id, node) DO UPDATE SET health = ?, items = ?, source = ?, updated = ?''',
               (cluster_id, node, health, json.dumps(sorted(items)), source, first_seen, now,
                health, json.dumps(sorted(items)), source, now))
    for kind, s, it in events:
        db.execute('INSERT INTO hw_events (ts, cluster_id, node, kind, severity, item, source) VALUES (?, ?, ?, ?, ?, ?, ?)',
                   (now, cluster_id, node, kind, s, it, source))
    if time.time() - _last_prune > 86400:
        _last_prune = time.time()
        try:
            db.execute('DELETE FROM hw_events WHERE ts < ?', (now - _RETENTION_MS,))
        except Exception as e:
            logging.debug(f'[hw_history] prune failed: {e}')


def incidents_in_period(events, from_ms, to_ms):
    """노드 하나의 이벤트(시간순 정렬 무관) → 보고 기간 [from_ms, to_ms) 의 이상 목록
    MAKUS vLAB incidentsInPeriod 와 같은 규칙: 기간 전에 생겨 이어진 것은 carried, 'new' 만 횟수로 셈, 복구 시각은 기간 뒤 것까지"""
    evs = sorted(events, key=lambda e: e['ts'])
    done, cur, before = [], {}, {}
    for e in evs:
        if e['ts'] >= to_ms:
            break
        k = e['item']
        if e['kind'] == 'recovered':
            it = cur.get(k) or (before.get(k) if e['ts'] >= from_ms else None)
            if it:
                it['recoveredAt'] = e['ts']
                done.append(it)
            cur.pop(k, None)
            before.pop(k, None)
            continue
        if e['ts'] < from_ms:
            o = before.get(k)
            if o:
                if _RANK.get(e['severity'], 0) > _RANK.get(o['severity'], 0):
                    o['severity'] = e['severity']
            else:
                before[k] = {'key': k, 'severity': e['severity'], 'at': e['ts'], 'count': 0, 'recoveredAt': None, 'carried': True}
            continue
        it = cur.get(k) or before.get(k)
        if it:
            if e['kind'] == 'new':
                it['count'] += 1  # 등급 상승은 횟수로 세지 않음
            if _RANK.get(e['severity'], 0) > _RANK.get(it['severity'], 0):
                it['severity'] = e['severity']
            if k not in cur:
                cur[k] = it
                before.pop(k, None)
        else:
            cur[k] = {'key': k, 'severity': e['severity'], 'at': e['ts'], 'count': 1, 'recoveredAt': None, 'carried': False}
    for k, o in before.items():
        cur.setdefault(k, o)
    for it in cur.values():
        r = next((e for e in evs if e['kind'] == 'recovered' and e['item'] == it['key'] and e['ts'] > it['at'] and e['ts'] >= to_ms), None)
        if r:
            it['recoveredAt'] = r['ts']
        done.append(it)
    for it in done:
        it['text'] = item_text(it['key'])
    return sorted(done, key=lambda x: x['at'])


def report_hardware(nodes_by_cluster, from_ms, to_ms, now_ms=None):
    """한국형 보고서 '하드웨어 상태 (BMC)' 자료 — nodes_by_cluster: {cluster_id: {node, ...}} (사용자가 볼 수 있는 노드만)
    하드웨어 감시 기록이 하나도 없으면 None (보고서에서 항목을 뺌)"""
    if not nodes_by_cluster:
        return None
    _ensure()
    now = float(now_ms if now_ms is not None else time.time() * 1000)
    db = _db()
    cids = list(nodes_by_cluster)
    ph = ','.join('?' * len(cids))
    states = [s for s in db.query(f'SELECT * FROM hw_state WHERE cluster_id IN ({ph})', tuple(cids))
              if s['node'] in nodes_by_cluster.get(s['cluster_id'], set())]
    if not states:
        return None
    rows = db.query(f'SELECT ts, cluster_id, node, kind, severity, item FROM hw_events WHERE cluster_id IN ({ph}) AND ts < ? ORDER BY ts',
                    tuple(cids) + (max(to_ms, now) + 1,))
    by_node = {}
    for r in rows:
        by_node.setdefault((r['cluster_id'], r['node']), []).append(
            {'ts': r['ts'], 'kind': r['kind'], 'severity': r['severity'], 'item': r['item']})
    live = to_ms > now
    servers = []
    for s in sorted(states, key=lambda x: (x['cluster_id'], x['node'])):
        evs = by_node.get((s['cluster_id'], s['node']), [])
        health = _norm_health(s['health'])
        sev = 'critical' if health == 'critical' else 'warning'
        alarms = []
        if live:
            for it in json.loads(s['items'] or '[]'):
                since = max((e['ts'] for e in evs if e['item'] == it and e['kind'] == 'new'), default=s['updated'])
                alarms.append({'key': it, 'severity': sev, 'text': item_text(it), 'since': since})
        servers.append({
            'name': s['node'], 'node': None, 'checked': True, 'reachable': True,
            'health': {'ok': 'OK', 'warning': 'Warning', 'critical': 'Critical'}[health],
            'source': s['source'], 'alarms': alarms,
            'incidents': incidents_in_period(evs, from_ms, to_ms),
        })
    covered_from = min(s['first_seen'] for s in states)
    return {
        'at': max(s['updated'] for s in states),
        'live': live,
        'covered': covered_from < to_ms,
        'coveredFrom': covered_from,
        'servers': servers,
    }
