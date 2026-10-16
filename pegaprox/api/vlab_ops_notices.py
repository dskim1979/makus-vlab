"""MOAVI Desk: notices for the administrators about running the service (pegaprox/vlab/ops_notices.py).

  GET  /api/vlab/admin/ops-notices    {settings, task_types}     admin.settings
  PUT  /api/vlab/admin/ops-notices    {terminal_pending?, terminal_every_min?, license_denied?,
                                       pair?, pair_down_min?, task_failed?, task_types?, channels?}

ops_tick (the minute loop, pegaprox/vlab/loans.py, on the active only) looks at the lab PCs
waiting, the server pair and the clusters' long tasks; license_denied is called by the
licence seat check (pegaprox/api/vlab_license.py) when it reads new refusals.
"""
import logging
import time

from flask import Blueprint, jsonify, request

from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import ops_notices as ops

bp = Blueprint('vlab_ops_notices', __name__)

TASK_EVERY = 120
_task_last = [0.0]


@bp.route('/api/vlab/admin/ops-notices', methods=['GET'])
@require_auth(perms=['admin.settings'])
def get_ops_notices():
    return jsonify({'settings': ops.get_settings(), 'task_types': ops.TASK_TYPES})


@bp.route('/api/vlab/admin/ops-notices', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def put_ops_notices():
    try:
        s = ops.save_settings(request.get_json(silent=True))
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    on = [k for k in ('terminal_pending', 'license_denied', 'pair', 'task_failed') if s[k]]
    log_audit(request.session.get('user', ''), 'vlab.ops_notices', f"operations notices: {', '.join(on) or 'none'}", get_client_ip())
    return jsonify({'settings': s, 'task_types': ops.TASK_TYPES})


def _send(title, text, data, s=None):
    s = s or ops.get_settings()
    try:
        from pegaprox.api.vlab_next import _alert
        _alert(title, text, dict(data, source='moavi-desk'), channels=s['channels'] or None)
    except Exception as e:
        logging.warning(f'[VLAB] operations notice: {e}')


# --- lab PCs waiting for approval ------------------------------------------------------------

def terminal_check(s, st, at=None):
    from pegaprox.api.vlab_enroll import settings as install_settings
    from pegaprox.vlab import enroll, store
    pending = enroll.pending_count()
    warn_at = install_settings()['pending_warn']
    what, st = ops.terminal_due(st, pending, warn_at, s['terminal_every_min'], at)
    if not what:
        return st
    rows = [t for t in store.list_terminals() if t.get('state') == 'pending']
    rows.sort(key=lambda t: str(t.get('created_at') or ''), reverse=True)
    names = ', '.join((t.get('name') or t.get('mac') or '?') for t in rows[:10]) + (' 외' if len(rows) > 10 else '')
    if what == 'warn':
        title = f"실습실 PC 승인 대기 {pending}대 (경고 기준 {warn_at}대)"
    else:
        title = f"실습실 PC {pending}대가 승인을 기다립니다"
    text = (f"{title}.\n최근 등록: {names}\n관리 콘솔 LAB > LAB > 단말에서 승인하거나 거절하세요. "
            "모르는 PC면 거절하고 등록 코드를 끄세요.")
    _send(title, text, {'kind': 'terminal_pending', 'pending': pending, 'severity': 'warning' if what == 'warn' else 'info'}, s)
    return st


# --- the server pair -------------------------------------------------------------------------

def pair_check(s, st, at=None):
    from pegaprox.core import ha
    role = ha.role()
    if role != 'active':
        return st
    took, st = ops.promoted(st, role, ha.epoch())
    if took:
        me = ha.own_url() or ha.instance_id()
        title = 'MOAVI Desk 서버 전환: 이 서버가 활성이 되었습니다'
        text = (f"{me} 가 활성 서버가 되었습니다(승격 또는 장애 전환). 예전 활성 서버의 상태를 확인하고, "
                "고친 뒤 대기 서버로 다시 붙이세요. 플랫폼 설정 > 서버 이중화.")
        _send(title, text, {'kind': 'pair_promoted', 'server': me, 'severity': 'critical'}, s)
    events, st = ops.pair_events(st, ha.members(), s['pair_down_min'], at)
    for e in events:
        m = e['member']
        who = m.get('url') or m.get('instance_id')
        site = f" ({m['site']})" if m.get('site') else ''
        if e['event'] == 'down':
            title = f"대기 서버 응답 없음: {who}"
            text = (f"대기 서버 {who}{site} 가 {s['pair_down_min']}분 넘게 응답하지 않습니다"
                    + (f" (마지막 응답 {e['since'][:16].replace('T', ' ')} UTC)" if e.get('since') else '')
                    + ". 지금 활성 서버가 멈추면 넘겨받을 서버가 없습니다." + (f"\n오류: {m['last_error']}" if m.get('last_error') else ''))
            sev = 'critical'
        else:
            title = f"대기 서버 복구: {who}"
            text = f"대기 서버 {who}{site} 가 다시 응답합니다."
            sev = 'info'
        _send(title, text, {'kind': f"pair_{e['event']}", 'member': who, 'severity': sev}, s)
    return st


# --- long tasks that failed ------------------------------------------------------------------

def _clusters_with_task_rule():
    """Clusters with an enabled alert rule on task_failed (경보 > 경보 규칙): those are told by
    that rule, not twice."""
    try:
        from pegaprox.api.alerts import load_cluster_alerts
        return {cid for cid, rules in (load_cluster_alerts() or {}).items()
                if any(isinstance(r, dict) and r.get('enabled', True) and r.get('metric') == 'task_failed' for r in rules or [])}
    except Exception:
        return set()


def task_check(s, st):
    from pegaprox.api import vlab_next as nxt
    from pegaprox.vlab import store
    cursors = dict(st.get('tasks') or {})
    desks = {(d['cluster_id'], int(d['vmid'])): d for d in store.list_desktops()}
    types = set(s['task_types'])
    ruled = _clusters_with_task_rule()
    for cid, mgr in nxt._task_clusters():
        if cid in ruled:            # an admin set the engine's own 작업 실패 rule there: it tells
            cursors.pop(cid, None)
            continue
        try:
            cname = nxt.core._cluster_name(cid, mgr)
            rows = [nxt._task_row(cid, cname, t, desks) for t in (mgr.get_tasks(limit=100) or [])
                    if isinstance(t, dict) and str(t.get('upid') or '').startswith('UPID:')]
        except Exception as e:
            logging.debug(f'[VLAB] tasks of {cid} for notices: {e}')
            continue
        failed, cursors[cid] = ops.failed_tasks(rows, cursors.get(cid), types)
        for r in failed[:20]:
            what = ops.TASK_TYPES.get(r['type'], r['type'])
            target = (r['desktop'] or {}).get('name') or (f"VM {r['vmid']}" if r['vmid'] is not None else r['node'])
            title = f"작업 실패: {what} - {target}"
            text = (f"{cname} / {r['node']} 의 {what} 작업이 실패했습니다.\n대상: {target}\n"
                    f"결과: {r['status'] or '(알 수 없음)'}\n" + (f"요청한 사람: {r['user']}\n" if r['user'] else '')
                    + "관리 콘솔 운영 > 요약 > 작업 진행에서 로그를 보세요.")
            _send(title, text, {'kind': 'task_failed', 'cluster': cname, 'node': r['node'], 'task': r['type'], 'upid': r['upid'],
                                'vmid': r['vmid'], 'severity': 'warning'}, s)
    st['tasks'] = cursors
    return st


# --- licence refusals ------------------------------------------------------------------------

def license_denied(server, count):
    """The licence seat check read `count` new refusals of `server`."""
    s = ops.get_settings()
    if not s['license_denied'] or count <= 0:
        return
    try:
        from pegaprox.vlab import license_usage as lu
        rows = lu.denials(server['id'], time.time() - 3600, limit=min(count, 50))
    except Exception:
        rows = []
    feats = {}
    for r in rows:
        f = feats.setdefault(r.get('feature') or '?', set())
        if r.get('user'):
            f.add(r['user'])
    detail = '\n'.join(f"- {f}: {', '.join(sorted(u)[:8]) or '-'}" for f, u in sorted(feats.items()))
    title = f"라이선스 거부 {count}건: {server['name']}"
    text = (f"{server['name']} ({server.get('host', '')}) 가 라이선스 요청 {count}건을 거부했습니다(좌석 부족 등).\n"
            + (f"기능 · 사용자:\n{detail}\n" if detail else '') + "가속 자원 > 라이선스 서버 > 좌석에서 쓰는 사람과 추이를 보세요.")
    _send(title, text, {'kind': 'license_denied', 'server': server['name'], 'count': count, 'severity': 'warning'}, s)


# --- the minute loop -------------------------------------------------------------------------

def ops_tick(at=None, force=False):
    from pegaprox.vlab import features
    s = ops.get_settings()
    st0 = ops.state()
    st = dict(st0)
    for on, check in ((s['terminal_pending'] and features.enabled('lab'), lambda x: terminal_check(s, x, at)),
                      (s['pair'], lambda x: pair_check(s, x, at))):
        if not on:
            continue
        try:
            st = check(st)
        except Exception as e:
            logging.warning(f'[VLAB] operations notices: {e}')
    if s['task_failed'] and (force or time.time() - _task_last[0] >= TASK_EVERY):
        _task_last[0] = time.time()
        try:
            st = task_check(s, st)
        except Exception as e:
            logging.warning(f'[VLAB] task failure notices: {e}')
    if st != st0:
        ops.save_state(st)
    return st
