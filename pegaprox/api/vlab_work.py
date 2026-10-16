# -*- coding: utf-8 -*-
"""
MOAVI Desk - long jobs kept alive, GPU / NPU use measured, idle loaned cards reclaimed
(pegaprox/vlab/workload.py).

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

  GET    /api/vlab/me/work                         the caller's desktops: "작업 중", what waits, card use   vlab.desk
  POST   /api/vlab/me/desktops/<id>/hold           {hours, note?} "작업 중 - 끄지 마세요" until then        vlab.desk
  DELETE /api/vlab/me/desktops/<id>/hold           take it off                                            vlab.desk
  GET    /api/vlab/admin/work                      steps put off (waiting and the last 7 days), holds     vlab.pool.view
  POST   /api/vlab/admin/deferrals/<id>/release    let the step run at the next minute                    vlab.pool.manage
  POST   /api/vlab/admin/deferrals/<id>/cancel     the step does not run at all                           vlab.pool.manage
  DELETE /api/vlab/admin/holds/<id>                take a user's "작업 중" off                              vlab.pool.manage
  GET    /api/vlab/admin/work-settings             sampling, the longest hold, reclaim rules             vlab.pool.view
  PUT    /api/vlab/admin/work-settings             {sample_minutes?, retention_days?, hold_max_hours?, reclaim?}  vlab.accel.manage
  GET    /api/vlab/admin/accel-usage               ?desktop_id=|lease_id=&hours= use over time            vlab.pool.view
  GET    /api/vlab/admin/reclaims                  loaned cards suggested for a reclaim                   vlab.accel.manage
  POST   /api/vlab/admin/reclaims/<lease_id>/dismiss   keep the loan; no new suggestion until it is used   vlab.accel.manage

Who asks before acting (each only when the pool's policy has defer_when_busy):
  pegaprox/api/vlab.py policy_tick   idle shutdown ('idle'), session limit ('session_limit')
  pegaprox/api/vlab.py _lab_phase    the end of a LAB class ('lab') or booking ('booking')
  pegaprox/api/schedules.py          a scheduled stop / shutdown / reboot of a desktop ('schedule')
A repeating step asks again every minute; a one-shot step is run later by deferral_tick.
The minute loop (pegaprox/vlab/loans.py) runs deferral_tick and accel_tick.
"""

import logging
import time
from datetime import timedelta

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.core import ha
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import policy as pool_policy
from pegaprox.vlab import store
from pegaprox.vlab import workload as wl

bp = Blueprint('vlab_work', __name__)

_bad = core._bad
_user = core._user
PROBE_WAIT = 8          # seconds the guest gets to print its GPU / CPU figures
RECENT_MINUTES = 15     # a sample this fresh is "now" on the screens
_accel_last = [0.0]

ACTION_KO = {'shutdown': '종료', 'stop': '강제 종료', 'reboot': '재시작', 'reset': '초기화', 'expire': '접속 종료'}
SOURCE_KO = {'idle': '미사용 자동 종료', 'session_limit': '최대 접속 시간', 'lab': 'LAB 시간표 정리',
             'booking': 'LAB 예약 정리', 'schedule': '예약 작업(일정)'}


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def settings():
    from pegaprox.api.helpers import load_server_settings
    return wl.effective_settings((load_server_settings() or {}).get(wl.SETTINGS_KEY))


# --- notices -----------------------------------------------------------------------------

def _mail(username, title, text):
    """To the user's own address, unless they turned work notices off (내 계정 > 알림)."""
    if not username:
        return
    try:
        from pegaprox.vlab import notices
        notices.mail(username, 'work', title, text)
    except Exception as e:
        logging.warning(f'[VLAB] work notice mail: {e}')


def _admins(title, text, data):
    try:
        from pegaprox.api.vlab_next import _alert
        _alert(title, text, dict(data, severity=data.get('severity', 'info')))
    except Exception as e:
        logging.warning(f'[VLAB] work notice alert: {e}')


def _why(reason):
    k = (reason or {}).get('kind')
    if k == 'hold':
        return f"사용자가 '작업 중'으로 표시함 ({str(reason.get('until', ''))[:16].replace('T', ' ')} UTC 까지)"
    if k == 'job':
        return f"빌드 작업 실행 중: {reason.get('job', '')}"
    if k == 'gpu':
        return f"GPU/NPU 사용률 {reason.get('value')}% (기준 {reason.get('threshold')}%)"
    if k == 'cpu':
        return f"CPU 부하 {reason.get('value')}% (기준 {reason.get('threshold')}%)"
    return '작업 중'


def _tell(d, event, desk):
    what = f"{SOURCE_KO.get(d['source'], d['source'])} - {ACTION_KO.get(d['action'], d['action'])}"
    name = desk['name'] if desk else d['desktop_id']
    if event == 'deferred':
        title = f"작업 중이라 미룸: {name}"
        text = (f"데스크톱 {name} 에서 작업이 진행 중이라 '{what}'을(를) 미뤘습니다.\n"
                f"이유: {_why(d['reason'])}\n작업이 끝나면 진행하며, 늦어도 {d['deadline'][:16].replace('T', ' ')} (UTC) 에는 진행합니다.")
    elif event == 'forced':
        title = f"최대 연장 시간 도달: {name}"
        text = f"데스크톱 {name} 의 '{what}'을(를) 최대 연장 시간까지 미뤘으므로 이제 진행합니다. 작업을 저장해 주세요."
    else:
        title = f"미루던 정리 취소: {name}"
        text = f"데스크톱 {name} 의 '{what}'은(는) 진행하지 않습니다: {d.get('result') or event}"
    _mail(d['username'], title, text)
    _admins(title, text, {'kind': f'work_{event}', 'desktop': name, 'user': d['username'], 'action': d['action'],
                          'source': d['source'], 'severity': 'warning' if event == 'forced' else 'info'})


# --- is the desktop working? --------------------------------------------------------------

def _probe(desk, vm):
    """What the guest prints of its GPUs / NPUs and CPU: (parsed, None) or (None, why not).
    A read through the guest agent: the exec only runs the vendors' query tools."""
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return None, 'cluster not connected'
    from pegaprox.api import vlab_next as nx
    node = (vm or {}).get('node') or desk['node']
    with ha.reading():
        os_kind = nx._guest_os(mgr, node, desk['vmid'])
        if os_kind is None:
            return None, 'guest agent not answering'
        code, out, _err, e = nx._agent_run(mgr, node, desk['vmid'], wl.probe_command(os_kind), wait=PROBE_WAIT)
    if e:
        return None, e
    if code is None:
        return None, 'the guest did not answer in time'
    return wl.parse_probe(out), None


def busy_reason(desk, pol, vm=None, at=None):
    """Why the desktop counts as working, or None: the user's hold, a build job on it, then the
    GPU / CPU figures read from the guest (a running qemu desktop only)."""
    at_iso = wl.iso(at) if at else store.now()
    h = wl.active_hold(desk['id'], at_iso)
    if h:
        return {'kind': 'hold', 'until': h['until'], 'by': h['username'], 'note': h['note']}
    from pegaprox.vlab import catalog
    job = next((j for j in catalog.jobs_in('running') if j['desktop_id'] == desk['id']), None)
    if job:
        return {'kind': 'job', 'job': job['name'], 'by': job['username']}
    if desk.get('vm_type', 'qemu') != 'qemu' or not vm or vm.get('status') != 'running':
        return None
    probe, _e = _probe(desk, vm)
    return wl.busy_from_probe(probe, pol)


def defer(desk, pool, action, source, source_id='', vm=None, at=None, username=''):
    """Ask before a step that stops or rolls back the desktop. True: it is working, leave it
    (the step waits, up to the pool's defer_max_hours); False: go ahead."""
    pol = pool_policy.effective((pool or {}).get('settings'))
    if not desk or not pol['defer_when_busy']:
        return False
    at = at or wl.utcnow()
    d = wl.waiting(desk['id'], action, source, source_id)
    if d and at >= wl.ts(d['deadline']):
        wl.finish(d['id'], 'forced', 'longest extension reached')
        log_audit('system', 'vlab.work.forced', f"{source} {action} of '{desk['name']}' after {pol['defer_max_hours']} h of waiting")
        _tell(d, 'forced', desk)
        return False
    if d and (at - wl.ts(d['checked_at'])).total_seconds() < wl.RECHECK_SECONDS:
        return True
    try:
        reason = busy_reason(desk, pol, vm, at)
    except Exception as e:
        logging.warning(f"[VLAB] busy check of {desk['name']}: {e}")
        reason = None
    if reason:
        if d:
            wl.recheck(d['id'], reason, at)
            return True
        user = username or desk.get('assigned_user') or reason.get('by') or ''
        d = wl.add_deferral(desk['id'], action, source, source_id, user, reason, at,
                            at + timedelta(hours=pol['defer_max_hours']))
        log_audit('system', 'vlab.work.defer', f"{source} {action} of '{desk['name']}' put off: {_why(reason)}")
        _tell(d, 'deferred', desk)
        return True
    if d:
        wl.finish(d['id'], 'done', 'not working any more')
    return False


def deferred_desktops():
    return {d['desktop_id'] for d in wl.deferrals('waiting')}


def drop_on_prepare(desk):
    """A new class or booking starts on the desktop: what the last one put off is not done."""
    for d in wl.drop_waiting(desk['id'], ('lab', 'booking'), 'the next session started'):
        log_audit('system', 'vlab.work.dropped', f"{d['source']} {d['action']} of '{desk['name']}': the next session started")
        _tell(dict(d, result='다음 수업/예약이 시작됨'), 'dropped', desk)


def defer_scheduled(cluster_id, vmid, action, schedule_id=''):
    """pegaprox/api/schedules.py: a scheduled stop / shutdown / reboot of a desktop VM."""
    desk = store.desktop_for_vm(cluster_id, vmid)
    if not desk:
        return False
    vm = core._vm_states(cluster_id).get(int(vmid))
    if not vm or vm.get('status') != 'running':
        return False
    return defer(desk, store.get_pool(desk['pool_id']), action, 'schedule', str(schedule_id or ''), vm=vm)


def deferral_tick(now=None):
    """Once a minute: run the one-shot steps (LAB / booking clean-up, scheduled stop) whose
    desktop stopped working or whose longest extension is over; close the repeating ones nobody
    asks about any more. Returns {'done': n, 'forced': n, 'dropped': n, 'failed': n}."""
    at = now or wl.utcnow()
    out = {'done': 0, 'forced': 0, 'dropped': 0, 'failed': 0}
    for d in wl.stale_waiting(at - timedelta(minutes=10)):
        wl.finish(d['id'], 'dropped', 'not due any more')
        out['dropped'] += 1
    open_now = store.open_session_desktops()
    live = {}
    for d in wl.deferrals('waiting'):
        if d['source'] not in wl.ONE_SHOT:
            continue
        desk = store.get_desktop(d['desktop_id'])
        if not desk:
            wl.finish(d['id'], 'dropped', 'desktop removed')
            out['dropped'] += 1
            continue
        if d['source'] in ('lab', 'booking') and desk['id'] in open_now:
            wl.finish(d['id'], 'dropped', 'in use again')
            out['dropped'] += 1
            continue
        if desk['cluster_id'] not in live:
            live[desk['cluster_id']] = core._vm_states(desk['cluster_id'])
        vm = live[desk['cluster_id']].get(int(desk['vmid']))
        if not vm:
            continue
        pool = store.get_pool(desk['pool_id']) or {}
        forced = at >= wl.ts(d['deadline'])
        if not forced:
            if (at - wl.ts(d['checked_at'])).total_seconds() < wl.RECHECK_SECONDS:
                continue
            reason = busy_reason(desk, pool_policy.effective(pool.get('settings')), vm, at)
            if reason:
                wl.recheck(d['id'], reason, at)
                continue
        mgr = cluster_managers.get(desk['cluster_id'])
        err = None
        if d['action'] == 'reset':
            if not desk.get('base_snap'):
                wl.finish(d['id'], 'dropped', 'no base snapshot')
                out['dropped'] += 1
                continue
            if not ha.confirm_step(f"vLAB deferred reset {desk['id']}"):
                break
            err = core._reset_one(desk)
        else:
            if vm.get('status') != 'running':
                wl.finish(d['id'], 'done', 'already stopped')
                out['done'] += 1
                continue
            if not ha.confirm_step(f"vLAB deferred {d['action']} {desk['id']}"):
                break
            r = mgr.vm_action(vm.get('node') or desk['node'], int(desk['vmid']), desk['vm_type'], d['action']) if mgr else None
            if not (isinstance(r, dict) and r.get('success')):
                err = str((r or {}).get('error') if isinstance(r, dict) else r or 'cluster not connected')[:200]
        if err:
            wl.finish(d['id'], 'failed', err)
            out['failed'] += 1
        else:
            wl.finish(d['id'], 'forced' if forced else 'done', 'longest extension reached' if forced else 'work finished')
            out['forced' if forced else 'done'] += 1
            if forced:
                _tell(d, 'forced', desk)
            # a classroom desktop goes back to nobody once its clean-up ran (as _lab_phase does)
            if d['source'] in ('lab', 'booking') and pool.get('type') == 'classroom' and desk['assigned_user'] \
                    and desk['id'] not in open_now and core._acl_set(desk['cluster_id'], desk['vmid'], desk['assigned_user'], False):
                store.set_assignment(desk['id'], None)
        log_audit('system', f"vlab.work.{'failed' if err else 'run'}",
                  f"{d['source']} {d['action']} of '{desk['name']}' put off since {d['first_at'][:16]}: "
                  + (err or ('longest extension reached' if forced else 'work finished')))
    return out


# --- GPU / NPU use -------------------------------------------------------------------------

def _card_desktops():
    """[(desk, lease or None, card name)] - desktops that hold a card: a loan or the pool's GPU."""
    leases = {(l['cluster_id'], int(l['vmid'])): l for l in store.list_leases(active_only=True)
              if l.get('vmid') is not None}
    pools = {p['id']: p for p in store.list_pools()}
    out = []
    for d in store.list_desktops():
        if d.get('vm_type', 'qemu') != 'qemu':
            continue
        lease = leases.get((d['cluster_id'], int(d['vmid'])))
        gpu = core._gpu_policy((pools.get(d['pool_id']) or {}).get('settings'))
        if lease:
            out.append((d, lease, lease['resource_name'] or lease['resource_id']))
        elif gpu:
            out.append((d, None, gpu.get('label') or gpu.get('mdev_type') or gpu.get('mapping') or 'GPU'))
    return out


def sample_now(at=None):
    """Read every card desktop once. Returns the number of sample rows written."""
    cfg = settings()
    at = at or wl.utcnow()
    at_iso = wl.iso(at)
    minutes = cfg['sample_minutes']
    users = {}
    for s in store.open_sessions():
        users.setdefault(s['desktop_id'], s['username'])
    live, rows = {}, []
    for desk, lease, card in _card_desktops():
        if desk['cluster_id'] not in live:
            live[desk['cluster_id']] = core._vm_states(desk['cluster_id'])
        vm = live[desk['cluster_id']].get(int(desk['vmid']))
        base = {'at': at_iso, 'minutes': minutes, 'cluster_id': desk['cluster_id'], 'vmid': int(desk['vmid']),
                'desktop_id': desk['id'], 'lease_id': lease['id'] if lease else '', 'card': card,
                'username': (lease or {}).get('username') or users.get(desk['id']) or desk.get('assigned_user') or ''}
        if not vm or vm.get('status') != 'running':
            if lease:   # a card on a stopped desktop is held and unused
                rows.append(dict(base, vendor='', idx=0, name='', util=None, status='off'))
            continue
        probe, err = _probe(desk, vm)
        if probe is None:
            rows.append(dict(base, vendor='', idx=0, name='', util=None, status='no_agent'))
            continue
        if not probe['cards']:
            rows.append(dict(base, vendor='', idx=0, name='', util=None, status='unavailable'))
            continue
        for c in probe['cards']:
            rows.append(dict(base, **c))
    wl.add_samples(rows)
    wl.prune_samples(wl.window_start(at, cfg['retention_days'] * 24))
    return len(rows)


def reclaim_tick(at=None):
    """Loaned cards under the threshold for N hours: tell the user, suggest it to the admins;
    with auto_return, give the card back M hours after the suggestion. Returns
    {'suggested': n, 'returned': n, 'cleared': n}."""
    cfg = settings()
    rc = cfg['reclaim']
    out = {'suggested': 0, 'returned': 0, 'cleared': 0}
    at = at or wl.utcnow()
    active = {l['id']: l for l in store.list_leases(active_only=True)}
    for r in wl.reclaims():
        if r['lease_id'] not in active:
            wl.forget_reclaim(r['lease_id'])
    if not rc['enabled']:
        return out
    since = wl.window_start(at, rc['idle_hours'])
    for lease in active.values():
        if lease.get('resource_type') == 'board' or not lease.get('vmid'):
            continue
        start = wl.ts(lease['starts_at'])
        if not start or at - start < timedelta(hours=rc['idle_hours']):
            continue
        rows = wl.samples(since, lease_id=lease['id'])
        verdict = wl.idle_verdict(rows, rc['threshold_pct'], rc['idle_hours'], cfg['sample_minutes'])
        cur = wl.reclaim(lease['id'])
        desk = store.desktop_for_vm(lease['cluster_id'], lease['vmid'])
        if desk and wl.active_hold(desk['id']):
            verdict = 'active'      # the user said it is working
        if verdict == 'active':
            if cur:
                wl.forget_reclaim(lease['id'])
                out['cleared'] += 1
            continue
        if verdict != 'idle':
            continue
        card = lease['resource_name'] or lease['resource_id']
        if not cur:
            avg = wl.summarize(rows, rc['threshold_pct'])['util_avg']
            wl.suggest_reclaim(lease['id'], since, avg)
            out['suggested'] += 1
            log_audit('system', 'vlab.reclaim.suggest', f"card {card} on qemu/{lease['vmid']} ({lease['username']}): "
                      f"under {rc['threshold_pct']}% for {rc['idle_hours']} h")
            tail = (f" 반납하지 않으면 {rc['auto_return_hours']}시간 뒤 자동으로 반납됩니다." if rc['auto_return'] else '')
            _mail(lease['username'], f"대여한 카드가 쓰이지 않고 있습니다: {card}",
                  f"대여 중인 {card} 의 사용률이 {rc['idle_hours']}시간 동안 {rc['threshold_pct']}% 미만이었습니다. "
                  f"필요하지 않으면 반납해 주세요. 계속 쓰려면 포털에서 '작업 중'을 켜 두세요.{tail}")
            _admins(f"카드 회수 제안: {card}", f"{lease['username']} 님이 대여한 {card} 가 {rc['idle_hours']}시간 동안 "
                    f"사용률 {rc['threshold_pct']}% 미만입니다. 가속 자원 > 카드 대여 현황에서 회수할 수 있습니다.",
                    {'kind': 'card_reclaim', 'card': card, 'user': lease['username']})
            continue
        if cur['state'] != 'suggested' or not rc['auto_return']:
            continue
        if at - wl.ts(cur['suggested_at']) < timedelta(hours=rc['auto_return_hours']):
            continue
        if not ha.confirm_step(f"vLAB idle card return {lease['id']}"):
            break
        err = core.return_lease(lease)
        if err:
            logging.warning(f"[VLAB] idle card {card} not returned: {err}")
            continue
        wl.set_reclaim(lease['id'], state='returned', returned_at=store.now())
        out['returned'] += 1
        log_audit('system', 'vlab.reclaim.return', f"card {card} from qemu/{lease['vmid']} ({lease['username']}): idle")
        _mail(lease['username'], f"쓰이지 않던 카드를 반납했습니다: {card}",
              f"{card} 가 오랫동안 쓰이지 않아 자동으로 반납했습니다. 다시 필요하면 관리자에게 대여를 요청하세요.")
    return out


def accel_tick(force=False):
    """Every sample_minutes from the minute loop: read the card desktops, then the reclaim rules."""
    cfg = settings()
    if not force and time.time() - _accel_last[0] < cfg['sample_minutes'] * 60 - 5:
        return None
    _accel_last[0] = time.time()
    n = sample_now()
    return n, reclaim_tick()


def recent_use(desktop_ids=None):
    """{desktop_id: {util, mem_used_mb, mem_total_mb, status, at, cards}} of the last sample in
    RECENT_MINUTES (the busiest card leads)."""
    since = wl.iso(wl.utcnow() - timedelta(minutes=RECENT_MINUTES))
    out = {}
    for did, rows in wl.latest_per_desktop(since).items():
        if desktop_ids is not None and did not in desktop_ids:
            continue
        ok = [r for r in rows if r['status'] == 'ok']
        top = max(ok, key=lambda r: r['util']) if ok else rows[0]
        out[did] = {'util': top['util'], 'mem_used_mb': top['mem_used_mb'], 'mem_total_mb': top['mem_total_mb'],
                    'status': top['status'], 'at': top['at'], 'vendor': top['vendor'],
                    'cards': [{k: r[k] for k in ('vendor', 'idx', 'name', 'util', 'mem_used_mb', 'mem_total_mb', 'status')}
                              for r in rows]}
    return out


def lease_use(lease_ids, since_iso, threshold=None):
    """{lease_id: summary} of the samples since then"""
    threshold = settings()['reclaim']['threshold_pct'] if threshold is None else threshold
    by = {}
    for r in wl.samples(since_iso):
        if r['lease_id'] in lease_ids:
            by.setdefault(r['lease_id'], []).append(r)
    return {lid: wl.summarize(rows, threshold) for lid, rows in by.items()}


def lease_extras(leases):
    """recent use and reclaim state for lease rows (card loan screens)"""
    use = recent_use()
    desks = {(d['cluster_id'], int(d['vmid'])): d['id'] for d in store.list_desktops()}
    rec = {r['lease_id']: r for r in wl.reclaims()}
    out = {}
    for l in leases:
        did = desks.get((l['cluster_id'], int(l['vmid']))) if l.get('vmid') is not None else None
        r = rec.get(l['id'])
        out[l['id']] = {'use': use.get(did) if did else None,
                        'reclaim': {'state': r['state'], 'suggested_at': r['suggested_at'], 'avg_util': r['avg_util']} if r else None}
    return out


def desktop_work(desk_ids):
    """{desktop_id: {hold, deferrals, use}} for the portal's and the admin's desktop lists"""
    holds = {h['desktop_id']: h for h in wl.holds()}
    waits = {}
    for d in wl.deferrals('waiting', set(desk_ids)):
        waits.setdefault(d['desktop_id'], []).append(_deferral_view(d))
    use = recent_use(set(desk_ids))
    return {did: {'hold': _hold_view(holds.get(did)), 'deferrals': waits.get(did, []), 'use': use.get(did)} for did in desk_ids}


def _hold_view(h):
    return {k: h[k] for k in ('id', 'desktop_id', 'username', 'note', 'until', 'created_at')} if h else None


def _deferral_view(d, desk=None):
    v = {k: d[k] for k in ('id', 'desktop_id', 'action', 'source', 'source_id', 'username', 'reason', 'first_at',
                           'checked_at', 'deadline', 'state', 'ended_at', 'result')}
    if desk is not None:
        v['desktop'] = desk['name'] if desk else None
        v['pool_id'] = desk['pool_id'] if desk else None
    return v


# --- portal ------------------------------------------------------------------------------

def _my_desktop(desktop_id):
    """The caller's desktop: assigned to them, or one they have a session on."""
    desk = store.get_desktop(desktop_id)
    if not desk or not core._can_reach(desk['cluster_id']):
        return None
    me = _user()
    if desk.get('assigned_user') == me:
        return desk
    if any(s['desktop_id'] == desk['id'] and s['username'] == me for s in store.open_sessions()):
        return desk
    return None


@bp.route('/api/vlab/me/work', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_work():
    me = _user()
    mine = {d['id']: d for d in store.desktops_of_user(me) if core._can_reach(d['cluster_id'])}
    for s in store.open_sessions():
        if s['username'] == me and s['desktop_id'] and s['desktop_id'] not in mine:
            d = store.get_desktop(s['desktop_id'])
            if d:
                mine[d['id']] = d
    work = desktop_work(list(mine))
    out = [dict(work[did], id=did, name=d['name']) for did, d in mine.items()]
    return jsonify({'desktops': out, 'hold_max_hours': settings()['hold_max_hours']})


@bp.route('/api/vlab/me/desktops/<desktop_id>/hold', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def set_my_hold(desktop_id):
    desk = _my_desktop(desktop_id)
    if not desk:
        return _bad('desktop not found', 404)
    data = _body()
    hours = data.get('hours')
    top = settings()['hold_max_hours']
    if not isinstance(hours, (int, float)) or isinstance(hours, bool) or not 0 < hours <= top:
        return _bad(f'hours must be more than 0 and at most {top}')
    note = data.get('note') or ''
    if not isinstance(note, str) or len(note) > 200:
        return _bad('note: up to 200 characters')
    until = wl.iso(wl.utcnow() + timedelta(hours=float(hours)))
    h = wl.set_hold(desk['id'], _user(), until, note.strip())
    log_audit(_user(), 'vlab.work.hold', f"'{desk['name']}' working until {until}" + (f': {note.strip()}' if note.strip() else ''),
              get_client_ip())
    return jsonify({'hold': _hold_view(h)})


@bp.route('/api/vlab/me/desktops/<desktop_id>/hold', methods=['DELETE'])
@require_auth(perms=['vlab.desk'])
def clear_my_hold(desktop_id):
    desk = _my_desktop(desktop_id)
    if not desk:
        return _bad('desktop not found', 404)
    wl.clear_holds(desk['id'], _user())
    log_audit(_user(), 'vlab.work.unhold', f"'{desk['name']}'", get_client_ip())
    return jsonify({'ok': True})


# --- admin -------------------------------------------------------------------------------

def _reachable_desks():
    pools = {p['id'] for p in store.list_pools() if core._can_reach(p['cluster_id'])}
    return {d['id']: d for d in store.list_desktops() if d['pool_id'] in pools}


@bp.route('/api/vlab/admin/work', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def admin_work():
    desks = _reachable_desks()
    week = wl.iso(wl.utcnow() - timedelta(days=7))
    rows = [d for d in wl.deferrals(desktop_ids=set(desks), limit=1000) if d['state'] == 'waiting' or d['first_at'] >= week]
    holds = [dict(_hold_view(h), desktop=desks[h['desktop_id']]['name']) for h in wl.holds() if h['desktop_id'] in desks]
    return jsonify({'deferrals': [_deferral_view(d, desks.get(d['desktop_id'])) for d in rows], 'holds': holds,
                    'waiting': sum(1 for d in rows if d['state'] == 'waiting')})


def _deferral_or_error(did):
    d = wl.get_deferral(did)
    desks = _reachable_desks()
    if not d or d['desktop_id'] not in desks:
        return None, None, _bad('deferral not found', 404)
    if d['state'] != 'waiting':
        return None, None, _bad('it is not waiting any more', 409)
    return d, desks[d['desktop_id']], None


@bp.route('/api/vlab/admin/deferrals/<did>/release', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def release_deferral(did):
    d, desk, err = _deferral_or_error(did)
    if err:
        return err
    wl.release(d['id'])
    log_audit(_user(), 'vlab.work.release', f"{d['source']} {d['action']} of '{desk['name']}' let run", get_client_ip())
    return jsonify({'ok': True})


@bp.route('/api/vlab/admin/deferrals/<did>/cancel', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def cancel_deferral(did):
    d, desk, err = _deferral_or_error(did)
    if err:
        return err
    wl.finish(d['id'], 'cancelled', f'cancelled by {_user()}')
    log_audit(_user(), 'vlab.work.cancel', f"{d['source']} {d['action']} of '{desk['name']}' will not run", get_client_ip())
    return jsonify({'ok': True})


@bp.route('/api/vlab/admin/holds/<hold_id>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def admin_clear_hold(hold_id):
    h = wl.get_hold(hold_id)
    desk = _reachable_desks().get(h['desktop_id']) if h else None
    if not desk:
        return _bad('hold not found', 404)
    wl.clear_holds(desk['id'], _user())
    log_audit(_user(), 'vlab.work.unhold', f"'{desk['name']}' of {h['username']}", get_client_ip())
    return jsonify({'ok': True})


@bp.route('/api/vlab/admin/work-settings', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_work_settings():
    return jsonify({'settings': settings(), 'defaults': wl.SETTINGS_DEFAULTS})


@bp.route('/api/vlab/admin/work-settings', methods=['PUT'])
@require_auth(perms=['vlab.accel.manage'])
def put_work_settings():
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    change, e = wl.validate_settings(_body())
    if e:
        return _bad(e)
    saved = load_server_settings() or {}
    merged = wl.merge_settings(saved.get(wl.SETTINGS_KEY), change)
    saved[wl.SETTINGS_KEY] = merged
    if not save_server_settings(saved):
        return _bad('Could not save the settings', 500)
    rc = merged['reclaim']
    log_audit(_user(), 'vlab.work.settings', f"sample {merged['sample_minutes']} min, keep {merged['retention_days']} d, "
              f"hold up to {merged['hold_max_hours']} h, reclaim {'on' if rc['enabled'] else 'off'} "
              f"({rc['threshold_pct']}% / {rc['idle_hours']} h, auto return {'after ' + str(rc['auto_return_hours']) + ' h' if rc['auto_return'] else 'off'})",
              get_client_ip())
    return jsonify({'settings': settings()})


@bp.route('/api/vlab/admin/accel-usage', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def accel_usage():
    desk_id = request.args.get('desktop_id') or ''
    lease_id = request.args.get('lease_id') or ''
    try:
        hours = max(1, min(24 * 90, int(request.args.get('hours') or 24)))
    except ValueError:
        return _bad('hours must be a number')
    if not desk_id and not lease_id:
        return _bad('desktop_id or lease_id required')
    if lease_id:
        lease = store.get_lease(lease_id)
        if not lease or not core._can_reach(lease['cluster_id']):
            return _bad('loan not found', 404)
    if desk_id and desk_id not in _reachable_desks():
        return _bad('desktop not found', 404)
    since = wl.iso(wl.utcnow() - timedelta(hours=hours))
    rows = wl.samples(since, lease_id=lease_id or None, desktop_id=desk_id or None)
    threshold = settings()['reclaim']['threshold_pct']
    series = []
    for at, minutes, util, status in wl.by_time(rows):
        mem = [r for r in rows if r['at'] == at and r['mem_total_mb']]
        series.append({'at': at, 'minutes': minutes, 'util': util, 'status': status,
                       'mem_used_mb': round(sum(r['mem_used_mb'] or 0 for r in mem), 1) if mem else None,
                       'mem_total_mb': round(sum(r['mem_total_mb'] or 0 for r in mem), 1) if mem else None})
    return jsonify({'hours': hours, 'threshold_pct': threshold, 'series': series,
                    'summary': wl.summarize(rows, threshold)})


@bp.route('/api/vlab/admin/reclaims', methods=['GET'])
@require_auth(perms=['vlab.accel.manage'])
def list_reclaims():
    leases = {l['id']: l for l in store.list_leases(active_only=True) if core._can_reach(l['cluster_id'])}
    desks = {(d['cluster_id'], int(d['vmid'])): d for d in store.list_desktops()}
    cfg = settings()['reclaim']
    since = wl.iso(wl.utcnow() - timedelta(hours=cfg['idle_hours']))
    rows = [r for r in wl.reclaims(('suggested', 'dismissed')) if r['lease_id'] in leases]
    use = lease_use({r['lease_id'] for r in rows}, since, cfg['threshold_pct'])
    out = []
    for r in rows:
        l = leases[r['lease_id']]
        d = desks.get((l['cluster_id'], int(l['vmid'])))
        out.append(dict(r, card=l['resource_name'] or l['resource_id'], username=l['username'], ends_at=l['ends_at'],
                        starts_at=l['starts_at'], desktop=d['name'] if d else None, desktop_id=d['id'] if d else None,
                        summary=use.get(r['lease_id'])))
    return jsonify({'reclaims': out, 'rules': cfg})


@bp.route('/api/vlab/admin/reclaims/<lease_id>/dismiss', methods=['POST'])
@require_auth(perms=['vlab.accel.manage'])
def dismiss_reclaim(lease_id):
    r = wl.reclaim(lease_id)
    lease = store.get_lease(lease_id)
    if not r or not lease or not core._can_reach(lease['cluster_id']):
        return _bad('no suggestion for that loan', 404)
    wl.set_reclaim(lease_id, state='dismissed', dismissed_by=_user(), dismissed_at=store.now())
    log_audit(_user(), 'vlab.reclaim.dismiss', f"card {lease['resource_name'] or lease['resource_id']} kept by {lease['username']}",
              get_client_ip())
    return jsonify({'ok': True})
