"""MOAVI Desk: card and board bookings on the reservation calendar (pegaprox/vlab/accel_bookings.py).

  GET    /api/vlab/me/accel-bookings/options     my desktops, the cards (mappings) and boards to book, settings   vlab.desk
  GET    /api/vlab/me/accel-bookings             my bookings from today                     vlab.desk
  GET    /api/vlab/accel-bookings/calendar       ?from=&to= every live booking (others' names left out)   vlab.desk
  POST   /api/vlab/me/accel-bookings             {kind, cluster_id, resource, desktop_id, start_at, end_at, purpose?}   vlab.desk
  POST   /api/vlab/me/accel-bookings/<bid>/cancel                                            vlab.desk
  GET    /api/vlab/admin/accel-bookings          ?from=&to=&status=                         vlab.pool.view
  POST   /api/vlab/admin/accel-bookings/<bid>/approve | reject {reason?} | cancel {reason?}   vlab.accel.manage
  GET    /api/vlab/admin/accel-booking-settings                                             vlab.pool.view
  PUT    /api/vlab/admin/accel-booking-settings  {enabled, approval, max_hours, max_days_ahead, roles, remind_min}   vlab.accel.manage

booking_tick (the minute loop, while GPU · AI or FPGA is on) lends what starts, returns what was
cancelled while it ran, marks the finished ones and tells the users before their start.
"""
import logging
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import accel, catalog, store
from pegaprox.vlab import accel_bookings as ab

bp = Blueprint('vlab_accel_book', __name__)

APPROVER_PERM = 'vlab.accel.manage'


def _user():
    return request.session.get('user', '')


def _bad(msg, status=400, **extra):
    return jsonify(dict({'error': msg}, **extra)), status


def _has(perm):
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import has_permission
    try:
        return bool(has_permission(build_authz_user(_user(), request.session), perm))
    except Exception:
        return False


def _role(username):
    from pegaprox.utils.auth import load_users
    return ((load_users() or {}).get(username) or {}).get('role') or ''


def _local_now():
    return datetime.now().replace(second=0, microsecond=0)


def _utc_iso(local):
    """A local 'YYYY-MM-DDTHH:MM' as UTC ISO (a card loan's end)."""
    return ab.parse(local).astimezone(timezone.utc).isoformat(timespec='seconds')


# --- what there is to book -----------------------------------------------------------------

def _cards(cluster_id):
    mgr = cluster_managers.get(cluster_id)
    if not mgr or not getattr(mgr, 'is_connected', False):
        return []
    out = []
    for m in accel.pci_mappings(mgr) or []:
        n = len(m.get('devices') or [])
        if n:
            out.append({'cluster_id': cluster_id, 'id': m['id'], 'name': m.get('description') or m['id'], 'count': n,
                        'kind': core.card_kind(m)})
    return out


def _clusters():
    return [cid for cid in list(cluster_managers) if core._can_reach(cid)]


def _boards():
    return [{'cluster_id': b['cluster_id'], 'id': b['id'], 'name': b['name'], 'node': b['node'], 'kind': b.get('kind') or ''}
            for b in catalog.list_boards() if core._can_reach(b['cluster_id'])]


def _resource(kind, cluster_id, resource):
    """(name, card kind, capacity) of a card mapping or a board, or None."""
    if kind == 'card':
        m = next((c for c in _cards(cluster_id) if c['id'] == resource), None)
        return (m['name'], m['kind'], m['count']) if m else None
    b = catalog.get_board(resource)
    return (b['name'], 'board', 1) if b and b['cluster_id'] == cluster_id else None


def _held(kind, cluster_id, resource):
    """[(desktop id, until)] of the loans / attachments running now that no booking started."""
    started = {r['lease_id'] for r in ab.between(ab.fmt(_local_now() - timedelta(days=60)), '9999', ['approved', 'cancelled'])
               if r.get('lease_id')}
    if kind == 'card':
        out = []
        for l in store.active_leases_on(cluster_id, resource):
            if l['id'] in started:
                continue
            try:
                until = datetime.fromisoformat(l['ends_at']).astimezone().replace(tzinfo=None)
            except (TypeError, ValueError):
                until = None
            out.append((l.get('vmid'), until))
        return out
    b = catalog.get_board(resource)
    if b and b.get('attached_desktop') and f"board:{b['id']}:{b['attached_desktop']}" not in started:
        return [(b['attached_desktop'], ab.parse(b['lease_until']) if b.get('lease_until') else None)]
    return []


def _my_desktops(username):
    return [{'id': d['id'], 'name': d['name'], 'cluster_id': d['cluster_id'], 'node': d['node'], 'pool': d.get('pool_name')}
            for d in store.desktops_of_user(username) if d.get('vm_type') == 'qemu' and core._can_reach(d['cluster_id'])]


@bp.route('/api/vlab/me/accel-bookings/options', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_options():
    s = ab.get_settings()
    cards = [c for cid in _clusters() for c in _cards(cid)]
    allowed = s['enabled'] and (not s['roles'] or _role(_user()) in s['roles'])
    return jsonify({'settings': s, 'allowed': allowed, 'desktops': _my_desktops(_user()), 'cards': cards, 'boards': _boards()})


def _view(r, mine=False, full=False):
    v = dict(r)
    desk = store.get_desktop(r['desktop_id'])
    v['desktop'] = desk['name'] if desk else None
    if not (mine or full):
        for k in ('username', 'purpose', 'reason', 'desktop', 'desktop_id', 'lease_id', 'error', 'reviewed_by'):
            v.pop(k, None)
    return v


@bp.route('/api/vlab/me/accel-bookings', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_bookings():
    since = ab.fmt(_local_now() - timedelta(days=1))
    return jsonify({'bookings': [_view(r, mine=True) for r in ab.of_user(_user(), since)]})


def _range():
    t0 = request.args.get('from') or ab.fmt(_local_now() - timedelta(days=7))
    t1 = request.args.get('to') or ab.fmt(_local_now() + timedelta(days=35))
    if not ab.parse(t0) or not ab.parse(t1):
        raise ValueError('from and to are YYYY-MM-DDTHH:MM')
    return t0, t1


@bp.route('/api/vlab/accel-bookings/calendar', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def calendar():
    try:
        t0, t1 = _range()
    except ValueError as e:
        return _bad(str(e))
    me = _user()
    return jsonify({'bookings': [_view(r, mine=r['username'] == me) for r in ab.between(t0, t1, ab.LIVE)]})


# --- booking ------------------------------------------------------------------------------

_WHY_KO = {'BAD_TIME': '시작과 끝을 확인하세요', 'PAST': '지난 시간은 예약할 수 없습니다', 'TOO_LONG': '예약 최대 길이를 넘었습니다',
           'TOO_FAR': '미리 예약할 수 있는 기간을 넘었습니다'}


@bp.route('/api/vlab/me/accel-bookings', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def book():
    s = ab.get_settings()
    me = _user()
    if not s['enabled']:
        return _bad('Card and board bookings are switched off', 403, code='OFF')
    privileged = _has(APPROVER_PERM)
    if s['roles'] and _role(me) not in s['roles'] and not privileged:
        return _bad('Your role may not book cards or boards', 403, code='ROLE')
    data = request.get_json(silent=True) or {}
    kind = data.get('kind')
    if kind not in ab.KINDS:
        return _bad('kind: card or board')
    cluster_id = str(data.get('cluster_id') or '')
    resource = str(data.get('resource') or '')
    desk = store.get_desktop(str(data.get('desktop_id') or ''))
    if not desk or desk.get('assigned_user') != me or desk['cluster_id'] != cluster_id:
        return _bad('Pick one of your desktops on that cluster', 404, code='DESKTOP')
    if desk.get('vm_type') != 'qemu':
        return _bad('Cards and boards go to virtual machines only', 400, code='DESKTOP')
    res = _resource(kind, cluster_id, resource) if core._can_reach(cluster_id) else None
    if not res:
        return _bad('Card or board not found', 404, code='RESOURCE')
    start, end = ab.parse(data.get('start_at')), ab.parse(data.get('end_at'))
    why = ab.check_times(start, end, s, _local_now(), privileged)
    if why:
        return _bad(_WHY_KO[why], 400, code=why)
    if kind == 'board':
        b = catalog.get_board(resource)
        live = core._vm_states(cluster_id).get(int(desk['vmid'])) or {}
        if (live.get('node') or desk['node']) != b['node']:
            return _bad(f"The board is on {b['node']} and your desktop runs on {live.get('node') or desk['node']} - "
                        "ask the admin to move it first", 409, code='NODE')
    others = ab.between(ab.fmt(start - timedelta(days=1)), ab.fmt(end + timedelta(days=1)), ab.LIVE)
    cand = {'kind': kind, 'cluster_id': cluster_id, 'resource': resource, 'desktop_id': desk['id'], 'start': start, 'end': end}
    clash = ab.conflicts(cand, others, res[2], _held(kind, cluster_id, resource), _local_now())
    if clash:
        return jsonify({'error': 'That time is taken', 'code': 'CONFLICT', 'conflicts': clash}), 409
    status = 'pending' if s['approval'] and not privileged else 'approved'
    row = ab.add({'kind': kind, 'cluster_id': cluster_id, 'resource': resource, 'resource_name': res[0], 'card_kind': res[1],
                  'desktop_id': desk['id'], 'username': me, 'start_at': ab.fmt(start), 'end_at': ab.fmt(end),
                  'purpose': str(data.get('purpose') or '').strip()[:120], 'status': status})
    log_audit(me, 'vlab.accel.book', f"{kind} '{res[0]}' for {desk['name']} {row['start_at']} ~ {row['end_at']} ({status})", get_client_ip())
    if status == 'pending':
        from pegaprox.api.vlab_notices import admins
        admins(f"카드 · 보드 예약 승인 요청: {res[0]}",
               f"{me} 님이 {res[0]} 를 {row['start_at'].replace('T', ' ')} ~ {row['end_at'][11:]} 에 {desk['name']} 로 예약했습니다. "
               f"목적: {row['purpose'] or '-'}\n가속 자원 > 카드 대여 > 예약에서 승인하거나 거절하세요.",
               {'kind': 'accel_booking_requested', 'user': me, 'resource': res[0]})
    return jsonify({'booking': _view(row, mine=True)}), 201


def _finish_now(r, by):
    """Give back what a started booking holds. Error text or None."""
    if r['kind'] == 'card':
        lease = store.get_lease(r['lease_id']) if r.get('lease_id') else None
        if lease and lease['state'] == 'active':
            e = core.return_lease(lease, by=by)
            if e:
                return e
            from pegaprox.api.vlab_notices import loan_returned
            loan_returned(lease, by=by)
        return None
    b = catalog.get_board(r['resource'])
    if not b or b.get('attached_desktop') != r['desktop_id']:
        return None
    from pegaprox.api.vlab_next import BOARD_SLOT
    desk = store.get_desktop(r['desktop_id'])
    mgr = cluster_managers.get(b['cluster_id'])
    if desk and mgr and getattr(mgr, 'is_connected', False):
        live = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
        res = mgr.update_vm_config(live.get('node') or desk['node'], int(desk['vmid']), 'qemu', {'delete': BOARD_SLOT})
        if not isinstance(res, dict) or not res.get('success'):
            return f"Could not detach: {str((res or {}).get('error') if isinstance(res, dict) else res)[:200]}"
    catalog.set_board_attachment(b['id'], None, None, '')
    log_audit(by, 'vlab.board.detach', f"board '{b['name']}' from its booking {r['id']}", '')
    return None


def _cancel(r, by, reason=''):
    if r['status'] not in ab.LIVE:
        return _bad(f"This booking is {r['status']} already", 409)
    out = ab.update(r['id'], status='cancelled', reason=reason[:300], reviewed_by=by, reviewed_at=store.now())
    if r.get('started_at') and not r.get('finished_at'):
        e = _finish_now(out, by)
        ab.update(r['id'], finished_at=store.now(), error=e or '')
    log_audit(by, 'vlab.accel.book.cancel', f"booking {r['id']} of {r['username']} ({r['resource_name']})" + (f': {reason}' if reason else ''),
              get_client_ip())
    return jsonify({'booking': _view(ab.get(r['id']), full=True)})


@bp.route('/api/vlab/me/accel-bookings/<bid>/cancel', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def cancel_mine(bid):
    r = ab.get(bid)
    if not r or r['username'] != _user():
        return _bad('Booking not found', 404)
    return _cancel(r, _user())


# --- the approvers -------------------------------------------------------------------------

def _reachable(r):
    return core._can_reach(r['cluster_id'])


@bp.route('/api/vlab/admin/accel-bookings', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def admin_list():
    try:
        t0, t1 = _range()
    except ValueError as e:
        return _bad(str(e))
    status = request.args.get('status')
    rows = ab.between(t0, t1, [status] if status in ab.STATUSES else None)
    pend = [r for r in ab.pending() if _reachable(r)]
    return jsonify({'bookings': [_view(r, full=True) for r in rows if _reachable(r)],
                    'pending': [_view(r, full=True) for r in pend], 'settings': ab.get_settings()})


def _answer(r, approved, by, reason=''):
    from pegaprox.api.vlab_notices import tell
    when = f"{r['start_at'].replace('T', ' ')} ~ {r['end_at'][11:]}"
    if approved:
        tell(r['username'], 'request', f"카드 · 보드 예약 승인: {r['resource_name']}",
             f"{r['resource_name']} 예약({when})이 승인되었습니다. 시작 {ab.START_EARLY}분 전에 데스크톱에 붙입니다"
             + (" (카드는 데스크톱을 다시 시작해야 보입니다)." if r['kind'] == 'card' else '.'), 'accel_booking_approved', booking_id=r['id'])
    else:
        tell(r['username'], 'request', f"카드 · 보드 예약 거절: {r['resource_name']}",
             f"{r['resource_name']} 예약({when})이 거절되었습니다." + (f"\n사유: {reason}" if reason else ''), 'accel_booking_rejected',
             booking_id=r['id'])


@bp.route('/api/vlab/admin/accel-bookings/<bid>/<action>', methods=['POST'])
@require_auth(perms=[APPROVER_PERM])
def admin_act(bid, action):
    r = ab.get(bid)
    if not r or not _reachable(r):
        return _bad('Booking not found', 404)
    reason = str((request.get_json(silent=True) or {}).get('reason') or '').strip()
    if action == 'cancel':
        return _cancel(r, _user(), reason)
    if action not in ('approve', 'reject'):
        return _bad('approve, reject or cancel', 404)
    if r['status'] != 'pending':
        return _bad(f"This booking is {r['status']} already", 409)
    if action == 'approve':
        others = [o for o in ab.between(r['start_at'], r['end_at'], ['approved']) if o['id'] != r['id']]
        res = _resource(r['kind'], r['cluster_id'], r['resource'])
        cand = {'kind': r['kind'], 'cluster_id': r['cluster_id'], 'resource': r['resource'], 'desktop_id': r['desktop_id'],
                'start': ab.parse(r['start_at']), 'end': ab.parse(r['end_at'])}
        clash = ab.conflicts(cand, others, res[2] if res else 0, _held(r['kind'], r['cluster_id'], r['resource']), _local_now())
        if clash:
            return jsonify({'error': 'That time is taken now', 'code': 'CONFLICT', 'conflicts': clash}), 409
    out = ab.update(bid, status='approved' if action == 'approve' else 'rejected', reason=reason[:300], reviewed_by=_user(),
                    reviewed_at=store.now())
    log_audit(_user(), f'vlab.accel.book.{action}', f"booking {bid} of {r['username']} ({r['resource_name']})", get_client_ip())
    _answer(out, action == 'approve', _user(), reason)
    return jsonify({'booking': _view(out, full=True)})


@bp.route('/api/vlab/admin/accel-booking-settings', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_settings():
    return jsonify({'settings': ab.get_settings()})


@bp.route('/api/vlab/admin/accel-booking-settings', methods=['PUT'])
@require_auth(perms=[APPROVER_PERM])
def put_settings():
    try:
        s = ab.save_settings(request.get_json(silent=True))
    except ValueError as e:
        return _bad(str(e))
    log_audit(_user(), 'vlab.accel.book.settings', f"card / board bookings: {'on' if s['enabled'] else 'off'}, approval "
              f"{'on' if s['approval'] else 'off'}, up to {s['max_hours']} h", get_client_ip())
    return jsonify({'settings': s})


# --- the minute loop -----------------------------------------------------------------------

def _start(r):
    desk = store.get_desktop(r['desktop_id'])
    if not desk:
        return 'the desktop is gone'
    if r['kind'] == 'card':
        out, err = core.lend_card(desk, r['resource'], _utc_iso(r['end_at']), r['resource_name'], f"booking:{r['username']}", ip='')
        if err:
            return err[0]
        ab.update(r['id'], lease_id=out['lease']['id'], started_at=store.now())
        return None
    from pegaprox.api.vlab_next import lend_board
    b = catalog.get_board(r['resource'])
    if not b:
        return 'the board is gone'
    if b.get('attached_desktop') and b['attached_desktop'] != r['desktop_id']:
        return 'the board is attached to another desktop'
    if b.get('attached_desktop') != r['desktop_id']:
        out, err = lend_board(b, desk, f"booking:{r['username']}", r['username'], r['end_at'], ip='')
        if err:
            return err[0]
    ab.update(r['id'], lease_id=f"board:{b['id']}:{desk['id']}", started_at=store.now())
    return None


def booking_tick(at=None):
    """Lend, give back and tell. Returns (started, finished)."""
    from pegaprox.api.vlab_notices import tell
    from pegaprox.vlab import notices
    at = at or _local_now()
    s = ab.get_settings()
    started = finished = 0
    starts, finishes, missed = ab.to_run(at)
    for r in starts:
        e = _start(r)
        if e:
            ab.update(r['id'], started_at=store.now(), finished_at=store.now(), error=str(e)[:300])
            tell(r['username'], 'loan', f"예약한 {r['resource_name']} 를 붙이지 못했습니다",
                 f"{r['start_at'].replace('T', ' ')} 예약의 {r['resource_name']} 를 붙이지 못했습니다: {e}\n관리자에게 문의하세요.",
                 'accel_booking_failed', 'warning', booking_id=r['id'])
            from pegaprox.api.vlab_notices import admins
            admins(f"카드 · 보드 예약 시작 실패: {r['resource_name']}", f"{r['username']} 님의 예약 {r['id']}: {e}",
                   {'kind': 'accel_booking_failed', 'user': r['username'], 'severity': 'warning'})
        else:
            started += 1
            log_audit('system', 'vlab.accel.book.start', f"booking {r['id']} of {r['username']}: {r['resource_name']}", '')
    for r in finishes:
        e = _finish_now(r, 'system') if r['status'] == 'cancelled' else None
        ab.update(r['id'], finished_at=store.now(), error=(e or r.get('error') or '')[:300])
        finished += 1
    for r in missed:
        ab.update(r['id'], started_at=store.now(), finished_at=store.now(), error='its time passed before it could start')
    mins = int(s.get('remind_min') or 0)
    if mins > 0:
        soon = [r for r in ab.between(ab.fmt(at), ab.fmt(at + timedelta(minutes=mins)), ['approved'])
                if ab.fmt(at) <= r['start_at'] <= ab.fmt(at + timedelta(minutes=mins)) and not r.get('started_at')]
        for r in soon:
            if not notices.once(f"accel-booking:{r['id']}:{r['start_at']}"):
                continue
            desk = store.get_desktop(r['desktop_id'])
            tell(r['username'], 'booking', f"곧 시작하는 카드 · 보드 예약: {r['resource_name']} {r['start_at'][11:]}",
                 f"{r['resource_name']} 예약이 {r['start_at'].replace('T', ' ')} 에 시작합니다 (데스크톱 {desk['name'] if desk else '-'}). "
                 + ("카드는 붙인 뒤 데스크톱을 다시 시작해야 보입니다. 작업을 저장해 두세요." if r['kind'] == 'card'
                    else "보드는 데스크톱이 보드가 꽂힌 서버에서 돌고 있어야 붙습니다."), 'accel_booking_soon', booking_id=r['id'])
    return started, finished
