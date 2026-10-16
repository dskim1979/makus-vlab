# -*- coding: utf-8 -*-
"""
MOAVI Desk - LAB reservations (포털 > 예약, LAB > 예약), pegaprox/vlab/reservations.py.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

  GET    /api/vlab/reservations/options               LABs and pools the caller may book, their rules   vlab.desk
  GET    /api/vlab/reservations/calendar              ?from=&to=&lab_id=&pool_id= classes and bookings (busy times)  vlab.desk
  GET    /api/vlab/me/reservations                    the caller's bookings (the last 30 days and later)  vlab.desk
  POST   /api/vlab/me/reservations/check              {kind, lab_id?, pool_id, quantity?, start_at, end_at, repeat?} what it collides with  vlab.desk
  POST   /api/vlab/me/reservations                    the same + purpose, note, participants, skip_conflicts?  vlab.desk
  PUT    /api/vlab/me/reservations/<id>               change one occurrence that has not started  vlab.desk
  POST   /api/vlab/me/reservations/<id>/cancel        {scope: one|series}                     vlab.desk
  POST   /api/vlab/me/reservations/<id>/desktop       a desktop of the booking, in its time, for a participant  vlab.desk
  GET    /api/vlab/admin/reservations                 ?from=&to=&lab_id=&status=              vlab.lab.manage
  GET    /api/vlab/admin/reservations/pending         requests waiting for approval           vlab.lab.manage
  GET    /api/vlab/admin/reservations/summary         today's bookings, waiting, running      vlab.pool.view
  POST   /api/vlab/admin/reservations/check           as the portal's, without the LAB rules  vlab.lab.manage
  POST   /api/vlab/admin/reservations                 {..., requester?} approved at once      vlab.lab.manage
  PUT    /api/vlab/admin/reservations/<id>            change one occurrence                   vlab.lab.manage
  POST   /api/vlab/admin/reservations/<id>/approve    {scope?, banner?}                       vlab.lab.manage
  POST   /api/vlab/admin/reservations/<id>/reject     {reason, scope?}                        vlab.lab.manage
  POST   /api/vlab/admin/reservations/<id>/cancel     {reason?, scope?}                       vlab.lab.manage
  GET    /api/vlab/admin/reservation-settings         per LAB, for pool bookings, notifications  vlab.lab.manage
  PUT    /api/vlab/admin/reservation-settings/<key>   key = a LAB id, _pool or _global        vlab.lab.manage
  GET    /api/vlab/admin/reports/reservations         ?days=&lab_id=&format=csv booked vs used, no-shows  vlab.report.view

An approved booking runs like a LAB schedule (pegaprox/api/vlab.py lab_tick -> due_items /
run_phase): its desktops are started `prepare_min` before, and put back (reset / off) at the
end. Only the requester and the participants get a desktop of it in its time, from the
portal or a LAB kiosk; the kiosk shows the booking in place of the class.
"""

import csv
import io
import logging
from datetime import datetime, timedelta

from flask import Blueprint, Response, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import catalog, labs, store
from pegaprox.vlab import reservations as rsv

bp = Blueprint('vlab_reserve', __name__)

_bad = core._bad
_user = core._user
APPROVER_PERM = 'vlab.lab.manage'
POOL_TYPES = core.LAB_POOL_TYPES


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _now():
    return core._local_now()


def _has(perm):
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import has_permission
    try:
        return has_permission(build_authz_user(_user(), request.session), perm)
    except Exception:
        return False


def _role(username):
    from pegaprox.utils.auth import load_users
    return ((load_users() or {}).get(username) or {}).get('role') or ''


def _groups(username):
    from pegaprox.api.vlab_next import _user_groups
    return _user_groups(username)


def _participant(r, username):
    return rsv.is_participant(r, username, catalog.department_of(username), _groups(username), catalog.descendants)


# --- what can be booked ----------------------------------------------------------------------

def _settings_key(lab_id):
    return lab_id or rsv.POOL_KEY


def _lab_pools(lab, settings, pools):
    ids = settings.get('pool_ids') or sorted({s['pool_id'] for s in store.list_lab_schedules(lab['id'])})
    out = [pools[i] for i in ids if i in pools]
    return out or [p for p in pools.values()]


def _bookable_pools():
    return {p['id']: p for p in store.list_pools()
            if p['type'] in POOL_TYPES and p.get('enabled', True) and core._can_reach(p['cluster_id'])}


def _pool_sizes():
    sizes = {}
    for d in store.list_desktops():
        sizes[d['pool_id']] = sizes.get(d['pool_id'], 0) + 1
    return sizes


def _may_book(settings, username, privileged):
    if privileged:
        return True
    roles = settings.get('roles') or []
    return not roles or _role(username) in roles


@bp.route('/api/vlab/reservations/options', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def reservation_options():
    username, privileged = _user(), _has(APPROVER_PERM)
    pools, sizes = _bookable_pools(), _pool_sizes()

    def pool_view(p):
        return {'id': p['id'], 'name': p['name'], 'type': p['type'], 'desktops': sizes.get(p['id'], 0)}

    out = []
    for lab in store.list_labs():
        s = rsv.get_settings(lab['id'])
        if not s['enabled'] and not privileged:
            continue
        out.append({'id': lab['id'], 'name': lab['name'], 'location': lab['location'], 'seats': lab['seats'],
                    'settings': s, 'may_book': s['enabled'] and _may_book(s, username, privileged),
                    'pools': [pool_view(p) for p in _lab_pools(lab, s, pools)]})
    ps = rsv.get_settings(rsv.POOL_KEY)
    return jsonify({'labs': out, 'pools': [pool_view(p) for p in pools.values()],
                    'pool_settings': ps, 'pool_may_book': ps['enabled'] and _may_book(ps, username, privileged),
                    'approver': privileged, 'max_weeks': rsv.MAX_WEEKS, 'now': rsv.fmt(_now())})


# --- checking a request ----------------------------------------------------------------------

def _resolve(data, requester, privileged, exclude=()):
    """(row, occurrences, report, error response). report = [{start, end, conflicts, rules}]
    per occurrence; the request is fine when every entry is empty."""
    clean, occ, e = rsv.validate(data)
    if e:
        return None, None, None, _bad(e)
    pools = _bookable_pools()
    pool = pools.get(data.get('pool_id') or '')
    if not pool:
        return None, None, None, _bad('Pool not found (a scheduled, reset or shared pool)', 404)
    lab = None
    if clean['kind'] in ('lab', 'seats'):
        lab = store.get_lab(data.get('lab_id') or '')
        if not lab:
            return None, None, None, _bad('LAB not found', 404)
    settings = rsv.get_settings(_settings_key(lab['id'] if lab else None))
    if lab and pool['id'] not in {p['id'] for p in _lab_pools(lab, settings, pools)}:
        return None, None, None, _bad("This pool is not one of the LAB's", 400)
    if not _may_book(settings, requester, privileged):
        return None, None, None, (jsonify({'error': 'Your role may not book this', 'code': 'ROLE'}), 403)
    if clean['kind'] == 'seats' and lab and lab['seats'] and clean['quantity'] > lab['seats']:
        return None, None, None, (jsonify({'error': f"The LAB has {lab['seats']} seats", 'code': 'SEATS', 'limit': lab['seats']}), 409)
    from pegaprox.utils.auth import load_users
    users = load_users() or {}
    for p in clean['participants']:
        if p['subject_type'] == 'user' and p['subject_id'] not in users:
            return None, None, None, _bad(f"No such user: {p['subject_id']}")
        if p['subject_type'] == 'department' and not catalog.get_department(p['subject_id']):
            return None, None, None, _bad(f"No such department: {p['subject_id']}")
    row = dict(clean, lab_id=lab['id'] if lab else None, pool_id=pool['id'], requester=requester,
               prepare_min=settings['prepare_min'], after=settings['after'])
    report = _report(row, occ, settings, privileged, exclude)
    return row, occ, report, None


def _with_demand(rows, pool_sizes):
    labs_by_id = {l['id']: l for l in store.list_labs()}
    for o in rows:
        if o['kind'] == 'lab':
            o['_demand'] = rsv.demand(o, int((labs_by_id.get(o.get('lab_id')) or {}).get('seats') or 0), pool_sizes.get(o['pool_id'], 0))
    return rows


def _report(row, occ, settings, privileged, exclude=()):
    sizes = _pool_sizes()
    lab = store.get_lab(row['lab_id']) if row.get('lab_id') else None
    schedules = store.list_lab_schedules()
    t0, t1 = rsv.fmt(min(a for a, _ in occ)), rsv.fmt(max(b for _, b in occ))
    others = _with_demand([o for o in rsv.between(t0, t1, rsv.LIVE) if o['id'] not in exclude], sizes)
    at = _now()
    out = []
    for a, b in occ:
        out.append({'start': rsv.fmt(a), 'end': rsv.fmt(b),
                    'rules': rsv.rule_errors(settings, a, b, at, privileged),
                    'conflicts': [rsv.wire(c) for c in rsv.conflicts(row, a, b, schedules, others, lab, sizes.get(row['pool_id'], 0))]})
    return out


def _bad_occurrences(report):
    return [x for x in report if x['rules'] or x['conflicts']]


def _check(privileged):
    data = _body()
    requester = (data.get('requester') or _user()) if privileged else _user()
    row, occ, report, err = _resolve(data, requester, privileged, exclude=tuple(data.get('exclude') or ())[:500])
    if err:
        return err
    return jsonify({'ok': not _bad_occurrences(report), 'occurrences': report,
                    'approval': _needs_approval(row, privileged)})


@bp.route('/api/vlab/me/reservations/check', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def my_reservation_check():
    return _check(False)


@bp.route('/api/vlab/admin/reservations/check', methods=['POST'])
@require_auth(perms=[APPROVER_PERM])
def admin_reservation_check():
    return _check(True)


def _needs_approval(row, privileged):
    if privileged:
        return False
    return bool(rsv.get_settings(_settings_key(row.get('lab_id'))).get('approval'))


# --- views -------------------------------------------------------------------------------------

def _names():
    return ({l['id']: l['name'] for l in store.list_labs()}, {p['id']: p['name'] for p in store.list_pools()})


def _view(r, names=None, full=True):
    lab_names, pool_names = names or _names()
    v = {'id': r['id'], 'series_id': r['series_id'], 'kind': r['kind'], 'lab_id': r['lab_id'],
         'lab': lab_names.get(r['lab_id']) if r['lab_id'] else None, 'pool_id': r['pool_id'],
         'pool': pool_names.get(r['pool_id']), 'quantity': r['quantity'], 'start_at': r['start_at'], 'end_at': r['end_at'],
         'purpose': r['purpose'], 'requester': r['requester'], 'status': r['status']}
    if full:
        at = _now()
        v.update({'note': r['note'], 'participants': r['participants'], 'reason': r['reason'],
                  'reviewed_by': r['reviewed_by'], 'reviewed_at': r['reviewed_at'], 'prepare_min': r['prepare_min'],
                  'after': r['after'], 'prepared': bool(r['prepared_at']), 'finished': bool(r['finished_at']),
                  'running': rsv.running(r, at), 'desktops': len(r['desktops']), 'handed': len(r['handed']),
                  'series_count': len(rsv.series(r['series_id'])) if r['series_id'] else 1,
                  'created_at': r['created_at']})
    return v


def _day_range(default_days=7):
    today = _now().date()
    try:
        d0 = datetime.strptime(request.args.get('from') or today.isoformat(), '%Y-%m-%d')
        d1 = datetime.strptime(request.args.get('to') or (today + timedelta(days=default_days - 1)).isoformat(), '%Y-%m-%d')
    except ValueError:
        return None, None, _bad('from and to are YYYY-MM-DD')
    if d1 < d0 or (d1 - d0).days > 62:
        return None, None, _bad('from..to is at most 62 days')
    return d0, d1 + timedelta(days=1), None


@bp.route('/api/vlab/reservations/calendar', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def reservation_calendar():
    """Busy times: the weekly classes and the live bookings in the range. Another person's
    booking shows its purpose and who booked it, not its note or participants."""
    d0, d1, err = _day_range()
    if err:
        return err
    lab_id, pool_id = request.args.get('lab_id') or None, request.args.get('pool_id') or None
    username, privileged = _user(), _has(APPROVER_PERM)
    names = _names()
    blocks = []
    for b in rsv.schedule_blocks(store.list_lab_schedules(), d0.date(), (d1 - timedelta(days=1)).date()):
        if (lab_id and b['lab_id'] != lab_id and not pool_id) or (pool_id and b['pool_id'] != pool_id and not lab_id) \
                or (lab_id and pool_id and b['lab_id'] != lab_id and b['pool_id'] != pool_id):
            continue
        blocks.append({'type': 'schedule', 'id': b['id'], 'lab_id': b['lab_id'], 'lab': names[0].get(b['lab_id']),
                       'pool_id': b['pool_id'], 'pool': names[1].get(b['pool_id']), 'title': b['title'],
                       'start_at': rsv.fmt(b['start']), 'end_at': rsv.fmt(b['end'])})
    for r in rsv.between(rsv.fmt(d0), rsv.fmt(d1), rsv.LIVE):
        if (lab_id and r['lab_id'] != lab_id and not pool_id) or (pool_id and r['pool_id'] != pool_id and not lab_id) \
                or (lab_id and pool_id and r['lab_id'] != lab_id and r['pool_id'] != pool_id):
            continue
        mine = r['requester'] == username
        blocks.append(dict(_view(r, names, full=mine or privileged), type='reservation', mine=mine))
    blocks.sort(key=lambda x: x['start_at'])
    return jsonify({'from': d0.date().isoformat(), 'to': (d1 - timedelta(days=1)).date().isoformat(), 'blocks': blocks})


@bp.route('/api/vlab/me/reservations', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_reservations():
    since = rsv.fmt(_now() - timedelta(days=30))
    names = _names()
    return jsonify({'reservations': [_view(r, names) for r in rsv.of_user(_user(), since)]})


# --- creating, changing, cancelling ----------------------------------------------------------

def _create(privileged):
    import uuid
    data = _body()
    requester = _user()
    if privileged and data.get('requester'):
        from pegaprox.utils.auth import load_users
        requester = str(data['requester'])
        if requester not in (load_users() or {}):
            return _bad(f'No such user: {requester}')
    row, occ, report, err = _resolve(data, requester, privileged)
    if err:
        return err
    bad = _bad_occurrences(report)
    keep = [(a, b) for (a, b), x in zip(occ, report) if not (x['rules'] or x['conflicts'])]
    if bad and (not data.get('skip_conflicts') or not keep):
        return jsonify({'error': 'The booking collides with others or breaks the LAB rules', 'code': 'CONFLICT',
                        'occurrences': report}), 409
    approval = _needs_approval(row, privileged)
    row['status'] = 'pending' if approval else 'approved'
    sid = ('ser_' + uuid.uuid4().hex[:12]) if len(keep) > 1 else ''
    made = [rsv.add(row, o, sid) for o in keep]
    if not approval:
        stamp = store.now()
        made = [rsv.update(r['id'], reviewed_by=_user(), reviewed_at=stamp) for r in made]
    first = made[0]
    log_audit(_user(), 'vlab.reservation.create',
              f"{row['kind']} {_where(first)} {first['start_at']}-{first['end_at'][11:]} x{len(made)} for '{requester}' "
              f"({row['status']}){' skipped ' + str(len(bad)) if bad else ''}: {row['purpose']}", get_client_ip())
    if approval:
        _notify(made, 'requested', _user())
    elif privileged and requester != _user():
        _notify(made, 'approved', _user())
    if not approval:
        _maybe_banner(made, bool(data.get('banner')))
    names = _names()
    return jsonify({'reservations': [_view(r, names) for r in made], 'skipped': bad, 'approval': approval}), 201


def _where(r):
    lab_names, pool_names = _names()
    return lab_names.get(r['lab_id']) or pool_names.get(r['pool_id']) or r['pool_id']


@bp.route('/api/vlab/me/reservations', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def my_reservation_create():
    return _create(False)


@bp.route('/api/vlab/admin/reservations', methods=['POST'])
@require_auth(perms=[APPROVER_PERM])
def admin_reservation_create():
    return _create(True)


def _change(rid, privileged):
    r = rsv.get(rid)
    if not r or (not privileged and r['requester'] != _user()):
        return _bad('Booking not found', 404)
    if r['status'] not in rsv.LIVE or r['prepared_at']:
        return jsonify({'error': 'Only a booking that has not started can be changed', 'code': 'STARTED'}), 409
    data = dict({k: r[k] for k in ('kind', 'lab_id', 'pool_id', 'quantity', 'start_at', 'end_at', 'purpose', 'note',
                                   'participants')}, **{k: v for k, v in _body().items() if k != 'repeat'})
    row, occ, report, err = _resolve(data, r['requester'], privileged, exclude=(rid,))
    if err:
        return err
    if _bad_occurrences(report):
        return jsonify({'error': 'The change collides with others or breaks the LAB rules', 'code': 'CONFLICT',
                        'occurrences': report}), 409
    status = r['status']
    if not privileged and _needs_approval(row, False):
        status = 'pending'
    a, b = occ[0]
    out = rsv.update(rid, kind=row['kind'], lab_id=row['lab_id'], pool_id=row['pool_id'], quantity=row['quantity'],
                     start_at=rsv.fmt(a), end_at=rsv.fmt(b), purpose=row['purpose'], note=row['note'],
                     participants=row['participants'], status=status)
    log_audit(_user(), 'vlab.reservation.update', f"booking {rid} of '{r['requester']}': {out['start_at']}-{out['end_at'][11:]} "
              f"({status})", get_client_ip())
    if out['banner_id']:
        _drop_banner(out)
        if status == 'approved':
            _maybe_banner([out], True)
    if r['requester'] != _user():
        _notify([out], 'changed', _user())
    elif status == 'pending' and r['status'] == 'approved':
        _notify([out], 'requested', _user())
    return jsonify({'reservation': _view(out)})


@bp.route('/api/vlab/me/reservations/<rid>', methods=['PUT'])
@require_auth(perms=['vlab.desk'])
def my_reservation_update(rid):
    return _change(rid, False)


@bp.route('/api/vlab/admin/reservations/<rid>', methods=['PUT'])
@require_auth(perms=[APPROVER_PERM])
def admin_reservation_update(rid):
    return _change(rid, True)


def _scope_rows(r, scope, statuses):
    if scope == 'series' and r['series_id']:
        at = rsv.fmt(_now())
        return [x for x in rsv.series(r['series_id']) if x['status'] in statuses and (x['id'] == r['id'] or x['end_at'] > at)]
    return [r] if r['status'] in statuses else []


def _cancel(rid, privileged):
    r = rsv.get(rid)
    if not r or (not privileged and r['requester'] != _user()):
        return _bad('Booking not found', 404)
    data = _body()
    rows = [x for x in _scope_rows(r, data.get('scope'), rsv.LIVE) if not x['finished_at']]
    if not rows:
        return jsonify({'error': 'Nothing left to cancel', 'code': 'NOT_LIVE'}), 409
    reason = str(data.get('reason') or '')[:300]
    out = []
    for x in rows:
        out.append(rsv.update(x['id'], status='cancelled', reason=reason, reviewed_by=_user(), reviewed_at=store.now()))
        if x['banner_id']:
            _drop_banner(x)
    log_audit(_user(), 'vlab.reservation.cancel', f"{len(out)} booking(s) of '{r['requester']}' from {r['start_at']}"
              f"{': ' + reason if reason else ''}", get_client_ip())
    if r['requester'] != _user():
        _notify(out, 'cancelled', _user(), reason)
    names = _names()
    return jsonify({'reservations': [_view(x, names) for x in out]})


@bp.route('/api/vlab/me/reservations/<rid>/cancel', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def my_reservation_cancel(rid):
    return _cancel(rid, False)


@bp.route('/api/vlab/admin/reservations/<rid>/cancel', methods=['POST'])
@require_auth(perms=[APPROVER_PERM])
def admin_reservation_cancel(rid):
    return _cancel(rid, True)


# --- approval ----------------------------------------------------------------------------------

@bp.route('/api/vlab/admin/reservations', methods=['GET'])
@require_auth(perms=[APPROVER_PERM])
def admin_reservations():
    d0, d1, err = _day_range()
    if err:
        return err
    status = request.args.get('status') or None
    if status and status not in rsv.STATUSES:
        return _bad('status is pending, approved, rejected or cancelled')
    names = _names()
    rows = rsv.between(rsv.fmt(d0), rsv.fmt(d1), (status,) if status else None, lab_id=request.args.get('lab_id') or None)
    blocks = []
    for b in rsv.schedule_blocks(store.list_lab_schedules(request.args.get('lab_id') or None), d0.date(), (d1 - timedelta(days=1)).date()):
        blocks.append({'type': 'schedule', 'id': b['id'], 'lab_id': b['lab_id'], 'lab': names[0].get(b['lab_id']),
                       'pool_id': b['pool_id'], 'pool': names[1].get(b['pool_id']), 'title': b['title'],
                       'start_at': rsv.fmt(b['start']), 'end_at': rsv.fmt(b['end'])})
    return jsonify({'reservations': [_view(r, names) for r in rows], 'schedules': blocks,
                    'from': d0.date().isoformat(), 'to': (d1 - timedelta(days=1)).date().isoformat()})


@bp.route('/api/vlab/admin/reservations/pending', methods=['GET'])
@require_auth(perms=[APPROVER_PERM])
def admin_reservations_pending():
    names = _names()
    at = rsv.fmt(_now())
    rows = [r for r in rsv.pending() if r['end_at'] > at]
    # one line per series: its first waiting occurrence and how many wait
    seen, out = {}, []
    for r in rows:
        if r['series_id'] and r['series_id'] in seen:
            seen[r['series_id']]['waiting'] += 1
            continue
        v = dict(_view(r, names), waiting=1)
        out.append(v)
        if r['series_id']:
            seen[r['series_id']] = v
    return jsonify({'pending': out})


@bp.route('/api/vlab/admin/reservations/summary', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def admin_reservations_summary():
    at = _now()
    t0, t1 = rsv.today_range(at)
    today = rsv.between(t0, t1, ('approved', 'pending'))
    return jsonify({'today': sum(1 for r in today if r['status'] == 'approved'),
                    'today_pending': sum(1 for r in today if r['status'] == 'pending'),
                    'pending': len([r for r in rsv.pending() if r['end_at'] > rsv.fmt(at)]),
                    'running': sum(1 for r in today if rsv.running(r, at))})


def _review(rid, decision):
    r = rsv.get(rid)
    if not r:
        return _bad('Booking not found', 404)
    data = _body()
    reason = str(data.get('reason') or '').strip()[:300]
    if decision == 'rejected' and not reason:
        return _bad('A reason is required to reject')
    rows = _scope_rows(r, data.get('scope'), ('pending',))
    if not rows:
        return jsonify({'error': 'This booking is not waiting for approval', 'code': 'NOT_PENDING'}), 409
    at = _now()
    rows = [x for x in rows if rsv.parse(x['end_at']) > at] or rows
    out = [rsv.update(x['id'], status=decision, reason=reason, reviewed_by=_user(), reviewed_at=store.now()) for x in rows]
    log_audit(_user(), f"vlab.reservation.{'approve' if decision == 'approved' else 'reject'}",
              f"{len(out)} booking(s) of '{r['requester']}' from {r['start_at']} ({_where(r)}){': ' + reason if reason else ''}",
              get_client_ip())
    if decision == 'approved':
        _maybe_banner(out, bool(data.get('banner')))
    _notify(out, decision, _user(), reason)
    names = _names()
    return jsonify({'reservations': [_view(x, names) for x in out]})


@bp.route('/api/vlab/admin/reservations/<rid>/approve', methods=['POST'])
@require_auth(perms=[APPROVER_PERM])
def admin_reservation_approve(rid):
    return _review(rid, 'approved')


@bp.route('/api/vlab/admin/reservations/<rid>/reject', methods=['POST'])
@require_auth(perms=[APPROVER_PERM])
def admin_reservation_reject(rid):
    return _review(rid, 'rejected')


# --- settings ----------------------------------------------------------------------------------

@bp.route('/api/vlab/admin/reservation-settings', methods=['GET'])
@require_auth(perms=[APPROVER_PERM])
def get_reservation_settings():
    from pegaprox.api.helpers import load_server_settings
    channels = [{'id': str(c.get('id')), 'name': c.get('name') or c.get('type') or str(c.get('id')), 'type': c.get('type')}
                for c in ((load_server_settings() or {}).get('alert_webhooks') or []) if isinstance(c, dict)]
    pools = _bookable_pools()
    return jsonify({'labs': {l['id']: dict(rsv.get_settings(l['id']), default_pools=[p['id'] for p in _lab_pools(l, {}, pools)])
                             for l in store.list_labs()},
                    'pool': rsv.get_settings(rsv.POOL_KEY), 'global': rsv.get_settings(rsv.GLOBAL_KEY),
                    'channels': channels, 'defaults': rsv.DEFAULTS})


@bp.route('/api/vlab/admin/reservation-settings/<key>', methods=['PUT'])
@require_auth(perms=[APPROVER_PERM])
def put_reservation_settings(key):
    data = _body()
    if key == rsv.GLOBAL_KEY:
        cur = rsv.get_settings(key)
        if 'mail' in data:
            cur['mail'] = bool(data['mail'])
        if 'channels' in data:
            if not isinstance(data['channels'], list) or len(data['channels']) > 50:
                return _bad('channels: a list of channel ids')
            cur['channels'] = [str(c) for c in data['channels']]
        if 'remind_min' in data:
            v = data['remind_min']
            if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= 1440:
                return _bad('remind_min: minutes from 0 (no reminder) to 1440')
            cur['remind_min'] = v
        out = rsv.save_settings(key, cur)
    else:
        if key != rsv.POOL_KEY and not store.get_lab(key):
            return _bad('LAB not found', 404)
        clean, e = rsv.clean_settings(data, rsv.get_settings(key))
        if e:
            return _bad(e)
        pools = _bookable_pools()
        unknown = [p for p in clean['pool_ids'] if p not in pools]
        if unknown:
            return _bad(f'Pool not found: {unknown[0]}', 404)
        out = rsv.save_settings(key, clean)
    log_audit(_user(), 'vlab.reservation.settings', f"reservation settings '{key}': {out}", get_client_ip())
    return jsonify({'settings': out})


# --- notifications -----------------------------------------------------------------------------

_EVENTS = {'requested': '예약 승인 요청', 'approved': '예약 승인', 'rejected': '예약 거절',
           'cancelled': '예약 취소', 'changed': '예약 변경'}


def _notify(rows, event, by, reason=''):
    """The requester hears of approve / reject / cancel / change by mail (their account's
    address) and the chosen webhook channels; a new request goes to the channels only."""
    if not rows:
        return
    r = rows[0]
    g = rsv.get_settings(rsv.GLOBAL_KEY)
    title = f"[MOAVI Desk] {_EVENTS.get(event, event)}: {_where(r)} {r['start_at'].replace('T', ' ')}"
    lines = [f"{_EVENTS.get(event, event)} - {_where(r)}",
             f"일시: {r['start_at'].replace('T', ' ')} ~ {r['end_at'][11:]}" + (f" 외 {len(rows) - 1}회" if len(rows) > 1 else ''),
             f"목적: {r['purpose'] or '-'}", f"신청자: {r['requester']}", f"처리: {by}"]
    if reason:
        lines.append(f"사유: {reason}")
    text = '\n'.join(lines)
    if g.get('channels'):
        try:
            from pegaprox.utils.webhooks import send_to_channels
            send_to_channels({'title': title, 'message': text, 'source': 'moavi-desk', 'severity': 'info',
                              'kind': f'lab_reservation_{event}', 'reservation_id': r['id'], 'requester': r['requester']},
                             g['channels'])
        except Exception as e:
            logging.warning(f'[VLAB] reservation webhook: {e}')
    from pegaprox.vlab import notices
    if event != 'requested' and g.get('mail', True) and notices.wants(r['requester'], 'request'):
        try:
            from pegaprox.utils.auth import load_users
            from pegaprox.utils.email import send_email
            email = ((load_users() or {}).get(r['requester']) or {}).get('email')
            if email:
                send_email([email], title, text, None)
        except Exception as e:
            logging.warning(f'[VLAB] reservation mail: {e}')


def _maybe_banner(rows, asked):
    """An approved LAB booking shows as a notice to everyone while it runs, when its LAB says
    so or the approver asked (one notice per occurrence, made when approved)."""
    for r in rows:
        if r['status'] != 'approved' or not r['lab_id']:
            continue
        if not (asked or rsv.get_settings(r['lab_id']).get('banner')):
            continue
        bid = _add_banner(r)
        if bid:
            rsv.update(r['id'], banner_id=bid)


def _add_banner(r):
    import secrets
    from pegaprox.api import banners as bn
    from pegaprox.api.vlab_next import _banner_starts, _save_banner_starts
    start = (rsv.parse(r['start_at']) - timedelta(minutes=int(r['prepare_min'] or 0))).astimezone()
    end = rsv.parse(r['end_at']).astimezone()
    if end <= bn._now():
        return ''
    text = f"[LAB 예약] {_where(r)} {r['start_at'][5:].replace('T', ' ')}~{r['end_at'][11:]} {r['purpose']}".strip()
    try:
        fields = bn._validated({'text': text[:bn.TEXT_MAX], 'severity': 'info', 'expires_at': bn._iso(end), 'scope': 'everyone'})
        with bn._write_lock:
            banners = bn.stored_banners()
            if banners is None or len(banners) >= bn.MAX_BANNERS:
                return ''
            stamp = bn._now()
            banner = dict(fields, id=secrets.token_hex(8), rev=1, created_at=bn._iso(stamp), created_by='system',
                          updated_at=bn._iso(stamp), updated_by='system')
            bn._save(banners + [banner])
            starts = _banner_starts()
            starts[banner['id']] = bn._iso(start)
            _save_banner_starts({k: v for k, v in starts.items() if k in {b['id'] for b in banners} | {banner['id']}})
        return banner['id']
    except Exception as e:
        logging.warning(f'[VLAB] reservation notice: {e}')
        return ''


def _drop_banner(r):
    from pegaprox.api import banners as bn
    try:
        with bn._write_lock:
            banners = bn.stored_banners()
            if banners is not None:
                bn._save([b for b in banners if b.get('id') != r['banner_id']])
        rsv.update(r['id'], banner_id='')
    except Exception as e:
        logging.warning(f'[VLAB] reservation notice removal: {e}')


# --- running: lab_tick, the hand-out of desktops, the kiosk ----------------------------------

def _allocate(r, pool):
    """Pick the booking's desktops: free ones of its pool that no other running booking
    holds (a scheduled pool's assignments are the room's own and do not count)."""
    if r['desktops']:
        return r['desktops']
    at = _now()
    held = set()
    t0, t1 = rsv.today_range(at)
    for o in rsv.between(rsv.fmt(at - timedelta(days=1)), t1, ('approved', 'cancelled'), pool_id=pool['id']):
        if o['id'] != r['id'] and o['prepared_at'] and not o['finished_at']:
            held.update(o['desktops'])
    lab = store.get_lab(r['lab_id']) if r['lab_id'] else None
    desks = store.list_desktops(pool['id'])
    want = rsv.demand(r, int((lab or {}).get('seats') or 0), len(desks))
    pick = []
    for d in sorted(desks, key=lambda x: x['name']):
        if d['id'] in held or d.get('state') in ('provisioning', 'error'):
            continue
        if pool['type'] != 'classroom' and d['assigned_user']:
            continue
        pick.append(d['id'])
        if len(pick) >= want:
            break
    rsv.update(r['id'], desktops=pick)
    return pick


def due_items(at, pools):
    """[(booking, pool, phase)] for lab_tick."""
    out = []
    for r in rsv.to_run(rsv.fmt(at + timedelta(minutes=180))):
        phase = rsv.due(r, at)
        pool = pools.get(r['pool_id'])
        if phase == 'skip' or (phase and not pool):
            rsv.update(r['id'], finished_at=store.now())
            continue
        if phase:
            out.append((r, pool, phase))
    return out


def run_phase(r, pool, phase):
    """Prepare (start its desktops) or finish (reset / off, then take back what was handed
    out) one booking. Returns what _lab_phase returns."""
    if phase == 'prepare':
        ids = set(_allocate(r, pool))
        desks = [d for d in store.list_desktops(pool['id']) if d['id'] in ids]
        result = core._lab_phase(r, pool, 'prepare', desks=desks)
        rsv.update(r['id'], prepared_at=store.now())
        return result
    ids = set(r['desktops'])
    desks = [d for d in store.list_desktops(pool['id']) if d['id'] in ids]
    if r['after'] != 'none' and desks:
        result = core._lab_phase(r, pool, 'finish', after=r['after'], desks=desks)
    else:
        result = {'phase': 'finish', 'done': [], 'skipped': [], 'failed': []}
    busy = store.open_session_desktops()
    left = []
    for h in r['handed']:
        d = store.get_desktop(h['desktop_id'])
        if not d or d['id'] in busy:
            if d:
                left.append(h)
            continue
        if h.get('assigned') and d['assigned_user'] == h['username']:
            if core._acl_set(d['cluster_id'], d['vmid'], h['username'], False):
                store.set_assignment(d['id'], None)
            else:
                left.append(h)
        elif not h.get('assigned'):
            from pegaprox.api.vlab_next import granted
            if not granted(pool['id'], h['username']) and not core._acl_set(d['cluster_id'], d['vmid'], h['username'], False):
                left.append(h)
    rsv.update(r['id'], finished_at=store.now(), handed=left)
    return result


def occupied_before(pool_id, start, at, skip_id=None):
    """Is a session of the pool that ends by `start` still not cleaned up? A prepare waits for
    it, so the clean-up never undoes the next session's start (LAB schedules and bookings)."""
    day = at.date().isoformat()
    for s in store.schedules_of_pool(pool_id):
        if s['id'] == skip_id or not s.get('enabled') or s.get('after') == 'none':
            continue
        occ = labs.occurrence(s, at.date())
        if occ and occ[1] <= start and at < occ[1] + labs.FINISH_GRACE and s.get('last_finished') != day:
            if not (s.get('last_prepared') != day and occ[1] <= at):    # never prepared: nothing to clean
                return True
    for o in rsv.between(rsv.fmt(at - timedelta(days=1)), rsv.fmt(start), ('approved', 'cancelled'), pool_id=pool_id):
        if o['id'] == skip_id or not o['prepared_at'] or o['finished_at']:
            continue
        if rsv.parse(o['end_at']) <= start and at < rsv.parse(o['end_at']) + labs.FINISH_GRACE:
            return True
    return False


def _hand_out(r, username, pool):
    """(desktop, error response) for a participant in the booking's time."""
    if not core._can_reach(pool['cluster_id']):
        return None, _bad('Pool not found', 404)
    ids = _allocate(r, pool)
    desks = {d['id']: d for d in store.list_desktops(pool['id']) if d['id'] in ids}
    busy = store.open_session_desktops()
    if pool['type'] == 'shared':
        counts = {}
        for s in store.open_sessions():
            counts[s['desktop_id']] = counts.get(s['desktop_id'], 0) + 1
        mine = next((desks[h['desktop_id']] for h in r['handed'] if h['username'] == username and h['desktop_id'] in desks), None)
        d = mine or (min(desks.values(), key=lambda x: (counts.get(x['id'], 0), x['name'])) if desks else None)
        if not d:
            return None, (jsonify({'error': 'Every desktop of this booking is taken', 'code': 'FULL'}), 409)
        if not core._acl_set(d['cluster_id'], d['vmid'], username, True):
            return None, _bad('VM access list unavailable - try again', 503)
        if not mine:
            rsv.update(r['id'], handed=r['handed'] + [{'desktop_id': d['id'], 'username': username, 'assigned': False}])
        return d, None
    mine = next((d for d in desks.values() if d['assigned_user'] == username), None)
    if mine:
        return mine, None
    free = [d for d in sorted(desks.values(), key=lambda x: x['name'])
            if not d['assigned_user'] and d['id'] not in busy and d.get('state') not in ('provisioning', 'resetting', 'error')]
    if not free:
        return None, (jsonify({'error': 'Every desktop of this booking is taken', 'code': 'FULL'}), 409)
    d = free[0]
    if not core._acl_set(d['cluster_id'], d['vmid'], username, True):
        return None, _bad('VM access list unavailable - try again', 503)
    store.set_assignment(d['id'], username)
    rsv.update(r['id'], handed=r['handed'] + [{'desktop_id': d['id'], 'username': username, 'assigned': True}])
    return d, None


@bp.route('/api/vlab/me/reservations/<rid>/desktop', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def my_reservation_desktop(rid):
    """A desktop of a booking for its requester or a participant, in its time."""
    username = _user()
    r = rsv.get(rid)
    if not r or not _participant(r, username):
        return _bad('Booking not found', 404)
    if not rsv.running(r, _now()):
        return jsonify({'error': 'The booking is not in its time', 'code': 'NOT_NOW'}), 409
    pool = store.get_pool(r['pool_id'])
    if not pool:
        return _bad('Pool not found', 404)
    d, err = _hand_out(r, username, pool)
    if err:
        return err
    log_audit(username, 'vlab.reservation.desktop', f"{d['vm_type']}/{d['vmid']} '{d['name']}' for booking {rid}", get_client_ip())
    return jsonify({'desktop': {'id': d['id'], 'name': d['name']}})


@bp.route('/api/vlab/me/reservations/now', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_reservations_now():
    """Bookings the caller takes part in that run now or start within the hour (the portal's
    '지금 예약' card)."""
    username, at = _user(), _now()
    dep, groups = catalog.department_of(username), _groups(username)
    names = _names()
    out = []
    for r in rsv.between(rsv.fmt(at), rsv.fmt(at + timedelta(hours=1)), ('approved',)):
        if rsv.is_participant(r, username, dep, groups, catalog.descendants):
            out.append(dict(_view(r, names, full=False), running=rsv.running(r, at)))
    return jsonify({'reservations': out})


def reserved_desktop(desk, username):
    """The connect route asks this for a desktop not assigned to the caller: a shared pool's
    desktop handed to them by a booking running now."""
    at = _now()
    for r in rsv.between(rsv.fmt(at), rsv.fmt(at + timedelta(minutes=1)), ('approved',), pool_id=desk['pool_id']):
        if rsv.running(r, at) and any(h['desktop_id'] == desk['id'] and h['username'] == username for h in r['handed']):
            return True
    return False


def kiosk_state(lab_id, at, current, upcoming, pool_names):
    """The LAB kiosk shows a booking of the room (whole LAB or seats) in place of the class."""
    t0 = rsv.fmt(at)
    rows = rsv.between(rsv.fmt(at - timedelta(hours=1)), rsv.fmt(at + timedelta(days=8)), ('approved',), lab_id=lab_id)

    def view(r, now_too):
        v = {'reservation_id': r['id'], 'pool_id': r['pool_id'], 'pool': pool_names.get(r['pool_id']),
             'title': r['purpose'] or '', 'start': r['start_at'], 'end': r['end_at'], 'kind': r['kind'],
             'requester': r['requester'], 'quantity': r['quantity']}
        if now_too:
            v['preparing'] = t0 < r['start_at']
        return v

    now_rows = [r for r in rows if rsv.running(r, at)]
    if now_rows:
        current = view(now_rows[0], True)
    later = [r for r in rows if r['start_at'] > t0 and not rsv.running(r, at)]
    if later and (upcoming is None or later[0]['start_at'] < upcoming['start']):
        upcoming = view(later[0], False)
    return current, upcoming


def kiosk_desktop(cur, username, terminal, view):
    r = rsv.get(cur['reservation_id'])
    if not r or not rsv.running(r, _now()):
        return jsonify({'error': 'No session in this LAB now', 'code': 'NO_SESSION', **view}), 409
    if not _participant(r, username):
        return jsonify({'error': 'This LAB is booked for others now', 'code': 'NOT_PARTICIPANT', **view}), 403
    pool = store.get_pool(r['pool_id'])
    if not pool:
        return _bad('Pool not found', 404)
    d, err = _hand_out(r, username, pool)
    if err:
        resp, code = err
        body = resp.get_json() or {}
        return jsonify({**body, **view}), code
    log_audit(username, 'vlab.kiosk.assign', f"{d['vm_type']}/{d['vmid']} '{d['name']}' at terminal "
              f"'{terminal['name'] or terminal['mac']}' (booking {r['id']}, LAB {view['lab']['name']})", get_client_ip())
    return jsonify({'desktop': {'id': d['id'], 'name': d['name']}, **view})


# --- report: booked vs used, no-shows ---------------------------------------------------------

def _clip_hours(spans):
    """Hours covered by the union of (a, b) spans."""
    total, cur = 0.0, None
    for a, b in sorted(spans):
        if cur and a <= cur[1]:
            cur = (cur[0], max(cur[1], b))
        else:
            if cur:
                total += (cur[1] - cur[0]).total_seconds()
            cur = (a, b)
    if cur:
        total += (cur[1] - cur[0]).total_seconds()
    return round(total / 3600, 2)


@bp.route('/api/vlab/admin/reports/reservations', methods=['GET'])
@require_auth(perms=['vlab.report.view'])
def reservation_report():
    """운영 > 사용률 보고서 > LAB 예약: approved bookings that ended in the last `days` days (or
    run now): booked hours, the hours someone of the booking was connected (sessions on its
    desktops, or of its participants on its pool), users, and no-shows (nobody connected)."""
    from datetime import timezone
    try:
        days = int(request.args.get('days', 30))
    except ValueError:
        return _bad('days must be a number')
    if not 1 <= days <= 366:
        return _bad('days must be 1..366')
    at = _now()
    since = datetime(at.year, at.month, at.day) - timedelta(days=days - 1)
    lab_id = request.args.get('lab_id') or None
    pools = {p['id']: p for p in store.list_pools() if core._can_reach(p['cluster_id'])}
    names = _names()
    rows = [r for r in rsv.between(rsv.fmt(since), rsv.fmt(at), ('approved',), lab_id=lab_id)
            if r['pool_id'] in pools]
    tz = datetime.now().astimezone().tzinfo
    until = at.replace(tzinfo=tz)
    sessions = store.sessions_overlapping(since.replace(tzinfo=tz).astimezone(timezone.utc).isoformat(timespec='seconds'),
                                          until.astimezone(timezone.utc).isoformat(timespec='seconds'))
    out, per_lab = [], {}
    for r in rows:
        a = rsv.parse(r['start_at']).replace(tzinfo=tz)
        b = min(rsv.parse(r['end_at']).replace(tzinfo=tz), until)
        desk_ids = set(r['desktops']) | {h['desktop_id'] for h in r['handed']}
        dep_cache = {}
        spans, users = [], set()
        for s in sessions:
            if s['pool_id'] != r['pool_id']:
                continue
            if s['desktop_id'] not in desk_ids:
                u = s['username']
                if u not in dep_cache:
                    dep_cache[u] = rsv.is_participant(r, u, catalog.department_of(u), None, catalog.descendants)
                if not dep_cache[u]:
                    continue
            sa = core._ts(s['started_at']).astimezone(tz)
            sb = core._ts(s['ended_at']).astimezone(tz) if s['ended_at'] else until
            sa, sb = max(sa, a), min(sb, b)
            if sb > sa:
                spans.append((sa, sb))
                users.add(s['username'])
        booked = round((rsv.parse(r['end_at']) - rsv.parse(r['start_at'])).total_seconds() / 3600, 2)
        used = _clip_hours(spans)
        ended = rsv.parse(r['end_at']) <= at
        row = {'id': r['id'], 'lab': names[0].get(r['lab_id']) or '', 'pool': names[1].get(r['pool_id']) or '',
               'kind': r['kind'], 'quantity': r['quantity'], 'start_at': r['start_at'], 'end_at': r['end_at'],
               'purpose': r['purpose'], 'requester': r['requester'], 'booked_hours': booked, 'used_hours': used,
               'users': len(users), 'no_show': ended and not spans, 'running': not ended}
        out.append(row)
        key = r['lab_id'] or ''
        g = per_lab.setdefault(key, {'lab_id': key, 'lab': row['lab'] or '(풀 예약)', 'reservations': 0, 'booked_hours': 0.0,
                                     'used_hours': 0.0, 'no_shows': 0, 'users': 0})
        g['reservations'] += 1
        g['booked_hours'] = round(g['booked_hours'] + booked, 2)
        g['used_hours'] = round(g['used_hours'] + used, 2)
        g['no_shows'] += 1 if row['no_show'] else 0
        g['users'] += len(users)
    if request.args.get('format') == 'csv':
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(['lab', 'pool', 'kind', 'quantity', 'start', 'end', 'purpose', 'requester', 'booked_hours', 'used_hours',
                    'users', 'no_show'])
        for x in out:
            w.writerow([_csv(x['lab']), _csv(x['pool']), x['kind'], x['quantity'], x['start_at'], x['end_at'], _csv(x['purpose']),
                        _csv(x['requester']), x['booked_hours'], x['used_hours'], x['users'], 'Y' if x['no_show'] else ''])
        return Response('\ufeff' + buf.getvalue(), mimetype='text/csv; charset=utf-8',
                        headers={'Content-Disposition': f'attachment; filename="lab-reservations-{days}d.csv"'})
    total_booked = round(sum(x['booked_hours'] for x in out), 2)
    total_used = round(sum(x['used_hours'] for x in out), 2)
    ended = [x for x in out if not x['running']]
    return jsonify({'days': days, 'from': since.date().isoformat(), 'to': at.date().isoformat(),
                    'totals': {'reservations': len(out), 'booked_hours': total_booked, 'used_hours': total_used,
                               'no_shows': sum(1 for x in out if x['no_show']),
                               'no_show_rate': round(sum(1 for x in ended if x['no_show']) / len(ended), 4) if ended else 0.0,
                               'use_rate': round(total_used / total_booked, 4) if total_booked else 0.0},
                    'by_lab': sorted(per_lab.values(), key=lambda g: -g['booked_hours']), 'reservations': out})


def _csv(v):
    """A cell a spreadsheet will not run as a formula."""
    v = str(v or '')
    return "'" + v if v[:1] in ('=', '+', '-', '@', '\t', '\r') else v
