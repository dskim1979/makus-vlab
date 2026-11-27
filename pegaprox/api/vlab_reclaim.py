"""MOAVI Desk: 자원 회수 - what can be taken back, why, and doing it one item at a time
(pegaprox/vlab/reclaim.py has the rules).

  GET    /api/vlab/admin/reclaim                ?days=7|14|30|60|90 (30) &cluster_id= &exempt=1   vlab.pool.view
  POST   /api/vlab/admin/reclaim/exempt         {key, note?} keep it: not listed nor counted      vlab.pool.manage
  DELETE /api/vlab/admin/reclaim/exempt         ?key=  listed again                               vlab.pool.manage
  POST   /api/vlab/admin/reclaim/apply          {key, action, ...} one item, one step             vlab.pool.manage
  GET    /api/vlab/admin/reclaim/settings       the weekly summary                                vlab.pool.view
  PUT    /api/vlab/admin/reclaim/settings       {weekly?, weekday?, hour?, days?}                 admin.settings

apply runs the route that already does the step - a desktop's 배정 해제 / 전원 / 하드웨어 /
스냅숏 삭제 / VM 삭제, a card's 반납 - with that route's own checks and audit line; a VM that
is not a desktop gets the same steps here. A delete (VM or snapshot) needs confirm_name, the
name typed again. Every step is in the audit log as vlab.reclaim.apply too. Nothing runs by
itself: reclaim_tick (the minute loop) only sends the weekly summary when it is turned on.
"""
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from flask import Blueprint, has_request_context, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import reclaim as rc
from pegaprox.vlab import store

bp = Blueprint('vlab_reclaim', __name__)

SNAP_TTL = 900            # the snapshot lists of a cluster are read at most every 15 minutes
SNAP_MAX_VMS = 400
_snap_cache = {}          # cluster_id -> (time, {vmid: [rows]})


def _bad(msg, status=400, code=None):
    body = {'error': msg}
    if code:
        body['code'] = code
    return jsonify(body), status


def _user():
    return request.session.get('user', '')


def _body():
    d = request.get_json(silent=True)
    return d if isinstance(d, dict) else {}


# --- reading the cluster ---------------------------------------------------------------------

def _reach(cid):
    """The caller reaches the cluster; the weekly summary (no request) sees every one."""
    return not has_request_context() or core._can_reach(cid)


def _clusters(only=None):
    out = []
    for cid, mgr in list(cluster_managers.items()):
        if only and cid != only:
            continue
        if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox' or not getattr(mgr, 'is_connected', False):
            continue
        if not _reach(cid):
            continue
        out.append((cid, mgr))
    return out


def _known_vmids(cluster_id):
    """VMs MOAVI Desk uses for something other than a desktop: golden images, JTAG gateways,
    licence servers. Read table by table (a table that is not there yet is skipped)."""
    out = set()
    for sql in ('SELECT vmid FROM vlab_golden_images WHERE cluster_id = ?',
                'SELECT vmid FROM vlab_jtag_gateways WHERE cluster_id = ?',
                'SELECT vmid FROM vlab_license_servers WHERE cluster_id = ?'):
        try:
            for r in store.db().query(sql, (cluster_id,)):
                if r['vmid'] is not None:
                    out.add(int(r['vmid']))
        except Exception:
            pass
    return out


def _last_seen():
    rows = store.db().query('''SELECT desktop_id, username, MAX(started_at) AS at FROM vlab_sessions
                               WHERE desktop_id IS NOT NULL GROUP BY desktop_id, username''')
    return {(r['desktop_id'], r['username']): r['at'] for r in rows}


def _rightsizing(cluster_id):
    from pegaprox.api import insights as core_insights
    try:
        body = core._core_body(core_insights.right_sizing(cluster_id))   # reads ?days= of this request
    except Exception as e:
        logging.debug(f'[VLAB] reclaim right-sizing {cluster_id}: {e}')
        body = None
    return (body or {}).get('recommendations') or [], body is not None


def _history(cluster_id, days):
    from pegaprox.api import insights as core_insights
    try:
        return core_insights._load_history(cluster_id, days=days + 1)
    except Exception as e:
        logging.debug(f'[VLAB] reclaim history {cluster_id}: {e}')
        return []


def _snapshots(cluster_id, mgr, vms, fresh=False):
    hit = _snap_cache.get(cluster_id)
    if hit and not fresh and time.time() - hit[0] < SNAP_TTL:
        return hit[1]
    want = [vm for vm in vms.values() if not vm.get('template') and vm.get('node')][:SNAP_MAX_VMS]

    def one(vm):
        try:
            return int(vm['vmid']), mgr.get_snapshots(vm['node'], int(vm['vmid']), vm.get('type') or 'qemu') or []
        except Exception:
            return int(vm['vmid']), []
    with ThreadPoolExecutor(max_workers=8) as ex:
        out = {vmid: rows for vmid, rows in ex.map(one, want) if rows}
    _snap_cache[cluster_id] = (time.time(), out)
    return out


def _loan_rows():
    from pegaprox.vlab import workload as wl
    leases = {l['id']: l for l in store.list_leases(active_only=True) if _reach(l['cluster_id'])}
    desks = {(d['cluster_id'], int(d['vmid'])): d for d in store.list_desktops()}
    pools = {p['id']: p for p in store.list_pools()}
    out = []
    for r in wl.reclaims(('suggested',)):
        l = leases.get(r['lease_id'])
        if not l:
            continue
        d = desks.get((l['cluster_id'], int(l['vmid'])))
        p = pools.get(d['pool_id']) if d else None
        out.append(dict(r, card=l['resource_name'] or l['resource_id'], username=l['username'], ends_at=l['ends_at'],
                        cluster_id=l['cluster_id'], vmid=int(l['vmid']), desktop=d['name'] if d else None,
                        desktop_id=d['id'] if d else None, pool_id=p['id'] if p else None, pool=p['name'] if p else None))
    return out


def build_report(days, cluster_id=None, with_exempt=False, rightsizing=True, fresh=False):
    at = rc.utcnow()
    pools = {p['id']: p for p in store.list_pools()}
    all_desks = store.list_desktops()
    last_seen = _last_seen()
    items, specs, notes = [], {}, []
    for cid, mgr in _clusters(cluster_id):
        try:
            vms = {int(r['vmid']): r for r in (mgr.get_vm_resources(max_age=15) or [])
                   if isinstance(r, dict) and r.get('vmid') is not None}
        except Exception as e:
            notes.append(f'{cid}: VM 목록을 못 읽음 ({e})')
            continue
        desks = [d for d in all_desks if d['cluster_id'] == cid]
        by_vmid = {int(d['vmid']): d for d in desks}
        known = _known_vmids(cid)
        specs[cid] = rc.typical_spec(desks, vms)
        items += rc.unused_desktops(cid, desks, vms, pools, last_seen, at, days)
        if rightsizing:
            recs, ok = _rightsizing(cid)
            if not ok:
                notes.append(f'{cid}: 크기 분석을 못 읽음')
            items += rc.oversized(cid, recs, vms, by_vmid, pools)
        ran, first = rc.last_running(_history(cid, days))
        stopped = rc.stopped_vms(cid, vms, by_vmid, pools, known, ran, first, at, days)
        if first is None or (at.timestamp() - first) / 86400 < days * 0.9:
            notes.append(f'{cid}: 측정 기록이 {days}일이 안 되어 오래 꺼진 VM은 아직 못 셉니다')
        items += stopped
        items += rc.orphans(cid, vms, by_vmid, known, {it['vmid'] for it in stopped})
        items += rc.old_snapshots(cid, _snapshots(cid, mgr, vms, fresh), vms, by_vmid, pools, at, days)
    reach = {cid for cid, _ in _clusters(cluster_id)}
    items += [it for it in rc.loans(_loan_rows()) if it['cluster_id'] in reach]
    ex = rc.exemptions()
    rc.mark_exempt(items, set(ex))
    spec = _merged_spec(specs)
    out_items = items if with_exempt else [it for it in items if not it['exempt']]
    return {
        'days': days, 'generated_at': at.isoformat(timespec='seconds'),
        'spec': spec, 'totals': rc.totals(items, spec), 'counts': rc.counts(items),
        'exempt_count': sum(1 for it in items if it['exempt']),
        'items': out_items, 'notes': notes,
        'pools': sorted({(it['pool_id'], it['pool']) for it in items if it.get('pool_id')}, key=lambda p: p[1] or ''),
    }


def _merged_spec(specs):
    if not specs:
        return dict(rc.FALLBACK_SPEC, from_desktops=0)
    best = max(specs.values(), key=lambda s: s.get('from_desktops', 0))
    return best


# --- the routes ------------------------------------------------------------------------------

def _days():
    try:
        days = int(request.args.get('days') or 30)
    except (TypeError, ValueError):
        return None
    return days if days in rc.DAYS else None


@bp.route('/api/vlab/admin/reclaim', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_reclaim():
    days = _days()
    if days is None:
        return _bad('days: ' + ', '.join(map(str, rc.DAYS)))
    cid = request.args.get('cluster_id') or None
    if cid and (cid not in cluster_managers or not core._can_reach(cid)):
        return _bad('Cluster not found', 404)
    rep = build_report(days, cid, with_exempt=request.args.get('exempt') in ('1', 'true'),
                       fresh=request.args.get('fresh') in ('1', 'true'))
    rep['pools'] = [{'id': i, 'name': n} for i, n in rep['pools']]
    rep['exemptions'] = list(rc.exemptions().values())
    return jsonify(rep)


@bp.route('/api/vlab/admin/reclaim/exempt', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def post_exempt():
    d = _body()
    key = d.get('key')
    if not rc.valid_key(key):
        return _bad('key: an item key of the report')
    kind = key.split(':', 1)[0]
    cid = key.split(':')[1] if key.count(':') >= 1 else ''
    target = str(d.get('target') or '')[:120]
    rc.exempt(key, kind, cid, target, str(d.get('note') or ''), _user())
    log_audit(_user(), 'vlab.reclaim.exempt', f"{key} ({target or '-'}) kept" + (f": {d.get('note')}" if d.get('note') else ''),
              get_client_ip())
    return jsonify({'ok': True})


@bp.route('/api/vlab/admin/reclaim/exempt', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_exempt():
    key = request.args.get('key') or _body().get('key')
    if not rc.valid_key(key) or key not in rc.exemptions():
        return _bad('Not exempt', 404)
    rc.unexempt(key)
    log_audit(_user(), 'vlab.reclaim.exempt', f'{key} listed again', get_client_ip())
    return jsonify({'ok': True})


def _ok(resp):
    r = resp[0] if isinstance(resp, tuple) else resp
    status = resp[1] if isinstance(resp, tuple) and len(resp) > 1 else getattr(r, 'status_code', 200)
    return 200 <= int(status) < 300


def _vm_live(cid, vmid):
    return core._vm_states(cid).get(int(vmid))


def _vm_step(d, action):
    """A step on a VM that is not a desktop: shutdown, resize, delete_snapshot, delete_vm."""
    cid = d.get('cluster_id')
    try:
        vmid = int(d.get('vmid'))
    except (TypeError, ValueError):
        return _bad('vmid is required')
    if cid not in cluster_managers or not core._can_reach(cid):
        return _bad('Cluster not found', 404)
    if store.desktop_for_vm(cid, vmid):
        return _bad('That VM is a desktop - give desktop_id', 409)
    mgr = cluster_managers[cid]
    vm = _vm_live(cid, vmid)
    if not vm:
        return _bad('The VM is not on the cluster any more', 404)
    if vm.get('template'):
        return _bad('A template is not changed here', 409)
    node, vtype = vm.get('node'), vm.get('type') or 'qemu'
    from pegaprox.utils.rbac import user_can_access_vm
    from pegaprox.utils.auth import resolve_authz_user
    user = resolve_authz_user(request.session)
    perm = {'shutdown': 'vm.stop', 'resize': 'vm.config', 'delete_snapshot': 'vm.snapshot', 'delete_vm': 'vm.delete'}[action]         if action in ('shutdown', 'resize', 'delete_snapshot', 'delete_vm') else 'vm.config'
    if not user or not user_can_access_vm(user, cid, vmid, perm, vtype):
        return _bad('Not allowed on that VM', 403)
    if action == 'shutdown':
        r = mgr.vm_action(node, vmid, vtype, 'shutdown')
        what = 'shutdown'
    elif action == 'resize':
        upd = {}
        for k, key, lo, hi in (('cores', 'cores', 1, 256), ('memory_mb', 'memory', 256, 4 * 1024 * 1024)):
            v = d.get(k)
            if v in (None, ''):
                continue
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                return _bad(f'{k}: a whole number from {lo} to {hi}')
            upd[key] = v
        if not upd:
            return _bad('Nothing to change')
        r = mgr.update_vm_config(node, vmid, vtype, upd)
        what = ', '.join(f'{k}={v}' for k, v in upd.items())
    elif action == 'delete_snapshot':
        name = str(d.get('snapshot') or '')
        if not name or name == 'current' or name == core.BASE_SNAP:
            return _bad('snapshot: the snapshot to delete')
        if str(d.get('confirm_name') or '') != name:
            return _bad("confirm_name must be the snapshot's name", code='CONFIRM')
        r = mgr.delete_snapshot(node, vmid, vtype, name)
        what = f"snapshot '{name}' deleted"
    elif action == 'delete_vm':
        if str(d.get('confirm_name') or '') != (vm.get('name') or ''):
            return _bad("confirm_name must be the VM's name", code='CONFIRM')
        if vmid in _known_vmids(cid):
            return _bad('MOAVI Desk uses that VM (golden image, JTAG gateway or licence server)', 409)
        if vm.get('status') == 'running':
            return _bad('Shut the VM down first', 409, 'VM_RUNNING')
        if vm.get('lock'):
            return _bad(f"The VM is busy ({vm['lock']}) - try again shortly", 409)
        r = mgr.delete_vm(node, vmid, vtype, purge=True)
        what = 'deleted'
        if isinstance(r, dict) and r.get('success'):
            try:
                from pegaprox.core.db import get_db
                from pegaprox.utils.rbac import invalidate_vm_acls_cache
                if get_db().delete_vm_acl(cid, vmid):
                    invalidate_vm_acls_cache()
            except Exception as ex:
                logging.error(f'[VLAB] {vtype}/{vmid} deleted but its VM ACL was not removed: {ex}')
            log_audit(_user(), 'vm.deleted', f"vLAB 자원 회수: VM '{vm.get('name')}' ({vtype}/{vmid}) deleted from {node}",
                      get_client_ip())
    else:
        return _bad('Unknown action')
    if not (isinstance(r, dict) and r.get('success')):
        err = r.get('error') if isinstance(r, dict) else None
        return _bad(str(err or f'{action} failed')[:300], 502)
    log_audit(_user(), f'vm.{action}' if action == 'shutdown' else 'vlab.vm.config',
              f"vLAB 자원 회수: {vtype}/{vmid} '{vm.get('name')}': {what}", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/reclaim/apply', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def apply_item():
    """{key, action, cluster_id?, vmid?, desktop_id?, snapshot?, lease_id?, cores?, memory_mb?,
    confirm_name?} - one step of one item, by the route that does it."""
    from pegaprox.api import vlab_next as nxt
    d = _body()
    key, action = d.get('key'), d.get('action')
    if not rc.valid_key(key):
        return _bad('key: an item key of the report')
    if action not in rc.ACTIONS or action == 'review':
        return _bad('action: ' + ', '.join(a for a in rc.ACTIONS if a != 'review'))
    desk_id = d.get('desktop_id') or None
    desk = store.get_desktop(desk_id) if desk_id else None
    if desk_id and (not desk or not core._can_reach(desk['cluster_id'])):
        return _bad('Desktop not found', 404)
    if action == 'return_card':
        lid = d.get('lease_id')
        if not lid:
            return _bad('lease_id is required')
        resp = core.return_lease_now(lid)
    elif desk:
        if action == 'unassign':
            if not desk.get('assigned_user'):
                return _bad('The desktop is not assigned', 409)
            resp = core.assign_desktop(desk['id'])            # no username in the body: unassigned
        elif action == 'shutdown':
            resp = core.admin_power_desktop(desk['id'])       # body action = shutdown
        elif action == 'resize':
            resp = nxt.desktop_vm_hardware(desk['id'])        # body cores / memory_mb
        elif action == 'delete_snapshot':
            name = str(d.get('snapshot') or '')
            if not name or name in (desk.get('base_snap') or '', core.BASE_SNAP):
                return _bad("snapshot: not the desktop's base snapshot")
            if str(d.get('confirm_name') or '') != name:
                return _bad("confirm_name must be the snapshot's name", code='CONFIRM')
            resp = nxt.desktop_snapshot_delete(desk['id'], name)
        elif action == 'delete_vm':
            resp = nxt.desktop_vm_delete(desk['id'])          # checks confirm_name = the desktop's name
        else:
            return _bad('Unknown action')
    else:
        if action == 'unassign':
            return _bad('desktop_id is required')
        resp = _vm_step(d, action)
    if not _ok(resp):
        return resp
    target = desk['name'] if desk else (d.get('snapshot') or d.get('lease_id') or f"{d.get('cluster_id')}/{d.get('vmid')}")
    extra = ''
    if action == 'resize':
        extra = ' ' + ', '.join(f'{k}={d[k]}' for k in ('cores', 'memory_mb') if d.get(k) not in (None, ''))
    log_audit(_user(), 'vlab.reclaim.apply', f"{key}: {rc.ACTIONS[action][0]} ({target}){extra}", get_client_ip())
    if action == 'delete_snapshot':
        _snap_cache.pop(d.get('cluster_id') or (desk or {}).get('cluster_id'), None)
    r = resp[0] if isinstance(resp, tuple) else resp
    try:
        result = r.get_json()
    except Exception:
        result = None
    return jsonify({'success': True, 'result': result})


@bp.route('/api/vlab/admin/reclaim/settings', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_settings():
    return jsonify({'settings': _settings(), 'last_sent': _state().get('last_sent')})


@bp.route('/api/vlab/admin/reclaim/settings', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def put_settings():
    try:
        upd = rc.validate_settings(_body())
    except ValueError as e:
        return _bad(str(e))
    s = dict(_settings(), **upd)
    from pegaprox.core.db import get_db
    get_db().save_server_setting(rc.SETTINGS_KEY, s)
    log_audit(_user(), 'vlab.reclaim.settings', f"weekly summary {'on' if s['weekly'] else 'off'} "
              f"(day {s['weekday']}, {s['hour']}:00, {s['days']} days)", get_client_ip())
    return jsonify({'settings': s})


def _settings():
    from pegaprox.core.db import get_db
    return rc.effective_settings(get_db().get_server_setting(rc.SETTINGS_KEY, None))


def _state():
    from pegaprox.core.db import get_db
    st = get_db().get_server_setting(rc.STATE_KEY, None)
    return st if isinstance(st, dict) else {}


# --- the weekly summary (the minute loop, on the active) -------------------------------------

def reclaim_tick(at=None):
    s = _settings()
    st = _state()
    at = at or datetime.now()
    if not rc.weekly_due(s, st.get('last_sent'), at):
        return False
    from pegaprox.core.db import get_db
    # outside a request there is no right-sizing (the core route reads the request): the
    # summary counts the other kinds and the page has the rest
    rep = build_report(s['days'], rightsizing=False)
    st['last_sent'] = rc.utcnow().isoformat(timespec='seconds')
    get_db().save_server_setting(rc.STATE_KEY, st)
    if not rep['totals']['items']:
        return True
    from pegaprox.api.vlab_ops_notices import _send
    _send(f"자원 회수 주간 요약: {rep['totals']['items']}건", rc.summary_text(rep),
          {'kind': 'reclaim_weekly', 'items': rep['totals']['items'], 'severity': 'info'})
    return True
