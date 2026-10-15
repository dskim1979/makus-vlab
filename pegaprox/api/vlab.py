# -*- coding: utf-8 -*-
"""
vLAB API (MAKUS) - the only API the vLAB console uses besides /api/auth/*.

  GET    /api/vlab/info                               product, API version (any signed-in user)
  GET    /api/vlab/me/desktops                        desktops assigned to the caller       vlab.desk
  GET    /api/vlab/me/leases                          cards/boards/desktops on loan         vlab.desk
  POST   /api/vlab/desktops/<desktop_id>/connect      {protocol: vnc|spice} -> how to connect  vlab.desk
  POST   /api/vlab/sessions/<session_id>/end          close the caller's own session        vlab.desk
  POST   /api/vlab/desktops/<desktop_id>/power        {action: start|shutdown|reboot|stop}  vlab.desk
  GET    /api/vlab/admin/audit                        audit log (?q=&user=&date_from=&date_to=&vlab_only=&offset=&limit=)  admin role
  GET    /api/vlab/admin/summary                      counts for the dashboard / system summary  vlab.pool.view
  GET    /api/vlab/admin/sessions                     session log (?username=&pool_id=&limit=)  vlab.report.view
  GET    /api/vlab/admin/usage                        usage report (?days=1..90&pool_id=): per day, pool, user  vlab.report.view
  GET    /api/vlab/admin/clusters                   clusters the caller can reach         vlab.pool.view
  GET    /api/vlab/admin/clusters/<cluster_id>/guests  guests (no templates), desktop or not  vlab.pool.view
  GET    /api/vlab/admin/clusters/<cluster_id>/nodes   nodes: load, memory, guests and desktops on each  vlab.pool.view
  GET    /api/vlab/admin/clusters/<cluster_id>/storage storage (shared ones once, with their nodes)  vlab.pool.view
  GET    /api/vlab/admin/clusters/<cluster_id>/accelerators  GPUs and FPGA cards per node, PCI mappings, who uses them  vlab.pool.view
  GET    /api/vlab/admin/clusters/<cluster_id>/nodes/<node>/pci/<pciid>/profiles  vGPU (mdev) profiles of a card  vlab.pool.view
  GET    /api/vlab/admin/pools/<pool_id>/policy       the pool's policy (connection, clipboard, USB, power, account)  vlab.pool.view
  PUT    /api/vlab/admin/pools/<pool_id>/policy       save it                                   vlab.pool.manage
  PUT    /api/vlab/admin/pools/<pool_id>/gpu          {mode: none|passthrough|vgpu, mapping, mdev_type?, label?}  vlab.pool.manage
  POST   /api/vlab/admin/pools/<pool_id>/gpu/apply    write the pool's GPU to every desktop VM (slot hostpci15)  vlab.pool.manage
  GET    /api/vlab/admin/leases                       card loans (?all=1 with returned ones)   vlab.accel.manage
  POST   /api/vlab/admin/leases                       {desktop_id, mapping, ends_at, name?} lend a card (slot hostpci14)  vlab.accel.manage
  POST   /api/vlab/admin/leases/<lease_id>/return     give it back now                          vlab.accel.manage
  POST   /api/vlab/admin/leases/<lease_id>/extend     {ends_at}                                 vlab.accel.manage
  POST   /api/vlab/admin/clusters                     connect a Proxmox cluster (core route does it)  cluster.add
  DELETE /api/vlab/admin/clusters/<cluster_id>        disconnect - refused while pools use it  cluster.delete
  GET    /api/vlab/admin/clusters/<cluster_id>/templates  templates to create desktops from (?details=1: disks, linked clone, pools)  vlab.pool.view
  POST   /api/vlab/admin/pools/<pool_id>/clone        {template_vmid, count, name_prefix, full?, start_vmid?}  vlab.pool.manage
  GET    /api/vlab/admin/users                        users in the caller's tenant (?all=1 with disabled)  vlab.pool.manage
  GET    /api/vlab/admin/directory                    AD/LDAP settings (bind password masked)  admin.settings
  PUT    /api/vlab/admin/directory                    save them (core settings route stores them)  admin.settings
  POST   /api/vlab/admin/directory/test               test with unsaved values (+ test_username?)  admin.settings
  GET    /api/vlab/admin/settings                     platform settings: sign-in, passwords, audit, mail  admin.settings
  PUT    /api/vlab/admin/settings                     save them (core settings route stores them)  admin.settings
  POST   /api/vlab/admin/settings/smtp-test           {email, smtp_*} send a test mail       admin.settings
  GET    /api/vlab/admin/users/<username>/access      effective access: desktops, VM ACL grants and their source  vlab.pool.manage
  GET    /api/vlab/admin/desktops                     every desktop of the reachable pools  vlab.pool.view
  GET    /api/vlab/admin/pools                        pools with desktop counts             vlab.pool.view
  POST   /api/vlab/admin/pools                        {name, type, cluster_id, description} vlab.pool.manage
  DELETE /api/vlab/admin/pools/<pool_id>              only an empty pool                    vlab.pool.manage
  GET    /api/vlab/admin/pools/<pool_id>/desktops     desktops of a pool                    vlab.pool.view
  POST   /api/vlab/admin/pools/<pool_id>/desktops     {node, vmid, type?, name?} add an existing guest   vlab.pool.manage
  DELETE /api/vlab/admin/desktops/<desktop_id>        take a desktop out of its pool (guest stays)       vlab.pool.manage
  PUT    /api/vlab/admin/desktops/<desktop_id>/assign {username|null}                       vlab.pool.manage
  POST   /api/vlab/admin/desktops/<desktop_id>/power  {action: start|shutdown|reboot|stop} any desktop  vlab.pool.manage
  POST   /api/vlab/admin/desktops/<desktop_id>/base   (re)take the base snapshot 'vlab-base'  vlab.pool.manage
  POST   /api/vlab/admin/desktops/<desktop_id>/reset  back to the base snapshot             vlab.pool.manage
  POST   /api/vlab/admin/pools/<pool_id>/reset        every desktop with a base {force?}    vlab.pool.manage

Assigning a desktop also grants the user on the core VM ACL, so the core console, SPICE
and snapshot routes authorise them exactly as they authorise any ACL user; unassigning
takes that grant away again. Every pool is bound to one cluster and the caller must be
able to reach that cluster (tenant scope) to see or change it. docs/vlab-design.md 3, 5, 6.
"""

import json
import re
import logging

from flask import Blueprint, jsonify, request

from pegaprox.api.helpers import acting_user, check_cluster_access
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import VLAB_API_VERSION
from pegaprox.vlab import accel
from pegaprox.vlab import policy as pool_policy
from pegaprox.vlab import store

bp = Blueprint('vlab', __name__)

DEFAULT_PROTOCOLS = ['vnc', 'spice']
MAX_NAME = 80


def _user():
    return request.session.get('user', '')


def _bad(msg, code=400):
    return jsonify({'error': msg}), code


def _vm_states(cluster_id):
    """{vmid: guest status} from the cluster's cached resource list; {} when unknown."""
    mgr = cluster_managers.get(cluster_id)
    if not mgr or not getattr(mgr, 'is_connected', False):
        return {}
    try:
        res = mgr.get_vm_resources() or []
    except Exception as e:
        logging.debug(f'[VLAB] resources of {cluster_id}: {e}')
        return {}
    out = {}
    for r in res:
        if isinstance(r, dict) and r.get('vmid') is not None:
            out[int(r['vmid'])] = r
    return out


BASE_SNAP = 'vlab-base'
RESET_POOL_TYPES = ('reset', 'classroom')   # pools whose desktops go back to their base after use


def _take_base(desk, node):
    """(Re)take the desktop's base snapshot. Returns an error text, or None when it worked."""
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr:
        return 'Cluster not connected'
    if desk.get('base_snap'):
        mgr.delete_snapshot(node, int(desk['vmid']), desk['vm_type'], desk['base_snap'])
    r = mgr.create_snapshot(node, int(desk['vmid']), desk['vm_type'], BASE_SNAP,
                            'vLAB base: reset goes back here', False)
    if not isinstance(r, dict) or not r.get('success'):
        return str((r or {}).get('error') if isinstance(r, dict) else r) or 'snapshot failed'
    store.set_base_snap(desk['id'], BASE_SNAP)
    return None


def _auto_base(d, vm):
    """A desktop of a reset/classroom pool gets its base right after its clone finished."""
    pool = store.get_pool(d['pool_id']) or {}
    if pool.get('type') not in RESET_POOL_TYPES or d.get('base_snap'):
        return
    err = _take_base(d, vm.get('node') or d['node'])
    if err:
        logging.warning(f"[VLAB] base snapshot of {d['vm_type']}/{d['vmid']} failed: {err}")


def _desktop_view(d, live):
    """What the console shows for one desktop (docs/vlab-design.md 4-3)."""
    state = d.get('state') or 'ready'
    vm = live.get(int(d['vmid']))
    if state == 'provisioning' and vm is not None and not vm.get('lock'):
        # the clone finished: the guest is on the cluster and no longer locked
        store.set_state(d['id'], 'ready')
        state = 'ready'
        _apply_gpu(d, vm.get('node') or d['node'], _gpu_policy(d.get('pool_settings')))
        _auto_base(d, vm)
    if state not in ('provisioning', 'resetting', 'error') and vm is not None:
        state = 'ready' if vm.get('status') == 'running' else 'stopped'
    settings = d.get('pool_settings')   # JSON text from the join, or the pool's parsed settings
    if isinstance(settings, str):
        try:
            settings = json.loads(settings or '{}')
        except ValueError:
            settings = {}
    protocols = (settings.get('protocols') if isinstance(settings, dict) else None) or DEFAULT_PROTOCOLS
    view = {
        'id': d['id'],
        'name': d['name'],
        'pool': d.get('pool_name', ''),
        'state': state,
        'protocols': protocols,
        'resources': [],
    }
    if vm is not None:
        spec = {}
        if vm.get('maxcpu'):
            spec['cpu'] = int(vm['maxcpu'])
        if vm.get('maxmem'):
            spec['memory_gb'] = round(int(vm['maxmem']) / 1024 ** 3)
        if spec:
            view['spec'] = spec
    gpu = _gpu_policy(settings)
    if gpu:
        view['gpu'] = {'mode': gpu['mode'], 'label': gpu.get('label') or gpu.get('mdev_type') or gpu['mapping']}
    return view


def _gpu_policy(settings):
    """The pool's GPU policy (settings.gpu) when it asks for one, else None."""
    if isinstance(settings, str):
        try:
            settings = json.loads(settings or '{}')
        except ValueError:
            return None
    g = (settings or {}).get('gpu') if isinstance(settings, dict) else None
    return g if isinstance(g, dict) and accel.gpu_value(g) else None


def _apply_gpu(desk, node, policy):
    """Write the pool's GPU into the desktop VM's own slot (accel.GPU_SLOT), or take it out
    when the pool has none. Other hostpci slots are never touched. Error text or None."""
    if desk.get('vm_type', 'qemu') != 'qemu':
        return 'containers take no GPU here' if policy else None
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr:
        return 'cluster not connected'
    want = accel.gpu_value(policy) if policy else None
    have = accel.hostpci_of(mgr, node, desk['vmid'])
    if have is None:
        return 'could not read the VM config'
    if (have.get(accel.GPU_SLOT) or None) == want:
        return None
    body = {accel.GPU_SLOT: want} if want else {'delete': accel.GPU_SLOT}
    try:
        r = mgr.update_vm_config(node, int(desk['vmid']), 'qemu', body)
    except Exception as e:
        return str(e)[:200]
    if not isinstance(r, dict) or not r.get('success'):
        return str((r or {}).get('error') if isinstance(r, dict) else r)[:200] or 'config update failed'
    return None


def _can_reach(cluster_id):
    ok, _ = check_cluster_access(cluster_id)
    return ok


# --- grants on the core VM ACL ---------------------------------------------------

def _acl_set(cluster_id, vmid, username, grant):
    """Add (grant=True) or remove the user on the guest's VM ACL. False when the ACL store
    could not be read - nothing is written then, so an unreadable store is never clobbered."""
    from pegaprox.core.db import get_db
    from pegaprox.utils.rbac import invalidate_vm_acls_cache, load_vm_acls, store_unavailable
    acls = load_vm_acls()
    if store_unavailable(acls):
        return False
    entry = dict((acls.get(cluster_id) or {}).get(str(vmid)) or {})
    users = set(entry.get('users') or [])
    if grant:
        users.add(username)
    else:
        users.discard(username)
    db = get_db()
    if users or entry.get('permissions'):
        db.save_vm_acl(cluster_id, str(vmid), {
            'users': sorted(users),
            'permissions': entry.get('permissions') or [],
            'inherit_role': entry.get('inherit_role', True),
        })
    else:
        db.delete_vm_acl(cluster_id, int(vmid))
    invalidate_vm_acls_cache()
    return True


# --- any signed-in user --------------------------------------------------------

@bp.route('/api/vlab/info', methods=['GET'])
@require_auth()
def vlab_info():
    return jsonify({'api_version': VLAB_API_VERSION, 'pool_types': list(store.POOL_TYPES)})


@bp.route('/api/vlab/me/desktops', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_desktops():
    rows = [d for d in store.desktops_of_user(_user()) if _can_reach(d['cluster_id'])]
    live = {}
    for cid in {d['cluster_id'] for d in rows}:
        live[cid] = _vm_states(cid)
    last = store.last_connected(_user())
    out = []
    for d in rows:
        v = _desktop_view(d, live.get(d['cluster_id'], {}))
        v['pool_type'] = d.get('pool_type', '')
        v['last_connected'] = last.get(d['id'])
        pol = pool_policy.effective(_settings_of(d))
        v['policy'] = {'clipboard': pol['clipboard'], 'allow_power': pol['allow_power'],
                       'start_on_connect': pol['start_on_connect']}
        out.append(v)
    return jsonify({'desktops': out})


@bp.route('/api/vlab/me/leases', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_leases():
    out = []
    desks = {(d['cluster_id'], d['vmid']): d for d in store.desktops_of_user(_user())}
    for l in store.active_leases_of_user(_user()):
        d = desks.get((l['cluster_id'], l['vmid']))
        out.append({'id': l['id'], 'kind': l['resource_type'], 'name': l['resource_name'] or l['resource_id'],
                    'ends_at': l['ends_at'], 'desktop': d['name'] if d else None})
    return jsonify({'leases': out})


# --- connecting -------------------------------------------------------------------

def _settings_of(d):
    s = d.get('pool_settings')
    if isinstance(s, str):
        try:
            return json.loads(s or '{}')
        except ValueError:
            return {}
    return s if isinstance(s, dict) else {}


def _vv_file(data, pol=None):
    """virt-viewer .vv from PVE's spiceproxy answer (same assembly as the core SPICE route),
    with the pool policy's SPICE options."""
    lines = ['[virt-viewer]']
    if pol:
        data = dict(data)
        data['enable-usbredir'] = 1 if pol['usb_redirect'] else 0
        data['enable-usb-autoshare'] = 1 if pol['usb_redirect'] and pol['usb_autoshare'] else 0
        data['delete-this-file'] = 1
        if pol['spice_fullscreen']:
            data['fullscreen'] = 1
    if 'type' not in data:
        lines.append('type=spice')
    for k, v in data.items():
        if v is None:
            continue
        val = str(v)
        if k == 'ca':
            val = val.replace('\r\n', '\n').replace('\n', '\\n')
        lines.append(f'{k}={val}')
    return '\n'.join(lines) + '\n'


@bp.route('/api/vlab/desktops/<desktop_id>/connect', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def connect_desktop(desktop_id):
    """How the caller reaches their desktop (docs/vlab-design.md 7-2).

    vnc   -> {ws_path, password}: the console opens noVNC on the engine's VNC websocket
    spice -> {vv, filename}: a virt-viewer file; remote-viewer goes through the node's spiceproxy
    Only the desktop's assigned user may connect, and the core VM ACL must still say so."""
    from urllib.parse import quote

    from pegaprox.api.ha import standby_console_refusal
    from pegaprox.utils.auth import request_credential, resolve_authz_user
    from pegaprox.utils.rbac import user_can_access_vm

    refused = standby_console_refusal()
    if refused:
        return refused
    username = _user()
    desk = store.get_desktop(desktop_id)
    if not desk or desk['assigned_user'] != username or not _can_reach(desk['cluster_id']):
        return _bad('Desktop not found', 404)
    data = request.get_json(silent=True) or {}
    protocol = data.get('protocol') or 'vnc'
    pool = store.get_pool(desk['pool_id']) or {}
    pol = pool_policy.effective(pool.get('settings'))
    allowed = pol['protocols']
    if protocol not in allowed:
        return _bad(f"protocol must be one of {', '.join(allowed)}")

    user = resolve_authz_user(request.session)
    if not user or not user_can_access_vm(user, desk['cluster_id'], int(desk['vmid']), 'vm.console', desk['vm_type']):
        return _bad('Permission denied: vm.console', 403)
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    vm = _vm_states(desk['cluster_id']).get(int(desk['vmid']))
    if vm is None:
        return _bad("The desktop's VM is not on the cluster any more", 404)
    if vm.get('status') != 'running':
        if pol['start_on_connect'] and not vm.get('lock'):
            r = mgr.vm_action(vm.get('node') or desk['node'], int(desk['vmid']), desk['vm_type'], 'start')
            if isinstance(r, dict) and r.get('success'):
                log_audit(username, 'vm.start', f"vLAB: start on connect '{desk['name']}' ({desk['vm_type']}/{desk['vmid']})",
                          get_client_ip())
                return jsonify({'error': 'The desktop is starting - connect again in a moment', 'code': 'STARTING'}), 409
        return jsonify({'error': 'The desktop is not running', 'code': 'VM_STOPPED'}), 409
    node, vmid, vm_type = vm.get('node') or desk['node'], int(desk['vmid']), desk['vm_type']

    if protocol == 'spice':
        if vm_type != 'qemu':
            return _bad('SPICE is only available for QEMU VMs')
        result = mgr.get_spice_ticket(node, vmid, vm_type)
        if not result.get('success'):
            err = str(result.get('error', 'Failed'))
            if 'no spice port' in err.lower():
                return jsonify({'error': 'This VM has no SPICE display', 'code': 'NO_SPICE'}), 409
            return _bad(err, 502)
        answer = {'type': 'spice', 'vv': _vv_file(result.get('data') or {}, pol), 'filename': f"{desk['name']}.vv"}
    else:
        result = mgr.get_vnc_ticket(node, vmid, vm_type)
        if not result.get('success'):
            return _bad(str(result.get('error', 'Console failed')), 502)
        from pegaprox.utils.realtime import create_ws_token
        ws_token = create_ws_token(username, user.get('effective_role', user.get('role', 'viewer')),
                                   sid=request_credential()[0])
        ticket, port = result.get('ticket') or '', result.get('port') or ''
        ws_path = (f"/api/clusters/{quote(desk['cluster_id'], safe='')}/vms/{quote(str(node), safe='')}/"
                   f"{vm_type}/{vmid}/vncwebsocket?token={quote(ws_token, safe='')}")
        if ticket and port:
            # hand vncproxy's ticket/port on, or the websocket handler mints a second vncproxy
            # whose password no longer matches this one (PVE 9.1)
            ws_path += f"&pve_ticket={quote(str(ticket), safe='')}&pve_port={quote(str(port), safe='')}"
        answer = {'type': 'vnc', 'ws_path': ws_path, 'password': ticket, 'clipboard': pol['clipboard']}

    answer['session_id'] = store.start_session(username, desk, protocol, get_client_ip())
    log_audit(username, 'vm.console', f"vLAB: {protocol} to desktop '{desk['name']}' ({vm_type}/{vmid})",
              get_client_ip())
    return jsonify(answer)


@bp.route('/api/vlab/sessions/<session_id>/end', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def end_session(session_id):
    row = store.db().query_one('SELECT desktop_id FROM vlab_sessions WHERE id = ?', (session_id,))
    if not store.end_session(session_id, _user()):
        return _bad('Session not found', 404)
    if row and row['desktop_id']:
        _after_session(store.get_desktop(row['desktop_id']), by=_user())
    return jsonify({'success': True})


# power action -> the core permission the VM ACL must grant for it
POWER_ACTIONS = {'start': 'vm.start', 'shutdown': 'vm.stop', 'stop': 'vm.stop', 'reboot': 'vm.restart'}


@bp.route('/api/vlab/desktops/<desktop_id>/power', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def power_desktop(desktop_id):
    """The assigned user switches their own desktop on/off. The core VM ACL must still grant
    the matching vm.* permission; 'stop' is the hard power-off, 'shutdown' asks the guest."""
    from pegaprox.utils.auth import resolve_authz_user
    from pegaprox.utils.rbac import user_can_access_vm

    username = _user()
    desk = store.get_desktop(desktop_id)
    if not desk or desk['assigned_user'] != username or not _can_reach(desk['cluster_id']):
        return _bad('Desktop not found', 404)
    action = (request.get_json(silent=True) or {}).get('action')
    if action not in POWER_ACTIONS:
        return _bad(f"action must be one of {', '.join(POWER_ACTIONS)}")
    if not pool_policy.effective((store.get_pool(desk['pool_id']) or {}).get('settings'))['allow_power']:
        return jsonify({'error': 'Power control is turned off for this pool', 'code': 'POWER_OFF'}), 403
    user = resolve_authz_user(request.session)
    if not user or not user_can_access_vm(user, desk['cluster_id'], int(desk['vmid']), POWER_ACTIONS[action],
                                          desk['vm_type']):
        return _bad(f'Permission denied: {POWER_ACTIONS[action]}', 403)
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    vm = _vm_states(desk['cluster_id']).get(int(desk['vmid']))
    if vm is None:
        return _bad("The desktop's VM is not on the cluster any more", 404)
    node = vm.get('node') or desk['node']
    result = mgr.vm_action(node, int(desk['vmid']), desk['vm_type'], action)
    if not isinstance(result, dict) or not result.get('success'):
        err = result.get('error') if isinstance(result, dict) else None
        return _bad(str(err or f'{action} failed'), 502)
    log_audit(username, f'vm.{action}', f"vLAB: {action} desktop '{desk['name']}' ({desk['vm_type']}/{desk['vmid']})",
              get_client_ip())
    return jsonify({'success': True, 'action': action, 'task': result.get('data') or result.get('upid')})


# --- admin: session log ------------------------------------------------------------

@bp.route('/api/vlab/admin/sessions', methods=['GET'])
@require_auth(perms=['vlab.report.view'])
def session_log():
    try:
        limit = max(1, min(int(request.args.get('limit', 200)), 1000))
    except ValueError:
        return _bad('limit must be a number')
    pools = {p['id']: p for p in store.list_pools() if _can_reach(p['cluster_id'])}
    desks = {d['id']: d for d in store.list_desktops()}
    rows = store.list_sessions(username=request.args.get('username') or None,
                               pool_id=request.args.get('pool_id') or None, limit=limit * 2)
    out = []
    for s in rows:
        if s['pool_id'] not in pools:
            continue   # pools outside the caller's reach, or deleted since
        d = desks.get(s['desktop_id']) or {}
        out.append({**s, 'pool': pools[s['pool_id']]['name'], 'desktop': d.get('name', ''), 'vmid': d.get('vmid')})
        if len(out) >= limit:
            break
    return jsonify({'sessions': out})


# --- admin: usage report ----------------------------------------------------------

# a session nobody ended (the window was just closed) would otherwise count until now
OPEN_SESSION_CAP_HOURS = 12


def _ts(iso):
    from datetime import datetime, timezone
    t = datetime.fromisoformat(iso)
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _peak(spans):
    """most spans open at once; a span ending exactly when another starts does not overlap it"""
    events = sorted([(a, 1) for a, _ in spans] + [(b, -1) for _, b in spans], key=lambda e: (e[0], e[1]))
    peak = cur = 0
    for _, step in events:
        cur += step
        peak = max(peak, cur)
    return peak


def _hours(spans):
    return round(sum((b - a).total_seconds() for _, a, b in spans) / 3600, 2)


@bp.route('/api/vlab/admin/usage', methods=['GET'])
@require_auth(perms=['vlab.report.view'])
def usage_report():
    """운영 > 사용률 보고서: the sessions of the last `days` days (local days, today included)
    per day, per pool and per user, within the caller's reach. Connected time is clipped to
    the window; a session still open counts up to now, at most OPEN_SESSION_CAP_HOURS.
    utilization = connected hours / (desktops in the pool x hours in the window)."""
    from datetime import datetime, timedelta, timezone
    try:
        days = int(request.args.get('days', 7))
    except ValueError:
        return _bad('days must be a number')
    if not 1 <= days <= 90:
        return _bad('days must be 1..90')
    pools = {p['id']: p for p in store.list_pools() if _can_reach(p['cluster_id'])}
    only = request.args.get('pool_id') or None
    if only:
        if only not in pools:
            return jsonify({'error': 'pool not found'}), 404
        pools = {only: pools[only]}
    desk_count = {}
    for d in store.list_desktops():
        if d['pool_id'] in pools:
            desk_count[d['pool_id']] = desk_count.get(d['pool_id'], 0) + 1

    now = datetime.now(timezone.utc)
    midnight = datetime.now().astimezone().replace(hour=0, minute=0, second=0, microsecond=0)
    day_starts = [(midnight - timedelta(days=days - 1 - i)).astimezone(timezone.utc) for i in range(days)]
    start = day_starts[0]
    cap = timedelta(hours=OPEN_SESSION_CAP_HOURS)

    spans, open_now = [], 0   # (session, begin, end) clipped to the window
    for s in store.sessions_overlapping(start.isoformat(timespec='seconds'), now.isoformat(timespec='seconds')):
        if s['pool_id'] not in pools:
            continue
        a = _ts(s['started_at'])
        if s['ended_at']:
            b = _ts(s['ended_at'])
        else:
            b = min(now, a + cap)
            open_now += 1
        a, b = max(a, start), min(b, now)
        if b >= a:
            spans.append((s, a, b))

    by_day = []
    for i, ds in enumerate(day_starts):
        de = day_starts[i + 1] if i + 1 < days else now
        started = [x for x in spans if ds <= _ts(x[0]['started_at']) < de]
        inside = [(s, max(a, ds), min(b, de)) for s, a, b in spans if a < de and b > ds]
        by_day.append({'date': ds.astimezone(midnight.tzinfo).date().isoformat(),
                       'sessions': len(started), 'users': len({x[0]['username'] for x in started}),
                       'hours': _hours(inside), 'peak': _peak([(a, b) for _, a, b in inside])})

    window_h = max((now - start).total_seconds() / 3600, 1e-9)
    by_pool = []
    for pid, p in pools.items():
        mine = [x for x in spans if x[0]['pool_id'] == pid]
        h, n = _hours(mine), desk_count.get(pid, 0)
        by_pool.append({'id': pid, 'name': p['name'], 'type': p['type'], 'desktops': n,
                        'sessions': len(mine), 'users': len({x[0]['username'] for x in mine}),
                        'hours': h, 'utilization': round(h / (n * window_h), 4) if n else 0.0})
    by_pool.sort(key=lambda r: (-r['hours'], r['name']))

    per_user = {}
    for s, a, b in spans:
        u = per_user.setdefault(s['username'], {'username': s['username'], 'sessions': 0, 'seconds': 0.0, 'last': ''})
        u['sessions'] += 1
        u['seconds'] += (b - a).total_seconds()
        u['last'] = max(u['last'], s['started_at'])
    top_users = sorted(({'username': u['username'], 'sessions': u['sessions'],
                         'hours': round(u['seconds'] / 3600, 2), 'last': u['last']} for u in per_user.values()),
                       key=lambda r: (-r['hours'], r['username']))[:20]

    protocols = {}
    for s, _, _ in spans:
        k = s['protocol'] or '-'
        protocols[k] = protocols.get(k, 0) + 1
    total_h = _hours(spans)
    return jsonify({
        'days': days, 'from': start.isoformat(timespec='seconds'), 'to': now.isoformat(timespec='seconds'),
        'totals': {'sessions': len(spans), 'users': len(per_user), 'hours': total_h,
                   'avg_minutes': round(total_h * 60 / len(spans), 1) if spans else 0.0,
                   'peak': _peak([(a, b) for _, a, b in spans]), 'open': open_now},
        'by_day': by_day, 'by_pool': by_pool, 'top_users': top_users, 'by_protocol': protocols,
        'open_session_cap_hours': OPEN_SESSION_CAP_HOURS,
    })


# --- admin: what the pool screens pick from ---------------------------------------

def _cluster_name(cid, mgr):
    cfg = getattr(mgr, 'config', None)
    name = getattr(cfg, 'name', None)
    return name if isinstance(name, str) and name else cid


@bp.route('/api/vlab/admin/clusters', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_clusters():
    pools_per = {}
    for p in store.list_pools():
        pools_per[p['cluster_id']] = pools_per.get(p['cluster_id'], 0) + 1
    out = []
    for cid, mgr in list(cluster_managers.items()):
        if not _can_reach(cid):
            continue
        cfg = getattr(mgr, 'config', None)
        host = getattr(cfg, 'host', '')
        err = getattr(mgr, 'connection_error', None)
        out.append({'id': cid, 'name': _cluster_name(cid, mgr),
                    'connected': bool(getattr(mgr, 'is_connected', False)),
                    'host': host if isinstance(host, str) else '',
                    'connection_error': err if isinstance(err, str) else None,
                    'pools': pools_per.get(cid, 0)})
    out.sort(key=lambda c: c['name'])
    return jsonify({'clusters': out})


# fields the console may send when connecting a Proxmox cluster; anything else is refused,
# so the console cannot reach engine settings it has no screen for
_CLUSTER_FIELDS = {'name', 'host', 'user', 'pass', 'ssl_verification'}


@bp.route('/api/vlab/admin/clusters', methods=['POST'])
@require_auth(perms=['cluster.add'])
def connect_cluster():
    """Connect a Proxmox VE cluster: {name, host, user, pass, ssl_verification?}. Checked here,
    then handed to the core route, which tests the connection, stores the credentials
    encrypted, creates its own API token on the cluster when it can, and starts the manager."""
    from pegaprox.api.clusters import add_cluster

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _bad('JSON body required')
    extra = sorted(set(data) - _CLUSTER_FIELDS)
    if extra:
        return _bad(f"unknown fields: {', '.join(extra)}")
    for f in ('name', 'host', 'user'):
        if not isinstance(data.get(f), str) or not data[f].strip():
            return _bad(f'{f} is required')
    if not isinstance(data.get('pass'), str) or not data['pass']:
        return _bad('pass is required')
    if 'ssl_verification' in data and not isinstance(data['ssl_verification'], bool):
        return _bad('ssl_verification must be true or false')
    if len(data['name']) > MAX_NAME:
        return _bad(f'name: at most {MAX_NAME} characters')
    return add_cluster()


@bp.route('/api/vlab/admin/clusters/<cluster_id>', methods=['DELETE'])
@require_auth(perms=['cluster.delete'])
def disconnect_cluster(cluster_id):
    """Disconnect a cluster - refused while vLAB pools still use it (their desktops and grants
    would be left pointing at nothing). The core route does the rest."""
    from pegaprox.api.clusters import delete_cluster

    if cluster_id not in cluster_managers or not _can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    if any(p['cluster_id'] == cluster_id for p in store.list_pools()):
        return _bad('vLAB pools still use this cluster - delete them first', 409)
    return delete_cluster(cluster_id)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/guests', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def cluster_guests(cluster_id):
    if cluster_id not in cluster_managers or not _can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    desks = {d['vmid']: d for d in store.list_desktops() if d['cluster_id'] == cluster_id}
    out = []
    for vmid, vm in sorted(_vm_states(cluster_id).items()):
        if vm.get('template') or vm.get('type') not in ('qemu', 'lxc'):
            continue
        d = desks.get(vmid)
        out.append({'vmid': vmid, 'name': vm.get('name') or f'vm-{vmid}', 'node': vm.get('node', ''),
                    'type': vm.get('type'), 'status': vm.get('status', ''),
                    'desktop_id': d['id'] if d else None, 'pool_id': d['pool_id'] if d else None})
    return jsonify({'guests': out})


# --- admin: cluster nodes and storage (클러스터 > 개요·노드·스토리지, read only) -------

def _num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else 0


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def cluster_nodes(cluster_id):
    """The nodes as the core sees them (cached a few seconds there), with how many guests
    and vLAB desktops each one runs."""
    mgr = cluster_managers.get(cluster_id)
    if not mgr or not _can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    try:
        status = mgr.get_node_status() or {}
    except Exception as e:
        logging.warning(f'[VLAB] node status of {cluster_id}: {e}')
        return jsonify({'error': 'Could not read the nodes'}), 502
    if not isinstance(status, dict):
        status = {}
    guests, running, desks = {}, {}, {}
    for vm in _vm_states(cluster_id).values():
        if vm.get('template') or vm.get('type') not in ('qemu', 'lxc'):
            continue
        n = vm.get('node', '')
        guests[n] = guests.get(n, 0) + 1
        if vm.get('status') == 'running':
            running[n] = running.get(n, 0) + 1
    for d in store.list_desktops():
        if d['cluster_id'] == cluster_id:
            desks[d['node']] = desks.get(d['node'], 0) + 1
    out = []
    for name, s in sorted(status.items()):
        if not isinstance(s, dict):
            continue
        info = s.get('cpuinfo') if isinstance(s.get('cpuinfo'), dict) else {}
        load = s.get('loadavg') if isinstance(s.get('loadavg'), list) else []
        out.append({
            'node': name, 'status': s.get('status', 'unknown'), 'online': not s.get('offline') and s.get('status') == 'online',
            'cpu_percent': _num(s.get('cpu_percent')), 'cpus': _num(info.get('cpus')), 'cpu_model': info.get('model') or '',
            'mem_used': _num(s.get('mem_used')), 'mem_total': _num(s.get('mem_total')), 'mem_percent': _num(s.get('mem_percent')),
            'disk_used': _num(s.get('disk_used')), 'disk_total': _num(s.get('disk_total')),
            'uptime': _num(s.get('uptime')), 'loadavg': [str(x) for x in load[:3]],
            'version': s.get('pveversion') or '', 'maintenance': bool(s.get('maintenance_mode')),
            'guests': guests.get(name, 0), 'running': running.get(name, 0), 'desktops': desks.get(name, 0),
        })
    return jsonify({'nodes': out, 'connected': bool(getattr(mgr, 'is_connected', False))})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/storage', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def cluster_storage(cluster_id):
    """Every storage of a Proxmox cluster from the core's cluster-wide read. A shared
    storage is listed once, with the nodes that see it."""
    from pegaprox.api import clusters as core_clusters
    mgr = cluster_managers.get(cluster_id)
    if not mgr or not _can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        return jsonify({'storage': [], 'note': 'only Proxmox clusters list storage here'})
    rows = core_clusters.cluster_storage_resources(cluster_id, mgr)
    if rows is None:
        return jsonify({'error': 'Could not read the storage'}), 502
    out, shared = [], {}
    for s in rows:
        name = s.get('storage') or '?'
        item = {'storage': name, 'type': s.get('plugintype') or '', 'shared': bool(s.get('shared')),
                'content': [c for c in str(s.get('content') or '').split(',') if c],
                'status': s.get('status') or 'unknown', 'used': _num(s.get('disk')), 'total': _num(s.get('maxdisk')),
                'nodes': [s.get('node') or '?']}
        if item['shared']:
            if name in shared:
                shared[name]['nodes'].append(item['nodes'][0])
                if shared[name]['status'] != 'available' and item['status'] == 'available':
                    shared[name].update(status='available', used=item['used'], total=item['total'])
                continue
            shared[name] = item
        out.append(item)
    for item in out:
        item['nodes'].sort()
    out.sort(key=lambda x: (not x['shared'], x['storage'], x['nodes']))
    return jsonify({'storage': out})


# --- admin: accelerators (가속 자원 > GPU·가속 카드 재고, vGPU 프로필, 리소스 매핑) -------

@bp.route('/api/vlab/admin/clusters/<cluster_id>/accelerators', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def cluster_accelerators(cluster_id):
    """GPUs and FPGA cards of every online node, the cluster's PCI mappings, and which
    guests use them (from the guests' hostpci entries; a guest on a mapping is counted on
    the mapping, PVE picks its card when it starts). docs/vlab-design.md 10-0."""
    mgr = cluster_managers.get(cluster_id)
    if not mgr or not _can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        return jsonify({'devices': [], 'mappings': [], 'note': 'only Proxmox clusters list accelerators here'})
    if not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    vms = _vm_states(cluster_id)
    nodes = sorted({vm.get('node') for vm in vms.values() if vm.get('node')})
    try:
        status = mgr.get_node_status() or {}
        if isinstance(status, dict) and status:
            nodes = sorted(n for n, x in status.items() if isinstance(x, dict) and not x.get('offline'))
    except Exception:
        pass
    devices, unreadable = [], []
    for node in nodes:
        pci = accel.node_pci(mgr, node)
        if pci is None:
            unreadable.append(node)
            continue
        devices += [accel.device_view(node, d) for d in pci if accel.classify(d)]
    mappings = accel.pci_mappings(mgr)
    desks = {(d['vmid']): d for d in store.list_desktops() if d['cluster_id'] == cluster_id}
    pools = {p['id']: p['name'] for p in store.list_pools()}

    # who uses what: only guests on nodes that have an accelerator, or on a mapping
    accel_nodes = {d['node'] for d in devices}
    used_raw, used_map = {}, {}
    for vmid, vm in vms.items():
        if vm.get('type') != 'qemu' or vm.get('template') or (vm.get('node') not in accel_nodes and not mappings):
            continue
        slots = accel.hostpci_of(mgr, vm.get('node', ''), vmid) or {}
        for slot, value in slots.items():
            h = accel.parse_hostpci(value)
            d = desks.get(vmid)
            who = {'vmid': vmid, 'name': vm.get('name') or f'vm-{vmid}', 'node': vm.get('node', ''),
                   'status': vm.get('status', ''), 'slot': slot, 'mdev': h['mdev'],
                   'desktop_id': d['id'] if d else None, 'pool': pools.get(d['pool_id']) if d else None}
            if h['mapping']:
                used_map.setdefault(h['mapping'], []).append(who)
            for dev in devices:
                if dev['node'] == vm.get('node') and h['addresses'] and accel.address_matches(dev['pciid'], h['addresses']):
                    used_raw.setdefault((dev['node'], dev['pciid']), []).append(who)
    for dev in devices:
        dev['used_by'] = used_raw.get((dev['node'], dev['pciid']), [])
        dev['mappings'] = [m['id'] for m in mappings or []
                           if any(x['node'] == dev['node'] and accel.address_matches(dev['pciid'], [x['path']])
                                  for x in m['devices'])]
    for m in mappings or []:
        m['used_by'] = used_map.get(m['id'], [])
        m['pools'] = sorted(p['name'] for p in store.list_pools()
                            if p['cluster_id'] == cluster_id and ((p.get('settings') or {}).get('gpu') or {}).get('mapping') == m['id'])
    gpus = [d for d in devices if d['kind'] == 'gpu']
    return jsonify({
        'devices': devices, 'mappings': mappings if mappings is not None else [],
        'mappings_readable': mappings is not None, 'unreadable_nodes': unreadable,
        'summary': {'gpus': len(gpus), 'fpgas': len(devices) - len(gpus),
                    'vgpu_capable': sum(1 for d in gpus if d['vgpu_capable']),
                    'in_use': sum(1 for d in devices if d['used_by']) + sum(1 for m in mappings or [] if m['used_by'])},
    })


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/pci/<pciid>/profiles', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def card_profiles(cluster_id, node, pciid):
    mgr = cluster_managers.get(cluster_id)
    if not mgr or not _can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    if not accel.PCI_ID.match(pciid) or not re.match(r'^[a-zA-Z][a-zA-Z0-9.\-]{0,62}$', node):
        return _bad('Invalid node or PCI id')
    profiles = accel.mdev_types(mgr, node, pciid)
    if profiles is None:
        return jsonify({'error': 'Could not read the profiles'}), 502
    return jsonify({'node': node, 'pciid': pciid, 'profiles': profiles})


@bp.route('/api/vlab/admin/pools/<pool_id>/gpu', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def set_pool_gpu(pool_id):
    """The pool's GPU: none, a whole card from a mapping, or a vGPU profile on a mapping.
    Saved only - POST .../gpu/apply writes it to the desktops (new clones get it by themselves)."""
    pool, err = _pool_or_error(pool_id)
    if err:
        return err
    data = request.get_json(silent=True) or {}
    mode = data.get('mode')
    if mode not in ('none', 'passthrough', 'vgpu'):
        return _bad('mode must be none, passthrough or vgpu')
    policy = {'mode': mode}
    if mode != 'none':
        mapping = data.get('mapping')
        if not isinstance(mapping, str) or not accel.MAPPING_ID.match(mapping):
            return _bad('mapping: the id of a PCI resource mapping')
        mappings = accel.pci_mappings(cluster_managers.get(pool['cluster_id'])) if pool['cluster_id'] in cluster_managers else None
        if mappings is not None and mapping not in {m['id'] for m in mappings}:
            return _bad(f"No PCI mapping '{mapping}' on this cluster", 404)
        policy['mapping'] = mapping
        if mode == 'vgpu':
            mdev = data.get('mdev_type')
            if not isinstance(mdev, str) or not accel.MDEV_TYPE.match(mdev):
                return _bad('mdev_type: a vGPU profile type such as nvidia-746')
            policy['mdev_type'] = mdev
        else:
            policy['x_vga'] = bool(data.get('x_vga', False))
        label = data.get('label')
        if label is not None:
            if not isinstance(label, str) or len(label) > 60:
                return _bad('label: up to 60 characters')
            policy['label'] = label.strip()
    store.set_pool_settings(pool['id'], dict(pool.get('settings') or {}, gpu=policy))
    log_audit(_user(), 'vlab.pool.gpu', f"pool '{pool['name']}': {mode}"
              + (f" {policy['mapping']}" if mode != 'none' else '') + (f" {policy.get('mdev_type')}" if mode == 'vgpu' else ''),
              get_client_ip())
    return jsonify({'gpu': policy})


@bp.route('/api/vlab/admin/pools/<pool_id>/gpu/apply', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def apply_pool_gpu(pool_id):
    """Write the pool's GPU to every desktop VM of it (or take it out for 'none'). A running
    VM gets it at its next start. Each desktop's outcome is reported."""
    pool, err = _pool_or_error(pool_id)
    if err:
        return err
    policy = _gpu_policy(pool.get('settings'))
    live = _vm_states(pool['cluster_id'])
    done, failed, pending = [], [], []
    for d in store.list_desktops(pool['id']):
        vm = live.get(int(d['vmid']))
        if vm is None:
            failed.append({'id': d['id'], 'name': d['name'], 'error': 'the VM is not on the cluster'})
            continue
        e = _apply_gpu(d, vm.get('node') or d['node'], policy)
        if e:
            failed.append({'id': d['id'], 'name': d['name'], 'error': e})
            continue
        done.append(d['id'])
        if vm.get('status') == 'running':
            pending.append(d['id'])
    log_audit(_user(), 'vlab.pool.gpu.apply', f"pool '{pool['name']}': {len(done)} applied, {len(failed)} failed",
              get_client_ip())
    return jsonify({'applied': done, 'failed': failed, 'needs_restart': pending}), (200 if not failed else 207)


# --- pool policy (데스크톱 풀 > 풀 > 정책) -------------------------------------------

def _after_session(desk, by='system'):
    """A session of the desktop closed: back to its base when the pool resets on logout
    and nobody else is still on it. Error text or None."""
    if not desk:
        return None
    pool = store.get_pool(desk['pool_id']) or {}
    pol = pool_policy.effective(pool.get('settings'))
    if not pol['reset_on_logout'] or pool.get('type') not in pool_policy.RESET_TYPES or not desk.get('base_snap'):
        return None
    if desk['id'] in store.open_session_desktops():
        return None
    e = _reset_one(desk)
    log_audit(by, 'vlab.desktop.reset', f"{desk['vm_type']}/{desk['vmid']} '{desk['name']}' on logout"
              + (f' - failed: {e}' if e else ''), get_client_ip() if by != 'system' else '')
    return e


@bp.route('/api/vlab/admin/pools/<pool_id>/policy', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_pool_policy(pool_id):
    pool, err = _pool_or_error(pool_id)
    if err:
        return err
    return jsonify({'policy': pool_policy.effective(pool.get('settings')), 'defaults': pool_policy.DEFAULTS,
                    'reset_allowed': pool.get('type') in pool_policy.RESET_TYPES})


@bp.route('/api/vlab/admin/pools/<pool_id>/policy', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def set_pool_policy(pool_id):
    pool, err = _pool_or_error(pool_id)
    if err:
        return err
    pol, e = pool_policy.validate(request.get_json(silent=True), pool.get('type'))
    if e:
        return _bad(e)
    settings = dict(pool.get('settings') or {}, policy=pol, protocols=pol['protocols'])
    store.set_pool_settings(pool['id'], settings)
    log_audit(_user(), 'vlab.pool.policy', f"pool '{pool['name']}': " + ', '.join(f'{k}={v}' for k, v in pol.items()),
              get_client_ip())
    return jsonify({'policy': pol})


def _ts_utc(iso):
    from datetime import datetime, timezone
    t = datetime.fromisoformat(iso)
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def policy_tick(now=None):
    """Once a minute (pegaprox/vlab/loans.py): close sessions open past max_session_hours,
    then shut down desktops idle past idle_shutdown_min. Returns what it did."""
    from datetime import datetime, timedelta, timezone
    now = now or datetime.now(timezone.utc)
    pools = {p['id']: p for p in store.list_pools()}
    policies = {pid: pool_policy.effective(p.get('settings')) for pid, p in pools.items()}
    done = {'expired': 0, 'shutdown': 0}

    for s in store.open_sessions():
        pol = policies.get(s['pool_id'])
        if not pol or not pol['max_session_hours']:
            continue
        if now - _ts_utc(s['started_at']) >= timedelta(hours=pol['max_session_hours']):
            store.close_session(s['id'], 'expired', at=now.isoformat(timespec='seconds'))
            done['expired'] += 1
            log_audit('system', 'vlab.session.expired', f"session {s['id']} of {s['username']} after "
                      f"{pol['max_session_hours']} h")
            _after_session(store.get_desktop(s['desktop_id']) if s['desktop_id'] else None)

    idle_pools = {pid for pid, pol in policies.items() if pol['idle_shutdown_min']}
    if idle_pools:
        open_now = store.open_session_desktops()
        last_end = store.last_end_per_desktop()
        live = {}
        for d in store.list_desktops():
            if d['pool_id'] not in idle_pools or d['id'] in open_now or d.get('state') in ('provisioning', 'resetting'):
                continue
            if d['cluster_id'] not in live:
                live[d['cluster_id']] = _vm_states(d['cluster_id'])
            vm = live[d['cluster_id']].get(int(d['vmid']))
            if not vm or vm.get('status') != 'running' or vm.get('lock'):
                continue
            limit = timedelta(minutes=policies[d['pool_id']]['idle_shutdown_min'])
            # up at least that long, and no session ended within it
            if timedelta(seconds=float(vm.get('uptime') or 0)) < limit:
                continue
            if last_end.get(d['id']) and now - _ts_utc(last_end[d['id']]) < limit:
                continue
            mgr = cluster_managers.get(d['cluster_id'])
            r = mgr.vm_action(vm.get('node') or d['node'], int(d['vmid']), d['vm_type'], 'shutdown') if mgr else None
            if isinstance(r, dict) and r.get('success'):
                done['shutdown'] += 1
                log_audit('system', 'vm.shutdown', f"vLAB: idle shutdown '{d['name']}' ({d['vm_type']}/{d['vmid']}) "
                          f"after {policies[d['pool_id']]['idle_shutdown_min']} min")
    return done


# --- admin: card loans (가속 자원 > 카드 대여 현황) ----------------------------------
# A loan puts one card of a PCI mapping on a user's desktop until ends_at, in vLAB's loan
# slot (accel.LEASE_SLOT); PVE picks a free card of the mapping when the VM starts. A
# mapping lends at most as many cards at once as it has. Expired loans are returned by
# pegaprox/vlab/loans.py. docs/vlab-design.md 10-0, 10-1.

def _utc_iso(value):
    """ISO text (any offset) -> UTC ISO text like store.now(), or None"""
    from datetime import datetime, timezone
    if not isinstance(value, str):
        return None
    try:
        t = datetime.fromisoformat(value.strip().replace('Z', '+00:00'))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.astimezone()   # the engine's local time
    return t.astimezone(timezone.utc).isoformat(timespec='seconds')


def _set_slot(cluster_id, node, vmid, slot, value):
    """Write (or with None delete) one hostpci slot of a VM. Error text or None."""
    mgr = cluster_managers.get(cluster_id)
    if not mgr:
        return 'cluster not connected'
    have = accel.hostpci_of(mgr, node, vmid)
    if have is None:
        return 'could not read the VM config'
    if (have.get(slot) or None) == value:
        return None
    try:
        r = mgr.update_vm_config(node, int(vmid), 'qemu', {slot: value} if value else {'delete': slot})
    except Exception as e:
        return str(e)[:200]
    if not isinstance(r, dict) or not r.get('success'):
        return str((r or {}).get('error') if isinstance(r, dict) else r)[:200] or 'config update failed'
    return None


def return_lease(lease, by='system'):
    """Take the card off the desktop and close the loan. Error text or None (closed)."""
    vm = _vm_states(lease['cluster_id']).get(int(lease['vmid'])) if lease.get('vmid') is not None else None
    if vm is not None:
        e = _set_slot(lease['cluster_id'], vm.get('node', ''), lease['vmid'], accel.LEASE_SLOT, None)
        if e:
            return e
    store.close_lease(lease['id'])
    log_audit(by, 'vlab.lease.return', f"{lease['resource_name'] or lease['resource_id']} from "
              f"qemu/{lease['vmid']} ({lease['username']})" + (' - VM gone' if vm is None else ''),
              get_client_ip() if by != 'system' else '')
    return None


def _lease_view(l, desks, vms):
    d = desks.get((l['cluster_id'], l['vmid']))
    vm = vms.get(l['cluster_id'], {}).get(int(l['vmid'])) if l.get('vmid') is not None else None
    return {**l, 'desktop_id': d['id'] if d else None, 'desktop': d['name'] if d else (vm or {}).get('name'),
            'vm_running': bool(vm and vm.get('status') == 'running')}


@bp.route('/api/vlab/admin/leases', methods=['GET'])
@require_auth(perms=['vlab.accel.manage'])
def list_leases():
    rows = [l for l in store.list_leases(active_only=request.args.get('all') != '1') if _can_reach(l['cluster_id'])]
    desks = {(d['cluster_id'], d['vmid']): d for d in store.list_desktops()}
    vms = {cid: _vm_states(cid) for cid in {l['cluster_id'] for l in rows}}
    return jsonify({'leases': [_lease_view(l, desks, vms) for l in rows]})


@bp.route('/api/vlab/admin/leases', methods=['POST'])
@require_auth(perms=['vlab.accel.manage'])
def create_lease():
    """{desktop_id, mapping, ends_at, name?}: lend a card of the mapping to the desktop's user."""
    from datetime import datetime, timezone
    data = request.get_json(silent=True) or {}
    desk = store.get_desktop(str(data.get('desktop_id') or ''))
    if not desk or not _can_reach(desk['cluster_id']):
        return _bad('Desktop not found', 404)
    if desk['vm_type'] != 'qemu':
        return _bad('Only virtual machines take a PCI card')
    if not desk['assigned_user']:
        return _bad('The desktop is not assigned to anyone - assign it first', 409)
    mapping = data.get('mapping')
    if not isinstance(mapping, str) or not accel.MAPPING_ID.match(mapping):
        return _bad('mapping: the id of a PCI resource mapping')
    ends = _utc_iso(data.get('ends_at'))
    if not ends:
        return _bad('ends_at: an ISO date and time')
    if ends <= datetime.now(timezone.utc).isoformat(timespec='seconds'):
        return _bad('ends_at must be in the future')
    name = str(data.get('name') or '').strip()[:80]
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    mappings = accel.pci_mappings(mgr)
    m = next((x for x in mappings or [] if x['id'] == mapping), None)
    if mappings is not None and m is None:
        return _bad(f"No PCI mapping '{mapping}' on this cluster", 404)
    if store.active_lease_of_vm(desk['cluster_id'], desk['vmid']):
        return _bad('This desktop has a card on loan already', 409)
    if m is not None and len(store.active_leases_on(desk['cluster_id'], mapping)) >= max(1, len(m['devices'])):
        return _bad(f"Every card of '{mapping}' is lent out", 409)
    vm = _vm_states(desk['cluster_id']).get(int(desk['vmid']))
    if vm is None:
        return _bad("The desktop's VM is not on the cluster any more", 404)
    e = _set_slot(desk['cluster_id'], vm.get('node') or desk['node'], desk['vmid'], accel.LEASE_SLOT, f'mapping={mapping},pcie=1')
    if e:
        return _bad(e, 502)
    kind = 'fpga' if m and any(x['id'].lower().startswith(('10ee:', '1172:')) for x in m['devices']) else 'gpu'
    lease = store.add_lease(kind, mapping, name or (m['description'] if m else '') or mapping, desk['assigned_user'],
                            desk['cluster_id'], desk['vmid'], ends)
    log_audit(_user(), 'vlab.lease.create', f"{lease['resource_name']} ({mapping}) to qemu/{desk['vmid']} "
              f"({desk['assigned_user']}) until {ends}", get_client_ip())
    return jsonify({'lease': lease, 'needs_restart': vm.get('status') == 'running'}), 201


def _lease_or_error(lease_id):
    l = store.get_lease(lease_id)
    if not l or not _can_reach(l['cluster_id']):
        return None, _bad('Loan not found', 404)
    if l['state'] != 'active':
        return None, _bad('This loan is closed already', 409)
    return l, None


@bp.route('/api/vlab/admin/leases/<lease_id>/return', methods=['POST'])
@require_auth(perms=['vlab.accel.manage'])
def return_lease_now(lease_id):
    l, err = _lease_or_error(lease_id)
    if err:
        return err
    e = return_lease(l, by=_user())
    if e:
        return _bad(e, 502)
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/leases/<lease_id>/extend', methods=['POST'])
@require_auth(perms=['vlab.accel.manage'])
def extend_lease(lease_id):
    l, err = _lease_or_error(lease_id)
    if err:
        return err
    ends = _utc_iso((request.get_json(silent=True) or {}).get('ends_at'))
    if not ends or (l['ends_at'] and ends <= l['ends_at']):
        return _bad('ends_at: a later ISO date and time')
    store.extend_lease(l['id'], ends)
    log_audit(_user(), 'vlab.lease.extend', f"{l['resource_name']} on qemu/{l['vmid']} until {ends}", get_client_ip())
    return jsonify({'lease': store.get_lease(l['id'])})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/templates', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def cluster_templates(cluster_id):
    """Templates to clone desktops from. ?details=1 also reads each one's disks and says
    whether a linked clone can be made of it (가상머신 > 템플릿 관리) - a config read per
    template, so the clone dialog leaves it out."""
    if cluster_id not in cluster_managers or not _can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    details = request.args.get('details') == '1'
    plugin = _storage_plugins(cluster_id) if details else {}
    from_tpl = {}
    if details:
        for p in store.list_pools():
            if p['cluster_id'] == cluster_id:
                for k in (p.get('settings') or {}).get('templates') or []:
                    from_tpl.setdefault(int(k), set()).add(p['id'])
    out = []
    for vmid, vm in sorted(_vm_states(cluster_id).items()):
        if vm.get('template') and vm.get('type') in ('qemu', 'lxc'):
            spec = {}
            if vm.get('maxcpu'):
                spec['cpu'] = int(vm['maxcpu'])
            if vm.get('maxmem'):
                spec['memory_gb'] = round(int(vm['maxmem']) / 1024 ** 3)
            if vm.get('maxdisk'):
                spec['disk_gb'] = round(int(vm['maxdisk']) / 1024 ** 3)
            t = {'vmid': vmid, 'name': vm.get('name') or f'tpl-{vmid}', 'node': vm.get('node', ''),
                 'type': vm.get('type'), 'spec': spec}
            if details:
                disks = _template_disks(cluster_id, vm)
                t['disks'] = [dict(x, plugin=plugin.get(x['storage'], '')) for x in disks] if disks is not None else None
                t['linked_clone'] = _linked_clone_ok(t['disks'], vm.get('type'))
                t['pools'] = len(from_tpl.get(vmid, ()))
            out.append(t)
    return jsonify({'templates': out})


_DISK_KEY = re.compile(r'^(scsi|virtio|sata|ide|efidisk|tpmstate)\d+$|^(rootfs|mp\d+)$')
_SNAPSHOT_STORAGE = ('lvmthin', 'zfspool', 'rbd')        # linked clones work on these as they are
_FILE_STORAGE = ('dir', 'nfs', 'cifs', 'glusterfs', 'cephfs', 'btrfs')   # ... on these with qcow2 disks


def _storage_plugins(cluster_id):
    """{storage name: plugin type}; {} when the cluster's storage cannot be read."""
    from pegaprox.api import clusters as core_clusters
    mgr = cluster_managers.get(cluster_id)
    if not mgr or getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        return {}
    try:
        rows = core_clusters.cluster_storage_resources(cluster_id, mgr) or []
    except Exception as e:
        logging.debug(f'[VLAB] storage of {cluster_id}: {e}')
        return {}
    return {s.get('storage'): s.get('plugintype') or '' for s in rows if s.get('storage')}


def _template_disks(cluster_id, vm):
    """[{key, storage, volume}] of the template's disks (CD-ROMs left out); None when the
    config cannot be read."""
    mgr = cluster_managers.get(cluster_id)
    try:
        r = mgr.get_vm_config(vm.get('node', ''), int(vm['vmid']), vm.get('type'))
    except Exception as e:
        logging.debug(f"[VLAB] config of {vm.get('vmid')}: {e}")
        return None
    raw = r.get('config', {}).get('raw') if isinstance(r, dict) and r.get('success') else None
    if not isinstance(raw, dict):
        return None
    out = []
    for k, v in sorted(raw.items()):
        if not _DISK_KEY.match(k) or not isinstance(v, str) or 'media=cdrom' in v:
            continue
        vol = v.split(',', 1)[0]
        if ':' not in vol or vol == 'none':
            continue
        storage, volume = vol.split(':', 1)
        out.append({'key': k, 'storage': storage, 'volume': volume})
    return out


def _linked_clone_ok(disks, vm_type):
    """True/False when every disk's storage says so, None when that is not known."""
    if disks is None or vm_type != 'qemu':
        return False if vm_type == 'lxc' else None
    if not disks:
        return None
    verdicts = []
    for d in disks:
        p = d.get('plugin')
        if not p:
            return None
        verdicts.append(p in _SNAPSHOT_STORAGE or (p in _FILE_STORAGE and d['volume'].endswith('.qcow2')))
    return all(verdicts)


@bp.route('/api/vlab/admin/users', methods=['GET'])
@require_auth(perms=['vlab.pool.manage'])
def assignable_users():
    """Accounts a desktop can be given to (?all=1: disabled ones too, for the user list).
    Outside the default tenant a caller only sees their own tenant's accounts, so the
    screens cannot list another tenant's people."""
    include_disabled = request.args.get('all') == '1'
    desks_per, last = {}, store.last_session_per_user()
    for d in store.list_desktops():
        if d['assigned_user']:
            desks_per[d['assigned_user']] = desks_per.get(d['assigned_user'], 0) + 1
    out = []
    for name, u in _visible_users().items():
        if not include_disabled and not u.get('enabled', True):
            continue
        out.append({'username': name, 'display_name': u.get('display_name') or name,
                    'role': u.get('role', ''), 'auth_source': u.get('auth_source', 'local'),
                    'email': u.get('email', ''), 'enabled': bool(u.get('enabled', True)),
                    'tenant_id': u.get('tenant_id') or 'default',
                    'desktops': desks_per.get(name, 0), 'last_connected': last.get(name)})
    out.sort(key=lambda u: u['username'])
    return jsonify({'users': out})


def _visible_users():
    """{username: record} the caller may see: everyone from the default tenant, else their own tenant."""
    from pegaprox.utils.auth import load_users
    tenant = (acting_user() or {}).get('tenant_id') or 'default'
    users = load_users(readonly=True) or {}
    if tenant == 'default':
        return dict(users)
    return {n: u for n, u in users.items() if (u.get('tenant_id') or 'default') == tenant}


@bp.route('/api/vlab/admin/users/<username>/access', methods=['GET'])
@require_auth(perms=['vlab.pool.manage'])
def user_access(username):
    """Effective access of one user (docs/vlab-design.md 4-2): the vLAB desktops assigned to
    them, and every VM ACL grant they hold with where it comes from - 'vlab' when a vLAB
    assignment made it, 'direct' when it was given some other way (and survives unassigning)."""
    from pegaprox.utils.rbac import acl_grants_user, get_user_permissions, load_vm_acls, store_unavailable

    u = _visible_users().get(username)
    if u is None:
        return _bad('User not found', 404)
    pools = {p['id']: p for p in store.list_pools() if _can_reach(p['cluster_id'])}
    all_desks = store.list_desktops()
    desks = [d for d in all_desks if d['assigned_user'] == username and d['pool_id'] in pools]
    by_vm = {(d['cluster_id'], int(d['vmid'])): d for d in all_desks}

    acls = load_vm_acls()
    grants = []
    if not store_unavailable(acls):
        for cid, vms in acls.items():
            if not _can_reach(cid):
                continue
            for vmid, entry in (vms or {}).items():
                if not acl_grants_user(entry, username):
                    continue
                d = by_vm.get((cid, int(vmid)))
                grants.append({'cluster_id': cid, 'vmid': int(vmid),
                               'desktop': d['name'] if d else None,
                               'source': 'vlab' if d and d['assigned_user'] == username else 'direct',
                               'permissions': entry.get('permissions') or [],
                               'inherit_role': entry.get('inherit_role', True)})
    grants.sort(key=lambda g: (g['cluster_id'], g['vmid']))
    perms = get_user_permissions(dict(u, username=username))
    return jsonify({
        'user': {'username': username, 'display_name': u.get('display_name') or username, 'role': u.get('role', ''),
                 'auth_source': u.get('auth_source', 'local'), 'enabled': bool(u.get('enabled', True)),
                 'tenant_id': u.get('tenant_id') or 'default', 'portal': 'vlab.desk' in perms},
        'desktops': [{'id': d['id'], 'name': d['name'], 'pool': pools[d['pool_id']]['name'], 'pool_id': d['pool_id'],
                      'vmid': d['vmid'], 'cluster_id': d['cluster_id']} for d in desks],
        'vm_acl': grants,
        'vm_acl_unavailable': store_unavailable(acls),
        'sessions': store.list_sessions(username=username, limit=10),
    })


@bp.route('/api/vlab/admin/desktops', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def all_desktops():
    pools = {p['id']: p for p in store.list_pools() if _can_reach(p['cluster_id'])}
    live = {cid: _vm_states(cid) for cid in {p['cluster_id'] for p in pools.values()}}
    out = []
    for d in store.list_desktops():
        pool = pools.get(d['pool_id'])
        if not pool:
            continue
        vms = live.get(d['cluster_id'], {})
        v = _desktop_view(dict(d, pool_name=pool['name'], pool_settings=pool.get('settings')), vms)
        v.update({'vmid': d['vmid'], 'node': d['node'], 'cluster_id': d['cluster_id'],
                  'pool_id': d['pool_id'], 'assigned_user': d['assigned_user']})
        vm = vms.get(int(d['vmid']))
        if vm is not None:
            # 가상머신 > 데스크톱(VM) 관리 shows what the guest uses right now
            v['node'] = vm.get('node') or d['node']
            v['usage'] = {'cpu_percent': round(_num(vm.get('cpu')) * 100, 1), 'cpus': _num(vm.get('maxcpu')),
                          'mem': _num(vm.get('mem')), 'maxmem': _num(vm.get('maxmem')),
                          'uptime': _num(vm.get('uptime'))}
        out.append(v)
    return jsonify({'desktops': out})


@bp.route('/api/vlab/admin/desktops/<desktop_id>/power', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def admin_power_desktop(desktop_id):
    """An administrator switches any desktop of a pool they reach on or off."""
    desk = store.get_desktop(desktop_id)
    if not desk or not _can_reach(desk['cluster_id']):
        return _bad('Desktop not found', 404)
    action = (request.get_json(silent=True) or {}).get('action')
    if action not in POWER_ACTIONS:
        return _bad(f"action must be one of {', '.join(POWER_ACTIONS)}")
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    vm = _vm_states(desk['cluster_id']).get(int(desk['vmid']))
    if vm is None:
        return _bad("The desktop's VM is not on the cluster any more", 404)
    result = mgr.vm_action(vm.get('node') or desk['node'], int(desk['vmid']), desk['vm_type'], action)
    if not isinstance(result, dict) or not result.get('success'):
        err = result.get('error') if isinstance(result, dict) else None
        return _bad(str(err or f'{action} failed'), 502)
    log_audit(_user(), f'vm.{action}', f"vLAB: {action} desktop '{desk['name']}' ({desk['vm_type']}/{desk['vmid']}) by admin",
              get_client_ip())
    return jsonify({'success': True, 'action': action, 'task': result.get('data') or result.get('upid')})


# --- admin: pools ----------------------------------------------------------------

@bp.route('/api/vlab/admin/pools', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_pools():
    return jsonify({'pools': [p for p in store.list_pools() if _can_reach(p['cluster_id'])]})


@bp.route('/api/vlab/admin/pools', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_pool():
    data = request.get_json(silent=True) or {}
    name = str(data.get('name') or '').strip()
    pool_type = str(data.get('type') or '').strip()
    cluster_id = str(data.get('cluster_id') or '').strip()
    if not name or len(name) > MAX_NAME:
        return _bad(f'name is required (at most {MAX_NAME} characters)')
    if pool_type not in store.POOL_TYPES:
        return _bad(f"type must be one of {', '.join(store.POOL_TYPES)}")
    if cluster_id not in cluster_managers:
        return _bad('Cluster not found', 404)
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    tenant = (acting_user() or {}).get('tenant_id', '') or ''
    pool = store.create_pool(name, pool_type, cluster_id, tenant_id=tenant,
                             description=str(data.get('description') or '')[:500], created_by=_user())
    log_audit(_user(), 'vlab.pool.create', f"pool '{name}' ({pool_type}) on {cluster_id}", get_client_ip())
    return jsonify({'pool': pool}), 201


def _pool_or_error(pool_id):
    pool = store.get_pool(pool_id)
    if not pool or not _can_reach(pool['cluster_id']):
        return None, _bad('Pool not found', 404)
    return pool, None


@bp.route('/api/vlab/admin/pools/<pool_id>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_pool(pool_id):
    pool, err = _pool_or_error(pool_id)
    if err:
        return err
    if store.list_desktops(pool_id):
        return _bad('The pool still has desktops - take them out first', 409)
    store.delete_pool(pool_id)
    log_audit(_user(), 'vlab.pool.delete', f"pool '{pool['name']}'", get_client_ip())
    return jsonify({'success': True})


# --- admin: desktops -------------------------------------------------------------

@bp.route('/api/vlab/admin/pools/<pool_id>/desktops', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def pool_desktops(pool_id):
    pool, err = _pool_or_error(pool_id)
    if err:
        return err
    live = _vm_states(pool['cluster_id'])
    out = []
    for d in store.list_desktops(pool_id):
        v = _desktop_view(dict(d, pool_name=pool['name'], pool_settings=pool.get('settings')), live)
        v.update({'vmid': d['vmid'], 'node': d['node'], 'assigned_user': d['assigned_user'],
                  'has_base': bool(d.get('base_snap'))})
        out.append(v)
    return jsonify({'desktops': out})


@bp.route('/api/vlab/admin/pools/<pool_id>/desktops', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def add_desktop(pool_id):
    pool, err = _pool_or_error(pool_id)
    if err:
        return err
    data = request.get_json(silent=True) or {}
    try:
        vmid = int(data.get('vmid'))
    except (TypeError, ValueError):
        return _bad('vmid must be a number')
    vm_type = data.get('type') or 'qemu'
    if vm_type not in ('qemu', 'lxc'):
        return _bad('type must be qemu or lxc')
    live = _vm_states(pool['cluster_id'])
    vm = live.get(vmid)
    if live and vm is None:
        return _bad(f'Guest {vmid} not found on the cluster', 404)
    if vm and vm.get('template'):
        return _bad(f'Guest {vmid} is a template - create desktops from it instead')
    node = str(data.get('node') or (vm or {}).get('node') or '').strip()
    if not node:
        return _bad('node is required')
    if store.desktop_for_vm(pool['cluster_id'], vmid):
        return _bad(f'Guest {vmid} is already a desktop', 409)
    name = str(data.get('name') or (vm or {}).get('name') or f'vm-{vmid}')[:MAX_NAME]
    desk = store.add_desktop(pool, node, vmid, name, vm_type)
    log_audit(_user(), 'vlab.desktop.add', f"{vm_type}/{vmid} into pool '{pool['name']}'", get_client_ip())
    return jsonify({'desktop': desk}), 201


MAX_CLONES = 100
_NAME_OK = re.compile(r'^[A-Za-z0-9][A-Za-z0-9-]{0,40}$')


def _free_vmids(cluster_id, count, start, tenant_range, live):
    """`count` VMIDs nobody uses: not on the cluster, not a vLAB desktop, inside the tenant's
    slice when it has one, from `start` up (a gap is skipped, never reused)."""
    used = set(live) | {int(d['vmid']) for d in store.list_desktops() if d['cluster_id'] == cluster_id}
    lo, hi = tenant_range if tenant_range[0] else (100, 999999999)
    out, v = [], max(lo, start or lo)
    while len(out) < count and v <= hi:
        if v not in used:
            out.append(v)
        v += 1
    return out


@bp.route('/api/vlab/admin/pools/<pool_id>/clone', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def clone_desktops(pool_id):
    """Create desktops from a template: {template_vmid, count, name_prefix, full?, start_vmid?}.

    Linked clones by default (QEMU only; the template's storage must allow them). The clones
    are sent one after another; each becomes a 'provisioning' desktop that turns 'ready' once
    the guest shows up unlocked. A failure stops the run and is reported with what was made."""
    from pegaprox.utils.rbac import TenantRangeUnknown, tenant_vmid_range

    pool, err = _pool_or_error(pool_id)
    if err:
        return err
    data = request.get_json(silent=True) or {}
    try:
        template_vmid = int(data.get('template_vmid'))
        count = int(data.get('count', 1))
        start_vmid = int(data['start_vmid']) if data.get('start_vmid') not in (None, '') else 0
    except (TypeError, ValueError):
        return _bad('template_vmid, count and start_vmid must be numbers')
    if not 1 <= count <= MAX_CLONES:
        return _bad(f'count must be 1 to {MAX_CLONES}')
    prefix = str(data.get('name_prefix') or '').strip()
    if not _NAME_OK.match(prefix):
        return _bad('name_prefix: letters, digits and "-", starting with a letter or digit (DNS name rules)')
    full = bool(data.get('full', False))

    mgr = cluster_managers.get(pool['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    live = _vm_states(pool['cluster_id'])
    tpl = live.get(template_vmid)
    if not tpl or not tpl.get('template'):
        return _bad(f'Guest {template_vmid} is not a template on this cluster', 404)
    vm_type = tpl.get('type') or 'qemu'
    if vm_type == 'lxc' and not full:
        return _bad('Containers can only be full clones')
    try:
        tenant_range = tenant_vmid_range((acting_user() or {}).get('tenant_id') or 'default')
    except TenantRangeUnknown:
        return _bad('Tenant settings unavailable - nothing created', 503)
    if not start_vmid and not tenant_range[0]:
        nxt = mgr.get_next_vmid()   # PVE's own next free id: where it would number a new guest
        if isinstance(nxt, dict) and nxt.get('success'):
            start_vmid = int(nxt.get('vmid') or 0)
    vmids = _free_vmids(pool['cluster_id'], count, start_vmid, tenant_range, live)
    if len(vmids) < count:
        return _bad(f'Only {len(vmids)} free VMIDs in range for {count} desktops', 409)

    taken = {d['name'] for d in store.list_desktops(pool['id'])}
    names, n = [], 1
    while len(names) < count:
        cand = f'{prefix}-{n:02d}'
        if cand not in taken:
            names.append(cand)
        n += 1

    created, failure = [], None
    for vmid, name in zip(vmids, names):
        r = mgr.clone_vm(tpl.get('node'), template_vmid, vm_type, vmid, name=name, full=full,
                         description=f"vLAB pool '{pool['name']}'")
        if not isinstance(r, dict) or not r.get('success'):
            failure = {'vmid': vmid, 'name': name, 'error': str((r or {}).get('error') if isinstance(r, dict) else r)[:300]}
            break
        desk = store.add_desktop(pool, tpl.get('node'), vmid, name, vm_type, state='provisioning')
        created.append({'id': desk['id'], 'vmid': vmid, 'name': name, 'task': r.get('data')})
    if created:
        # 템플릿 관리 counts the pools made from each template
        used = set((pool.get('settings') or {}).get('templates') or [])
        if template_vmid not in used:
            store.set_pool_settings(pool['id'], dict(pool.get('settings') or {}, templates=sorted(used | {template_vmid})))
    log_audit(_user(), 'vlab.desktop.clone',
              f"{len(created)}/{count} from template {template_vmid} into pool '{pool['name']}'"
              + (f" - stopped at {failure['vmid']}: {failure['error'][:120]}" if failure else ''), get_client_ip())
    status = 201 if not failure else (207 if created else 502)
    return jsonify({'created': created, 'failed': failure}), status


def _desktop_or_error(desktop_id):
    desk = store.get_desktop(desktop_id)
    if not desk or not _can_reach(desk['cluster_id']):
        return None, _bad('Desktop not found', 404)
    return desk, None


@bp.route('/api/vlab/admin/desktops/<desktop_id>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def remove_desktop(desktop_id):
    desk, err = _desktop_or_error(desktop_id)
    if err:
        return err
    if desk['assigned_user'] and not _acl_set(desk['cluster_id'], desk['vmid'], desk['assigned_user'], False):
        return _bad('VM access list unavailable - nothing changed', 503)
    store.remove_desktop(desktop_id)
    log_audit(_user(), 'vlab.desktop.remove', f"{desk['vm_type']}/{desk['vmid']}", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/desktops/<desktop_id>/assign', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def assign_desktop(desktop_id):
    from pegaprox.core.db import get_db
    desk, err = _desktop_or_error(desktop_id)
    if err:
        return err
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    username = str(username).strip() if username else None
    if username and not get_db().get_user(username):
        return _bad('User not found', 404)
    previous = desk['assigned_user']
    if previous == username:
        return jsonify({'desktop': desk})
    # grant the new user first, then revoke the old one: a failure half-way leaves an
    # extra grant to clean up, never a desktop whose user lost access silently
    if username and not _acl_set(desk['cluster_id'], desk['vmid'], username, True):
        return _bad('VM access list unavailable - nothing changed', 503)
    if previous and not _acl_set(desk['cluster_id'], desk['vmid'], previous, False):
        return _bad('VM access list unavailable - the previous user still has access', 503)
    store.set_assignment(desktop_id, username)
    log_audit(_user(), 'vlab.desktop.assign',
              f"{desk['vm_type']}/{desk['vmid']}: {previous or '-'} -> {username or '-'}", get_client_ip())
    return jsonify({'desktop': store.get_desktop(desktop_id)})


# --- base snapshot and reset (docs/vlab-design.md 6-2) -------------------------------

def _live_node(desk):
    vm = _vm_states(desk['cluster_id']).get(int(desk['vmid']))
    return vm, (vm or {}).get('node') or desk['node']


@bp.route('/api/vlab/admin/desktops/<desktop_id>/base', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def take_base(desktop_id):
    """The desktop as it is now becomes what a reset goes back to (the old base is replaced)."""
    desk, err = _desktop_or_error(desktop_id)
    if err:
        return err
    vm, node = _live_node(desk)
    if vm is None:
        return _bad("The desktop's VM is not on the cluster", 404)
    if vm.get('lock'):
        return _bad(f"The VM is busy ({vm['lock']}) - try again shortly", 409)
    e = _take_base(desk, node)
    if e:
        return _bad(e, 502)
    log_audit(_user(), 'vlab.desktop.base', f"{desk['vm_type']}/{desk['vmid']} '{desk['name']}'", get_client_ip())
    return jsonify({'success': True, 'base_snap': BASE_SNAP})


def _reset_one(desk):
    """Roll the desktop back to its base. Returns an error text, or None when PVE took it."""
    if not desk.get('base_snap'):
        return 'no base snapshot'
    mgr = cluster_managers.get(desk['cluster_id'])
    vm, node = _live_node(desk)
    if not mgr or vm is None:
        return "the VM is not on the cluster"
    if vm.get('lock'):
        return f"the VM is busy ({vm['lock']})"
    r = mgr.rollback_snapshot(node, int(desk['vmid']), desk['vm_type'], desk['base_snap'])
    if not isinstance(r, dict) or not r.get('success'):
        return str((r or {}).get('error') if isinstance(r, dict) else r) or 'rollback failed'
    policy = _gpu_policy((store.get_pool(desk['pool_id']) or {}).get('settings'))
    if policy:
        e = _apply_gpu(desk, node, policy)
        if e:
            logging.warning(f"[VLAB] GPU of {desk['vm_type']}/{desk['vmid']} after reset: {e}")
    loan = store.active_lease_of_vm(desk['cluster_id'], desk['vmid'])
    if loan:
        e = _set_slot(desk['cluster_id'], node, desk['vmid'], accel.LEASE_SLOT, f"mapping={loan['resource_id']},pcie=1")
        if e:
            logging.warning(f"[VLAB] loaned card of {desk['vm_type']}/{desk['vmid']} after reset: {e}")
    return None


@bp.route('/api/vlab/admin/desktops/<desktop_id>/reset', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def reset_desktop(desktop_id):
    """Back to the base snapshot. Everything done on the desktop since is gone; the VM ends up
    stopped (the base is taken without RAM). Refused while someone is connected unless force."""
    desk, err = _desktop_or_error(desktop_id)
    if err:
        return err
    if not desk.get('base_snap'):
        return _bad('This desktop has no base snapshot yet', 409)
    force = bool((request.get_json(silent=True) or {}).get('force'))
    if not force and desk['id'] in store.open_session_desktops():
        return jsonify({'error': 'Someone is connected to this desktop', 'code': 'IN_USE'}), 409
    e = _reset_one(desk)
    if e:
        return _bad(e, 502)
    log_audit(_user(), 'vlab.desktop.reset', f"{desk['vm_type']}/{desk['vmid']} '{desk['name']}'", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/pools/<pool_id>/reset', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def reset_pool(pool_id):
    """Reset every desktop of the pool that has a base. Desktops in use are skipped unless
    force; each desktop's outcome is reported."""
    pool, err = _pool_or_error(pool_id)
    if err:
        return err
    force = bool((request.get_json(silent=True) or {}).get('force'))
    busy = store.open_session_desktops()
    done, skipped, failed = [], [], []
    for d in store.list_desktops(pool_id):
        if not d.get('base_snap'):
            skipped.append({'id': d['id'], 'name': d['name'], 'reason': 'no_base'})
        elif d['id'] in busy and not force:
            skipped.append({'id': d['id'], 'name': d['name'], 'reason': 'in_use'})
        else:
            e = _reset_one(d)
            if e:
                failed.append({'id': d['id'], 'name': d['name'], 'error': e})
            else:
                done.append({'id': d['id'], 'name': d['name']})
    log_audit(_user(), 'vlab.pool.reset',
              f"pool '{pool['name']}': {len(done)} reset, {len(skipped)} skipped, {len(failed)} failed", get_client_ip())
    return jsonify({'reset': done, 'skipped': skipped, 'failed': failed})


# --- directory (AD / LDAP) ---------------------------------------------------------
# The engine already signs users in against AD/LDAP (pegaprox/utils/ldap.py). These routes
# only expose the settings the vLAB console has a screen for and hand saving and testing to
# the core settings routes, which encrypt the bind password and run the checks.

_DIRECTORY_FIELDS = {
    'ldap_enabled': bool, 'ldap_server': str, 'ldap_port': int, 'ldap_use_ssl': bool,
    'ldap_use_starttls': bool, 'ldap_verify_tls': bool, 'ldap_bind_dn': str, 'ldap_bind_password': str,
    'ldap_base_dn': str, 'ldap_user_filter': str, 'ldap_username_attribute': str,
    'ldap_email_attribute': str, 'ldap_display_name_attribute': str, 'ldap_group_base_dn': str,
    'ldap_group_filter': str, 'ldap_default_role': str, 'ldap_auto_create_users': bool,
    'ldap_group_mappings': list,
}
_DIRECTORY_DEFAULTS = {
    'ldap_enabled': False, 'ldap_server': '', 'ldap_port': 389, 'ldap_use_ssl': False, 'ldap_use_starttls': False,
    'ldap_verify_tls': False, 'ldap_bind_dn': '', 'ldap_base_dn': '',
    'ldap_user_filter': '(&(objectClass=person)(sAMAccountName={username}))',
    'ldap_username_attribute': 'sAMAccountName', 'ldap_email_attribute': 'mail',
    'ldap_display_name_attribute': 'displayName', 'ldap_group_base_dn': '',
    'ldap_group_filter': '(&(objectClass=group)(member={user_dn}))', 'ldap_default_role': 'viewer',
    'ldap_auto_create_users': False, 'ldap_group_mappings': [],
}


def _directory_body(extra=()):
    """The request body if it only carries directory fields of the right type, else an error."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, _bad('JSON body required')
    unknown = sorted(set(data) - set(_DIRECTORY_FIELDS) - set(extra))
    if unknown:
        return None, _bad(f"unknown fields: {', '.join(unknown)}")
    for k, typ in _DIRECTORY_FIELDS.items():
        if k in data and not (isinstance(data[k], typ) and not (typ is int and isinstance(data[k], bool))):
            return None, _bad(f'{k} must be {typ.__name__}')
    for m in data.get('ldap_group_mappings') or []:
        if not isinstance(m, dict) or not str(m.get('group_dn') or '').strip() or not str(m.get('role') or '').strip():
            return None, _bad('ldap_group_mappings: every entry needs group_dn and role')
    return data, None


@bp.route('/api/vlab/admin/directory', methods=['GET'])
@require_auth(perms=['admin.settings'])
def get_directory():
    from pegaprox.api.helpers import load_server_settings
    saved = load_server_settings() or {}
    out = {k: saved.get(k, v) for k, v in _DIRECTORY_DEFAULTS.items()}
    out['ldap_bind_password'] = '********' if saved.get('ldap_bind_password') else ''
    return jsonify({'directory': out})


@bp.route('/api/vlab/admin/directory', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def save_directory():
    """Save the directory settings. The masked password ('********') keeps the stored one."""
    from pegaprox.api.settings import update_server_settings
    _, err = _directory_body()
    if err:
        return err
    return update_server_settings()


@bp.route('/api/vlab/admin/directory/test', methods=['POST'])
@require_auth(perms=['admin.settings'])
def test_directory():
    """Connect, bind and read the base DN with the given (not yet saved) values; with
    test_username also look that account up. Answers the core test's step list."""
    from pegaprox.api.settings import test_ldap
    data, err = _directory_body(extra=('test_username',))
    if err:
        return err
    if 'test_username' in data and not isinstance(data['test_username'], str):
        return _bad('test_username must be str')
    return test_ldap()


# --- platform settings -------------------------------------------------------------
# 운영 > 플랫폼 설정: sign-in and session, password policy, audit retention, air-gap mode
# and mail. Same pattern as the directory: only these fields, saved by the core route
# (which clamps the numbers, encrypts the SMTP password and audits the changes). Ports,
# TLS and the reverse proxy are the install's business (nginx), not this screen's.

_PLATFORM_DEFAULTS = {
    'session_timeout': 28800, 'strict_session_ip': False,
    'login_max_attempts': 5, 'login_lockout_time': 300, 'login_attempt_window': 600,
    'force_2fa': False, 'force_2fa_exclude_admins': False,
    'password_min_length': 8, 'password_require_uppercase': True, 'password_require_lowercase': True,
    'password_require_numbers': True, 'password_require_special': False,
    'password_expiry_enabled': False, 'password_expiry_days': 90, 'password_expiry_warning_days': 14,
    'audit_retention_days': 90, 'air_gap_mode': False,
    'smtp_enabled': False, 'smtp_host': '', 'smtp_port': 587, 'smtp_user': '', 'smtp_password': '',
    'smtp_from_email': '', 'smtp_from_name': '', 'smtp_tls': True, 'smtp_ssl': False,
    'alert_email_recipients': [],
}
_PLATFORM_FIELDS = {k: type(v) for k, v in _PLATFORM_DEFAULTS.items()}
_SMTP_TEST_FIELDS = ('email', 'smtp_host', 'smtp_port', 'smtp_user', 'smtp_password', 'smtp_from_email',
                     'smtp_from_name', 'smtp_tls', 'smtp_ssl')


def _platform_body(allowed):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, _bad('JSON body required')
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        return None, _bad(f"unknown fields: {', '.join(unknown)}")
    for k, v in data.items():
        typ = _PLATFORM_FIELDS.get(k, str)
        if not isinstance(v, typ) or (typ is int and isinstance(v, bool)):
            return None, _bad(f'{k} must be {typ.__name__}')
    if not all(isinstance(x, str) for x in data.get('alert_email_recipients') or []):
        return None, _bad('alert_email_recipients must be a list of str')
    return data, None


@bp.route('/api/vlab/admin/settings', methods=['GET'])
@require_auth(perms=['admin.settings'])
def get_platform_settings():
    from pegaprox.api.helpers import load_server_settings
    saved = load_server_settings() or {}
    out = {k: saved.get(k, v) for k, v in _PLATFORM_DEFAULTS.items()}
    out['smtp_password'] = '********' if saved.get('smtp_password') else ''
    return jsonify({'settings': out})


@bp.route('/api/vlab/admin/settings', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def save_platform_settings():
    """Save them. The masked password ('********') keeps the stored one; the core clamps
    numbers to its ranges, so read the settings back to see what was stored."""
    from pegaprox.api.settings import update_server_settings
    _, err = _platform_body(_PLATFORM_FIELDS)
    if err:
        return err
    return update_server_settings()


@bp.route('/api/vlab/admin/settings/smtp-test', methods=['POST'])
@require_auth(perms=['admin.settings'])
def test_platform_smtp():
    """Send a test mail to `email` with the given (unsaved) SMTP values - the core test."""
    from pegaprox.api import realtime
    data, err = _platform_body(_SMTP_TEST_FIELDS)
    if err:
        return err
    if not (data.get('email') or '').strip():
        return _bad('email required')
    return realtime.test_smtp()


# --- system summary ------------------------------------------------------------------

def _versions():
    from pegaprox.constants import PEGAPROX_VERSION
    out = {'engine': PEGAPROX_VERSION, 'vlab_api': VLAB_API_VERSION, 'build': ''}
    try:
        import os
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'version.json'),
                  encoding='utf-8') as fh:
            v = json.load(fh)
        out['build'] = str(v.get('build') or v.get('version') or '')
    except (OSError, ValueError):
        pass
    return out


@bp.route('/api/vlab/admin/summary', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def summary():
    """What the dashboard and 운영 > 시스템 요약 show: clusters, pools, desktops by state,
    users, open sessions - all within the caller's reach."""
    clusters = [(cid, m) for cid, m in list(cluster_managers.items()) if _can_reach(cid)]
    pools = [p for p in store.list_pools() if _can_reach(p['cluster_id'])]
    pool_ids = {p['id'] for p in pools}
    live = {cid: _vm_states(cid) for cid, _ in clusters}
    states = {}
    desks = [d for d in store.list_desktops() if d['pool_id'] in pool_ids]
    for d in desks:
        st = _desktop_view(d, live.get(d['cluster_id'], {}))['state']
        states[st] = states.get(st, 0) + 1
    open_ids = store.open_session_desktops()
    by_type = {}
    for p in pools:
        by_type[p['type']] = by_type.get(p['type'], 0) + 1
    users = _visible_users()
    return jsonify({
        'clusters': {'total': len(clusters), 'connected': sum(1 for _, m in clusters if getattr(m, 'is_connected', False))},
        'pools': {'total': len(pools), 'by_type': by_type},
        'desktops': {'total': len(desks), 'assigned': sum(1 for d in desks if d['assigned_user']),
                     'by_state': states, 'in_session': sum(1 for d in desks if d['id'] in open_ids)},
        'users': {'total': len(users), 'enabled': sum(1 for u in users.values() if u.get('enabled', True))},
        'sessions_today': store.sessions_since(_today_start()),
        'versions': _versions(),
    })


def _today_start():
    from datetime import datetime, timezone
    now = datetime.now().astimezone()
    return now.replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc).isoformat(timespec='seconds')


# --- audit log -----------------------------------------------------------------------

@bp.route('/api/vlab/admin/audit', methods=['GET'])
@require_auth(roles=['admin'])
def audit_log():
    """The engine's audit log, as the core search reads it (same admin-role gate as
    /api/audit/search). vlab_only=1 without q narrows it to vLAB's own entries: their
    action starts with 'vlab.' or their details with 'vLAB:', and both contain "vlab"."""
    from pegaprox.core.db import get_db
    a = request.args
    try:
        offset = max(0, min(int(a.get('offset', 0)), 100000))
        limit = max(1, min(int(a.get('limit', 100)), 500))
    except ValueError:
        return _bad('offset and limit must be numbers')
    q = (a.get('q') or '').strip()[:200]
    if not q and a.get('vlab_only') == '1':
        q = 'vlab'
    rows, total = get_db().search_audit_log(
        q=q, user=(a.get('user') or '').strip()[:80], date_from=(a.get('date_from') or '').strip(),
        date_to=(a.get('date_to') or '').strip(), offset=offset, limit=limit)
    keep = ('id', 'timestamp', 'user', 'action', 'details', 'ip_address', 'cluster', 'severity')
    return jsonify({'entries': [{k: r.get(k) for k in keep if k in r} for r in rows],
                    'total': total, 'offset': offset, 'limit': limit,
                    'has_more': (offset + len(rows)) < total})
