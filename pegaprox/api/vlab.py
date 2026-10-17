# -*- coding: utf-8 -*-
"""
vLAB API (MAKUS) - the only API the vLAB console uses besides /api/auth/*.

  GET    /api/vlab/info                               product, API version (any signed-in user)
  GET    /api/vlab/branding                           white label to display (public: the sign-in screen needs it)
  GET    /api/vlab/branding/image/<tenant>/<file>     its logo / favicon (public)
  GET    /api/vlab/admin/branding                     the stored white label            admin.settings
  PUT    /api/vlab/admin/branding                     save it                           admin.settings
  POST   /api/vlab/admin/branding/image               multipart slot (logo|loginLogo|favicon), file  admin.settings
  DELETE /api/vlab/admin/branding/image/<slot>        remove one image                  admin.settings
  GET    /api/vlab/me/desktops                        desktops assigned to the caller       vlab.desk
  GET    /api/vlab/me/leases                          cards/boards/desktops on loan         vlab.desk
  POST   /api/vlab/desktops/<desktop_id>/connect      {protocol: vnc|spice} -> how to connect  vlab.desk
  POST   /api/vlab/sessions/<session_id>/end          close the caller's own session        vlab.desk
  POST   /api/vlab/desktops/<desktop_id>/power        {action: start|shutdown|reboot|stop}  vlab.desk
  GET    /api/vlab/admin/audit                        audit log (?q=&user=&date_from=&date_to=&vlab_only=&offset=&limit=)  admin role
  GET    /api/vlab/admin/summary                      counts for the dashboard / system summary  vlab.pool.view
  GET    /api/vlab/admin/sessions                     session log (?username=&pool_id=&limit=)  vlab.report.view
  POST   /api/vlab/admin/sessions/<session_id>/end    end an open session (a VNC console is hung up)  vlab.pool.manage
  POST   /api/vlab/admin/users/<username>/sessions/end  end every open session of the user  vlab.pool.manage
  GET    /api/vlab/admin/usage                        usage report (?days=1..90&pool_id=): per day, pool, user  vlab.report.view
  GET    /api/vlab/admin/clusters                   clusters the caller can reach         vlab.pool.view
  GET    /api/vlab/admin/clusters/<cluster_id>/guests  guests (no templates), desktop or not  vlab.pool.view
  GET    /api/vlab/admin/clusters/<cluster_id>/nodes   nodes: load, memory, guests and desktops on each  vlab.pool.view
  GET    /api/vlab/admin/clusters/<cluster_id>/storage storage (shared ones once, with their nodes)  vlab.pool.view
  GET    /api/vlab/admin/clusters/<cluster_id>/accelerators  GPUs and FPGA cards per node, PCI mappings, who uses them  vlab.pool.view
  GET    /api/vlab/admin/clusters/<cluster_id>/nodes/<node>/pci/<pciid>/profiles  vGPU (mdev) profiles of a card  vlab.pool.view
  GET    /api/vlab/admin/clusters/<cluster_id>/infra   health, nodes, 5-min history, sessions, storage, alerts (?range=24h|7d|30d)  vlab.pool.view
  GET    /api/vlab/admin/clusters/<cluster_id>/alerts  alert rules, firing alerts and mutes (the core reads)  vlab.pool.view
  POST   /api/vlab/admin/clusters/<cluster_id>/alerts/rules            a rule (the core route)  vlab.pool.manage
  PUT    /api/vlab/admin/clusters/<cluster_id>/alerts/rules/<rule_id>  change it (the core route)  vlab.pool.manage
  DELETE /api/vlab/admin/clusters/<cluster_id>/alerts/rules/<rule_id>  remove it (the core route)  vlab.pool.manage
  POST   /api/vlab/admin/clusters/<cluster_id>/alerts/active/<fired_id>/ack  acknowledge a firing alert  vlab.pool.manage
  POST   /api/vlab/admin/clusters/<cluster_id>/alerts/mutes            {minutes, rule_id|object_key|active_alert_id}  vlab.pool.manage
  DELETE /api/vlab/admin/clusters/<cluster_id>/alerts/mutes/<mute_id>  lift a mute  vlab.pool.manage
  GET    /api/vlab/admin/alert-channels               notification channels, secrets masked (the core route)  admin.settings
  POST   /api/vlab/admin/alert-channels               {name, type, url, token?, topic?, enabled?}  admin.settings
  PUT    /api/vlab/admin/alert-channels/<cid>         change one (a masked url/token is kept)  admin.settings
  DELETE /api/vlab/admin/alert-channels/<cid>         remove one  admin.settings
  POST   /api/vlab/admin/alert-channels/<cid>/test    send a test alert  admin.settings
  GET    /api/vlab/admin/clusters/<cluster_id>/rightsizing  which VMs need more / can give back (core insights, ?days=7|30)  vlab.pool.view
  GET    /api/vlab/admin/labs                         LABs with terminals, schedules, what runs now and next  vlab.pool.view
  POST   /api/vlab/admin/labs                         {name, location?, description?, seats?}   vlab.pool.manage
  PUT    /api/vlab/admin/labs/<lab_id>                change it                                 vlab.pool.manage
  DELETE /api/vlab/admin/labs/<lab_id>                remove it (its schedules; terminals stay)  vlab.pool.manage
  GET    /api/vlab/admin/terminals                    terminals (?lab_id)                       vlab.pool.view
  POST   /api/vlab/admin/terminals                    {mac, name?, lab_id?, ip?} add one, approved  vlab.pool.manage
  PUT    /api/vlab/admin/terminals/<terminal_id>      {name?, lab_id?, state?}                  vlab.pool.manage
  DELETE /api/vlab/admin/terminals/<terminal_id>      remove it                                 vlab.pool.manage
  POST   /api/vlab/terminals/register                 a signed-in client on a known terminal says it is there {mac, name?}  signed in
           (new PCs come in with an enrolment code through the MOAVI Desk Agent: api/vlab_enroll.py)
  GET    /api/vlab/client/config                      what the Windows client should do (update, protocol)  signed in
  GET    /api/vlab/admin/client                       the client settings                       admin.settings
  PUT    /api/vlab/admin/client                       {latest_version?, min_version?, download_url?, protocol?}  admin.settings
  POST   /api/vlab/admin/terminals/<terminal_id>/key  a new kiosk key for it (shown once)       vlab.pool.manage
  GET    /api/vlab/kiosk                              the kiosk's room and session (header X-Terminal-Key)  terminal key
  POST   /api/vlab/kiosk/start                        a desktop of the session for the signed-in user (+ key)  vlab.desk
  GET    /api/vlab/admin/lab-schedules                schedules (?lab_id)                       vlab.pool.view
  POST   /api/vlab/admin/lab-schedules                {lab_id, pool_id, weekdays, start_time, end_time, prepare_min?, after?, title?}  vlab.pool.manage
  PUT    /api/vlab/admin/lab-schedules/<id>           change it                                 vlab.pool.manage
  DELETE /api/vlab/admin/lab-schedules/<id>           remove it                                 vlab.pool.manage
  POST   /api/vlab/admin/lab-schedules/<id>/run       {phase: prepare|finish} now               vlab.pool.manage
  (LAB bookings - portal 예약, LAB > 예약 - are in pegaprox/api/vlab_reserve.py; lab_tick runs them too)
  (research data - datasets, file transfer, export control - is in pegaprox/api/vlab_data.py)
  GET    /api/vlab/admin/clusters/<cluster_id>/backup/storages  where backups can go (PBS first)  vlab.pool.view
  GET    /api/vlab/admin/clusters/<cluster_id>/backup/jobs      scheduled backups (the core route) + their pool  vlab.pool.view
  POST   /api/vlab/admin/pools/<pool_id>/backup/job   a scheduled backup of the pool's desktops (the core route)  vlab.pool.manage
  DELETE /api/vlab/admin/clusters/<cluster_id>/backup/jobs/<job_id>  remove one (the core route)  vlab.pool.manage
  GET    /api/vlab/admin/pbs                          PBS servers the engine knows (the core route)  vlab.pool.view
  GET    /api/vlab/admin/desktops/<desktop_id>/backups            its backups (the core route)  vlab.pool.view
  POST   /api/vlab/admin/desktops/<desktop_id>/backups            back it up now {storage, mode?, notes?}  vlab.pool.manage
  POST   /api/vlab/admin/desktops/<desktop_id>/backups/restore    {volid, start?, force?} back into the same VM  vlab.pool.manage
  DELETE /api/vlab/admin/desktops/<desktop_id>/backups/<volid>    delete one backup  vlab.pool.manage
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
  PUT    /api/vlab/admin/pools/<pool_id>              {name?, description?, enabled?, settings?} (cluster, type fixed)  vlab.pool.manage
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
from datetime import datetime
import re
import logging

from flask import Blueprint, jsonify, request

from pegaprox.api.helpers import acting_user, check_cluster_access
from pegaprox.core import ha
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import VLAB_API_VERSION
from pegaprox.vlab import accel
from pegaprox.vlab import labs
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
    raw = accel.vm_raw(mgr, node, desk['vmid'])
    if raw is None:
        return 'could not read the VM config'
    want = accel.fit_slot(accel.gpu_value(policy), raw) if policy else None
    if (raw.get(accel.GPU_SLOT) or None) == want:
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
    from pegaprox.api.vlab_next import storage_paths
    from pegaprox.vlab import nas
    from pegaprox.api.vlab_work import desktop_work
    work = desktop_work([d['id'] for d in rows])
    pools = {}
    out = []
    for d in rows:
        v = _desktop_view(d, live.get(d['cluster_id'], {}))
        v['work'] = work.get(d['id'])
        v['pool_type'] = d.get('pool_type', '')
        v['last_connected'] = last.get(d['id'])
        pol = pool_policy.effective(_settings_of(d))
        v['policy'] = {'clipboard': pol['clipboard'], 'allow_power': pol['allow_power'],
                       'start_on_connect': pol['start_on_connect'], 'web_ide': pol['web_ide']}
        pool = pools.setdefault(d['pool_id'], store.get_pool(d['pool_id']))
        paths = storage_paths(pool, _user()) if pool else None
        if paths:
            got = nas.last(d['id'], _user())
            v['storage'] = dict(paths, ok=got['ok'] if got else None, code=got['code'] if got else '',
                                warnings=got['warnings'] if got else [])
        out.append(v)
    return jsonify({'desktops': out})


@bp.route('/api/vlab/me/leases', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_leases():
    from pegaprox.api.vlab_work import lease_extras
    out = []
    desks = {(d['cluster_id'], d['vmid']): d for d in store.desktops_of_user(_user())}
    leases = store.active_leases_of_user(_user())
    extra = lease_extras(leases)
    for l in leases:
        d = desks.get((l['cluster_id'], l['vmid']))
        out.append({'id': l['id'], 'kind': l['resource_type'], 'name': l['resource_name'] or l['resource_id'],
                    'ends_at': l['ends_at'], 'desktop': d['name'] if d else None, **extra.get(l['id'], {})})
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
    from pegaprox.api.vlab_next import shared_member
    username = _user()
    desk = store.get_desktop(desktop_id)
    if (not desk or not _can_reach(desk['cluster_id'])
            or (desk['assigned_user'] != username and not shared_member(desk, username))):
        return _bad('Desktop not found', 404)
    data = request.get_json(silent=True) or {}
    protocol = data.get('protocol') or 'vnc'
    pool = store.get_pool(desk['pool_id']) or {}
    if not pool.get('enabled', True):
        return jsonify({'error': 'This pool is switched off', 'code': 'POOL_DISABLED'}), 409
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

    if protocol in ('rdp', 'guac'):
        from pegaprox.api.vlab_next import desktop_rdp_answer
        answer, err = desktop_rdp_answer(desk, mgr, node, vmid, username, protocol, pool)
        if err:
            return err
    elif protocol == 'spice':
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
                                   sid=request_credential()[0], tag=desktop_ws_tag(desk))
        ticket, port = result.get('ticket') or '', result.get('port') or ''
        ws_path = (f"/api/clusters/{quote(desk['cluster_id'], safe='')}/vms/{quote(str(node), safe='')}/"
                   f"{vm_type}/{vmid}/vncwebsocket?token={quote(ws_token, safe='')}")
        if ticket and port:
            # hand vncproxy's ticket/port on, or the websocket handler mints a second vncproxy
            # whose password no longer matches this one (PVE 9.1)
            ws_path += f"&pve_ticket={quote(str(ticket), safe='')}&pve_port={quote(str(port), safe='')}"
        answer = {'type': 'vnc', 'ws_path': ws_path, 'password': ticket, 'clipboard': pol['clipboard']}

    if vm_type == 'qemu':
        # 공유 저장소: mount the pool's NAS and make the user's folder; a failure is told, not fatal
        from pegaprox.api.vlab_next import storage_on_connect
        storage = storage_on_connect(desk, pool, mgr, node, username)
        if storage:
            answer['storage'] = storage
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


def desktop_ws_tag(desk):
    """The tag of the VNC websockets opened to a desktop, so ending its session hangs them up."""
    return f"vlab-desk:{desk['id']}"


# protocols whose connection the engine does not carry: ending the session only closes the record
UNREACHED_PROTOCOLS = ('spice', 'rdp', 'guac')


def _end_admin_session(s):
    """Close an open session for an administrator. {id, username, protocol, hung_up, record_only}"""
    from pegaprox.utils.realtime import hang_up_tagged
    store.close_session(s['id'], result='terminated')
    desk = store.get_desktop(s['desktop_id']) if s.get('desktop_id') else None
    hung = 0
    if desk and s.get('protocol') == 'vnc':
        # the user's other VNC sessions on the same desktop go with it: one tag per desktop
        hung = hang_up_tagged(s['username'], desktop_ws_tag(desk))
    if desk:
        _after_session(desk, by=_user())
    record_only = (s.get('protocol') or '') in UNREACHED_PROTOCOLS
    try:
        from pegaprox.api.vlab_notices import session_ended
        session_ended(s, desk, _user(), record_only)
    except Exception as e:
        logging.warning(f'[VLAB] session end notice: {e}')
    return {'id': s['id'], 'username': s['username'], 'protocol': s.get('protocol') or '',
            'hung_up': hung, 'record_only': record_only}


@bp.route('/api/vlab/admin/sessions/<session_id>/end', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def admin_end_session(session_id):
    """End someone's open session. A VNC console through the engine is hung up; SPICE, RDP and
    browser RDP go to the node or the desktop directly, so for them only the record closes
    (record_only) - the viewer stays open until the user leaves or the desktop is reset."""
    s = store.get_session(session_id)
    pool = store.get_pool(s['pool_id']) if s and s.get('pool_id') else None
    if not s or not pool or not _can_reach(pool['cluster_id']):
        return _bad('Session not found', 404)
    if s.get('ended_at'):
        return jsonify({'error': 'The session has already ended', 'code': 'ENDED'}), 409
    out = _end_admin_session(s)
    log_audit(_user(), 'vlab.session.end', f"session {s['id']} of '{s['username']}' ({out['protocol']}) "
              f"in pool '{pool['name']}' ended by admin" + (' - record only' if out['record_only'] else ''),
              get_client_ip())
    return jsonify({'success': True, 'session': out})


@bp.route('/api/vlab/admin/users/<username>/sessions/end', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def admin_end_user_sessions(username):
    """End every open session of a user in the pools the caller reaches."""
    pools = {p['id']: p for p in store.list_pools() if _can_reach(p['cluster_id'])}
    ended = [_end_admin_session(s) for s in store.open_sessions()
             if s['username'] == username and s.get('pool_id') in pools]
    if ended:
        log_audit(_user(), 'vlab.session.end', f"{len(ended)} open session(s) of '{username}' ended by admin",
                  get_client_ip())
    return jsonify({'success': True, 'ended': ended})


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
    npus = [d for d in devices if d['kind'] == 'npu']
    return jsonify({
        'devices': devices, 'mappings': mappings if mappings is not None else [],
        'mappings_readable': mappings is not None, 'unreadable_nodes': unreadable,
        'summary': {'gpus': len(gpus), 'fpgas': sum(1 for d in devices if d['kind'] == 'fpga'), 'npus': len(npus),
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
            if data.get('mig'):     # a MIG-backed profile (A100-3-20C): the card's MIG mode has to be on
                policy['mig'] = True
        else:
            policy['x_vga'] = bool(data.get('x_vga', False))
        label = data.get('label')
        if label is not None:
            if not isinstance(label, str) or len(label) > 60:
                return _bad('label: up to 60 characters')
            policy['label'] = label.strip()
    store.set_pool_settings(pool['id'], dict(pool.get('settings') or {}, gpu=policy))
    log_audit(_user(), 'vlab.pool.gpu', f"pool '{pool['name']}': {mode}"
              + (f" {policy['mapping']}" if mode != 'none' else '') + (f" {policy.get('mdev_type')}" if mode == 'vgpu' else '')
              + (' (MIG)' if policy.get('mig') else ''),
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


# --- backup (운영 > 백업, PBS) ---------------------------------------------------------
# The core already backs guests up and restores them (vzdump, PBS storages, scheduled
# backup jobs). These routes hand the request to those core routes as it is - their
# permission checks (backup.*, the VM ACL) run as they always do - and only add what vLAB
# knows: which VM a desktop is, which VMs a pool has, and that a restore goes back into
# the desktop's own VM.

def _desk_vm(desktop_id):
    desk, err = _desktop_or_error(desktop_id)
    if err:
        return None, None, err
    vm, node = _live_node(desk)
    if vm is None:
        return None, None, _bad("The desktop's VM is not on the cluster any more", 404)
    return desk, node, None


def _vmid_of_volid(volid):
    m = re.search(r'/(?:vm|ct)/(\d+)/', volid) or re.search(r'vzdump-(?:qemu|lxc|openvz)-(\d+)-', volid)
    return int(m.group(1)) if m else None


# --- infrastructure dashboard -------------------------------------------------------
# The core's own figures in one read for the dashboard: the health score, live node
# status, the 5-minute metrics snapshots (background/metrics.py, metrics_history), the
# storages, the firing alerts - plus the desktop sessions over the same window.

INFRA_RANGES = {'24h': (1, 300), '7d': (7, 3600), '30d': (30, 4 * 3600)}


def _core_body(resp):
    r = resp[0] if isinstance(resp, tuple) else resp
    if getattr(r, 'status_code', 200) != 200:
        return None
    try:
        return r.get_json()
    except Exception:
        return None


def _bucket(points, step, keys):
    """Average `keys` of [{ts, ...}] inside step-second windows."""
    out, cur, start = [], [], None
    for pt in points:
        b = pt['ts'] - pt['ts'] % step
        if start is not None and b != start and cur:
            out.append({'ts': start, **{k: round(sum(c[k] for c in cur) / len(cur), 2) for k in keys}})
            cur = []
        start = b
        cur.append(pt)
    if cur:
        out.append({'ts': start, **{k: round(sum(c[k] for c in cur) / len(cur), 2) for k in keys}})
    return out


def _session_series(cluster_id, since, until, step):
    """Open desktop sessions of this cluster's pools in each step window."""
    pools = {p['id'] for p in store.list_pools() if p.get('cluster_id') == cluster_id}
    rows = [r for r in store.sessions_overlapping(since.isoformat(timespec='seconds'),
                                                  until.isoformat(timespec='seconds'))
            if r.get('pool_id') in pools]
    spans = [(_ts_utc(r['started_at']).timestamp(),
              _ts_utc(r['ended_at']).timestamp() if r.get('ended_at') else until.timestamp()) for r in rows]
    t0 = int(since.timestamp()) - int(since.timestamp()) % step
    return [{'ts': t, 'sessions': sum(1 for a, b in spans if a < t + step and b >= t)}
            for t in range(t0, int(until.timestamp()) + 1, step)]


@bp.route('/api/vlab/admin/clusters/<cluster_id>/infra', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def cluster_infra(cluster_id):
    from datetime import datetime, timedelta, timezone
    from pegaprox.api import alerts as core_alerts
    from pegaprox.api import clusters as core_clusters
    from pegaprox.api.helpers import load_metrics_window
    mgr = cluster_managers.get(cluster_id)
    if not mgr or not _can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    rng = request.args.get('range', '24h')
    if rng not in INFRA_RANGES:
        return _bad('range must be one of ' + ', '.join(INFRA_RANGES))
    days, step = INFRA_RANGES[rng]
    until = datetime.now(timezone.utc)
    since = until - timedelta(days=days)

    # live nodes (the core's status read; its cache when the cluster is unreachable)
    try:
        status = mgr.get_node_status() if mgr.is_connected else {}
    except Exception as e:
        logging.debug(f'[VLAB] infra node status {cluster_id}: {e}')
        status = {}
    status = status or getattr(mgr, '_cached_metrics', None) or {}
    nodes = [{'name': name, 'status': n.get('status', 'unknown'),
              'cpu_pct': n.get('cpu_percent', 0), 'mem_pct': n.get('mem_percent', 0),
              'mem_used': n.get('mem_used', 0), 'mem_total': n.get('mem_total', 0),
              'disk_pct': n.get('disk_percent', 0), 'uptime': n.get('uptime', 0),
              'netin': n.get('netin', 0), 'netout': n.get('netout', 0)}
             for name, n in sorted(status.items()) if isinstance(n, dict)]

    # history from the snapshots
    cluster_pts, node_pts = [], {}
    try:
        window = load_metrics_window(days) or []
    except Exception as e:
        logging.debug(f'[VLAB] infra history {cluster_id}: {e}')
        window = []
    cutoff = since.timestamp()
    for ts, clusters in window:
        cd = (clusters or {}).get(cluster_id)
        if not cd or ts < cutoff:
            continue
        t = cd.get('totals') or {}
        cluster_pts.append({'ts': ts,
                            'cpu_pct': (t.get('cpu_used', 0) / t['cpu_total'] * 100) if t.get('cpu_total') else 0,
                            'mem_pct': (t.get('mem_used', 0) / t['mem_total'] * 100) if t.get('mem_total') else 0,
                            'vms_running': t.get('vms_running', 0) + t.get('cts_running', 0)})
        for nn, nd in (cd.get('nodes') or {}).items():
            node_pts.setdefault(nn, []).append({'ts': ts, 'cpu': nd.get('cpu', 0), 'mem': nd.get('mem_percent', 0)})

    # storages: a shared one once, a local one per node
    storages, seen = [], set()
    for r in core_clusters.cluster_storage_resources(cluster_id, mgr) or []:
        if r.get('status') != 'available' or not r.get('maxdisk'):
            continue
        key = r.get('storage') if r.get('shared') else f"{r.get('node')}/{r.get('storage')}"
        if key in seen:
            continue
        seen.add(key)
        storages.append({'storage': r.get('storage'), 'node': None if r.get('shared') else r.get('node'),
                         'type': r.get('plugintype') or '', 'used': r.get('disk') or 0, 'total': r.get('maxdisk') or 0})
    storages.sort(key=lambda x: -(x['used'] / x['total'] if x['total'] else 0))

    health = _core_body(core_clusters.get_cluster_health(cluster_id)) or {}
    alerts = (_core_body(core_alerts.get_active_alerts(cluster_id)) or {}).get('active_alerts') or []

    return jsonify({
        'cluster_id': cluster_id, 'range': rng, 'step': step,
        'connected': bool(mgr.is_connected),
        'health': {'score': health.get('score'), 'band': health.get('band'),
                   'issues': (health.get('issues') or [])[:6]},
        'nodes': nodes,
        'history': _bucket(cluster_pts, step, ('cpu_pct', 'mem_pct', 'vms_running')),
        'node_history': {nn: _bucket(pts, step, ('cpu', 'mem')) for nn, pts in sorted(node_pts.items())},
        'sessions': _session_series(cluster_id, since, until, step),
        'storages': storages[:12],
        'alerts': [{k: a.get(k) for k in ('id', 'severity', 'message', 'target_type', 'target_name',
                                           'metric', 'triggered_at', 'acked_at')} for a in alerts[:20]],
    })

# --- alerts (운영 > 경보) -------------------------------------------------------------
# The core already watches the clusters: alert rules, the incidents they raise (with
# acknowledgement and escalation), mutes, and the notification channels (Slack, Discord,
# Teams, ntfy, a generic webhook; e-mail through the SMTP settings). These routes hand
# the request to those core routes as it is - their own checks (cluster.config,
# alert.manage, admin.settings, tenant scope) run as they always do.

def _alert_cluster(cluster_id):
    if cluster_id not in cluster_managers or not _can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    return None


@bp.route('/api/vlab/admin/clusters/<cluster_id>/alerts', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def cluster_alerts(cluster_id):
    """Rules, firing incidents and mutes of the cluster in one read (the three core reads)."""
    from pegaprox.api import alerts as core_alerts
    err = _alert_cluster(cluster_id)
    if err:
        return err
    rules = (_core_body(core_alerts.get_cluster_alerts(cluster_id)) or {}).get('alerts') or []
    active = (_core_body(core_alerts.get_active_alerts(cluster_id)) or {}).get('active_alerts') or []
    mutes = (_core_body(core_alerts.list_alert_mutes(cluster_id)) or {}).get('mutes') or []
    return jsonify({'rules': rules, 'active': active, 'mutes': mutes})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/alerts/rules', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_alert_rule(cluster_id):
    from pegaprox.api import alerts as core_alerts
    return _alert_cluster(cluster_id) or core_alerts.create_cluster_alert(cluster_id)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/alerts/rules/<rule_id>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def update_alert_rule(cluster_id, rule_id):
    from pegaprox.api import alerts as core_alerts
    return _alert_cluster(cluster_id) or core_alerts.update_cluster_alert(cluster_id, rule_id)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/alerts/rules/<rule_id>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_alert_rule(cluster_id, rule_id):
    from pegaprox.api import alerts as core_alerts
    return _alert_cluster(cluster_id) or core_alerts.delete_cluster_alert(cluster_id, rule_id)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/alerts/active/<fired_id>/ack', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def ack_alert(cluster_id, fired_id):
    from pegaprox.api import alerts as core_alerts
    return _alert_cluster(cluster_id) or core_alerts.ack_active_alert(cluster_id, fired_id)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/alerts/mutes', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_alert_mute(cluster_id):
    from pegaprox.api import alerts as core_alerts
    return _alert_cluster(cluster_id) or core_alerts.create_alert_mute(cluster_id)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/alerts/mutes/<mute_id>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_alert_mute(cluster_id, mute_id):
    from pegaprox.api import alerts as core_alerts
    return _alert_cluster(cluster_id) or core_alerts.delete_alert_mute(cluster_id, mute_id)


@bp.route('/api/vlab/admin/alert-channels', methods=['GET'])
@require_auth(perms=['admin.settings'])
def alert_channels():
    """The notification channels, secrets masked (the core read without ?full)."""
    from pegaprox.api import alerts as core_alerts
    resp = core_alerts.list_alert_channels()
    body = _core_body(resp)
    if body is None:
        return resp
    return jsonify({'channels': body if isinstance(body, list) else []})


@bp.route('/api/vlab/admin/alert-channels', methods=['POST'])
@require_auth(perms=['admin.settings'])
def create_alert_channel():
    from pegaprox.api import alerts as core_alerts
    return core_alerts.create_alert_channel()


@bp.route('/api/vlab/admin/alert-channels/<cid>', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def update_alert_channel(cid):
    from pegaprox.api import alerts as core_alerts
    return core_alerts.update_alert_channel(cid)


@bp.route('/api/vlab/admin/alert-channels/<cid>', methods=['DELETE'])
@require_auth(perms=['admin.settings'])
def delete_alert_channel(cid):
    from pegaprox.api import alerts as core_alerts
    return core_alerts.delete_alert_channel(cid)


@bp.route('/api/vlab/admin/alert-channels/<cid>/test', methods=['POST'])
@require_auth(perms=['admin.settings'])
def test_alert_channel(cid):
    from pegaprox.api import alerts as core_alerts
    return core_alerts.test_alert_channel(cid)


# --- right-sizing (the core's insights) ----------------------------------------------
# The core's per-VM analysis of the metrics history (insights.right_sizing: mean / p95 CPU,
# mean / max memory over the window) with each VM's desktop, pool and user beside it, so
# the dashboard can say which desktop needs more and which can give some back.

RIGHTSIZE_ACTION = {'undersized_cpu': 'grow', 'undersized_mem': 'grow',
                    'oversized_cpu': 'reclaim', 'oversized_mem': 'reclaim', 'idle': 'idle'}


@bp.route('/api/vlab/admin/clusters/<cluster_id>/rightsizing', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def cluster_rightsizing(cluster_id):
    from pegaprox.api import insights as core_insights
    if cluster_id not in cluster_managers or not _can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    try:
        days = int(request.args.get('days', 7))
    except (TypeError, ValueError):
        return _bad('days must be a number')
    if days not in (7, 30):
        return _bad('days must be 7 or 30')
    resp = core_insights.right_sizing(cluster_id)     # reads ?days= from this request
    body = _core_body(resp)
    if body is None:
        return resp
    pools = {p['id']: p for p in store.list_pools()}
    out = []
    for r in body.get('recommendations') or []:
        try:
            desk = store.desktop_for_vm(cluster_id, int(r.get('vmid')))
        except (TypeError, ValueError):
            desk = None
        pool = pools.get(desk['pool_id']) if desk else None
        actions = sorted({RIGHTSIZE_ACTION.get(f.get('kind'), 'other') for f in r.get('flags') or []})
        out.append({**r, 'actions': actions,
                    'desktop_id': desk['id'] if desk else None, 'desktop': desk['name'] if desk else None,
                    'pool_id': pool['id'] if pool else None, 'pool': pool['name'] if pool else None,
                    'assigned_to': (desk or {}).get('assigned_user') or None})
    summary = body.get('summary') or {}
    return jsonify({
        'cluster_id': cluster_id, 'days': days,
        'snapshots': body.get('snapshots_in_window', 0), 'min_samples': body.get('min_samples_required', 0),
        'total_vms': body.get('total_vms', 0),
        'counts': {'grow': summary.get('undersized_cpu', 0) + summary.get('undersized_mem', 0),
                   'reclaim': summary.get('oversized_cpu', 0) + summary.get('oversized_mem', 0),
                   'idle': summary.get('idle', 0), 'ok': summary.get('ok', 0), 'no_data': summary.get('no_data', 0)},
        'recommendations': out,
    })


@bp.route('/api/vlab/admin/clusters/<cluster_id>/backup/storages', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def backup_storages(cluster_id):
    from pegaprox.api import clusters as core_clusters
    mgr = cluster_managers.get(cluster_id)
    if not mgr or not _can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    rows = core_clusters.cluster_storage_resources(cluster_id, mgr)
    if rows is None:
        return jsonify({'error': 'Could not read the storage'}), 502
    seen, out = set(), []
    for r in rows:
        content = [c for c in str(r.get('content') or '').split(',') if c]
        name = r.get('storage')
        if 'backup' not in content or not name or name in seen:
            continue
        seen.add(name)
        out.append({'storage': name, 'type': r.get('plugintype') or '', 'pbs': r.get('plugintype') == 'pbs',
                    'shared': bool(r.get('shared')), 'status': r.get('status') or 'unknown',
                    'used': _num(r.get('disk')), 'total': _num(r.get('maxdisk'))})
    out.sort(key=lambda x: (not x['pbs'], not x['shared'], x['storage']))
    return jsonify({'storages': out})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/backup/jobs', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def backup_jobs(cluster_id):
    from pegaprox.api import storage as core_storage
    if cluster_id not in cluster_managers or not _can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    resp = core_storage.get_backup_jobs(cluster_id)
    r = resp[0] if isinstance(resp, tuple) else resp
    if getattr(r, 'status_code', 200) != 200:
        return resp
    body = r.get_json()
    jobs = body if isinstance(body, list) else (body or {}).get('jobs') or (body or {}).get('data') or []
    pools = {p['id']: p['name'] for p in store.list_pools()}
    for j in jobs:
        m = re.match(r'^vlab-pool:(\S+)', str(j.get('comment') or ''))
        j['vlab_pool_id'] = m.group(1) if m else None
        j['vlab_pool'] = pools.get(m.group(1)) if m else None
    return jsonify({'jobs': jobs})


@bp.route('/api/vlab/admin/pools/<pool_id>/backup/job', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def pool_backup_job(pool_id):
    """A scheduled backup of the pool's desktops, made by the core route with this body.
    The body names the pool's VMIDs and carries the comment 'vlab-pool:<id> <name>';
    other VMs, or a whole-node/all-guests job, are refused here."""
    from pegaprox.api import storage as core_storage
    pool, err = _pool_or_error(pool_id)
    if err:
        return err
    data = request.get_json(silent=True) or {}
    mine = {int(d['vmid']) for d in store.list_desktops(pool['id'])}
    try:
        wanted = {int(x) for x in str(data.get('vmid') or '').split(',') if x.strip()}
    except ValueError:
        return _bad('vmid: the pool desktops\' VMIDs, comma separated')
    if not wanted or not wanted <= mine:
        return _bad("vmid must list desktops of this pool only")
    if any(k in data for k in ('all', 'pool', 'exclude', 'node')):
        return _bad('A vLAB pool backup names its VMs; all / pool / exclude / node are not taken')
    if not str(data.get('comment') or '').startswith(f'vlab-pool:{pool["id"]}'):
        return _bad(f"comment must start with vlab-pool:{pool['id']}")
    if not data.get('storage') or not data.get('schedule'):
        return _bad('storage and schedule required')
    return core_storage.create_backup_job(pool['cluster_id'])


@bp.route('/api/vlab/admin/clusters/<cluster_id>/backup/jobs/<job_id>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_pool_backup_job(cluster_id, job_id):
    from pegaprox.api import storage as core_storage
    if cluster_id not in cluster_managers or not _can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    return core_storage.delete_backup_job(cluster_id, job_id)


@bp.route('/api/vlab/admin/pbs', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def pbs_servers():
    from pegaprox.api import pbs as core_pbs
    return core_pbs.list_pbs_servers()


@bp.route('/api/vlab/admin/desktops/<desktop_id>/backups', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def desktop_backups(desktop_id):
    from pegaprox.api import vms as core_vms
    desk, node, err = _desk_vm(desktop_id)
    if err:
        return err
    return core_vms.get_vm_backups(desk['cluster_id'], node, desk['vm_type'], int(desk['vmid']))


@bp.route('/api/vlab/admin/desktops/<desktop_id>/backups', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def desktop_backup_now(desktop_id):
    from pegaprox.api import vms as core_vms
    desk, node, err = _desk_vm(desktop_id)
    if err:
        return err
    data = request.get_json(silent=True) or {}
    if not data.get('storage'):
        return _bad('storage required')
    if data.get('mode', 'snapshot') not in ('snapshot', 'suspend', 'stop'):
        return _bad('mode must be snapshot, suspend or stop')
    return core_vms.create_vm_backup(desk['cluster_id'], node, desk['vm_type'], int(desk['vmid']))


@bp.route('/api/vlab/admin/desktops/<desktop_id>/backups/restore', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def desktop_restore(desktop_id):
    """Back into the desktop's own VM from one of its own backups. Refused while someone is
    connected unless force. The VM's snapshots go with the restore, so the desktop's base
    is cleared (retake it, or the reset pool takes a new one)."""
    from pegaprox.api import vms as core_vms
    desk, node, err = _desk_vm(desktop_id)
    if err:
        return err
    data = request.get_json(silent=True) or {}
    volid = str(data.get('volid') or '')
    extra = set(data) - {'volid', 'start', 'force'}
    if extra:
        return _bad(f"not taken here: {', '.join(sorted(extra))} (a restore goes back into the desktop's VM)")
    if _vmid_of_volid(volid) != int(desk['vmid']):
        return _bad("volid must be a backup of this desktop", 400)
    if not data.get('force') and desk['id'] in store.open_session_desktops():
        return jsonify({'error': 'Someone is connected to this desktop', 'code': 'IN_USE'}), 409
    resp = core_vms.restore_vm_backup(desk['cluster_id'], node, desk['vm_type'], int(desk['vmid']))
    r = resp[0] if isinstance(resp, tuple) else resp
    if getattr(r, 'status_code', 200) == 200:
        store.set_base_snap(desk['id'], '')
        log_audit(_user(), 'vlab.desktop.restore', f"{desk['vm_type']}/{desk['vmid']} '{desk['name']}' from {volid}",
                  get_client_ip())
    return resp


@bp.route('/api/vlab/admin/desktops/<desktop_id>/backups/<path:volid>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def desktop_backup_delete(desktop_id, volid):
    from pegaprox.api import vms as core_vms
    desk, node, err = _desk_vm(desktop_id)
    if err:
        return err
    if _vmid_of_volid(volid) != int(desk['vmid']):
        return _bad("volid must be a backup of this desktop", 400)
    return core_vms.delete_vm_backup(desk['cluster_id'], node, desk['vm_type'], int(desk['vmid']), volid)


# --- white label (운영 > 화이트라벨) ------------------------------------------------
# The core's white label for separate front ends (pegaprox/api/frontend_branding.py) is
# reused as it is - its record, cleaning and image checks. Its own routes take a server
# API token only; the vLAB console is a browser, so these routes reach the same storage
# with the console's session (admin.settings to change it, reading is public).

def _branding_view(rec):
    out = dict(rec)
    for k in ('logoUrl', 'loginLogoUrl', 'faviconUrl'):
        out[k] = f"/api/vlab/branding/image/{rec[k]}" if rec.get(k) else ''
    return out


@bp.route('/api/vlab/branding', methods=['GET'])
def branding_public():
    from pegaprox.api import frontend_branding as fb
    rec = fb.resolved(fb.DEFAULT_TENANT)
    keep = ('enabled', 'appName', 'browserTitle', 'logoUrl', 'loginLogoUrl', 'faviconUrl', 'primaryColor',
            'footerText', 'loginTagline', 'docsUrl', 'supportUrl', 'feedbackUrl', 'hideVersion')
    return jsonify({k: v for k, v in _branding_view(rec).items() if k in keep})


@bp.route('/api/vlab/branding/image/<tenant>/<name>', methods=['GET'])
def branding_image(tenant, name):
    from flask import Response
    from pegaprox.api import frontend_branding as fb
    got = fb.read_image(tenant, name)
    if not got:
        return jsonify({'error': 'Not found'}), 404
    buf, mime = got
    return Response(buf, mimetype=mime, headers={'X-Content-Type-Options': 'nosniff',
                                                 'Cache-Control': 'public, max-age=86400'})


@bp.route('/api/vlab/admin/branding', methods=['GET'])
@require_auth(perms=['admin.settings'])
def branding_get():
    from pegaprox.api import frontend_branding as fb
    return jsonify({'branding': _branding_view(fb.record(fb.DEFAULT_TENANT)), 'defaults': fb.DEFAULTS})


@bp.route('/api/vlab/admin/branding', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def branding_put():
    from pegaprox.api import frontend_branding as fb
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _bad('JSON body required')
    current = fb.record(fb.DEFAULT_TENANT)
    # the images keep their stored references: they change through the image routes only
    body = dict(data, logoUrl=current['logoUrl'], loginLogoUrl=current['loginLogoUrl'], faviconUrl=current['faviconUrl'])
    rec = fb.save_record(fb.DEFAULT_TENANT, body, actor=_user())
    return jsonify({'branding': _branding_view(rec)})


_SLOT_FIELD = {'logo': 'logoUrl', 'loginLogo': 'loginLogoUrl', 'favicon': 'faviconUrl'}


@bp.route('/api/vlab/admin/branding/image', methods=['POST'])
@require_auth(perms=['admin.settings'])
def branding_image_upload():
    from pegaprox.api import frontend_branding as fb
    if (request.content_length or 0) > fb.MAX_IMAGE_BYTES + 64 * 1024:
        return _bad('File too large (max 5MB)', 413)
    slot = request.form.get('slot')
    f = request.files.get('file')
    if slot not in _SLOT_FIELD or f is None:
        return _bad('slot (logo, loginLogo, favicon) and file required')
    url, err = fb.save_image(fb.DEFAULT_TENANT, slot, f.read(fb.MAX_IMAGE_BYTES + 1), actor=_user())
    if err:
        return _bad(err[0], err[1])
    rec = fb.record(fb.DEFAULT_TENANT)
    rec[_SLOT_FIELD[slot]] = url
    rec = fb.save_record(fb.DEFAULT_TENANT, rec, actor=_user())
    return jsonify({'branding': _branding_view(rec)})


@bp.route('/api/vlab/admin/branding/image/<slot>', methods=['DELETE'])
@require_auth(perms=['admin.settings'])
def branding_image_delete(slot):
    from pegaprox.api import frontend_branding as fb
    if slot not in _SLOT_FIELD:
        return _bad('slot must be logo, loginLogo or favicon')
    fb.remove_image(fb.DEFAULT_TENANT, slot)
    rec = fb.record(fb.DEFAULT_TENANT)
    rec[_SLOT_FIELD[slot]] = ''
    rec = fb.save_record(fb.DEFAULT_TENANT, rec, actor=_user())
    return jsonify({'branding': _branding_view(rec)})


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
    was = pool_policy.effective(pool.get('settings')).get('ssh_files', 'off') != 'off'
    settings = dict(pool.get('settings') or {}, policy=pol, protocols=pol['protocols'])
    store.set_pool_settings(pool['id'], settings)
    now_on = pol.get('ssh_files', 'off') != 'off'
    if now_on != was:
        # existing Warpgate SSH targets follow the switch (their web file panel)
        try:
            from pegaprox.vlab.warpgate import resync_ssh_file_transfer
            resync_ssh_file_transfer(store.list_desktops(pool['id']), now_on)
        except Exception as e:
            logging.warning(f"[VLAB] Warpgate SSH file panel for pool '{pool['name']}': {str(e)[:200]}")
    log_audit(_user(), 'vlab.pool.policy', f"pool '{pool['name']}': " + ', '.join(f'{k}={v}' for k, v in pol.items()),
              get_client_ip())
    return jsonify({'policy': pol})


def _ts_utc(iso):
    from datetime import datetime, timezone
    t = datetime.fromisoformat(iso)
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def policy_tick(now=None):
    """Once a minute (pegaprox/vlab/loans.py): close sessions open past max_session_hours,
    then shut down desktops idle past idle_shutdown_min. A desktop that is working (a busy
    GPU / CPU, a build job, the user's "작업 중") is left alone while its pool says so
    (pegaprox/api/vlab_work.py defer). Returns what it did."""
    from datetime import datetime, timedelta, timezone
    from pegaprox.api import vlab_work
    now = now or datetime.now(timezone.utc)
    pools = {p['id']: p for p in store.list_pools()}
    policies = {pid: pool_policy.effective(p.get('settings')) for pid, p in pools.items()}
    done = {'expired': 0, 'shutdown': 0, 'deferred': 0}

    states = {}
    for s in store.open_sessions():
        pol = policies.get(s['pool_id'])
        if not pol or not pol['max_session_hours']:
            continue
        if now - _ts_utc(s['started_at']) >= timedelta(hours=pol['max_session_hours']):
            desk = store.get_desktop(s['desktop_id']) if s['desktop_id'] else None
            if desk and desk['cluster_id'] not in states:
                states[desk['cluster_id']] = _vm_states(desk['cluster_id'])
            if desk and vlab_work.defer(desk, pools.get(s['pool_id']), 'expire', 'session_limit', s['id'],
                                        vm=states[desk['cluster_id']].get(int(desk['vmid'])), at=now, username=s['username']):
                done['deferred'] += 1
                continue
            # a reset-on-logout pool changes the VM: confirm the lease first (HA 5.2)
            if not ha.confirm_step(f"vLAB session limit {s['id']}"):
                break
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
            if vlab_work.defer(d, pools.get(d['pool_id']), 'shutdown', 'idle', vm=vm, at=now):
                done['deferred'] += 1
                continue
            mgr = cluster_managers.get(d['cluster_id'])
            if not ha.confirm_step(f"vLAB idle shutdown {d['id']}"):
                break
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
    raw = accel.vm_raw(mgr, node, vmid)
    if raw is None:
        return 'could not read the VM config'
    value = accel.fit_slot(value, raw)
    if (raw.get(slot) or None) == value:
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
    from pegaprox.api.vlab_work import lease_extras
    extra = lease_extras([l for l in rows if l['state'] == 'active'])
    return jsonify({'leases': [dict(_lease_view(l, desks, vms), **extra.get(l['id'], {})) for l in rows]})


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
    out, err = lend_card(desk, mapping, ends, name, _user())
    if err:
        return _bad(err[0], err[1])
    return jsonify(out), 201


def card_kind(m):
    """'fpga', 'npu' or 'gpu' from a PCI mapping's device ids."""
    ids = [x['id'].lower() for x in (m or {}).get('devices') or []]
    return ('fpga' if any(i.startswith(tuple(f'{v}:' for v in accel.FPGA_VENDOR_IDS)) for i in ids)
            else 'npu' if any(i.startswith(tuple(f'{v}:' for v in accel.NPU_VENDOR_IDS)) for i in ids) else 'gpu')


def lend_card(desk, mapping, ends, name, by, ip=None):
    """Lend a card of `mapping` to the desktop's user until `ends` (UTC ISO).
    ({lease, needs_restart, warnings}, None) or (None, (message, status))."""
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return None, ('Cluster not connected', 503)
    mappings = accel.pci_mappings(mgr)
    m = next((x for x in mappings or [] if x['id'] == mapping), None)
    if mappings is not None and m is None:
        return None, (f"No PCI mapping '{mapping}' on this cluster", 404)
    if store.active_lease_of_vm(desk['cluster_id'], desk['vmid']):
        return None, ('This desktop has a card on loan already', 409)
    if m is not None and len(store.active_leases_on(desk['cluster_id'], mapping)) >= max(1, len(m['devices'])):
        return None, (f"Every card of '{mapping}' is lent out", 409)
    vm = _vm_states(desk['cluster_id']).get(int(desk['vmid']))
    if vm is None:
        return None, ("The desktop's VM is not on the cluster any more", 404)
    e = _set_slot(desk['cluster_id'], vm.get('node') or desk['node'], desk['vmid'], accel.LEASE_SLOT, f'mapping={mapping},pcie=1')
    if e:
        return None, (e, 502)
    kind = card_kind(m)
    lease = store.add_lease(kind, mapping, name or (m['description'] if m else '') or mapping, desk['assigned_user'],
                            desk['cluster_id'], desk['vmid'], ends)
    log_audit(by, 'vlab.lease.create', f"{lease['resource_name']} ({mapping}) to qemu/{desk['vmid']} "
              f"({desk['assigned_user']}) until {ends}", ip if ip is not None else get_client_ip())
    from pegaprox.vlab import accel_checks
    try:
        warnings = accel_checks.for_vm(mgr, desk['cluster_id'], vm.get('node') or desk['node'], desk['vmid'], desk=desk)
    except Exception as e:      # advice only: a loan never fails on it
        logging.debug(f'[VLAB] accel checks of qemu/{desk["vmid"]}: {e}')
        warnings = []
    from pegaprox.api.vlab_notices import loan_granted
    loan_granted(lease, needs_restart=vm.get('status') == 'running')
    return {'lease': lease, 'needs_restart': vm.get('status') == 'running', 'warnings': warnings}, None


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
    from pegaprox.api.vlab_notices import loan_returned
    loan_returned(l, by=_user())
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
    from pegaprox.api.vlab_notices import loan_extended
    loan_extended(l, ends)
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
    from pegaprox.vlab import catalog
    from pegaprox.api.vlab_accounts import expiry_fields
    desks_per, last, deps = {}, store.last_session_per_user(), catalog.user_departments()
    expiry = expiry_fields()
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
                    'totp_enabled': bool(u.get('totp_enabled')), 'last_login': u.get('last_login'),
                    'must_change_password': bool(u.get('force_password_change')),
                    'department_id': deps.get(name),
                    'expires_at': (expiry.get(name) or {}).get('expires_at'),
                    'expired': bool((expiry.get(name) or {}).get('expired')),
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
    from pegaprox.api.vlab_work import desktop_work
    work = desktop_work([d['id'] for d in store.list_desktops() if d['pool_id'] in pools])
    out = []
    for d in store.list_desktops():
        pool = pools.get(d['pool_id'])
        if not pool:
            continue
        vms = live.get(d['cluster_id'], {})
        v = _desktop_view(dict(d, pool_name=pool['name'], pool_settings=pool.get('settings')), vms)
        v.update({'vmid': d['vmid'], 'node': d['node'], 'cluster_id': d['cluster_id'],
                  'pool_id': d['pool_id'], 'assigned_user': d['assigned_user'], 'work': work.get(d['id'])})
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


# settings the pool form changes; the policy, GPU, grants and templates have routes of their own
GATEWAY_SETTINGS = {'rdp_gateway_id': ('rdpgw', 'msrdgw'), 'guac_gateway_id': ('guacamole',)}


def _pool_settings_change(pool, data):
    """(new settings, [changed keys]) from the request's `settings`, or raises ValueError."""
    from pegaprox.vlab import catalog
    if not isinstance(data, dict):
        raise ValueError('settings must be an object')
    unknown = set(data) - set(GATEWAY_SETTINGS) - {'max_sessions'}
    if unknown:
        raise ValueError(f"settings: unknown {', '.join(sorted(unknown))}")
    settings = dict(pool.get('settings') or {})
    changed = []
    if 'max_sessions' in data:
        if pool['type'] != 'shared':
            raise ValueError('max_sessions is for shared pools only')
        try:
            ms = int(data['max_sessions'])
        except (TypeError, ValueError):
            raise ValueError('max_sessions must be a number')
        if not 1 <= ms <= 500:
            raise ValueError('max_sessions must be 1 to 500')
        if ((settings.get('shared') or {}).get('max_sessions')) != ms:
            settings['shared'] = dict(settings.get('shared') or {}, max_sessions=ms)
            changed.append('max_sessions')
    for key, kinds in GATEWAY_SETTINGS.items():
        if key not in data:
            continue
        gid = str(data[key] or '').strip()
        if gid:
            g = catalog.get_gateway(gid)
            if not g or g['kind'] not in kinds:
                raise ValueError(f"{key}: no {' / '.join(kinds)} gateway {gid}")
        if (settings.get(key) or '') == gid:
            continue
        if gid:
            settings[key] = gid
        else:
            settings.pop(key, None)
        changed.append(key)
    return settings, changed


@bp.route('/api/vlab/admin/pools/<pool_id>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def update_pool(pool_id):
    """Rename a pool, change its description, switch it on or off, or its connection settings
    (max_sessions of a shared pool, the RDP / Guacamole gateway). Its cluster and type stay:
    the desktops, grants and schedules were made for them - make a new pool instead.
    A switched-off pool hands out and connects no desktop; open sessions run on."""
    pool, err = _pool_or_error(pool_id)
    if err:
        return err
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _bad('A JSON object is required')
    for key in ('cluster_id', 'type'):
        if key in data and data[key] != pool[key]:
            return jsonify({'error': f'The {key} of a pool cannot be changed - create a new pool',
                            'code': 'IMMUTABLE'}), 400
    fields = {}
    if 'name' in data:
        name = str(data.get('name') or '').strip()
        if not name or len(name) > MAX_NAME:
            return _bad(f'name is required (at most {MAX_NAME} characters)')
        if name != pool['name']:
            fields['name'] = name
    if 'description' in data:
        desc = str(data.get('description') or '').strip()[:500]
        if desc != (pool.get('description') or ''):
            fields['description'] = desc
    if 'enabled' in data:
        if not isinstance(data['enabled'], bool):
            return _bad('enabled must be true or false')
        if data['enabled'] != pool['enabled']:
            fields['enabled'] = data['enabled']
    settings, keys = None, []
    if 'settings' in data:
        try:
            settings, keys = _pool_settings_change(pool, data['settings'])
        except ValueError as e:
            return _bad(str(e))
    changed = list(fields) + keys
    if not changed:
        return jsonify({'pool': pool, 'changed': []})
    if fields:
        store.update_pool(pool_id, **fields)
    if keys:
        store.set_pool_settings(pool_id, settings)
    after = next((p for p in store.list_pools() if p['id'] == pool_id), None) or store.get_pool(pool_id)
    log_audit(_user(), 'vlab.pool.update', f"pool '{pool['name']}': " + ', '.join(
        f"{k}={after[k]!r}" if k in ('name', 'enabled') else k for k in changed), get_client_ip())
    return jsonify({'pool': after, 'changed': changed})


@bp.route('/api/vlab/admin/pools/<pool_id>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_pool(pool_id):
    pool, err = _pool_or_error(pool_id)
    if err:
        return err
    if store.list_desktops(pool_id):
        return _bad('The pool still has desktops - take them out first', 409)
    store.delete_pool(pool_id)
    from pegaprox.vlab import datasets, nas
    nas.forget_pool(pool_id)
    datasets.forget_pool(pool_id)
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
    from pegaprox.api.vlab_notices import desktop_assigned
    desktop_assigned(desk, previous, username)
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
    # the base has no moavi-nla account (or an older password): a new one on the next Warpgate RDP
    try:
        from pegaprox.vlab.warpgate import nla_forget
        nla_forget(desk['id'])
    except Exception as e:
        logging.warning(f"[VLAB] Warpgate NLA reset for {desk['name']}: {str(e)[:200]}")
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
    from pegaprox.api.vlab_notices import desktop_reset
    desktop_reset(desk, _user())
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
                from pegaprox.api.vlab_notices import desktop_reset
                desktop_reset(d, _user())
    log_audit(_user(), 'vlab.pool.reset',
              f"pool '{pool['name']}': {len(done)} reset, {len(skipped)} skipped, {len(failed)} failed", get_client_ip())
    return jsonify({'reset': done, 'skipped': skipped, 'failed': failed})


# --- LABs: rooms, terminals, schedules (pegaprox/vlab/labs.py) ---------------------------
# A room's schedule gets the pool's desktops started `prepare_min` before a session and, at
# its end, back to their base and off (or just off). lab_tick runs once a minute beside the
# loan returns (pegaprox/vlab/loans.py); the routes manage rooms, terminals and schedules.

LAB_POOL_TYPES = ('classroom', 'reset', 'shared')


def _local_now():
    return datetime.now()


def _lab_view(lab, schedules, now):
    current, upcoming = labs.state_at([x for x in schedules if x['lab_id'] == lab['id']], now)
    return {**lab, 'schedules': sum(1 for x in schedules if x['lab_id'] == lab['id']), 'current': current, 'next': upcoming}


@bp.route('/api/vlab/admin/labs', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_labs():
    now = _local_now()
    schedules = store.list_lab_schedules()
    return jsonify({'labs': [_lab_view(l, schedules, now) for l in store.list_labs()], 'now': now.isoformat(timespec='minutes')})


def _lab_body():
    data = request.get_json(silent=True) or {}
    name = str(data.get('name') or '').strip()
    if not name or len(name) > 80:
        return None, _bad('A name of 1-80 characters is required')
    try:
        seats = max(0, min(10000, int(data.get('seats') or 0)))
    except (TypeError, ValueError):
        return None, _bad('seats must be a number')
    return {'name': name, 'location': str(data.get('location') or '')[:120],
            'description': str(data.get('description') or '')[:500], 'seats': seats}, None


@bp.route('/api/vlab/admin/labs', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_lab():
    body, err = _lab_body()
    if err:
        return err
    lab = store.save_lab(None, **body)
    log_audit(_user(), 'vlab.lab.create', f"LAB '{lab['name']}'", get_client_ip())
    return jsonify({'lab': lab}), 201


@bp.route('/api/vlab/admin/labs/<lab_id>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def update_lab(lab_id):
    if not store.get_lab(lab_id):
        return _bad('LAB not found', 404)
    body, err = _lab_body()
    if err:
        return err
    lab = store.save_lab(lab_id, **body)
    log_audit(_user(), 'vlab.lab.update', f"LAB '{lab['name']}'", get_client_ip())
    return jsonify({'lab': lab})


@bp.route('/api/vlab/admin/labs/<lab_id>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_lab(lab_id):
    lab = store.get_lab(lab_id)
    if not lab:
        return _bad('LAB not found', 404)
    store.delete_lab(lab_id)
    from pegaprox.vlab import enroll
    enroll.forget_lab(lab_id)
    from pegaprox.vlab import reservations
    reservations.delete_of_lab(lab_id)      # its bookings that have not started are cancelled
    log_audit(_user(), 'vlab.lab.delete', f"LAB '{lab['name']}' (its schedules too; terminals kept unassigned)", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/terminals', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_terminals():
    from pegaprox.vlab import enroll
    return jsonify({'terminals': enroll.annotate(store.list_terminals(request.args.get('lab_id') or None))})


@bp.route('/api/vlab/admin/terminals', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def add_terminal():
    data = request.get_json(silent=True) or {}
    mac = labs.norm_mac(data.get('mac'))
    if not mac:
        return _bad('A MAC address like 00:11:22:33:44:55 is required')
    if store.terminal_by_mac(mac):
        return _bad('This MAC address is registered already', 409)
    lab_id = data.get('lab_id') or None
    if lab_id and not store.get_lab(lab_id):
        return _bad('LAB not found', 404)
    t = store.add_terminal(mac, str(data.get('name') or '')[:80], lab_id, str(data.get('ip') or '')[:64], 'approved', _user())
    log_audit(_user(), 'vlab.terminal.add', f"terminal {mac} '{t['name']}'", get_client_ip())
    return jsonify({'terminal': t}), 201


@bp.route('/api/vlab/admin/terminals/<terminal_id>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def update_terminal(terminal_id):
    t = store.get_terminal(terminal_id)
    if not t:
        return _bad('Terminal not found', 404)
    data = request.get_json(silent=True) or {}
    fields = {}
    if 'name' in data:
        fields['name'] = str(data.get('name') or '')[:80]
    if 'lab_id' in data:
        lab_id = data.get('lab_id') or None
        if lab_id and not store.get_lab(lab_id):
            return _bad('LAB not found', 404)
        fields['lab_id'] = lab_id
    if data.get('state') in ('approved', 'pending'):
        fields['state'] = data['state']
    t = store.update_terminal(terminal_id, **fields)
    log_audit(_user(), 'vlab.terminal.update', f"terminal {t['mac']} '{t['name']}' {fields}", get_client_ip())
    return jsonify({'terminal': t})


@bp.route('/api/vlab/admin/terminals/<terminal_id>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_terminal(terminal_id):
    t = store.get_terminal(terminal_id)
    if not t:
        return _bad('Terminal not found', 404)
    store.delete_terminal(terminal_id)
    from pegaprox.vlab import enroll
    enroll.forget(terminal_id)
    log_audit(_user(), 'vlab.terminal.delete', f"terminal {t['mac']} '{t['name']}'", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/terminals/register', methods=['POST'])
@require_auth()
def register_terminal():
    """A signed-in MOAVI Desk Client on a room's PC says it is there: {mac, name?}. A known
    terminal has its last contact and address updated; an unknown PC is not taken - PCs come in
    only with an enrolment code, through the MOAVI Desk Agent (api/vlab_enroll.py)."""
    data = request.get_json(silent=True) or {}
    mac = labs.norm_mac(data.get('mac'))
    if not mac:
        return _bad('A MAC address is required')
    ip = get_client_ip() or ''
    t = store.terminal_by_mac(mac)
    if t:
        t = store.update_terminal(t['id'], ip=ip, last_seen=store.now())
    else:
        return jsonify({'state': 'unknown', 'lab': None})
    lab = store.get_lab(t['lab_id']) if t.get('lab_id') else None
    return jsonify({'state': t['state'], 'lab': {'id': lab['id'], 'name': lab['name']} if lab else None})


def _schedule_body(schedule_id=None):
    data = request.get_json(silent=True) or {}
    clean, e = labs.validate(data)
    if e:
        return None, None, None, _bad(e)
    lab = store.get_lab(data.get('lab_id') or '')
    if not lab:
        return None, None, None, _bad('LAB not found', 404)
    pool = store.get_pool(data.get('pool_id') or '')
    if not pool or not _can_reach(pool['cluster_id']):
        return None, None, None, _bad('Pool not found', 404)
    if pool['type'] not in LAB_POOL_TYPES:
        return None, None, None, _bad('A LAB schedule takes a scheduled (classroom), reset or shared pool')
    for other in store.list_lab_schedules(lab['id']):
        if other['id'] != schedule_id and other['enabled'] and clean['enabled'] and labs.overlaps(other, clean):
            return None, None, None, (jsonify({'error': 'This LAB has another schedule at that time', 'code': 'OVERLAP',
                                               'schedule_id': other['id']}), 409)
    return lab, pool, clean, None


@bp.route('/api/vlab/admin/lab-schedules', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_lab_schedules():
    pools = {p['id']: p for p in store.list_pools()}
    rooms = {l['id']: l['name'] for l in store.list_labs()}
    out = []
    for x in store.list_lab_schedules(request.args.get('lab_id') or None):
        p = pools.get(x['pool_id']) or {}
        out.append({**x, 'enabled': bool(x['enabled']), 'weekdays': labs.weekdays(x['weekdays']),
                    'lab': rooms.get(x['lab_id']), 'pool': p.get('name'), 'pool_type': p.get('type')})
    return jsonify({'schedules': out})


@bp.route('/api/vlab/admin/lab-schedules', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_lab_schedule():
    lab, pool, clean, err = _schedule_body()
    if err:
        return err
    x = store.save_lab_schedule(None, lab['id'], pool['id'], clean)
    log_audit(_user(), 'vlab.lab.schedule', f"LAB '{lab['name']}': pool '{pool['name']}' {clean['weekdays']} "
              f"{clean['start_time']}-{clean['end_time']} (prepare {clean['prepare_min']} min, after: {clean['after']})", get_client_ip())
    return jsonify({'schedule': x}), 201


@bp.route('/api/vlab/admin/lab-schedules/<schedule_id>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def update_lab_schedule(schedule_id):
    if not store.get_lab_schedule(schedule_id):
        return _bad('Schedule not found', 404)
    lab, pool, clean, err = _schedule_body(schedule_id)
    if err:
        return err
    x = store.save_lab_schedule(schedule_id, lab['id'], pool['id'], clean)
    log_audit(_user(), 'vlab.lab.schedule', f"LAB '{lab['name']}' schedule {schedule_id} changed", get_client_ip())
    return jsonify({'schedule': x})


@bp.route('/api/vlab/admin/lab-schedules/<schedule_id>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_lab_schedule(schedule_id):
    x = store.get_lab_schedule(schedule_id)
    if not x:
        return _bad('Schedule not found', 404)
    store.delete_lab_schedule(schedule_id)
    log_audit(_user(), 'vlab.lab.schedule.delete', f"schedule {schedule_id} of LAB {x['lab_id']}", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/lab-schedules/<schedule_id>/run', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def run_lab_schedule(schedule_id):
    """Run a phase now: {phase: prepare|finish} - before a session that starts early, or to
    clean the room right away."""
    x = store.get_lab_schedule(schedule_id)
    if not x:
        return _bad('Schedule not found', 404)
    phase = (request.get_json(silent=True) or {}).get('phase')
    if phase not in ('prepare', 'finish'):
        return _bad('phase must be prepare or finish')
    pool = store.get_pool(x['pool_id'])
    if not pool or not _can_reach(pool['cluster_id']):
        return _bad('Pool not found', 404)
    result = _lab_phase(x, pool, phase, after=x['after'] if phase == 'finish' else None)
    log_audit(_user(), f'vlab.lab.{phase}', f"schedule {schedule_id}, pool '{pool['name']}' by hand: {result}", get_client_ip())
    return jsonify(result)


def _lab_phase(sched, pool, phase, after=None, desks=None):
    """Start the pool's desktops (prepare) or put them back (finish: reset = base and off,
    off = shut down). Desktops someone is connected to are left alone at the finish, and so
    are those still working (pegaprox/api/vlab_work.py defer): their clean-up waits.
    `desks` narrows it to some of them (a booking of N seats or desktops)."""
    from pegaprox.api import vlab_work
    source = 'booking' if 'kind' in sched else 'lab'
    done, skipped, failed = [], [], []
    mgr = cluster_managers.get(pool['cluster_id'])
    live = _vm_states(pool['cluster_id'])
    busy = store.open_session_desktops()
    held = set()
    targets = store.list_desktops(pool['id']) if desks is None else desks
    for d in targets:
        vm = live.get(int(d['vmid']))
        if not mgr or not vm:
            failed.append({'id': d['id'], 'name': d['name'], 'error': 'the VM is not on the cluster'})
            continue
        if phase == 'prepare':
            vlab_work.drop_on_prepare(d)
            if vm.get('status') == 'running':
                skipped.append({'id': d['id'], 'name': d['name'], 'reason': 'running'})
                continue
            if not ha.confirm_step(f"LAB prepare {d['id']}"):
                break
            r = mgr.vm_action(vm.get('node') or d['node'], int(d['vmid']), d['vm_type'], 'start')
        else:
            if d['id'] in busy:
                skipped.append({'id': d['id'], 'name': d['name'], 'reason': 'in_use'})
                continue
            act = 'reset' if after == 'reset' and d.get('base_snap') else 'shutdown'
            if (act == 'reset' or vm.get('status') == 'running') and vlab_work.defer(
                    d, pool, act, source, sched.get('id', ''), vm=vm, username=d.get('assigned_user') or ''):
                skipped.append({'id': d['id'], 'name': d['name'], 'reason': 'working'})
                held.add(d['id'])
                continue
            if after == 'reset' and d.get('base_snap'):
                if not ha.confirm_step(f"LAB reset {d['id']}"):
                    break
                e = _reset_one(d)
                (failed.append({'id': d['id'], 'name': d['name'], 'error': e}) if e else done.append({'id': d['id'], 'name': d['name']}))
                continue
            if vm.get('status') != 'running':
                skipped.append({'id': d['id'], 'name': d['name'], 'reason': 'stopped'})
                continue
            if not ha.confirm_step(f"LAB shutdown {d['id']}"):
                break
            r = mgr.vm_action(vm.get('node') or d['node'], int(d['vmid']), d['vm_type'], 'shutdown')
        if isinstance(r, dict) and r.get('success'):
            done.append({'id': d['id'], 'name': d['name']})
        else:
            failed.append({'id': d['id'], 'name': d['name'], 'error': str((r or {}).get('error') if isinstance(r, dict) else r)})
    if phase == 'finish' and pool.get('type') == 'classroom':
        keep = {d['id'] for d in targets}
        for d in store.list_desktops(pool['id']):
            if d['id'] in keep and d['assigned_user'] and d['id'] not in busy | held and _acl_set(d['cluster_id'], d['vmid'], d['assigned_user'], False):
                store.set_assignment(d['id'], None)
    return {'phase': phase, 'done': done, 'skipped': skipped, 'failed': failed}


def lab_tick(now=None):
    """Once a minute (pegaprox/vlab/loans.py): run every LAB schedule and booking phase that
    is due (pegaprox/api/vlab_reserve.py). Every clean-up runs before any start, and a start
    waits while a session of the same pool that ends by then is not cleaned up yet, so one
    session's reset never undoes the next one's start. Returns [(id, phase, result)]."""
    from pegaprox.api import vlab_reserve
    now = now or _local_now()
    pools = {p['id']: p for p in store.list_pools()}
    due = []
    for sched in store.list_lab_schedules():
        phase = labs.due(sched, now)
        pool = pools.get(sched['pool_id'])
        if phase and pool:
            due.append(('schedule', sched, pool, phase))
    due += [('reservation', r, pool, phase) for r, pool, phase in vlab_reserve.due_items(now, pools)]
    out = []
    for kind, item, pool, phase in sorted(due, key=lambda x: x[3] != 'finish'):
        if kind == 'schedule':
            if phase == 'prepare' and vlab_reserve.occupied_before(pool['id'], labs.occurrence(item, now.date())[0], now, item['id']):
                continue
            result = _lab_phase(item, pool, phase, after=item['after'] if phase == 'finish' else None)
            store.mark_lab_schedule(item['id'], phase, now.date().isoformat())
            what = f"{item['start_time']}-{item['end_time']}"
        else:
            if phase == 'prepare' and vlab_reserve.occupied_before(pool['id'], vlab_reserve.rsv.parse(item['start_at']), now, item['id']):
                continue
            result = vlab_reserve.run_phase(item, pool, phase)
            what = f"booking {item['id']} {item['start_at']}-{item['end_at'][11:]}"
        log_audit('system', f'vlab.lab.{phase}', f"pool '{pool['name']}' ({what}): "
                  f"{len(result['done'])} done, {len(result['skipped'])} skipped, {len(result['failed'])} failed")
        out.append((item['id'], phase, result))
    return out


# --- LAB kiosk: a browser in full screen on a room's PC (/kiosk) --------------------------
# An admin makes the terminal a key (shown once) and types it into the PC's kiosk page.
# The page shows the room and its session; a user signs in with their own account and gets a
# free desktop of the session's pool, assigned to them until the session's clean-up.
# MOAVI Desk Client keeps registering by MAC (/api/vlab/terminals/register).

KIOSK_HEADER = 'X-Terminal-Key'


def _key_hash(key):
    import hashlib
    return hashlib.sha256(str(key).encode()).hexdigest() if key else ''


@bp.route('/api/vlab/admin/terminals/<terminal_id>/key', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def make_terminal_key(terminal_id):
    """A new key for this terminal's kiosk page (the old one stops working); approves it."""
    import secrets
    t = store.get_terminal(terminal_id)
    if not t:
        return _bad('Terminal not found', 404)
    key = 'mdt_' + secrets.token_urlsafe(24)
    store.set_terminal_key(terminal_id, _key_hash(key))
    from pegaprox.vlab import enroll
    enroll.set_key_state(terminal_id, 'manual')   # typed in by hand: its agent is not sent one
    log_audit(_user(), 'vlab.terminal.key', f"terminal {t['mac']} '{t['name']}': new kiosk key", get_client_ip())
    return jsonify({'key': key, 'terminal': store.get_terminal(terminal_id)})


def _kiosk_terminal():
    t = store.terminal_by_key(_key_hash(request.headers.get(KIOSK_HEADER, '').strip()))
    if not t or t['state'] != 'approved':
        return None, (jsonify({'error': 'This terminal key is not valid', 'code': 'BAD_KEY'}), 401)
    if not t.get('lab_id') or not store.get_lab(t['lab_id']):
        return None, (jsonify({'error': 'This terminal belongs to no LAB', 'code': 'NO_LAB'}), 409)
    store.update_terminal(t['id'], last_seen=store.now(), ip=get_client_ip() or t.get('ip') or '')
    return t, None


def _kiosk_view(t):
    lab = store.get_lab(t['lab_id'])
    pools = {p['id']: p['name'] for p in store.list_pools()}
    current, upcoming = labs.state_at(store.list_lab_schedules(lab['id']), _local_now())
    for x in (current, upcoming):
        if x:
            x['pool'] = pools.get(x['pool_id'])
    # a booking of the room (LAB > 예약) shows in place of the class
    from pegaprox.api.vlab_reserve import kiosk_state
    current, upcoming = kiosk_state(lab['id'], _local_now(), current, upcoming, pools)
    return {'terminal': {'id': t['id'], 'name': t['name']},
            'lab': {'id': lab['id'], 'name': lab['name'], 'location': lab['location']},
            'current': current, 'next': upcoming, 'now': _local_now().isoformat(timespec='minutes')}


@bp.route('/api/vlab/kiosk', methods=['GET'])
def kiosk_info():
    """The kiosk page before anyone signs in: its room and what runs now and next.
    Reached with the terminal key alone (header X-Terminal-Key)."""
    t, err = _kiosk_terminal()
    if err:
        return err
    return jsonify(_kiosk_view(t))


@bp.route('/api/vlab/kiosk/start', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def kiosk_start():
    """The signed-in user at a kiosk gets a desktop of the session's pool: theirs if they hold
    one there, else a free one, assigned to them (the clean-up after the session frees it)."""
    t, err = _kiosk_terminal()
    if err:
        return err
    view = _kiosk_view(t)
    cur = view['current']
    if not cur:
        return jsonify({'error': 'No session in this LAB now', 'code': 'NO_SESSION', **view}), 409
    username = _user()
    if cur.get('reservation_id'):
        from pegaprox.api.vlab_reserve import kiosk_desktop
        return kiosk_desktop(cur, username, t, view)
    desks = store.list_desktops(cur['pool_id'])
    mine = next((d for d in desks if d['assigned_user'] == username), None)
    if not mine:
        busy = store.open_session_desktops()
        free = [d for d in desks if not d['assigned_user'] and d['id'] not in busy and d.get('state') not in ('provisioning', 'resetting', 'error')]
        if not free:
            return jsonify({'error': 'Every desktop of this session is taken', 'code': 'FULL', **view}), 409
        mine = free[0]
        if not _acl_set(mine['cluster_id'], mine['vmid'], username, True):
            return _bad('VM access list unavailable - try again', 503)
        store.set_assignment(mine['id'], username)
        log_audit(username, 'vlab.kiosk.assign', f"{mine['vm_type']}/{mine['vmid']} '{mine['name']}' at terminal "
                  f"'{t['name'] or t['mac']}' (LAB {view['lab']['name']})", get_client_ip())
    return jsonify({'desktop': {'id': mine['id'], 'name': mine['name']}, **view})


# --- MOAVI Desk Client (Windows) ---------------------------------------------------------
# What the engine asks of its installed clients: the version to offer, the oldest one it still
# takes, where to download it and the protocol to prefer. Kept in the server settings
# (synced to HA peers with them).

_CLIENT_DEFAULTS = {'latest_version': '', 'min_version': '', 'download_url': '', 'protocol': 'auto'}
_CLIENT_KEY = 'vlab_client'
_VERSION_RE = re.compile(r'^\d+(\.\d+){0,3}$')


def _client_settings():
    from pegaprox.api.helpers import load_server_settings
    saved = (load_server_settings() or {}).get(_CLIENT_KEY) or {}
    if isinstance(saved, str):
        try:
            saved = json.loads(saved)
        except ValueError:
            saved = {}
    return {k: saved.get(k, v) for k, v in _CLIENT_DEFAULTS.items()}


@bp.route('/api/vlab/client/config', methods=['GET'])
@require_auth()
def client_config():
    """For a signed-in MOAVI Desk Client: the update it should offer or require, its protocol
    and the remote-support page (the white label's, else the company's)."""
    from pegaprox.api import frontend_branding as fb
    c = _client_settings()
    support = (fb.resolved(fb.DEFAULT_TENANT) or {}).get('supportUrl') or 'https://support.makussystems.co.kr/'
    return jsonify({'product': 'MOAVI Desk', **c, 'support_url': support, 'api_version': VLAB_API_VERSION})


@bp.route('/api/vlab/admin/client', methods=['GET'])
@require_auth(perms=['admin.settings'])
def client_settings_get():
    return jsonify({'client': _client_settings()})


@bp.route('/api/vlab/admin/client', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def client_settings_put():
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return _bad('JSON body required')
    unknown = sorted(set(data) - set(_CLIENT_DEFAULTS))
    if unknown:
        return _bad(f"unknown fields: {', '.join(unknown)}")
    c = _client_settings()
    for k in _CLIENT_DEFAULTS:
        if k in data:
            if not isinstance(data[k], str):
                return _bad(f'{k} must be str')
            c[k] = data[k].strip()
    for k in ('latest_version', 'min_version'):
        if c[k] and not _VERSION_RE.match(c[k]):
            return _bad(f'{k} must look like 1.2.3')
    if c['download_url'] and not re.match(r'^https?://', c['download_url']):
        return _bad('download_url must start with http:// or https://')
    if c['protocol'] not in ('auto', 'rdp', 'spice', 'vnc'):
        return _bad('protocol must be auto, rdp, spice or vnc')
    settings = load_server_settings() or {}
    settings[_CLIENT_KEY] = c
    if not save_server_settings(settings):
        return _bad('Could not save the settings', 500)
    log_audit(_user(), 'vlab.client.settings',
              f"client: latest {c['latest_version'] or '-'}, min {c['min_version'] or '-'}, protocol {c['protocol']}",
              get_client_ip())
    return jsonify({'client': c})


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
