"""MOAVI Desk: 클러스터 > 고가용성 (HA) and 클러스터 > 부하 분산 (pegaprox/vlab/hadrs.py).

  GET    /api/vlab/admin/clusters/<id>/ha/extra             prerequisites, disk storage of the HA guests,
                                                            the keep-apart rules, the pools        vlab.pool.view + ha.view
  POST   .../ha/pool {pool_id, action: add|remove}          every desktop of the pool in or out of HA   vlab.pool.manage + ha.config
  POST   .../ha/separate {name, vmids}                      keep these guests on different nodes        vlab.pool.manage + ha.config
  DELETE .../ha/separate/<name>
  GET    .../balance ?refresh=1                             mode, settings, node scores, recommended
                                                            moves, guests left out, move history        vlab.pool.view + cluster.view
  PUT    .../balance {mode?, check_interval?, ...}          mode and settings                            vlab.pool.manage + cluster.config
  POST   .../balance/apply {vmid, to}                       live-migrates one recommended guest          vlab.pool.manage + cluster.config
  POST   .../balance/run                                    the core's balance-now (moves at once)       vlab.pool.manage + cluster.config

Nothing here moves or registers a guest on its own except ha_tick, which carries out the pool policy
'HA 사용' an administrator set (new desktops only). A recommendation is computed, never executed,
until 적용 is pressed.
"""
import logging
import re
import time

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.core import ha
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import hadrs, policy, store

bp = Blueprint('vlab_hadrs', __name__)

_bad = core._bad
_user = core._user
_NAME_RE = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,39}')
_PLAN_TTL = 60
_INFO_TTL = 60
_plans = {}      # cluster_id -> (at, moves)
_infos = {}      # cluster_id -> (at, {vmid: {'storage', 'passthrough'}})

SETTINGS = {
    'check_interval': (60, 86400), 'migration_threshold': (5, 200),
    'balance_cpu_weight': (0, 10), 'balance_mem_weight': (0, 10), 'balance_io_weight': (0, 10),
}
FLAGS = ('balance_local_disks', 'balance_containers')


def _target(cluster_id, node=None):
    from pegaprox.api.vlab_next import _build_target
    return _build_target(cluster_id, node)


def _body():
    d = request.get_json(silent=True)
    return d if isinstance(d, dict) else {}


# --- what each guest can do --------------------------------------------------------------------

def _guest_info(cluster_id, mgr, vms, refresh=False):
    """{vmid: {'storage': shared|local|unknown|nodisk, 'passthrough': pci|usb|None}} for the given
    guests (config reads cached a minute)."""
    at, cache = _infos.get(cluster_id, (0.0, {}))
    if refresh or time.time() - at > _INFO_TTL:
        at, cache = time.time(), {}
        _infos[cluster_id] = (at, cache)
    out = {}
    for vm in vms:
        vmid = int(vm['vmid'])
        if vmid not in cache:
            node, kind = vm.get('node'), vm.get('type')
            info = {'storage': 'unknown', 'passthrough': None}
            try:
                info['storage'] = mgr._ha_check_vm_storage(vmid, kind, node)
            except Exception as e:
                logging.debug(f'[VLAB] storage of {vmid}: {e}')
            if kind == 'qemu':
                try:
                    info['passthrough'] = mgr._vm_passthrough(node, vmid)
                except Exception:
                    pass
            if info['storage'] not in ('shared', 'local', 'nodisk', 'unknown'):
                info['storage'] = 'unknown'
            if info['passthrough'] not in ('pci', 'usb'):
                info['passthrough'] = None
            cache[vmid] = info
        out[vmid] = cache[vmid]
    return out


def _desk_map(cluster_id):
    pools = {p['id']: p for p in store.list_pools()}
    out = {}
    for d in store.list_desktops():
        if d['cluster_id'] == cluster_id:
            p = pools.get(d['pool_id']) or {}
            out[int(d['vmid'])] = {'id': d['id'], 'name': d['name'], 'pool_id': d['pool_id'], 'pool': p.get('name', '')}
    return out


# --- 고가용성 ----------------------------------------------------------------------------------

def _pve_rules(mgr):
    """PVE 9 HA rules, or None on a cluster without /cluster/ha/rules."""
    try:
        r = mgr._api_get(f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/ha/rules")
        if r.status_code == 200:
            return r.json().get('data') or []
    except Exception as e:
        logging.debug(f'[VLAB] HA rules: {e}')
    return None


def _sids_vmids(text):
    out = []
    for sid in str(text or '').split(','):
        kind, _, num = sid.strip().partition(':')
        if kind in ('vm', 'ct') and num.isdigit():
            out.append(int(num))
    return out


def _balancer_rules(cluster_id):
    from pegaprox.api.alerts import load_cluster_affinity_rules
    try:
        return [r for r in (load_cluster_affinity_rules().get(cluster_id) or []) if r.get('type') == 'separate']
    except Exception:
        return []


def _separate_rules(cluster_id, mgr):
    by = {}
    for r in _pve_rules(mgr) or []:
        if str(r.get('type')).lower() == 'resource-affinity' and str(r.get('affinity')).lower() == 'negative':
            by[str(r.get('rule'))] = {'name': str(r.get('rule')), 'vmids': _sids_vmids(r.get('resources')),
                                      'ha_rule': True, 'balancer_rule': False, 'enabled': not r.get('disable'),
                                      'comment': str(r.get('comment') or '')}
    for r in _balancer_rules(cluster_id):
        x = by.setdefault(str(r.get('name')), {'name': str(r.get('name')), 'vmids': [], 'ha_rule': False,
                                               'enabled': True, 'comment': ''})
        x['balancer_rule'] = True
        x['balancer_id'] = r.get('id')
        x['vmids'] = sorted(set(x['vmids']) | {int(v) for v in r.get('vms') or [] if str(v).isdigit()})
    return sorted(by.values(), key=lambda x: x['name'])


@bp.route('/api/vlab/admin/clusters/<cluster_id>/ha/extra', methods=['GET'])
@require_auth(perms=['vlab.pool.view', 'ha.view'])
def ha_extra(cluster_id):
    """What the HA page needs beside the resource list: nodes online, quorum, the disk storage of
    every HA guest (a guest on node-local disks cannot start elsewhere), the keep-apart rules and
    each pool with its 'HA 사용' switch and how many of its desktops are under HA."""
    from pegaprox.api import clusters as core_clusters
    from pegaprox.api.vlab_next import _ha_current
    mgr, err = _target(cluster_id)
    if err:
        return err
    status = mgr.get_node_status() or {}
    online = [n for n, d in status.items() if d.get('status') == 'online']
    _cur, quorate, _master = _ha_current(mgr)
    res = core._core_body(core_clusters.get_proxmox_ha_resources(cluster_id)) or []
    ha_vmids = {v for r in res if isinstance(r, dict) for v in _sids_vmids(r.get('sid'))}
    live = core._vm_states(cluster_id)
    info = _guest_info(cluster_id, mgr, [live[v] for v in ha_vmids if v in live], refresh=request.args.get('refresh') == '1')
    pools = []
    for p in store.list_pools():
        if p['cluster_id'] != cluster_id:
            continue
        desks = store.list_desktops(p['id'])
        pools.append({'id': p['id'], 'name': p['name'], 'type': p['type'],
                      'ha_enabled': bool(policy.effective(p.get('settings'), p['type']).get('ha_enabled')),
                      'desktops': len(desks), 'in_ha': sum(1 for d in desks if int(d['vmid']) in ha_vmids)})
    separate = _separate_rules(cluster_id, mgr)
    names = {str(v): (live.get(v) or {}).get('name') or '' for r in separate for v in r['vmids']}
    return jsonify({'nodes_online': len(online), 'nodes_total': len(status), 'quorate': quorate,
                    'rules_supported': _pve_rules(mgr) is not None, 'names': names,
                    'storage': {str(v): i['storage'] for v, i in info.items()},
                    'passthrough': {str(v): i['passthrough'] for v, i in info.items() if i['passthrough']},
                    'separate': separate, 'pools': pools,
                    'waiting': len(hadrs.ha_waiting())})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/ha/pool', methods=['POST'])
@require_auth(perms=['vlab.pool.manage', 'ha.config'])
def ha_pool(cluster_id):
    """{pool_id, action: add|remove} - every desktop of the pool goes under HA (keeping its power
    state: a running one 'started', the rest 'stopped') or comes out of it."""
    from pegaprox.api import clusters as core_clusters
    mgr, err = _target(cluster_id)
    if err:
        return err
    data = _body()
    pool = store.get_pool(str(data.get('pool_id') or ''))
    if not pool or pool['cluster_id'] != cluster_id:
        return _bad('No such pool on this cluster', 404)
    action = data.get('action')
    if action not in ('add', 'remove'):
        return _bad('action: add or remove')
    res = core._core_body(core_clusters.get_proxmox_ha_resources(cluster_id)) or []
    in_ha = {v for r in res if isinstance(r, dict) for v in _sids_vmids(r.get('sid'))}
    live = core._vm_states(cluster_id)
    ok, failed = [], []
    for d in store.list_desktops(pool['id']):
        vmid = int(d['vmid'])
        if d.get('vm_type', 'qemu') != 'qemu' or (action == 'add') == (vmid in in_ha):
            continue
        if not core_clusters._ha_sid_authorized(cluster_id, f'vm:{vmid}'):
            failed.append({'vmid': vmid, 'name': d['name'], 'error': 'Access denied'})
            continue
        if action == 'add':
            state = 'started' if (live.get(vmid) or {}).get('status') == 'running' else 'stopped'
            r = mgr.add_vm_to_proxmox_ha(vmid, 'vm', None, 1, 1, state, f"MOAVI Desk pool {pool['name']}"[:200])
        else:
            r = mgr.remove_vm_from_proxmox_ha(vmid, 'vm')
        if isinstance(r, dict) and r.get('success'):
            ok.append(vmid)
        else:
            failed.append({'vmid': vmid, 'name': d['name'], 'error': str((r or {}).get('error') or 'failed')[:200]})
    if ok:
        log_audit(_user(), 'ha.vm_added' if action == 'add' else 'ha.vm_removed',
                  f"Pool {pool['name']}: {len(ok)} desktop(s) {'added to' if action == 'add' else 'removed from'} HA",
                  cluster=core._cluster_name(cluster_id, mgr))
    return jsonify({'done': ok, 'failed': failed})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/ha/separate', methods=['POST'])
@require_auth(perms=['vlab.pool.manage', 'ha.config'])
def ha_separate_add(cluster_id):
    """{name, vmids: [..2+]} - keep these guests on different nodes: a negative resource-affinity
    rule of Proxmox HA (placement after a node fails; PVE 9 and the guests must be under HA) and
    an enforced 'separate' rule of the balancer (its moves and recommendations)."""
    from pegaprox.api.alerts import load_cluster_affinity_rules, save_cluster_affinity_rules
    from pegaprox.api import clusters as core_clusters
    from pegaprox.utils.auth import build_authz_user
    from pegaprox.utils.rbac import user_can_access_vm
    import uuid
    from datetime import datetime
    mgr, err = _target(cluster_id)
    if err:
        return err
    data = _body()
    name = data.get('name')
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        return _bad('name: letters, digits, "-" and "_", starting with a letter')
    vmids = data.get('vmids')
    if not isinstance(vmids, list) or not 2 <= len(vmids) <= 32 or not all(isinstance(v, int) and v >= 100 for v in vmids):
        return _bad('vmids: 2 to 32 VM ids')
    vmids = sorted(set(vmids))
    live = core._vm_states(cluster_id)
    _au = build_authz_user(request.session.get('user', ''), request.session)
    for v in vmids:
        if v not in live:
            return _bad(f'No VM {v} on the cluster', 404)
        if not user_can_access_vm(_au, cluster_id, v, 'vm.migrate'):
            return _bad(f'Access denied to VM {v}', 403)
    if any(r['name'] == name for r in _separate_rules(cluster_id, mgr)):
        return _bad('A rule of that name exists', 409)
    res = core._core_body(core_clusters.get_proxmox_ha_resources(cluster_id)) or []
    in_ha = {v for r in res if isinstance(r, dict) for v in _sids_vmids(r.get('sid'))}
    ha_rule = False
    if _pve_rules(mgr) is not None and all(v in in_ha for v in vmids):
        sids = ','.join(f"{'ct' if (live.get(v) or {}).get('type') == 'lxc' else 'vm'}:{v}" for v in vmids)
        r = mgr._api_post(f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/ha/rules",
                          data={'rule': name, 'type': 'resource-affinity', 'affinity': 'negative', 'resources': sids,
                                'comment': 'MOAVI Desk: keep apart'})
        if r.status_code != 200:
            return _bad(f'Proxmox HA refused the rule: {(r.text or "")[:200]}', 502)
        ha_rule = True
    rules = load_cluster_affinity_rules()
    rules.setdefault(cluster_id, []).append({'id': str(uuid.uuid4())[:8], 'name': name, 'type': 'separate', 'vms': vmids,
                                             'vm_ids': vmids, 'enforce': True, 'enabled': True,
                                             'created_at': datetime.now().isoformat()})
    save_cluster_affinity_rules(rules)
    log_audit(_user(), 'ha.rule_created', f"Keep apart '{name}': {', '.join(map(str, vmids))}" + (' (HA rule too)' if ha_rule else ''),
              cluster=core._cluster_name(cluster_id, mgr))
    return jsonify({'success': True, 'ha_rule': ha_rule}), 201


@bp.route('/api/vlab/admin/clusters/<cluster_id>/ha/separate/<name>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage', 'ha.config'])
def ha_separate_remove(cluster_id, name):
    from pegaprox.core.db import get_db
    mgr, err = _target(cluster_id)
    if err:
        return err
    if not _NAME_RE.fullmatch(name):
        return _bad('Invalid name')
    rule = next((r for r in _separate_rules(cluster_id, mgr) if r['name'] == name), None)
    if not rule:
        return _bad('No such rule', 404)
    if rule['ha_rule']:
        r = mgr._api_delete(f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/ha/rules/{name}")
        if r.status_code != 200:
            return _bad(f'Proxmox HA kept the rule: {(r.text or "")[:200]}', 502)
    if rule.get('balancer_id'):
        get_db().execute('DELETE FROM affinity_rules WHERE id = ? AND cluster_id = ?', (rule['balancer_id'], cluster_id))
    log_audit(_user(), 'ha.rule_deleted', f"Keep apart '{name}' removed", cluster=core._cluster_name(cluster_id, mgr))
    return jsonify({'success': True})


def ha_tick(limit=10):
    """New desktops of 'HA 사용' pools go under Proxmox HA once ready (from the minute loop)."""
    rows = hadrs.due(limit)
    if not rows:
        return
    for row in rows:
        desk = store.get_desktop(row['desktop_id'])
        if not desk:
            hadrs.done(row['desktop_id'])
            continue
        pool = store.get_pool(desk['pool_id'])
        if not pool or not policy.effective(pool.get('settings'), pool['type']).get('ha_enabled'):
            hadrs.done(desk['id'])
            continue
        attempts = int(row['attempts']) + 1
        mgr = cluster_managers.get(desk['cluster_id'])
        if desk['state'] != 'ready' or not mgr or not getattr(mgr, 'is_connected', False):
            if attempts >= 60:     # an hour without becoming ready: left to the HA page
                hadrs.done(desk['id'])
            else:
                hadrs.later(desk['id'], attempts, 60)
            continue
        vm = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
        state = 'started' if vm.get('status') == 'running' else 'stopped'
        # a leader that lost its lease starts no new step (design 5.2)
        if not ha.confirm_step(f"HA for desktop {desk['vm_type']}/{desk['vmid']} by pool policy"):
            return
        r = mgr.add_vm_to_proxmox_ha(int(desk['vmid']), 'vm', None, 1, 1, state, f"MOAVI Desk pool {pool['name']}"[:200])
        if isinstance(r, dict) and (r.get('success') or 'already' in str(r.get('error') or '').lower()):
            hadrs.done(desk['id'])
            log_audit('system', 'ha.vm_added', f"Desktop {desk['name']} (VM {desk['vmid']}) added to HA by pool policy",
                      cluster=core._cluster_name(desk['cluster_id'], mgr))
        elif attempts >= hadrs.HA_MAX_ATTEMPTS:
            hadrs.done(desk['id'])
            logging.warning(f"[VLAB] HA for desktop {desk['name']}: gave up ({str((r or {}).get('error'))[:200]})")
        else:
            hadrs.later(desk['id'], attempts, min(60 * 2 ** attempts, 3600))


# --- 부하 분산 ---------------------------------------------------------------------------------

def _settings(mgr):
    c = mgr.config
    return {'check_interval': int(getattr(c, 'check_interval', 300) or 300),
            'migration_threshold': getattr(c, 'migration_threshold', 20),
            'balance_cpu_weight': getattr(c, 'balance_cpu_weight', 1.0), 'balance_mem_weight': getattr(c, 'balance_mem_weight', 1.0),
            'balance_io_weight': getattr(c, 'balance_io_weight', 0.0),
            'balance_local_disks': bool(getattr(c, 'balance_local_disks', False)),
            'balance_containers': bool(getattr(c, 'balance_containers', False)),
            'excluded_nodes': list(getattr(c, 'excluded_nodes', []) or [])}


def _excluded(cluster_id, mgr, live, refresh=False):
    """Running guests the balancer leaves where they are, with the reason."""
    running = [v for v in live.values() if v.get('status') == 'running' and v.get('type') in ('qemu', 'lxc')
               and not v.get('template')]
    info = _guest_info(cluster_id, mgr, running, refresh)
    s = _settings(mgr)
    try:
        by_admin = set(mgr.get_balancing_excluded_vms() or [])
        pools_out = set(mgr.get_balancing_excluded_pools() or [])
    except Exception:
        by_admin, pools_out = set(), set()
    desks = _desk_map(cluster_id)
    out = []
    for v in running:
        vmid = int(v['vmid'])
        i = info.get(vmid) or {}
        reason = hadrs.why_stays(v, {}, i.get('storage') if i.get('storage') != 'nodisk' else 'shared',
                                 s['balance_local_disks'], s['balance_containers'])
        reason = i.get('passthrough') or reason
        if not reason and (vmid in by_admin or v.get('pool', '') in pools_out):
            reason = 'excluded'
        if reason:
            d = desks.get(vmid)
            out.append({'vmid': vmid, 'name': v.get('name') or '', 'node': v.get('node') or '', 'reason': reason,
                        'pool': d['pool'] if d else ''})
    return sorted(out, key=lambda x: (x['node'], x['vmid']))


def stays_reasons(cluster_id, mgr, vms):
    """{vmid: reason} for the running guests of vms that live migration leaves where they are
    (the maintenance preview). Containers restart rather than stay, so they are not listed."""
    running = [v for v in vms if v.get('status') == 'running' and v.get('type') in ('qemu', 'lxc') and not v.get('template')]
    info = _guest_info(cluster_id, mgr, running)
    s = _settings(mgr)
    out = {}
    for v in running:
        i = info.get(int(v['vmid'])) or {}
        r = i.get('passthrough') or hadrs.why_stays(v, {}, i.get('storage') if i.get('storage') != 'nodisk' else 'shared',
                                                    s['balance_local_disks'], True)
        if r:
            out[int(v['vmid'])] = r
    return out


@bp.route('/api/vlab/admin/clusters/<cluster_id>/balance', methods=['GET'])
@require_auth(perms=['vlab.pool.view', 'cluster.view'])
def balance_get(cluster_id):
    mgr, err = _target(cluster_id)
    if err:
        return err
    refresh = request.args.get('refresh') == '1'
    mode = hadrs.mode_of(cluster_id, mgr)
    status = mgr.get_node_status() or {}
    s = _settings(mgr)
    nodes = [{'node': n, 'online': d.get('status') == 'online', 'maintenance': bool(d.get('maintenance_mode')),
              'excluded': n in s['excluded_nodes'], 'score': d.get('score') or 0,
              'cpu': d.get('cpu_percent') or 0, 'mem': d.get('mem_percent') or 0}
             for n, d in sorted(status.items())]
    live = core._vm_states(cluster_id)
    recs, at = [], None
    if mode != 'off':
        at, recs = _plans.get(cluster_id, (0, None))
        if refresh or recs is None or time.time() - at > _PLAN_TTL:
            try:
                recs = hadrs.plan(mgr, node_status=status)
            except Exception as e:
                logging.error(f'[VLAB] balance plan of {cluster_id}: {e}')
                recs = []
            at = time.time()
            _plans[cluster_id] = (at, recs)
        desks = _desk_map(cluster_id)
        recs = [dict(r, pool=(desks.get(r['vmid']) or {}).get('pool', '')) for r in recs]
    try:
        hadrs.take_core_log(cluster_id, mgr)
    except Exception as e:
        logging.debug(f'[VLAB] balance log: {e}')
    last = getattr(mgr, 'last_run', None)
    return jsonify({'mode': mode, 'settings': s, 'nodes': nodes, 'recommendations': recs,
                    'computed_at': int(at) if at else None,
                    'last_run': last.isoformat() if hasattr(last, 'isoformat') else None,
                    'excluded': _excluded(cluster_id, mgr, live, refresh), 'history': hadrs.moves(cluster_id)})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/balance', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage', 'cluster.config'])
def balance_put(cluster_id):
    """{mode?: off|recommend|auto, check_interval?, migration_threshold?, balance_*_weight?,
    balance_local_disks?, balance_containers?}. 'auto' turns the core's auto_migrate on; the
    other two keep it off."""
    from pegaprox.api.helpers import require_unconfined
    from pegaprox.core.config import save_config
    mgr, err = _target(cluster_id)
    if err:
        return err
    denied = require_unconfined(cluster_id)
    if denied:
        return denied
    data = _body()
    if set(data) - set(SETTINGS) - set(FLAGS) - {'mode'}:
        return _bad('Unknown field')
    mode = data.get('mode')
    if mode is not None and mode not in hadrs.MODES:
        return _bad(f"mode: one of {', '.join(hadrs.MODES)}")
    clean = {}
    for k, (lo, hi) in SETTINGS.items():
        if k in data:
            v = data[k]
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
                return _bad(f'{k}: {lo} to {hi}')
            clean[k] = int(v) if k in ('check_interval', 'migration_threshold') else float(v)
    for k in FLAGS:
        if k in data:
            if not isinstance(data[k], bool):
                return _bad(f'{k}: true or false')
            clean[k] = data[k]
    if clean.get('balance_cpu_weight') == 0 and clean.get('balance_mem_weight') == 0 and clean.get('balance_io_weight', 0) == 0:
        return _bad('At least one weight above 0')
    for k, v in clean.items():
        setattr(mgr.config, k, v)
    if mode:
        hadrs.set_mode(cluster_id, mode, _user())
        mgr.config.auto_migrate = mode == 'auto'
    save_config()
    _plans.pop(cluster_id, None)
    _infos.pop(cluster_id, None)
    log_audit(_user(), 'cluster.config_changed', f"부하 분산: {', '.join(sorted(list(clean) + (['mode=' + mode] if mode else [])))}",
              cluster=core._cluster_name(cluster_id, mgr))
    return jsonify({'success': True, 'mode': hadrs.mode_of(cluster_id, mgr), 'settings': _settings(mgr)})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/balance/apply', methods=['POST'])
@require_auth(perms=['vlab.pool.manage', 'cluster.config'])
def balance_apply(cluster_id):
    """{vmid, to} - live-migrates one guest (normally a recommendation). The answer carries the
    Proxmox task; the move shows in the history either way."""
    from pegaprox.api.helpers import require_unconfined
    from pegaprox.api.vms import _require_vm_access
    mgr, err = _target(cluster_id)
    if err:
        return err
    denied = require_unconfined(cluster_id)
    if denied:
        return denied
    data = _body()
    vmid, to = data.get('vmid'), data.get('to')
    if not isinstance(vmid, int) or isinstance(vmid, bool) or not isinstance(to, str) or not to:
        return _bad('vmid and to required')
    vm = core._vm_states(cluster_id).get(vmid)
    if not vm or vm.get('type') not in ('qemu', 'lxc') or vm.get('template'):
        return _bad('No such VM on the cluster', 404)
    status = mgr.get_node_status() or {}
    t = status.get(to)
    if not t or t.get('status') != 'online' or t.get('maintenance_mode'):
        return _bad('The target node is not online or is in maintenance', 409)
    if vm.get('node') == to:
        return _bad('The VM is on that node already', 409)
    denied = _require_vm_access(cluster_id, vmid, 'vm.migrate', vm['type'])
    if denied:
        return denied
    info = _guest_info(cluster_id, mgr, [vm], refresh=True).get(vmid) or {}
    s = _settings(mgr)
    reason = info.get('passthrough') or hadrs.why_stays(vm, {}, info.get('storage') if info.get('storage') != 'nodisk' else 'shared',
                                                        s['balance_local_disks'], s['balance_containers'])
    if reason and reason != 'container':
        return jsonify({'error': 'This VM cannot live-migrate', 'code': 'NOT_MOVABLE', 'reason': reason}), 409
    opts = {'with_local_disks': True} if info.get('storage') == 'local' else {}
    r = mgr.migrate_vm_manual(vm['node'], vmid, vm['type'], to, online=vm.get('status') == 'running', options=opts)
    ok = isinstance(r, dict) and r.get('success')
    hadrs.record_move(cluster_id, vmid, vm.get('name'), vm['node'], to, 'apply', _user(), bool(ok),
                      '' if ok else str((r or {}).get('error') or 'failed'))
    _plans.pop(cluster_id, None)
    log_audit(_user(), 'vm.migrated' if ok else 'vm.migrate_failed',
              f"부하 분산: VM {vmid} {vm['node']} -> {to}", cluster=core._cluster_name(cluster_id, mgr))
    if not ok:
        return _bad(str((r or {}).get('error') or 'Migration failed')[:300], 502)
    return jsonify({'success': True, 'task': r.get('task') or r.get('upid') or r.get('data')})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/balance/run', methods=['POST'])
@require_auth(perms=['vlab.pool.manage', 'cluster.config'])
def balance_run(cluster_id):
    """지금 분산: the core's balance check now, moving what it finds whatever the mode."""
    from pegaprox.api import clusters as core_clusters
    _, err = _target(cluster_id)
    if err:
        return err
    _plans.pop(cluster_id, None)
    return core_clusters.trigger_balance_now(cluster_id)
