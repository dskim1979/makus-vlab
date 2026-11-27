# -*- coding: utf-8 -*-
"""
네트워크 격리 (MAKUS): the pool policy's net_* switches carried into the Proxmox firewall
(what goes where: pegaprox/vlab/netiso.py).

  GET  /api/vlab/admin/clusters/<cluster_id>/netiso   the gateway's addresses, a suggestion,
                                                      whether the datacenter firewall is on    vlab.pool.view
  PUT  /api/vlab/admin/clusters/<cluster_id>/netiso   {gateway_sources: [ip or cidr]}            vlab.pool.manage
  GET  /api/vlab/admin/pools/<pool_id>/netiso         the pool's state: each desktop applied or
                                                      not, its addresses, the last problem       vlab.pool.view
  POST /api/vlab/admin/pools/<pool_id>/netiso/apply   apply now (otherwise the minute loop does
                                                      it within NETISO_EVERY)                   vlab.pool.manage

The minute loop (pegaprox/vlab/loans.py) calls netiso_tick: a pool is synced when its policy,
its desktops or the gateway's addresses changed, and every NETISO_EVERY for the desktops'
addresses. A pool whose switch went off, or a desktop that left it, gets its firewall back:
the vlab-netiso rule out, the policies ACCEPT, the VM firewall off again if this turned it on.
Nothing is applied while the cluster has no gateway address: DROP without one would cut the
desktops off from MOAVI itself.
"""

import logging
import time

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.core import ha
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import log_audit, get_client_ip
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import netiso, policy, store

bp = Blueprint('vlab_netiso', __name__)

NETISO_EVERY = 300          # the desktops' addresses (DHCP) are looked at again this often
_state = {}                 # pool id -> {'fp', 'at', 'problem', 'desktops': {desktop id: {...}}}


def _fw(mgr, path):
    return f"https://{mgr.host}:{mgr.api_port}/api2/json{path}"


def _data(r):
    if r is None or r.status_code != 200:
        return None
    try:
        return r.json().get('data')
    except ValueError:
        return None


def _ok(r, what):
    if r is None or r.status_code != 200:
        raise RuntimeError(f"{what}: {'' if r is None else r.text[:200]}")


def cluster_firewall(mgr):
    """{'enable': bool, 'policy_in': ...} of the datacenter firewall, None when unknown."""
    try:
        d = _data(mgr._api_get(_fw(mgr, '/cluster/firewall/options'), timeout=8))
    except Exception:
        return None
    if not isinstance(d, dict):
        return None
    return {'enable': bool(int(d.get('enable') or 0)), 'policy_in': d.get('policy_in') or 'ACCEPT'}


# --- cluster objects -------------------------------------------------------------------------------

def _ensure_ipset(mgr, name, cidrs, comment, keep=None):
    """The ipset holds exactly `cidrs` (plus the entries `keep(entry)` says stay)."""
    sets = _data(mgr._api_get(_fw(mgr, '/cluster/firewall/ipset'), timeout=8)) or []
    if not any(s.get('name') == name for s in sets):
        _ok(mgr._api_post(_fw(mgr, '/cluster/firewall/ipset'), data={'name': name, 'comment': comment}, timeout=10),
            f'ipset {name}')
        have = []
    else:
        have = _data(mgr._api_get(_fw(mgr, f'/cluster/firewall/ipset/{name}'), timeout=8)) or []
    have_cidrs = {e.get('cidr'): e for e in have}
    for c, e in have_cidrs.items():
        if c not in cidrs and not (keep and keep(e)):
            _ok(mgr._api_delete(_fw(mgr, f"/cluster/firewall/ipset/{name}/{c.replace('/', '%2F')}"), timeout=10),
                f'ipset {name} - {c}')
    for c, note in cidrs.items():
        if c not in have_cidrs:
            _ok(mgr._api_post(_fw(mgr, f'/cluster/firewall/ipset/{name}'), data={'cidr': c, 'comment': note}, timeout=10),
                f'ipset {name} + {c}')


def _ensure_group(mgr, name, rules, comment):
    groups = _data(mgr._api_get(_fw(mgr, '/cluster/firewall/groups'), timeout=8)) or []
    if not any(g.get('group') == name for g in groups):
        _ok(mgr._api_post(_fw(mgr, '/cluster/firewall/groups'), data={'group': name, 'comment': comment[:100]}, timeout=10),
            f'group {name}')
        have = []
    else:
        have = _data(mgr._api_get(_fw(mgr, f'/cluster/firewall/groups/{name}'), timeout=8)) or []
    have = sorted(have, key=lambda r: int(r.get('pos', 0)))
    if [netiso.rule_key(r) for r in have] == [netiso.rule_key(r) for r in rules]:
        return False
    for r in sorted(have, key=lambda r: -int(r.get('pos', 0))):
        _ok(mgr._api_delete(_fw(mgr, f"/cluster/firewall/groups/{name}/{int(r['pos'])}"), timeout=10), f'group {name} rule')
    for r in reversed(rules):            # each POST lands at the top
        _ok(mgr._api_post(_fw(mgr, f'/cluster/firewall/groups/{name}'), data=r, timeout=10), f'group {name} rule')
    return True


def _drop_cluster_objects(mgr, pool_id):
    """The pool's group and ipset, once nothing uses them (best effort)."""
    for path in (f'/cluster/firewall/groups/{netiso.group_name(pool_id)}', f'/cluster/firewall/ipset/{netiso.ipset_name(pool_id)}'):
        try:
            if path.startswith('/cluster/firewall/groups/'):
                for r in sorted(_data(mgr._api_get(_fw(mgr, path), timeout=8)) or [], key=lambda r: -int(r.get('pos', 0))):
                    mgr._api_delete(_fw(mgr, f"{path}/{int(r['pos'])}"), timeout=10)
            else:
                for e in _data(mgr._api_get(_fw(mgr, path), timeout=8)) or []:
                    mgr._api_delete(_fw(mgr, f"{path}/{str(e.get('cidr')).replace('/', '%2F')}"), timeout=10)
            mgr._api_delete(_fw(mgr, path), timeout=10)
        except Exception as e:
            logging.info(f'[VLAB] netiso: {path} left in place: {str(e)[:200]}')


# --- one desktop -----------------------------------------------------------------------------------

def _vm_path(node, vm_type, vmid):
    return f"/nodes/{node}/{'lxc' if vm_type == 'lxc' else 'qemu'}/{int(vmid)}"


def _apply_desktop(mgr, desk, node, pol, group):
    """NIC firewall=1, the group rule, the VM's firewall options. Returns what changed."""
    base = _vm_path(node, desk.get('vm_type'), desk['vmid'])
    changed = []
    cfg = _data(mgr._api_get(_fw(mgr, f'{base}/config'), timeout=8)) or {}
    nics = {k: with_fw for k, v in cfg.items() if k.startswith('net') and k[3:].isdigit()
            for with_fw in [netiso.with_firewall(v)] if with_fw}
    if nics:
        _ok(mgr._api_put(_fw(mgr, f'{base}/config'), data=nics, timeout=20), 'NIC firewall')
        changed.append('nic')
    rules = _data(mgr._api_get(_fw(mgr, f'{base}/firewall/rules'), timeout=8)) or []
    ours = [r for r in rules if str(r.get('comment') or '').startswith(netiso.TAG)]
    right = [r for r in ours if r.get('type') == 'group' and r.get('action') == group and int(r.get('enable', 1) or 0)]
    if not (len(ours) == 1 and right):
        for r in sorted(ours, key=lambda r: -int(r.get('pos', 0))):
            _ok(mgr._api_delete(_fw(mgr, f"{base}/firewall/rules/{int(r['pos'])}"), timeout=10), 'old rule')
        _ok(mgr._api_post(_fw(mgr, f'{base}/firewall/rules'),
                          data={'type': 'group', 'action': group, 'enable': 1, 'comment': netiso.TAG, 'pos': 0}, timeout=10),
            'group rule')
        changed.append('rule')
    opts = _data(mgr._api_get(_fw(mgr, f'{base}/firewall/options'), timeout=8)) or {}
    want = netiso.vm_options(pol)
    was_on = bool(int(opts.get('enable') or 0))
    if any(str(opts.get(k, '')) != str(v) for k, v in want.items()):
        _ok(mgr._api_put(_fw(mgr, f'{base}/firewall/options'), data=want, timeout=10), 'firewall options')
        changed.append('options')
    return changed, not was_on


def _revert_desktop(mgr, row):
    base = _vm_path(row['node'], row['vm_type'], row['vmid'])
    rules = _data(mgr._api_get(_fw(mgr, f'{base}/firewall/rules'), timeout=8))
    if rules is None:
        return          # the VM is gone (or elsewhere): nothing of ours to take back
    for r in sorted([r for r in rules if str(r.get('comment') or '').startswith(netiso.TAG)], key=lambda r: -int(r.get('pos', 0))):
        _ok(mgr._api_delete(_fw(mgr, f"{base}/firewall/rules/{int(r['pos'])}"), timeout=10), 'rule')
    opts = {'policy_in': 'ACCEPT', 'policy_out': 'ACCEPT'}
    if int(row['enabled_by_us'] or 0):
        opts['enable'] = 0
    _ok(mgr._api_put(_fw(mgr, f'{base}/firewall/options'), data=opts, timeout=10), 'firewall options')


# --- a pool ----------------------------------------------------------------------------------------

def _fingerprint(pol, desks, sources):
    keys = ('net_isolation', 'net_peers', 'net_allow_in', 'net_egress', 'net_allow_out')
    return repr(([pol.get(k) for k in keys], sorted((d['id'], d.get('vmid')) for d in desks), sorted(sources)))


def sync_pool(pool, force=False, confirm=True):
    """Bring the pool's desktops in line with its net_* policy. Returns the pool's state."""
    pol = policy.effective(pool.get('settings'), pool.get('type'))
    st = _state.setdefault(pool['id'], {'fp': None, 'at': 0, 'problem': '', 'desktops': {}})
    mgr = cluster_managers.get(pool.get('cluster_id'))
    if not mgr or not getattr(mgr, 'is_connected', False):
        st['problem'] = 'cluster not connected'
        return st
    desks = [d for d in store.list_desktops(pool['id']) if d.get('vmid')]
    rows = netiso.applied_rows(pool_id=pool['id'])
    sources = netiso.gateway_sources(pool['cluster_id'])
    fp = _fingerprint(pol, desks, sources)
    if not force and st['fp'] == fp and time.time() - st['at'] < NETISO_EVERY:
        return st
    if not pol.get('net_isolation'):
        if rows and confirm and not ha.confirm_step(f"network isolation off for pool {pool['name']}"):
            return st
        for row in rows:
            try:
                _revert_desktop(mgr, row)
                netiso.forget(row['desktop_id'])
            except Exception as e:
                st['desktops'][row['desktop_id']] = {'error': str(e)[:200]}
        if rows:
            _drop_cluster_objects(mgr, pool['id'])
            log_audit('system', 'vlab.netiso.off', f"pool '{pool['name']}': firewall of {len(rows)} desktop(s) back as before", '')
        st.update(fp=fp, at=time.time(), problem='', desktops={})
        return st
    if not sources:
        st.update(problem='no gateway address for this cluster - nothing applied', at=time.time(), fp=None)
        return st
    if confirm and not ha.confirm_step(f"network isolation for pool {pool['name']}"):
        return st
    vms = core._vm_states(pool['cluster_id'])
    group, ipset = netiso.group_name(pool['id']), netiso.ipset_name(pool['id'])
    problem = ''
    try:
        _ensure_ipset(mgr, netiso.GW_IPSET, {c: 'MOAVI gateway' for c in sources}, 'MOAVI gateway (vlab-netiso)')
        # the pool's addresses: running desktops as the guest agent says; a stopped one keeps its last
        addrs, running = {}, set()
        for d in desks:
            vm = vms.get(int(d['vmid'])) or {}
            if vm.get('status') == 'running' and d.get('vm_type', 'qemu') == 'qemu':
                running.add(d['id'])
                for ip in netiso.ipv4s(mgr._fetch_qemu_ips(vm.get('node') or d['node'], int(d['vmid']))):
                    addrs[ip] = d['id']
        ids = {d['id'] for d in desks}
        _ensure_ipset(mgr, ipset, addrs, f"MOAVI Desk pool {pool['name']} (vlab-netiso)"[:100],
                      keep=lambda e: e.get('comment') in ids and e.get('comment') not in running)
        _ensure_group(mgr, group, netiso.group_rules(pool['id'], pol), f"MOAVI Desk pool {pool['name']} (vlab-netiso)")
    except Exception as e:
        st.update(problem=f'cluster firewall objects: {str(e)[:200]}', at=time.time(), fp=None)
        return st
    seen = {}
    for d in desks:
        vm = vms.get(int(d['vmid'])) or {}
        node = vm.get('node') or d['node']
        info = {'name': d['name'], 'vmid': d['vmid'], 'ips': sorted(ip for ip, i in addrs.items() if i == d['id'])}
        try:
            changed, enabled_now = _apply_desktop(mgr, d, node, pol, group)
            netiso.mark_applied(dict(d, node=node), enabled_now and 'options' in changed)
            info.update(applied=True, changed=changed)
        except Exception as e:
            info.update(applied=False, error=str(e)[:200])
            problem = problem or f"{d['name']}: {str(e)[:200]}"
        seen[d['id']] = info
    for row in rows:                     # desktops that left the pool
        if row['desktop_id'] not in seen:
            try:
                _revert_desktop(mgr, row)
            except Exception as e:
                logging.info(f"[VLAB] netiso: desktop {row['desktop_id']} left pool {pool['name']}: {str(e)[:200]}")
            netiso.forget(row['desktop_id'])
    changed = [i['name'] for i in seen.values() if i.get('changed')]
    if changed:
        log_audit('system', 'vlab.netiso.apply', f"pool '{pool['name']}': isolation applied to {', '.join(changed)[:400]}", '')
    st.update(fp=None if problem else fp, at=time.time(), problem=problem, desktops=seen)
    return st


def netiso_tick():
    """The minute loop: pools with isolation on, and pools that still have desktops applied."""
    with_rows = {r['pool_id'] for r in netiso.applied_rows()}
    for pool in store.list_pools():
        pol = policy.effective(pool.get('settings'), pool.get('type'))
        if not pol.get('net_isolation') and pool['id'] not in with_rows:
            continue
        try:
            sync_pool(pool)
        except Exception as e:
            logging.warning(f"[VLAB] netiso: pool {pool.get('name')}: {str(e)[:200]}")
    pools = {p['id'] for p in store.list_pools()}
    for row in netiso.applied_rows():    # a pool that was deleted
        if row['pool_id'] not in pools:
            mgr = cluster_managers.get(row['cluster_id'])
            if mgr and getattr(mgr, 'is_connected', False) and ha.confirm_step('network isolation of a deleted pool'):
                try:
                    _revert_desktop(mgr, row)
                except Exception:
                    pass
                netiso.forget(row['desktop_id'])


def kick(pool_id):
    """The pool's policy changed: the next tick syncs it at once."""
    if pool_id in _state:
        _state[pool_id]['fp'] = None


# --- routes ----------------------------------------------------------------------------------------

def _gateway_hosts():
    hosts = []
    try:
        from pegaprox.vlab import rdpgw
        hosts.append(rdpgw.config().get('host', '').split(':')[0])
    except Exception:
        pass
    try:
        from pegaprox.vlab import warpgate
        hosts.append(warpgate._host_of(warpgate.config().get('base_url') or ''))
    except Exception:
        pass
    return hosts


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netiso', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_cluster_netiso(cluster_id):
    mgr = cluster_managers.get(cluster_id)
    fw = cluster_firewall(mgr) if mgr and getattr(mgr, 'is_connected', False) else None
    return jsonify({'gateway_sources': netiso.gateway_sources(cluster_id),
                    'suggested': netiso.suggested_sources(_gateway_hosts()),
                    'cluster_firewall': fw})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netiso', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def set_cluster_netiso(cluster_id):
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'unknown cluster'}), 404
    data = request.get_json(silent=True) or {}
    sources, err = netiso.clean_sources(data.get('gateway_sources'))
    if err:
        return jsonify({'error': err}), 400
    user = request.session.get('user', '') if hasattr(request, 'session') else ''
    netiso.set_gateway_sources(cluster_id, sources, user)
    log_audit(user, 'vlab.netiso.gateway', f"cluster {cluster_id}: gateway addresses {', '.join(sources) or '(none)'}",
              get_client_ip())
    return jsonify({'gateway_sources': sources})


def _pool(pool_id):
    pool = store.get_pool(pool_id)
    return pool, (None if pool else (jsonify({'error': 'pool not found'}), 404))


def _answer(pool, st):
    pol = policy.effective(pool.get('settings'), pool.get('type'))
    rows = {r['desktop_id']: r for r in netiso.applied_rows(pool_id=pool['id'])}
    desks = []
    for d in store.list_desktops(pool['id']):
        info = dict((st or {}).get('desktops', {}).get(d['id']) or {})
        desks.append({'id': d['id'], 'name': d['name'], 'vmid': d.get('vmid'),
                      'applied': d['id'] in rows and info.get('applied', True),
                      'at': rows[d['id']]['at'] if d['id'] in rows else None,
                      'ips': info.get('ips') or [], 'error': info.get('error') or ''})
    return {'enabled': bool(pol.get('net_isolation')), 'group': netiso.group_name(pool['id']),
            'ipset': netiso.ipset_name(pool['id']), 'gateway_sources': netiso.gateway_sources(pool['cluster_id']),
            'problem': (st or {}).get('problem') or '', 'checked_at': (st or {}).get('at') or None, 'desktops': desks}


@bp.route('/api/vlab/admin/pools/<pool_id>/netiso', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_pool_netiso(pool_id):
    pool, err = _pool(pool_id)
    if err:
        return err
    return jsonify(_answer(pool, _state.get(pool['id'])))


@bp.route('/api/vlab/admin/pools/<pool_id>/netiso/apply', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def apply_pool_netiso(pool_id):
    pool, err = _pool(pool_id)
    if err:
        return err
    st = sync_pool(pool, force=True, confirm=False)
    log_audit(request.session.get('user', '') if hasattr(request, 'session') else '', 'vlab.netiso.apply_now',
              f"pool '{pool['name']}'", get_client_ip())
    return jsonify(_answer(pool, st))
