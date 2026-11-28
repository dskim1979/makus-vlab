# -*- coding: utf-8 -*-
"""
네트워크 분리 2단계 (MAKUS): segments (Proxmox SDN VNet + subnet in the PVE IPAM) per cluster,
and pools whose desktops are moved onto one (pool policy net_segment). What goes where:
pegaprox/vlab/netseg.py.

  GET    /api/vlab/admin/clusters/<cid>/netseg                 zone, segments (pools using them,
                                                               desktops on them), SDN state      vlab.pool.view
  PUT    /api/vlab/admin/clusters/<cid>/netseg/zone            {zone, type, bridge, peers, mtu,
                                                               existing}                         vlab.pool.manage
  POST   /api/vlab/admin/clusters/<cid>/netseg/segments        a segment                         vlab.pool.manage
  PUT    /api/vlab/admin/clusters/<cid>/netseg/segments/<sid>  change it                         vlab.pool.manage
  DELETE /api/vlab/admin/clusters/<cid>/netseg/segments/<sid>  only when no pool / desktop uses it vlab.pool.manage
  POST   /api/vlab/admin/clusters/<cid>/netseg/sdn             write the zone, VNets, subnets to
                                                               Proxmox SDN and apply them          vlab.pool.manage
  GET    /api/vlab/admin/clusters/<cid>/netseg/ipam            per segment: addresses in use (PVE
                                                               IPAM, guest agent), free, problems  vlab.pool.view
  POST   /api/vlab/admin/clusters/<cid>/netseg/segments/<sid>/ips     reserve {ip, mac, vmid}     vlab.pool.manage
  DELETE /api/vlab/admin/clusters/<cid>/netseg/segments/<sid>/ips     {ip, mac}                   vlab.pool.manage
  GET    /api/vlab/admin/pools/<pid>/netseg                    each desktop on the segment or not
  POST   /api/vlab/admin/pools/<pid>/netseg/apply              {restart}: move now; restart = the
                                                               running ones too, with a reboot     vlab.pool.manage

The SDN apply (PUT /cluster/sdn) reloads the network of every node, so it is only ever done
from the button, never by the minute loop, and refused while Proxmox holds SDN changes that are
not MOAVI's (they would go live with it). The minute loop (netseg_tick) only moves desktops:
a stopped desktop of a pool with a segment goes onto its VNet, one whose pool left the segment
(or that left the pool) goes back to its old bridge - running ones wait until they are off.
"""

import ipaddress
import logging
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.api.vlab_netiso import _data, _fw, _ok, _vm_path
from pegaprox.core import ha
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import log_audit, get_client_ip
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import netseg, policy, store

bp = Blueprint('vlab_netseg', __name__)

_state = {}                 # pool id -> {'fp', 'at', 'problem', 'desktops': {desktop id: {...}}}
_OURS = re.compile(r'^mv[0-9a-f]{6}$')


def _user():
    return request.session.get('user', '') if hasattr(request, 'session') else ''


def _mgr(cluster_id):
    # no is_connected gate: an idle manager reads False until its next call (a call that fails
    # raises and is reported where it is made)
    return cluster_managers.get(cluster_id)


# --- Proxmox SDN -----------------------------------------------------------------------------------

def _list(mgr, path):
    r = mgr._api_get(_fw(mgr, path), timeout=10)
    if r is None or r.status_code != 200:
        raise RuntimeError(f"{path}: HTTP {getattr(r, 'status_code', None)} {(getattr(r, 'text', '') or '')[:160]}")
    return _data(r) or []


def sdn_state(mgr, cluster_id):
    """{'available', 'zones': [{zone, type}], 'vnets': {vnet: {...}}, 'pending_ours', 'pending_other'}."""
    try:
        zones = _list(mgr, '/cluster/sdn/zones?pending=1')
        vnets = _list(mgr, '/cluster/sdn/vnets?pending=1')
    except Exception as e:
        return {'available': False, 'problem': str(e)[:200], 'zones': [], 'vnets': {}, 'pending_ours': [], 'pending_other': []}
    z = netseg.zone(cluster_id)
    ours_zone = z['zone'] if z and not z['existing'] else None
    mine = {s['vnet'] for s in netseg.segments(cluster_id)}
    pend_ours, pend_other = [], []
    for o in zones:
        if o.get('state'):
            (pend_ours if o.get('zone') == ours_zone else pend_other).append(f"zone {o.get('zone')} ({o['state']})")
    for o in vnets:
        if o.get('state'):
            (pend_ours if o.get('vnet') in mine or _OURS.match(str(o.get('vnet') or '')) else pend_other).append(
                f"vnet {o.get('vnet')} ({o['state']})")
    return {'available': True, 'problem': '',
            'zones': [{'zone': o.get('zone'), 'type': o.get('type'), 'pending': o.get('state') or ''} for o in zones],
            'vnets': {o.get('vnet'): o for o in vnets}, 'pending_ours': pend_ours, 'pending_other': pend_other}


def _subnet_range(v):
    """dhcp-range as Proxmox lists it (strings or objects) -> (start, end)."""
    for x in v or []:
        if isinstance(x, dict):
            return x.get('start-address') or '', x.get('end-address') or ''
        kv = dict(p.split('=', 1) for p in str(x).split(',') if '=' in p)
        return kv.get('start-address', ''), kv.get('end-address', '')
    return '', ''


def push_sdn(mgr, cluster_id, by=''):
    """The zone, each segment's VNet and subnet written to Proxmox SDN; VNets MOAVI made that have
    no segment any more removed; then applied (PUT /cluster/sdn). Returns {changed, applied, problem}."""
    z = netseg.zone(cluster_id)
    if not z:
        return {'changed': [], 'applied': False, 'problem': 'no zone set for this cluster'}
    st = sdn_state(mgr, cluster_id)
    if not st['available']:
        return {'changed': [], 'applied': False, 'problem': f"Proxmox SDN not available: {st['problem']}"}
    if st['pending_other']:
        return {'changed': [], 'applied': False,
                'problem': 'Proxmox has SDN changes that are not MOAVI\'s waiting to be applied - apply or revert them in '
                           f"Proxmox first: {', '.join(st['pending_other'])[:300]}"}
    changed = []
    zones = {o['zone']: o for o in st['zones']}
    if z['existing']:
        if z['zone'] not in zones:
            return {'changed': [], 'applied': False, 'problem': f"zone {z['zone']} is not in Proxmox SDN"}
    elif z['zone'] not in zones:
        _ok(mgr._api_post(_fw(mgr, '/cluster/sdn/zones'), data=netseg.zone_body(z), timeout=15), f"zone {z['zone']}")
        changed.append(f"zone {z['zone']}")
    segs = netseg.segments(cluster_id)
    want = {s['vnet']: s for s in segs}
    for vnet, s in want.items():
        body = netseg.vnet_body(s, z['zone'])
        have = st['vnets'].get(vnet)
        if not have:
            _ok(mgr._api_post(_fw(mgr, '/cluster/sdn/vnets'), data=body, timeout=15), f'vnet {vnet}')
            changed.append(f'vnet {vnet}')
        elif str(have.get('tag') or '') != str(body.get('tag') or '') or (have.get('alias') or '') != body['alias']:
            upd = {k: v for k, v in body.items() if k not in ('vnet', 'zone')}
            _ok(mgr._api_put(_fw(mgr, f'/cluster/sdn/vnets/{vnet}'), data=upd, timeout=15), f'vnet {vnet}')
            changed.append(f'vnet {vnet} (changed)')
        subs = _data(mgr._api_get(_fw(mgr, f'/cluster/sdn/vnets/{vnet}/subnets'), timeout=10)) or []
        sid = netseg.subnet_id(z['zone'], s['subnet'])
        sb = netseg.subnet_body(s)
        for sub in subs:                  # a subnet of another CIDR: the segment's network was changed
            if sub.get('subnet') != sid and (sub.get('cidr') or '') != s['subnet']:
                _ok(mgr._api_delete(_fw(mgr, f"/cluster/sdn/vnets/{vnet}/subnets/{sub.get('subnet')}"), timeout=15),
                    f"subnet {sub.get('subnet')}")
                changed.append(f"subnet {sub.get('subnet')} (removed)")
        cur = next((x for x in subs if x.get('subnet') == sid or (x.get('cidr') or '') == s['subnet']), None)
        if not cur:
            _ok(mgr._api_post(_fw(mgr, f'/cluster/sdn/vnets/{vnet}/subnets'), data=sb, timeout=15), f'subnet {sid}')
            changed.append(f'subnet {sid}')
        else:
            rng = _subnet_range(cur.get('dhcp-range'))
            if ((cur.get('gateway') or '') != sb['gateway'] or int(cur.get('snat') or 0) != sb['snat']
                    or rng != (s['dhcp_start'], s['dhcp_end'])):
                upd = {k: v for k, v in sb.items() if k not in ('subnet', 'type')}
                if not s['dhcp_start'] and rng[0]:
                    upd['delete'] = 'dhcp-range'
                _ok(mgr._api_put(_fw(mgr, f"/cluster/sdn/vnets/{vnet}/subnets/{cur.get('subnet')}"), data=upd, timeout=15),
                    f'subnet {sid}')
                changed.append(f'subnet {sid} (changed)')
    used = {r['vnet'] for r in netseg.moved_rows(cluster_id=cluster_id)}
    for vnet, o in st['vnets'].items():  # VNets MOAVI made for segments since deleted
        if _OURS.match(str(vnet or '')) and o.get('zone') == z['zone'] and vnet not in want and vnet not in used \
                and o.get('state') != 'deleted':
            for sub in _data(mgr._api_get(_fw(mgr, f'/cluster/sdn/vnets/{vnet}/subnets'), timeout=10)) or []:
                _ok(mgr._api_delete(_fw(mgr, f"/cluster/sdn/vnets/{vnet}/subnets/{sub.get('subnet')}"), timeout=15),
                    f"subnet {sub.get('subnet')}")
            _ok(mgr._api_delete(_fw(mgr, f'/cluster/sdn/vnets/{vnet}'), timeout=15), f'vnet {vnet}')
            changed.append(f'vnet {vnet} (removed)')
    if not changed and not st['pending_ours']:
        return {'changed': [], 'applied': False, 'problem': ''}
    _ok(mgr._api_put(_fw(mgr, '/cluster/sdn'), data={}, timeout=60), 'SDN apply')
    log_audit(by or 'system', 'vlab.netseg.sdn', f"cluster {cluster_id}: {', '.join(changed) or 'pending changes'} applied", '')
    nodes = node_zone_status(mgr, z['zone'], wait=APPLY_WAIT)
    return {'changed': changed, 'applied': True, 'problem': '', 'nodes': nodes, 'node_problem': node_problem(nodes)}


APPLY_WAIT = 30             # seconds the nodes get to build the zone after an SDN apply


def node_zone_status(mgr, zone_name, wait=0):
    """{node: 'available' | 'error' | 'pending' | 'missing' | 'unknown'} of the zone on each node
    (GET /nodes/<n>/sdn/zones). The cluster config can be applied while a node never built the
    zone - e.g. its /etc/network/interfaces lacks 'source /etc/network/interfaces.d/sdn' - and a
    VM put on that VNet would not start there."""
    try:
        nodes = [n.get('node') for n in _list(mgr, '/nodes') if n.get('node')]
    except Exception:
        return {}
    out, until = {}, time.time() + wait
    while True:
        for n in nodes:
            try:
                zs = _list(mgr, f'/nodes/{n}/sdn/zones')
                z = next((x for x in zs if x.get('zone') == zone_name), None)
                out[n] = (z.get('status') or 'unknown') if z else 'missing'
            except Exception:
                out[n] = 'unknown'
        if not any(v in ('pending', 'missing') for v in out.values()) or time.time() >= until:
            return out
        time.sleep(3)


def node_problem(nodes):
    bad = sorted(n for n, v in nodes.items() if v != 'available')
    if not bad:
        return ''
    return (f"the zone is not built on node(s) {', '.join(bad)} - check that each node's /etc/network/interfaces "
            "ends with 'source /etc/network/interfaces.d/sdn' (and has dnsmasq for a simple zone), then SDN apply again")


def _vnet_live(st, vnet):
    o = st['vnets'].get(vnet)
    return bool(o) and not o.get('state')


# --- desktops --------------------------------------------------------------------------------------

def _nics(cfg):
    keys = sorted((k for k in cfg if re.match(r'^net\d+$', k)), key=lambda k: int(k[3:]))
    return [(k, cfg[k]) for k in keys]


def _first_nic(cfg):
    n = _nics(cfg)
    return n[0] if n else (None, None)


def _pick_nic(cfg, from_bridge, vnet, recorded=None):
    """The NIC that goes onto the segment: the one moved before, else one already on the VNet,
    else the one on `from_bridge` (a VM with a management NIC and a desktop NIC moves only the
    desktop one), else the first. (None, None, reason) when the VM has no such NIC."""
    nics = _nics(cfg)
    if not nics:
        return None, None, 'no network card'
    by = dict(nics)
    if recorded and recorded in by:
        return recorded, by[recorded], ''
    for k, v in nics:
        if netseg.nic_parts(v)[0].get('bridge') == vnet:
            return k, v, ''
    if from_bridge:
        for k, v in nics:
            if netseg.nic_parts(v)[0].get('bridge') == from_bridge:
                return k, v, ''
        return None, None, f'no network card on bridge {from_bridge}'
    return nics[0][0], nics[0][1], ''


def _in_window(spec, now=None):
    """'HH:MM-HH:MM' (local time, may run past midnight)."""
    if not spec:
        return False
    a, b = spec.split('-')
    t = (now or datetime.now()).strftime('%H:%M')
    return a <= t < b if a <= b else (t >= a or t < b)


def _may_restart(pol, restart, busy):
    """Whether a running desktop may be restarted onto (or off) the segment now.
    restart: True = the 재시작해서 적용 'all' button, 'idle' = its idle-only form, False = the loop."""
    if restart is True:
        return True
    if busy:
        return False
    if restart == 'idle':
        return True
    mode = pol.get('net_segment_move') or 'off'
    return mode == 'idle' or (mode == 'window' and _in_window(pol.get('net_segment_window') or ''))


PROBE_PORT = 3389


def probe(ip, port=PROBE_PORT, timeout=1.5):
    """From the MOAVI server (the engine's host - the gateway's view of the network):
    'open' (connected), 'reachable' (refused: the host answered), 'unreachable' (no route /
    host unreachable), 'timeout' (filtered or down)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((str(ip), int(port)))
        return 'open'
    except ConnectionRefusedError:
        return 'reachable'
    except socket.timeout:
        return 'timeout'
    except OSError as e:
        return 'unreachable' if getattr(e, 'errno', None) in (101, 113, 10051, 10065) else 'timeout'
    finally:
        s.close()


def _put_nic(mgr, node, desk_like, nic, value):
    base = _vm_path(node, desk_like.get('vm_type'), desk_like['vmid'])
    _ok(mgr._api_put(_fw(mgr, f'{base}/config'), data={nic: value}, timeout=20), 'NIC bridge')


def _reboot(mgr, node, desk_like):
    base = _vm_path(node, desk_like.get('vm_type'), desk_like['vmid'])
    _ok(mgr._api_post(_fw(mgr, f'{base}/status/reboot'), data={}, timeout=20), 'reboot')


def _restore(mgr, row, node, running, restart):
    """Back to the old bridge. Returns 'restored', 'waiting' (running) or 'gone'."""
    base = _vm_path(node, 'qemu', row['vmid'])
    cfg = _data(mgr._api_get(_fw(mgr, f'{base}/config'), timeout=8))
    if cfg is None:
        return 'gone'
    value = cfg.get(row['nic'])
    if not value:
        return 'gone'
    kv, _ = netseg.nic_parts(value)
    if kv.get('bridge') != row['vnet']:
        return 'restored'                # someone moved it already: leave it
    if running and not restart:
        return 'waiting'
    _put_nic(mgr, node, row, row['nic'], netseg.nic_with(value, row['orig_bridge'], row['orig_tag']))
    if running:
        _reboot(mgr, node, row)
    return 'restored'


def _seg_ips(mgr, node, desk, seg):
    from pegaprox.vlab import netiso
    try:
        ips = netiso.ipv4s(mgr._fetch_qemu_ips(node, int(desk['vmid'])) or [])
    except Exception:
        return []
    net = ipaddress.ip_network(seg['subnet'])
    return [ip for ip in ips if ipaddress.ip_address(ip) in net]


def _old_address(mgr, node, desk, seg):
    """The guest's IPv4 addresses when none is in the segment's subnet (a fixed address in the
    guest, or a lease not renewed yet); [] when it has one of the subnet or reports nothing."""
    from pegaprox.vlab import netiso
    try:
        ips = netiso.ipv4s(mgr._fetch_qemu_ips(node, int(desk['vmid'])) or [])
    except Exception:
        return []
    net = ipaddress.ip_network(seg['subnet'])
    return [] if not ips or any(ipaddress.ip_address(ip) in net for ip in ips) else ips


def _fingerprint(seg, desks, vms, rows):
    return repr((seg and (seg['id'], seg['vnet']), sorted((d['id'], d.get('vmid'), (vms.get(int(d['vmid'])) or {}).get('status'))
                                                          for d in desks),
                 sorted((r['desktop_id'], r['segment_id']) for r in rows)))


def sync_pool(pool, force=False, confirm=True, restart=False):
    """The pool's desktops onto its segment's VNet (or back). Returns the pool's state.
    restart: False (the loop: running desktops move by net_segment_move), 'idle' (restart the
    running ones nobody is connected to), True (restart all running ones)."""
    pol = policy.effective(pool.get('settings'), pool.get('type'))
    st = _state.setdefault(pool['id'], {'fp': None, 'at': 0, 'problem': '', 'desktops': {}})
    mgr = _mgr(pool.get('cluster_id'))
    if not mgr:
        st['problem'] = 'cluster not connected'
        return st
    seg_id = pol.get('net_segment') or ''
    seg = netseg.segment(seg_id) if seg_id else None
    desks = [d for d in store.list_desktops(pool['id']) if d.get('vmid')]
    rows = netseg.moved_rows(pool_id=pool['id'])
    vms = core._vm_states(pool['cluster_id'])
    fp = _fingerprint(seg, desks, vms, rows)
    if not force and not restart and st['fp'] == fp:
        return st
    if seg_id and (not seg or seg['cluster_id'] != pool['cluster_id']):
        st.update(problem=f"segment {seg_id} is not one of this cluster's", fp=None, at=time.time())
        return st
    if not rows and not seg:
        st.update(fp=fp, at=time.time(), problem='', desktops={})
        return st
    if confirm and not ha.confirm_step(f"network segment for pool {pool['name']}"):
        return st
    problem = ''
    seen = {}
    rows_by = {r['desktop_id']: r for r in rows}
    busy = store.open_session_desktops() if desks else set()
    from_bridge = pol.get('net_segment_from') or ''
    sdn = sdn_state(mgr, pool['cluster_id']) if seg else None
    live = bool(seg) and sdn['available'] and _vnet_live(sdn, seg['vnet'])
    node_ok = {}
    if seg and not live:
        problem = 'the segment is not applied in Proxmox SDN yet (네트워크 분리 > SDN 적용)'
    elif seg:
        z = netseg.zone(pool['cluster_id'])
        node_ok = node_zone_status(mgr, z['zone'] if z else '')
        # only the nodes this pool's desktops are on: another node without the zone is the
        # cluster page's warning, not this pool's problem
        mine = {(vms.get(int(d['vmid'])) or {}).get('node') or d['node'] for d in desks}
        problem = node_problem({n: s for n, s in node_ok.items() if n in mine})
        if z and z['type'] == 'simple' and len(mine) > 1:
            # a simple zone is a separate network on every node: one pool on two nodes would be
            # two networks with the same addresses
            problem = (f"segment '{seg['name']}' is in a single-node (simple) zone but the pool's desktops are on "
                       f"{', '.join(sorted(mine))} - use a VLAN or VXLAN zone, or keep the pool on one node")
            live = False
    for d in desks:
        vm = vms.get(int(d['vmid'])) or {}
        node = vm.get('node') or d['node']
        running = vm.get('status') == 'running'
        info = {'name': d['name'], 'vmid': d['vmid'], 'running': running}
        try:
            cfg = _data(mgr._api_get(_fw(mgr, f"{_vm_path(node, d.get('vm_type'), d['vmid'])}/config"), timeout=8)) or {}
            recorded = (rows_by.get(d['id']) or {}).get('nic')
            if seg:
                nic, value, why = _pick_nic(cfg, from_bridge, seg['vnet'], recorded)
            else:
                nic, value = (recorded, cfg.get(recorded)) if recorded and cfg.get(recorded) else _first_nic(cfg)
                why = '' if nic else 'no network card'
            kv, _ = netseg.nic_parts(value)
            info['bridge'] = kv.get('bridge') or ''
            info['nic'] = nic or ''
            busy_now = d['id'] in busy
            if not nic:
                info.update(state='error', error=why)
                problem = problem or f"{d['name']}: {why}"
            elif cfg.get('lock') and kv.get('bridge') != (seg or {}).get('vnet'):
                info['state'] = 'waiting_lock'     # a clone or backup still holds the VM: next minute
            elif seg:
                if kv.get('bridge') == seg['vnet']:
                    info['state'] = 'on'          # (put there by hand: no record, so nothing to put back later)
                    if running:                   # on the VNet - but does the guest use an address of it?
                        old_ips = _old_address(mgr, node, d, seg)
                        new_ips = [] if old_ips else _seg_ips(mgr, node, d, seg)
                        if new_ips:
                            info['ips'] = new_ips
                            info['reach'] = probe(new_ips[0])
                        if old_ips:
                            info['old_ips'] = old_ips
                            problem = problem or (f"{d['name']} is on the segment but still uses {', '.join(old_ips)} - its network "
                                                  f"card has a fixed address; set it to DHCP (or an address of {seg['subnet']})")
                elif not live or (node_ok and node_ok.get(node) != 'available'):
                    info['state'] = 'waiting_sdn'      # the VNet's bridge is not on that node: the VM would not start
                elif running and not _may_restart(pol, restart, busy_now):
                    info['state'] = 'waiting_busy' if busy_now else 'waiting'
                else:
                    old = rows_by.get(d['id'])
                    orig_bridge, orig_tag = (old['orig_bridge'], old['orig_tag']) if old else (kv.get('bridge') or '', kv.get('tag') or '')
                    _put_nic(mgr, node, d, nic, netseg.nic_with(value, seg['vnet']))
                    netseg.mark_moved(dict(d, node=node), seg['id'], nic, orig_bridge, orig_tag, seg['vnet'])
                    if running:
                        _reboot(mgr, node, d)
                    info.update(state='on', bridge=seg['vnet'], changed=True)
            elif d['id'] in rows_by:
                res = _restore(mgr, dict(rows_by[d['id']], nic=nic), node, running, running and _may_restart(pol, restart, busy_now))
                if res in ('restored', 'gone'):
                    netseg.forget(d['id'])
                    info.update(state='off', changed=res == 'restored')
                else:
                    info['state'] = 'waiting_back'
            else:
                info['state'] = 'off'
        except Exception as e:
            info.update(state='error', error=str(e)[:200])
            problem = problem or f"{d['name']}: {str(e)[:200]}"
        seen[d['id']] = info
    for row in rows:                       # desktops that left the pool: back to their bridge when off
        if row['desktop_id'] in seen:
            continue
        vm = vms.get(int(row['vmid'])) or {}
        try:
            res = _restore(mgr, row, vm.get('node') or row['node'], vm.get('status') == 'running', False)
            if res != 'waiting':
                netseg.forget(row['desktop_id'])
        except Exception as e:
            logging.info(f"[VLAB] netseg: desktop {row['desktop_id']} left pool {pool['name']}: {str(e)[:200]}")
    moved_now = [i['name'] for i in seen.values() if i.get('changed')]
    if moved_now:
        log_audit('system', 'vlab.netseg.move',
                  f"pool '{pool['name']}': {', '.join(moved_now)[:300]} " + (f"onto segment '{seg['name']}'" if seg else 'back to their bridge'), '')
    # a lock, a user or the move window can clear without the fingerprint changing: look again next minute
    again = any(i.get('state') in ('waiting_lock', 'waiting_busy', 'waiting_back') for i in seen.values()) or (
        (pol.get('net_segment_move') or 'off') != 'off' and any(i.get('state') == 'waiting' for i in seen.values()))
    st.update(fp=None if problem or again else fp, at=time.time(), problem=problem, desktops=seen)
    return st


def netseg_tick():
    with_rows = {r['pool_id'] for r in netseg.moved_rows()}
    pools = store.list_pools()
    for pool in pools:
        pol = policy.effective(pool.get('settings'), pool.get('type'))
        if not pol.get('net_segment') and pool['id'] not in with_rows:
            continue
        try:
            sync_pool(pool)
        except Exception as e:
            logging.warning(f"[VLAB] netseg: pool {pool.get('name')}: {str(e)[:200]}")
    ids = {p['id'] for p in pools}
    for row in netseg.moved_rows():        # the pool was deleted
        if row['pool_id'] in ids:
            continue
        mgr = _mgr(row['cluster_id'])
        if not mgr or not ha.confirm_step('network segment of a deleted pool'):
            continue
        vm = core._vm_states(row['cluster_id']).get(int(row['vmid'])) or {}
        try:
            if _restore(mgr, row, vm.get('node') or row['node'], vm.get('status') == 'running', False) != 'waiting':
                netseg.forget(row['desktop_id'])
        except Exception:
            pass


def desktop_added(pool):
    try:
        if policy.effective(pool.get('settings'), pool.get('type')).get('net_segment'):
            sync_pool(store.get_pool(pool['id']) or pool, force=True, confirm=False)
    except Exception as e:
        logging.warning(f"[VLAB] netseg: new desktop of pool {pool.get('name')}: {str(e)[:200]}")


def release_desktop(desktop_id):
    """A desktop left MOAVI: back to its old bridge if it is off (otherwise the minute loop does
    it once it is)."""
    row = netseg.moved(desktop_id)
    if not row:
        return
    mgr = _mgr(row['cluster_id'])
    if not mgr:
        return
    vm = core._vm_states(row['cluster_id']).get(int(row['vmid'])) or {}
    if _restore(mgr, row, vm.get('node') or row['node'], vm.get('status') == 'running', False) != 'waiting':
        netseg.forget(desktop_id)
        log_audit('system', 'vlab.netseg.release', f"VM {row['vmid']}: back on bridge {row['orig_bridge']} (no longer a desktop)", '')


def before_start(desk):
    """Called before MOAVI starts a stopped desktop (start on connect, LAB prepare): one of a
    pool with a segment goes onto it first, so it never comes up on the wrong network.
    Returns '' (start it) or why not (the caller answers 'try again')."""
    try:
        pool = store.get_pool(desk.get('pool_id') or '')
        if not pool:
            return ''
        seg_id = policy.effective(pool.get('settings'), pool.get('type')).get('net_segment')
        if not seg_id:
            return ''
        st = sync_pool(pool, force=True, confirm=False)
        info = (st.get('desktops') or {}).get(desk['id']) or {}
        if info.get('state') == 'on':
            return ''
        return {'waiting_lock': 'the desktop is still being prepared (locked)',
                'waiting_sdn': "the desktop's network is not ready on its node",
                'error': info.get('error') or 'its network card could not be moved'}.get(info.get('state'), 'its network is being moved')
    except Exception as e:
        logging.warning(f"[VLAB] netseg before start of {desk.get('id')}: {str(e)[:200]}")
        return ''


def migrate_block(desk, target):
    """Why a desktop on a segment may not move to `target` ('' when it may): its zone is not
    built there, or the zone is a single-node one (a separate network on every node)."""
    row = netseg.moved(desk['id'])
    if not row:
        return ''
    z = netseg.zone(row['cluster_id'])
    if not z:
        return ''
    if z['type'] == 'simple':
        return f"the desktop is on segment VNet {row['vnet']} of a single-node zone - it cannot leave its node"
    mgr = _mgr(row['cluster_id'])
    status = node_zone_status(mgr, z['zone']).get(target) if mgr else None
    if status != 'available':
        return f"node {target} does not have the desktop's network (zone {z['zone']}: {status or 'unknown'})"
    return ''


def kick(pool_id):
    if pool_id in _state:
        _state[pool_id]['fp'] = None


# --- IPAM ------------------------------------------------------------------------------------------

def _ipam_entries(mgr):
    try:
        rows = _list(mgr, '/cluster/sdn/ipams/pve/status')
    except Exception:
        return None
    out = []
    for r in rows if isinstance(rows, list) else []:
        if isinstance(r, dict) and r.get('ip'):
            out.append({'ip': str(r['ip']).split('/')[0], 'mac': str(r.get('mac') or '').upper(), 'vmid': r.get('vmid'),
                        'hostname': r.get('hostname') or '', 'vnet': r.get('vnet') or '', 'gateway': bool(r.get('gateway'))})
    return out


def ipam_view(mgr, cluster_id):
    """Per segment: the addresses in use, from the PVE IPAM and the desktops' guest agents, with
    problems (the same address twice, a desktop on the segment with an address outside it)."""
    pve = _ipam_entries(mgr)
    vms = core._vm_states(cluster_id)
    desks = {d['id']: d for d in store.list_desktops()}
    out = []
    for s in netseg.segments(cluster_id):
        net = ipaddress.ip_network(s['subnet'])
        entries = {}

        def add(ip, **kw):
            e = entries.setdefault(ip, {'ip': ip, 'mac': '', 'vmid': None, 'name': '', 'desktop_id': '', 'sources': [], 'problem': ''})
            for k, v in kw.items():
                if k == 'source':
                    if v not in e['sources']:
                        e['sources'].append(v)
                elif v and not e.get(k):
                    e[k] = v
                elif v and e.get(k) and k in ('mac', 'vmid') and str(e[k]) != str(v):
                    e['problem'] = 'duplicate'
        add(s['gateway'], name='gateway', source='segment')
        for r in pve or []:
            try:
                inside = ipaddress.ip_address(r['ip']) in net
            except ValueError:
                continue
            if r['vnet'] == s['vnet'] or inside:
                add(r['ip'], mac=r['mac'], vmid=r['vmid'], name=r['hostname'] or ('gateway' if r['gateway'] else ''), source='ipam')
        outside = []
        for row in netseg.moved_rows(segment_id=s['id']):
            d = desks.get(row['desktop_id']) or {}
            vm = vms.get(int(row['vmid'])) or {}
            if vm.get('status') != 'running':
                continue
            try:
                ips = mgr._fetch_qemu_ips(vm.get('node') or row['node'], int(row['vmid'])) or []
            except Exception:
                ips = []
            for ip in ips:
                try:
                    a = ipaddress.ip_address(str(ip))
                except ValueError:
                    continue
                if a.version != 4 or a.is_loopback or a.is_link_local:
                    continue
                if a in net:
                    add(str(a), vmid=row['vmid'], name=d.get('name') or '', desktop_id=row['desktop_id'], source='agent')
                else:
                    outside.append({'ip': str(a), 'vmid': row['vmid'], 'name': d.get('name') or '', 'desktop_id': row['desktop_id']})
        items = sorted(entries.values(), key=lambda e: ipaddress.ip_address(e['ip']))
        out.append({'segment_id': s['id'], 'vnet': s['vnet'], 'subnet': s['subnet'], 'usable': netseg.usable(s['subnet']),
                    'used': len(items), 'free': max(netseg.usable(s['subnet']) - len(items), 0),
                    'dhcp': {'start': s['dhcp_start'], 'end': s['dhcp_end']} if s['dhcp_start'] else None,
                    'entries': items, 'outside': outside,
                    'duplicates': sum(1 for e in items if e['problem'] == 'duplicate')})
    return {'ipam': pve is not None, 'segments': out}


# --- routes ----------------------------------------------------------------------------------------

def _cluster(cid):
    if cid not in cluster_managers:
        return jsonify({'error': 'unknown cluster'}), 404
    return None


def _uses(cluster_id):
    """segment id -> {'pools': [names], 'desktops': n}"""
    out = {}
    for p in store.list_pools():
        if p.get('cluster_id') != cluster_id:
            continue
        sid = policy.effective(p.get('settings'), p.get('type')).get('net_segment')
        if sid:
            out.setdefault(sid, {'pools': [], 'desktops': 0})['pools'].append(p['name'])
    for r in netseg.moved_rows(cluster_id=cluster_id):
        out.setdefault(r['segment_id'], {'pools': [], 'desktops': 0})['desktops'] += 1
    return out


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netseg', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_cluster_netseg(cluster_id):
    err = _cluster(cluster_id)
    if err:
        return err
    return jsonify(cluster_view(cluster_id))


def cluster_view(cluster_id):
    """The zone, the segments (with their pools and gateway reach) and the SDN state of a cluster
    (also the 네트워크 구성도, pegaprox/api/vlab_netmap.py)."""
    mgr = _mgr(cluster_id)
    st = sdn_state(mgr, cluster_id) if mgr else {'available': False, 'problem': 'cluster not connected', 'zones': [],
                                                  'vnets': {}, 'pending_ours': [], 'pending_other': []}
    uses = _uses(cluster_id)
    segs = []
    gws = [s['gateway'] for s in netseg.segments(cluster_id)]
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(gws)))) as ex:
        reach = dict(zip(gws, ex.map(lambda ip: probe(ip, 22, 1.0), gws)))
    for s in netseg.segments(cluster_id):
        o = st['vnets'].get(s['vnet'])
        segs.append(dict(s, pools=uses.get(s['id'], {}).get('pools', []), desktops=uses.get(s['id'], {}).get('desktops', 0),
                         usable=netseg.usable(s['subnet']),
                         sdn='missing' if not o else (o.get('state') or 'applied'),
                         gateway_reach=reach.get(s['gateway'], 'timeout')))
    z = netseg.zone(cluster_id)
    nodes = (node_zone_status(mgr, z['zone']) if mgr and z and st['available'] and any(o['zone'] == z['zone'] for o in st['zones'])
             else {})
    return {'zone': z, 'segments': segs,
            'sdn': dict({k: st[k] for k in ('available', 'problem', 'zones', 'pending_ours', 'pending_other')},
                        nodes=nodes, node_problem=node_problem(nodes))}


def bridges(mgr):
    """{'nodes': [...], 'bridges': [{name, type, nodes, vlan_aware, addressed, comments}]}: the
    Linux / OVS bridges of every node (GET /nodes/<n>/network). A bridge with an address on a
    node is usually its management network - said, so a VM network is picked instead."""
    nodes, out = [], {}
    for n in [x.get('node') for x in _list(mgr, '/nodes') if x.get('node')]:
        try:
            nets = _list(mgr, f'/nodes/{n}/network')
        except Exception:
            continue                       # an unreadable node is left out, not counted as missing the bridge
        nodes.append(n)
        for i in nets:
            if i.get('type') not in ('bridge', 'OVSBridge'):
                continue
            b = out.setdefault(i['iface'], {'name': i['iface'], 'type': i.get('type'), 'nodes': [], 'vlan_aware': [],
                                            'addressed': [], 'comments': ''})
            b['nodes'].append(n)
            if int(i.get('bridge_vlan_aware') or 0):
                b['vlan_aware'].append(n)
            if i.get('address') or i.get('cidr'):
                b['addressed'].append(n)
            b['comments'] = b['comments'] or (i.get('comments') or '').strip()[:80]
    return {'nodes': nodes, 'bridges': sorted(out.values(), key=lambda b: b['name'])}


def _ssh_run(mgr, node, cmd):
    """One read-only command on a node over the cluster's SSH (as 템플릿 만들기 does)."""
    from pegaprox.utils.ssh import read_capped
    try:
        ip = mgr._get_node_ip(node) if hasattr(mgr, '_get_node_ip') else None
    except Exception:
        ip = None
    ssh = mgr._ssh_connect(ip or mgr.host)
    if not ssh:
        raise RuntimeError('SSH to the node failed')
    try:
        _i, out, _e = ssh.exec_command(cmd, get_pty=False, timeout=20)
        out.channel.recv_exit_status()
        return read_capped(out)
    finally:
        try:
            ssh.close()
        except Exception:
            pass


def readiness(mgr, cluster_id):
    """Per node, what a zone needs there (read only): the 'source /etc/network/interfaces.d/sdn'
    line, dnsmasq (simple zones' DHCP), IP forwarding (simple zones route), the zone's bridge
    (VLAN), the underlay MTU (VXLAN takes 50 bytes)."""
    z = netseg.zone(cluster_id)
    bridge = (z or {}).get('bridge') or ''
    if bridge and not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,15}', bridge):
        bridge = ''
    cmd = ("grep -qE '^[[:space:]]*source[[:space:]]+/etc/network/interfaces.d/(sdn|\\*)' /etc/network/interfaces "
           "&& echo SRC=1 || echo SRC=0; "
           "dpkg-query -W -f='${Status}' dnsmasq 2>/dev/null | grep -q 'ok installed' && echo DNSMASQ=1 || echo DNSMASQ=0; "
           "echo FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null); "
           "echo MTU=$(ip -o route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p' | xargs -r -I{} cat /sys/class/net/{}/mtu)")
    if bridge:
        cmd += f"; test -d /sys/class/net/{bridge} && echo BR=1 || echo BR=0"
    nodes = [n.get('node') for n in _list(mgr, '/nodes') if n.get('node')]
    zt = (z or {}).get('type') or ''

    def one(n):
        try:
            kv = dict(line.split('=', 1) for line in _ssh_run(mgr, n, cmd).splitlines() if '=' in line)
        except Exception as e:
            return n, [{'id': 'ssh', 'ok': False, 'detail': str(e)[:160]}]
        checks = [{'id': 'source', 'ok': kv.get('SRC') == '1',
                   'fix': "echo 'source /etc/network/interfaces.d/sdn' >> /etc/network/interfaces"}]
        if zt == 'simple':
            checks.append({'id': 'dnsmasq', 'ok': kv.get('DNSMASQ') == '1',
                           'fix': 'apt install -y dnsmasq && systemctl disable --now dnsmasq'})
            checks.append({'id': 'forward', 'ok': kv.get('FWD') == '1',
                           'fix': "sysctl -w net.ipv4.ip_forward=1 (and net.ipv4.ip_forward=1 in /etc/sysctl.d/)"})
        if zt == 'vlan' and bridge:
            checks.append({'id': 'bridge', 'ok': kv.get('BR') == '1', 'detail': bridge})
        if zt == 'vxlan':
            mtu = int(kv.get('MTU') or 0) if str(kv.get('MTU') or '').isdigit() else 0
            zm = int((z or {}).get('mtu') or 0)
            checks.append({'id': 'mtu', 'ok': bool(mtu) and (zm and zm <= mtu - 50 or mtu >= 1550),
                           'detail': f'underlay {mtu or "?"}, zone {zm or "default"}',
                           'fix': 'set the zone MTU to the underlay MTU - 50 (e.g. 1450), and the same inside the desktops'})
        return n, checks
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(nodes)))) as ex:
        res = dict(ex.map(one, nodes))
    return {'zone_type': zt, 'nodes': [{'node': n, 'checks': res.get(n, []), 'ok': all(c['ok'] for c in res.get(n, []))} for n in nodes]}


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netseg/bridges', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_bridges(cluster_id):
    err = _cluster(cluster_id)
    if err:
        return err
    mgr = _mgr(cluster_id)
    try:
        return jsonify(bridges(mgr))
    except Exception as e:
        return jsonify({'error': str(e)[:300]}), 502


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netseg/readiness', methods=['GET'])
@require_auth(perms=['vlab.pool.manage'])
def get_readiness(cluster_id):
    err = _cluster(cluster_id)
    if err:
        return err
    if not netseg.zone(cluster_id):
        return jsonify({'error': 'set the zone first'}), 409
    try:
        return jsonify(readiness(_mgr(cluster_id), cluster_id))
    except Exception as e:
        return jsonify({'error': str(e)[:300]}), 502


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netseg/zone', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_zone(cluster_id):
    """Forget the zone; one MOAVI made is taken out of Proxmox SDN too (and applied). Only
    without segments."""
    err = _cluster(cluster_id)
    if err:
        return err
    z = netseg.zone(cluster_id)
    if not z:
        return jsonify({'error': 'no zone set'}), 404
    if netseg.segments(cluster_id):
        return jsonify({'error': 'delete the segments first'}), 409
    removed = False
    if not z['existing']:
        mgr = _mgr(cluster_id)
        if not mgr:
            return jsonify({'error': 'cluster not connected'}), 409
        st = sdn_state(mgr, cluster_id)
        if st['pending_other']:
            return jsonify({'error': "Proxmox has SDN changes that are not MOAVI's waiting to be applied - apply or revert "
                                     f"them in Proxmox first: {', '.join(st['pending_other'])[:300]}"}), 409
        if any(o['zone'] == z['zone'] for o in st['zones']):
            if any(v.get('zone') == z['zone'] and v.get('state') != 'deleted' for v in st['vnets'].values()):
                return jsonify({'error': f"zone {z['zone']} still has VNets in Proxmox - SDN apply first"}), 409
            try:
                _ok(mgr._api_delete(_fw(mgr, f"/cluster/sdn/zones/{z['zone']}"), timeout=15), f"zone {z['zone']}")
                _ok(mgr._api_put(_fw(mgr, '/cluster/sdn'), data={}, timeout=60), 'SDN apply')
            except Exception as e:
                return jsonify({'error': str(e)[:300]}), 502
            removed = True
    netseg.delete_zone(cluster_id)
    log_audit(_user(), 'vlab.netseg.zone_delete',
              f"cluster {cluster_id}: zone {z['zone']}{' removed from Proxmox SDN' if removed else ''}", get_client_ip())
    return jsonify({'deleted': z['zone'], 'removed_from_sdn': removed})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netseg/zone', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def put_zone(cluster_id):
    err = _cluster(cluster_id)
    if err:
        return err
    z, e = netseg.clean_zone(request.get_json(silent=True) or {})
    if e:
        return jsonify({'error': e}), 400
    old = netseg.zone(cluster_id)
    if old and netseg.segments(cluster_id) and (old['zone'] != z['zone'] or old['type'] != z['type']):
        return jsonify({'error': 'the zone cannot change while it has segments - delete them first'}), 409
    if z['type'] == 'vlan' and not z['existing']:
        try:
            b = bridges(_mgr(cluster_id))
            have = next((x for x in b['bridges'] if x['name'] == z['bridge']), None)
            missing = sorted(set(b['nodes']) - set(have['nodes'] if have else []))
            if missing:
                return jsonify({'error': f"bridge {z['bridge']} is not on node(s) {', '.join(missing)}"}), 400
        except Exception as e:
            logging.info(f'[VLAB] netseg: bridges of {cluster_id} not read ({str(e)[:120]}) - zone saved unchecked')
    netseg.set_zone(cluster_id, z, _user())
    log_audit(_user(), 'vlab.netseg.zone', f"cluster {cluster_id}: zone {z['zone']} ({z['type']}{', existing' if z['existing'] else ''})",
              get_client_ip())
    return jsonify({'zone': netseg.zone(cluster_id)})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netseg/segments', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def add_segment(cluster_id):
    err = _cluster(cluster_id)
    if err:
        return err
    z = netseg.zone(cluster_id)
    if not z:
        return jsonify({'error': 'set the zone first'}), 409
    if len(netseg.segments(cluster_id)) >= netseg.SEGMENTS_MAX:
        return jsonify({'error': f'at most {netseg.SEGMENTS_MAX} segments'}), 409
    f, e = netseg.clean_segment(request.get_json(silent=True) or {}, cluster_id, z['type'])
    if e:
        return jsonify({'error': e}), 400
    s = netseg.add_segment(cluster_id, f, _user())
    log_audit(_user(), 'vlab.netseg.add', f"cluster {cluster_id}: segment '{s['name']}' {s['subnet']} tag {s['tag']}", get_client_ip())
    return jsonify(s), 201


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netseg/segments/<segment_id>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def put_segment(cluster_id, segment_id):
    s = netseg.segment(segment_id)
    if not s or s['cluster_id'] != cluster_id:
        return jsonify({'error': 'segment not found'}), 404
    z = netseg.zone(cluster_id)
    f, e = netseg.clean_segment(request.get_json(silent=True) or {}, cluster_id, z['type'] if z else 'vlan', segment_id)
    if e:
        return jsonify({'error': e}), 400
    s = netseg.update_segment(segment_id, f)
    log_audit(_user(), 'vlab.netseg.edit', f"cluster {cluster_id}: segment '{s['name']}' {s['subnet']} tag {s['tag']}", get_client_ip())
    return jsonify(s)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netseg/segments/<segment_id>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_segment(cluster_id, segment_id):
    s = netseg.segment(segment_id)
    if not s or s['cluster_id'] != cluster_id:
        return jsonify({'error': 'segment not found'}), 404
    u = _uses(cluster_id).get(segment_id)
    if u and (u['pools'] or u['desktops']):
        return jsonify({'error': f"in use: pools {', '.join(u['pools']) or '-'}, {u['desktops']} desktop(s) still on it"}), 409
    netseg.delete_segment(segment_id)
    log_audit(_user(), 'vlab.netseg.delete', f"cluster {cluster_id}: segment '{s['name']}' (VNet removed at the next SDN 적용)",
              get_client_ip())
    return jsonify({'deleted': segment_id})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netseg/sdn', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def apply_sdn(cluster_id):
    err = _cluster(cluster_id)
    if err:
        return err
    mgr = _mgr(cluster_id)
    if not mgr:
        return jsonify({'error': 'cluster not connected'}), 409
    try:
        res = push_sdn(mgr, cluster_id, _user())
    except Exception as e:
        return jsonify({'error': str(e)[:300]}), 502
    if res['problem']:
        return jsonify({'error': res['problem']}), 409
    if res.get('node_problem'):
        log_audit(_user(), 'vlab.netseg.sdn_nodes', f"cluster {cluster_id}: {res['node_problem']}", get_client_ip())
    for p in store.list_pools():           # pools waiting for their VNet move on the next tick
        if p.get('cluster_id') == cluster_id:
            kick(p['id'])
    return jsonify(res)


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netseg/ipam', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_ipam(cluster_id):
    err = _cluster(cluster_id)
    if err:
        return err
    mgr = _mgr(cluster_id)
    if not mgr:
        return jsonify({'error': 'cluster not connected'}), 409
    return jsonify(ipam_view(mgr, cluster_id))


def _reservation(cluster_id, segment_id):
    s = netseg.segment(segment_id)
    if not s or s['cluster_id'] != cluster_id:
        return None, None, (jsonify({'error': 'segment not found'}), 404)
    z = netseg.zone(cluster_id)
    mgr = _mgr(cluster_id)
    if not mgr or not z:
        return None, None, (jsonify({'error': 'cluster not connected or no zone'}), 409)
    data = request.get_json(silent=True) or {}
    try:
        ip = ipaddress.ip_address(str(data.get('ip') or '').strip())
    except ValueError:
        return None, None, (jsonify({'error': 'ip: an address'}), 400)
    if ip not in ipaddress.ip_network(s['subnet']):
        return None, None, (jsonify({'error': f"{ip} is not in {s['subnet']}"}), 400)
    mac = str(data.get('mac') or '').strip().upper()
    if mac and not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac):
        return None, None, (jsonify({'error': 'mac: AA:BB:CC:DD:EE:FF'}), 400)
    body = {'zone': z['zone'], 'ip': str(ip)}
    if mac:
        body['mac'] = mac
    if data.get('vmid'):
        body['vmid'] = int(data['vmid'])
    return mgr, (s, body), None


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netseg/segments/<segment_id>/ips', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def reserve_ip(cluster_id, segment_id):
    mgr, sb, err = _reservation(cluster_id, segment_id)
    if err:
        return err
    s, body = sb
    r = mgr._api_post(_fw(mgr, f"/cluster/sdn/vnets/{s['vnet']}/ips"), data=body, timeout=15)
    if r is None or r.status_code != 200:
        return jsonify({'error': f"Proxmox: {(getattr(r, 'text', '') or '')[:200]}"}), 502
    log_audit(_user(), 'vlab.netseg.reserve', f"segment '{s['name']}': {body['ip']} {body.get('mac', '')}", get_client_ip())
    return jsonify({'reserved': body['ip']})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netseg/segments/<segment_id>/ips', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def release_ip(cluster_id, segment_id):
    mgr, sb, err = _reservation(cluster_id, segment_id)
    if err:
        return err
    s, body = sb
    q = '&'.join(f'{k}={v}' for k, v in body.items())
    r = mgr._api_delete(_fw(mgr, f"/cluster/sdn/vnets/{s['vnet']}/ips?{q}"), timeout=15)
    if r is None or r.status_code != 200:
        return jsonify({'error': f"Proxmox: {(getattr(r, 'text', '') or '')[:200]}"}), 502
    log_audit(_user(), 'vlab.netseg.unreserve', f"segment '{s['name']}': {body['ip']}", get_client_ip())
    return jsonify({'released': body['ip']})


def _answer(pool, st):
    pol = policy.effective(pool.get('settings'), pool.get('type'))
    seg = netseg.segment(pol.get('net_segment')) if pol.get('net_segment') else None
    rows = {r['desktop_id']: r for r in netseg.moved_rows(pool_id=pool['id'])}
    desks = []
    for d in store.list_desktops(pool['id']):
        info = dict((st or {}).get('desktops', {}).get(d['id']) or {})
        row = rows.get(d['id'])
        desks.append({'id': d['id'], 'name': d['name'], 'vmid': d.get('vmid'),
                      'state': info.get('state') or ('on' if row and seg and row['segment_id'] == seg['id'] else 'off'),
                      'bridge': info.get('bridge') or (row['vnet'] if row else ''),
                      'orig_bridge': row['orig_bridge'] if row else '', 'running': bool(info.get('running')), 'old_ips': info.get('old_ips') or [], 'nic': info.get('nic') or (row['nic'] if row else ''), 'ips': info.get('ips') or [], 'reach': info.get('reach') or '',
                      'error': info.get('error') or ''})
    return {'segment': seg, 'problem': (st or {}).get('problem') or '', 'checked_at': (st or {}).get('at') or None,
            'desktops': desks}


@bp.route('/api/vlab/admin/pools/<pool_id>/netseg', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_pool_netseg(pool_id):
    pool = store.get_pool(pool_id)
    if not pool:
        return jsonify({'error': 'pool not found'}), 404
    return jsonify(_answer(pool, _state.get(pool['id'])))


@bp.route('/api/vlab/admin/pools/<pool_id>/netseg/apply', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def apply_pool_netseg(pool_id):
    pool = store.get_pool(pool_id)
    if not pool:
        return jsonify({'error': 'pool not found'}), 404
    r = (request.get_json(silent=True) or {}).get('restart')
    restart = 'idle' if r == 'idle' else bool(r)
    st = sync_pool(pool, force=True, confirm=False, restart=restart)
    log_audit(_user(), 'vlab.netseg.apply_now', f"pool '{pool['name']}'{' (idle running desktops restarted)' if restart == 'idle' else ' (running desktops restarted)' if restart else ''}",
              get_client_ip())
    return jsonify(_answer(pool, st))
