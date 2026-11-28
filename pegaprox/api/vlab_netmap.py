# -*- coding: utf-8 -*-
"""
네트워크 구성도 (MAKUS): one look at how a cluster's desktops are networked - which network
(segment) each pool is on, what the firewall lets in and out, and what is set up wrong.

Read only. It puts together what 네트워크 격리 (pegaprox/api/vlab_netiso.py) and 네트워크 분리
(pegaprox/api/vlab_netseg.py) want with what Proxmox has now:

  the datacenter firewall      on? (off: no rule filters anything)
  each pool's firewall group   the rules Proxmox has against the ones the policy makes
  each desktop                 its NIC's bridge, firewall=1 on the NIC, the VM firewall on with
                               policy_in DROP
  each segment                 applied in SDN, its gateway reached from the MOAVI server

and answers findings, worst first: {level critical|warning|info, code, pool, segment, detail}.
The console words them (src/admin/pages/NetMapPage.tsx); codes are listed in FINDINGS.
"""

import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor

from flask import Blueprint, jsonify

from pegaprox.api import vlab as core
from pegaprox.api import vlab_netiso, vlab_netseg
from pegaprox.api.vlab_netiso import _data, _fw, _vm_path, cluster_firewall
from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import netiso, netseg, policy, store

bp = Blueprint('vlab_netmap', __name__)

DESKTOPS_READ = 200         # desktops per pool whose VM settings are read (the rest are counted, not read)
READ_AT_ONCE = 16           # Proxmox reads in flight for one map: 200 desktops = about 400 reads, a few seconds
CACHE_FOR = 60              # seconds a map is answered again from memory (다시 점검 reads afresh)
_cache = {}                 # cluster id -> (when, map)
LEVELS = ('critical', 'warning', 'info')
FINDINGS = (
    # critical: isolation or the users' connection does not work as the console says
    'dc_firewall_off', 'no_gateway', 'rules_missing', 'rules_differ', 'vm_firewall_off',
    'gateway_unreachable', 'sdn_node_problem',
    # warning: works, but less separated than it looks
    'dc_firewall_unknown', 'pool_not_isolated', 'pool_on_management', 'segment_without_isolation',
    'allow_in_wide', 'segment_pending', 'pool_problem',
    # info: as designed, worth knowing
    'egress_open', 'peers_open', 'segment_shared', 'segment_unused',
    # pool to pool (마이크로 세그먼트)
    'peer_out_missing', 'rule_pool_missing',
)


def _peer(v, pool_ipset, others=None):
    v = str(v or '')
    if v.startswith('+dc/'):
        v = '+' + v[4:]
    if v == f'+{netiso.GW_IPSET}':
        return 'gateway', ''
    if v == f'+{pool_ipset}':
        return 'pool', ''
    if others and v in others:
        return 'other', others[v]
    return 'cidr', v


def rule_view(pool_id, pol):
    """The pool's firewall rules as the console draws them: [{dir, peer gateway|pool|cidr, cidr,
    proto, port, note}]. With net_egress 'any' everything goes out (one 'any' rule says so)."""
    ipset = netiso.ipset_name(pool_id)
    others = {f'+{netiso.ipset_name(p)}': p for p in netiso.peer_pools(pol)}
    out = []
    for r in netiso.group_rules(pool_id, pol):
        kind, cidr = _peer(r.get('source') if r['type'] == 'in' else r.get('dest'), ipset, others)
        note = (r.get('comment') or '').replace(netiso.TAG, '').lstrip(': ')
        rule = {'dir': r['type'], 'peer': 'pool_other' if kind == 'other' else kind, 'cidr': '' if kind == 'other' else cidr,
                'proto': r.get('proto') or 'any', 'port': r.get('dport') or '', 'note': note,
                'action': 'drop' if r.get('action') == 'DROP' else 'accept'}
        if kind == 'other':
            rule['pool'] = cidr
        out.append(rule)
    if pol.get('net_egress') != 'list':
        out.append({'dir': 'out', 'peer': 'any', 'cidr': '', 'proto': 'any', 'port': '', 'note': '', 'action': 'accept'})
    return out


def _live_group(mgr, pool_id, pol, groups):
    """match | differ | missing | unknown: the pool's group in Proxmox against what the policy makes."""
    name = netiso.group_name(pool_id)
    if groups is None:
        return 'unknown'
    if not any(g.get('group') == name for g in groups):
        return 'missing'
    try:
        have = _data(mgr._api_get(_fw(mgr, f'/cluster/firewall/groups/{name}'), timeout=8))
    except Exception:
        have = None
    if have is None:
        return 'unknown'
    have = sorted(have, key=lambda r: int(r.get('pos', 0)))
    want = netiso.group_rules(pool_id, pol)
    return 'match' if [netiso.rule_key(r) for r in have] == [netiso.rule_key(r) for r in want] else 'differ'


def _desktop(mgr, d, node, isolated, from_bridge, recorded_nic, running=False):
    """{bridge, nic, nic_fw, vm_fw, policy_in, error} of one desktop, as Proxmox has it."""
    out = {'bridge': '', 'nic': '', 'nic_fw': None, 'vm_fw': None, 'policy_in': '', 'error': '', 'ips': []}
    path = _vm_path(node, d.get('vm_type'), d['vmid'])
    try:
        if running and d.get('vm_type', 'qemu') == 'qemu':
            try:
                out['ips'] = netiso.ipv4s(mgr._fetch_qemu_ips(node, int(d['vmid'])))
            except Exception:
                pass
        cfg = _data(mgr._api_get(_fw(mgr, f'{path}/config'), timeout=8))
        if not isinstance(cfg, dict):
            out['error'] = 'settings unreadable'
            return out
        nics = dict(vlab_netseg._nics(cfg))
        nic = recorded_nic if recorded_nic in nics else ''
        if not nic and from_bridge:
            nic = next((k for k, v in sorted(nics.items()) if netseg.nic_parts(v)[0].get('bridge') == from_bridge), '')
        if not nic:
            nic = (vlab_netseg._first_nic(cfg) or ('', ''))[0] or ''
        kv = netseg.nic_parts(nics.get(nic, ''))[0] if nic else {}
        out.update(nic=nic, bridge=kv.get('bridge') or '', nic_fw=kv.get('firewall') == '1')
        if isolated:
            o = _data(mgr._api_get(_fw(mgr, f'{path}/firewall/options'), timeout=8))
            if isinstance(o, dict):
                out.update(vm_fw=bool(int(o.get('enable') or 0)), policy_in=o.get('policy_in') or 'ACCEPT')
    except Exception as e:
        out['error'] = str(e)[:200]
    return out


def _wide(cidr):
    try:
        return ipaddress.ip_network(cidr, strict=False).prefixlen <= 8
    except ValueError:
        return False


def cluster_map(cluster_id):
    mgr = cluster_managers.get(cluster_id)
    connected = bool(mgr)
    fw = cluster_firewall(mgr) if mgr else None
    sources = netiso.gateway_sources(cluster_id)
    seg_view = vlab_netseg.cluster_view(cluster_id)
    segs = {s['id']: s for s in seg_view['segments']}
    try:
        br = vlab_netseg.bridges(mgr) if mgr else {'nodes': [], 'bridges': []}
    except Exception as e:
        logging.info(f'[VLAB] netmap: bridges of {cluster_id}: {str(e)[:200]}')
        br = {'nodes': [], 'bridges': []}
    addressed = {b['name'] for b in br['bridges'] if b['addressed']}
    try:
        groups = _data(mgr._api_get(_fw(mgr, '/cluster/firewall/groups'), timeout=8)) if mgr else None
    except Exception:
        groups = None
    vms = core._vm_states(cluster_id) if mgr else {}
    pools = [p for p in store.list_pools() if p.get('cluster_id') == cluster_id]
    findings = []

    def find(level, code, pool=None, segment=None, detail=''):
        findings.append({'level': level, 'code': code, 'pool': pool or '', 'segment': segment or '', 'detail': str(detail)[:300]})

    # every pool's desktops read at once (READ_AT_ONCE calls in flight over the cluster, not pool by pool)
    plan = []
    for p in pools:
        pol = policy.effective(p.get('settings'), p.get('type'))
        moved = {r['desktop_id']: r for r in netseg.moved_rows(pool_id=p['id'])}
        desks = [d for d in store.list_desktops(p['id']) if d.get('vmid')]
        plan.append((p, pol, moved, desks, desks[:DESKTOPS_READ]))
    jobs = [(d, pol, moved) for _p, pol, moved, _desks, read in plan for d in read]
    info_all = {}
    if mgr and jobs:
        def one(job):
            d, pol, moved = job
            vm = vms.get(int(d['vmid'])) or {}
            return d['id'], _desktop(mgr, d, vm.get('node') or d['node'], bool(pol.get('net_isolation')),
                                     pol.get('net_segment_from') or '', (moved.get(d['id']) or {}).get('nic'),
                                     vm.get('status') == 'running')
        with ThreadPoolExecutor(max_workers=min(READ_AT_ONCE, len(jobs))) as ex:
            info_all = dict(ex.map(one, jobs))
    out_pools = []
    for p, pol, moved, desks, read in plan:
        iso = bool(pol.get('net_isolation'))
        sid = pol.get('net_segment') or ''
        info = {d['id']: info_all[d['id']] for d in read if d['id'] in info_all}
        applied = {r['desktop_id'] for r in netiso.applied_rows(pool_id=p['id'])}
        live = (_live_group(mgr, p['id'], pol, groups) if iso and mgr else 'off' if not iso else 'unknown')
        seg = segs.get(sid)
        bridges = sorted({i['bridge'] for i in info.values() if i['bridge']})
        fw_off = [d['name'] for d in read if iso and info.get(d['id']) and not info[d['id']]['error']
                  and (info[d['id']]['nic_fw'] is False or info[d['id']]['vm_fw'] is False
                       or (info[d['id']]['vm_fw'] and info[d['id']]['policy_in'] != 'DROP'))]
        on_seg = [d for d in desks if seg and (info.get(d['id']) or {}).get('bridge') == seg['vnet']]
        iso_st = vlab_netiso._state.get(p['id']) or {}
        seg_st = vlab_netseg._state.get(p['id']) or {}
        out_pools.append({
            'id': p['id'], 'name': p['name'], 'type': p.get('type') or '',
            'isolation': iso, 'peers': bool(pol.get('net_peers')), 'egress': pol.get('net_egress') or 'any',
            'segment': sid, 'from_bridge': pol.get('net_segment_from') or '',
            'rules': rule_view(p['id'], pol) if iso else [], 'live': live,
            'bridges': bridges,
            'desktops': {'total': len(desks), 'read': len(read), 'isolated': len([d for d in desks if d['id'] in applied]),
                         'fw_off': len(fw_off), 'on_segment': len(on_seg),
                         'errors': len([i for i in info.values() if i['error']])},
            'problem': iso_st.get('problem') or seg_st.get('problem') or '',
            'vms': [dict({k: (info.get(d['id']) or {}).get(k) for k in ('bridge', 'nic_fw', 'vm_fw', 'policy_in', 'ips', 'error')},
                         id=d['id'], name=d['name'], vmid=d['vmid'],
                         node=(vms.get(int(d['vmid'])) or {}).get('node') or d['node'],
                         status=(vms.get(int(d['vmid'])) or {}).get('status') or 'unknown',
                         isolated=d['id'] in applied, read=d['id'] in info) for d in desks],
            '_pol': pol,
        })
        # --- findings of the pool
        if not iso:
            if desks:
                find('warning', 'pool_not_isolated', p['id'])
        else:
            if not sources:
                find('critical', 'no_gateway', p['id'])
            if live == 'missing' and desks:
                find('critical', 'rules_missing', p['id'], detail=netiso.group_name(p['id']))
            elif live == 'differ':
                find('critical', 'rules_differ', p['id'], detail=netiso.group_name(p['id']))
            if fw_off:
                find('critical', 'vm_firewall_off', p['id'], detail=', '.join(fw_off))
            wide = [r['cidr'] for r in pol.get('net_allow_in') or [] if _wide(r.get('cidr'))]
            if wide:
                find('warning', 'allow_in_wide', p['id'], detail=', '.join(wide))
            if pol.get('net_egress') != 'list':
                find('info', 'egress_open', p['id'])
            if pol.get('net_peers'):
                find('info', 'peers_open', p['id'])
        if sid and not iso:
            find('warning', 'segment_without_isolation', p['id'], sid)
        if not sid and set(bridges) & addressed:
            find('warning', 'pool_on_management', p['id'], detail=', '.join(sorted(set(bridges) & addressed)))
        if sid and seg and desks and len(on_seg) < len(desks):
            find('warning', 'segment_pending', p['id'], sid, f'{len(on_seg)}/{len(desks)}')
        if out_pools[-1]['problem']:
            find('warning', 'pool_problem', p['id'], detail=out_pools[-1]['problem'])
    # --- pool to pool: a rule naming a pool that is gone; an inbound allow the other side cannot send
    by_id = {x['id']: x for x in out_pools}
    for x in out_pools:
        pol = x.pop('_pol')
        if not x['isolation']:
            continue
        for r in pol.get('net_allow_in') or []:
            if not r.get('pool'):
                continue
            other = by_id.get(r['pool'])
            if not other:
                find('warning', 'rule_pool_missing', x['id'], detail=r['pool'])
                continue
            if r.get('action') == 'drop' or not other['isolation'] or other['egress'] != 'list':
                continue
            if not any(o['dir'] == 'out' and o['action'] == 'accept' and o.get('pool') == x['id'] for o in other['rules']):
                find('warning', 'peer_out_missing', other['id'],
                     detail=f"{x['name']} {r['proto']}{(' ' + r['port']) if r['port'] else ''}")
        for r in pol.get('net_allow_out') or []:
            if r.get('pool') and r['pool'] not in by_id:
                find('warning', 'rule_pool_missing', x['id'], detail=r['pool'])
    for x in out_pools:
        x.pop('_pol', None)
    # --- the cluster and the segments
    if any(x['isolation'] for x in out_pools):
        if fw is None:
            find('warning', 'dc_firewall_unknown')
        elif not fw['enable']:
            find('critical', 'dc_firewall_off')
    if seg_view['sdn'].get('node_problem'):
        find('critical', 'sdn_node_problem', detail=seg_view['sdn']['node_problem'])
    for s in seg_view['segments']:
        users = [x for x in out_pools if x['segment'] == s['id']]
        if not users:
            find('info', 'segment_unused', segment=s['id'])
            continue
        if len(users) > 1:
            find('info', 'segment_shared', segment=s['id'], detail=', '.join(x['name'] for x in users))
        if s['sdn'] == 'applied' and s.get('gateway_reach') in ('unreachable', 'timeout'):
            find('critical', 'gateway_unreachable', segment=s['id'], detail=s['gateway'])
    findings.sort(key=lambda f: LEVELS.index(f['level']))
    return {'connected': connected, 'cluster_firewall': fw, 'gateway': {'sources': sources, 'hosts': [h for h in vlab_netiso._gateway_hosts() if h]},
            'zone': seg_view['zone'], 'sdn': seg_view['sdn'], 'segments': seg_view['segments'],
            'bridges': br['bridges'], 'nodes': br['nodes'], 'pools': out_pools, 'findings': findings}


@bp.route('/api/vlab/admin/clusters/<cluster_id>/netmap', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_cluster_netmap(cluster_id):
    """네트워크 구성도: segments, pools, their firewall rules and what is set up wrong (read only)."""
    if cluster_id not in cluster_managers:
        return jsonify({'error': 'unknown cluster'}), 404
    import time
    from flask import request
    hit = _cache.get(cluster_id)
    if hit and request.args.get('fresh') != '1' and time.time() - hit[0] < CACHE_FOR:
        return jsonify(dict(hit[1], cached_at=hit[0]))
    m = cluster_map(cluster_id)
    _cache[cluster_id] = (time.time(), m)
    return jsonify(dict(m, cached_at=None))
