# -*- coding: utf-8 -*-
"""
Microsegmentation (MAKUS) - firewall rules proposed from the traffic actually seen.

The sFlow collector knows who talked to whom. For every guest of a cluster this module
lists the inbound conversations it served (protocol, port, the addresses that came in)
and turns them into Proxmox VM firewall rules: IN ACCEPT <proto> <port> from <sources>.

  GET  /api/microseg/recommend?cluster_id=&hours=24&min_bytes=0   proposals per guest + current firewall state
  POST /api/microseg/apply   {cluster_id, node, type, vmid, rules:[{proto, port, sources[]}], mode}
                              mode 'monitor': rules in place, inbound policy ACCEPT with logging (nothing blocked)
                              mode 'enforce': same rules, inbound policy DROP (everything else blocked)
  POST /api/microseg/revert  {cluster_id, node, type, vmid}   managed rules out, inbound policy ACCEPT

Rules written here carry the comment 'vlab-microseg' and are the only ones this module
touches: apply replaces them, revert removes them, the operator's own rules stay. The
guest's NICs need firewall=1 and the datacenter firewall must be on for any of it to
filter; both are reported, neither is changed here.

admin.settings (flows cover every address of the cluster) plus access to the cluster.
"""

import ipaddress
import logging

from flask import Blueprint, jsonify, request

from pegaprox.api.helpers import check_cluster_access, get_connected_manager
from pegaprox.background import sflow_collector as sc
from pegaprox.utils.audit import log_audit, get_client_ip
from pegaprox.utils.auth import require_auth

bp = Blueprint('microseg', __name__)

TAG = 'vlab-microseg'
PROTO = {1: 'icmp', 6: 'tcp', 17: 'udp', 58: 'ipv6-icmp'}
MAX_SOURCES = 100


def _fw_url(mgr, node, vmtype, vmid, sub=''):
    return f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/{vmtype}/{vmid}/firewall{sub}"


def _get(mgr, url):
    try:
        r = mgr._create_session().get(url, timeout=8)
        return r.json().get('data') if r.status_code == 200 else None
    except Exception:
        return None


def _nic_firewall(mgr, node, vmtype, vmid):
    cfg = _get(mgr, f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/{vmtype}/{vmid}/config") or {}
    nics = {k: v for k, v in cfg.items() if k.startswith('net') and k[3:].isdigit()}
    return {k: ('firewall=1' in str(v)) for k, v in nics.items()}


def proposals(cluster_id, hours, min_bytes=0):
    from pegaprox.api.flows import guest_ip_map
    rows = sc.history(hours) if hours >= 1 else sc.recent(60)
    ipmap = guest_ip_map()
    guests = {}
    for r in rows:
        g = ipmap.get(r['server'])
        if not g or g.get('cluster_id') != cluster_id or r['bytes'] < min_bytes:
            continue
        key = (g.get('type') or 'qemu', int(g['vmid']))
        e = guests.setdefault(key, {'vmid': int(g['vmid']), 'type': g.get('type') or 'qemu', 'name': g.get('name', ''),
                                    'node': g.get('node', ''), 'ips': set(), 'rules': {}})
        e['ips'].add(r['server'])
        proto = PROTO.get(r['proto'])
        if not proto:
            continue
        rk = (proto, r['port'] if proto in ('tcp', 'udp') else 0)
        rule = e['rules'].setdefault(rk, {'proto': rk[0], 'port': rk[1], 'sources': {}, 'bytes': 0})
        rule['bytes'] += r['bytes']
        src = rule['sources'].setdefault(r['client'], {'ip': r['client'], 'bytes': 0, 'guest': None})
        src['bytes'] += r['bytes']
        cg = ipmap.get(r['client'])
        if cg:
            src['guest'] = {'cluster': cg.get('cluster'), 'vmid': cg.get('vmid'), 'name': cg.get('name')}
    out = []
    for e in guests.values():
        rules = []
        for rule in sorted(e['rules'].values(), key=lambda x: x['bytes'], reverse=True):
            srcs = sorted(rule['sources'].values(), key=lambda x: x['bytes'], reverse=True)
            rules.append({'proto': rule['proto'], 'port': rule['port'], 'bytes': rule['bytes'],
                          'sources': srcs[:MAX_SOURCES], 'sources_truncated': len(srcs) > MAX_SOURCES})
        out.append({**e, 'ips': sorted(e['ips']), 'rules': rules})
    out.sort(key=lambda x: (x['name'] or '', x['vmid']))
    return out


@bp.route('/api/microseg/recommend', methods=['GET'])
@require_auth(perms=['admin.settings'])
def microseg_recommend():
    cluster_id = request.args.get('cluster_id', '')
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    mgr, error = get_connected_manager(cluster_id)
    if error:
        return error
    try:
        hours = max(0, min(24 * 31, int(request.args.get('hours', 24))))
        min_bytes = max(0, int(request.args.get('min_bytes', 0)))
    except (TypeError, ValueError):
        return jsonify({'error': 'invalid range'}), 400
    guests = proposals(cluster_id, hours, min_bytes)
    dc = _get(mgr, f"https://{mgr.host}:{mgr.api_port}/api2/json/cluster/firewall/options") or {}
    for g in guests[:200]:
        if not g['node']:
            continue
        opts = _get(mgr, _fw_url(mgr, g['node'], g['type'], g['vmid'], '/options')) or {}
        cur = _get(mgr, _fw_url(mgr, g['node'], g['type'], g['vmid'], '/rules')) or []
        g['firewall'] = {
            'enabled': str(opts.get('enable', 0)) == '1', 'policy_in': opts.get('policy_in', 'ACCEPT'),
            'managed_rules': sum(1 for x in cur if x.get('comment') == TAG),
            'other_rules': sum(1 for x in cur if x.get('comment') != TAG),
            'nics': _nic_firewall(mgr, g['node'], g['type'], g['vmid']),
        }
    return jsonify({'cluster_id': cluster_id, 'hours': hours, 'datacenter_firewall': str(dc.get('enable', 0)) == '1',
                    'collector': {'enabled': sc.settings().get('enabled', False), 'listening': sc.status().get('listening')},
                    'guests': guests})


def _target(data):
    cluster_id = str(data.get('cluster_id') or '')
    node = str(data.get('node') or '')
    vmtype = data.get('type') if data.get('type') in ('qemu', 'lxc') else None
    try:
        vmid = int(data.get('vmid'))
    except (TypeError, ValueError):
        vmid = None
    if not cluster_id or not node or not vmtype or vmid is None or not node.replace('-', '').replace('.', '').isalnum():
        return None
    return cluster_id, node, vmtype, vmid


def _remove_managed(mgr, node, vmtype, vmid):
    cur = _get(mgr, _fw_url(mgr, node, vmtype, vmid, '/rules')) or []
    for pos in sorted((int(x['pos']) for x in cur if x.get('comment') == TAG), reverse=True):
        r = mgr._create_session().delete(_fw_url(mgr, node, vmtype, vmid, f'/rules/{pos}'), timeout=10)
        if r.status_code != 200:
            raise RuntimeError(f'remove rule {pos}: {r.text[:200]}')


@bp.route('/api/microseg/apply', methods=['POST'])
@require_auth(perms=['admin.settings'])
def microseg_apply():
    data = request.get_json(silent=True) or {}
    t = _target(data)
    if not t:
        return jsonify({'error': 'cluster_id, node, type and vmid are required'}), 400
    cluster_id, node, vmtype, vmid = t
    mode = data.get('mode')
    if mode not in ('monitor', 'enforce'):
        return jsonify({'error': "mode must be 'monitor' or 'enforce'"}), 400
    rules = []
    for rule in (data.get('rules') or [])[:100]:
        proto = rule.get('proto')
        if proto not in ('tcp', 'udp', 'icmp', 'ipv6-icmp'):
            return jsonify({'error': f'invalid protocol: {proto}'}), 400
        try:
            port = int(rule.get('port') or 0)
        except (TypeError, ValueError):
            return jsonify({'error': 'invalid port'}), 400
        if not 0 <= port <= 65535:
            return jsonify({'error': 'invalid port'}), 400
        srcs = []
        for s in (rule.get('sources') or [])[:MAX_SOURCES]:
            try:
                srcs.append(str(ipaddress.ip_network(str(s).strip(), strict=False)))
            except ValueError:
                return jsonify({'error': f'invalid source: {s}'}), 400
        rules.append((proto, port, srcs))
    if mode == 'enforce' and not rules:
        return jsonify({'error': 'enforce without any rule would block all inbound traffic'}), 400
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    mgr, error = get_connected_manager(cluster_id)
    if error:
        return error
    try:
        _remove_managed(mgr, node, vmtype, vmid)
        s = mgr._create_session()
        for proto, port, srcs in reversed(rules):            # each POST lands at position 0
            body = {'type': 'in', 'action': 'ACCEPT', 'enable': 1, 'proto': proto, 'comment': TAG}
            if port and proto in ('tcp', 'udp'):
                body['dport'] = str(port)
            if srcs:
                body['source'] = ','.join(srcs)
            r = s.post(_fw_url(mgr, node, vmtype, vmid, '/rules'), data=body, timeout=10)
            if r.status_code != 200:
                raise RuntimeError(f'add rule {proto}/{port}: {r.text[:200]}')
        opts = {'enable': 1, 'policy_in': 'ACCEPT' if mode == 'monitor' else 'DROP', 'log_level_in': 'info'}
        r = s.put(_fw_url(mgr, node, vmtype, vmid, '/options'), data=opts, timeout=10)
        if r.status_code != 200:
            raise RuntimeError(f'firewall options: {r.text[:200]}')
    except Exception as e:
        logging.warning(f'[microseg] apply {cluster_id}/{vmtype}/{vmid}: {e}')
        return jsonify({'error': f'apply failed: {e}'}), 502
    log_audit(request.session.get('user', ''), 'microseg.apply',
              f'{vmtype} {vmid} on {node}: {len(rules)} rule(s), mode={mode}', get_client_ip(), cluster=mgr.config.name)
    return jsonify({'ok': True, 'mode': mode, 'rules': len(rules), 'nics': _nic_firewall(mgr, node, vmtype, vmid)})


@bp.route('/api/microseg/revert', methods=['POST'])
@require_auth(perms=['admin.settings'])
def microseg_revert():
    data = request.get_json(silent=True) or {}
    t = _target(data)
    if not t:
        return jsonify({'error': 'cluster_id, node, type and vmid are required'}), 400
    cluster_id, node, vmtype, vmid = t
    ok, err = check_cluster_access(cluster_id)
    if not ok:
        return err
    mgr, error = get_connected_manager(cluster_id)
    if error:
        return error
    try:
        _remove_managed(mgr, node, vmtype, vmid)
        r = mgr._create_session().put(_fw_url(mgr, node, vmtype, vmid, '/options'), data={'policy_in': 'ACCEPT'}, timeout=10)
        if r.status_code != 200:
            raise RuntimeError(r.text[:200])
    except Exception as e:
        return jsonify({'error': f'revert failed: {e}'}), 502
    log_audit(request.session.get('user', ''), 'microseg.revert', f'{vmtype} {vmid} on {node}', get_client_ip(), cluster=mgr.config.name)
    return jsonify({'ok': True})
