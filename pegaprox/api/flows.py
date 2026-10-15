# -*- coding: utf-8 -*-
"""
Network flows (MAKUS) - sFlow collector settings and the conversations it saw.

  GET /api/flows/status                  collector settings + counters + agents seen
  PUT /api/flows/config                  {enabled, port, allowed_agents[], retention_days} - opens / closes the port live
  GET /api/flows/top?minutes=60          conversations of the last minutes (<= 60, from memory)
  GET /api/flows/top?hours=24            ... or of the last hours (from the hourly table)
        &ip=<addr>&limit=<n>             filter on one address; each side carries the guest it belongs to
  GET /api/flows/setup                   how to make the nodes export sFlow here (hsflowd / Open vSwitch)

All of it is admin.settings: flows show every address pair on the cluster networks.
"""

import ipaddress
import logging

from flask import Blueprint, jsonify, request

from pegaprox.background import sflow_collector as sc
from pegaprox.core.db import get_db
from pegaprox.utils.audit import log_audit, get_client_ip
from pegaprox.utils.auth import require_auth

bp = Blueprint('flows', __name__)

PROTO = {1: 'icmp', 6: 'tcp', 17: 'udp', 58: 'icmpv6', 132: 'sctp'}


def guest_ip_map():
    """address -> {cluster_id, cluster, vmid, name, node, type} for every guest with a known address."""
    out = {}
    try:
        from pegaprox.globals import cluster_managers
        from pegaprox.background import guest_index
    except Exception:
        return out
    for cid, mgr in list(cluster_managers.items()):
        cname = getattr(getattr(mgr, 'config', None), 'name', cid)
        names = {}
        try:
            for r in mgr.get_vm_resources(max_age=120) or []:
                vmid = r.get('vmid')
                info = {'cluster_id': cid, 'cluster': cname, 'vmid': vmid, 'name': r.get('name', ''),
                        'node': r.get('node', ''), 'type': r.get('type', 'qemu')}
                names[(r.get('type', 'qemu'), vmid)] = info
                for ip in (r.get('ip_addresses') or ([r['ip']] if r.get('ip') else [])):
                    out.setdefault(str(ip).split('/')[0], info)
        except Exception as e:
            logging.debug(f'[flows] resources of {cid}: {e}')
        try:
            for (vtype, vmid), entry in guest_index.snapshot(cid).items():
                info = names.get((vtype, vmid)) or {'cluster_id': cid, 'cluster': cname, 'vmid': vmid, 'name': '', 'node': '', 'type': vtype}
                for _net, ip in entry.get('ips') or []:
                    ip = str(ip).split('/')[0]
                    if ip and ip not in ('dhcp', 'auto', 'manual'):
                        out.setdefault(ip, info)
        except Exception as e:
            logging.debug(f'[flows] guest index of {cid}: {e}')
    return out


def _decorate(rows, ipmap):
    for r in rows:
        r['proto_name'] = PROTO.get(r['proto'], str(r['proto']))
        r['client_guest'] = ipmap.get(r['client'])
        r['server_guest'] = ipmap.get(r['server'])
    return rows


@bp.route('/api/flows/status', methods=['GET'])
@require_auth(perms=['admin.settings'])
def flows_status():
    return jsonify({'settings': sc.settings(), 'collector': sc.status()})


@bp.route('/api/flows/config', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def flows_config():
    data = request.get_json(silent=True) or {}
    cfg = sc.settings()
    if 'enabled' in data:
        cfg['enabled'] = bool(data['enabled'])
    if 'port' in data:
        try:
            port = int(data['port'])
        except (TypeError, ValueError):
            return jsonify({'error': 'invalid port'}), 400
        if not 1024 <= port <= 65535:
            return jsonify({'error': 'port must be 1024-65535'}), 400
        cfg['port'] = port
    if 'allowed_agents' in data:
        agents = data['allowed_agents'] if isinstance(data['allowed_agents'], list) else []
        clean = []
        for a in agents[:200]:
            try:
                clean.append(str(ipaddress.ip_network(str(a).strip(), strict=False)))
            except ValueError:
                return jsonify({'error': f'invalid agent address: {a}'}), 400
        cfg['allowed_agents'] = clean
    if 'retention_days' in data:
        try:
            cfg['retention_days'] = max(1, min(90, int(data['retention_days'])))
        except (TypeError, ValueError):
            return jsonify({'error': 'invalid retention'}), 400
    get_db().save_server_setting(sc.SETTINGS_KEY, cfg)
    sc.stop_sflow_collector()
    sc.start_sflow_collector()
    log_audit(request.session.get('user', ''), 'flows.config',
              f"enabled={cfg['enabled']} port={cfg['port']} agents={len(cfg['allowed_agents'])}", get_client_ip())
    return jsonify({'settings': cfg, 'collector': sc.status()})


@bp.route('/api/flows/top', methods=['GET'])
@require_auth(perms=['admin.settings'])
def flows_top():
    try:
        limit = max(1, min(2000, int(request.args.get('limit', 200))))
        if request.args.get('hours'):
            rows = sc.history(int(request.args['hours']))
        else:
            rows = sc.recent(int(request.args.get('minutes', 60)))
    except (TypeError, ValueError):
        return jsonify({'error': 'invalid range'}), 400
    ip = (request.args.get('ip') or '').strip()
    if ip:
        rows = [r for r in rows if ip in (r['client'], r['server'])]
    total_bytes = sum(r['bytes'] for r in rows)
    hosts = {}
    for r in rows:
        for side in ('client', 'server'):
            h = hosts.setdefault(r[side], [0, 0])
            h[0] += r['bytes']
            h[1] += r['packets']
    top_hosts = sorted(({'ip': k, 'bytes': v[0], 'packets': v[1]} for k, v in hosts.items()), key=lambda x: x['bytes'], reverse=True)[:50]
    ipmap = guest_ip_map()
    for h in top_hosts:
        h['guest'] = ipmap.get(h['ip'])
    return jsonify({'total_bytes': total_bytes, 'conversations': len(rows),
                    'rows': _decorate(rows[:limit], ipmap), 'top_hosts': top_hosts})


@bp.route('/api/flows/setup', methods=['GET'])
@require_auth(perms=['admin.settings'])
def flows_setup():
    cfg = sc.settings()
    collector = (request.args.get('collector') or request.host.split(':')[0]).strip()
    port = int(cfg.get('port') or 6343)
    return jsonify({
        'collector': collector, 'port': port,
        'hsflowd_conf': (
            'sflow {\n'
            f'  collector {{ ip = {collector} udpport = {port} }}\n'
            '  sampling = 1000\n'
            '  polling = 30\n'
            '  pcap { dev = vmbr0 }\n'
            '}\n'),
        'hsflowd_steps': [
            'apt install hsflowd   (or the .deb from sflow.net)',
            'write the configuration above to /etc/hsflowd.conf (one pcap line per bridge to watch)',
            'systemctl enable --now hsflowd',
        ],
        'ovs_command': (f'ovs-vsctl -- --id=@s create sflow agent=vmbr0 target="\\"{collector}:{port}\\"" '
                        'sampling=1000 polling=30 -- set bridge vmbr0 sflow=@s'),
    })
