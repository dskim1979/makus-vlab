# -*- coding: utf-8 -*-
"""
네트워크 분리 2단계 (MAKUS): segments - a department's own network, as a Proxmox SDN VNet with a
subnet in the PVE IPAM - and pools whose desktops are moved onto one (pool policy net_segment).

  cluster   zone <zone>          one SDN zone MOAVI keeps its VNets in (vlan: on a bridge with
                                 802.1q tags; vxlan: tunnels between the nodes' addresses, no
                                 switch change; simple: on one node only, with dnsmasq DHCP),
                                 ipam 'pve'. Or an existing zone of the operator, used as it is.
            vnet mv<h>           a segment: tag (VLAN / VXLAN id), alias = the segment's name
            subnet               its CIDR, gateway, SNAT, the DHCP range (simple zones)
  desktop   the first NIC's bridge = the VNet (its old bridge and tag kept, put back when the
            pool leaves the segment)

<h> is 6 hex digits of sha1(segment id): VNet ids are at most 8 characters. Zones, VNets and
subnets of other names are the operator's and are never touched. A desktop that is running is
moved only when it is next off (or with 재시작해서 적용): moving it live would leave its address
on the wrong network until its DHCP lease is renewed.

Applying is pegaprox/api/vlab_netseg.py (the minute loop, 지금 적용, the SDN 적용).
"""

import hashlib
import ipaddress
import re
import threading
import uuid

from pegaprox.vlab.store import db as _store_db, now

ZONE_TYPES = ('vlan', 'vxlan', 'simple')
DEFAULT_ZONE = 'moavi'
SEGMENTS_MAX = 200
TAG_MAX = {'vlan': 4094, 'vxlan': 16777215, 'simple': 0}

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_netseg_zone (
        cluster_id TEXT PRIMARY KEY,
        zone TEXT NOT NULL,
        type TEXT NOT NULL,
        bridge TEXT NOT NULL DEFAULT '',
        peers TEXT NOT NULL DEFAULT '',
        mtu INTEGER NOT NULL DEFAULT 0,
        existing INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL DEFAULT ''
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_netseg (
        id TEXT PRIMARY KEY,
        cluster_id TEXT NOT NULL,
        name TEXT NOT NULL,
        department TEXT NOT NULL DEFAULT '',
        tag INTEGER NOT NULL DEFAULT 0,
        subnet TEXT NOT NULL,
        gateway TEXT NOT NULL DEFAULT '',
        dhcp_start TEXT NOT NULL DEFAULT '',
        dhcp_end TEXT NOT NULL DEFAULT '',
        snat INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL DEFAULT ''
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_netseg_moved (
        desktop_id TEXT PRIMARY KEY,
        cluster_id TEXT NOT NULL,
        pool_id TEXT NOT NULL,
        segment_id TEXT NOT NULL,
        node TEXT NOT NULL DEFAULT '',
        vmid INTEGER NOT NULL,
        nic TEXT NOT NULL DEFAULT 'net0',
        orig_bridge TEXT NOT NULL,
        orig_tag TEXT NOT NULL DEFAULT '',
        vnet TEXT NOT NULL,
        at TEXT NOT NULL
    )''',
)
TABLES = ('vlab_netseg_zone', 'vlab_netseg', 'vlab_netseg_moved')

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_netseg', False):
        with _lock:
            if not getattr(d, '_vlab_netseg', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_netseg = True
    return d


def vnet_name(segment_id):
    return 'mv' + hashlib.sha1(str(segment_id).encode('utf-8')).hexdigest()[:6]


_ID = re.compile(r'^[a-z][a-z0-9]{0,7}$')
_BRIDGE = re.compile(r'^[A-Za-z][A-Za-z0-9_.-]{0,15}$')


# --- the zone, per cluster -------------------------------------------------------------------------

def zone(cluster_id):
    r = db().query_one('SELECT * FROM vlab_netseg_zone WHERE cluster_id = ?', (cluster_id,))
    return dict(r) if r else None


def clean_zone(v):
    """(zone, None) or (None, error)."""
    if not isinstance(v, dict):
        return None, 'JSON object required'
    name = str(v.get('zone') or DEFAULT_ZONE).strip()
    if not _ID.match(name):
        return None, 'zone: a letter, then letters or digits, at most 8 (Proxmox SDN zone id)'
    existing = bool(v.get('existing'))
    typ = v.get('type') or 'vlan'
    if typ not in ZONE_TYPES:
        return None, f"type must be one of {', '.join(ZONE_TYPES)}"
    bridge = str(v.get('bridge') or '').strip()
    peers = str(v.get('peers') or '').replace(' ', '')
    if not existing:
        if typ == 'vlan' and not _BRIDGE.match(bridge):
            return None, 'bridge: the nodes\' bridge the VLANs ride on (e.g. vmbr0)'
        if typ == 'vxlan':
            ips = [p for p in peers.split(',') if p]
            if not ips:
                return None, 'peers: the nodes\' addresses, comma separated'
            for p in ips:
                try:
                    ipaddress.ip_address(p)
                except ValueError:
                    return None, f"peers: '{p}' is not an address"
            peers = ','.join(ips)
    mtu = v.get('mtu') or 0
    if not isinstance(mtu, int) or isinstance(mtu, bool) or not (mtu == 0 or 1280 <= mtu <= 9000):
        return None, 'mtu: 0 (Proxmox default) or 1280 to 9000'
    return {'zone': name, 'type': typ, 'bridge': bridge if typ == 'vlan' else '', 'peers': peers if typ == 'vxlan' else '',
            'mtu': mtu, 'existing': existing}, None


def set_zone(cluster_id, z, by=''):
    db().execute('''INSERT INTO vlab_netseg_zone (cluster_id, zone, type, bridge, peers, mtu, existing, updated_at, updated_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cluster_id) DO UPDATE SET zone = excluded.zone, type = excluded.type,
                    bridge = excluded.bridge, peers = excluded.peers, mtu = excluded.mtu, existing = excluded.existing,
                    updated_at = excluded.updated_at, updated_by = excluded.updated_by''',
                 (cluster_id, z['zone'], z['type'], z['bridge'], z['peers'], int(z['mtu']), 1 if z['existing'] else 0, now(), by))


def zone_body(z):
    """What POST /cluster/sdn/zones takes for a zone MOAVI makes."""
    body = {'zone': z['zone'], 'type': z['type'], 'ipam': 'pve'}
    if z['type'] == 'vlan':
        body['bridge'] = z['bridge']
    elif z['type'] == 'vxlan':
        body['peers'] = z['peers']
    elif z['type'] == 'simple':
        body['dhcp'] = 'dnsmasq'
    if z.get('mtu'):
        body['mtu'] = int(z['mtu'])
    return body


# --- segments --------------------------------------------------------------------------------------

def _row(r):
    d = dict(r)
    d['snat'] = bool(d.get('snat'))
    d['vnet'] = vnet_name(d['id'])
    return d


def segments(cluster_id=None):
    if cluster_id:
        rows = db().query('SELECT * FROM vlab_netseg WHERE cluster_id = ? ORDER BY name', (cluster_id,))
    else:
        rows = db().query('SELECT * FROM vlab_netseg ORDER BY name')
    return [_row(r) for r in rows]


def segment(segment_id):
    r = db().query_one('SELECT * FROM vlab_netseg WHERE id = ?', (segment_id,))
    return _row(r) if r else None


def clean_segment(v, cluster_id, zone_type, segment_id=None):
    """(fields, None) or (None, error). Checks the subnet, gateway and DHCP range, and that no
    other segment of the cluster has the same tag or an overlapping subnet."""
    if not isinstance(v, dict):
        return None, 'JSON object required'
    name = str(v.get('name') or '').strip()
    if not 1 <= len(name) <= 40:
        return None, 'name: 1 to 40 characters'
    dept = str(v.get('department') or '').strip()[:80]
    tag = v.get('tag') or 0
    hi = TAG_MAX.get(zone_type, 4094)
    if not isinstance(tag, int) or isinstance(tag, bool) or tag < 0 or tag > hi or (zone_type != 'simple' and tag < 1):
        return None, ('tag: not used in a simple zone (0)' if zone_type == 'simple' else f'tag: 1 to {hi}')
    try:
        net = ipaddress.ip_network(str(v.get('subnet') or '').strip(), strict=False)
    except ValueError:
        return None, "subnet: a network such as 10.20.1.0/24"
    if net.version != 4 or not 16 <= net.prefixlen <= 29:
        return None, 'subnet: IPv4, from /16 to /29'

    def host(key, required=False):
        s = str(v.get(key) or '').strip()
        if not s:
            if required:
                raise ValueError(f'{key}: required')
            return ''
        try:
            a = ipaddress.ip_address(s)
        except ValueError:
            raise ValueError(f"{key}: '{s}' is not an address")
        if a not in net or a in (net.network_address, net.broadcast_address):
            raise ValueError(f'{key}: {a} is not a host address of {net}')
        return str(a)
    try:
        gw = host('gateway', required=True)
        start, end = host('dhcp_start'), host('dhcp_end')
    except ValueError as e:
        return None, str(e)
    if bool(start) != bool(end):
        return None, 'dhcp_start and dhcp_end go together'
    if start:
        a, b, g = ipaddress.ip_address(start), ipaddress.ip_address(end), ipaddress.ip_address(gw)
        if a > b:
            return None, 'dhcp_start comes before dhcp_end'
        if a <= g <= b:
            return None, 'the DHCP range must leave out the gateway'
    for other in segments(cluster_id):
        if other['id'] == segment_id:
            continue
        if zone_type != 'simple' and tag and other['tag'] == tag:
            return None, f"tag {tag} is already segment '{other['name']}'"
        if ipaddress.ip_network(other['subnet']).overlaps(net):
            return None, f"{net} overlaps segment '{other['name']}' ({other['subnet']})"
    # SNAT is done by the nodes only in simple (and EVPN) zones; a VLAN / VXLAN subnet goes out
    # through the router that holds its gateway address
    return {'name': name, 'department': dept, 'tag': tag, 'subnet': str(net), 'gateway': gw,
            'dhcp_start': start, 'dhcp_end': end, 'snat': bool(v.get('snat')) and zone_type == 'simple'}, None


def add_segment(cluster_id, f, by=''):
    sid = 'seg_' + uuid.uuid4().hex[:12]
    db().execute('''INSERT INTO vlab_netseg (id, cluster_id, name, department, tag, subnet, gateway, dhcp_start, dhcp_end,
                    snat, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (sid, cluster_id, f['name'], f['department'], int(f['tag']), f['subnet'], f['gateway'],
                  f['dhcp_start'], f['dhcp_end'], 1 if f['snat'] else 0, now(), by))
    return segment(sid)


def update_segment(segment_id, f):
    db().execute('''UPDATE vlab_netseg SET name = ?, department = ?, tag = ?, subnet = ?, gateway = ?, dhcp_start = ?,
                    dhcp_end = ?, snat = ? WHERE id = ?''',
                 (f['name'], f['department'], int(f['tag']), f['subnet'], f['gateway'], f['dhcp_start'], f['dhcp_end'],
                  1 if f['snat'] else 0, segment_id))
    return segment(segment_id)


def delete_segment(segment_id):
    db().execute('DELETE FROM vlab_netseg WHERE id = ?', (segment_id,))


def vnet_body(seg, zone_name):
    body = {'vnet': seg['vnet'], 'zone': zone_name, 'alias': re.sub(r'[^A-Za-z0-9 _.-]', '', seg['name'])[:60] or seg['vnet']}
    if seg.get('tag'):
        body['tag'] = int(seg['tag'])
    return body


def subnet_body(seg):
    body = {'subnet': seg['subnet'], 'type': 'subnet', 'gateway': seg['gateway'], 'snat': 1 if seg['snat'] else 0}
    if seg.get('dhcp_start'):
        body['dhcp-range'] = [f"start-address={seg['dhcp_start']},end-address={seg['dhcp_end']}"]
    return body


def subnet_id(zone_name, cidr):
    """Proxmox names a subnet <zone>-<network>-<prefix>."""
    net = ipaddress.ip_network(cidr)
    return f'{zone_name}-{net.network_address}-{net.prefixlen}'


def usable(cidr):
    net = ipaddress.ip_network(cidr)
    return max(net.num_addresses - 2, 0)


# --- a desktop's NIC -------------------------------------------------------------------------------

def nic_parts(value):
    """'virtio=AA:..,bridge=vmbr0,tag=20,firewall=1' -> (model=mac part, {key: value}, [order])."""
    parts = [p for p in str(value or '').split(',') if p]
    kv, order = {}, []
    for p in parts:
        k, _, val = p.partition('=')
        kv[k] = val
        order.append(k)
    return kv, order


def nic_mac(value):
    kv, order = nic_parts(value)
    for k in order:
        if k in ('virtio', 'e1000', 'e1000e', 'rtl8139', 'vmxnet3', 'hwaddr', 'macaddr'):
            return kv[k].upper()
    return ''


def nic_with(value, bridge, tag=''):
    """The NIC value on another bridge: the tag dropped (a VNet carries its own) or put back."""
    kv, order = nic_parts(value)
    kv['bridge'] = bridge
    if 'bridge' not in order:
        order.append('bridge')
    if tag:
        kv['tag'] = str(tag)
        if 'tag' not in order:
            order.insert(order.index('bridge') + 1, 'tag')
    elif 'tag' in kv:
        order.remove('tag')
        kv.pop('tag')
    return ','.join(f'{k}={kv[k]}' if kv[k] != '' or k in ('bridge',) else k for k in order)


def moved(desktop_id):
    r = db().query_one('SELECT * FROM vlab_netseg_moved WHERE desktop_id = ?', (desktop_id,))
    return dict(r) if r else None


def moved_rows(cluster_id=None, pool_id=None, segment_id=None):
    sql, args = 'SELECT * FROM vlab_netseg_moved WHERE 1 = 1', []
    for col, val in (('cluster_id', cluster_id), ('pool_id', pool_id), ('segment_id', segment_id)):
        if val:
            sql += f' AND {col} = ?'
            args.append(val)
    return [dict(r) for r in db().query(sql, tuple(args))]


def mark_moved(desk, segment_id, nic, orig_bridge, orig_tag, vnet):
    """The first move keeps the original bridge; moving on to another segment keeps it too."""
    old = moved(desk['id'])
    if old:
        orig_bridge, orig_tag = old['orig_bridge'], old['orig_tag']
    db().execute('''INSERT INTO vlab_netseg_moved (desktop_id, cluster_id, pool_id, segment_id, node, vmid, nic, orig_bridge,
                    orig_tag, vnet, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(desktop_id) DO UPDATE SET cluster_id = excluded.cluster_id, pool_id = excluded.pool_id,
                    segment_id = excluded.segment_id, node = excluded.node, vmid = excluded.vmid, nic = excluded.nic,
                    orig_bridge = excluded.orig_bridge, orig_tag = excluded.orig_tag, vnet = excluded.vnet, at = excluded.at''',
                 (desk['id'], desk['cluster_id'], desk['pool_id'], segment_id, desk.get('node') or '', int(desk['vmid']),
                  nic, orig_bridge, str(orig_tag or ''), vnet, now()))


def forget(desktop_id):
    db().execute('DELETE FROM vlab_netseg_moved WHERE desktop_id = ?', (desktop_id,))

