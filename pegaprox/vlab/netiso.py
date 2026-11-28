# -*- coding: utf-8 -*-
"""
네트워크 격리 (MAKUS): a pool's desktops reachable only through the MOAVI gateway.

The pool policy says what (net_isolation, net_peers, net_allow_in, net_egress, net_allow_out;
pegaprox/vlab/policy.py); this module says how, in the Proxmox firewall, so nothing inside a
desktop can undo it:

  cluster   ipset vlab-gw        the gateway's addresses (rdpgw, Warpgate, the engine: what the
                                 desktops see the MOAVI server come from), set per cluster here
            ipset vlabd-<h>      the pool's desktops' addresses (guest agent), for net_peers
            group vlab-<h>       the pool's rules: IN from +vlab-gw, from +vlabd-<h> with
                                 net_peers, net_allow_in; with net_egress 'list' also OUT to
                                 those and net_allow_out
  desktop   netN firewall=1, a GROUP vlab-<h> rule (comment vlab-netiso), options enable,
            policy_in DROP, policy_out DROP with 'list', dhcp and ndp on

<h> is the first 8 hex digits of sha1(pool id): Proxmox keeps group names to 18 characters.
Rules, ipsets and groups with other names are the operator's and are never touched. The
datacenter firewall must be on for any of it to filter: reported, never changed here (turning
it on decides the nodes' own traffic too).

Applying is pegaprox/api/vlab_netiso.py (the minute loop and 지금 적용).
"""

import hashlib
import ipaddress
import json
import threading

from pegaprox.vlab.store import db as _store_db, now

TAG = 'vlab-netiso'
GW_IPSET = 'vlab-gw'
GATEWAY_MAX = 20

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_netiso (
        cluster_id TEXT PRIMARY KEY,
        gateway_sources TEXT NOT NULL DEFAULT '[]',
        updated_at TEXT NOT NULL,
        updated_by TEXT NOT NULL DEFAULT ''
    )''',
    '''CREATE TABLE IF NOT EXISTS vlab_netiso_applied (
        desktop_id TEXT PRIMARY KEY,
        cluster_id TEXT NOT NULL,
        pool_id TEXT NOT NULL,
        node TEXT NOT NULL DEFAULT '',
        vmid INTEGER NOT NULL,
        vm_type TEXT NOT NULL DEFAULT 'qemu',
        enabled_by_us INTEGER NOT NULL DEFAULT 0,
        at TEXT NOT NULL
    )''',
)
TABLES = ('vlab_netiso', 'vlab_netiso_applied')

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_netiso', False):
        with _lock:
            if not getattr(d, '_vlab_netiso', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_netiso = True
    return d


# --- names -------------------------------------------------------------------------------------

def _h(pool_id):
    return hashlib.sha1(str(pool_id).encode('utf-8')).hexdigest()[:8]


def group_name(pool_id):
    return f'vlab-{_h(pool_id)}'


def ipset_name(pool_id):
    return f'vlabd-{_h(pool_id)}'


# --- the gateway's addresses, per cluster --------------------------------------------------------

def clean_sources(v):
    """([cidr], None) or (None, error): IPv4 / IPv6 addresses or networks, at most GATEWAY_MAX."""
    if not isinstance(v, list) or len(v) > GATEWAY_MAX:
        return None, f'gateway_sources: a list of at most {GATEWAY_MAX}'
    out = []
    for x in v:
        try:
            net = ipaddress.ip_network(str(x).strip(), strict=False)
        except ValueError:
            return None, f"gateway_sources: '{x}' is not an address or network"
        if net.prefixlen == 0:
            return None, 'gateway_sources: 0.0.0.0/0 would let everyone in'
        c = str(net) if net.num_addresses > 1 else str(net.network_address)
        if c not in out:
            out.append(c)
    return out, None


def gateway_sources(cluster_id):
    r = db().query_one('SELECT gateway_sources FROM vlab_netiso WHERE cluster_id = ?', (cluster_id,))
    try:
        v = json.loads(r['gateway_sources']) if r else []
    except (TypeError, ValueError):
        v = []
    return v if isinstance(v, list) else []


def set_gateway_sources(cluster_id, sources, by=''):
    db().execute('''INSERT INTO vlab_netiso (cluster_id, gateway_sources, updated_at, updated_by) VALUES (?, ?, ?, ?)
                    ON CONFLICT(cluster_id) DO UPDATE SET gateway_sources = excluded.gateway_sources,
                    updated_at = excluded.updated_at, updated_by = excluded.updated_by''',
                 (cluster_id, json.dumps(sources), now(), by))


def suggested_sources(hosts):
    """The literal IP addresses among the gateway's host names (rdpgw, Warpgate): a first
    suggestion for the console. Names are not looked up here."""
    out = []
    for h in hosts:
        h = (h or '').strip().strip('[]')
        try:
            ip = str(ipaddress.ip_address(h))
        except ValueError:
            continue
        if ip not in out:
            out.append(ip)
    return out


# --- what the pool's group holds -----------------------------------------------------------------

def _rule(direction, peer_field, peer, proto='any', port='', note='', action='ACCEPT'):
    r = {'type': direction, 'action': action, 'enable': 1, peer_field: peer}
    if proto != 'any':
        r['proto'] = proto
    if port:
        r['dport'] = port
    r['comment'] = f'{TAG}{": " + note if note else ""}'[:100]
    return r


def peer_of(r):
    """A policy rule's other side as Proxmox names it: another pool's ipset, or the address."""
    return f"+{ipset_name(r['pool'])}" if r.get('pool') else r['cidr']


def peer_pools(pol):
    """The pool ids the pool's rules name (their ipsets must exist in the cluster)."""
    return sorted({r['pool'] for k in ('net_allow_in', 'net_allow_out') for r in pol.get(k) or [] if r.get('pool')})


def group_rules(pool_id, pol):
    """The group's rules, top first, as Proxmox takes them (POST .../groups/<group>): the gateway
    first (nothing a rule says cuts the users off), then the drop rules (차단), then the accepts."""
    peers = f'+{ipset_name(pool_id)}'

    def own(direction, key, drop):
        field = 'source' if direction == 'in' else 'dest'
        return [_rule(direction, field, peer_of(r), r['proto'], r['port'], r.get('note', ''), 'DROP' if drop else 'ACCEPT')
                for r in pol.get(key) or [] if (r.get('action') == 'drop') == drop]
    rules = [_rule('in', 'source', f'+{GW_IPSET}', note='MOAVI gateway')]
    rules += own('in', 'net_allow_in', True)
    if pol.get('net_peers'):
        rules.append(_rule('in', 'source', peers, note='same pool'))
    rules += own('in', 'net_allow_in', False)
    rules += own('out', 'net_allow_out', True)          # with egress 'any' these are what stops traffic out
    if pol.get('net_egress') == 'list':
        rules.append(_rule('out', 'dest', f'+{GW_IPSET}', note='MOAVI gateway'))
        if pol.get('net_peers'):
            rules.append(_rule('out', 'dest', peers, note='same pool'))
        rules += own('out', 'net_allow_out', False)
    return rules


_RULE_KEYS = ('type', 'action', 'source', 'dest', 'proto', 'dport', 'comment')


def rule_key(r):
    """A rule as Proxmox lists it, compared with what group_rules wants."""
    def val(k):
        v = str(r.get(k) or '')
        return '+' + v[4:] if v.startswith('+dc/') else v       # PVE 8.2+ may list a datacenter ipset as +dc/<name>
    return tuple(val(k) for k in _RULE_KEYS) + (str(int(r.get('enable', 1) or 0)),)


def vm_options(pol):
    return {'enable': 1, 'policy_in': 'DROP', 'policy_out': 'DROP' if pol.get('net_egress') == 'list' else 'ACCEPT',
            'dhcp': 1, 'ndp': 1}


def with_firewall(net_value):
    """A netN value with firewall=1 (None when it already has it)."""
    parts = [p for p in str(net_value).split(',') if p]
    if 'firewall=1' in parts:
        return None
    parts = [p for p in parts if not p.startswith('firewall=')]
    return ','.join(parts + ['firewall=1'])


def ipv4s(ips):
    out = []
    for ip in ips or []:
        try:
            a = ipaddress.ip_address(str(ip))
        except ValueError:
            continue
        if a.version == 4 and not a.is_loopback and not a.is_link_local and str(a) not in out:
            out.append(str(a))
    return out


# --- desktops the firewall was put on ------------------------------------------------------------

def applied(desktop_id):
    return db().query_one('SELECT * FROM vlab_netiso_applied WHERE desktop_id = ?', (desktop_id,))


def applied_rows(cluster_id=None, pool_id=None):
    sql, args = 'SELECT * FROM vlab_netiso_applied WHERE 1 = 1', []
    if cluster_id:
        sql += ' AND cluster_id = ?'
        args.append(cluster_id)
    if pool_id:
        sql += ' AND pool_id = ?'
        args.append(pool_id)
    return db().query(sql, tuple(args))


def mark_applied(desk, enabled_by_us):
    db().execute('''INSERT INTO vlab_netiso_applied (desktop_id, cluster_id, pool_id, node, vmid, vm_type, enabled_by_us, at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(desktop_id) DO UPDATE SET cluster_id = excluded.cluster_id, pool_id = excluded.pool_id,
                    node = excluded.node, vmid = excluded.vmid, vm_type = excluded.vm_type,
                    enabled_by_us = MAX(vlab_netiso_applied.enabled_by_us, excluded.enabled_by_us), at = excluded.at''',
                 (desk['id'], desk['cluster_id'], desk['pool_id'], desk.get('node') or '', int(desk['vmid']),
                  desk.get('vm_type') or 'qemu', 1 if enabled_by_us else 0, now()))


def forget(desktop_id):
    db().execute('DELETE FROM vlab_netiso_applied WHERE desktop_id = ?', (desktop_id,))
