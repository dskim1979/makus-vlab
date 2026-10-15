# -*- coding: utf-8 -*-
"""
sFlow collector (MAKUS) - who talks to whom on the cluster networks.

Proxmox nodes export sFlow v5 (hsflowd, or Open vSwitch `sflow`) to this server on
UDP 6343. Every flow sample carries the first bytes of a sampled packet; this module
reads the Ethernet / VLAN / IPv4 / IPv6 / TCP / UDP headers out of it, scales bytes and
packets by the sampling rate, and adds them up per conversation:

    (client, server, protocol, service port)

The service port is the lower of the two ports when it is below 49152 (else the
destination port), and the side that owns it is the server, so both directions of one
conversation land on the same row.

  * in memory: one bucket per minute for the last hour (live view)
  * on disk (flows.db, SQLCipher when the main DB is encrypted): one row per
    conversation per hour, kept FLOW_RETENTION_DAYS (default 7)

Off by default: the port opens only after an admin turns it on (Settings key
'sflow_collector'). Datagrams are accepted only from the agents allowed there, or -
when that list is empty - from the addresses of the nodes of connected clusters.
Memory is bounded (keys per bucket, datagram size); a flood drops instead of growing.
"""

import ipaddress
import logging
import os
import struct
import threading
import time
from datetime import datetime, timedelta

from pegaprox.constants import CONFIG_DIR
from pegaprox.core import dbcrypto

SETTINGS_KEY = 'sflow_collector'
DEFAULTS = {'enabled': False, 'port': 6343, 'allowed_agents': [], 'retention_days': 7}
DB_FILE = os.path.join(CONFIG_DIR, 'flows.db')

MAX_KEYS_PER_MINUTE = int(os.environ.get('MAKUS_FLOW_MAX_KEYS', '5000'))
MAX_KEYS_PER_HOUR = int(os.environ.get('MAKUS_FLOW_MAX_KEYS_HOUR', '20000'))
MAX_DATAGRAM = 65535
EPHEMERAL = 49152

_lock = threading.Lock()
_minutes = {}       # 'YYYY-mm-ddTHH:MM' -> {key: [bytes, packets]}
_hour_key = None    # 'YYYY-mm-ddTHH'
_hour = {}          # current hour, flushed to the DB every minute
_stats = {'datagrams': 0, 'samples': 0, 'dropped_agent': 0, 'parse_errors': 0, 'overflow': 0,
          'agents': {}, 'started_at': None, 'listening': False, 'port': None, 'error': ''}
_thread = None
_stop = threading.Event()
_sock = None
_node_ips = {'at': 0.0, 'ips': set()}


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

class _Reader:
    __slots__ = ('b', 'i')

    def __init__(self, b, i=0):
        self.b = b
        self.i = i

    def u32(self):
        if self.i + 4 > len(self.b):
            raise ValueError('short')
        v = struct.unpack_from('>I', self.b, self.i)[0]
        self.i += 4
        return v

    def take(self, n):
        if n < 0 or self.i + n > len(self.b):
            raise ValueError('short')
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def skip_padded(self, n):
        self.take((n + 3) & ~3)


def _ports(proto, data, off):
    if proto in (6, 17, 132) and len(data) >= off + 4:
        return struct.unpack_from('>HH', data, off)
    return None, None


def parse_header(data):
    """Ethernet frame bytes -> (src, dst, proto, sport, dport) or None."""
    if len(data) < 14:
        return None
    etype = struct.unpack_from('>H', data, 12)[0]
    off = 14
    while etype in (0x8100, 0x88A8) and len(data) >= off + 4:   # VLAN / QinQ
        etype = struct.unpack_from('>H', data, off + 2)[0]
        off += 4
    if etype == 0x0800 and len(data) >= off + 20:
        ihl = (data[off] & 0x0F) * 4
        proto = data[off + 9]
        frag = struct.unpack_from('>H', data, off + 6)[0] & 0x1FFF
        src = str(ipaddress.IPv4Address(data[off + 12:off + 16]))
        dst = str(ipaddress.IPv4Address(data[off + 16:off + 20]))
        sp, dp = _ports(proto, data, off + ihl) if frag == 0 else (None, None)
        return src, dst, proto, sp, dp
    if etype == 0x86DD and len(data) >= off + 40:
        proto = data[off + 6]
        src = str(ipaddress.IPv6Address(data[off + 8:off + 24]))
        dst = str(ipaddress.IPv6Address(data[off + 24:off + 40]))
        sp, dp = _ports(proto, data, off + 40)
        return src, dst, proto, sp, dp
    return None


def conversation(src, dst, proto, sp, dp):
    """-> (client, server, proto, port): the side that owns the service port is the server."""
    if sp is None or dp is None:
        return src, dst, proto, 0
    low = min(sp, dp)
    svc = low if low < EPHEMERAL else dp
    if svc == dp:
        return src, dst, proto, dp
    return dst, src, proto, sp


def parse_datagram(data):
    """sFlow v5 datagram -> (agent, [(src, dst, proto, sport, dport, bytes, packets)])."""
    r = _Reader(data)
    if r.u32() != 5:
        raise ValueError('not sFlow v5')
    at = r.u32()
    if at == 1:
        agent = str(ipaddress.IPv4Address(r.take(4)))
    elif at == 2:
        agent = str(ipaddress.IPv6Address(r.take(16)))
    else:
        raise ValueError('agent address')
    r.u32(); r.u32(); r.u32()                       # sub agent, sequence, uptime
    n = r.u32()
    out = []
    for _ in range(min(n, 1000)):
        fmt = r.u32()
        length = r.u32()
        body = _Reader(r.take(length))
        enterprise, kind = fmt >> 12, fmt & 0xFFF
        if enterprise != 0 or kind not in (1, 3):
            continue                                # counter samples and vendor formats
        body.u32()                                  # sequence
        if kind == 1:
            body.u32()                              # source id
        else:
            body.u32(); body.u32()                  # source id type, index
        rate = max(1, body.u32())
        body.u32(); body.u32()                      # pool, drops
        if kind == 1:
            body.u32(); body.u32()                  # input, output
        else:
            body.u32(); body.u32(); body.u32(); body.u32()
        for _ in range(min(body.u32(), 64)):
            rfmt = body.u32()
            rlen = body.u32()
            rec = _Reader(body.take(rlen))
            if rfmt != 1:                           # 1 = raw packet header
                continue
            if rec.u32() != 1:                      # 1 = Ethernet
                continue
            frame_len = rec.u32()
            rec.u32()                               # stripped
            hlen = rec.u32()
            hdr = rec.take(min(hlen, len(rec.b) - rec.i))
            p = parse_header(hdr)
            if p:
                out.append((*p, frame_len * rate, rate))
    return agent, out


# ---------------------------------------------------------------------------
# aggregation
# ---------------------------------------------------------------------------

def _add(bucket, key, nbytes, npk, cap):
    cur = bucket.get(key)
    if cur is None:
        if len(bucket) >= cap:
            _stats['overflow'] += 1
            return
        bucket[key] = [nbytes, npk]
    else:
        cur[0] += nbytes
        cur[1] += npk


def ingest(agent, flows, now=None):
    global _hour_key, _hour
    now = now or datetime.now()
    mk = now.strftime('%Y-%m-%dT%H:%M')
    hk = now.strftime('%Y-%m-%dT%H')
    with _lock:
        a = _stats['agents'].setdefault(agent, {'datagrams': 0, 'last': None})
        a['datagrams'] += 1
        a['last'] = now.isoformat(timespec='seconds')
        if _hour_key != hk:
            if _hour_key and _hour:
                _pending_hours.append((_hour_key, _hour))
            _hour_key, _hour = hk, {}
        bucket = _minutes.setdefault(mk, {})
        for src, dst, proto, sp, dp, nbytes, npk in flows:
            key = conversation(src, dst, proto, sp, dp)
            _add(bucket, key, nbytes, npk, MAX_KEYS_PER_MINUTE)
            _add(_hour, key, nbytes, npk, MAX_KEYS_PER_HOUR)
        _stats['samples'] += len(flows)
        cutoff = (now - timedelta(minutes=61)).strftime('%Y-%m-%dT%H:%M')
        for k in [k for k in _minutes if k < cutoff]:
            del _minutes[k]


_pending_hours = []


def _rows(bucket):
    rows = [{'client': k[0], 'server': k[1], 'proto': k[2], 'port': k[3], 'bytes': v[0], 'packets': v[1]} for k, v in bucket.items()]
    rows.sort(key=lambda x: x['bytes'], reverse=True)
    return rows


def recent(minutes=60):
    """Conversations of the last `minutes` (<= 60) from memory."""
    cutoff = (datetime.now() - timedelta(minutes=max(1, min(60, minutes)))).strftime('%Y-%m-%dT%H:%M')
    total = {}
    with _lock:
        for k, bucket in _minutes.items():
            if k >= cutoff:
                for key, (b, p) in bucket.items():
                    cur = total.setdefault(key, [0, 0])
                    cur[0] += b
                    cur[1] += p
    return _rows(total)


def history(hours=24):
    """Conversations of the last `hours` from the hourly table (current hour included)."""
    flush()
    since = (datetime.now() - timedelta(hours=max(1, min(24 * 31, hours)))).strftime('%Y-%m-%dT%H')
    conn = _open_db()
    try:
        cur = conn.execute(
            'SELECT client, server, proto, port, SUM(bytes), SUM(packets) FROM flows_hourly '
            'WHERE hour >= ? GROUP BY client, server, proto, port ORDER BY SUM(bytes) DESC LIMIT 20000', (since,))
        return [{'client': a, 'server': b, 'proto': c, 'port': d, 'bytes': e, 'packets': f} for a, b, c, d, e, f in cur.fetchall()]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------

def _open_db():
    conn = dbcrypto.connect(DB_FILE, timeout=30)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('''CREATE TABLE IF NOT EXISTS flows_hourly (
        hour TEXT NOT NULL, client TEXT NOT NULL, server TEXT NOT NULL, proto INTEGER NOT NULL,
        port INTEGER NOT NULL, bytes INTEGER NOT NULL, packets INTEGER NOT NULL,
        PRIMARY KEY (hour, client, server, proto, port))''')
    return conn


def flush():
    """Write the current hour (and any finished one) to the DB, prune old hours."""
    with _lock:
        items = list(_pending_hours)
        _pending_hours.clear()
        if _hour_key and _hour:
            items.append((_hour_key, {k: list(v) for k, v in _hour.items()}))
    if not items:
        return
    conn = _open_db()
    try:
        for hk, bucket in items:
            conn.executemany(
                'INSERT OR REPLACE INTO flows_hourly (hour, client, server, proto, port, bytes, packets) VALUES (?,?,?,?,?,?,?)',
                [(hk, k[0], k[1], k[2], k[3], int(v[0]), int(v[1])) for k, v in bucket.items()])
        days = max(1, min(90, int(settings().get('retention_days') or 7)))
        conn.execute('DELETE FROM flows_hourly WHERE hour < ?', ((datetime.now() - timedelta(days=days)).strftime('%Y-%m-%dT%H'),))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# settings, allowed agents
# ---------------------------------------------------------------------------

def settings():
    from pegaprox.core.db import get_db
    raw = get_db().get_server_setting(SETTINGS_KEY, {})
    return {**DEFAULTS, **(raw if isinstance(raw, dict) else {})}


def _cluster_node_ips():
    """Addresses of the nodes of connected clusters (refreshed every 5 minutes)."""
    if time.monotonic() - _node_ips['at'] < 300 and _node_ips['ips']:
        return _node_ips['ips']
    ips = set()
    try:
        from pegaprox.globals import cluster_managers
        for mgr in list(cluster_managers.values()):
            for h in [getattr(mgr, 'host', '')] + list(getattr(getattr(mgr, 'config', None), 'fallback_hosts', None) or []):
                if h:
                    ips.add(str(h).split(':')[0].strip('[]'))
            for n in list((getattr(mgr, 'nodes', None) or {}).values()):
                ip = n.get('ip') if isinstance(n, dict) else None
                if ip:
                    ips.add(str(ip))
    except Exception as e:
        logging.debug(f'[sflow] node addresses: {e}')
    _node_ips.update(at=time.monotonic(), ips=ips)
    return ips


def agent_allowed(agent_ip, cfg):
    allowed = [str(a).strip() for a in (cfg.get('allowed_agents') or []) if str(a).strip()]
    if allowed:
        for a in allowed:
            try:
                if ipaddress.ip_address(agent_ip) in ipaddress.ip_network(a, strict=False):
                    return True
            except ValueError:
                continue
        return False
    return agent_ip in _cluster_node_ips()


# ---------------------------------------------------------------------------
# listener
# ---------------------------------------------------------------------------

def _udp_listener(port, cfg):
    import socket
    global _sock
    sock = socket.socket(socket.AF_INET6 if socket.has_ipv6 else socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if sock.family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind(('::', port))
        else:
            sock.bind(('0.0.0.0', port))
    except OSError as e:
        _stats['error'] = f'bind {port}: {e}'
        logging.warning(f'[sflow] cannot listen on UDP {port}: {e}')
        return
    _sock = sock
    _stats.update(listening=True, port=port, error='', started_at=datetime.now().isoformat(timespec='seconds'))
    logging.info(f'[sflow] collector listening on UDP {port}')
    while not _stop.is_set():
        try:
            data, addr = sock.recvfrom(MAX_DATAGRAM)
        except Exception:
            if _stop.is_set():
                break
            time.sleep(0.1)
            continue
        src = addr[0][7:] if addr[0].startswith('::ffff:') else addr[0]
        _stats['datagrams'] += 1
        if not agent_allowed(src, cfg):
            _stats['dropped_agent'] += 1
            continue
        try:
            _agent, flows = parse_datagram(data)
            ingest(src, flows)
        except Exception:
            _stats['parse_errors'] += 1
    _stats['listening'] = False


def _flush_loop():
    import gevent
    while not _stop.is_set():
        gevent.sleep(60)
        try:
            from gevent import get_hub
            get_hub().threadpool.apply(flush)
        except Exception as e:
            logging.warning(f'[sflow] flush failed: {e}')


def _collector_loop(cfg):
    import gevent
    port = int(cfg.get('port') or 6343)
    gevent.spawn(_flush_loop)
    gevent.joinall([gevent.spawn(_udp_listener, port, cfg)])


def start_sflow_collector():
    """Start the collector when it is enabled (called at startup and after a config change)."""
    global _thread
    cfg = settings()
    if not cfg.get('enabled'):
        logging.info('[sflow] collector disabled - UDP port stays closed')
        return False
    if _thread is not None and _thread.is_alive():
        return True
    _stop.clear()
    _thread = threading.Thread(target=_collector_loop, args=(cfg,), daemon=True, name='sflow-collector')
    _thread.start()
    return True


def stop_sflow_collector():
    global _thread, _sock
    _stop.set()
    if _sock is not None:
        try:
            _sock.close()
        except Exception:
            pass
        _sock = None
    if _thread is not None:
        _thread.join(timeout=5)
    _thread = None
    _stats['listening'] = False
    try:
        flush()
    except Exception:
        pass


def status():
    with _lock:
        agents = {k: dict(v) for k, v in _stats['agents'].items()}
    return {k: v for k, v in _stats.items() if k != 'agents'} | {'agents': agents}
