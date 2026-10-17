#!/usr/bin/env python3
"""MOAVI Desk protocol benchmark - bytes on the wire per protocol, per workload, per profile.

    benchstat.py run <run_dir> [...]     one run folder (from capture.sh) -> per_second.csv, stats.csv
    benchstat.py summary <runs_root>     every run below it -> summary.csv, summary.md
    benchstat.py selftest                build a sample pcap and pcapng, parse them, check the numbers

A run folder holds capture.pcap and run.json from capture.sh and, copied from the desktop,
markers.json (the UTC window of each workload) and counters.csv (RDP counters). Without
markers.json the whole capture is one workload called "all".

Bytes are the frame length on the wire (pcap orig_len: Ethernet header included, no
preamble/FCS), so a 128-byte snaplen is enough. Each frame is put in a class by the port of
its server side (see CLASSES); "down" is server -> client, "up" is client -> server.

Python 3.8+, standard library only (no tshark/scapy needed on the machine that analyses).
"""
import argparse
import csv
import json
import math
import os
import struct
import sys
import tempfile

# class -> (transport, server ports). The first match wins, so the server side of a flow is
# whichever end has one of these ports.
CLASSES = [
    ('rdp-udp', 'udp', {3389, 3391}),          # RDP UDP transport (3391: through RD Gateway)
    ('rdp-tcp', 'tcp', {3389}),
    ('spice', 'tcp', {3128}),                  # Proxmox spiceproxy (remote-viewer goes through it)
    ('web', 'tcp', {443, 8006, 8080, 8443}),   # noVNC websocket, Guacamole, RD Gateway over HTTPS
    # other products measured on the same bench, for a like-for-like comparison
    ('blast', 'tcp', {22443}), ('blast', 'udp', {22443}),        # VMware/Omnissa Blast Extreme
    ('hdx', 'tcp', {1494, 2598}), ('hdx', 'udp', {1494, 2598}),  # Citrix HDX (ICA, CGP, EDT)
]
CLASS_NAMES = list(dict.fromkeys(c[0] for c in CLASSES)) + ['other']

# which classes count as the protocol under test (the "total" columns); "other" (DNS, ARP,
# Windows Update ...) is reported but never counted
PROTOCOL_CLASSES = {
    'rdp': ('rdp-tcp', 'rdp-udp'),
    'rdpgw': ('rdp-udp', 'web'),               # RDP through RD Gateway: HTTPS 443 + UDP 3391
    'spice': ('spice',),
    'novnc': ('web',),
    'webrdp': ('web',),
    'blast': ('blast', 'web'),                 # web: Blast through a UAG / connection server on 443
    'hdx': ('hdx', 'web'),                     # web: HDX through a Citrix Gateway on 443
}

COUNTER_FIELDS = ('fps_out', 'skip_network', 'skip_client', 'tcp_rtt_ms', 'udp_rtt_ms', 'encode_ms', 'cpu_pct')

LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL, LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_LINUX_SLL2 = 1, 101, 113, 228, 229, 276


# --- reading pcap / pcapng ---------------------------------------------------------------

def read_frames(path):
    """Yield (timestamp, wire_length, linktype, captured_bytes) from a pcap or pcapng file."""
    with open(path, 'rb') as f:
        magic = f.read(4)
        f.seek(0)
        if magic == b'\x0a\x0d\x0d\x0a':
            yield from _read_pcapng(f)
        else:
            yield from _read_pcap(f)


def _read_pcap(f):
    hdr = f.read(24)
    if len(hdr) < 24:
        raise ValueError('not a pcap file (too short)')
    magic = hdr[:4]
    table = {b'\xd4\xc3\xb2\xa1': ('<', 1e-6), b'\xa1\xb2\xc3\xd4': ('>', 1e-6),
             b'\x4d\x3c\xb2\xa1': ('<', 1e-9), b'\xa1\xb2\x3c\x4d': ('>', 1e-9)}
    if magic not in table:
        raise ValueError('not a pcap/pcapng file')
    end, frac = table[magic]
    linktype = struct.unpack(end + 'I', hdr[20:24])[0] & 0x0FFFFFFF
    rec = struct.Struct(end + 'IIII')
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        sec, sub, incl, orig = rec.unpack(h)
        data = f.read(incl)
        if len(data) < incl:
            return                              # a capture cut short by Ctrl-C
        yield sec + sub * frac, orig, linktype, data


def _read_pcapng(f):
    end = '<'
    interfaces = []                             # per section: (linktype, seconds per tick)
    while True:
        h = f.read(8)
        if len(h) < 8:
            return
        btype_raw, blen_raw = h[:4], h[4:]
        if btype_raw == b'\x0a\x0d\x0d\x0a':    # section header: byte order is in it
            bom = f.read(4)
            end = '<' if bom == b'\x4d\x3c\x2b\x1a' else '>'
            blen = struct.unpack(end + 'I', blen_raw)[0]
            f.read(blen - 12)
            interfaces = []
            continue
        btype, blen = struct.unpack(end + 'II', h)
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return
        body = body[:-4]                        # trailing block length
        if btype == 1:                          # interface description
            linktype = struct.unpack(end + 'H', body[:2])[0]
            res = 1e-6
            opts = body[8:]
            while len(opts) >= 4:
                code, olen = struct.unpack(end + 'HH', opts[:4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:     # if_tsresol
                    v = opts[4]
                    res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                opts = opts[4 + olen + (-olen % 4):]
            interfaces.append((linktype, res))
        elif btype == 6:                        # enhanced packet
            iface, ts_hi, ts_lo, incl, orig = struct.unpack(end + 'IIIII', body[:20])
            linktype, res = interfaces[iface]
            yield ((ts_hi << 32) | ts_lo) * res, orig, linktype, body[20:20 + incl]
        elif btype == 3 and interfaces:         # simple packet: no timestamp, skip
            continue


# --- decoding just enough of each frame --------------------------------------------------

def decode(linktype, data):
    """(proto, src, sport, dst, dport) for TCP/UDP over IPv4/IPv6, else None."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        etype, off = struct.unpack('!H', data[12:14])[0], 14
        while etype in (0x8100, 0x88A8) and len(data) >= off + 4:   # VLAN tags
            etype, off = struct.unpack('!H', data[off + 2:off + 4])[0], off + 4
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        etype, off = struct.unpack('!H', data[14:16])[0], 16
    elif linktype == LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return None
        etype, off = struct.unpack('!H', data[0:2])[0], 20
    elif linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if not data:
            return None
        etype, off = (0x0800 if data[0] >> 4 == 4 else 0x86DD), 0
    else:
        return None
    if etype == 0x0800:
        if len(data) < off + 20:
            return None
        ihl = (data[off] & 0x0F) * 4
        proto = data[off + 9]
        frag = struct.unpack('!H', data[off + 6:off + 8])[0] & 0x1FFF
        src, dst = _ip4(data[off + 12:off + 16]), _ip4(data[off + 16:off + 20])
        l4 = off + ihl
        if frag:                                # a later fragment carries no ports
            return ('udp' if proto == 17 else 'tcp' if proto == 6 else str(proto)), src, None, dst, None
    elif etype == 0x86DD:
        if len(data) < off + 40:
            return None
        proto = data[off + 6]
        src, dst = _ip6(data[off + 8:off + 24]), _ip6(data[off + 24:off + 40])
        l4 = off + 40
    else:
        return None
    if proto not in (6, 17) or len(data) < l4 + 4:
        return None
    sport, dport = struct.unpack('!HH', data[l4:l4 + 4])
    return ('tcp' if proto == 6 else 'udp'), src, sport, dst, dport


def _ip4(b):
    return '.'.join(str(x) for x in b)


def _ip6(b):
    return ':'.join('%x' % struct.unpack('!H', b[i:i + 2])[0] for i in range(0, 16, 2))


def classify(d, client_ip=None):
    """(class, direction) of a decoded frame; direction 'down' = towards the client."""
    proto, src, sport, dst, dport = d
    for name, transport, ports in CLASSES:
        if transport != proto:
            continue
        if sport in ports:
            return name, 'down'
        if dport in ports:
            return name, 'up'
    if client_ip:
        return 'other', ('down' if dst == client_ip else 'up')
    return 'other', 'down'


# --- one run -----------------------------------------------------------------------------

def bin_capture(pcap, client_ip=None):
    """{second (int epoch): {class: [down_bytes, up_bytes, packets]}} plus the first/last ts."""
    bins, first, last = {}, None, None
    for ts, wire, linktype, data in read_frames(pcap):
        d = decode(linktype, data)
        if d is None:
            cls, direction = 'other', 'down'
        else:
            if client_ip and client_ip not in (d[1], d[3]):
                continue
            cls, direction = classify(d, client_ip)
        first = ts if first is None else min(first, ts)
        last = ts if last is None else max(last, ts)
        sec = int(math.floor(ts))
        slot = bins.setdefault(sec, {}).setdefault(cls, [0, 0, 0])
        slot[0 if direction == 'down' else 1] += wire
        slot[2] += 1
    return bins, first, last


def windows_for(run_dir, first, last, clock_offset=0.0):
    """[(workload, start, end)] from markers.json, else the whole capture as 'all'."""
    path = os.path.join(run_dir, 'markers.json')
    if os.path.exists(path):
        with open(path, encoding='utf-8-sig') as f:
            m = json.load(f)
        out = [(w['workload'], float(w['start']) + clock_offset, float(w['end']) + clock_offset)
               for w in m.get('workloads', [])]
        if out:
            return out
    if first is None:
        return []
    return [('all', first, last)]


def percentile(values, p):
    if not values:
        return 0.0
    v = sorted(values)
    k = (len(v) - 1) * p / 100.0
    lo, hi = int(math.floor(k)), int(math.ceil(k))
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def read_counters(run_dir):
    path = os.path.join(run_dir, 'counters.csv')
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding='utf-8-sig', newline='') as f:
        for r in csv.DictReader(f):
            try:
                rows.append({k: (float(v) if v not in ('', None) else None) for k, v in r.items()})
            except ValueError:
                continue
    return rows


def counter_means(rows, start, end):
    out = {}
    sel = [r for r in rows if r.get('utc_epoch') is not None and start <= r['utc_epoch'] <= end]
    for k in COUNTER_FIELDS:
        vals = [r[k] for r in sel if r.get(k) is not None]
        out[k] = round(sum(vals) / len(vals), 2) if vals else None
    return out


def analyze_run(run_dir, clock_offset=0.0, write=True):
    with open(os.path.join(run_dir, 'run.json'), encoding='utf-8-sig') as f:
        meta = json.load(f)
    protocol = meta.get('protocol', '?')
    counted = PROTOCOL_CLASSES.get(protocol, tuple(CLASS_NAMES[:-1]))
    bins, first, last = bin_capture(os.path.join(run_dir, 'capture.pcap'), meta.get('client_ip'))
    windows = windows_for(run_dir, first, last, clock_offset)
    counters = read_counters(run_dir)

    per_second, stats = [], []
    for workload, start, end in windows:
        s0, s1 = int(math.floor(start)), int(math.ceil(end)) - 1
        # whole seconds only: a partial first/last second would read as a dip
        if end - start >= 2:
            s0, s1 = int(math.ceil(start)), int(math.floor(end)) - 1
        down_mbps, up_mbps, total_mbps = [], [], []
        cls_bytes = {c: [0, 0] for c in CLASS_NAMES}
        for sec in range(s0, s1 + 1):
            slot = bins.get(sec, {})
            row = {'workload': workload, 'utc_second': sec}
            dn = up = 0
            for c in CLASS_NAMES:
                b = slot.get(c, [0, 0, 0])
                row[c + '_down_bytes'], row[c + '_up_bytes'] = b[0], b[1]
                cls_bytes[c][0] += b[0]
                cls_bytes[c][1] += b[1]
                if c in counted:
                    dn += b[0]
                    up += b[1]
            per_second.append(row)
            down_mbps.append(dn * 8 / 1e6)
            up_mbps.append(up * 8 / 1e6)
            total_mbps.append((dn + up) * 8 / 1e6)
        n = len(total_mbps)
        udp = cls_bytes['rdp-udp'][0] + cls_bytes['rdp-udp'][1]
        rdp = udp + cls_bytes['rdp-tcp'][0] + cls_bytes['rdp-tcp'][1]
        st = {
            'run': os.path.basename(os.path.normpath(run_dir)),
            'protocol': protocol, 'profile': meta.get('profile', 'off'), 'workload': workload,
            'seconds': n,
            'down_avg_mbps': round(sum(down_mbps) / n, 3) if n else 0.0,
            'down_p95_mbps': round(percentile(down_mbps, 95), 3),
            'up_avg_mbps': round(sum(up_mbps) / n, 3) if n else 0.0,
            'total_avg_mbps': round(sum(total_mbps) / n, 3) if n else 0.0,
            'total_p95_mbps': round(percentile(total_mbps, 95), 3),
            'total_max_mbps': round(max(total_mbps), 3) if n else 0.0,
            'total_mb': round(sum(total_mbps) / 8, 3),
            'rdp_udp_share_pct': round(100.0 * udp / rdp, 1) if rdp else None,
            'other_mb': round(sum(cls_bytes['other']) / 1e6, 6),
        }
        st.update(counter_means(counters, start, end))
        stats.append(st)

    if write:
        _write_csv(os.path.join(run_dir, 'per_second.csv'), per_second,
                   ['workload', 'utc_second'] + [c + s for c in CLASS_NAMES for s in ('_down_bytes', '_up_bytes')])
        _write_csv(os.path.join(run_dir, 'stats.csv'), stats, STAT_FIELDS)
    return stats


STAT_FIELDS = ['run', 'protocol', 'profile', 'workload', 'seconds', 'down_avg_mbps', 'down_p95_mbps',
               'up_avg_mbps', 'total_avg_mbps', 'total_p95_mbps', 'total_max_mbps', 'total_mb',
               'rdp_udp_share_pct', 'other_mb'] + list(COUNTER_FIELDS)


def _write_csv(path, rows, fields):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        for r in rows:
            w.writerow({k: ('' if r.get(k) is None else r.get(k)) for k in fields})


# --- the summary over many runs ----------------------------------------------------------

PROFILE_ORDER = ['lan', 'branch', 'home', 'bad']
PROTOCOL_ORDER = ['rdp', 'rdpgw', 'spice', 'novnc', 'webrdp', 'blast', 'hdx']
WORKLOAD_ORDER = ['idle', 'scroll', 'video', '3d', 'all']


def _order(seq, v):
    return (seq.index(v), v) if v in seq else (len(seq), v)


def summarize(root, clock_offset=0.0):
    runs = sorted(os.path.dirname(os.path.join(dp, 'run.json'))
                  for dp, _, files in os.walk(root) if 'run.json' in files and 'capture.pcap' in files)
    all_stats = []
    for r in runs:
        try:
            all_stats.extend(analyze_run(r, clock_offset))
        except Exception as e:                  # one broken run must not hide the others
            print(f'skip {r}: {e}', file=sys.stderr)
    groups = {}
    for s in all_stats:
        groups.setdefault((s['profile'], s['protocol'], s['workload']), []).append(s)
    rows = []
    for (profile, protocol, workload), ss in sorted(
            groups.items(), key=lambda kv: (_order(PROFILE_ORDER, kv[0][0]), _order(PROTOCOL_ORDER, kv[0][1]),
                                            _order(WORKLOAD_ORDER, kv[0][2]))):
        def mean(k):
            v = [s[k] for s in ss if s.get(k) is not None]
            return round(sum(v) / len(v), 2) if v else None
        rows.append({
            'profile': profile, 'protocol': protocol, 'workload': workload, 'runs': len(ss),
            'seconds': sum(s['seconds'] for s in ss),
            'down_avg_mbps': mean('down_avg_mbps'), 'down_p95_mbps': mean('down_p95_mbps'),
            'up_avg_mbps': mean('up_avg_mbps'), 'total_avg_mbps': mean('total_avg_mbps'),
            'total_p95_mbps': mean('total_p95_mbps'),
            # the spread between repeats: a number with a wide range needs more runs
            'total_avg_min': round(min(s['total_avg_mbps'] for s in ss), 2),
            'total_avg_max': round(max(s['total_avg_mbps'] for s in ss), 2),
            'rdp_udp_share_pct': mean('rdp_udp_share_pct'),
            **{k: mean(k) for k in COUNTER_FIELDS},
        })
    fields = ['profile', 'protocol', 'workload', 'runs', 'seconds', 'down_avg_mbps', 'down_p95_mbps',
              'up_avg_mbps', 'total_avg_mbps', 'total_p95_mbps', 'total_avg_min', 'total_avg_max',
              'rdp_udp_share_pct'] + list(COUNTER_FIELDS)
    _write_csv(os.path.join(root, 'summary.csv'), rows, fields)
    with open(os.path.join(root, 'summary.md'), 'w', encoding='utf-8') as f:
        f.write(markdown_table(rows))
    return rows


def markdown_table(rows):
    def fmt(v):
        return '-' if v is None else (f'{v:.2f}' if isinstance(v, float) else str(v))
    head = ['프로파일', '프로토콜', '워크로드', '회', '평균 Mbps', 'p95 Mbps', '↓평균', '↑평균',
            '반복 범위', 'RDP UDP %', 'FPS', 'RTT ms']
    out = ['| ' + ' | '.join(head) + ' |', '|' + '---|' * len(head)]
    for r in rows:
        rtt = r.get('udp_rtt_ms') or r.get('tcp_rtt_ms')
        out.append('| ' + ' | '.join([
            r['profile'], r['protocol'], r['workload'], str(r['runs']), fmt(r['total_avg_mbps']),
            fmt(r['total_p95_mbps']), fmt(r['down_avg_mbps']), fmt(r['up_avg_mbps']),
            f"{fmt(r['total_avg_min'])}~{fmt(r['total_avg_max'])}", fmt(r['rdp_udp_share_pct']),
            fmt(r.get('fps_out')), fmt(rtt)]) + ' |')
    return '\n'.join(out) + '\n'


# --- self-check --------------------------------------------------------------------------

def _eth_frame(src, dst, proto, sport, dport, payload_len, v6=False):
    """An Ethernet frame with a real IPv4/IPv6 + TCP/UDP header and payload_len zero bytes."""
    l4 = struct.pack('!HHIIBBHHH', sport, dport, 1, 0, 0x50, 0x18, 65535, 0, 0) if proto == 'tcp' \
        else struct.pack('!HHHH', sport, dport, 8 + payload_len, 0)
    pnum = 6 if proto == 'tcp' else 17
    body = l4 + bytes(payload_len)
    if v6:
        ip = struct.pack('!IHBB', 0x60000000, len(body), pnum, 64) + _p6(src) + _p6(dst)
        etype = 0x86DD
    else:
        ip = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(body), 0, 0x4000, 64, pnum, 0) + \
            bytes(int(x) for x in src.split('.')) + bytes(int(x) for x in dst.split('.'))
        etype = 0x0800
    return b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + struct.pack('!H', etype) + ip + body


def _p6(a):
    head, _, tail = a.partition('::')
    h = [int(x, 16) for x in head.split(':') if x]
    t = [int(x, 16) for x in tail.split(':') if x]
    return struct.pack('!8H', *(h + [0] * (8 - len(h) - len(t)) + t))


def _sample_frames(t0):
    """Frames over 10 seconds with known totals; returns (frames, expected).

    Seconds 0-4 'scroll': RDP UDP 1000 B frames down x100/s, 100 B up x50/s; RDP TCP 200 B
    down x10/s. Seconds 5-9 'video': spice-like traffic to 3128 (must not count for rdp),
    RDP UDP 1400 B down x300/s. Plus DNS (other) every second and an IPv6 RDP frame.
    """
    C, S = '10.9.0.50', '10.9.0.10'
    frames = []
    for s in range(10):
        for i in range(100 if s < 5 else 300):
            frames.append((t0 + s + i / 1000.0, _eth_frame(S, C, 'udp', 3389, 50000, 1000 - 42 if s < 5 else 1400 - 42)))
        if s < 5:
            for i in range(50):
                frames.append((t0 + s + 0.5 + i / 1000.0, _eth_frame(C, S, 'udp', 50000, 3389, 100 - 42)))
            for i in range(10):
                frames.append((t0 + s + 0.7 + i / 1000.0, _eth_frame(S, C, 'tcp', 3389, 50001, 200 - 54)))
        else:
            frames.append((t0 + s + 0.8, _eth_frame(S, C, 'tcp', 3128, 50002, 5000 - 54)))
        frames.append((t0 + s + 0.9, _eth_frame(C, '10.9.0.1', 'udp', 53000, 53, 80 - 42)))
    # an IPv6 RDP frame and one not involving the client (must be ignored)
    frames.append((t0 + 2.95, _eth_frame('fd00::10', 'fd00::50', 'udp', 3389, 50000, 0, v6=True)))
    frames.append((t0 + 3.95, _eth_frame('10.9.0.77', '10.9.0.78', 'tcp', 3389, 50003, 9000)))
    frames.sort()
    scroll_down = 5 * (100 * 1000 + 10 * 200)
    scroll_up = 5 * 50 * 100
    video_down = 5 * 300 * 1400
    expected = {
        'scroll': {'total_mb': (scroll_down + scroll_up) / 1e6, 'down_avg_mbps': scroll_down * 8 / 1e6 / 5,
                   'up_avg_mbps': scroll_up * 8 / 1e6 / 5, 'seconds': 5,
                   'rdp_udp_share_pct': round(100.0 * (5 * 100 * 1000 + scroll_up) / (scroll_down + scroll_up), 1)},
        'video': {'total_mb': video_down / 1e6, 'down_avg_mbps': video_down * 8 / 1e6 / 5, 'up_avg_mbps': 0.0,
                  'seconds': 5, 'rdp_udp_share_pct': 100.0},
    }
    return frames, expected


def _write_pcap(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 128, LINKTYPE_ETHERNET))
        for ts, fr in frames:
            sec, usec = int(ts), int(round((ts - int(ts)) * 1e6))
            cap = fr[:128]                       # what tcpdump -s 128 keeps
            f.write(struct.pack('<IIII', sec, usec, len(cap), len(fr)) + cap)


def _write_pcapng(path, frames):
    def block(btype, body):
        body += bytes(-len(body) % 4)
        n = len(body) + 12
        return struct.pack('<II', btype, n) + body + struct.pack('<I', n)
    with open(path, 'wb') as f:
        f.write(block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        # nanosecond resolution (if_tsresol = 9), as newer tcpdump/dumpcap may write
        f.write(block(1, struct.pack('<HHI', LINKTYPE_ETHERNET, 0, 128) +
                      struct.pack('<HHB3x', 9, 1, 9) + struct.pack('<HH', 0, 0)))
        for ts, fr in frames:
            t = int(round(ts * 1e9))
            cap = fr[:128]
            f.write(block(6, struct.pack('<IIIII', 0, t >> 32, t & 0xFFFFFFFF, len(cap), len(fr)) + cap))


def selftest():
    t0 = 1792200000.0
    frames, expected = _sample_frames(t0)
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        for kind, writer in (('pcap', _write_pcap), ('pcapng', _write_pcapng)):
            run = os.path.join(tmp, 'runs', f'sample_{kind}_rdp_home')
            os.makedirs(run)
            writer(os.path.join(run, 'capture.pcap'), frames)
            with open(os.path.join(run, 'run.json'), 'w') as f:
                json.dump({'protocol': 'rdp', 'profile': 'home', 'client_ip': '10.9.0.50',
                           'capture_start': t0, 'capture_stop': t0 + 10}, f)
            with open(os.path.join(run, 'markers.json'), 'w', encoding='utf-8-sig') as f:   # PowerShell's BOM
                json.dump({'workloads': [{'workload': 'scroll', 'start': t0, 'end': t0 + 5},
                                         {'workload': 'video', 'start': t0 + 5, 'end': t0 + 10}]}, f)
            with open(os.path.join(run, 'counters.csv'), 'w', newline='') as f:
                f.write('utc_epoch,' + ','.join(COUNTER_FIELDS) + '\n')
                for s in range(10):
                    f.write(f'{t0 + s + 0.5},{30 if s < 5 else 20},0,0,52,51,4,10\n')
            got = {s['workload']: s for s in analyze_run(run)}
            for wl, exp in expected.items():
                for k, v in exp.items():
                    g = got.get(wl, {}).get(k)
                    if g is None or abs(g - v) > 1e-3 * max(1.0, abs(v)):
                        failures.append(f'{kind} {wl} {k}: got {g}, expected {v}')
            if got.get('scroll', {}).get('fps_out') != 30.0:
                failures.append(f"{kind} scroll fps_out: got {got.get('scroll', {}).get('fps_out')}, expected 30.0")
            if not got.get('video', {}).get('other_mb'):
                failures.append(f'{kind}: DNS frames should show as other_mb')
        d6 = decode(LINKTYPE_ETHERNET, _eth_frame('fd00::10', 'fd00::50', 'udp', 3389, 50000, 0, v6=True))
        if d6 != ('udp', 'fd00:0:0:0:0:0:0:10', 3389, 'fd00:0:0:0:0:0:0:50', 50000):
            failures.append(f'IPv6 decode: {d6}')
        rows = summarize(os.path.join(tmp, 'runs'))
        if len(rows) != 2 or rows[0]['runs'] != 2:
            failures.append(f'summary: expected 2 rows of 2 runs, got {[(r["workload"], r["runs"]) for r in rows]}')
        with open(os.path.join(tmp, 'runs', 'summary.md'), encoding='utf-8') as f:
            md = f.read()
    if failures:
        print('SELFTEST FAILED')
        for x in failures:
            print('  ' + x)
        return 1
    print('selftest ok: pcap + pcapng parsed, classes, directions, markers, counters and summary check out')
    print(md)
    return 0


def main(argv=None):
    if hasattr(sys.stdout, 'reconfigure'):      # the Korean table on a cp949 / C-locale console
        sys.stdout.reconfigure(errors='replace')
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('run', help='analyse run folders')
    p.add_argument('run_dir', nargs='+')
    p.add_argument('--clock-offset', type=float, default=0.0,
                   help='seconds to add to the desktop timestamps (desktop clock behind the emulator: positive)')
    p = sub.add_parser('summary', help='analyse every run below a folder and build the summary table')
    p.add_argument('root')
    p.add_argument('--clock-offset', type=float, default=0.0)
    sub.add_parser('selftest', help='parse a generated sample pcap/pcapng and check the numbers')
    a = ap.parse_args(argv)
    if a.cmd == 'selftest':
        return selftest()
    if a.cmd == 'run':
        for d in a.run_dir:
            for s in analyze_run(d, a.clock_offset):
                print(f"{s['run']}  {s['workload']:<7} {s['seconds']:>4} s  avg {s['total_avg_mbps']:8.3f} Mbps  "
                      f"p95 {s['total_p95_mbps']:8.3f}  down {s['down_avg_mbps']:8.3f}  up {s['up_avg_mbps']:7.3f}"
                      + (f"  udp {s['rdp_udp_share_pct']}%" if s['rdp_udp_share_pct'] is not None else ''))
        return 0
    rows = summarize(a.root, a.clock_offset)
    print(markdown_table(rows))
    return 0


if __name__ == '__main__':
    sys.exit(main())
