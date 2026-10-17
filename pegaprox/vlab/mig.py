# -*- coding: utf-8 -*-
"""
MOAVI Desk - NVIDIA MIG (Multi-Instance GPU) on the nodes (GPU · FPGA · NPU > GPU · 가속 카드 재고).

A100 / A30 / H100 / H200 (and Blackwell B200) cards split into up to seven GPU instances, each
with its own memory and SMs (profiles '1g.10gb', '3g.40gb', ...). What the engine reads and does:

  * read: one SSH command per node (the core's guarded node path, PegaProxManager._node_ssh_exec)
    runs NODE_SCRIPT - nvidia-smi's GPU list with the driver and MIG mode (current / pending),
    the host vGPU mode, and the GPU instance profiles, GPU instances and compute instances.
    parse_node() turns that into {driver, vgpu_manager, gpus: [...]}.
  * write: MIG mode on / off and the GPU instance layout of one card (mode_command,
    layout_command), only while no running VM on the node uses an NVIDIA card (busy_vms) -
    the route asks for the node's name typed back, confirms the HA lease and writes the audit.

How a MIG instance reaches a desktop on Proxmox: MIG devices are not PCI devices, so they cannot
be passed through (VFIO) on their own. What works is MIG-backed vGPU: the host runs NVIDIA's vGPU
manager (NVIDIA AI Enterprise / vGPU C-series), MIG mode is on, GPU instances are made here, and
the pool's GPU policy picks a MIG-backed vGPU profile ('A100-3-20C', 'H100-1-10C') on a mapping of
the card's SR-IOV virtual functions. A whole card can still be passed through; MIG inside that VM
is then the guest's business and the card is not shared between desktops.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).
"""

import re
import threading
import time

# MIG-capable NVIDIA cards, by model name (nvidia-smi / pci.ids)
MIG_MODEL = re.compile(r'\b(A100|A800|A30|H100|H800|H200|H20|GH200|B200|B100|GB200|RTX PRO 6000)\b', re.I)
# MIG-backed vGPU profile names: A100-1-5C, A100D-3-40C, H100XM-1-10C, A30-1-6CME, H100-1-10C
MIG_VGPU = re.compile(r'-(\d)-(\d+)C(ME)?$', re.I)

# The GPU instance profiles of the common cards (NVIDIA MIG user guide), shown when a node cannot
# be read; writes use only what the node itself lists.
REFERENCE = {
    'A100 40GB': ['1g.5gb x7', '1g.10gb x4', '2g.10gb x3', '3g.20gb x2', '4g.20gb x1', '7g.40gb x1'],
    'A100 80GB': ['1g.10gb x7', '1g.20gb x4', '2g.20gb x3', '3g.40gb x2', '4g.40gb x1', '7g.80gb x1'],
    'A30 24GB': ['1g.6gb x4', '2g.12gb x2', '4g.24gb x1'],
    'H100 80GB': ['1g.10gb x7', '1g.20gb x4', '2g.20gb x3', '3g.40gb x2', '4g.40gb x1', '7g.80gb x1'],
    'H100 94GB (NVL)': ['1g.12gb x7', '1g.24gb x4', '2g.24gb x3', '3g.47gb x2', '4g.47gb x1', '7g.94gb x1'],
    'H200 141GB': ['1g.18gb x7', '1g.35gb x4', '2g.35gb x3', '3g.71gb x2', '4g.71gb x1', '7g.141gb x1'],
}

NODE_SCRIPT = r'''
if command -v nvidia-smi >/dev/null 2>&1; then
echo @@gpus; nvidia-smi --query-gpu=index,pci.bus_id,name,driver_version,mig.mode.current,mig.mode.pending,memory.total --format=csv,noheader,nounits 2>&1
echo @@vgpu; nvidia-smi -q 2>/dev/null | grep -iE 'Host VGPU Mode|Virtualization Mode' | head -16
echo @@gip; nvidia-smi mig -lgip 2>&1
echo @@gi; nvidia-smi mig -lgi 2>&1
echo @@ci; nvidia-smi mig -lci 2>&1
else echo @@none; fi
echo @@end
'''

# root for the writes: the node login may be a sudo user (pegaprox@pam)
_SUDO = 'S=; [ "$(id -u)" = 0 ] || S="sudo -n"; '


def is_mig_model(name):
    return bool(MIG_MODEL.search(str(name or '')))


def vgpu_profile_slices(name):
    """MIG-backed vGPU profile -> its number of compute slices ('A100-3-20C' -> 3), else None."""
    m = MIG_VGPU.search(str(name or '').strip())
    return int(m.group(1)) if m else None


def short_bus(bus_id):
    """'00000000:41:00.0' -> '0000:41:00.0'."""
    b = str(bus_id or '').strip().lower()
    m = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}\.[0-7])$', b)
    return f'0000:{m.group(1)}' if m else b


def _sections(out):
    cur, sec = None, {}
    for line in str(out or '').splitlines():
        s = line.rstrip()
        if s.strip().startswith('@@'):
            cur = s.strip()[2:]
            sec.setdefault(cur, [])
        elif cur is not None:
            sec[cur].append(s)
    return sec


def _mode(v):
    v = str(v or '').strip().lower()
    return 'enabled' if v == 'enabled' else ('disabled' if v == 'disabled' else None)


_GIP = re.compile(r'^\|\s*(\d+)\s+MIG\s+(\S+)\s+(\d+)\s+(\d+)/(\d+)\s+([\d.]+)\s+\S+\s+(\d+)')
_GI = re.compile(r'^\|\s*(\d+)\s+MIG\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+):(\d+)')
_CI = re.compile(r'^\|\s*(\d+)\s+(\d+)\s+MIG\s+(\S+)\s+(\d+)\s+(\d+)')


def parse_node(out):
    """NODE_SCRIPT's output -> {'nvidia': bool, 'driver', 'vgpu_manager', 'gpus': [...]}."""
    sec = _sections(out)
    if 'none' in sec or 'gpus' not in sec:
        return {'nvidia': False, 'driver': '', 'vgpu_manager': False, 'gpus': [], 'complete': 'end' in sec}
    gpus, driver = [], ''
    for line in sec.get('gpus') or []:
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 7 or not parts[0].isdigit():
            continue
        try:
            mem = int(float(parts[6]))
        except ValueError:
            mem = None
        driver = driver or parts[3]
        cur, pend = _mode(parts[4]), _mode(parts[5])
        gpus.append({'index': int(parts[0]), 'bus_id': short_bus(parts[1]), 'name': parts[2], 'driver': parts[3],
                     'mig_capable': cur is not None or is_mig_model(parts[2]), 'mig_current': cur,
                     'mig_pending': pend, 'memory_mb': mem, 'profiles': [], 'gpu_instances': [], 'compute_instances': []})
    by = {g['index']: g for g in gpus}
    for line in sec.get('gip') or []:
        m = _GIP.match(line)
        if m and int(m.group(1)) in by:
            by[int(m.group(1))]['profiles'].append({
                'name': m.group(2), 'id': int(m.group(3)), 'free': int(m.group(4)), 'total': int(m.group(5)),
                'memory_gb': float(m.group(6)), 'sm': int(m.group(7))})
    for line in sec.get('gi') or []:
        m = _GI.match(line)
        if m and int(m.group(1)) in by:
            by[int(m.group(1))]['gpu_instances'].append({
                'profile': m.group(2), 'profile_id': int(m.group(3)), 'id': int(m.group(4)),
                'start': int(m.group(5)), 'size': int(m.group(6))})
    for line in sec.get('ci') or []:
        m = _CI.match(line)
        if m and int(m.group(1)) in by:
            by[int(m.group(1))]['compute_instances'].append({
                'gpu_instance': int(m.group(2)), 'profile': m.group(3), 'profile_id': int(m.group(4)), 'id': int(m.group(5))})
    vgpu_lines = ' '.join(sec.get('vgpu') or []).lower()
    vgpu = bool(re.search(r'host vgpu mode\s*:\s*(sr-iov|non sr-iov)', vgpu_lines)) or 'host vgpu' in vgpu_lines
    for g in gpus:
        g['slices_used'] = sum(gi['size'] for gi in g['gpu_instances'])
    return {'nvidia': True, 'driver': driver, 'vgpu_manager': vgpu, 'gpus': gpus, 'complete': 'end' in sec}


# --- writes -----------------------------------------------------------------------------------

def mode_command(index, enable, reset=False):
    cmd = f'{_SUDO}$S nvidia-smi -i {int(index)} -mig {1 if enable else 0}'
    if reset:
        cmd += f' && $S nvidia-smi -i {int(index)} -r'
    return cmd


def layout_command(index, profile_ids, compute=False):
    """Destroy the card's compute and GPU instances, then make the given GPU instances (with a
    default compute instance each when `compute`). The destroys may find nothing: their exit
    codes do not count; the create's does."""
    i = int(index)
    cmd = f'{_SUDO}$S nvidia-smi mig -i {i} -dci >/dev/null 2>&1; $S nvidia-smi mig -i {i} -dgi >/dev/null 2>&1; '
    if profile_ids:
        cmd += f"$S nvidia-smi mig -i {i} -cgi {','.join(str(int(p)) for p in profile_ids)}" + (' -C' if compute else '')
    else:
        cmd += 'true'
    return cmd


def resolve_layout(gpu, wanted):
    """Profile names or ids -> ids from the card's own list. Raises ValueError for an unknown one
    or one asked for more often than the card has room for (an empty card's totals)."""
    if not isinstance(wanted, list) or len(wanted) > 8:
        raise ValueError('layout: a list of up to 8 GPU instance profiles')
    profiles = gpu.get('profiles') or []
    by_name = {p['name'].lower(): p for p in profiles}
    by_id = {p['id']: p for p in profiles}
    ids = []
    for w in wanted:
        p = by_id.get(w) if isinstance(w, int) else by_name.get(str(w).strip().lower())
        if p is None and isinstance(w, str) and w.strip().isdigit():
            p = by_id.get(int(w))
        if p is None:
            raise ValueError(f"'{w}' is not a GPU instance profile of this card")
        ids.append(p['id'])
    for pid in set(ids):
        if ids.count(pid) > by_id[pid]['total']:
            raise ValueError(f"{by_id[pid]['name']}: at most {by_id[pid]['total']} on this card")
    slices = sum(int(re.match(r'(\d+)g', by_id[p]['name']).group(1)) for p in ids if re.match(r'(\d+)g', by_id[p]['name']))
    if slices > 7:
        raise ValueError(f'the layout needs {slices} of 7 compute slices')
    return ids


def busy_vms(vms, configs, nvidia_addresses, mappings, node):
    """The running VMs on `node` that hold an NVIDIA card: a hostpci slot on a mapping with an
    NVIDIA device (10de:) on this node, or a raw address of an NVIDIA device of the node.
    vms: {vmid: {node, status, type, name}}; configs: {vmid: {slot: value}}."""
    from pegaprox.vlab import accel
    nv_maps = {m['id'] for m in mappings or []
               if any(d.get('node') == node and str(d.get('id') or '').lower().startswith('10de:') for d in m['devices'])}
    out = []
    for vmid, vm in vms.items():
        if vm.get('node') != node or vm.get('status') != 'running' or vm.get('type', 'qemu') != 'qemu':
            continue
        for slot, value in (configs.get(vmid) or {}).items():
            h = accel.parse_hostpci(value)
            if (h['mapping'] and h['mapping'] in nv_maps) or any(
                    accel.address_matches(a, h['addresses']) for a in nvidia_addresses):
                out.append({'vmid': int(vmid), 'name': vm.get('name') or f'vm-{vmid}', 'slot': slot})
                break
    return out


# --- a small cache of the node reads (the inventory page, the checks and the compatibility
# table all ask; one SSH per node a minute is enough) -----------------------------------------

TTL = 60
_cache, _cache_lock = {}, threading.Lock()


def cached(cluster_id, node):
    with _cache_lock:
        hit = _cache.get((cluster_id, node))
    return hit[1] if hit and time.monotonic() - hit[0] < TTL else None


def remember(cluster_id, node, state):
    with _cache_lock:
        _cache[(cluster_id, node)] = (time.monotonic(), state)


def forget(cluster_id, node=None):
    with _cache_lock:
        for k in [k for k in _cache if k[0] == cluster_id and (node is None or k[1] == node)]:
            _cache.pop(k, None)


def read_node(mgr, cluster_id, node, refresh=False):
    """The node's NVIDIA state (parse_node) with 'readable' and 'error'; cached for TTL seconds."""
    if not refresh:
        hit = cached(cluster_id, node)
        if hit is not None:
            return hit
    try:
        rc, out, err = mgr._node_ssh_exec(node, NODE_SCRIPT, timeout=40)
    except Exception as e:
        rc, out, err = -1, '', str(e)
    if rc != 0 and '@@' not in str(out or ''):
        state = {'readable': False, 'error': str(err or out or 'SSH failed')[:300], 'nvidia': False, 'driver': '',
                 'vgpu_manager': False, 'gpus': []}
    else:
        state = dict(parse_node(out), readable=True, error='')
    remember(cluster_id, node, state)
    return state


def card_state(state, pciid):
    """The GPU of a node state at a PCI address, or for a virtual function the GPU on the same
    bus (an A100's VFs sit at 41:00.4 ... beside its 41:00.0)."""
    if not state:
        return None
    want = short_bus(pciid)
    gpus = state.get('gpus') or []
    for g in gpus:
        if g['bus_id'] == want:
            return g
    bus = want.rsplit(':', 1)[0]
    same = [g for g in gpus if g['bus_id'].rsplit(':', 1)[0] == bus]
    return same[0] if len(same) == 1 else None
