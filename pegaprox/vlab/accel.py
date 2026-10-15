# -*- coding: utf-8 -*-
"""
vLAB accelerators (MAKUS): GPUs, vGPU profiles and FPGA cards on the cluster's nodes.

The PVE reads are small wrappers (node_pci, pci_mappings, mdev_types) so the routes and
the tests can stand them in; everything else here is plain parsing. docs/vlab-design.md 10-0.

Desktops get their GPU through a cluster PCI resource mapping (`mapping=<id>`), never a
raw address: PVE accepts a raw hostpci address from root@pam only, which the API token
vLAB uses is not. vLAB writes one slot of its own, GPU_SLOT, and leaves the rest alone.
"""

import logging
import re

GPU_SLOT = 'hostpci15'     # the pool's GPU policy
LEASE_SLOT = 'hostpci14'   # a card on loan

_GPU_CLASSES = ('0300', '0302', '0380')        # VGA, 3D controller, other display controller
_ACCEL_CLASS = '1200'                          # processing accelerator
_GPU_VENDORS = {'10de': 'NVIDIA', '1002': 'AMD', '8086': 'Intel'}
_FPGA_VENDORS = {'10ee': 'AMD Xilinx', '1172': 'Intel (Altera)'}
# the display chips of server boards (remote console) report class 0300 too
_BMC_VENDORS = ('1a03', '102b', '19a2', '19e5')   # ASPEED, Matrox, Emulex/ServerEngines, Huawei

PCI_ID = re.compile(r'^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$')
MAPPING_ID = re.compile(r'^[a-zA-Z][a-zA-Z0-9_\-]{1,63}$')
MDEV_TYPE = re.compile(r'^[\w.\-]{1,64}$')


def _hex(v, width):
    if v is None:
        return ''
    s = format(v, 'x') if isinstance(v, int) else str(v)
    return s.lower().replace('0x', '').strip().zfill(width)


def classify(dev):
    """'gpu', 'fpga' or None for one /nodes/<n>/hardware/pci entry."""
    vendor, cls = _hex(dev.get('vendor'), 4), _hex(dev.get('class'), 6)[:4]
    if vendor in _FPGA_VENDORS:
        return 'fpga'
    if vendor in _BMC_VENDORS:
        return None
    if cls in _GPU_CLASSES or (cls == _ACCEL_CLASS and vendor in _GPU_VENDORS):
        return 'gpu'
    return None


def device_view(node, dev):
    vendor = _hex(dev.get('vendor'), 4)
    return {
        'node': node,
        'pciid': dev.get('id') or '',
        'kind': classify(dev),
        'vendor': dev.get('vendor_name') or _GPU_VENDORS.get(vendor) or _FPGA_VENDORS.get(vendor) or vendor or '?',
        'vendor_id': vendor,
        'device_id': _hex(dev.get('device'), 4),
        'model': dev.get('device_name') or _hex(dev.get('device'), 4) or 'Unknown',
        'subsystem': dev.get('subsystem_device_name') or '',
        'iommu_group': dev.get('iommugroup'),
        'vgpu_capable': bool(dev.get('mdev')),
    }


def _short(addr):
    """'0000:41:00.0' and '41:00.0' compare equal; a bare '41:00' names all functions."""
    a = addr.lower()
    return a[5:] if re.match(r'^[0-9a-f]{4}:', a) else a


def parse_hostpci(value):
    """{'mapping': id|None, 'addresses': [..], 'mdev': type|None} of one hostpciN value."""
    parts = [p.strip() for p in str(value or '').split(',') if p.strip()]
    out = {'mapping': None, 'addresses': [], 'mdev': None}
    for i, p in enumerate(parts):
        if '=' in p:
            k, v = p.split('=', 1)
            if k == 'mapping':
                out['mapping'] = v
            elif k == 'host':
                out['addresses'] = v.split(';')
            elif k == 'mdev':
                out['mdev'] = v
        elif i == 0:
            out['addresses'] = p.split(';')
    return out


def address_matches(pciid, addresses):
    s = _short(pciid)
    for a in addresses:
        a = _short(a)
        if a == s or ('.' not in a and s.startswith(a + '.')):
            return True
    return False


def parse_mapping(m):
    """One /cluster/mapping/pci entry -> {id, description, mdev, devices: [{node, path, id}]}."""
    devices = []
    for entry in m.get('map') or []:
        kv = dict(x.split('=', 1) for x in str(entry).split(',') if '=' in x)
        if kv.get('node') and kv.get('path'):
            devices.append({'node': kv['node'], 'path': kv['path'], 'id': kv.get('id', '')})
    return {'id': m.get('id') or '', 'description': m.get('description') or '', 'mdev': bool(m.get('mdev')),
            'devices': devices}


def parse_profile(t):
    """One /hardware/pci/<id>/mdev entry -> profile with the numbers its description carries
    ('num_heads=4, frl_config=60, framebuffer=2048M, max_resolution=5120x2880, max_instance=16')."""
    desc = str(t.get('description') or '')
    kv = {}
    for part in desc.replace('\n', ',').split(','):
        if '=' in part:
            k, v = part.split('=', 1)
            kv[k.strip()] = v.strip()
    fb = kv.get('framebuffer', '')
    m = re.match(r'^(\d+)\s*([MG])', fb, re.I)
    fb_mb = (int(m.group(1)) * (1024 if m.group(2).upper() == 'G' else 1)) if m else None

    def _int(k):
        try:
            return int(kv[k])
        except (KeyError, ValueError):
            return None
    return {'type': t.get('type') or '', 'name': t.get('name') or t.get('type') or '', 'description': desc,
            'available': int(t.get('available') or 0), 'framebuffer_mb': fb_mb,
            'max_instance': _int('max_instance'), 'heads': _int('num_heads'),
            'max_resolution': kv.get('max_resolution') or ''}


# --- PVE reads --------------------------------------------------------------------

def _get(mgr, path):
    url = f"https://{mgr.host}:{mgr.api_port}/api2/json/{path}"
    r = mgr._api_get(url, timeout=15)
    if r is None or r.status_code != 200:
        return None
    return r.json().get('data')


def node_pci(mgr, node):
    """The node's PCI devices, or None when they cannot be read."""
    try:
        data = _get(mgr, f'nodes/{node}/hardware/pci')
    except Exception as e:
        logging.debug(f'[VLAB] pci of {node}: {e}')
        return None
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else None


def pci_mappings(mgr):
    """The cluster's PCI resource mappings (parsed), or None when they cannot be read."""
    try:
        data = _get(mgr, 'cluster/mapping/pci')
    except Exception as e:
        logging.debug(f'[VLAB] pci mappings: {e}')
        return None
    return [parse_mapping(m) for m in data if isinstance(m, dict)] if isinstance(data, list) else None


def mdev_types(mgr, node, pciid):
    """vGPU profiles of one card; [] when it has none (PVE answers 500 then), None on error."""
    try:
        url = f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/hardware/pci/{pciid}/mdev"
        r = mgr._api_get(url, timeout=15)
    except Exception as e:
        logging.debug(f'[VLAB] mdev of {pciid} on {node}: {e}')
        return None
    if r is None:
        return None
    if r.status_code == 500:
        return []
    if r.status_code != 200:
        return None
    return [parse_profile(t) for t in (r.json().get('data') or []) if isinstance(t, dict)]


def hostpci_of(mgr, node, vmid):
    """{slot: value} of the VM's hostpci entries, or None when the config cannot be read."""
    try:
        r = mgr.get_vm_config(node, int(vmid), 'qemu')
    except Exception as e:
        logging.debug(f'[VLAB] config of {vmid}: {e}')
        return None
    raw = r.get('config', {}).get('raw') if isinstance(r, dict) and r.get('success') else None
    if not isinstance(raw, dict):
        return None
    return {k: v for k, v in raw.items() if re.fullmatch(r'hostpci\d+', k)}


def gpu_value(policy):
    """The GPU_SLOT value a pool's GPU policy asks for, or None for no GPU."""
    if not policy or policy.get('mode') in (None, '', 'none') or not policy.get('mapping'):
        return None
    v = f"mapping={policy['mapping']},pcie=1"
    if policy.get('mode') == 'vgpu' and policy.get('mdev_type'):
        v += f",mdev={policy['mdev_type']}"
    elif policy.get('mode') == 'passthrough' and policy.get('x_vga'):
        v += ',x-vga=1'
    return v
