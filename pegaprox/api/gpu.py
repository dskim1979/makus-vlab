# -*- coding: utf-8 -*-
"""
GPU / NVIDIA vGPU management.

Two layers:
  - Discovery: list GPU-class PCI devices per node, and — for cards with an
    NVIDIA vGPU manager driver installed on the host — the mediated-device
    (mdev) profiles Proxmox exposes for that card (e.g. 'nvidia-263').
  - Allocation: assign a GPU to a VM, either as a whole-device PCI passthrough
    or as a single vGPU (mdev) slice. Building on the existing hostpciN slot
    logic in pegaprox/api/vms.py — this module only adds the GPU-aware
    picker on top, it doesn't duplicate the underlying passthrough mechanism.

Whole-card passthrough vs vGPU are mutually exclusive per physical GPU:
once one mdev slice is handed to a VM, the remaining capacity is other mdev
slices of the SAME profile family (the card's framebuffer is statically
partitioned by profile at creation time) — not a free-for-all mix. We surface
that as 'available_instances' per profile rather than a single free/used bit.

vGPU requires the NVIDIA vGPU host driver to already be installed and
licensed on the Proxmox node — this module only reads/writes Proxmox's own
PCI + mdev API, it cannot install or license the vGPU manager itself.
"""
import logging
import re
from flask import Blueprint, jsonify, request

from pegaprox.globals import cluster_managers
from pegaprox.utils.auth import require_auth
from pegaprox.utils.audit import log_audit
from pegaprox.api.helpers import check_cluster_access, get_connected_manager, safe_error, parse_pve_error

bp = Blueprint('gpu', __name__)

# PCI class 0300 = VGA compatible controller, 0302 = 3D controller (headless
# compute GPUs like datacenter NVIDIA cards report as 0302, not 0300).
_GPU_PCI_CLASSES = ('0300', '0302')

_PCIID_RE = re.compile(r'^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]$')


_NVIDIA_VENDOR_ID = '10de'


def _valid_pciid(pciid):
    return bool(pciid) and bool(_PCIID_RE.match(pciid))


def _is_gpu(dev):
    """True if this /nodes/{node}/hardware/pci entry is an NVIDIA GPU.

    NS: Proxmox reports 'class' as a 6-hex-digit string — class + subclass +
    prog-if, e.g. '030000' for VGA compatible controller, '030200' for a
    headless 3D/compute card — not the bare 4-digit class+subclass we
    originally compared against. That earlier version did an exact-string
    match against ('0300', '0302'), which a real 6-digit value can never
    equal, so no card was ever detected (confirmed against a live cluster —
    a passed-through GPU didn't show up in the inventory or the VM's GPU
    picker at all). Compares only the first 4 hex digits (class+subclass),
    ignoring prog-if, and tolerates the class arriving as an int, with or
    without a '0x' prefix, or with leading zeros dropped.

    Also requires vendor == NVIDIA (0x10de) — this feature is NVIDIA vGPU
    only (see module docstring), and class alone isn't a reliable enough
    signal: every server motherboard's onboard BMC (ASPEED/Matrox, for the
    IPMI/iDRAC/iLO remote console) reports as PCI class 0300 too, so without
    the vendor check the inventory would count the board's own remote-console
    chip as an allocatable "GPU" alongside any real cards.
    """
    raw = dev.get('class')
    if raw is None:
        return False
    cls = format(raw, 'x') if isinstance(raw, int) else str(raw)
    cls = cls.lower().replace('0x', '').strip()
    if len(cls) < 6:
        cls = cls.zfill(6)  # pad short/leading-zero-stripped values to the full 6 digits
    if cls[:4] not in _GPU_PCI_CLASSES:
        return False

    vendor = dev.get('vendor')
    if vendor is None:
        return False
    vendor = format(vendor, 'x') if isinstance(vendor, int) else str(vendor)
    vendor = vendor.lower().replace('0x', '').strip().zfill(4)
    return vendor == _NVIDIA_VENDOR_ID


def _get_node_gpu_utilization(manager, node):
    """{pciid: {gpu_pct, mem_pct, mem_used_mb, mem_total_mb, temp_c}} for every
    NVIDIA GPU on this node, via `nvidia-smi` over SSH.

    Proxmox's own API has no concept of live GPU utilization — hardware/pci
    is a static device listing — so this is the only way to get it, and it
    only works if the NVIDIA driver is actually installed on the host (which
    it must be anyway for passthrough/vGPU to work at all). Returns {} on
    any failure (no SSH access, driver not installed, nvidia-smi not on
    PATH, etc.) rather than raising — utilization is a nice-to-have overlay
    on top of the inventory, never a reason to fail the whole request.
    """
    try:
        node_ip = manager._get_node_ip(node)
        if not node_ip:
            return {}
        ssh = manager._ssh_connect(node_ip, retries=1)
        if not ssh:
            return {}
        try:
            cmd = ('nvidia-smi --query-gpu=pci.bus_id,utilization.gpu,utilization.memory,'
                   'memory.used,memory.total,temperature.gpu --format=csv,noheader,nounits')
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=10)
            from pegaprox.utils.ssh import read_capped
            output = read_capped(stdout)  # bounded: a node must not be able to exhaust our memory
            if stdout.channel.recv_exit_status() != 0:
                return {}
        finally:
            ssh.close()

        result = {}
        for line in output.strip().splitlines():
            parts = [p.strip() for p in line.split(',')]
            if len(parts) != 6:
                continue
            bus_id, gpu_pct, mem_pct, mem_used, mem_total, temp = parts
            # nvidia-smi reports the full domain:bus:device.function
            # (e.g. '00000000:42:00.0', 8-hex-digit domain); Proxmox's pciid
            # uses a 4-hex-digit domain ('0000:42:00.0'). Keep only the
            # bus:device.function tail and re-prefix with the short domain
            # so both sides compare equal regardless of domain width.
            short_form = '0000:' + bus_id.lower().split(':', 1)[-1] if ':' in bus_id else bus_id.lower()
            try:
                result[short_form] = {
                    'gpu_pct': float(gpu_pct) if gpu_pct.replace('.', '', 1).isdigit() else None,
                    'mem_pct': float(mem_pct) if mem_pct.replace('.', '', 1).isdigit() else None,
                    'mem_used_mb': float(mem_used) if mem_used.replace('.', '', 1).isdigit() else None,
                    'mem_total_mb': float(mem_total) if mem_total.replace('.', '', 1).isdigit() else None,
                    'temp_c': float(temp) if temp.replace('.', '', 1).isdigit() else None,
                }
            except (ValueError, AttributeError):
                continue
        return result
    except Exception as e:
        logging.debug(f"[gpu] utilization query failed on {node}: {e}")
        return {}


def _friendly_vendor(vendor_id, vendor_name):
    # Proxmox's hardware/pci listing already resolves vendor/device names via
    # the system's pci.ids database when available; fall back to raw IDs.
    if vendor_name:
        return vendor_name
    known = {'0x10de': 'NVIDIA', '0x1002': 'AMD', '0x8086': 'Intel'}
    return known.get(str(vendor_id).lower(), vendor_id or 'Unknown')


def _get_node_gpu_assignments(manager, host, port, node, session=None):
    """pciid -> [{'vmid', 'name', 'mdev'}] for every hostpciN entry across
    every VM on this node. Shared by the per-VM picker (list_node_gpus, so it
    doesn't offer an already-claimed card again) and the cluster inventory."""
    session = session or manager._create_session()
    assignments = {}
    try:
        qemu_url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu"
        qemu_resp = session.get(qemu_url, timeout=15)
        vms = qemu_resp.json().get('data', []) if qemu_resp.status_code == 200 else []
    except Exception:
        return assignments

    for vm in vms:
        vmid = vm.get('vmid')
        try:
            cfg_url = f"https://{host}:{port}/api2/json/nodes/{node}/qemu/{vmid}/config"
            cfg_resp = session.get(cfg_url, timeout=10)
            config = cfg_resp.json().get('data', {}) if cfg_resp.status_code == 200 else {}
        except Exception:
            continue
        for key, value in config.items():
            if not key.startswith('hostpci'):
                continue
            # value looks like "0000:01:00.0" or "0000:01:00.0,mdev=nvidia-263"
            parts = str(value).split(',')
            dev_addr = parts[0].strip()
            mdev = next((p.split('=', 1)[1] for p in parts[1:] if p.startswith('mdev=')), None)
            assignments.setdefault(dev_addr, []).append({
                'vmid': vmid,
                'name': vm.get('name', f'VM {vmid}'),
                'mdev': mdev,
            })
    return assignments


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/gpus', methods=['GET'])
@require_auth(perms=['node.view'])
def list_node_gpus(cluster_id, node):
    """GPU-class PCI devices on one node, each flagged with whether Proxmox
    reports vGPU (mdev) capability for it.

    Whole-device (non-vGPU) cards already claimed by another VM are dropped
    from the list entirely — offering one for a second whole-device
    passthrough would just fail when the second VM starts, since Proxmox
    can't hand the same physical device to two guests at once. A vGPU-capable
    card stays listed even with some slices already handed out elsewhere;
    /profiles reports the remaining available_instances per profile, and the
    frontend disables any profile that's fully consumed.

    Pass ?include_allocated=1 to skip that filtering and get every detected
    GPU regardless of assignment — used to resolve a friendly name/vendor for
    a hostpci entry a VM already has (which is, by definition, "allocated"),
    not for the add-a-new-GPU picker."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error
    include_allocated = request.args.get('include_allocated', '').lower() in ('1', 'true', 'yes')

    try:
        host, port = manager.host, manager.api_port
        session = manager._create_session()
        url = f"https://{host}:{port}/api2/json/nodes/{node}/hardware/pci"
        # NS: no query params here on purpose — an earlier version sent
        # params={'pci-class': ''} intending "no filter", but Proxmox appears
        # to treat an empty pci-class value as "only devices whose class is
        # the empty string" (i.e. none), so the endpoint always came back
        # empty regardless of what was actually installed. We already filter
        # client-side in _is_gpu(), so just fetch every PCI device unfiltered.
        r = session.get(url, timeout=15)
        if r.status_code != 200:
            return jsonify({'error': parse_pve_error(r.text)}), r.status_code
        devices = r.json().get('data', []) or []
    except Exception as e:
        logging.error(f"[gpu] listing PCI devices on {node} failed: {e}")
        return jsonify({'error': safe_error(e, 'Failed to list PCI devices')}), 500

    assignments = _get_node_gpu_assignments(manager, host, port, node, session)

    gpus = []
    for dev in devices:
        if not _is_gpu(dev):
            continue
        pciid = dev.get('id') or dev.get('device_id') or ''
        vgpu_capable = bool(dev.get('mdev'))
        existing = assignments.get(pciid, [])
        # A whole-device (mdev is None) assignment locks the entire card to
        # that one VM — hide it, unless the caller explicitly wants the full
        # unfiltered list (e.g. to label an already-attached device).
        if not include_allocated:
            if existing and not vgpu_capable and any(a['mdev'] is None for a in existing):
                continue
            if existing and vgpu_capable and any(a['mdev'] is None for a in existing):
                # a whole-device grab on a vGPU-capable card still locks it entirely
                continue
        gpus.append({
            'pciid': pciid,
            'device_name': dev.get('device_name') or dev.get('device') or 'Unknown GPU',
            'vendor': _friendly_vendor(dev.get('vendor'), dev.get('vendor_name')),
            'subsystem_device': dev.get('subsystem_device_name') or '',
            'iommu_group': dev.get('iommugroup'),
            # Proxmox sets mdev=1 on the PCI entry when the host driver exposes
            # mediated-device support for this card.
            'vgpu_capable': vgpu_capable,
            'in_use_by': existing,  # non-empty only for partially-used vGPU cards here
        })

    return jsonify({'node': node, 'gpus': gpus})


@bp.route('/api/clusters/<cluster_id>/nodes/<node>/gpus/<pciid>/profiles', methods=['GET'])
@require_auth(perms=['node.view'])
def list_vgpu_profiles(cluster_id, node, pciid):
    """Available NVIDIA vGPU (mdev) profiles for one physical GPU, with how
    many more instances of each profile currently fit in what's left of the
    card's framebuffer."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    if not _valid_pciid(pciid):
        return jsonify({'error': 'Invalid PCI device id'}), 400
    manager, error = get_connected_manager(cluster_id)
    if error: return error

    try:
        host, port = manager.host, manager.api_port
        url = f"https://{host}:{port}/api2/json/nodes/{node}/hardware/pci/{pciid}/mdev"
        r = manager._create_session().get(url, timeout=15)
        if r.status_code == 500:
            # Proxmox returns 500 (not 404) for a card with no vGPU driver —
            # treat that as "no profiles" rather than surfacing a scary error,
            # since this endpoint is routinely polled for every GPU including
            # plain passthrough-only ones.
            return jsonify({'pciid': pciid, 'vgpu_capable': False, 'profiles': []})
        if r.status_code != 200:
            return jsonify({'error': parse_pve_error(r.text)}), r.status_code
        raw = r.json().get('data', []) or []
    except Exception as e:
        logging.error(f"[gpu] listing mdev profiles for {pciid} on {node} failed: {e}")
        return jsonify({'error': safe_error(e, 'Failed to list vGPU profiles')}), 500

    profiles = []
    for p in raw:
        profiles.append({
            'type': p.get('type'),
            'name': p.get('name') or p.get('type'),
            'description': p.get('description', ''),
            'framebuffer_mb': p.get('available') and p.get('type'),  # PVE doesn't expose MB directly per-type
            'available_instances': p.get('available', 0),
        })

    return jsonify({'pciid': pciid, 'vgpu_capable': True, 'profiles': profiles})


@bp.route('/api/clusters/<cluster_id>/gpu-inventory', methods=['GET'])
@require_auth(perms=['node.view'])
def cluster_gpu_inventory(cluster_id):
    """Cluster-wide capacity view: every physical GPU on every node, and
    which VMs currently hold a slice of it (whole-device or vGPU profile).

    Cross-references live VM configs (hostpciN entries) against the node PCI
    listing — same source of truth the per-VM passthrough tab uses, just
    rolled up across the whole cluster for planning instead of per-VM."""
    ok, err = check_cluster_access(cluster_id)
    if not ok: return err
    manager, error = get_connected_manager(cluster_id)
    if error: return error

    try:
        host, port = manager.host, manager.api_port
        session = manager._create_session()

        nodes_url = f"https://{host}:{port}/api2/json/nodes"
        nodes_resp = session.get(nodes_url, timeout=15)
        if nodes_resp.status_code != 200:
            return jsonify({'error': parse_pve_error(nodes_resp.text)}), nodes_resp.status_code
        nodes = [n['node'] for n in nodes_resp.json().get('data', [])]
    except Exception as e:
        logging.error(f"[gpu] cluster inventory: listing nodes failed: {e}")
        return jsonify({'error': safe_error(e, 'Failed to list nodes')}), 500

    inventory = []
    for node in nodes:
        try:
            session = manager._create_session()
            pci_url = f"https://{host}:{port}/api2/json/nodes/{node}/hardware/pci"
            pci_resp = session.get(pci_url, timeout=15)
            devices = pci_resp.json().get('data', []) if pci_resp.status_code == 200 else []
        except Exception as e:
            logging.warning(f"[gpu] cluster inventory: PCI listing failed on {node}: {e}")
            continue

        node_gpus = [d for d in devices if _is_gpu(d)]
        if not node_gpus:
            continue

        vm_assignments = _get_node_gpu_assignments(manager, host, port, node, session)
        # One SSH call per node (not per-GPU) — nvidia-smi returns every card
        # on the host in a single query.
        utilization = _get_node_gpu_utilization(manager, node)

        for dev in node_gpus:
            pciid = dev.get('id') or ''
            assigned = vm_assignments.get(pciid, [])
            util = utilization.get(pciid.lower())
            inventory.append({
                'node': node,
                'pciid': pciid,
                'device_name': dev.get('device_name') or dev.get('device') or 'Unknown GPU',
                'vendor': _friendly_vendor(dev.get('vendor'), dev.get('vendor_name')),
                'vgpu_capable': bool(dev.get('mdev')),
                'assignments': assigned,
                'status': 'allocated' if assigned else 'free',
                'utilization': util,  # None if nvidia-smi/SSH wasn't reachable
            })

    total = len(inventory)
    allocated = sum(1 for g in inventory if g['status'] == 'allocated')
    return jsonify({
        'cluster_id': cluster_id,
        'gpus': inventory,
        'summary': {
            'total_gpus': total,
            'allocated': allocated,
            'free': total - allocated,
            'vgpu_capable_count': sum(1 for g in inventory if g['vgpu_capable']),
        },
    })
