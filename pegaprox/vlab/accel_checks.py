"""MOAVI Desk: checks for accelerator cards on desktop VMs (가속 자원 > 카드 · 패스스루 점검).

What goes wrong with PCIe passthrough of GPUs, AMD Xilinx Alveo cards and NPUs on Proxmox,
turned into things the engine can see in a VM's config and in the vLAB catalog:

  PCIE_NOT_Q35     the card sits on the PCI bus of an i440fx VM (pcie=1 needs q35); large cards
                   and Windows 11 want q35 + OVMF
  SEABIOS_BAR      a GPU or FPGA on a SeaBIOS VM: the card's large 64-bit BARs may not map
  BALLOON          memory ballooning below the VM's memory: a passthrough VM pins all of it
  ONBOOT           start at boot with a passthrough card: a card that does not reset cleanly
                   can stop the node from coming up
  HA_ONE_NODE      under Proxmox HA, but the card's mapping has a card on one node only
  XILINX_FUNCTION  an Alveo mapping that passes one PCI function (management PF0 / user PF1)
  XILINX_RESET     an FPGA card: stopping or restarting the VM resets it, the loaded xclbin /
                   bitstream is gone; a flash (shell) update needs a cold reboot of the node
  AMD_GPU_RESET    an AMD GPU passed through whole: the known reset problem after stop/start
  VGPU_LICENSE     vGPU without a watched licence server: unlicensed vGPU is cut to 15 fps
                   after 20 minutes and to 3 fps with CUDA off after a day
  SAME_MAPPING     the same mapping in two slots of one VM (pool GPU and a loan)
  JTAG_PID         a board registered by the Platform Cable USB II's pre-firmware id 03fd:0013:
                   the cable re-enumerates as 03fd:0008 once its firmware loads
  LICENSE_MAC      a licence server VM without a fixed MAC: a clone or restore changes the
                   MAC the licence (FlexLM host id) is bound to

Each finding: {code, severity: error|warn|info, cluster_id, vmid, desktop_id, name, ko, en}.
Advice only: nothing here changes a VM.
"""
import re

from pegaprox.vlab import accel, catalog, store

_SLOT = re.compile(r'^hostpci\d+$')
_FN = re.compile(r'\.[0-7]$')
MAX_VMS = 300


def _f(code, sev, ko, en, **ctx):
    return dict({'code': code, 'severity': sev, 'ko': ko, 'en': en}, **ctx)


def _devices(raw, mappings):
    """[(slot, value, mapping or None, [vendor ids], mdev?)] of the VM's hostpci slots."""
    out = []
    by_id = {m['id']: m for m in mappings or []}
    for k, v in sorted((raw or {}).items()):
        if not _SLOT.match(k):
            continue
        kv = accel.parse_hostpci(v) or {}
        m = by_id.get(kv.get('mapping') or '')
        vendors = sorted({(d.get('id') or '').split(':')[0].lower() for d in (m or {}).get('devices') or [] if d.get('id')})
        out.append((k, str(v), m, vendors, bool(kv.get('mdev'))))
    return out


def for_vm(mgr, cluster_id, node, vmid, desk=None, raw=None, mappings=None, ha_sids=None, watched_licence=None):
    """Findings for one VM (qemu). Reads what it is not given."""
    raw = raw if raw is not None else accel.vm_raw(mgr, node, vmid)
    if not raw:
        return []
    if mappings is None:
        mappings = accel.pci_mappings(mgr) or []
    devs = _devices(raw, mappings)
    if not devs:
        return []
    ctx = {'cluster_id': cluster_id, 'vmid': int(vmid), 'desktop_id': (desk or {}).get('id'),
           'name': (desk or {}).get('name') or raw.get('name') or f'VM {vmid}'}
    out = []
    fpga = any(v in accel.FPGA_VENDOR_IDS for _, _, _, vs, _ in devs for v in vs)
    gpu_whole = any(not mdev and any(v in ('10de', '1002', '8086') for v in vs) for _, _, _, vs, mdev in devs)
    big = fpga or gpu_whole
    q35 = accel.is_q35(raw)

    if not q35:
        out.append(_f('PCIE_NOT_Q35', 'warn' if big else 'info',
                      '머신 종류가 i440fx라 카드가 PCI 버스로 붙습니다(pcie=1은 q35에서만 됨). Alveo · GPU와 Windows 11은 q35 + OVMF(UEFI)를 권장합니다.',
                      'The VM is i440fx, so the card sits on the PCI bus (pcie=1 needs q35). Alveo, GPUs and Windows 11 want q35 + OVMF (UEFI).', **ctx))
    if big and str(raw.get('bios') or 'seabios') != 'ovmf':
        out.append(_f('SEABIOS_BAR', 'warn',
                      'SeaBIOS VM입니다. GPU · FPGA 카드의 큰 64비트 BAR가 매핑되지 않아 VM 안에서 카드가 안 보일 수 있습니다. OVMF(UEFI) VM을 쓰고, 노드 BIOS의 Above 4G Decoding을 켜세요.',
                      'A SeaBIOS VM: the large 64-bit BARs of GPU and FPGA cards may not map and the card may not show in the guest. Use an OVMF (UEFI) VM and enable Above 4G Decoding in the node BIOS.', **ctx))
    try:
        mem, bal = int(raw.get('memory') or 0), raw.get('balloon')
        if bal is not None and 0 < int(bal) < mem:
            out.append(_f('BALLOON', 'warn',
                          f'메모리 벌루닝이 {bal} MB로 잡혀 있습니다. 패스스루 VM은 메모리 {mem} MB를 모두 고정하므로 벌루닝이 되지 않고 노드 메모리 계산이 틀어집니다. balloon을 0으로 두세요.',
                          f'Ballooning is set to {bal} MB. A passthrough VM pins all {mem} MB, so ballooning does nothing and the node memory sums go wrong. Set balloon to 0.', **ctx))
    except (TypeError, ValueError):
        pass
    if str(raw.get('onboot') or '0') == '1':
        out.append(_f('ONBOOT', 'warn',
                      '노드가 켜질 때 자동 시작으로 되어 있습니다. 리셋이 깨끗하지 않은 카드는 노드 부팅을 멈추게 할 수 있으니, 패스스루 VM은 자동 시작을 끄고 수동 · 시간표로 켜세요.',
                      'Start at boot is on. A card that does not reset cleanly can hang the node at boot; turn it off for passthrough VMs and start them by hand or by schedule.', **ctx))
    if ha_sids and f'vm:{vmid}' in ha_sids:
        for slot, _, m, _, _ in devs:
            if m and len({d['node'] for d in m['devices']}) < 2:
                out.append(_f('HA_ONE_NODE', 'warn',
                              f"Proxmox HA에 올라가 있지만 매핑 '{m['id']}'의 카드가 노드 하나에만 있습니다. 노드가 죽으면 다른 노드에서 카드 없이 켜지지 못합니다. 다른 노드의 같은 카드를 매핑에 더하거나 HA에서 빼세요.",
                              f"Under Proxmox HA, but mapping '{m['id']}' has a card on one node only: on another node the VM cannot start. Add the same card on other nodes to the mapping, or take the VM out of HA.", slot=slot, **ctx))
    seen = {}
    for slot, _, m, vendors, mdev in devs:
        if m:
            if m['id'] in seen:
                out.append(_f('SAME_MAPPING', 'error',
                              f"같은 매핑 '{m['id']}'이 {seen[m['id']]}와 {slot}에 두 번 붙어 있습니다(풀 GPU 정책과 카드 대여가 겹침). VM이 켜지지 않거나 카드 두 장을 차지합니다.",
                              f"Mapping '{m['id']}' sits in {seen[m['id']]} and {slot} (the pool GPU policy and a loan overlap): the VM may not start or takes two cards.", slot=slot, **ctx))
            seen[m['id']] = slot
        if '10ee' in vendors and m and any(_FN.search(d.get('path') or '') for d in m['devices']):
            out.append(_f('XILINX_FUNCTION', 'info',
                          f"Alveo 매핑 '{m['id']}'이 PCI 기능 하나만 넘깁니다. Alveo는 관리(PF0) · 사용자(PF1) 두 기능이라, 한쪽만 넘기면 VM 안에서 xbmgmt(플래시 · 리셋)나 xbutil 일부가 안 됩니다. 의도한 것이 아니면 매핑 경로를 기능 번호 없이(예: 0000:3b:00) 두세요.",
                          f"Alveo mapping '{m['id']}' passes one PCI function. Alveo has a management PF0 and a user PF1; with one of them the guest lacks xbmgmt (flash, reset) or parts of xbutil. Unless intended, map the device without a function number (e.g. 0000:3b:00).", slot=slot, **ctx))
        if not mdev and '1002' in vendors:
            out.append(_f('AMD_GPU_RESET', 'warn',
                          'AMD GPU를 통째로 넘겼습니다. AMD GPU는 VM을 끄고 켜거나 Proxmox에서 재시작하면 카드가 다시 안 잡히거나 노드가 멈추는 리셋 문제가 알려져 있습니다. 노드에 vendor-reset을 설치하고(지원 카드인지 확인), 재시작은 게스트 안에서 하세요.',
                          'A whole AMD GPU is passed through. AMD GPUs have a known reset problem: after a stop/start or a restart from Proxmox the card may not come back or the node may hang. Install vendor-reset on the node (check the card is supported) and restart from inside the guest.', slot=slot, **ctx))
        if mdev and watched_licence is False:
            out.append(_f('VGPU_LICENSE', 'warn',
                          'vGPU를 쓰는데 자동 감시하는 라이선스 서버가 없습니다. 라이선스를 못 받은 vGPU는 20분 뒤 15fps로 제한되고 CUDA가 느려지며, 24시간 뒤에는 3fps · CUDA 중지가 됩니다. 가속 자원 > 라이선스 서버에 vGPU 라이선스 서버(DLS)를 등록하고 자동 감시를 켜세요.',
                          'vGPU without a watched licence server. An unlicensed vGPU is cut to 15 fps with slower CUDA after 20 minutes, and to 3 fps with CUDA off after 24 hours. Register the vGPU licence server (DLS) under Accelerators > Licence servers and watch it.', slot=slot, **ctx))
    if fpga:
        out.append(_f('XILINX_RESET', 'info',
                      'FPGA 카드: VM을 끄거나 다시 시작하면 카드가 리셋되어 올려 둔 xclbin · 비트스트림이 지워집니다. 시작한 뒤 다시 프로그램하세요(xbutil program). 카드 플래시(shell) 갱신은 노드를 완전히 껐다 켜야 반영됩니다.',
                      'FPGA card: stopping or restarting the VM resets the card and the loaded xclbin / bitstream is gone; program it again after the start (xbutil program). A card flash (shell) update only takes effect after a cold reboot of the node.', **ctx))
    return out


def _watched_licence():
    try:
        return any(s.get('watch') for s in catalog.list_license_servers())
    except Exception:
        return None


def scan(cluster_managers, reachable):
    """Every finding over the desktops that carry a card (a pool GPU or a loan), the boards
    and the licence servers. `reachable(cluster_id)` filters by the caller's access."""
    findings, read = [], 0
    watched = _watched_licence()
    loans = {(l['cluster_id'], int(l['vmid'])) for l in store.list_leases(active_only=True) if l.get('vmid') is not None}
    pools = {p['id']: p for p in store.list_pools()}
    per_cluster = {}
    for d in store.list_desktops():
        if d.get('vm_type') != 'qemu' or not reachable(d['cluster_id']):
            continue
        gpu = ((pools.get(d['pool_id']) or {}).get('settings') or {}).get('gpu') or {}
        if (gpu.get('mode') in (None, '', 'none')) and (d['cluster_id'], int(d['vmid'])) not in loans:
            continue
        per_cluster.setdefault(d['cluster_id'], []).append(d)
    for cid, desks in per_cluster.items():
        mgr = cluster_managers.get(cid)
        if not mgr or not getattr(mgr, 'is_connected', False):
            findings.append(_f('CLUSTER_DOWN', 'info', '클러스터에 연결되지 않아 점검하지 못했습니다.', 'Not connected to the cluster: not checked.', cluster_id=cid))
            continue
        mappings = accel.pci_mappings(mgr) or []
        try:
            ha_sids = {r.get('sid') for r in mgr.get_proxmox_ha_resources() or []}
        except Exception:
            ha_sids = set()
        for d in desks:
            if read >= MAX_VMS:
                break
            read += 1
            findings += for_vm(mgr, cid, d['node'], d['vmid'], desk=d, mappings=mappings, ha_sids=ha_sids, watched_licence=watched)
    for b in catalog.list_boards():
        if not reachable(b.get('cluster_id') or ''):
            continue
        if str(b.get('usb') or '').lower() == '03fd:0013':
            findings.append(_f('JTAG_PID', 'warn',
                               f"보드 '{b['name']}'이 03fd:0013으로 등록되어 있습니다. Platform Cable USB II는 펌웨어를 올린 뒤 03fd:0008로 다시 잡혀 연결이 끊깁니다. 03fd:0008이나 포트 경로(예: 1-4.2)로 등록하세요.",
                               f"Board '{b['name']}' is registered as 03fd:0013. The Platform Cable USB II re-enumerates as 03fd:0008 once its firmware loads and the passthrough is lost. Register 03fd:0008 or the port path (e.g. 1-4.2).",
                               cluster_id=b.get('cluster_id'), name=b['name'], board_id=b['id']))
    for s in catalog.list_license_servers():
        if s.get('cluster_id') and not reachable(s['cluster_id']):
            continue
        if s.get('vmid') and not s.get('fixed_mac'):
            findings.append(_f('LICENSE_MAC', 'warn',
                               f"라이선스 서버 '{s['name']}' VM에 고정 MAC이 적혀 있지 않습니다. FlexLM 라이선스는 MAC(호스트 ID)에 묶여, VM을 복제 · 복원하면 MAC이 바뀌어 라이선스가 멈춥니다. VM의 MAC을 고정하고 여기 적어 두세요.",
                               f"Licence server '{s['name']}' has no fixed MAC noted. FlexLM licences are bound to the MAC (host id); a clone or restore changes it and the licence stops. Fix the VM's MAC and note it here.",
                               cluster_id=s.get('cluster_id'), vmid=s.get('vmid'), name=s['name'], license_id=s['id']))
        if not s.get('watch'):
            findings.append(_f('LICENSE_UNWATCHED', 'info',
                               f"라이선스 서버 '{s['name']}'의 자동 감시가 꺼져 있습니다. 끊기면 설계 툴 · vGPU가 멈출 때까지 모릅니다.",
                               f"Licence server '{s['name']}' is not watched: nobody hears when it stops answering.",
                               cluster_id=s.get('cluster_id'), name=s['name'], license_id=s['id']))
    order = {'error': 0, 'warn': 1, 'info': 2}
    findings.sort(key=lambda f: (order.get(f['severity'], 3), f['code'], str(f.get('name'))))
    return {'findings': findings, 'checked_vms': read,
            'counts': {k: sum(1 for f in findings if f['severity'] == k) for k in ('error', 'warn', 'info')}}
