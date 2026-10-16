"""MOAVI Desk: 가상머신 > 환경 카탈로그 (pegaprox/vlab/envcat.py) and NVIDIA MIG on the nodes
(가속 자원 > GPU · 가속 카드 재고, pegaprox/vlab/mig.py).

  GET  /api/vlab/admin/environments                         golden images with their environment     vlab.pool.view
  PUT  /api/vlab/admin/golden-images/<id>/environment       {kind, components, cards, description, note}  vlab.pool.manage
  POST /api/vlab/admin/golden-images/<id>/environment/probe {apply?} read the versions through the guest agent  vlab.pool.manage
  GET  /api/vlab/admin/clusters/<cid>/environment-compat    nodes' NVIDIA host driver / vGPU manager against
                                                            each environment's guest driver and CUDA   vlab.pool.view
  GET  /api/vlab/admin/clusters/<cid>/mig                   MIG mode, GPU / compute instances, profiles per node  vlab.pool.view
  PUT  /api/vlab/admin/clusters/<cid>/nodes/<node>/mig/<index>  {action: mode|layout, ..., confirm: <node>}  vlab.accel.manage

"이 환경으로 풀 만들기" is the existing pair POST /api/vlab/admin/pools + POST
/api/vlab/admin/golden-images/<id>/deploy. The portal's 받을 수 있는 데스크톱 carries the pool's
environment (envcat.portal_view, GET /api/vlab/me/pools).

Node reads and the MIG writes go over SSH through the core's guarded node path
(PegaProxManager._node_ssh_exec); the version read goes through the PVE guest agent. A MIG write
is a step that cannot be taken back while desktops hold the card: it is refused while a running VM
on the node has an NVIDIA card, needs the node's name typed back, asks ha.confirm_step and is audited.
"""
import re

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.core import ha
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import accel, catalog, envcat, mig, store

bp = Blueprint('vlab_env', __name__)

_bad = core._bad
_user = core._user
NODE = re.compile(r'^[a-zA-Z][a-zA-Z0-9.\-]{0,62}$')
PROBE_WAIT = 90.0     # seconds the version read waits for the guest (vivado -version is slow)


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _golden_or_error(gid):
    img = catalog.get_golden(gid)
    if not img or not core._can_reach(img['cluster_id']):
        return None, _bad('Golden image not found', 404)
    return img, None


def _mgr_or_error(cluster_id):
    mgr = cluster_managers.get(cluster_id)
    if not mgr or not core._can_reach(cluster_id):
        return None, _bad('Cluster not found', 404)
    if getattr(mgr, 'cluster_type', 'proxmox') != 'proxmox':
        return None, _bad('Only Proxmox clusters have this', 409)
    if not getattr(mgr, 'is_connected', False):
        return None, _bad('Cluster not connected', 503)
    return mgr, None


def _pool_gpu(p):
    return ((p.get('settings') or {}).get('gpu') or {})


def _env_view(img, env, pools):
    env = env or envcat.empty(img['id'])
    mine = [p for p in pools if (p.get('settings') or {}).get('golden_id') == img['id']]
    return {
        'golden_id': img['id'], 'name': img['name'], 'cluster_id': img['cluster_id'], 'node': img['node'],
        'vmid': img['vmid'], 'current_version': img['current_version'], 'notes': img.get('notes', ''),
        'kind': env['kind'], 'components': env['components'], 'cards': env['cards'] or {'mappings': [], 'vendors': []},
        'description': env['description'], 'history': env['history'], 'probe': env['probe'], 'probed_at': env['probed_at'],
        'updated_by': env['updated_by'], 'updated_at': env['updated_at'], 'highlights': envcat.highlights(env),
        'pools': [{'id': p['id'], 'name': p['name'], 'type': p['type'], 'gpu': {k: v for k, v in _pool_gpu(p).items()
                                                                             if k in ('mode', 'label', 'mig')}} for p in mine],
    }


@bp.route('/api/vlab/admin/environments', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_environments():
    envs, pools = envcat.all_envs(), store.list_pools()
    out = []
    for img in catalog.list_golden():
        if not core._can_reach(img['cluster_id']):
            continue
        live = core._vm_states(img['cluster_id']).get(int(img['vmid'])) or {}
        out.append(dict(_env_view(img, envs.get(img['id']), pools), status=live.get('status') or 'unknown'))
    return jsonify({'environments': out, 'kinds': list(envcat.KINDS), 'components': envcat.COMPONENTS})


@bp.route('/api/vlab/admin/golden-images/<gid>/environment', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def save_environment(gid):
    img, err = _golden_or_error(gid)
    if err:
        return err
    data = _body()
    kind = data.get('kind')
    if kind is not None and kind not in envcat.KINDS:
        return _bad(f"kind: one of {', '.join(envcat.KINDS)}")
    try:
        comps = envcat.clean_components(data['components']) if 'components' in data else None
    except ValueError as e:
        return _bad(str(e))
    cards = None
    if 'cards' in data:
        c = data.get('cards') or {}
        if not isinstance(c, dict):
            return _bad('cards: {mappings: [...], vendors: [...]}')
        maps = [m for m in (c.get('mappings') or []) if isinstance(m, str)]
        vendors = [v for v in (c.get('vendors') or []) if isinstance(v, str)]
        if any(not accel.MAPPING_ID.match(m) for m in maps) or len(maps) > 20:
            return _bad('cards.mappings: up to 20 PCI resource mapping ids')
        if any(len(v) > 40 for v in vendors) or len(vendors) > 10:
            return _bad('cards.vendors: up to 10 names')
        cards = {'mappings': sorted(set(maps)), 'vendors': sorted(set(v.strip() for v in vendors if v.strip()))}
    desc = data.get('description')
    if desc is not None and (not isinstance(desc, str) or len(desc) > 2000):
        return _bad('description: up to 2000 characters')
    note = str(data.get('note') or '').strip()
    if len(note) > 300:
        return _bad('note: up to 300 characters')
    env = envcat.save(gid, _user(), kind=kind, components=comps, cards=cards,
                      description=desc.strip() if isinstance(desc, str) else None, note=note,
                      version=img['current_version'])
    log_audit(_user(), 'vlab.env.save', f"environment of golden image '{img['name']}': "
              + (', '.join(envcat.highlights(env)) or 'no components') + (f' - {note}' if note else ''), get_client_ip())
    return jsonify({'environment': _env_view(img, env, store.list_pools())})


@bp.route('/api/vlab/admin/golden-images/<gid>/environment/probe', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def probe_environment(gid):
    """버전 읽기: run envcat's probe script in the golden VM through the guest agent (the VM has to
    be running with the agent). {apply: true} writes the versions found into the components."""
    from pegaprox.api import vlab_next
    img, err = _golden_or_error(gid)
    if err:
        return err
    mgr, err = _mgr_or_error(img['cluster_id'])
    if err:
        return err
    live = core._vm_states(img['cluster_id']).get(int(img['vmid'])) or {}
    if live.get('status') != 'running':
        return jsonify({'error': 'Start the golden image VM first: the versions are read inside it', 'code': 'NOT_RUNNING'}), 409
    node = live.get('node') or img['node']
    os_kind = vlab_next._guest_os(mgr, node, img['vmid'])
    if os_kind is None:
        return jsonify({'error': 'The guest agent does not answer (install qemu-guest-agent and enable it in Options)',
                        'code': 'NO_AGENT'}), 409
    argv = (['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', envcat.PROBE_WINDOWS] if os_kind == 'windows'
            else ['/bin/bash', '-c', envcat.PROBE_LINUX])
    rc, out, errout, failure = vlab_next._agent_run(mgr, node, img['vmid'], argv, wait=PROBE_WAIT)
    if failure:
        return jsonify({'error': f'The guest agent refused: {failure}', 'code': 'AGENT_ERROR'}), 502
    if rc is None:
        return jsonify({'error': f'No answer from the guest within {int(PROBE_WAIT)} s', 'code': 'TIMEOUT'}), 504
    found = envcat.parse_probe(out)
    found['os_type'] = os_kind
    env = envcat.set_probe(gid, found, _user())
    applied = []
    if _body().get('apply'):
        merged = envcat.merge(env['components'], found['components'])
        applied = envcat.changes(env['components'], merged)
        env = envcat.save(gid, _user(), components=merged, note='버전 읽기' if applied else '',
                          version=img['current_version'])
    log_audit(_user(), 'vlab.env.probe', f"golden image '{img['name']}': read {len(found['components'])} versions"
              + (f', {len(applied)} changed' if applied else ''), get_client_ip())
    return jsonify({'found': found, 'changes': applied, 'environment': _env_view(img, env, store.list_pools())})


# --- nodes: NVIDIA host driver, vGPU manager and MIG -------------------------------------------

def _nvidia_nodes(mgr, cluster_id):
    """{node: [NVIDIA GPU devices (accel.device_view)]} of the online nodes, and the unreadable nodes."""
    vms = core._vm_states(cluster_id)
    nodes = sorted({vm.get('node') for vm in vms.values() if vm.get('node')})
    try:
        status = mgr.get_node_status() or {}
        if isinstance(status, dict) and status:
            nodes = sorted(n for n, x in status.items() if isinstance(x, dict) and not x.get('offline'))
    except Exception:
        pass
    out, unreadable = {}, []
    for node in nodes:
        pci = accel.node_pci(mgr, node)
        if pci is None:
            unreadable.append(node)
            continue
        gpus = [accel.device_view(node, d) for d in pci if accel.classify(d) == 'gpu' and accel._hex(d.get('vendor'), 4) == '10de']
        if gpus:
            out[node] = gpus
    return out, unreadable


def mig_states(mgr, cluster_id):
    """{node: mig.read_node state} of the nodes with an NVIDIA GPU (cached reads) - for the checks."""
    return _node_states(mgr, cluster_id)[1]


def _node_states(mgr, cluster_id, refresh=False):
    nv, unreadable = _nvidia_nodes(mgr, cluster_id)
    states = {node: mig.read_node(mgr, cluster_id, node, refresh=refresh) for node in nv}
    return nv, states, unreadable


@bp.route('/api/vlab/admin/clusters/<cluster_id>/environment-compat', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def environment_compat(cluster_id):
    mgr, err = _mgr_or_error(cluster_id)
    if err:
        return err
    nv, states, unreadable = _node_states(mgr, cluster_id, refresh=request.args.get('refresh') == '1')
    mappings = accel.pci_mappings(mgr) or []
    map_nodes = {m['id']: {d['node'] for d in m['devices']} for m in mappings}
    nodes = []
    for node, devs in sorted(nv.items()):
        st = states.get(node) or {}
        nodes.append({'node': node, 'readable': st.get('readable', False), 'error': st.get('error', ''),
                      'driver': st.get('driver', ''), 'vgpu_manager': st.get('vgpu_manager', False),
                      'models': sorted({g['name'] for g in st.get('gpus') or []} or {d['model'] for d in devs})})
    envs, pools = envcat.all_envs(), store.list_pools()
    rows = []
    for img in catalog.list_golden():
        if img['cluster_id'] != cluster_id:
            continue
        env = envs.get(img['id'])
        if not env or not (envcat.version_of(env, 'nvidia_driver') or envcat.version_of(env, 'cuda')
                           or 'NVIDIA' in ((env.get('cards') or {}).get('vendors') or [])):
            continue
        want = set()
        for m in (env.get('cards') or {}).get('mappings') or []:
            want |= map_nodes.get(m, set())
        modes = {_pool_gpu(p).get('mode') for p in pools if (p.get('settings') or {}).get('golden_id') == img['id']}
        use_vgpu = True if 'vgpu' in modes else (False if 'passthrough' in modes else None)
        cells = {}
        for n in nodes:
            if want and n['node'] not in want:
                continue
            cells[n['node']] = envcat.compat(env, n, use_vgpu=use_vgpu)
        rows.append({'golden_id': img['id'], 'name': img['name'], 'kind': env['kind'],
                     'highlights': envcat.highlights(env), 'use_vgpu': use_vgpu, 'cells': cells})
    return jsonify({'nodes': nodes, 'rows': rows, 'unreadable_nodes': unreadable})


def _users_by_card(mgr, cluster_id, node, devs):
    """{pciid: [VMs on the node whose hostpci reaches the card]} (raw address or a mapping path
    on the same bus - a card's virtual functions)."""
    vms = core._vm_states(cluster_id)
    mappings = accel.pci_mappings(mgr) or []
    by_id = {m['id']: m for m in mappings}
    out = {d['pciid']: [] for d in devs}
    for vmid, vm in vms.items():
        if vm.get('node') != node or vm.get('type') != 'qemu' or vm.get('template'):
            continue
        for slot, value in (accel.hostpci_of(mgr, node, vmid) or {}).items():
            h = accel.parse_hostpci(value)
            paths = list(h['addresses'])
            if h['mapping'] and h['mapping'] in by_id:
                paths += [x['path'] for x in by_id[h['mapping']]['devices'] if x['node'] == node]
            for d in devs:
                bus = mig.short_bus(d['pciid']).rsplit(':', 1)[0]
                if any(accel.address_matches(d['pciid'], [p]) or mig.short_bus(p).rsplit(':', 1)[0] == bus for p in paths):
                    out[d['pciid']].append({'vmid': int(vmid), 'name': vm.get('name') or f'vm-{vmid}', 'slot': slot,
                                            'status': vm.get('status', ''), 'mdev': h['mdev']})
    return out


@bp.route('/api/vlab/admin/clusters/<cluster_id>/mig', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def cluster_mig(cluster_id):
    mgr, err = _mgr_or_error(cluster_id)
    if err:
        return err
    nv, states, unreadable = _node_states(mgr, cluster_id, refresh=request.args.get('refresh') == '1')
    nodes = []
    for node, devs in sorted(nv.items()):
        st = states.get(node) or {}
        users = _users_by_card(mgr, cluster_id, node, devs)
        cards = []
        for d in devs:
            if d.get('virtual_function'):
                continue
            g = mig.card_state(st, d['pciid']) or {}
            cards.append({'pciid': d['pciid'], 'model': d['model'], 'vgpu_capable': d['vgpu_capable'],
                          'mig_capable': bool(g.get('mig_capable')) if g else mig.is_mig_model(d['model']),
                          'state': g or None, 'used_by': users.get(d['pciid'], [])})
        nodes.append({'node': node, 'readable': st.get('readable', False), 'error': st.get('error', ''),
                      'driver': st.get('driver', ''), 'vgpu_manager': st.get('vgpu_manager', False),
                      'nvidia_tools': st.get('nvidia', False), 'cards': cards})
    return jsonify({'nodes': nodes, 'unreadable_nodes': unreadable, 'reference': mig.REFERENCE,
                    'summary': {'mig_capable': sum(1 for n in nodes for c in n['cards'] if c['mig_capable']),
                                'mig_enabled': sum(1 for n in nodes for c in n['cards'] if (c['state'] or {}).get('mig_current') == 'enabled'),
                                'gpu_instances': sum(len((c['state'] or {}).get('gpu_instances') or []) for n in nodes for c in n['cards'])}})


@bp.route('/api/vlab/admin/clusters/<cluster_id>/nodes/<node>/mig/<int:index>', methods=['PUT'])
@require_auth(perms=['vlab.accel.manage'])
def set_mig(cluster_id, node, index):
    """{action: 'mode', enable, reset?} or {action: 'layout', layout: ['3g.40gb', ...], compute?},
    with {confirm: <node name>}. Refused while a running VM on the node holds an NVIDIA card."""
    if not NODE.match(node) or index < 0 or index > 63:
        return _bad('Invalid node or GPU index')
    mgr, err = _mgr_or_error(cluster_id)
    if err:
        return err
    data = _body()
    action = data.get('action')
    if action not in ('mode', 'layout'):
        return _bad('action: mode or layout')
    if str(data.get('confirm') or '') != node:
        return jsonify({'error': 'Type the node name to confirm', 'code': 'CONFIRM'}), 400
    state = mig.read_node(mgr, cluster_id, node, refresh=True)
    if not state.get('readable'):
        return jsonify({'error': f"Cannot read the node over SSH: {state.get('error')}", 'code': 'UNREADABLE'}), 502
    gpu = next((g for g in state['gpus'] if g['index'] == index), None)
    if not gpu:
        return _bad(f'No GPU {index} on {node}', 404)
    if not gpu['mig_capable'] or gpu['mig_current'] is None:
        return _bad(f"{gpu['name']} does not support MIG", 409)
    if action == 'layout':
        if gpu['mig_current'] != 'enabled' or gpu['mig_pending'] == 'disabled':
            return jsonify({'error': 'Turn MIG mode on first (and reset the GPU if it is pending)', 'code': 'MIG_OFF'}), 409
        try:
            ids = mig.resolve_layout(gpu, data.get('layout'))
        except ValueError as e:
            return _bad(str(e))
        cmd = mig.layout_command(index, ids, compute=bool(data.get('compute')))
        what = f"layout {', '.join(data.get('layout') or []) or '(empty)'}" + (' +CI' if data.get('compute') else '')
    else:
        enable = bool(data.get('enable'))
        cmd = mig.mode_command(index, enable, reset=bool(data.get('reset')))
        what = f"MIG mode {'on' if enable else 'off'}" + (' + GPU reset' if data.get('reset') else '')
    pci = accel.node_pci(mgr, node) or []
    nv_addr = [d.get('id') for d in pci if accel._hex(d.get('vendor'), 4) == '10de' and d.get('id')]
    vms = core._vm_states(cluster_id)
    configs = {vmid: accel.hostpci_of(mgr, node, vmid) or {} for vmid, vm in vms.items()
               if vm.get('node') == node and vm.get('status') == 'running' and vm.get('type') == 'qemu'}
    busy = mig.busy_vms(vms, configs, nv_addr, accel.pci_mappings(mgr) or [], node)
    if busy:
        return jsonify({'error': 'VMs on this node are using an NVIDIA card: stop them first', 'code': 'BUSY',
                        'vms': busy}), 409
    if not ha.confirm_step(f'MIG {what} on {node} GPU {index}'):
        return jsonify({'error': 'This instance is not the active one: nothing changed', 'code': 'HA_STANDBY'}), 409
    try:
        rc, out, errout = mgr._node_ssh_exec(node, cmd, timeout=120)
    except Exception as e:
        rc, out, errout = -1, '', str(e)
    mig.forget(cluster_id, node)
    text = '\n'.join(x for x in (str(out or '').strip(), str(errout or '').strip()) if x)[-2000:]
    log_audit(_user(), 'vlab.mig', f"{node} GPU {index} ({gpu['name']}): {what} - "
              + ('done' if rc == 0 else f'failed (rc={rc}): {text[-200:]}'), get_client_ip())
    after = mig.read_node(mgr, cluster_id, node, refresh=True)
    new = next((g for g in after.get('gpus') or [] if g['index'] == index), None)
    if rc != 0:
        return jsonify({'error': f'nvidia-smi failed (rc={rc})', 'code': 'COMMAND_FAILED', 'output': text, 'gpu': new}), 502
    return jsonify({'success': True, 'output': text, 'gpu': new,
                    'pending': bool(new and new.get('mig_pending') and new.get('mig_pending') != new.get('mig_current'))})
