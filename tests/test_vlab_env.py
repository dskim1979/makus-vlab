"""MOAVI Desk: the research environment catalogue (가상머신 > 환경 카탈로그) and NVIDIA MIG on the
nodes (GPU · FPGA · NPU > GPU · 가속 카드 재고) - pegaprox/vlab/envcat.py, pegaprox/vlab/mig.py,
pegaprox/api/vlab_env.py, and the MIG findings of pegaprox/vlab/accel_checks.py.

No real MIG card here: the node's nvidia-smi output below is what an A100 80GB in MIG mode with
a vGPU manager prints (NVIDIA MIG user guide, vGPU 17); SSH is stood in by _node_ssh_exec.
"""
import pytest

from pegaprox.core import ha
from pegaprox.vlab import accel, accel_checks, envcat, mig

CID = 'cluster_1'
RES = [
    {'vmid': 500, 'node': 'gpu1', 'name': 'gold-ai-2404', 'type': 'qemu', 'status': 'running'},
    {'vmid': 501, 'node': 'gpu1', 'name': 'gold-vivado', 'type': 'qemu', 'status': 'stopped'},
    {'vmid': 600, 'node': 'gpu1', 'name': 'ai-01', 'type': 'qemu', 'status': 'running'},
    {'vmid': 601, 'node': 'gpu1', 'name': 'ai-02', 'type': 'qemu', 'status': 'stopped'},
]
PCI = {'gpu1': [
    {'id': '0000:41:00.0', 'class': '0x030200', 'vendor': '0x10de', 'device': '0x20b5', 'vendor_name': 'NVIDIA Corporation',
     'device_name': 'GA100 [A100 PCIe 80GB]', 'iommugroup': 40, 'mdev': 1},
    {'id': '0000:41:00.4', 'class': '0x030200', 'vendor': '0x10de', 'device': '0x20b5', 'device_name': 'GA100 [A100 PCIe 80GB] (VF)'},
]}
MAPPINGS = [{'id': 'a100-vf', 'description': 'A100 VFs', 'mdev': 1,
             'map': ['id=10de:20b5,iommugroup=60,node=gpu1,path=0000:41:00.4']}]

GIP = '''+-----------------------------------------------------------------------------+
| GPU instance profiles:                                                      |
| GPU   Name             ID    Instances   Memory     P2P    SM    DEC   ENC  |
|                              Free/Total   GiB              CE    JPEG  OFA  |
|=============================================================================|
|   0  MIG 1g.10gb       19     5/7        9.75       No     14     0     0   |
|                                                             1     0     0   |
+-----------------------------------------------------------------------------+
|   0  MIG 1g.20gb       15     2/4        19.62      No     14     1     0   |
+-----------------------------------------------------------------------------+
|   0  MIG 2g.20gb       14     2/3        19.62      No     28     1     0   |
+-----------------------------------------------------------------------------+
|   0  MIG 3g.40gb        9     1/2        39.38      No     42     2     0   |
+-----------------------------------------------------------------------------+
|   0  MIG 4g.40gb        5     0/1        39.38      No     56     2     0   |
+-----------------------------------------------------------------------------+
|   0  MIG 7g.80gb        0     0/1        79.12      No     98     5     0   |
+-----------------------------------------------------------------------------+'''
GI = '''+-------------------------------------------------------+
| GPU instances:                                        |
| GPU   Name             Profile  Instance   Placement  |
|                          ID       ID       Start:Size |
|=======================================================|
|   0  MIG 3g.40gb          9        2          0:4     |
+-------------------------------------------------------+
|   0  MIG 1g.10gb         19        9          4:1     |
+-------------------------------------------------------+
|   0  MIG 1g.10gb         19       10          5:1     |
+-------------------------------------------------------+'''
CI = '''+--------------------------------------------------------------------+
| Compute instances:                                                 |
| GPU     GPU       Name             Profile   Instance   Placement  |
|       Instance                       ID        ID       Start:Size |
|         ID                                                         |
|====================================================================|
|   0      2       MIG 3g.40gb          2         0          0:3     |
+--------------------------------------------------------------------+'''


def node_out(mode='Enabled', pending='Enabled', driver='550.54.16', vgpu=True, gi=GI):
    return '\n'.join([
        '@@gpus', f'0, 00000000:41:00.0, NVIDIA A100 80GB PCIe, {driver}, {mode}, {pending}, 81920',
        '@@vgpu', '    Virtualization Mode                   : Host VGPU' if vgpu else '    Virtualization Mode : None',
        '    Host VGPU Mode                    : SR-IOV' if vgpu else '',
        '@@gip', GIP, '@@gi', gi, '@@ci', CI, '@@end'])


PROBE = '''@@os
Ubuntu 22.04
@@nvidia_driver
550.54.15
@@cuda_driver
CUDA Version: 12.4
@@cuda
Cuda compilation tools, release 12.4, V12.4.131
@@cudnn
#define CUDNN_MAJOR 9
#define CUDNN_MINOR 1
#define CUDNN_PATCHLEVEL 0
@@python
Python 3.10.12
@@pytorch
2.4.1+cu124 12.4
@@tensorflow
@@jax
@@rbln
@@rocm
@@vivado
@@vitis
@@quartus
@@furiosa
@@rbln_driver
@@end
'''


# --- pure rules ----------------------------------------------------------------------------

def test_the_probe_lists_only_what_is_installed():
    r = envcat.parse_probe(PROBE)
    got = {c['key']: c['version'] for c in r['components']}
    assert got == {'os': 'Ubuntu 22.04', 'nvidia_driver': '550.54.15', 'cuda': '12.4', 'cudnn': '9.1.0',
                   'python': '3.10.12', 'pytorch': '2.4.1+cu124'}
    assert (r['driver_cuda'], r['pytorch_cuda'], r['complete']) == ('12.4', '12.4', True)
    fpga = envcat.parse_probe('@@vivado\nVivado v2024.2 (64-bit)\n@@quartus\nVersion 23.1std.0 Build 991\n'
                              '@@furiosa\nfuriosa-smi 2025.1.0\n@@rocm\n6.2.1-112\n@@end\n')
    assert {c['key']: c['version'] for c in fpga['components']} == {
        'vivado': '2024.2', 'quartus': '23.1', 'furiosa': '2025.1.0', 'rocm': '6.2.1-112'}


def test_cuda_and_driver_tables():
    assert envcat.cuda_needs('12.4') == '550.54' and envcat.cuda_needs('11.8') == '520.61'
    assert envcat.cuda_needs('12.7') == '560.28'        # a minor the table lacks: the newest below it
    assert envcat.driver_cuda('550.90.07') == '12.4' and envcat.driver_cuda('535.183') == '12.2'
    assert envcat.cuda_check('550.54.15', '12.4') == []
    (n,) = envcat.cuda_check('535.183.01', '12.4')
    assert (n['code'], n['severity']) == ('CUDA_MINOR_COMPAT', 'warn')
    (n,) = envcat.cuda_check('470.82', '12.1')
    assert (n['code'], n['severity']) == ('CUDA_DRIVER_OLD', 'error')


def test_vgpu_needs_the_same_branch_on_host_and_guest():
    env = {'components': [{'key': 'nvidia_driver', 'version': '550.54.15'}, {'key': 'cuda', 'version': '12.4'}]}
    ok = envcat.compat(env, {'driver': '550.54.16', 'vgpu_manager': True, 'models': ['NVIDIA A100 80GB PCIe']})
    assert (ok['status'], ok['mode'], ok['host_vgpu_release']) == ('ok', 'vgpu', '17')
    older_host = envcat.compat(env, {'driver': '535.161.05', 'vgpu_manager': True, 'models': []})
    assert older_host['status'] == 'error' and older_host['notes'][0]['code'] == 'VGPU_BRANCH'
    older_guest = envcat.compat(env, {'driver': '570.124.03', 'vgpu_manager': True, 'models': []})
    assert older_guest['status'] == 'warn'
    # passthrough: the host driver does not matter, CUDA against the guest driver does
    pt = envcat.compat({'components': [{'key': 'nvidia_driver', 'version': '535.183'}, {'key': 'cuda', 'version': '12.4'}]},
                       {'driver': '', 'vgpu_manager': False, 'models': ['NVIDIA H100 80GB HBM3']})
    assert pt['mode'] == 'passthrough' and [n['code'] for n in pt['notes']] == ['CUDA_MINOR_COMPAT']
    # the CUDA a PyTorch wheel was built for counts too
    torch = envcat.compat({'components': [{'key': 'nvidia_driver', 'version': '525.147'},
                                          {'key': 'pytorch', 'version': '2.5.1+cu124'}]}, {'vgpu_manager': False})
    assert torch['pytorch_cuda'] == '12.4' and torch['notes'][0]['ko'].startswith('PyTorch 2.5.1+cu124 (CUDA 12.4)')
    blackwell = envcat.compat({'components': [{'key': 'nvidia_driver', 'version': '550.54'}]},
                              {'vgpu_manager': False, 'models': ['NVIDIA B200']})
    assert blackwell['status'] == 'error' and blackwell['notes'][0]['code'] == 'ARCH_DRIVER'


def test_nvidia_smi_output_is_read():
    st = mig.parse_node(node_out())
    (g,) = st['gpus']
    assert (st['driver'], st['vgpu_manager'], g['bus_id'], g['mig_current'], g['memory_mb']) == (
        '550.54.16', True, '0000:41:00.0', 'enabled', 81920)
    assert [(p['name'], p['id'], p['free'], p['total']) for p in g['profiles']][:2] == [('1g.10gb', 19, 5, 7), ('1g.20gb', 15, 2, 4)]
    assert [(i['profile'], i['id'], i['start'], i['size']) for i in g['gpu_instances']] == [
        ('3g.40gb', 2, 0, 4), ('1g.10gb', 9, 4, 1), ('1g.10gb', 10, 5, 1)]
    assert g['slices_used'] == 6 and g['compute_instances'][0]['gpu_instance'] == 2
    plain = mig.parse_node('@@gpus\n0, 00000000:81:00.0, NVIDIA L40S, 550.54.16, [N/A], [N/A], 46068\n@@vgpu\n@@gip\n'
                           'No MIG-enabled devices found.\n@@gi\n@@ci\n@@end\n')
    assert plain['gpus'][0]['mig_capable'] is False and plain['vgpu_manager'] is False
    assert mig.parse_node('@@none\n@@end\n')['nvidia'] is False
    assert mig.card_state(st, '0000:41:00.4')['index'] == 0          # a VF finds its card by the bus
    assert mig.vgpu_profile_slices('NVIDIA A100-3-40C') == 3 and mig.vgpu_profile_slices('NVIDIA A100-4C') is None
    assert accel.parse_profile({'type': 'nvidia-700', 'name': 'NVIDIA A100D-1-10CME'})['mig_slices'] == 1


def test_layouts_are_checked_against_the_card():
    (g,) = mig.parse_node(node_out())['gpus']
    assert mig.resolve_layout(g, ['3g.40gb', '2g.20gb', 19, '19']) == [9, 14, 19, 19]
    with pytest.raises(ValueError):
        mig.resolve_layout(g, ['5g.50gb'])
    with pytest.raises(ValueError):
        mig.resolve_layout(g, ['3g.40gb'] * 3)              # two fit
    with pytest.raises(ValueError):
        mig.resolve_layout(g, ['4g.40gb', '4g.40gb'])        # 8 of 7 slices (and one 4g at most)
    cmd = mig.layout_command(0, [9, 19], compute=True)
    assert cmd.endswith('$S nvidia-smi mig -i 0 -cgi 9,19 -C') and '-dgi' in cmd and 'sudo -n' in cmd
    assert mig.mode_command(1, True, reset=True).endswith('$S nvidia-smi -i 1 -mig 1 && $S nvidia-smi -i 1 -r')


# --- routes ---------------------------------------------------------------------------------

@pytest.fixture
def lab(api, seed, monkeypatch):
    mgr = api.make_fake_manager(CID, get_vm_resources=RES, get_node_status={'gpu1': {'status': 'online'}},
                                get_snapshots=[{'name': 'gold-20261001-0900', 'snaptime': 1}],
                                create_pool=None, update_vm_config={'success': True})
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    configs = {600: {'hostpci15': 'mapping=a100-vf,pcie=1,mdev=nvidia-700'}, 601: {}, 500: {}, 501: {}}
    ssh = {'out': node_out(), 'calls': []}

    def node_exec(node, cmd, timeout=30):
        ssh['calls'].append(cmd)
        return (0, ssh['out'], '') if 'nvidia-smi --query-gpu' in cmd else (0, 'Created GPU instance', '')
    mgr._node_ssh_exec.side_effect = node_exec
    monkeypatch.setattr(accel, 'node_pci', lambda m, node: PCI.get(node))
    monkeypatch.setattr(accel, 'pci_mappings', lambda m: [accel.parse_mapping(x) for x in MAPPINGS])
    monkeypatch.setattr(accel, 'hostpci_of', lambda m, node, vmid: dict(configs.get(int(vmid), {})))
    monkeypatch.setattr(accel, 'vm_raw', lambda m, node, vmid: dict(configs.get(int(vmid), {}), machine='q35', bios='ovmf'))
    mig.forget(CID)
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    gold = admin.post('/api/vlab/admin/golden-images', json={'cluster_id': CID, 'vmid': 500, 'name': 'AI 연구 (PyTorch)'}).get_json()['image']
    yield api, mgr, admin, alice, gold, configs, ssh
    mig.forget(CID)


def test_environment_is_saved_with_its_history(lab):
    _, _, admin, alice, gold, _, _ = lab
    url = f"/api/vlab/admin/golden-images/{gold['id']}/environment"
    assert admin.put(url, json={'kind': 'magic'}).status_code == 400
    assert admin.put(url, json={'components': [{'key': 'cuda', 'version': '12.4'}, {'key': 'cuda', 'version': '12.1'}]}).status_code == 400
    assert admin.put(url, json={'cards': {'mappings': ['0000:41:00.0']}}).status_code == 400
    r = admin.put(url, json={'kind': 'ai', 'description': 'LLM 미세조정 실습', 'note': '첫 등록',
                             'components': [{'key': 'os', 'version': 'Ubuntu 22.04'}, {'key': 'cuda', 'version': '12.4'},
                                            {'key': 'pytorch', 'version': '2.4.1'}],
                             'cards': {'mappings': ['a100-vf'], 'vendors': ['NVIDIA']}})
    assert r.status_code == 200, r.get_json()
    env = r.get_json()['environment']
    assert env['kind'] == 'ai' and env['highlights'][:2] == ['CUDA 12.4', 'PyTorch 2.4.1']
    assert env['history'][0]['note'] == '첫 등록' and env['history'][0]['changes'][0] == {'key': 'os', 'from': None, 'to': 'Ubuntu 22.04'}
    admin.put(url, json={'components': [{'key': 'os', 'version': 'Ubuntu 22.04'}, {'key': 'cuda', 'version': '12.6'},
                                        {'key': 'pytorch', 'version': '2.4.1'}]})
    (e,) = [x for x in admin.get('/api/vlab/admin/environments').get_json()['environments'] if x['golden_id'] == gold['id']]
    assert e['history'][0]['changes'] == [{'key': 'cuda', 'from': '12.4', 'to': '12.6'}] and len(e['history']) == 2
    assert e['status'] == 'running'
    assert alice.get('/api/vlab/admin/environments').status_code == 403
    assert alice.put(url, json={'kind': 'ai'}).status_code == 403
    # the image goes, its environment with it
    admin.delete(f"/api/vlab/admin/golden-images/{gold['id']}")
    assert envcat.get(gold['id']) is None


def test_version_read_through_the_guest_agent(lab, monkeypatch):
    from pegaprox.api import vlab_next
    _, _, admin, _, gold, _, _ = lab
    seen = {}

    def run(mgr, node, vmid, argv, stdin=None, wait=8):
        seen['argv'] = argv
        return 0, PROBE, '', ''
    monkeypatch.setattr(vlab_next, '_guest_os', lambda m, n, v: 'linux')
    monkeypatch.setattr(vlab_next, '_agent_run', run)
    url = f"/api/vlab/admin/golden-images/{gold['id']}/environment"
    admin.put(url, json={'components': [{'key': 'cuda', 'version': '12.1'}, {'key': 'custom_lib', 'version': '1.0'}]})
    r = admin.post(url + '/probe', json={'apply': True})
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert seen['argv'][:2] == ['/bin/bash', '-c'] and '@@pytorch' in seen['argv'][2]
    assert {'key': 'cuda', 'from': '12.1', 'to': '12.4'} in body['changes']
    comps = {c['key']: c for c in body['environment']['components']}
    assert comps['custom_lib']['version'] == '1.0' and comps['cuda']['source'] == 'probe'
    assert body['environment']['history'][0]['note'] == '버전 읽기'
    # without apply only the probe is kept
    admin.put(url, json={'components': [{'key': 'cuda', 'version': '12.1'}]})
    body = admin.post(url + '/probe').get_json()
    assert body['changes'] == [] and body['environment']['components'] == [{'key': 'cuda', 'name': 'CUDA', 'version': '12.1'}]
    assert body['environment']['probe']['driver_cuda'] == '12.4'
    monkeypatch.setattr(vlab_next, '_guest_os', lambda m, n, v: None)
    assert admin.post(url + '/probe').get_json()['code'] == 'NO_AGENT'
    stopped = admin.post('/api/vlab/admin/golden-images', json={'cluster_id': CID, 'vmid': 501}).get_json()['image']
    r = admin.post(f"/api/vlab/admin/golden-images/{stopped['id']}/environment/probe")
    assert r.status_code == 409 and r.get_json()['code'] == 'NOT_RUNNING'


def test_compatibility_table(lab):
    _, _, admin, _, gold, _, ssh = lab
    admin.put(f"/api/vlab/admin/golden-images/{gold['id']}/environment",
              json={'kind': 'ai', 'components': [{'key': 'nvidia_driver', 'version': '535.161.08'}, {'key': 'cuda', 'version': '12.2'}],
                    'cards': {'mappings': ['a100-vf']}})
    r = admin.get(f'/api/vlab/admin/clusters/{CID}/environment-compat').get_json()
    assert r['nodes'] == [{'node': 'gpu1', 'readable': True, 'error': '', 'driver': '550.54.16', 'vgpu_manager': True,
                           'models': ['NVIDIA A100 80GB PCIe']}]
    (row,) = r['rows']
    cell = row['cells']['gpu1']
    assert (cell['mode'], cell['status'], cell['notes'][0]['code']) == ('vgpu', 'warn', 'VGPU_BRANCH')
    # read once a minute
    n = len(ssh['calls'])
    admin.get(f'/api/vlab/admin/clusters/{CID}/environment-compat')
    assert len(ssh['calls']) == n
    admin.get(f'/api/vlab/admin/clusters/{CID}/environment-compat?refresh=1')
    assert len(ssh['calls']) == n + 1


def test_mig_state_per_node(lab):
    _, _, admin, alice, _, _, ssh = lab
    r = admin.get(f'/api/vlab/admin/clusters/{CID}/mig').get_json()
    (node,) = r['nodes']
    (card,) = node['cards']                                  # the VF is not a card of its own
    assert (node['node'], node['vgpu_manager'], card['mig_capable'], card['state']['mig_current']) == ('gpu1', True, True, 'enabled')
    assert [u['vmid'] for u in card['used_by']] == [600]      # through the mapping of its VF
    assert r['summary'] == {'mig_capable': 1, 'mig_enabled': 1, 'gpu_instances': 3}
    assert 'A100 80GB' in r['reference']
    assert alice.get(f'/api/vlab/admin/clusters/{CID}/mig').status_code == 403
    ssh['out'] = ''
    mig.forget(CID)
    mgr = lab[1]
    mgr._node_ssh_exec.side_effect = lambda node, cmd, timeout=30: (-1, '', 'SSH connection to gpu1 failed')
    (node,) = admin.get(f'/api/vlab/admin/clusters/{CID}/mig').get_json()['nodes']
    assert node['readable'] is False and 'SSH' in node['error'] and node['cards'][0]['mig_capable'] is True


def test_mig_writes_wait_for_an_idle_node(lab, monkeypatch):
    _, mgr, admin, alice, _, configs, ssh = lab
    monkeypatch.setattr(ha, 'confirm_step', lambda *a, **k: True)
    url = f'/api/vlab/admin/clusters/{CID}/nodes/gpu1/mig/0'
    body = {'action': 'layout', 'layout': ['3g.40gb', '3g.40gb'], 'confirm': 'gpu1'}
    assert alice.put(url, json=body).status_code == 403
    assert admin.put(url, json=dict(body, confirm='gpu2')).get_json()['code'] == 'CONFIRM'
    r = admin.put(url, json=body)                             # ai-01 runs on the card's VF
    assert r.status_code == 409 and r.get_json()['code'] == 'BUSY' and r.get_json()['vms'][0]['vmid'] == 600
    assert not any('-cgi' in c for c in ssh['calls'])
    configs[600] = {}
    assert admin.put(url, json=dict(body, layout=['9g.90gb'])).status_code == 400
    monkeypatch.setattr(ha, 'confirm_step', lambda *a, **k: False)
    assert admin.put(url, json=body).get_json()['code'] == 'HA_STANDBY'
    monkeypatch.setattr(ha, 'confirm_step', lambda *a, **k: True)
    r = admin.put(url, json=body)
    assert r.status_code == 200, r.get_json()
    assert any(c.endswith('-cgi 9,9') for c in ssh['calls'])
    r = admin.put(url, json={'action': 'mode', 'enable': False, 'confirm': 'gpu1'})
    assert r.status_code == 200 and any(c.endswith('nvidia-smi -i 0 -mig 0') for c in ssh['calls'])
    # a card not in MIG mode takes no layout
    ssh['out'] = node_out(mode='Disabled', pending='Disabled')
    assert admin.put(url, json=body).get_json()['code'] == 'MIG_OFF'


def test_pool_policy_takes_a_mig_backed_profile(lab):
    _, _, admin, _, _, _, _ = lab
    pool = admin.post('/api/vlab/admin/pools', json={'name': 'LLM 실습', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    r = admin.put(f"/api/vlab/admin/pools/{pool['id']}/gpu", json={'mode': 'vgpu', 'mapping': 'a100-vf', 'mdev_type': 'nvidia-700',
                                                                   'label': 'A100-3-40C', 'mig': True})
    assert r.get_json()['gpu'] == {'mode': 'vgpu', 'mapping': 'a100-vf', 'mdev_type': 'nvidia-700', 'mig': True, 'label': 'A100-3-40C'}


def test_mig_checks():
    state = mig.parse_node(node_out())
    ctx = {'cluster_id': CID, 'vmid': 600, 'desktop_id': 'd1', 'name': 'ai-01'}
    maps = [accel.parse_mapping(x) for x in MAPPINGS] + [
        accel.parse_mapping({'id': 'a100-whole', 'map': ['id=10de:20b5,node=gpu1,path=0000:41:00.0']})]

    def codes(raw, policy=None, st=state):
        return sorted(f['code'] for f in accel_checks.for_vm(None, CID, 'gpu1', 600, raw=dict(raw, machine='q35', bios='ovmf'),
                                                             mappings=maps, mig_state=st, gpu_policy=policy) if f['code'].startswith('MIG'))
    assert codes({'hostpci15': 'mapping=a100-vf,pcie=1,mdev=nvidia-700'}, {'mig': True}) == []
    assert codes({'hostpci15': 'mapping=a100-vf,pcie=1,mdev=nvidia-700'}, {}) == ['MIG_TIMESLICED']
    assert codes({'hostpci0': 'mapping=a100-whole,pcie=1'}) == ['MIG_WHOLE_PASSTHROUGH']
    assert codes({'hostpci0': '0000:41:00.0,pcie=1'}) == ['MIG_WHOLE_PASSTHROUGH']
    empty = mig.parse_node(node_out(gi='No GPU instances found: Not Found'))
    assert codes({'hostpci15': 'mapping=a100-vf,pcie=1,mdev=nvidia-700'}, {'mig': True}, empty) == ['MIG_NO_INSTANCES']
    off = mig.parse_node(node_out(mode='Disabled', pending='Disabled', gi=''))
    assert codes({'hostpci15': 'mapping=a100-vf,pcie=1,mdev=nvidia-700'}, {'mig': True}, off) == ['MIG_MODE_OFF']
    assert codes({'hostpci15': 'mapping=a100-vf,pcie=1,mdev=nvidia-700'}, {'mig': True}, None) == []


def test_mig_pending_and_checks_through_the_route(lab, monkeypatch):
    _, _, admin, _, _, _, ssh = lab
    pool = admin.post('/api/vlab/admin/pools', json={'name': 'LLM', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': 600})
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/gpu", json={'mode': 'vgpu', 'mapping': 'a100-vf', 'mdev_type': 'nvidia-700'})
    ssh['out'] = node_out(pending='Disabled')
    codes = [f['code'] for f in admin.get('/api/vlab/admin/accel/checks').get_json()['findings']]
    assert 'MIG_PENDING' in codes and 'MIG_TIMESLICED' in codes


def test_the_portal_shows_the_environment(lab, seed):
    api, _, admin, _, gold, _, _ = lab
    admin.put(f"/api/vlab/admin/golden-images/{gold['id']}/environment",
              json={'kind': 'ai', 'components': [{'key': 'cuda', 'version': '12.4'}, {'key': 'pytorch', 'version': '2.4.1'},
                                                 {'key': 'os', 'version': 'Ubuntu 22.04'}, {'key': 'python', 'version': '3.10'}]})
    pool = admin.post('/api/vlab/admin/pools', json={'name': 'AI 실습', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    from pegaprox.vlab import catalog, store
    store.set_pool_settings(pool['id'], dict(store.get_pool(pool['id']).get('settings') or {}, golden_id=gold['id']))
    catalog.set_pool_grants(pool['id'], [{'subject_type': 'user', 'subject_id': 'carol'}])
    carol = api.as_user(seed.user('carol', role='user'))
    (p,) = [x for x in carol.get('/api/vlab/me/pools').get_json()['pools'] if x['id'] == pool['id']]
    assert p['environment'] == {'name': 'AI 연구 (PyTorch)', 'kind': 'ai', 'highlights': ['CUDA 12.4', 'PyTorch 2.4.1', 'Ubuntu 22.04']}
