"""vLAB accelerators (MAKUS): GPU / FPGA inventory, vGPU profiles and the pools' GPU policy.

A desktop gets its GPU through a PCI resource mapping in vLAB's own slot (hostpci15), so a
token-connected cluster can do it and hand-made hostpci entries stay as they are.
docs/vlab-design.md 10-0.
"""
import pytest

from pegaprox.vlab import accel

CID = 'cluster_1'
RES = [
    {'vmid': 300, 'node': 'pve1', 'name': 'ai-desk-01', 'type': 'qemu', 'status': 'running', 'maxcpu': 8},
    {'vmid': 301, 'node': 'pve1', 'name': 'ai-desk-02', 'type': 'qemu', 'status': 'stopped'},
    {'vmid': 302, 'node': 'pve2', 'name': 'vivado-01', 'type': 'qemu', 'status': 'running'},
]
PCI = {
    'pve1': [
        {'id': '0000:02:00.0', 'class': '0x030000', 'vendor': '0x1a03', 'device': '0x2000', 'vendor_name': 'ASPEED'},
        {'id': '0000:41:00.0', 'class': '0x030200', 'vendor': '0x10de', 'device': '0x25b6', 'vendor_name': 'NVIDIA Corporation',
         'device_name': 'GA107GL [A16]', 'iommugroup': 40, 'mdev': 1},
        {'id': '0000:41:00.1', 'class': '0x040300', 'vendor': '0x10de', 'device': '0x2291'},          # its audio function
        {'id': '0000:81:00.0', 'class': '0x030000', 'vendor': '0x1002', 'device': '0x7448', 'device_name': 'Radeon PRO W7900'},
    ],
    'pve2': [
        {'id': '0000:c1:00.0', 'class': '0x120000', 'vendor': '0x10ee', 'device': '0x5048', 'device_name': 'Alveo U250'},
    ],
}
MAPPINGS = [
    {'id': 'gpu-a16', 'description': 'A16 vGPU', 'mdev': 1,
     'map': ['id=10de:25b6,iommugroup=40,node=pve1,path=0000:41:00.0,subsystem-id=10de:14a9']},
]


# --- parsing ----------------------------------------------------------------------

@pytest.mark.parametrize('dev, kind', [
    ({'class': '0x030200', 'vendor': '0x10de'}, 'gpu'),
    ({'class': 0x030000, 'vendor': 0x1002}, 'gpu'),
    ({'class': '038000', 'vendor': '1002'}, 'gpu'),            # AMD Instinct
    ({'class': '0x120000', 'vendor': '0x10de'}, 'gpu'),        # compute-only card
    ({'class': '0x030000', 'vendor': '0x1a03'}, None),         # the board's remote-console chip
    ({'class': '0x030000', 'vendor': '0x102b'}, None),
    ({'class': '0x040300', 'vendor': '0x10de'}, None),         # a GPU's audio function
    ({'class': '0x120000', 'vendor': '0x10ee'}, 'fpga'),
    ({'class': '0x058000', 'vendor': '0x10ee'}, 'fpga'),       # the card's management function
    ({'class': '0x020000', 'vendor': '0x8086'}, None),         # a NIC
])
def test_devices_are_classified(dev, kind):
    assert accel.classify(dev) == kind


def test_vgpu_profiles_carry_their_numbers():
    p = accel.parse_profile({'type': 'nvidia-746', 'name': 'NVIDIA A16-2Q', 'available': 16,
                             'description': 'num_heads=4, frl_config=60, framebuffer=2048M, max_resolution=5120x2880, max_instance=16'})
    assert (p['framebuffer_mb'], p['max_instance'], p['heads'], p['max_resolution'], p['available']) == (
        2048, 16, 4, '5120x2880', 16)
    assert accel.parse_profile({'type': 'x', 'description': 'framebuffer=4G'})['framebuffer_mb'] == 4096


def test_hostpci_values_are_read():
    assert accel.parse_hostpci('mapping=gpu-a16,mdev=nvidia-746,pcie=1') == {
        'mapping': 'gpu-a16', 'addresses': [], 'mdev': 'nvidia-746'}
    assert accel.parse_hostpci('0000:41:00.0,pcie=1,x-vga=1')['addresses'] == ['0000:41:00.0']
    assert accel.parse_hostpci('host=41:00.0;41:00.1,pcie=1')['addresses'] == ['41:00.0', '41:00.1']
    assert accel.address_matches('0000:41:00.0', ['41:00'])          # all functions of the device
    assert accel.address_matches('0000:41:00.0', ['41:00.0'])
    assert not accel.address_matches('0000:41:00.0', ['41:00.1'])


def test_the_slot_value_follows_the_policy():
    assert accel.gpu_value({'mode': 'vgpu', 'mapping': 'gpu-a16', 'mdev_type': 'nvidia-746'}) == \
        'mapping=gpu-a16,pcie=1,mdev=nvidia-746'
    assert accel.gpu_value({'mode': 'passthrough', 'mapping': 'w7900', 'x_vga': True}) == 'mapping=w7900,pcie=1,x-vga=1'
    assert accel.gpu_value({'mode': 'none'}) is None and accel.gpu_value(None) is None


# --- routes -----------------------------------------------------------------------

@pytest.fixture
def gpu(api, seed, monkeypatch):
    mgr = api.make_fake_manager(CID, get_vm_resources=RES, update_vm_config={'success': True},
                                rollback_snapshot={'success': True},
                                get_node_status={'pve1': {'status': 'online'}, 'pve2': {'status': 'online'}})
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    configs = {300: {'hostpci0': '0000:81:00.0,pcie=1,x-vga=1'}, 301: {}, 302: {'hostpci0': 'mapping=gpu-a16,mdev=nvidia-746'}}
    monkeypatch.setattr(accel, 'node_pci', lambda m, node: PCI.get(node))
    monkeypatch.setattr(accel, 'pci_mappings', lambda m: [accel.parse_mapping(x) for x in MAPPINGS])
    monkeypatch.setattr(accel, 'hostpci_of', lambda m, node, vmid: dict(configs.get(int(vmid), {})))
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    return api, mgr, admin, alice, configs


def _pool(admin, vmids=(300, 301), type_='dedicated'):
    pool = admin.post('/api/vlab/admin/pools', json={'name': 'AI 연구실', 'type': type_, 'cluster_id': CID}).get_json()['pool']
    desks = [admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': v}).get_json()['desktop'] for v in vmids]
    return pool, desks


def test_accelerators_list_gpus_and_fpgas_and_who_uses_them(gpu):
    _, _, admin, alice, _ = gpu
    _pool(admin, vmids=(300,))
    r = admin.get(f'/api/vlab/admin/clusters/{CID}/accelerators').get_json()
    devs = {(d['node'], d['pciid']): d for d in r['devices']}
    assert set(devs) == {('pve1', '0000:41:00.0'), ('pve1', '0000:81:00.0'), ('pve2', '0000:c1:00.0')}
    a16 = devs[('pve1', '0000:41:00.0')]
    assert (a16['kind'], a16['vgpu_capable'], a16['iommu_group'], a16['mappings'], a16['used_by']) == (
        'gpu', True, 40, ['gpu-a16'], [])
    (w7900_user,) = devs[('pve1', '0000:81:00.0')]['used_by']
    assert (w7900_user['vmid'], w7900_user['slot'], w7900_user['pool']) == (300, 'hostpci0', 'AI 연구실')
    assert devs[('pve2', '0000:c1:00.0')]['kind'] == 'fpga'
    (m,) = r['mappings']
    assert [(u['vmid'], u['mdev']) for u in m['used_by']] == [(302, 'nvidia-746')]
    assert r['summary'] == {'gpus': 2, 'fpgas': 1, 'vgpu_capable': 1, 'in_use': 2}
    assert alice.get(f'/api/vlab/admin/clusters/{CID}/accelerators').status_code == 403
    assert admin.get('/api/vlab/admin/clusters/nowhere/accelerators').status_code == 404


def test_card_profiles(gpu, monkeypatch):
    _, _, admin, _, _ = gpu
    monkeypatch.setattr(accel, 'mdev_types', lambda m, node, pciid: [accel.parse_profile(
        {'type': 'nvidia-746', 'name': 'NVIDIA A16-2Q', 'available': 8, 'description': 'framebuffer=2048M, max_instance=16'})])
    url = f'/api/vlab/admin/clusters/{CID}/nodes/pve1/pci/0000:41:00.0/profiles'
    (p,) = admin.get(url).get_json()['profiles']
    assert (p['type'], p['available'], p['framebuffer_mb']) == ('nvidia-746', 8, 2048)
    assert admin.get(f'/api/vlab/admin/clusters/{CID}/nodes/pve1/pci/zz/profiles').status_code == 400
    monkeypatch.setattr(accel, 'mdev_types', lambda m, node, pciid: None)
    assert admin.get(url).status_code == 502


def test_pool_gpu_policy_is_checked_and_saved(gpu):
    _, _, admin, alice, _ = gpu
    pool, _ = _pool(admin)
    url = f"/api/vlab/admin/pools/{pool['id']}/gpu"
    assert admin.put(url, json={'mode': 'magic'}).status_code == 400
    assert admin.put(url, json={'mode': 'vgpu', 'mapping': 'gpu-a16'}).status_code == 400          # no profile
    assert admin.put(url, json={'mode': 'vgpu', 'mapping': 'nope', 'mdev_type': 'nvidia-746'}).status_code == 404
    assert admin.put(url, json={'mode': 'passthrough', 'mapping': '0000:41:00.0'}).status_code == 400  # raw address
    r = admin.put(url, json={'mode': 'vgpu', 'mapping': 'gpu-a16', 'mdev_type': 'nvidia-746', 'label': 'A16-2Q'})
    assert r.status_code == 200 and r.get_json()['gpu']['mdev_type'] == 'nvidia-746'
    assert alice.put(url, json={'mode': 'none'}).status_code == 403
    desks = admin.get(f"/api/vlab/admin/pools/{pool['id']}/desktops").get_json()['desktops']
    assert all(d['gpu'] == {'mode': 'vgpu', 'label': 'A16-2Q'} for d in desks)


def test_applying_writes_only_vlabs_slot(gpu):
    _, mgr, admin, _, configs = gpu
    pool, desks = _pool(admin)
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/gpu", json={'mode': 'vgpu', 'mapping': 'gpu-a16', 'mdev_type': 'nvidia-746'})
    r = admin.post(f"/api/vlab/admin/pools/{pool['id']}/gpu/apply")
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert len(body['applied']) == 2 and body['needs_restart'] == [desks[0]['id']]          # 300 is running
    calls = [c[0] for c in mgr.update_vm_config.call_args_list]
    assert calls == [('pve1', 300, 'qemu', {'hostpci15': 'mapping=gpu-a16,pcie=1,mdev=nvidia-746'}),
                     ('pve1', 301, 'qemu', {'hostpci15': 'mapping=gpu-a16,pcie=1,mdev=nvidia-746'})]
    # already there: nothing written again
    configs[300]['hostpci15'] = configs[301]['hostpci15'] = 'mapping=gpu-a16,pcie=1,mdev=nvidia-746'
    mgr.update_vm_config.reset_mock()
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/gpu/apply")
    assert mgr.update_vm_config.call_count == 0
    # none takes vLAB's slot out and leaves hostpci0 alone
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/gpu", json={'mode': 'none'})
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/gpu/apply")
    assert [c[0][3] for c in mgr.update_vm_config.call_args_list] == [{'delete': 'hostpci15'}] * 2


def test_a_reset_puts_the_gpu_back(gpu):
    _, mgr, admin, _, _ = gpu
    pool, desks = _pool(admin, vmids=(301,), type_='reset')
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/gpu", json={'mode': 'passthrough', 'mapping': 'gpu-a16'})
    from pegaprox.vlab import store
    store.set_base_snap(desks[0]['id'], 'vlab-base')
    mgr.update_vm_config.reset_mock()
    assert admin.post(f"/api/vlab/admin/desktops/{desks[0]['id']}/reset").status_code == 200
    assert mgr.update_vm_config.call_args[0] == ('pve1', 301, 'qemu', {'hostpci15': 'mapping=gpu-a16,pcie=1'})


# --- card loans ---------------------------------------------------------------------

FPGA_MAPPINGS = MAPPINGS + [
    {'id': 'fpga-u250', 'description': 'Alveo U250', 'map': [
        'id=10ee:5004,iommugroup=51,node=pve2,path=0000:c1:00.0',
        'id=10ee:5004,iommugroup=52,node=pve2,path=0000:c2:00.0']},
]


@pytest.fixture
def loans(gpu, monkeypatch):
    api, mgr, admin, alice, configs = gpu
    monkeypatch.setattr(accel, 'pci_mappings', lambda m: [accel.parse_mapping(x) for x in FPGA_MAPPINGS])
    pool, desks = _pool(admin, vmids=(300, 301))
    for d in desks:
        admin.put(f"/api/vlab/admin/desktops/{d['id']}/assign", json={'username': 'alice'})
    mgr.update_vm_config.reset_mock()
    return api, mgr, admin, alice, desks


def _later(days=7):
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec='seconds')


def test_a_card_is_lent_to_a_desktop(loans):
    _, mgr, admin, alice, desks = loans
    r = admin.post('/api/vlab/admin/leases', json={'desktop_id': desks[0]['id'], 'mapping': 'fpga-u250', 'ends_at': _later()})
    assert r.status_code == 201, r.get_json()
    lease = r.get_json()['lease']
    assert (lease['resource_type'], lease['username'], lease['vmid'], lease['state']) == ('fpga', 'alice', 300, 'active')
    assert r.get_json()['needs_restart'] is True                           # 300 is running
    assert mgr.update_vm_config.call_args[0] == ('pve1', 300, 'qemu', {'hostpci14': 'mapping=fpga-u250,pcie=1'})
    (row,) = admin.get('/api/vlab/admin/leases').get_json()['leases']
    assert (row['desktop'], row['vm_running']) == ('ai-desk-01', True)
    (mine,) = alice.get('/api/vlab/me/leases').get_json()['leases']
    assert (mine['kind'], mine['name'], mine['desktop']) == ('fpga', 'Alveo U250', 'ai-desk-01')
    assert alice.post('/api/vlab/admin/leases', json={}).status_code == 403


def test_loans_are_checked(loans):
    _, _, admin, _, desks = loans
    url = '/api/vlab/admin/leases'
    ok = {'desktop_id': desks[0]['id'], 'mapping': 'fpga-u250', 'ends_at': _later()}
    assert admin.post(url, json={**ok, 'ends_at': 'soon'}).status_code == 400
    assert admin.post(url, json={**ok, 'ends_at': _later(-1)}).status_code == 400
    assert admin.post(url, json={**ok, 'mapping': 'nope'}).status_code == 404
    assert admin.post(url, json={**ok, 'desktop_id': 'nope'}).status_code == 404
    assert admin.post(url, json=ok).status_code == 201
    assert admin.post(url, json=ok).status_code == 409                    # one card per desktop
    # gpu-a16 has one card: the second desktop cannot get one while it is out
    assert admin.post(url, json={**ok, 'desktop_id': desks[1]['id'], 'mapping': 'gpu-a16'}).status_code == 201
    from pegaprox.vlab import store
    third = admin.post('/api/vlab/admin/pools', json={'name': 'B', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    d3 = admin.post(f"/api/vlab/admin/pools/{third['id']}/desktops", json={'vmid': 302}).get_json()['desktop']
    assert admin.post(url, json={**ok, 'desktop_id': d3['id'], 'mapping': 'gpu-a16'}).status_code == 409   # not assigned
    admin.put(f"/api/vlab/admin/desktops/{d3['id']}/assign", json={'username': 'alice'})
    r = admin.post(url, json={**ok, 'desktop_id': d3['id'], 'mapping': 'gpu-a16'})
    assert r.status_code == 409 and 'lent out' in r.get_json()['error']
    assert len(store.active_leases_on(CID, 'gpu-a16')) == 1


def test_return_and_extend(loans, gpu):
    _, mgr, admin, _, desks = loans
    lease = admin.post('/api/vlab/admin/leases', json={'desktop_id': desks[1]['id'], 'mapping': 'fpga-u250',
                                                       'ends_at': _later(2)}).get_json()['lease']
    gpu[4][301]['hostpci14'] = 'mapping=fpga-u250,pcie=1'               # what the create wrote
    url = f"/api/vlab/admin/leases/{lease['id']}"
    assert admin.post(url + '/extend', json={'ends_at': _later(1)}).status_code == 400   # earlier than now's end
    r = admin.post(url + '/extend', json={'ends_at': _later(10)})
    assert r.status_code == 200 and r.get_json()['lease']['ends_at'] > lease['ends_at']
    assert admin.post(url + '/return').status_code == 200
    assert mgr.update_vm_config.call_args[0] == ('pve1', 301, 'qemu', {'delete': 'hostpci14'})
    assert admin.get('/api/vlab/admin/leases').get_json()['leases'] == []
    (closed,) = admin.get('/api/vlab/admin/leases?all=1').get_json()['leases']
    assert closed['state'] == 'returned' and closed['returned_at']
    assert admin.post(url + '/return').status_code == 409


def test_due_loans_go_back_by_themselves(loans, gpu):
    _, mgr, admin, _, desks = loans
    configs = gpu[4]
    from pegaprox.vlab import loans as loan_job
    from pegaprox.vlab import store
    lease = admin.post('/api/vlab/admin/leases', json={'desktop_id': desks[1]['id'], 'mapping': 'fpga-u250',
                                                       'ends_at': _later()}).get_json()['lease']
    configs[301]['hostpci14'] = 'mapping=fpga-u250,pcie=1'
    store.extend_lease(lease['id'], '2000-01-01T00:00:00+00:00')          # long due
    assert loan_job.return_due() == (1, 0)
    assert store.get_lease(lease['id'])['state'] == 'returned'
    assert mgr.update_vm_config.call_args[0] == ('pve1', 301, 'qemu', {'delete': 'hostpci14'})
    assert loan_job.return_due() == (0, 0)
