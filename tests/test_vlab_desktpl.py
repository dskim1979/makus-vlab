# -*- coding: utf-8 -*-
"""MOAVI Desk desktop templates (pegaprox/vlab/desktpl.py, pegaprox/api/vlab_desktpl.py): the presets, the
texts the build puts in the guest, and a whole Linux and Windows build against a stand-in node (SSH)
and guest agent."""
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET

import pytest

from pegaprox.core import ha
from pegaprox.vlab import desktpl

CID = 'cluster_1'


# --- the texts -------------------------------------------------------------------------------

def test_every_preset_is_offered_with_its_oses():
    ps = {p['id']: p for p in desktpl.preset_list()}
    assert set(ps) == {'office', 'research', 'gpu', 'npu', 'fpga'}
    assert [o['id'] for o in ps['office']['os_options']] == ['win11', 'win10', 'ws2025', 'ws2022']
    assert {'ubuntu-2604', 'debian-12', 'rocky-9', 'almalinux-10'} <= {o['id'] for o in ps['research']['os_options']}
    assert {o['id'] for o in ps['npu']['os_options']} == {'ubuntu-2204', 'ubuntu-2404'}
    for p in ps.values():
        assert p['os_default'] == p['os_choices'][0]
        for o in p['os_choices']:
            assert desktpl.OSES[o]['platform'] == p['platform']


def test_every_linux_os_has_a_cloud_image_in_the_library():
    from pegaprox.api.templates_lib import CATALOG
    ids = {c['id'] for c in CATALOG}
    for k, o in desktpl.OSES.items():
        if o['platform'] == 'linux':
            assert o['base'] in ids, k


def test_the_oses_a_use_needs_have_what_it_installs():
    for o in desktpl.PRESETS['gpu']['os_choices']:
        assert desktpl.OSES[o].get('cuda'), o                        # NVIDIA publishes a CUDA repository for it


def test_validate_checks_the_inputs():
    assert desktpl.validate('nope', {})[1]
    assert desktpl.validate('research', {'name': 'bad name!'})[1]
    assert desktpl.validate('research', {'cores': 0})[1]
    assert desktpl.validate('npu', {'os': 'rocky-9'})[1]               # not an OS the NPU vendors support
    assert desktpl.validate('research', {'desktop': 'kde'})[1]
    o, err = desktpl.validate('research', {})
    assert not err and o['name'] == 'moavi-research-ubuntu2404' and o['os'] == 'ubuntu-2404' and o['desktop'] == 'xfce'
    o, _ = desktpl.validate('research', {'os': 'rocky-9', 'desktop': 'gnome'})
    assert o['os'] == 'rocky-9' and o['desktop'] == 'gnome'
    assert desktpl.validate('office', {})[1]                           # the ISOs are needed
    o, err = desktpl.validate('office', {'windows_iso': 'ceph-fs:iso/Win11_24H2_Korean_x64.iso', 'virtio_iso': 'ceph-fs:iso/virtio-win-0.1.262.iso'})
    assert not err and o['edition'] == 'Windows 11 Pro' and o['language'] == 'ko-KR' and o['os'] == 'win11'
    o, err = desktpl.validate('office', {'os': 'ws2022', 'windows_iso': 'ceph-fs:iso/ws2022.iso', 'virtio_iso': 'ceph-fs:iso/virtio-win.iso',
                                         'product_key': 'wx4nm-kywyw-qjjr4-xv3qb-6vm33'})
    assert not err and o['edition'] == 'Windows Server 2022 SERVERDATACENTER' and o['product_key'] == 'WX4NM-KYWYW-QJJR4-XV3QB-6VM33'
    assert desktpl.validate('office', {'os': 'ws2022', 'windows_iso': 'a:iso/b.iso', 'virtio_iso': 'a:iso/c.iso', 'product_key': 'nope'})[1]
    assert desktpl.validate('research', {'vendor_dir': 'nas:/x'})[1]   # only npu / fpga take a vendor folder
    assert desktpl.validate('npu', {'vendor_dir': 'nas; rm -rf /:/x'})[1]
    assert desktpl.validate('fpga', {'vendor_dir': 'nas:/tools/vivado'})[1]   # the EULA must be accepted
    o, err = desktpl.validate('fpga', {'vendor_dir': 'nas:/tools/vivado', 'accept_eula': True})
    assert not err and o['agree'] == 'XilinxEULA,3rdPartyEULA'


def _combos():
    for pid, p in desktpl.PRESETS.items():
        if p['platform'] != 'linux':
            continue
        for o in p['os_choices']:
            for d in desktpl.DESKTOPS:
                yield pid, o, d


@pytest.mark.parametrize('preset,os_id,desktop', list(_combos()))
def test_every_use_os_and_desktop_gives_valid_bash(preset, os_id, desktop):
    extra = {'vendor_dir': 'nas:/v', 'accept_eula': True} if preset in ('npu', 'fpga') else {}
    opts, err = desktpl.validate(preset, dict(extra, os=os_id, desktop=desktop))
    assert not err, err
    script = desktpl.build_script(opts)
    assert script.startswith('#!/bin/bash') and desktpl.READY_FILE in script
    assert 'passwd -l' in script and 'chpasswd' not in script        # no password login in the template
    rhel = desktpl.OSES[os_id]['family'] == 'rhel'
    assert ('dnf' in script and 'apt-get' not in script) if rhel else ('apt-get' in script and 'dnf ' not in script)
    assert 'xrdp' in script and 'jupyter-vscode-proxy' in script and 'code-server' in script and 'realmd' in script
    assert ('gnome-session' in script) == (desktop == 'gnome') and ('xfce4-session' in script) == (desktop == 'xfce')
    if rhel:
        assert 'FILTER_RPC_ARGS' in script and 'epel-release' in script and 'ibus-hangul' in script
    else:
        assert 'fcitx5-hangul' in script
    bash = shutil.which('bash')
    if bash:
        r = subprocess.run([bash, '-n'], input=script, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


def test_build_script_carries_each_presets_parts():
    s = {p: desktpl.build_script(desktpl.validate(p, {'vendor_dir': 'nas:/v', 'accept_eula': True} if p in ('npu', 'fpga') else {})[0])
         for p in ('research', 'gpu', 'npu', 'fpga')}
    assert 'nvidia-open' in s['gpu'] and desktpl.TORCH_INDEX in s['gpu'] and 'repos/ubuntu2404/' in s['gpu'] and 'nvidia-open' not in s['research']
    assert '/mnt/moavi-vendor/*.deb' in s['npu'] and 'mount -t nfs' in s['npu']
    assert '52-moavi-jtag.rules' in s['fpga'] and '--agree XilinxEULA,3rdPartyEULA --batch Install' in s['fpga']
    no_vivado = desktpl.build_script(desktpl.validate('fpga', {})[0])
    assert 'xsetup' not in no_vivado and 'mount -t nfs' not in no_vivado and '52-moavi-jtag.rules' in no_vivado
    el_gpu = desktpl.build_script(desktpl.validate('gpu', {'os': 'rocky-9'})[0])
    assert 'cuda-rhel9.repo' in el_gpu and 'nvidia-driver:open-dkms' in el_gpu
    debian = desktpl.build_script(desktpl.validate('research', {'os': 'debian-12'})[0])
    assert 'firefox-esr' in debian and 'language-pack-ko' not in debian


def test_user_data_is_cloud_config_with_the_script():
    opts, _ = desktpl.validate('gpu', {'name': 'gpu-2404'})
    ud = desktpl.user_data(opts)
    assert ud.startswith('#cloud-config\n') and 'hostname: gpu-2404' in ud and 'ssh_pwauth: false' in ud
    lines = ud.split('\n')
    start = lines.index('    content: |') + 1
    body = [ln for ln in lines[start:lines.index('runcmd:')]]
    assert all(ln == '' or ln.startswith('      ') for ln in body)      # the script stays inside its block
    assert '[bash, /usr/local/sbin/moavi-template-build.sh]' in ud
    assert desktpl.meta_data(opts, 'dtb_1') == 'instance-id: moavi-build-dtb_1\nlocal-hostname: gpu-2404\n'


def test_udev_rules_cover_the_jtag_cables():
    rules = desktpl.udev_rules()
    for vid, _ in desktpl.JTAG_VENDORS:
        assert f'ATTR{{idVendor}}=="{vid}", MODE="0666"' in rules


def test_stage_progress_moves_forward():
    seq = [desktpl.stage_progress('fpga', s) for s in ('boot', 'update', 'desktop', 'fpga', 'vivado', 'done')]
    assert seq == sorted(seq) and seq[0] == 30 and seq[-1] == 90


def _win_opts(os_id='win11', **kw):
    return desktpl.validate('office', dict(kw, os=os_id, windows_iso='ceph-fs:iso/Win.iso', virtio_iso='ceph-fs:iso/virtio-win.iso'))[0]


def test_answer_files_are_well_formed_xml():
    xml = desktpl.autounattend(_win_opts(), 'Pw<&>"1x')
    root = ET.fromstring(xml)
    ns = {'u': 'urn:schemas-microsoft-com:unattend'}
    assert {s.get('pass') for s in root.findall('u:settings', ns)} == {'windowsPE', 'specialize', 'oobeSystem'}
    assert 'Pw&lt;&amp;&gt;"1x' in xml                                 # escaped, not breaking the XML
    assert 'vioscsi\\w11\\amd64' in xml and 'NetKVM\\w11\\amd64' in xml
    assert '<Value>Windows 11 Pro</Value>' in xml and '0412:00000412' in xml and 'PreventDeviceEncryption' in xml
    ET.fromstring(desktpl.oobe_xml())


@pytest.mark.parametrize('os_id,folder', [('win11', 'w11'), ('win10', 'w10'), ('ws2025', '2k25'), ('ws2022', '2k22')])
def test_each_windows_gets_its_own_drivers_and_image(os_id, folder):
    xml = desktpl.autounattend(_win_opts(os_id), 'Pw1aaaaaaaaaaaaaaa!')
    ET.fromstring(xml)
    assert f'vioscsi\\{folder}\\amd64' in xml and f"<Value>{desktpl.OSES[os_id]['edition']}</Value>" in xml
    assert '<ProductKey>' not in xml
    keyed = desktpl.autounattend(_win_opts(os_id, product_key='WX4NM-KYWYW-QJJR4-XV3QB-6VM33'), 'Pw1aaaaaaaaaaaaaaa!')
    assert '<Key>WX4NM-KYWYW-QJJR4-XV3QB-6VM33</Key>' in keyed
    assert ('DoNotOpenServerManagerAtLogon' in desktpl.firstlogon_ps1(server=True)
            and 'DoNotOpenServerManagerAtLogon' not in desktpl.firstlogon_ps1())


def test_sysprep_removes_the_setup_password():
    s = desktpl.SYSPREP_WINDOWS
    assert 'Panther' in s and 'DefaultPassword' in s and 'AutoAdminLogon -Value 0' in s and '/generalize' in s


def test_parse_status():
    assert desktpl.parse_status('ready\nlog') == ('ready', '')
    assert desktpl.parse_status('failed pytorch\n') == ('failed', 'pytorch')
    assert desktpl.parse_status('stage desktop\n== ...') == ('stage', 'desktop')
    assert desktpl.parse_status('') == ('stage', 'boot')


def test_builds_are_local_to_the_engine():
    assert 'vlab_desktpl_builds' in ha.LOCAL_TABLES


# --- the build, against a stand-in node and guest agent --------------------------------------

class FakeNode:
    def __init__(self, *a, **k):
        self.cmds, self.files, self.status = [], {}, 'running'

    def run(self, cmd, label, timeout=1800, quiet=False, ok=(0,)):
        self.cmds.append(cmd)
        if cmd.startswith('pvesh get /cluster/nextid'):
            return '"9100"'
        if cmd.startswith('pvesm status --content iso'):
            return 'Name Type Status Total Used Available %\nlocal dir active 1 1 1 1%\n'
        if cmd.startswith('pvesm path'):
            vol = cmd.split()[-1].strip("'")
            return f"/var/lib/vz/template/{vol.split(':', 1)[1]}" if 'cidata' in vol else '/mnt/pve/ceph-fs/template/iso/Win11.iso'
        if cmd.startswith('qm importdisk'):
            return "unused0: successfully imported disk 'local-lvm:vm-9100-disk-0'"
        if cmd.startswith('qm status'):
            return f'status: {self.status}'
        if cmd.startswith('qm shutdown'):
            self.status = 'stopped'
        return ''

    def write(self, path, text):
        self.files[path] = text

    def close(self):
        pass


@pytest.fixture
def lab(api, seed, monkeypatch):
    import pegaprox.api.vlab_desktpl as dt
    import pegaprox.api.vlab_next as nxt
    mgr = api.make_fake_manager(CID, get_vm_resources=[])
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    node = FakeNode()
    monkeypatch.setattr(dt, '_Node', lambda *a, **k: node)
    monkeypatch.setattr(dt, 'POLL', 0)
    agent = {'calls': [], 'answers': ['stage update', 'stage desktop', 'ready']}

    def run(mgr, n, vmid, argv, stdin=None, wait=None):
        agent['calls'].append(argv[-1])
        text = argv[-1]
        if text in (dt.desktpl.STATUS_LINUX, dt.desktpl.STATUS_WINDOWS):
            return 0, agent['answers'].pop(0) if len(agent['answers']) > 1 else agent['answers'][0], '', ''
        if 'sysprep' in text:
            node.status = 'stopped'
        return 0, '', '', ''
    monkeypatch.setattr(nxt, '_agent_run', run)
    started = []
    monkeypatch.setattr(dt.threading, 'Thread', lambda target, args, **k: started.append((target, args)) or type('T', (), {'start': lambda s: None})())
    return admin, node, agent, started, dt


def _go(started):
    target, args = started.pop()
    target(*args)


def test_a_linux_build_ends_as_a_golden_image_with_its_card(lab):
    from pegaprox.vlab import catalog, envcat
    admin, node, agent, started, dt = lab
    assert admin.post(f'/api/vlab/admin/clusters/{CID}/desktop-templates/gpu/build', json={'node': 'pve1'}).status_code == 400
    r = admin.post(f'/api/vlab/admin/clusters/{CID}/desktop-templates/gpu/build',
                   json={'node': 'pve1', 'storage': 'local-lvm', 'bridge': 'vmbr0', 'name': 'gpu-2404'})
    assert r.status_code == 202, r.get_json()
    assert 'admin_password' not in r.get_json()                       # Linux templates have no password
    bid = r.get_json()['build']['id']
    _go(started)
    b = admin.get(f'/api/vlab/admin/desktop-templates/builds/{bid}').get_json()['build']
    assert b['status'] == 'completed', b
    gid = b['result']['golden_id']
    img = catalog.get_golden(gid)
    assert img['vmid'] == 9100 and img['name'] == 'gpu-2404'
    assert envcat.get(gid)['kind'] == 'ai'
    joined = '\n'.join(node.cmds)
    assert 'qm create 9100' in joined and 'qm importdisk 9100' in joined and '-V cidata' in joined
    assert '--ide2 local:iso/moavi-cidata-' in joined and 'cicustom' not in joined     # no Snippets storage
    assert 'qm resize 9100 scsi0 120G' in joined and 'qm start 9100' in joined and 'qm set 9100 --delete ide2' in joined
    assert 'qm set 9100 --ide2 local-lvm:cloudinit --ipconfig0 ip=dhcp' in joined     # clones get their own name
    assert 'qm template' not in joined                                # a golden image is a VM
    ud = next(v for k, v in node.files.items() if k.endswith('/user-data'))
    assert 'nvidia-open' in ud and any(k.endswith('/meta-data') for k in node.files)
    assert desktpl.SEAL_LINUX in agent['calls']


def test_no_iso_storage_is_told_plainly(lab, monkeypatch):
    admin, node, agent, started, dt = lab
    orig = node.run

    def run(cmd, label, **k):
        if cmd.startswith('pvesm status --content iso'):
            return 'Name Type Status Total Used Available %\n'
        return orig(cmd, label, **k)
    monkeypatch.setattr(node, 'run', run)
    bid = admin.post(f'/api/vlab/admin/clusters/{CID}/desktop-templates/research/build',
                     json={'node': 'pve1', 'storage': 'local-lvm'}).get_json()['build']['id']
    _go(started)
    b = admin.get(f'/api/vlab/admin/desktop-templates/builds/{bid}').get_json()['build']
    assert b['status'] == 'failed' and 'ISO' in b['error']


def test_a_guest_failure_stops_the_build(lab):
    admin, node, agent, started, dt = lab
    agent['answers'][:] = ['stage nvidia', 'failed nvidia driver and CUDA']
    bid = admin.post(f'/api/vlab/admin/clusters/{CID}/desktop-templates/gpu/build',
                     json={'node': 'pve1', 'storage': 'local-lvm'}).get_json()['build']['id']
    _go(started)
    b = admin.get(f'/api/vlab/admin/desktop-templates/builds/{bid}').get_json()['build']
    assert b['status'] == 'failed' and 'nvidia driver and CUDA' in b['error']


def test_a_windows_build_ends_as_a_template_and_keeps_no_password(lab, db):
    admin, node, agent, started, dt = lab
    r = admin.post(f'/api/vlab/admin/clusters/{CID}/desktop-templates/office/build',
                   json={'node': 'pve1', 'storage': 'local-lvm', 'windows_iso': 'ceph-fs:iso/Win11.iso',
                         'virtio_iso': 'ceph-fs:iso/virtio-win.iso'})
    assert r.status_code == 202, r.get_json()
    pw = r.get_json()['admin_password']
    assert len(pw) >= 16 and r.get_json()['admin_user'] == 'moavi-admin'
    bid = r.get_json()['build']['id']
    _go(started)
    b = admin.get(f'/api/vlab/admin/desktop-templates/builds/{bid}').get_json()['build']
    assert b['status'] == 'completed', b
    joined = '\n'.join(node.cmds)
    assert '--bios ovmf' in joined and 'version=v2.0' in joined and 'genisoimage' in joined and 'qm sendkey 9100 ret' in joined
    assert 'qm set 9100 --delete ide0,ide2,sata0' in joined and 'qm template 9100' in joined
    assert any(pw in v for v in node.files.values())                 # on the answer CD (deleted after the build)
    row = db.query_one('SELECT options, log FROM vlab_desktpl_builds WHERE id = ?', (bid,))
    assert pw not in row['options'] and pw not in row['log'] and pw not in json.dumps(b)
    assert pw not in joined                                           # never on a command line


def test_cancel_stops_after_the_step(lab):
    admin, node, agent, started, dt = lab
    agent['answers'][:] = ['stage update']
    bid = admin.post(f'/api/vlab/admin/clusters/{CID}/desktop-templates/research/build',
                     json={'node': 'pve1', 'storage': 'local-lvm'}).get_json()['build']['id']
    assert admin.post(f'/api/vlab/admin/desktop-templates/builds/{bid}/cancel').status_code == 200
    _go(started)
    assert admin.get(f'/api/vlab/admin/desktop-templates/builds/{bid}').get_json()['build']['status'] == 'cancelled'


def test_the_list_offers_presets_and_builds(lab):
    admin, *_ = lab
    body = admin.get('/api/vlab/admin/desktop-templates').get_json()
    assert len(body['presets']) == 5 and body['builds'] == []
