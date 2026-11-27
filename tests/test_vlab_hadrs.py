"""MOAVI Desk: 고가용성 · 부하 분산 (pegaprox/vlab/hadrs.py): what cannot live-migrate, the recommend-only
plan (no move is made), the pool policy 'HA 사용' defaults."""
from types import SimpleNamespace

from pegaprox.vlab import hadrs, policy

GB = 1024 ** 3


def test_passthrough_is_read_from_the_config():
    assert hadrs.passthrough_of({'hostpci0': '0000:41:00,pcie=1'}) == 'pci'
    assert hadrs.passthrough_of({'usb0': 'host=1234:5678'}) == 'usb'
    assert hadrs.passthrough_of({'usb0': 'spice'}) is None
    assert hadrs.passthrough_of({'scsi0': 'ceph:vm-1-disk-0'}) is None


def test_why_a_guest_stays():
    vm = {'type': 'qemu'}
    assert hadrs.why_stays(vm, {'hostpci0': 'x'}, 'shared') == 'pci'
    assert hadrs.why_stays(vm, {}, 'local') == 'local_disk'
    assert hadrs.why_stays(vm, {}, 'local', balance_local_disks=True) is None
    assert hadrs.why_stays({'type': 'lxc'}, {}, 'shared') == 'container'
    assert hadrs.why_stays(vm, {}, 'shared') is None


def test_ha_enabled_defaults_by_pool_type():
    assert policy.defaults_for('dedicated')['ha_enabled'] is True
    for t in ('reset', 'classroom', 'shared', 'buildfarm'):
        assert policy.defaults_for(t)['ha_enabled'] is False
    # a saved policy without it keeps the type's default; one with it keeps the choice
    out, err = policy.validate({}, 'reset')
    assert err is None and 'ha_enabled' not in out
    out, err = policy.validate({'ha_enabled': True}, 'reset')
    assert err is None and out['ha_enabled'] is True
    assert policy.effective({'policy': {'ha_enabled': True}}, 'classroom')['ha_enabled'] is True


class FakeMgr:
    """check_balance_needed / find_migration_candidate as the core decides, on two nodes."""

    def __init__(self, vms):
        self.config = SimpleNamespace(migration_threshold=20, migration_tolerance=0, excluded_nodes=[],
                                      balance_cpu_weight=1.0, balance_mem_weight=1.0, balance_io_weight=0.0)
        self.vms = vms
        self.migrated = []

    def check_balance_needed(self, status):
        s = sorted(status.items(), key=lambda x: x[1]['score'])
        lo, hi = s[0], s[-1]
        return (hi[1]['score'] - lo[1]['score'] > 20, hi[0], lo[0])

    def find_migration_candidate(self, src, dst, exclude_vmids=None, node_status=None):
        c = [v for v in self.vms if v['node'] == src and v['vmid'] not in (exclude_vmids or [])]
        return dict(sorted(c, key=lambda v: v['mem'])[0]) if c else None

    def migrate_vm(self, *a, **k):     # the plan must never call it
        self.migrated.append(a)
        return True


def _node(cpu, mem_used, mem_total=100 * GB):
    return {'status': 'online', 'cpu_percent': cpu, 'mem_used': mem_used, 'mem_total': mem_total,
            'mem_percent': 100.0 * mem_used / mem_total, 'disk_percent': 0, 'cpuinfo': {'cpus': 32},
            'score': cpu + 100.0 * mem_used / mem_total}


def test_plan_proposes_moves_without_making_them():
    vms = [{'vmid': 101 + i, 'name': f'd{i}', 'node': 'pve1', 'type': 'qemu', 'mem': 8 * GB, 'cpu': 0.1, 'maxcpu': 4}
           for i in range(6)]
    mgr = FakeMgr(vms)
    status = {'pve1': _node(40, 70 * GB), 'pve2': _node(10, 10 * GB)}
    moves = hadrs.plan(mgr, max_moves=5, node_status=status)
    assert moves and all(m['from'] == 'pve1' and m['to'] == 'pve2' for m in moves)
    assert len({m['vmid'] for m in moves}) == len(moves)
    assert moves[-1]['after'] < moves[0]['before']
    assert mgr.migrated == []
    # the caller's status is not touched
    assert status['pve1']['mem_used'] == 70 * GB


def test_plan_stops_when_balanced():
    mgr = FakeMgr([{'vmid': 101, 'name': 'a', 'node': 'pve1', 'type': 'qemu', 'mem': GB, 'cpu': 0, 'maxcpu': 1}])
    assert hadrs.plan(mgr, node_status={'pve1': _node(20, 30 * GB), 'pve2': _node(20, 25 * GB)}) == []
