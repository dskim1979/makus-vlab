"""네트워크 구성도: what each pool is on, what its firewall lets through, and what is set up wrong."""
import re

import pytest

from test_vlab_netseg import CID, FakeSDN, Resp, _make_segment

from pegaprox.vlab import netiso


class FakeFW(FakeSDN):
    """FakeSDN plus the Proxmox firewall reads the map makes."""

    def __init__(self, vms):
        super().__init__(vms)
        self.dc_fw = 0
        self.groups = {}                # name -> [rules]
        self.vm_fw = {}                 # vmid -> options

    def get(self, url, **k):
        p = self._path(url)
        if p == '/cluster/firewall/options':
            return Resp({'enable': self.dc_fw, 'policy_in': 'ACCEPT'})
        if p == '/cluster/firewall/groups':
            return Resp([{'group': g} for g in self.groups])
        m = re.match(r'/cluster/firewall/groups/([^/]+)$', p)
        if m:
            return Resp(self.groups[m.group(1)]) if m.group(1) in self.groups else Resp(None, 404)
        m = re.match(r'/nodes/[^/]+/qemu/(\d+)/firewall/options$', p)
        if m:
            return Resp(self.vm_fw.get(int(m.group(1)), {'enable': 0}))
        return super().get(url, **k)


@pytest.fixture
def nm(api, seed, monkeypatch):
    from pegaprox.api import vlab_netiso, vlab_netseg
    admin = api.as_user(seed.user('root', role='admin'))
    fw = FakeFW({400: {'config': {'net0': 'virtio=BC:24:11:00:00:01,bridge=vmbr0'}, 'ips': []},
                 401: {'config': {'net0': 'virtio=BC:24:11:00:00:02,bridge=vmbr0'}, 'ips': []}})
    res = [{'vmid': 400, 'node': 'pve1', 'name': 'win-01', 'type': 'qemu', 'status': 'stopped'},
           {'vmid': 401, 'node': 'pve1', 'name': 'win-02', 'type': 'qemu', 'status': 'stopped'}]
    mgr = api.make_fake_manager(CID, get_vm_resources=res)
    mgr.is_connected = True
    mgr.host, mgr.api_port = 'pve1', 8006
    mgr._api_get.side_effect = fw.get
    mgr._api_post.side_effect = fw.post
    mgr._api_put.side_effect = fw.put
    mgr._api_delete.side_effect = fw.delete
    api.set_manager(CID, mgr)
    pool = admin.post('/api/vlab/admin/pools', json={'name': '설계팀', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    for vmid in (400, 401):
        assert admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': vmid}).status_code in (200, 201)
    vlab_netseg._state.clear()
    vlab_netiso._state.clear()
    monkeypatch.setattr(vlab_netseg, 'probe', lambda ip, port=3389, timeout=1.5: 'open')
    netiso.set_gateway_sources(CID, ['192.168.0.55'])
    return admin, fw, pool


def _map(admin):
    r = admin.get(f'/api/vlab/admin/clusters/{CID}/netmap?fresh=1')
    assert r.status_code == 200
    return r.get_json()


def _codes(m, level=None):
    return {f['code'] for f in m['findings'] if level is None or f['level'] == level}


def _isolate(admin, pool, **kw):
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json=dict({'net_isolation': True}, **kw)).status_code == 200


def _open(admin, pool, **kw):
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json=dict({'net_isolation': False}, **kw)).status_code == 200


def test_an_open_pool_on_the_management_bridge(nm):
    admin, fw, pool = nm
    _open(admin, pool)                                   # new pools start isolated
    m = _map(admin)
    p = m['pools'][0]
    assert p['isolation'] is False and p['bridges'] == ['vmbr0'] and p['live'] == 'off' and p['rules'] == []
    assert {'pool_not_isolated', 'pool_on_management'} <= _codes(m, 'warning')
    assert not _codes(m, 'critical')                  # nothing isolated: the datacenter firewall is not asked about
    assert m['gateway']['sources'] == ['192.168.0.55'] and any(b['name'] == 'vmbr1' for b in m['bridges'])


def test_isolation_that_does_not_filter_is_critical_until_it_does(nm):
    admin, fw, pool = nm
    _isolate(admin, pool, net_allow_in=[{'cidr': '0.0.0.0/0', 'proto': 'tcp', 'port': '22', 'note': 'ssh'}])
    m = _map(admin)
    assert {'dc_firewall_off', 'rules_missing', 'vm_firewall_off'} <= _codes(m, 'critical')
    assert 'allow_in_wide' in _codes(m, 'warning') and 'egress_open' in _codes(m, 'info')
    rules = m['pools'][0]['rules']
    assert rules[0] == {'dir': 'in', 'peer': 'gateway', 'cidr': '', 'proto': 'any', 'port': '', 'note': 'MOAVI gateway', 'action': 'accept'}
    assert {'dir': 'in', 'peer': 'cidr', 'cidr': '0.0.0.0/0', 'proto': 'tcp', 'port': '22', 'note': 'ssh', 'action': 'accept'} in rules
    assert rules[-1]['dir'] == 'out' and rules[-1]['peer'] == 'any'
    # as 네트워크 격리 sets it up
    from pegaprox.vlab import policy, store
    pol = policy.effective(store.get_pool(pool['id']).get('settings'), 'dedicated')
    fw.dc_fw = 1
    fw.groups[netiso.group_name(pool['id'])] = [dict(r, pos=i) for i, r in enumerate(netiso.group_rules(pool['id'], pol))]
    for v in (400, 401):
        fw.vms[v]['config']['net0'] += ',firewall=1'
        fw.vm_fw[v] = {'enable': 1, 'policy_in': 'DROP'}
    m = _map(admin)
    assert not _codes(m, 'critical') and m['pools'][0]['live'] == 'match' and m['pools'][0]['desktops']['fw_off'] == 0
    # someone edits the group in Proxmox
    fw.groups[netiso.group_name(pool['id'])].pop()
    assert 'rules_differ' in _codes(_map(admin), 'critical')
    # or turns one VM's firewall off
    fw.groups[netiso.group_name(pool['id'])] = [dict(r, pos=i) for i, r in enumerate(netiso.group_rules(pool['id'], pol))]
    fw.vm_fw[401] = {'enable': 0}
    f = next(x for x in _map(admin)['findings'] if x['code'] == 'vm_firewall_off')
    assert f['detail'] == 'win-02'


def test_segments_in_the_map(nm):
    admin, fw, pool = nm
    s = _make_segment(admin)
    m = _map(admin)
    assert 'segment_unused' in _codes(m, 'info') and m['segments'][0]['id'] == s['id']
    admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/sdn')
    _open(admin, pool, net_segment=s['id'])
    m = _map(admin)
    assert m['pools'][0]['segment'] == s['id']
    assert {'segment_without_isolation', 'pool_not_isolated'} <= _codes(m, 'warning')
    assert 'pool_on_management' not in _codes(m)       # it has its own network now (or will)


def test_a_segment_gateway_the_moavi_server_cannot_reach(nm, monkeypatch):
    from pegaprox.api import vlab_netseg
    admin, fw, pool = nm
    s = _make_segment(admin)
    admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/sdn')
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'net_segment': s['id'], 'net_isolation': True})
    monkeypatch.setattr(vlab_netseg, 'probe', lambda ip, port=3389, timeout=1.5: 'unreachable')
    f = next(x for x in _map(admin)['findings'] if x['code'] == 'gateway_unreachable')
    assert f['level'] == 'critical' and f['segment'] == s['id'] and f['detail'] == '10.20.1.1'


def test_unknown_cluster(nm):
    admin, fw, pool = nm
    assert admin.get('/api/vlab/admin/clusters/nope/netmap').status_code == 404


# --- 마이크로 세그먼트: pool to pool, drop rules, the desktops in the map ---------------------------

def test_pool_to_pool_rules_drops_first_and_the_desktops(nm):
    admin, fw, pool = nm
    other = admin.post('/api/vlab/admin/pools', json={'name': '연구소', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy",
                     json={'net_allow_in': [{'pool': pool['id'], 'proto': 'tcp', 'port': '445'}]}).status_code == 400   # itself
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy",
                     json={'net_allow_in': [{'pool': 'pool_nope', 'proto': 'tcp', 'port': '445'}]}).status_code == 400
    _isolate(admin, pool, net_allow_in=[{'pool': other['id'], 'proto': 'tcp', 'port': '445', 'note': 'smb'},
                                        {'cidr': '10.0.0.0/8', 'proto': 'tcp', 'port': '22'},
                                        {'cidr': '10.9.0.0/16', 'proto': 'any', 'action': 'drop'}],
             net_allow_out=[{'cidr': '0.0.0.0/0', 'proto': 'tcp', 'port': '25', 'action': 'drop', 'note': 'no mail'}])
    _isolate(admin, other, net_egress='list')
    from pegaprox.vlab import policy, store
    pol = policy.effective(store.get_pool(pool['id']).get('settings'), 'dedicated')
    g = netiso.group_rules(pool['id'], pol)
    assert [(r['type'], r['action']) for r in g][:2] == [('in', 'ACCEPT'), ('in', 'DROP')]        # gateway, then the drop
    assert any(r.get('source') == f"+{netiso.ipset_name(other['id'])}" and r.get('dport') == '445' for r in g)
    assert any(r['type'] == 'out' and r['action'] == 'DROP' and r.get('dport') == '25' for r in g)
    m = _map(admin)
    p = next(x for x in m['pools'] if x['id'] == pool['id'])
    assert {'dir': 'in', 'peer': 'pool_other', 'cidr': '', 'proto': 'tcp', 'port': '445', 'note': 'smb', 'action': 'accept',
            'pool': other['id']} in p['rules']
    assert [v['vmid'] for v in p['vms']] == [400, 401] and p['vms'][0]['bridge'] == 'vmbr0'
    f = next(x for x in m['findings'] if x['code'] == 'peer_out_missing')            # 연구소 sends only its list
    assert f['pool'] == other['id'] and '445' in f['detail']


def test_the_map_is_answered_from_memory_for_a_minute(nm):
    """Up to 200 desktops: about 400 Proxmox reads per map - a reload within a minute does not repeat
    them; 다시 점검 (?fresh=1) does."""
    admin, fw, pool = nm
    from pegaprox.api import vlab_netmap
    vlab_netmap._cache.clear()
    first = admin.get(f'/api/vlab/admin/clusters/{CID}/netmap').get_json()
    assert first['cached_at'] is None
    calls = len(fw.writes)
    again = admin.get(f'/api/vlab/admin/clusters/{CID}/netmap').get_json()
    assert again['cached_at'] and again['pools'] == first['pools']
    assert admin.get(f'/api/vlab/admin/clusters/{CID}/netmap?fresh=1').get_json()['cached_at'] is None
