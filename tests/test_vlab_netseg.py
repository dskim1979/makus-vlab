"""네트워크 분리 2단계: segments as Proxmox SDN VNets, desktops moved onto them, the IPAM view."""
import json
import re
from urllib.parse import unquote

import pytest

from pegaprox.vlab import netseg, policy

CID = 'netseg_c1'


# --- checks ------------------------------------------------------------------------------------------

def test_policy_default_and_nic_rewrite():
    assert policy.effective({}, 'dedicated')['net_segment'] == ''
    assert policy.validate({'net_segment': 'seg_x'}, 'dedicated')[0]['net_segment'] == 'seg_x'
    assert policy.validate({'net_segment': 5}, 'dedicated')[1]
    v = 'virtio=BC:24:11:A4:68:84,bridge=vmbr0,tag=20,firewall=1'
    assert netseg.nic_with(v, 'mv1a2b3c') == 'virtio=BC:24:11:A4:68:84,bridge=mv1a2b3c,firewall=1'
    assert netseg.nic_with('virtio=AA,bridge=mv1a2b3c,firewall=1', 'vmbr0', '20') == 'virtio=AA,bridge=vmbr0,tag=20,firewall=1'
    assert netseg.nic_mac(v) == 'BC:24:11:A4:68:84'
    assert len(netseg.vnet_name('seg_abc')) == 8 and netseg.vnet_name('seg_abc') == netseg.vnet_name('seg_abc')
    assert netseg.subnet_id('moavi', '10.20.1.0/24') == 'moavi-10.20.1.0-24'


def test_zone_and_segment_checks():
    assert netseg.clean_zone({'type': 'vlan', 'bridge': 'vmbr0'})[0]['zone'] == 'moavi'
    assert netseg.clean_zone({'type': 'vlan'})[1]                      # a VLAN zone needs the bridge
    assert netseg.clean_zone({'type': 'vxlan', 'peers': '10.0.0.1, 10.0.0.2'})[0]['peers'] == '10.0.0.1,10.0.0.2'
    assert netseg.clean_zone({'type': 'vxlan', 'peers': 'pve1'})[1]
    assert netseg.clean_zone({'zone': 'Too-Long-Name', 'type': 'vlan', 'bridge': 'vmbr0'})[1]
    assert netseg.clean_zone({'zone': 'sdn1', 'existing': True})[0]['existing'] is True
    ok = {'name': '설계팀', 'tag': 110, 'subnet': '10.20.1.0/24', 'gateway': '10.20.1.1'}
    f, err = netseg.clean_segment(ok, 'none', 'vlan')
    assert err is None and f['subnet'] == '10.20.1.0/24' and f['dhcp_start'] == ''
    for bad in (dict(ok, tag=0), dict(ok, tag=5000), dict(ok, subnet='10.20.1.0/8'), dict(ok, gateway='10.20.2.1'),
                dict(ok, gateway='10.20.1.0'), dict(ok, dhcp_start='10.20.1.10'),
                dict(ok, dhcp_start='10.20.1.50', dhcp_end='10.20.1.10'), dict(ok, dhcp_start='10.20.1.1', dhcp_end='10.20.1.9'),
                dict(ok, name='')):
        assert netseg.clean_segment(bad, 'none', 'vlan')[1], bad
    assert netseg.clean_segment(dict(ok, tag=0), 'none', 'simple')[0]


# --- a Proxmox SDN in memory ------------------------------------------------------------------------

class Resp:
    def __init__(self, data, code=200):
        self.status_code, self._data = code, data
        self.text = json.dumps(data)

    def json(self):
        return {'data': self._data}


class FakeSDN:
    def __init__(self, vms):
        self.zones, self.vnets, self.subnets, self.ips = {}, {}, {}, []
        self.vms = vms           # vmid -> {'config', 'ips'}
        self.applied, self.reboots, self.writes = 0, [], []
        self.node_status = 'available'      # what each node says of an applied zone
        self.other_node = False             # a second node, pve2, that never builds the zone

    def _path(self, url):
        return unquote(url.split('/api2/json', 1)[1]).split('?')[0]

    def get(self, url, **k):
        p = self._path(url)
        if p == '/nodes':
            return Resp([{'node': n, 'status': 'online'} for n in ['pve1'] + (['pve2'] if self.other_node else [])])
        if p == '/nodes/pve2/sdn/zones':
            return Resp([{'zone': z, 'status': 'error'} for z, o in self.zones.items() if not o.get('state')])
        if p == '/nodes/pve1/sdn/zones':
            return Resp([{'zone': z, 'status': self.node_status} for z, o in self.zones.items() if not o.get('state')])
        if p == '/cluster/sdn/zones':
            return Resp(list(self.zones.values()))
        if p == '/cluster/sdn/vnets':
            return Resp(list(self.vnets.values()))
        m = re.match(r'/cluster/sdn/vnets/([^/]+)/subnets$', p)
        if m:
            return Resp(list(self.subnets.get(m.group(1), {}).values()))
        if p == '/cluster/sdn/ipams/pve/status':
            return Resp(self.ips)
        m = re.match(r'/nodes/[^/]+/qemu/(\d+)/config$', p)
        if m and int(m.group(1)) in self.vms:
            return Resp(self.vms[int(m.group(1))]['config'])
        return Resp(None, 500)

    def post(self, url, data=None, **k):
        p = self._path(url)
        self.writes.append(('POST', p, data))
        if p == '/cluster/sdn/zones':
            self.zones[data['zone']] = dict(data, state='new')
        elif p == '/cluster/sdn/vnets':
            self.vnets[data['vnet']] = dict(data, state='new')
        elif re.match(r'/cluster/sdn/vnets/[^/]+/subnets$', p):
            v = p.split('/')[4]
            net = data['subnet']
            sid = f"{self.vnets[v]['zone']}-{net.split('/')[0]}-{net.split('/')[1]}"
            self.subnets.setdefault(v, {})[sid] = dict(data, subnet=sid, cidr=net)
        elif re.match(r'/cluster/sdn/vnets/[^/]+/ips$', p):
            self.ips.append({'ip': data['ip'], 'mac': data.get('mac'), 'vnet': p.split('/')[4], 'vmid': data.get('vmid')})
        elif p.endswith('/status/reboot'):
            self.reboots.append(int(p.split('/')[4]))
        return Resp(None)

    def put(self, url, data=None, **k):
        p = self._path(url)
        self.writes.append(('PUT', p, data))
        if p == '/cluster/sdn':
            self.applied += 1
            for o in list(self.zones.values()) + list(self.vnets.values()):
                o.pop('state', None)
            for name in [n for n, o in self.vnets.items() if o.get('deleted')]:
                self.vnets.pop(name)
            for name in [n for n, o in self.zones.items() if o.get('deleted')]:
                self.zones.pop(name)
        elif re.match(r'/cluster/sdn/vnets/[^/]+$', p):
            self.vnets[p.split('/')[4]].update(data, state='changed')
        elif re.match(r'/cluster/sdn/vnets/[^/]+/subnets/[^/]+$', p):
            self.subnets[p.split('/')[4]][p.split('/')[6]].update(data)
        else:
            self.vms[int(re.search(r'/qemu/(\d+)/', p).group(1))]['config'].update(data)
        return Resp(None)

    def delete(self, url, **k):
        p = self._path(url)
        self.writes.append(('DELETE', p, None))
        m = re.match(r'/cluster/sdn/vnets/([^/]+)/subnets/([^/]+)$', p)
        if m:
            self.subnets.get(m.group(1), {}).pop(m.group(2), None)
        elif re.match(r'/cluster/sdn/vnets/[^/]+$', p):
            self.vnets[p.split('/')[4]].update(state='deleted', deleted=True)
        elif re.match(r'/cluster/sdn/zones/[^/]+$', p):
            self.zones[p.split('/')[4]].update(state='deleted', deleted=True)
        return Resp(None)


@pytest.fixture
def seg(api, seed):
    from pegaprox.api import vlab_netseg
    admin = api.as_user(seed.user('root', role='admin'))
    sdn = FakeSDN({400: {'config': {'net0': 'virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=5'}, 'ips': ['10.20.1.21']},
                   401: {'config': {'net0': 'virtio=BC:24:11:00:00:02,bridge=vmbr0'}, 'ips': ['192.168.0.30']}})
    res = [{'vmid': 400, 'node': 'pve1', 'name': 'win-01', 'type': 'qemu', 'status': 'stopped'},
           {'vmid': 401, 'node': 'pve1', 'name': 'win-02', 'type': 'qemu', 'status': 'running'}]
    mgr = api.make_fake_manager(CID, get_vm_resources=res)
    mgr.is_connected = True
    mgr.host, mgr.api_port = 'pve1', 8006
    mgr._api_get.side_effect = sdn.get
    mgr._api_post.side_effect = sdn.post
    mgr._api_put.side_effect = sdn.put
    mgr._api_delete.side_effect = sdn.delete
    mgr._fetch_qemu_ips.side_effect = lambda node, vmid: sdn.vms[vmid]['ips']
    api.set_manager(CID, mgr)
    pool = admin.post('/api/vlab/admin/pools', json={'name': '설계팀', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    for vmid in (400, 401):
        assert admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': vmid}).status_code in (200, 201)
    vlab_netseg._state.clear()
    return admin, sdn, pool, res


def _make_segment(admin):
    assert admin.put(f'/api/vlab/admin/clusters/{CID}/netseg/zone', json={'type': 'vlan', 'bridge': 'vmbr0'}).status_code == 200
    r = admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/segments',
                   json={'name': '설계팀', 'department': '설계', 'tag': 110, 'subnet': '10.20.1.0/24', 'gateway': '10.20.1.1'})
    assert r.status_code == 201
    return r.get_json()


def test_segment_written_to_sdn_and_applied_once(seg):
    admin, sdn, pool, _ = seg
    s = _make_segment(admin)
    assert admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/segments',
                      json={'name': 'x', 'tag': 110, 'subnet': '10.30.0.0/24', 'gateway': '10.30.0.1'}).status_code == 400  # same tag
    assert admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/segments',
                      json={'name': 'x', 'tag': 111, 'subnet': '10.20.0.0/16', 'gateway': '10.20.0.1'}).status_code == 400  # overlaps
    view = admin.get(f'/api/vlab/admin/clusters/{CID}/netseg').get_json()
    assert view['segments'][0]['sdn'] == 'missing' and view['sdn']['available'] is True
    r = admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/sdn').get_json()
    assert r['applied'] and sdn.applied == 1
    assert sdn.zones['moavi']['type'] == 'vlan' and sdn.zones['moavi']['bridge'] == 'vmbr0' and sdn.zones['moavi']['ipam'] == 'pve'
    v = sdn.vnets[s['vnet']]
    assert v['zone'] == 'moavi' and v['tag'] == 110
    assert list(sdn.subnets[s['vnet']]) == ['moavi-10.20.1.0-24']
    assert admin.get(f'/api/vlab/admin/clusters/{CID}/netseg').get_json()['segments'][0]['sdn'] == 'applied'
    # again: nothing to write, no network reload
    assert admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/sdn').get_json()['applied'] is False and sdn.applied == 1


def test_others_pending_sdn_changes_block_the_apply(seg):
    admin, sdn, pool, _ = seg
    _make_segment(admin)
    sdn.vnets['opsnet'] = {'vnet': 'opsnet', 'zone': 'ops', 'state': 'new'}
    r = admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/sdn')
    assert r.status_code == 409 and 'opsnet' in r.get_json()['error'] and sdn.applied == 0


def test_desktops_move_and_come_back(seg):
    from pegaprox.api import vlab_netseg
    admin, sdn, pool, res = seg
    s = _make_segment(admin)
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'net_segment': 'seg_nope'}).status_code == 400
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'net_segment': s['id']}).status_code == 200
    st = admin.post(f"/api/vlab/admin/pools/{pool['id']}/netseg/apply").get_json()
    assert {d['vmid']: d['state'] for d in st['desktops']} == {400: 'waiting_sdn', 401: 'waiting_sdn'}
    assert 'SDN' in st['problem'] and sdn.vms[400]['config']['net0'].endswith('bridge=vmbr0,tag=5')

    admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/sdn')
    vlab_netseg.netseg_tick()                               # the stopped one moves, the running one waits
    assert sdn.vms[400]['config']['net0'] == f"virtio=BC:24:11:00:00:01,bridge={s['vnet']}"
    assert sdn.vms[401]['config']['net0'].endswith('bridge=vmbr0') and not sdn.reboots
    st = admin.get(f"/api/vlab/admin/pools/{pool['id']}/netseg").get_json()
    assert {d['vmid']: d['state'] for d in st['desktops']} == {400: 'on', 401: 'waiting'}

    st = admin.post(f"/api/vlab/admin/pools/{pool['id']}/netseg/apply", json={'restart': True}).get_json()
    assert sdn.vms[401]['config']['net0'].endswith(f"bridge={s['vnet']}") and sdn.reboots == [401]
    assert all(d['state'] == 'on' for d in st['desktops'])
    assert admin.delete(f"/api/vlab/admin/clusters/{CID}/netseg/segments/{s['id']}").status_code == 409   # in use

    # the pool leaves the segment: the stopped one goes back now (its VLAN tag too), the running one when off
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'net_segment': ''})
    vlab_netseg.netseg_tick()
    assert sdn.vms[400]['config']['net0'] == 'virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=5'
    assert sdn.vms[401]['config']['net0'].endswith(f"bridge={s['vnet']}")
    res[1]['status'] = 'stopped'
    vlab_netseg.netseg_tick()
    assert sdn.vms[401]['config']['net0'].endswith('bridge=vmbr0')
    assert netseg.moved_rows(pool_id=pool['id']) == []

    # unused now: deleting it takes the VNet out at the next SDN apply
    assert admin.delete(f"/api/vlab/admin/clusters/{CID}/netseg/segments/{s['id']}").status_code == 200
    admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/sdn')
    assert s['vnet'] not in sdn.vnets and sdn.applied == 2


def test_unregistering_puts_the_bridge_back(seg):
    from pegaprox.api import vlab_netseg
    admin, sdn, pool, _ = seg
    s = _make_segment(admin)
    admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/sdn')
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'net_segment': s['id']})
    vlab_netseg.netseg_tick()
    desk = next(d for d in admin.get(f"/api/vlab/admin/pools/{pool['id']}/netseg").get_json()['desktops'] if d['vmid'] == 400)
    assert desk['state'] == 'on' and desk['orig_bridge'] == 'vmbr0'
    assert admin.delete(f"/api/vlab/admin/desktops/{desk['id']}").status_code == 200
    assert sdn.vms[400]['config']['net0'] == 'virtio=BC:24:11:00:00:01,bridge=vmbr0,tag=5'
    assert netseg.moved(desk['id']) is None


def test_ipam_view_and_reservations(seg):
    from pegaprox.api import vlab_netseg
    admin, sdn, pool, res = seg
    s = _make_segment(admin)
    admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/sdn')
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'net_segment': s['id']})
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/netseg/apply", json={'restart': True})
    res[0]['status'] = 'running'
    sdn.ips = [{'ip': '10.20.1.21', 'mac': 'bc:24:11:00:00:01', 'vnet': s['vnet'], 'vmid': 400, 'hostname': 'win-01'},
               {'ip': '10.20.1.21', 'mac': 'BC:24:11:00:00:09', 'vnet': s['vnet'], 'vmid': 999}]
    v = admin.get(f'/api/vlab/admin/clusters/{CID}/netseg/ipam').get_json()
    g = v['segments'][0]
    assert v['ipam'] is True and g['usable'] == 254
    by_ip = {e['ip']: e for e in g['entries']}
    assert by_ip['10.20.1.1']['name'] == 'gateway'
    assert by_ip['10.20.1.21']['problem'] == 'duplicate' and 'agent' in by_ip['10.20.1.21']['sources']
    assert g['outside'] == [{'ip': '192.168.0.30', 'vmid': 401, 'name': 'win-02', 'desktop_id': g['outside'][0]['desktop_id']}]
    assert g['used'] == 2 and g['free'] == 252

    r = admin.post(f"/api/vlab/admin/clusters/{CID}/netseg/segments/{s['id']}/ips", json={'ip': '10.20.1.50', 'mac': 'bc:24:11:00:00:02'})
    assert r.status_code == 200 and sdn.ips[-1]['ip'] == '10.20.1.50' and sdn.ips[-1]['mac'] == 'BC:24:11:00:00:02'
    assert admin.post(f"/api/vlab/admin/clusters/{CID}/netseg/segments/{s['id']}/ips", json={'ip': '10.99.0.5'}).status_code == 400


def test_snat_only_in_a_simple_zone():
    ok = {'name': 'a', 'tag': 110, 'subnet': '10.20.1.0/24', 'gateway': '10.20.1.1', 'snat': True}
    assert netseg.clean_segment(ok, 'none', 'vlan')[0]['snat'] is False
    assert netseg.clean_segment(dict(ok, tag=0), 'none', 'simple')[0]['snat'] is True


def test_a_node_that_did_not_build_the_zone_holds_the_move(seg, monkeypatch):
    from pegaprox.api import vlab_netseg
    monkeypatch.setattr(vlab_netseg, 'APPLY_WAIT', 0)
    admin, sdn, pool, _ = seg
    s = _make_segment(admin)
    sdn.node_status = 'error'               # e.g. no 'source /etc/network/interfaces.d/sdn' on the node
    r = admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/sdn').get_json()
    assert r['applied'] and r['nodes'] == {'pve1': 'error'} and 'interfaces.d/sdn' in r['node_problem']
    v = admin.get(f'/api/vlab/admin/clusters/{CID}/netseg').get_json()
    assert v['sdn']['nodes'] == {'pve1': 'error'} and v['sdn']['node_problem']
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'net_segment': s['id']})
    st = admin.post(f"/api/vlab/admin/pools/{pool['id']}/netseg/apply", json={'restart': True}).get_json()
    assert all(d['state'] == 'waiting_sdn' for d in st['desktops']) and 'pve1' in st['problem']
    assert sdn.vms[400]['config']['net0'].endswith('bridge=vmbr0,tag=5') and not sdn.reboots   # nothing moved
    sdn.node_status = 'available'
    vlab_netseg.netseg_tick()
    assert sdn.vms[400]['config']['net0'].endswith(f"bridge={s['vnet']}")


def test_the_zone_can_be_deleted_once_empty(seg):
    admin, sdn, pool, _ = seg
    s = _make_segment(admin)
    admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/sdn')
    assert admin.delete(f'/api/vlab/admin/clusters/{CID}/netseg/zone').status_code == 409     # has a segment
    admin.delete(f"/api/vlab/admin/clusters/{CID}/netseg/segments/{s['id']}")
    assert admin.delete(f'/api/vlab/admin/clusters/{CID}/netseg/zone').status_code == 409     # its VNet still in Proxmox
    admin.post(f'/api/vlab/admin/clusters/{CID}/netseg/sdn')
    r = admin.delete(f'/api/vlab/admin/clusters/{CID}/netseg/zone')
    assert r.status_code == 200 and r.get_json()['removed_from_sdn'] is True
    assert 'moavi' not in sdn.zones and netseg.zone(CID) is None


def test_a_guest_keeping_its_old_address_is_reported(seg):
    from pegaprox.api import vlab_netseg
    admin, sdn, pool, res = seg
    s = _make_segment(admin)
    admin.post(f"/api/vlab/admin/clusters/{CID}/netseg/sdn")
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={"net_segment": s["id"]})
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/netseg/apply", json={"restart": True})
    st = admin.post(f"/api/vlab/admin/pools/{pool['id']}/netseg/apply").get_json()     # 401 still on 192.168.0.30
    d = next(x for x in st["desktops"] if x["vmid"] == 401)
    assert d["state"] == "on" and d["old_ips"] == ["192.168.0.30"] and "fixed address" in st["problem"]
    sdn.vms[401]["ips"] = ["10.20.1.40"]
    st = admin.post(f"/api/vlab/admin/pools/{pool['id']}/netseg/apply").get_json()
    assert st["problem"] == "" and all(not x["old_ips"] for x in st["desktops"])


def test_a_node_without_the_zone_is_not_the_problem_of_a_pool_elsewhere(seg):
    admin, sdn, pool, _ = seg
    sdn.other_node = True
    s = _make_segment(admin)
    r = admin.post(f"/api/vlab/admin/clusters/{CID}/netseg/sdn").get_json()
    assert r["nodes"] == {"pve1": "available", "pve2": "error"} and "pve2" in r["node_problem"]
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={"net_segment": s["id"]})
    st = admin.post(f"/api/vlab/admin/pools/{pool['id']}/netseg/apply", json={"restart": True}).get_json()
    assert all(d["state"] == "on" for d in st["desktops"]) and "pve2" not in st["problem"]
