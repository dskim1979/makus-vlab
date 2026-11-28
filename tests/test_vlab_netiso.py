"""네트워크 격리: the pool policy's net_* switches and how they land in the Proxmox firewall."""
import json
import re
from urllib.parse import unquote

import pytest

from pegaprox.vlab import netiso, policy

CID = 'netiso_c1'


# --- the policy --------------------------------------------------------------------------------

def test_isolation_is_off_by_default():
    pol = policy.effective({}, 'dedicated')
    assert pol['net_isolation'] is False and pol['net_egress'] == 'any'
    assert pol['net_allow_in'] == [] and pol['net_allow_out'] == []


def test_rules_are_checked():
    pol, err = policy.validate({'net_isolation': True, 'net_allow_in': [
        {'cidr': '10.1.0.0/24', 'proto': 'tcp', 'port': '22', 'note': 'IT'},
        {'cidr': '10.1.0.9'}]}, 'dedicated')
    assert err is None
    assert pol['net_allow_in'] == [{'cidr': '10.1.0.0/24', 'proto': 'tcp', 'port': '22', 'note': 'IT'},
                                   {'cidr': '10.1.0.9/32', 'proto': 'any', 'port': '', 'note': ''}]
    for bad in ({'cidr': 'nas01'}, {'cidr': '10.0.0.1', 'proto': 'gre'}, {'cidr': '10.0.0.1', 'port': '22'},
                {'cidr': '10.0.0.1', 'proto': 'tcp', 'port': '99999'}, {'cidr': '10.0.0.1', 'proto': 'tcp', 'port': '90:80'}):
        assert policy.validate({'net_allow_in': [bad]}, 'dedicated')[1]
    assert policy.validate({'net_egress': 'some'}, 'dedicated')[1]
    assert policy.validate({'net_allow_out': [{'cidr': '0.0.0.0/0', 'proto': 'tcp', 'port': '80,443'}]}, 'dedicated')[0]


def test_gateway_sources_refuse_everyone():
    assert netiso.clean_sources(['192.168.0.55', '10.0.0.0/24']) == (['192.168.0.55', '10.0.0.0/24'], None)
    assert netiso.clean_sources(['0.0.0.0/0'])[1]
    assert netiso.clean_sources(['gw.local'])[1]
    assert netiso.suggested_sources(['192.168.0.55', 'moavi.example.com', '192.168.0.55']) == ['192.168.0.55']


def test_group_rules():
    pid = 'pool-1'
    base = netiso.group_rules(pid, {'net_isolation': True})
    assert [(r['type'], r['source']) for r in base] == [('in', '+vlab-gw')]
    rules = netiso.group_rules(pid, {'net_peers': True, 'net_egress': 'list',
                                     'net_allow_in': [{'cidr': '10.1.0.0/24', 'proto': 'tcp', 'port': '22', 'note': 'IT'}],
                                     'net_allow_out': [{'cidr': '10.0.0.53/32', 'proto': 'udp', 'port': '53', 'note': 'DNS'}]})
    ips = netiso.ipset_name(pid)
    assert [(r['type'], r.get('source') or r.get('dest')) for r in rules] == [
        ('in', '+vlab-gw'), ('in', f'+{ips}'), ('in', '10.1.0.0/24'),
        ('out', '+vlab-gw'), ('out', f'+{ips}'), ('out', '10.0.0.53/32')]
    assert rules[2]['proto'] == 'tcp' and rules[2]['dport'] == '22' and rules[2]['comment'] == 'vlab-netiso: IT'
    assert len(netiso.group_name(pid)) <= 18
    assert netiso.vm_options({'net_egress': 'list'})['policy_out'] == 'DROP'
    assert netiso.vm_options({})['policy_in'] == 'DROP' and netiso.vm_options({})['dhcp'] == 1


def test_nic_and_rule_compare():
    assert netiso.with_firewall('virtio=BC:24:11:A4:68:84,bridge=vmbr0') == 'virtio=BC:24:11:A4:68:84,bridge=vmbr0,firewall=1'
    assert netiso.with_firewall('virtio=AA,bridge=vmbr0,firewall=1') is None
    assert netiso.with_firewall('virtio=AA,bridge=vmbr0,firewall=0') == 'virtio=AA,bridge=vmbr0,firewall=1'
    want = netiso.group_rules('p', {})[0]
    listed = dict(want, source='+dc/vlab-gw', pos=0, ipversion=4)
    assert netiso.rule_key(listed) == netiso.rule_key(want)


# --- applying: a Proxmox firewall in memory ----------------------------------------------------------

class Resp:
    def __init__(self, data, code=200):
        self.status_code, self._data = code, data
        self.text = json.dumps(data)

    def json(self):
        return {'data': self._data}


class FakePVE:
    def __init__(self, vms):
        self.dc = {'enable': 1, 'policy_in': 'DROP'}
        self.ipsets, self.groups = {}, {}
        self.vms = vms          # vmid -> {'config', 'rules', 'options', 'ips'}
        self.writes = []

    def _path(self, url):
        return unquote(url.split('/api2/json', 1)[1])

    def get(self, url, **k):
        p = self._path(url)
        if p == '/cluster/firewall/options':
            return Resp(self.dc)
        if p == '/cluster/firewall/ipset':
            return Resp([{'name': n} for n in self.ipsets])
        if p.startswith('/cluster/firewall/ipset/'):
            return Resp(self.ipsets.get(p.rsplit('/', 1)[1], []))
        if p == '/cluster/firewall/groups':
            return Resp([{'group': n} for n in self.groups])
        if p.startswith('/cluster/firewall/groups/'):
            return Resp([dict(r, pos=i) for i, r in enumerate(self.groups[p.rsplit('/', 1)[1]])])
        m = re.match(r'/nodes/[^/]+/qemu/(\d+)/(config|firewall/rules|firewall/options)$', p)
        vm = self.vms.get(int(m.group(1))) if m else None
        if vm is None:
            return Resp(None, 500)
        if m.group(2) == 'config':
            return Resp(vm['config'])
        if m.group(2) == 'firewall/rules':
            return Resp([dict(r, pos=i) for i, r in enumerate(vm['rules'])])
        return Resp(vm['options'])

    def post(self, url, data=None, **k):
        p = self._path(url)
        self.writes.append(('POST', p, data))
        if p == '/cluster/firewall/ipset':
            self.ipsets[data['name']] = []
        elif p.startswith('/cluster/firewall/ipset/'):
            self.ipsets[p.rsplit('/', 1)[1]].append({'cidr': data['cidr'], 'comment': data.get('comment')})
        elif p == '/cluster/firewall/groups':
            self.groups[data['group']] = []
        elif p.startswith('/cluster/firewall/groups/'):
            self.groups[p.rsplit('/', 1)[1]].insert(0, dict(data))
        else:
            vm = self.vms[int(re.search(r'/qemu/(\d+)/', p).group(1))]
            vm['rules'].insert(0, {k: v for k, v in data.items() if k != 'pos'})
        return Resp(None)

    def put(self, url, data=None, **k):
        p = self._path(url)
        self.writes.append(('PUT', p, data))
        vm = self.vms[int(re.search(r'/qemu/(\d+)/', p).group(1))]
        (vm['config'] if p.endswith('/config') else vm['options']).update(data)
        return Resp(None)

    def delete(self, url, **k):
        p = self._path(url)
        self.writes.append(('DELETE', p, None))
        m = re.match(r'/cluster/firewall/ipset/([^/]+)/(.+)$', p)
        if m:
            self.ipsets[m.group(1)] = [e for e in self.ipsets[m.group(1)] if e['cidr'] != m.group(2)]
        elif re.match(r'/cluster/firewall/groups/[^/]+/\d+$', p):
            name, pos = p.split('/')[-2:]
            self.groups[name].pop(int(pos))
        elif re.match(r'/cluster/firewall/(groups|ipset)/[^/]+$', p):
            kind, name = p.split('/')[-2:]
            (self.groups if kind == 'groups' else self.ipsets).pop(name, None)
        else:
            vm = self.vms[int(re.search(r'/qemu/(\d+)/', p).group(1))]
            vm['rules'].pop(int(p.rsplit('/', 1)[1]))
        return Resp(None)


@pytest.fixture
def iso(api, seed):
    from pegaprox.api import vlab_netiso
    admin = api.as_user(seed.user('root', role='admin'))
    pve = FakePVE({300: {'config': {'net0': 'virtio=AA,bridge=vmbr0'}, 'rules': [{'type': 'in', 'action': 'ACCEPT', 'comment': 'mine'}],
                         'options': {}, 'ips': ['192.168.0.22', 'fe80::1']},
                   301: {'config': {'net0': 'virtio=BB,bridge=vmbr0'}, 'rules': [], 'options': {'enable': 1}, 'ips': ['192.168.0.23']}})
    mgr = api.make_fake_manager(CID, get_vm_resources=[
        {'vmid': 300, 'node': 'pve1', 'name': 'win-01', 'type': 'qemu', 'status': 'running'},
        {'vmid': 301, 'node': 'pve1', 'name': 'win-02', 'type': 'qemu', 'status': 'running'}])
    mgr.is_connected = True
    mgr.host, mgr.api_port = 'pve1', 8006
    mgr._api_get.side_effect = pve.get
    mgr._api_post.side_effect = pve.post
    mgr._api_put.side_effect = pve.put
    mgr._api_delete.side_effect = pve.delete
    mgr._fetch_qemu_ips.side_effect = lambda node, vmid: pve.vms[vmid]['ips']
    api.set_manager(CID, mgr)
    pool = admin.post('/api/vlab/admin/pools', json={'name': '설계팀', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    for vmid in (300, 301):
        assert admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': vmid}).status_code in (200, 201)
    vlab_netiso._state.clear()
    return admin, pve, pool


def test_nothing_without_a_gateway_address(iso):
    admin, pve, pool = iso
    assert admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'net_isolation': True}).status_code == 200
    st = admin.post(f"/api/vlab/admin/pools/{pool['id']}/netiso/apply").get_json()
    assert 'gateway' in st['problem'] and not pve.writes


def test_apply_and_take_back(iso):
    admin, pve, pool = iso
    assert admin.put(f'/api/vlab/admin/clusters/{CID}/netiso', json={'gateway_sources': ['192.168.0.55']}).status_code == 200
    assert admin.get(f'/api/vlab/admin/clusters/{CID}/netiso').get_json()['cluster_firewall'] == {'enable': True, 'policy_in': 'DROP'}
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'net_isolation': True, 'net_peers': True})
    st = admin.post(f"/api/vlab/admin/pools/{pool['id']}/netiso/apply").get_json()
    assert st['problem'] == '' and all(d['applied'] for d in st['desktops'])
    group, ipset = netiso.group_name(pool['id']), netiso.ipset_name(pool['id'])
    assert [e['cidr'] for e in pve.ipsets['vlab-gw']] == ['192.168.0.55']
    assert sorted(e['cidr'] for e in pve.ipsets[ipset]) == ['192.168.0.22', '192.168.0.23']
    assert [r['source'] for r in pve.groups[group]] == ['+vlab-gw', f'+{ipset}']
    vm = pve.vms[300]
    assert vm['config']['net0'].endswith(',firewall=1')
    assert vm['rules'][0] == {'type': 'group', 'action': group, 'enable': 1, 'comment': 'vlab-netiso'}
    assert vm['rules'][1]['comment'] == 'mine'          # the operator's rule stays
    assert vm['options']['policy_in'] == 'DROP' and vm['options']['enable'] == 1

    # again: nothing to change
    pve.writes.clear()
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/netiso/apply")
    assert not pve.writes

    # off: back as before - the firewall off again where this turned it on, the operator's rule kept
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'net_isolation': False})
    admin.post(f"/api/vlab/admin/pools/{pool['id']}/netiso/apply")
    assert vm['rules'] == [{'type': 'in', 'action': 'ACCEPT', 'comment': 'mine'}]
    assert vm['options']['enable'] == 0 and vm['options']['policy_in'] == 'ACCEPT'
    assert pve.vms[301]['options']['enable'] == 1      # it was on before
    assert group not in pve.groups and ipset not in pve.ipsets
    assert netiso.applied_rows(pool_id=pool['id']) == []


def test_the_tick_follows_a_policy_change(iso):
    from pegaprox.api import vlab_netiso
    admin, pve, pool = iso
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'net_isolation': False})
    admin.put(f'/api/vlab/admin/clusters/{CID}/netiso', json={'gateway_sources': ['192.168.0.55']})
    vlab_netiso.netiso_tick()
    assert not pve.writes                               # isolation is off
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'net_isolation': True, 'net_egress': 'list',
              'net_allow_out': [{'cidr': '10.0.0.53', 'proto': 'udp', 'port': '53', 'note': 'DNS'}]})
    vlab_netiso.netiso_tick()
    group = netiso.group_name(pool['id'])
    assert [r['type'] for r in pve.groups[group]] == ['in', 'out', 'out']
    assert pve.vms[301]['options']['policy_out'] == 'DROP'


def test_a_new_pool_starts_isolated_and_registering_applies_it(iso, api):
    admin, pve, pool = iso
    assert admin.get(f"/api/vlab/admin/pools/{pool['id']}/policy").get_json()['policy']['net_isolation'] is True
    admin.put(f'/api/vlab/admin/clusters/{CID}/netiso', json={'gateway_sources': ['192.168.0.55']})
    pve.vms[302] = {'config': {'net0': 'virtio=CC,bridge=vmbr0'}, 'rules': [], 'options': {}, 'ips': ['192.168.0.24']}
    from pegaprox.globals import cluster_managers
    cluster_managers[CID].get_vm_resources.return_value = cluster_managers[CID].get_vm_resources.return_value + [
        {'vmid': 302, 'node': 'pve1', 'name': 'win-03', 'type': 'qemu', 'status': 'running'}]
    r = admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': 302})
    assert r.status_code in (200, 201)
    group = netiso.group_name(pool['id'])
    assert pve.vms[302]['rules'][0]['action'] == group and pve.vms[302]['options']['policy_in'] == 'DROP'
    assert pve.vms[300]['options']['policy_in'] == 'DROP'      # the whole pool on the same sync

    # unregistering takes it off that VM at once
    desk = r.get_json()['desktop']
    assert admin.delete(f"/api/vlab/admin/desktops/{desk['id']}").status_code == 200
    assert pve.vms[302]['rules'] == [] and pve.vms[302]['options']['policy_in'] == 'ACCEPT'
    assert pve.vms[302]['options']['enable'] == 0
    assert netiso.applied(desk['id']) is None


def test_a_rule_naming_another_pool_keeps_that_pools_addresses(iso):
    """마이크로 세그먼트: 설계팀 takes SMB from 연구소's desktops - 연구소's ipset is kept for the rule,
    though 연구소 itself is not isolated."""
    admin, pve, pool = iso
    admin.put(f'/api/vlab/admin/clusters/{CID}/netiso', json={'gateway_sources': ['192.168.0.55']})
    other = admin.post('/api/vlab/admin/pools', json={'name': '연구소', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    admin.put(f"/api/vlab/admin/pools/{other['id']}/policy", json={'net_isolation': False})
    from pegaprox.vlab import store
    store.remove_desktop(next(d['id'] for d in store.list_desktops(pool['id']) if d['vmid'] == 301))
    assert admin.post(f"/api/vlab/admin/pools/{other['id']}/desktops", json={'vmid': 301}).status_code in (200, 201)
    admin.put(f"/api/vlab/admin/pools/{pool['id']}/policy",
              json={'net_isolation': True, 'net_allow_in': [{'pool': other['id'], 'proto': 'tcp', 'port': '445'}]})
    st = admin.post(f"/api/vlab/admin/pools/{pool['id']}/netiso/apply").get_json()
    assert st['problem'] == '', st
    peer = netiso.ipset_name(other['id'])
    assert [e['cidr'] for e in pve.ipsets[peer]] == ['192.168.0.23']
    assert any(r.get('source') == f'+{peer}' and r.get('dport') == '445' for r in pve.groups[netiso.group_name(pool['id'])])
