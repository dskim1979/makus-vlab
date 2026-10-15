"""Microsegmentation: rules proposed from seen traffic, applied and reverted on the VM firewall."""
import types

import pytest

import pegaprox.api.flows as flows
import pegaprox.api.microseg as ms
import pegaprox.background.sflow_collector as sc
from pegaprox.utils.auth import create_api_token


class _Resp:
    def __init__(self, data=None, status=200):
        self.status_code = status
        self._data = data
        self.text = 'ok' if status == 200 else 'boom'

    def json(self):
        return {'data': self._data}


class _PVE:
    """Just enough of the Proxmox API for the VM firewall."""

    def __init__(self):
        self.rules = [{'pos': 0, 'comment': 'ops rule', 'type': 'in', 'action': 'ACCEPT'}]
        self.options = {'enable': 0, 'policy_in': 'ACCEPT'}
        self.calls = []

    def session(self):
        pve = self

        class S:
            def get(self, url, timeout=None):
                if url.endswith('/firewall/rules'):
                    return _Resp([dict(r, pos=i) for i, r in enumerate(pve.rules)])
                if url.endswith('/firewall/options'):
                    return _Resp(dict(pve.options))
                if url.endswith('/config'):
                    return _Resp({'net0': 'virtio=AA:BB,bridge=vmbr0,firewall=1'})
                return _Resp({'enable': 1})

            def post(self, url, data=None, timeout=None):
                pve.calls.append(('post', data))
                pve.rules.insert(0, dict(data))
                return _Resp(None)

            def put(self, url, data=None, timeout=None):
                pve.calls.append(('put', data))
                pve.options.update(data)
                return _Resp(None)

            def delete(self, url, timeout=None):
                pos = int(url.rsplit('/', 1)[1])
                pve.calls.append(('delete', pos))
                pve.rules.pop(pos)
                return _Resp(None)
        return S()


@pytest.fixture
def cluster(api, seed, monkeypatch):
    pve = _PVE()
    mgr = types.SimpleNamespace(host='pve1', api_port=8006, is_connected=True, config=types.SimpleNamespace(name='c1'),
                                _create_session=pve.session)
    monkeypatch.setattr(ms, 'get_connected_manager', lambda cid: (mgr, None))
    monkeypatch.setattr(ms, 'check_cluster_access', lambda cid: (True, None))
    monkeypatch.setattr(flows, 'guest_ip_map', lambda: {
        '10.0.0.10': {'cluster_id': 'c1', 'cluster': 'c1', 'vmid': 100, 'name': 'web', 'node': 'pve1', 'type': 'qemu'},
        '10.0.0.20': {'cluster_id': 'c1', 'cluster': 'c1', 'vmid': 200, 'name': 'app', 'node': 'pve1', 'type': 'qemu'},
    })
    monkeypatch.setattr(sc, 'history', lambda hours: [
        {'client': '10.0.0.20', 'server': '10.0.0.10', 'proto': 6, 'port': 443, 'bytes': 5000, 'packets': 5},
        {'client': '192.168.1.5', 'server': '10.0.0.10', 'proto': 6, 'port': 443, 'bytes': 1000, 'packets': 1},
        {'client': '10.0.0.10', 'server': '10.0.0.20', 'proto': 6, 'port': 5432, 'bytes': 800, 'packets': 2},
        {'client': '10.0.0.99', 'server': '8.8.8.8', 'proto': 17, 'port': 53, 'bytes': 100, 'packets': 1},
    ])
    seed.user('root', role='admin')
    h = {'Authorization': f"Bearer {create_api_token('root', 'front', role='admin')['token']}"}
    return api.anon(), h, pve


def test_proposals_group_inbound_traffic_per_guest(cluster):
    c, h, _ = cluster
    b = c.get('/api/microseg/recommend?cluster_id=c1&hours=24', headers=h).get_json()
    web = next(g for g in b['guests'] if g['vmid'] == 100)
    assert web['rules'][0]['proto'] == 'tcp' and web['rules'][0]['port'] == 443
    assert [s['ip'] for s in web['rules'][0]['sources']] == ['10.0.0.20', '192.168.1.5']
    assert web['rules'][0]['sources'][0]['guest']['name'] == 'app'
    assert web['firewall']['other_rules'] == 1 and web['firewall']['nics'] == {'net0': True}
    assert {g['vmid'] for g in b['guests']} == {100, 200}        # 8.8.8.8 is not a guest


def test_monitor_then_enforce_replaces_only_managed_rules_and_revert_restores(cluster):
    c, h, pve = cluster
    body = {'cluster_id': 'c1', 'node': 'pve1', 'type': 'qemu', 'vmid': 100,
            'rules': [{'proto': 'tcp', 'port': 443, 'sources': ['10.0.0.20', '192.168.1.0/24']}], 'mode': 'monitor'}
    assert c.post('/api/microseg/apply', headers=h, json=body).status_code == 200
    managed = [r for r in pve.rules if r.get('comment') == ms.TAG]
    assert len(managed) == 1 and managed[0]['dport'] == '443' and managed[0]['source'] == '10.0.0.20/32,192.168.1.0/24'
    assert pve.options['policy_in'] == 'ACCEPT' and pve.options['enable'] == 1
    assert c.post('/api/microseg/apply', headers=h, json=dict(body, mode='enforce')).status_code == 200
    assert sum(1 for r in pve.rules if r.get('comment') == ms.TAG) == 1      # replaced, not stacked
    assert pve.options['policy_in'] == 'DROP'
    assert any(r.get('comment') == 'ops rule' for r in pve.rules)             # the operator's rule stays
    assert c.post('/api/microseg/revert', headers=h, json=body).status_code == 200
    assert not any(r.get('comment') == ms.TAG for r in pve.rules) and pve.options['policy_in'] == 'ACCEPT'


def test_bad_input_and_an_empty_enforce_are_refused(cluster, api):
    c, h, _ = cluster
    base = {'cluster_id': 'c1', 'node': 'pve1', 'type': 'qemu', 'vmid': 100}
    assert c.post('/api/microseg/apply', headers=h, json=dict(base, mode='enforce', rules=[])).status_code == 400
    assert c.post('/api/microseg/apply', headers=h, json=dict(base, mode='monitor', rules=[{'proto': 'gre', 'port': 0}])).status_code == 400
    assert c.post('/api/microseg/apply', headers=h, json=dict(base, mode='monitor', rules=[{'proto': 'tcp', 'port': 22, 'sources': ['x;rm']}])).status_code == 400
    assert c.post('/api/microseg/apply', headers=h, json=dict(base, node='pve1;x', mode='monitor', rules=[])).status_code == 400
    viewer = {'Authorization': f"Bearer {create_api_token('root', 'ro', role='viewer')['token']}"}
    assert c.get('/api/microseg/recommend?cluster_id=c1', headers=viewer).status_code == 403
