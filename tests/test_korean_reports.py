# Full-stack tests for the Korean public-sector reports API (pegaprox/api/korean_reports.py).
#
# Real Flask app + real blueprint through tests/conftest.py, faking only the cluster
# manager's _api_get (the Proxmox REST reads the collector makes). Covers:
#   * the three report types (ops / resource / asset) and the data shape the browser
#     bundle (static/js/makus-reports.js) renders
#   * report-period math (KST dates, end day inclusive) and the RRD / vzdump period filter
#   * input validation (bad date, > 1 year) -> 400
#   * authz: anonymous 401, cross-tenant user sees none of the other tenant's clusters,
#     clusterIds cannot widen the scope, XCP-ng clusters are skipped
#   * a cluster that fails to answer is reported in `errors`, not as a 500

import time
import types

import pytest
from datetime import datetime, timezone, timedelta

KST = timezone(timedelta(hours=9))
DATA = '/api/korean-reports/data'
CLUSTERS = '/api/korean-reports/clusters'


@pytest.fixture(autouse=True)
def _clear_report_cache():
    # the collector reuses raw cluster reads for 30 s (preview refreshes) — isolate tests
    import pegaprox.api.korean_reports as kr
    kr._raw_cache.clear()
    yield
    kr._raw_cache.clear()


def _ms(ymd, hour=0):
    return int(datetime.strptime(ymd, '%Y-%m-%d').replace(hour=hour, tzinfo=KST).timestamp() * 1000)


class _Resp:
    def __init__(self, data, status=200):
        self.status_code = status
        self._data = data

    def json(self):
        return {'data': self._data}


def _fake_pve(api, cluster_id='cluster_1', name='lab-cluster', fail=False, period=('2026-09-01', '2026-09-30')):
    """A fake Proxmox VE manager whose _api_get answers the collector's reads."""
    in_period = _ms(period[0], 12) // 1000
    before = _ms(period[0]) // 1000 - 86400 * 3

    def api_get(url, **kw):
        if fail:
            raise RuntimeError('boom')
        path = url.split('/api2/json', 1)[1]
        if path == '/cluster/resources':
            return _Resp([
                {'type': 'node', 'node': 'pve01', 'status': 'online', 'maxcpu': 32, 'maxmem': 256e9, 'mem': 128e9, 'cpu': 0.25, 'uptime': 99},
                {'type': 'node', 'node': 'pve02', 'status': 'offline', 'maxcpu': 16, 'maxmem': 64e9},
                {'type': 'qemu', 'vmid': 100, 'name': 'web01', 'node': 'pve01', 'status': 'running', 'maxcpu': 4, 'maxmem': 8e9, 'maxdisk': 100e9, 'tags': 'prod;web'},
                {'type': 'lxc', 'vmid': 101, 'name': 'ct01', 'node': 'pve02', 'status': 'stopped', 'maxcpu': 2, 'maxmem': 2e9, 'maxdisk': 8e9},
                {'type': 'qemu', 'vmid': 9000, 'name': 'tmpl', 'node': 'pve01', 'template': 1},
                {'type': 'storage', 'storage': 'ceph', 'node': 'pve01', 'status': 'available', 'shared': 1, 'maxdisk': 1000, 'disk': 900, 'plugintype': 'rbd'},
                {'type': 'storage', 'storage': 'ceph', 'node': 'pve02', 'status': 'available', 'shared': 1, 'maxdisk': 1000, 'disk': 900, 'plugintype': 'rbd'},
                {'type': 'storage', 'storage': 'local', 'node': 'pve01', 'status': 'available', 'maxdisk': 1000, 'disk': 100, 'plugintype': 'dir'},
            ])
        if path == '/cluster/status':
            return _Resp([{'type': 'cluster', 'name': name}])
        if '/rrddata' in path:
            cf_max = 'cf=MAX' in path
            return _Resp([
                {'time': in_period, 'cpu': 0.9 if cf_max else 0.5, 'memused': 80, 'memtotal': 100},
                {'time': before, 'cpu': 1.0, 'memused': 100, 'memtotal': 100},  # outside the period
            ])
        if '/tasks' in path:
            return _Resp([
                {'starttime': in_period, 'status': 'OK', 'id': '100'},
                {'starttime': in_period, 'status': 'WARNINGS: 1', 'id': '100'},
                {'starttime': in_period, 'status': 'job errors', 'id': '101'},
                {'starttime': in_period},  # still running
            ])
        return _Resp(None, 404)

    m = api.make_fake_manager(cluster_id)
    m.host, m.api_port, m.is_connected = '10.0.0.1', 8006, True
    m.config = types.SimpleNamespace(name=name)
    m._api_get.side_effect = api_get
    api.set_manager(cluster_id, m)
    return m


def _body(**kw):
    b = {'type': 'ops', 'from': '2026-09-01', 'to': '2026-09-30',
         'meta': {'org': '○○시청', 'author': '홍길동' * 30}}
    b.update(kw)
    return b


def test_ops_report_data_admin(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    _fake_pve(api)
    r = api.as_user(admin).post(DATA, json=_body())
    assert r.status_code == 200, r.get_data(as_text=True)
    d = r.get_json()
    assert d['type'] == 'ops' and d['locale'] == 'ko'
    assert d['period'] == {'from': _ms('2026-09-01'), 'to': _ms('2026-10-01') - 1}
    assert [c['name'] for c in d['clusters']] == ['lab-cluster']
    n1 = next(n for n in d['nodes'] if n['node'] == 'pve01')
    assert n1['cpuAvg'] == 50 and n1['cpuMax'] == 90 and n1['memAvg'] == 80  # out-of-period point ignored
    assert n1['cpuNow'] == 25 and n1['memNow'] == 50 and n1['vms'] == 1
    pve02 = next(n for n in d['nodes'] if n['node'] == 'pve02')
    assert pve02['status'] == 'offline' and pve02['cpuAvg'] is None
    assert sorted(v['vmid'] for v in d['vms']) == [100, 101]  # template excluded
    assert next(v for v in d['vms'] if v['vmid'] == 100)['tags'] == 'prod, web'
    assert [s['name'] for s in d['storages']] == ['ceph', 'local']  # shared once, sorted by usage
    assert d['backups'] == {'total': 3, 'ok': 1, 'warn': 1, 'fail': 1, 'failures': d['backups']['failures']}
    assert d['backups']['failures'][0]['target'] == 'VM 101'
    assert len(d['meta']['author']) == 40 and d['meta']['org'] == '○○시청'
    assert d['errors'] == []


def test_resource_and_asset_types(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    _fake_pve(api)
    c = api.as_user(admin)
    res = c.post(DATA, json=_body(type='resource')).get_json()
    assert res['type'] == 'resource' and res['backups'] is None and res['nodes'][0]['cpuAvg'] is not None
    asset = c.post(DATA, json=_body(type='asset')).get_json()
    # the asset inventory skips the RRD reads (state at generation time)
    assert asset['type'] == 'asset' and all(n['cpuAvg'] is None for n in asset['nodes'])
    assert len(asset['vms']) == 2


def test_validation_errors_400(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    _fake_pve(api)
    c = api.as_user(admin)
    assert c.post(DATA, json=_body(**{'from': '2026/09/01'})).status_code == 400
    assert c.post(DATA, json=_body(**{'from': '2026-09-30', 'to': '2026-09-01'})).status_code == 400
    r = c.post(DATA, json=_body(**{'from': '2024-01-01', 'to': '2026-01-01', 'locale': 'en'}))
    assert r.status_code == 400 and 'one year' in r.get_json()['error']


def test_anonymous_401(api, seed):
    _fake_pve(api)
    assert api.anon().post(DATA, json=_body()).status_code == 401
    assert api.anon().get(CLUSTERS).status_code == 401


def test_cross_tenant_user_sees_nothing_and_cannot_widen(api, seed):
    seed.tenant('tenant_other', clusters=['cluster_2'])
    dave = seed.user('dave', role='user', tenant_id='tenant_other')
    m = _fake_pve(api)
    c = api.as_user(dave)
    assert c.get(CLUSTERS).get_json() == []
    d = c.post(DATA, json=_body(clusterIds=['cluster_1'])).get_json()
    assert d['nodes'] == [] and d['vms'] == [] and d['clusters'] == []
    m._api_get.assert_not_called()


def test_cluster_filter_and_xcpng_skipped(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    _fake_pve(api, 'cluster_1', 'one')
    _fake_pve(api, 'cluster_2', 'two')
    x = api.set_manager('xcp_1', api.make_fake_manager('xcp_1', cluster_type='xcpng'))
    c = api.as_user(admin)
    names = [k['name'] for k in c.get(CLUSTERS).get_json()]
    assert names == ['one', 'two']
    d = c.post(DATA, json=_body(clusterIds=['cluster_2'])).get_json()
    assert [k['name'] for k in d['clusters']] == ['two']
    x._api_get.assert_not_called()


def test_failing_cluster_reported_not_500(api, seed):
    admin = seed.user('root', role='admin', tenant_id='default')
    _fake_pve(api, 'cluster_1', 'good')
    _fake_pve(api, 'cluster_2', 'bad', fail=True)
    d = api.as_user(admin).post(DATA, json=_body()).get_json()
    assert [k['name'] for k in d['clusters']] == ['good']
    assert d['errors'] and d['errors'][0]['connection'] == 'bad'
    # every cluster failing -> 502 with the reasons
    api.set_manager('cluster_1', api.make_fake_manager('cluster_1'))
    _fake_pve(api, 'cluster_1', 'good', fail=True)
    r = api.as_user(admin).post(DATA, json=_body(type='resource', **{'to': '2026-09-29'}))
    assert r.status_code == 502


def test_ops_report_includes_hardware_history_for_visible_nodes(api, seed):
    import pegaprox.core.hw_history as hw
    hw._ensured = False
    admin = seed.user('root', role='admin', tenant_id='default')
    _fake_pve(api)
    s = lambda h, bad=(): {'available': True, 'health': h, 'bad': list(bad), 'source': 'inband'}
    hw.record('cluster_1', 'pve01', s('ok'), _ms('2026-08-20'))
    hw.record('cluster_1', 'pve01', s('critical', ['PSU2']), _ms('2026-09-10', 9))
    hw.record('cluster_1', 'pve01', s('ok'), _ms('2026-09-11', 9))
    hw.record('cluster_9', 'ghost', s('critical', ['Fan']), _ms('2026-09-10'))  # not a visible cluster
    c = api.as_user(admin)
    d = c.post(DATA, json=_body()).get_json()
    x = d['hardware']
    assert x and x['covered'] and x['live'] is False
    assert [k['name'] for k in x['servers']] == ['pve01']
    inc = x['servers'][0]['incidents']
    assert inc[0]['key'] == 'PSU2' and inc[0]['recoveredAt'] == _ms('2026-09-11', 9)
    # only the operations report carries it
    assert c.post(DATA, json=_body(type='resource')).get_json()['hardware'] is None
