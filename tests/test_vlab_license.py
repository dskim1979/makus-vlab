"""MOAVI Desk licence seats (pegaprox/vlab/license_usage.py, pegaprox/api/vlab_license.py):
lmstat -a and lmgrd debug log parsing on real-shaped samples, the seat thresholds, the
numbers of the report, and the routes in engine and guest agent mode.
"""
import time
from datetime import datetime

import pytest

from pegaprox.vlab import catalog, store
from pegaprox.vlab import license_usage as lu

CID = 'cluster_1'
NOW = datetime(2026, 10, 16, 10, 20)

# Vivado (xilinxd) and Quartus (alterad) on one lmgrd, as lmutil 11.19 prints it
LMSTAT = """lmutil - Copyright (c) 1989-2023 Flexera. All Rights Reserved.
Flexible License Manager status on Fri 10/16/2026 10:20

[Detecting lmgrd processes...]
License server status: 2100@lic01
    License file(s) on lic01: /opt/flexlm/licenses/lab.lic:

     lic01: license server UP (MASTER) v11.19.4

Vendor daemon status (on lic01):

   xilinxd: UP v11.19.4
   alterad: UP v11.19.4

Feature usage info:

Users of Vivado_System_Edition:  (Total of 10 licenses issued;  Total of 3 licenses in use)

  "Vivado_System_Edition" v2024.12, vendor: xilinxd, expiry: 31-dec-2026
  vendor_string: Floating
  floating license

    alice ws-fpga-01 ws-fpga-01:0 (v2024.1) (lic01/2100 201), start Fri 10/16 9:03
    bob LAB-A-02.univ.ac.kr /dev/pts/1 (v2024.1) (lic01/2100 305), start Fri 10/16 9:41, 2 licenses

Users of Vitis:  (Total of 2 licenses issued;  Total of 2 licenses in use)

  "Vitis" v2024.12, vendor: xilinxd, expiry: 31-dec-2026
  floating license

    carol build-07 build-07 (v2024.1) (lic01/2100 401), start Thu 10/15 23:50

  "Vitis" v2025.06, vendor: xilinxd, expiry: 31-dec-2026
  floating license

    dave pc-dave pc-dave (v2025.1) (lic01/2100 402), start Fri 10/16 10:01
    erin pc-erin pc-erin (v2025.1) (lic01/2100 403) queued for 1 license

Users of Synthesis:  (Uncounted, node-locked)

Users of quartus:  (Total of 1 license issued;  Total of 0 licenses in use)

Users of broken_feat:  (Error: 1 licenses, unsupported by licensed server)
"""

DOWN = """lmutil - Copyright (c) 1989-2023 Flexera. All Rights Reserved.
Flexible License Manager status on Fri 10/16/2026 10:20

Error getting status: Cannot connect to license server system. (-15,570:10061 "WinSock: Connection refused")
"""

DEBUG_LOG = """ 9:00:01 (lmgrd) TIMESTAMP 10/15/2026
23:55:10 (xilinxd) OUT: "Vitis" carol@build-07
23:58:40 (xilinxd) DENIED: "Vitis" dave@pc-dave  (Licensed number of users already reached. (-4,342:10054 ""))
 0:12:03 (xilinxd) DENIED: "Vitis" erin@pc-erin  (Licensed number of users already reached. (-4,342:10054 ""))
 0:20:00 (xilinxd) UNSUPPORTED: "Vivado_HLS" frank@pc-frank  (License server system does not support this feature. (-18,327:10054 ""))
 0:20:00 (xilinxd) IN: "Vitis" carol@build-07
"""


def _epoch(y, mo, d, h, mi, s=0):
    return int(time.mktime(datetime(y, mo, d, h, mi, s).timetuple()))


# --- parsers -----------------------------------------------------------------------------

def test_lmstat_features_totals_and_holders():
    r = lu.parse_lmstat(LMSTAT, now=NOW)
    assert r['error'] == ''
    assert [s['up'] for s in r['servers']] == [True]
    assert {d['vendor'] for d in r['daemons']} == {'xilinxd', 'alterad'}
    f = {x['feature']: x for x in r['features']}
    # node-locked and errored features are not seats
    assert sorted(f) == ['Vitis', 'Vivado_System_Edition', 'quartus']
    viv = f['Vivado_System_Edition']
    assert (viv['vendor'], viv['total'], viv['in_use'], viv['queued']) == ('xilinxd', 10, 3, 0)
    alice, bob = viv['holders']
    assert (alice['user'], alice['host'], alice['display'], alice['version']) == ('alice', 'ws-fpga-01', 'ws-fpga-01:0', '2024.1')
    assert alice['start'] == _epoch(2026, 10, 16, 9, 3) and alice['count'] == 1
    assert (bob['host'], bob['count']) == ('LAB-A-02.univ.ac.kr', 2)
    # two INCREMENT lines of one feature are one row; a queued request is not a holder
    vitis = f['Vitis']
    assert (vitis['total'], vitis['in_use'], vitis['queued']) == (2, 2, 1)
    assert [h['user'] for h in vitis['holders']] == ['carol', 'dave']
    assert [h['version'] for h in vitis['holders']] == ['2024.1', '2025.1']
    assert vitis['holders'][0]['start'] == _epoch(2026, 10, 15, 23, 50)
    assert f['quartus']['total'] == 1 and f['quartus']['holders'] == []


def test_lmstat_start_without_a_year_is_never_in_the_future():
    r = lu.parse_lmstat(LMSTAT.replace('start Fri 10/16 9:03', 'start Thu 12/31 23:00'), now=NOW)
    alice = [x for x in r['features'] if x['feature'].startswith('Vivado')][0]['holders'][0]
    assert alice['start'] == _epoch(2025, 12, 31, 23, 0)


def test_lmstat_errors_are_told():
    assert lu.parse_lmstat(DOWN)['error'].startswith('Error getting status: Cannot connect')
    assert lu.parse_lmstat('')['error'] == 'no lmstat output'
    m = lu.merge([lu.parse_lmstat(DOWN), lu.parse_lmstat(LMSTAT, now=NOW)])
    assert m['error'] == '' and len(m['features']) == 3          # one lmgrd answered


def test_two_lmgrd_ports_add_up():
    one = lu.parse_lmstat(LMSTAT, now=NOW)
    m = lu.merge([one, lu.parse_lmstat(LMSTAT, now=NOW)])
    viv = [f for f in m['features'] if f['feature'] == 'Vivado_System_Edition'][0]
    assert (viv['total'], viv['in_use'], len(viv['holders'])) == (20, 6, 4)


def test_debug_log_denials_take_the_day_from_timestamp_and_cross_midnight():
    rows = lu.parse_denials(DEBUG_LOG, now=NOW)
    assert [(r['kind'], r['feature'], r['user'], r['host']) for r in rows] == [
        ('denied', 'Vitis', 'dave', 'pc-dave'), ('denied', 'Vitis', 'erin', 'pc-erin'),
        ('unsupported', 'Vivado_HLS', 'frank', 'pc-frank')]
    assert rows[0]['at'] == _epoch(2026, 10, 15, 23, 58, 40)
    assert rows[1]['at'] == _epoch(2026, 10, 16, 0, 12, 3)
    assert rows[0]['reason'].startswith('Licensed number of users already reached')


def test_debug_log_without_timestamp_counts_back_from_now():
    log = '\n'.join(DEBUG_LOG.splitlines()[1:])            # the TIMESTAMP line rotated away
    rows = lu.parse_denials(log, now=NOW)
    assert rows[0]['at'] == _epoch(2026, 10, 15, 23, 58, 40)
    assert rows[2]['at'] == _epoch(2026, 10, 16, 0, 20, 0)


def test_tool_and_log_paths():
    assert lu.check_tool_path('') == ''
    assert lu.check_tool_path('/opt/Xilinx/Vivado/2024.1/bin/unwrapped/lnx64.o/lmutil').endswith('lmutil')
    assert lu.check_tool_path(r'C:\flexlm\lmutil.exe').endswith('lmutil.exe')
    for bad in ('lmutil', '/bin/sh', '/opt/lmutil; rm -rf /', '/opt/x/lmutil"', '/usr/bin/python3'):
        with pytest.raises(ValueError):
            lu.check_tool_path(bad)
    assert lu.check_log_path('/var/log/lmgrd.log') == '/var/log/lmgrd.log'
    for bad in ('lmgrd.log', "/var/log/x'.log", '/var/log/$(id)'):
        with pytest.raises(ValueError):
            lu.check_log_path(bad)
    assert lu.guest_lmstat_command('', 2100, 'lic01', 'linux') == ['lmutil', 'lmstat', '-a', '-c', '2100@lic01']
    assert lu.guest_lmstat_command(r'C:\flexlm\lmstat.exe', 27000, 'lic01', 'windows') == [r'C:\flexlm\lmstat.exe', '-a', '-c', '27000@lic01']
    assert lu.guest_log_command('/var/log/lmgrd.log', 'linux', 10) == ['tail', '-n', '10', '/var/log/lmgrd.log']


def test_seat_threshold_levels_alert_once_each_way():
    s = {'seat_threshold': 90, 'feature_thresholds': {'quartus': 0, 'Vitis': 50}, 'seat_alerted': {}}
    f = lambda name, used, total: {'feature': name, 'in_use': used, 'total': total}    # noqa: E731
    ev, st = lu.seat_alerts(s, [f('Vivado', 9, 10), f('Vitis', 1, 2), f('quartus', 1, 1)])
    assert [(e['feature'], e['level']) for e in ev] == [('Vivado', 'high'), ('Vitis', 'high')]    # quartus: 0 = off
    s['seat_alerted'] = st
    ev, st = lu.seat_alerts(s, [f('Vivado', 9, 10), f('Vitis', 2, 2)])
    assert [(e['feature'], e['level']) for e in ev] == [('Vitis', 'full')]
    s['seat_alerted'] = st
    ev, st = lu.seat_alerts(s, [f('Vivado', 5, 10), f('Vitis', 2, 2)])
    assert [(e['feature'], e['level']) for e in ev] == [('Vivado', 'ok')] and st == {'Vitis': 'full'}


def test_stats_shortages_advice_and_user_hours():
    rows = [{'feature': 'V', 'vendor': 'x', 'at': t * 300, 'total': 2, 'in_use': u}
            for t, u in enumerate([1, 2, 2, 1, 2, 0])]
    st = lu.feature_stats(rows)['V']
    assert (st['peak'], st['avg'], st['shortage_count'], st['shortage_minutes']) == (2, 1.33, 2, 15)
    assert lu.advice(st)['action'] == 'add'
    idle = lu.feature_stats([{'feature': 'Q', 'vendor': '', 'at': i * 300, 'total': 10, 'in_use': 3}
                             for i in range(7 * 288)])['Q']
    assert lu.advice(idle) == {'action': 'reduce', 'seats': 6}
    assert lu.advice(dict(idle, samples=10))['action'] == 'keep'         # too short to say
    co = [{'username': 'alice', 'feature': 'V', 'server_id': 's', 'host': 'h1', 'count': 1, 'started': 0, 'first_seen': 300, 'last_seen': 7200},
          {'username': 'alice', 'feature': 'V', 'server_id': 's', 'host': 'h2', 'count': 2, 'started': 3600, 'first_seen': 3600, 'last_seen': 5400}]
    u = lu.user_hours(co, 1800, 10000)
    assert u == [{'user': 'alice', 'feature': 'V', 'server_id': 's', 'checkouts': 2, 'hours': 2.5, 'hosts': ['h1', 'h2']}]


# --- routes ------------------------------------------------------------------------------

RES = [{'vmid': 210, 'node': 'pve1', 'name': 'lic01', 'type': 'qemu', 'status': 'running'},
       {'vmid': 300, 'node': 'pve1', 'name': 'ws-fpga-01', 'type': 'qemu', 'status': 'running'}]


@pytest.fixture
def env(api, seed):
    mgr = api.make_fake_manager(CID, get_vm_resources=RES)
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    pool = store.create_pool('FPGA 설계', 'dedicated', CID)
    store.add_desktop(pool, 'pve1', 300, 'ws-fpga-01')
    lab = store.add_desktop(pool, 'pve1', 301, 'lab-a-02')
    store.start_session('bob', lab, 'spice', '10.0.0.5')
    return api, mgr, admin, alice


def _server(admin, **extra):
    r = admin.post('/api/vlab/admin/license-servers', json=dict({'name': 'FPGA 툴 (FlexLM)', 'host': 'lic01', 'ports': '2100, 2101'}, **extra))
    assert r.status_code == 201, r.get_json()
    return r.get_json()['server']


def test_settings_are_checked_and_need_the_manage_permission(env):
    _, _, admin, alice = env
    s = _server(admin)
    url = f"/api/vlab/admin/license-servers/{s['id']}/usage-settings"
    assert alice.put(url, json={'mode': 'engine'}).status_code == 403
    assert alice.get(f"/api/vlab/admin/license-servers/{s['id']}/usage").status_code == 403
    assert admin.put(url, json={'mode': 'sometimes'}).status_code == 400
    assert admin.put(url, json={'mode': 'engine', 'lmutil_path': '/bin/sh'}).status_code == 400
    assert admin.put(url, json={'mode': 'engine', 'seat_threshold': 101}).status_code == 400
    assert admin.put(url, json={'mode': 'engine', 'feature_thresholds': {'Vitis': 'x'}}).status_code == 400
    r = admin.put(url, json={'mode': 'agent'})
    assert r.status_code == 400 and 'VM' in r.get_json()['error']               # agent mode needs the VM
    r = admin.put(url, json={'mode': 'engine', 'lm_ports': '2100', 'seat_threshold': 80, 'feature_thresholds': {'Vitis': 100},
                             'alert_channels': ['ch1']})
    assert r.status_code == 200, r.get_json()
    st = r.get_json()['settings']
    assert (st['mode'], st['lm_ports'], st['seat_threshold'], st['feature_thresholds'], st['alert_channels']) == \
        ('engine', [2100], 80, {'Vitis': 100}, ['ch1'])
    assert admin.post(f"/api/vlab/admin/license-servers/{s['id']}/usage/collect").status_code in (200,)
    off = _server(admin, name='끔')
    assert admin.post(f"/api/vlab/admin/license-servers/{off['id']}/usage/collect").status_code == 409


def test_engine_mode_reads_keeps_matches_desktops_and_alerts(env, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    _, _, admin, _ = env
    s = _server(admin)
    admin.put(f"/api/vlab/admin/license-servers/{s['id']}/usage-settings",
              json={'mode': 'engine', 'lm_ports': [2100], 'alert_channels': ['ch-lab']})
    ran = []
    monkeypatch.setattr(lu, 'find_lmutil', lambda configured='': '/opt/moavi/lmutil/lmutil')
    monkeypatch.setattr(lu, 'run_lmutil', lambda path, port, host: ran.append((path, port, host)) or (0, LMSTAT, ''))
    sent = []
    monkeypatch.setattr(nxt, '_alert', lambda title, text, data, channels=None: sent.append((data['kind'], data.get('feature'), channels)))
    monkeypatch.setattr(nxt, '_tcp_probe', lambda h, p, timeout=2.0: (True, 1, ''))
    assert nxt.license_tick(force=True) == 1                       # ports checked, then the seats read
    assert ran == [('/opt/moavi/lmutil/lmutil', 2100, 'lic01')]
    # Vitis 2/2: full; Vivado 3/10 is under 90 %
    assert sent == [('license_seats_full', 'Vitis', ['ch-lab'])]
    nxt.license_tick(force=True)
    assert len(sent) == 1                                           # once

    u = admin.get(f"/api/vlab/admin/license-servers/{s['id']}/usage?hours=24").get_json()
    assert u['settings']['last_ok'] == 1 and u['lmutil'] == '/opt/moavi/lmutil/lmutil'
    f = {x['feature']: x for x in u['features']}
    assert (f['Vitis']['in_use'], f['Vitis']['total'], f['Vitis']['pct'], f['Vitis']['alerted']) == (2, 2, 100, 'full')
    # two checks (the same second here: one sample), one run of every seat taken
    assert f['Vitis']['shortage_count'] == 1 and f['Vitis']['shortage_minutes'] in (5, 10)
    who = {h['user']: h for h in f['Vivado_System_Edition']['holders']}
    assert who['alice']['desktop']['name'] == 'ws-fpga-01' and who['alice']['desktop']['match'] == 'host'
    # bob's host is a FQDN in upper case: the short name finds the desktop
    assert who['bob']['desktop']['name'] == 'lab-a-02' and who['bob']['count'] == 2
    assert f['Vitis']['holders'][0]['desktop'] is None             # build-07 is not a MOAVI desktop
    assert u['series']['Vitis'][0]['max'] == 2 and u['bucket'] == 3600

    rep = admin.get('/api/vlab/admin/reports/licenses?days=7').get_json()
    row = [r for r in rep['features'] if r['feature'] == 'Vitis'][0]
    assert (row['peak'], row['total'], row['advice']['action']) == (2, 2, 'add')
    users = {(r['user'], r['feature']) for r in rep['users']}
    assert ('alice', 'Vivado_System_Edition') in users and ('carol', 'Vitis') in users
    csv = admin.get('/api/vlab/admin/reports/licenses?days=7&format=csv').get_data(as_text=True)
    assert csv.lstrip('\ufeff').startswith('server,feature,vendor,seats,peak') and 'Vitis' in csv
    csv = admin.get('/api/vlab/admin/reports/licenses?days=7&view=users&format=csv').get_data(as_text=True)
    assert csv.lstrip('\ufeff').startswith('user,server,feature,hours') and 'alice' in csv

    assert admin.delete(f"/api/vlab/admin/license-servers/{s['id']}").status_code == 200
    assert lu.latest_at(s['id']) is None                           # its history went with it


def test_engine_mode_without_lmutil_says_where_to_put_it(env, monkeypatch):
    _, _, admin, _ = env
    s = _server(admin)
    admin.put(f"/api/vlab/admin/license-servers/{s['id']}/usage-settings", json={'mode': 'engine'})
    monkeypatch.setattr(lu, 'find_lmutil', lambda configured='': '')
    r = admin.post(f"/api/vlab/admin/license-servers/{s['id']}/usage/collect").get_json()
    assert r['ok'] is False and '/opt/moavi/lmutil' in r['error']
    assert catalog.get_license_server(s['id'])['usage_ok'] == 0


def test_agent_mode_runs_lmstat_and_reads_denials_on_the_vm(env, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    _, _, admin, _ = env
    s = _server(admin, cluster_id=CID, vmid=210)
    r = admin.put(f"/api/vlab/admin/license-servers/{s['id']}/usage-settings",
                  json={'mode': 'agent', 'debug_log': '/var/log/flexlm/lmgrd.log', 'lmutil_path': '/opt/flexlm/lmutil'})
    assert r.status_code == 200, r.get_json()
    cmds = []

    def run(mgr, node, vmid, command, stdin=None, wait=8.0):
        cmds.append((node, vmid, command))
        return (0, DEBUG_LOG, '', '') if command[0] == 'tail' else (0, LMSTAT, '', '')
    monkeypatch.setattr(nxt, '_agent_run', run)
    monkeypatch.setattr(nxt, '_guest_os', lambda mgr, node, vmid: 'linux')
    monkeypatch.setattr(nxt, '_alert', lambda *a, **k: None)
    r = admin.post(f"/api/vlab/admin/license-servers/{s['id']}/usage/collect").get_json()
    assert r['ok'] is True, r
    assert cmds[0] == ('pve1', 210, ['/opt/flexlm/lmutil', 'lmstat', '-a', '-c', '2100@lic01'])
    assert cmds[1][2] == ['tail', '-n', '2000', '/var/log/flexlm/lmgrd.log']
    u = admin.get(f"/api/vlab/admin/license-servers/{s['id']}/usage?hours=2160").get_json()
    assert u['denied_total'] == 3 and u['denials'][0]['user'] == 'frank'
    admin.post(f"/api/vlab/admin/license-servers/{s['id']}/usage/collect")
    assert admin.get(f"/api/vlab/admin/license-servers/{s['id']}/usage?hours=2160").get_json()['denied_total'] == 3   # read again, counted once

    # the agent does not answer: said, nothing kept
    monkeypatch.setattr(nxt, '_guest_os', lambda mgr, node, vmid: None)
    r = admin.post(f"/api/vlab/admin/license-servers/{s['id']}/usage/collect").get_json()
    assert r['ok'] is False and 'guest agent' in r['error']


def test_old_samples_go_after_90_days(env):
    lu.record('lic_x', {'features': [{'feature': 'V', 'vendor': '', 'total': 1, 'in_use': 1, 'queued': 0,
                                      'holders': [{'user': 'a', 'host': 'h', 'display': 'h', 'version': '', 'vendor': '', 'start': 1, 'count': 1}]}]},
              at=1000)
    lu.record_denials('lic_x', [{'at': 1000, 'feature': 'V', 'user': 'a', 'host': 'h', 'vendor': '', 'kind': 'denied', 'reason': ''}])
    lu.prune(now=1000 + 91 * 86400)
    assert lu.latest_at('lic_x') is None and lu.checkouts('lic_x', 0, 10 ** 10) == [] and lu.denials('lic_x', 0) == []


def test_the_usage_tables_are_per_instance_and_their_reads_go_to_the_active():
    from pegaprox.core import ha
    assert set(lu.TABLES) <= set(ha.LOCAL_TABLES) and not set(lu.TABLES) & set(ha.SYNC_TABLES)
    assert {'/api/vlab/admin/license-servers/<lid>/usage', '/api/vlab/admin/reports/licenses'} <= ha.FORWARDED_READS
    assert 'vlab_license_servers' in ha.SYNC_TABLES               # the settings travel with the server
