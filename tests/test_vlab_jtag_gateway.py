"""MOAVI Desk board lab - JTAG gateway VMs (pegaprox/vlab/jtag_gw.py, the routes in api/vlab_next.py):
cables on a gateway VM shared over hw_server / XVC / jtagd, one cable one board, health and lending."""
import pytest

from pegaprox.vlab import catalog, jtag_gw, store
from test_vlab_next import CID, env  # noqa: F401 - the shared fixture

LISTING = '\n'.join([
    '1d6b:0002|0000:00:1d.0|Linux Foundation|xHCI Host Controller|usb1',
    '0403:6010|210251A08870|Digilent|Digilent USB Device|1-1',
    '0403:6014|FT4ABCDE|FTDI|Single RS232-HS|1-2',
    '2109:2817||VIA Labs|USB2.0 Hub|1-3',
    '03fd:0008|000013ca2b5a01|Xilinx|Platform Cable USB II|1-3.1',
    '046d:c52b||Logitech|USB Receiver|2-1',
    'garbage line',
])


# --- pure ------------------------------------------------------------------------------------

def test_cables_are_read_from_the_listing():
    cables = jtag_gw.parse_cables(LISTING)
    assert [c['port'] for c in cables] == ['1-1', '1-2', '1-3.1', '2-1']        # root hub, hub, junk left out; JTAG first
    assert cables[0] == {'vidpid': '0403:6010', 'serial': '210251A08870', 'manufacturer': 'Digilent',
                         'product': 'Digilent USB Device', 'port': '1-1', 'jtag': True}
    assert [c['jtag'] for c in cables] == [True, True, True, False]


def test_free_slots_and_pci_values():
    assert jtag_gw.free_slot({'usb0': 'host=1-1', 'usb1': 'spice'}, 'usb') == 'usb2'
    assert jtag_gw.free_slot({f'usb{i}': 'x' for i in range(14)}, 'usb') is None
    assert jtag_gw.free_slot({'hostpci0': 'x'}, 'pci') == 'hostpci1'
    assert jtag_gw.pci_value('0000:05:00.0', {'machine': 'pc-q35-8.1'}) == '0000:05:00.0,pcie=1'
    assert jtag_gw.pci_value('0000:05:00.0', {}) == '0000:05:00.0'
    assert jtag_gw.valid_pci('0000:05:00.0') and jtag_gw.valid_pci('05:00') and not jtag_gw.valid_pci('usb')


def test_power_is_an_extension_point(monkeypatch):
    monkeypatch.setattr(jtag_gw, 'POWER_DRIVERS', {})
    assert jtag_gw.power({}, 'on', {'driver': 'pdu'}) == (False, 'NO_DRIVER')
    seen = []
    jtag_gw.register_power_driver('pdu', lambda b, a, cfg: seen.append((a, cfg['outlet'])))
    assert jtag_gw.power({}, 'cycle', {'driver': 'pdu', 'outlet': 7}) == (True, '') and seen == [('cycle', 7)]
    jtag_gw.register_power_driver('bad', lambda b, a, cfg: (_ for _ in ()).throw(RuntimeError('relay offline')))
    assert jtag_gw.power({}, 'off', {'driver': 'bad'}) == (False, 'relay offline')


# --- the routes ------------------------------------------------------------------------------

@pytest.fixture
def gw(env, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    api, mgr, admin, alice, bob, viewer = env
    states = {300: {'vmid': 300, 'node': 'pve1', 'type': 'qemu', 'status': 'running'},
              700: {'vmid': 700, 'node': 'pve2', 'type': 'qemu', 'status': 'running'}}
    monkeypatch.setattr(nxt.core, '_vm_states', lambda cid: states)
    mgr.get_vm_config.return_value = {'success': True, 'config': {'raw': {'usb0': 'spice', 'machine': 'q35'}}}
    up = {'ok': True}
    monkeypatch.setattr(nxt, '_tcp_probe', lambda h, p, timeout=2.0: (up['ok'], 1, '' if up['ok'] else 'refused'))
    monkeypatch.setattr(nxt, '_alert', lambda *a, **k: None)
    r = admin.post('/api/vlab/admin/jtag-gateways', json={'name': 'jtag-gw-01', 'cluster_id': CID, 'vmid': 700, 'host': 'jtag-gw-01.lab'})
    assert r.status_code == 201, r.get_json()
    return env, r.get_json()['gateway'], states, up


def test_gateway_registration_and_passthrough(gw):
    (api, mgr, admin, alice, bob, viewer), g, states, up = gw
    assert g['hw_port'] == 3121 and g['jtagd_port'] == 1309 and g['state'] == 'unknown' and g['vm']['node'] == 'pve2'
    assert viewer.post('/api/vlab/admin/jtag-gateways', json={'name': 'x', 'cluster_id': CID, 'host': 'h'}).status_code == 403
    assert admin.post('/api/vlab/admin/jtag-gateways', json={'name': 'x', 'cluster_id': CID, 'host': 'bad host'}).status_code == 400
    r = admin.post(f"/api/vlab/admin/jtag-gateways/{g['id']}/passthrough", json={'kind': 'usb', 'usb': '03fd:0008'})
    assert r.status_code == 200 and r.get_json()['slot'] == 'usb1' and not r.get_json()['needs_restart']
    assert mgr.update_vm_config.call_args[0] == ('pve2', 700, 'qemu', {'usb1': 'host=03fd:0008'})
    assert admin.post(f"/api/vlab/admin/jtag-gateways/{g['id']}/passthrough", json={'kind': 'usb', 'usb': '03fd:0008'}).status_code == 409
    r = admin.post(f"/api/vlab/admin/jtag-gateways/{g['id']}/passthrough", json={'kind': 'pci', 'pci': '0000:05:00.0'})
    assert r.status_code == 200 and r.get_json()['needs_restart']
    assert mgr.update_vm_config.call_args[0] == ('pve2', 700, 'qemu', {'hostpci0': '0000:05:00.0,pcie=1'})
    assert admin.post(f"/api/vlab/admin/jtag-gateways/{g['id']}/passthrough", json={'kind': 'pci', 'pci': 'nope'}).status_code == 400
    mgr.get_vm_config.return_value = {'success': True, 'config': {'raw': {'usb1': 'host=03fd:0008', 'hostpci0': 'x'}}}
    assert admin.delete(f"/api/vlab/admin/jtag-gateways/{g['id']}/passthrough/usb1").status_code == 200
    assert mgr.update_vm_config.call_args[0] == ('pve2', 700, 'qemu', {'delete': 'usb1'})
    assert admin.delete(f"/api/vlab/admin/jtag-gateways/{g['id']}/passthrough/usb9").status_code == 404   # not ours
    assert [p['slot'] for p in catalog.get_jtag_gateway(g['id'])['passthrough']] == ['hostpci0']


def test_cables_are_discovered_and_mapped_to_boards(gw, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    (api, mgr, admin, alice, bob, viewer), g, states, up = gw
    monkeypatch.setattr(nxt, '_agent_run', lambda m, n, v, cmd, **k: (0, LISTING, '', ''))
    b = admin.post('/api/vlab/admin/boards', json={'name': 'ZCU102 #3', 'cluster_id': CID, 'target': 'network', 'gateway_id': g['id'],
                                                    'cable_serial': '210251A08870'}).get_json()['board']
    r = admin.post(f"/api/vlab/admin/jtag-gateways/{g['id']}/discover")
    assert r.status_code == 200, r.get_json()
    cables = r.get_json()['gateway']['cables']
    assert cables[0]['serial'] == '210251A08870' and cables[0]['board'] == 'ZCU102 #3' and cables[1]['board'] is None
    monkeypatch.setattr(nxt, '_agent_run', lambda m, n, v, cmd, **k: (None, '', '', 'guest agent is not running'))
    assert admin.post(f"/api/vlab/admin/jtag-gateways/{g['id']}/discover").status_code == 502
    assert admin.delete(f"/api/vlab/admin/jtag-gateways/{g['id']}").status_code == 409                   # a board uses it
    assert admin.delete(f"/api/vlab/admin/boards/{b['id']}").status_code == 200
    assert admin.delete(f"/api/vlab/admin/jtag-gateways/{g['id']}").status_code == 200


def test_one_cable_one_board_and_the_connection(gw):
    (api, mgr, admin, alice, bob, viewer), g, states, up = gw
    base = {'cluster_id': CID, 'target': 'network', 'gateway_id': g['id']}
    assert admin.post('/api/vlab/admin/boards', json=dict(base, name='no serial')).status_code == 400    # hw_server needs the cable
    assert admin.post('/api/vlab/admin/boards', json=dict(base, name='x', cable_serial='a b')).status_code == 400
    assert admin.post('/api/vlab/admin/boards', json=dict(base, name='x', cable_serial='S1', gateway_id='jgw_nope')).status_code == 404
    b1 = admin.post('/api/vlab/admin/boards', json=dict(base, name='ZCU102 #1', cable_serial='210251A08870', uart_port=7001,
                                                         power={'driver': 'pdu', 'outlet': 3})).get_json()['board']
    assert (b1['host'], b1['port'], b1['node'], b1['usb']) == ('', None, '', '')
    r = admin.post('/api/vlab/admin/boards', json=dict(base, name='ZCU102 dup', cable_serial='210251A08870'))
    assert r.status_code == 400 and 'one cable, one board' in r.get_json()['error']
    assert admin.post('/api/vlab/admin/boards', json=dict(base, name='uart dup', cable_serial='S2', uart_port=7001)).status_code == 400
    assert admin.put(f"/api/vlab/admin/boards/{b1['id']}", json=dict(base, name='ZCU102 #1', cable_serial='210251A08870', uart_port=7001)).status_code == 200
    x1 = admin.post('/api/vlab/admin/boards', json=dict(base, name='KV260 XVC', protocol='xvc', port=2600)).get_json()['board']
    assert admin.post('/api/vlab/admin/boards', json=dict(base, name='KV260 b', protocol='xvc', port=2600)).status_code == 400
    q = admin.post('/api/vlab/admin/boards', json=dict(base, name='Agilex', protocol='quartus', cable_serial='USB-1')).get_json()['board']
    assert admin.post('/api/vlab/admin/boards', json=dict(base, name='bad power', cable_serial='S3', power={'x': 1})).status_code == 400

    pool = store.create_pool('보드 실습', 'dedicated', CID)
    desk = store.add_desktop(pool, 'pve1', 300, 'lab-win11-01')
    store.set_assignment(desk['id'], 'alice')
    calls = mgr.update_vm_config.call_count
    r = admin.post(f"/api/vlab/admin/boards/{b1['id']}/attach", json={'desktop_id': desk['id']})
    assert r.status_code == 200, r.get_json()
    c = r.get_json()['connection']
    assert c['endpoint'] == 'jtag-gw-01.lab:3121' and c['cable_serial'] == '210251A08870' and c['uart'] == 'jtag-gw-01.lab:7001'
    assert c['tcl'] == ['connect_hw_server -url jtag-gw-01.lab:3121', 'open_hw_target [lindex [get_hw_targets */210251A08870] 0]']
    assert mgr.update_vm_config.call_count == calls                                                     # the desktop VM is not touched
    by = {v['name']: v for v in admin.get('/api/vlab/admin/boards').get_json()['boards']}
    assert by['KV260 XVC']['connection']['endpoint'] == 'jtag-gw-01.lab:2600'
    assert by['Agilex']['connection']['endpoint'] == 'jtag-gw-01.lab:1309'
    assert by['ZCU102 #1']['gateway'] == {'id': g['id'], 'name': 'jtag-gw-01', 'state': 'unknown'} and by['ZCU102 #1']['available']
    mine = alice.get('/api/vlab/me/boards').get_json()['boards']
    assert mine[0]['connection']['cable_serial'] == '210251A08870' and mine[0]['gateway']['name'] == 'jtag-gw-01'
    # the same cable registered on a second record by hand still cannot go to two people
    catalog.save_board(None, 'twin', CID, '', '', '', '', 'network', '', None, 'hw_server', '', g['id'], '210251A08870')
    twin = next(b for b in catalog.list_boards() if b['name'] == 'twin')
    r = admin.post(f"/api/vlab/admin/boards/{twin['id']}/attach", json={'desktop_id': desk['id']})
    assert r.status_code == 409 and 'lent already' in r.get_json()['error']
    assert admin.post(f"/api/vlab/admin/boards/{q['id']}/power", json={'action': 'on'}).status_code == 501
    assert admin.post(f"/api/vlab/admin/boards/{q['id']}/power", json={'action': 'boom'}).status_code == 400
    assert x1


def test_a_down_gateway_makes_its_boards_unavailable(gw):
    import pegaprox.api.vlab_next as nxt
    (api, mgr, admin, alice, bob, viewer), g, states, up = gw
    base = {'cluster_id': CID, 'target': 'network', 'gateway_id': g['id']}
    b = admin.post('/api/vlab/admin/boards', json=dict(base, name='ZCU102 #1', cable_serial='C1')).get_json()['board']
    admin.post('/api/vlab/admin/boards', json=dict(base, name='Agilex', protocol='quartus', cable_serial='Q1'))
    pool = store.create_pool('보드 실습', 'dedicated', CID)
    desk = store.add_desktop(pool, 'pve1', 300, 'lab-win11-01')
    assert nxt.gateway_tick(force=True) == 1
    gv = admin.get('/api/vlab/admin/jtag-gateways').get_json()['gateways'][0]
    assert gv['state'] == 'up' and [p['port'] for p in gv['last_detail']['ports']] == [3121, 1309]
    states[700]['status'] = 'stopped'
    assert nxt.gateway_tick() == 0                                                      # not before 2 minutes
    r = admin.post(f"/api/vlab/admin/jtag-gateways/{g['id']}/check")
    assert r.get_json()['gateway']['state'] == 'down' and r.get_json()['gateway']['last_detail']['vm'] == 'stopped'
    listed = admin.get('/api/vlab/admin/boards').get_json()['boards']
    assert all(not v['available'] and v['gateway']['state'] == 'down' for v in listed)
    r = admin.post(f"/api/vlab/admin/boards/{b['id']}/attach", json={'desktop_id': desk['id']})
    assert r.status_code == 409 and 'is down' in r.get_json()['error']
    states[700]['status'] = 'running'
    up['ok'] = False
    nxt.gateway_tick(force=True)
    assert catalog.get_jtag_gateway(g['id'])['last_ok'] == 0 and catalog.get_jtag_gateway(g['id'])['alerted_at']
    up['ok'] = True
    nxt.gateway_tick(force=True)
    assert catalog.get_jtag_gateway(g['id'])['alerted_at'] is None
    assert admin.post(f"/api/vlab/admin/boards/{b['id']}/attach", json={'desktop_id': desk['id']}).status_code == 200
