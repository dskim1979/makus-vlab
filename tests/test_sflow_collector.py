"""sFlow collector: parsing, conversations, storage, agent filter and the flows API."""
import struct
from datetime import datetime

import pytest

import pegaprox.background.sflow_collector as sc
from pegaprox.utils.auth import create_api_token


def _eth_ipv4_tcp(src, dst, sport, dport, vlan=None):
    eth = b'\x00' * 12
    if vlan is not None:
        eth += struct.pack('>HH', 0x8100, vlan)
    eth += struct.pack('>H', 0x0800)
    ip = bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0]) + bytes(map(int, src.split('.'))) + bytes(map(int, dst.split('.')))
    tcp = struct.pack('>HH', sport, dport) + b'\x00' * 16
    return eth + ip + tcp


def _datagram(headers, rate=100, frame_len=1500, agent='10.0.0.1'):
    samples = b''
    for h in headers:
        hpad = h + b'\x00' * ((4 - len(h) % 4) % 4)
        rec = struct.pack('>IIII', 1, frame_len, 4, len(h)) + hpad
        body = struct.pack('>IIIIIII', 1, 7, rate, 0, 0, 1, 2) + struct.pack('>I', 1) + struct.pack('>II', 1, len(rec)) + rec
        samples += struct.pack('>II', 1, len(body)) + body
    counter = struct.pack('>II', 2, 8) + b'\x00' * 8          # a counter sample is skipped
    head = struct.pack('>II', 5, 1) + bytes(map(int, agent.split('.'))) + struct.pack('>IIII', 0, 1, 1000, len(headers) + 1)
    return head + counter + samples


@pytest.fixture(autouse=True)
def fresh(tmp_path, monkeypatch):
    monkeypatch.setattr(sc, 'DB_FILE', str(tmp_path / 'flows.db'))
    sc._minutes.clear()
    sc._pending_hours.clear()
    monkeypatch.setattr(sc, '_hour_key', None)
    monkeypatch.setattr(sc, '_hour', {})
    yield


def test_a_datagram_yields_scaled_flows_through_vlan_tags():
    agent, flows = sc.parse_datagram(_datagram([_eth_ipv4_tcp('10.1.1.5', '10.1.1.9', 51000, 443, vlan=20)]))
    assert agent == '10.0.0.1'
    assert flows == [('10.1.1.5', '10.1.1.9', 6, 51000, 443, 150000, 100)]


def test_both_directions_land_on_one_conversation():
    assert sc.conversation('10.1.1.5', '10.1.1.9', 6, 51000, 443) == ('10.1.1.5', '10.1.1.9', 6, 443)
    assert sc.conversation('10.1.1.9', '10.1.1.5', 6, 443, 51000) == ('10.1.1.5', '10.1.1.9', 6, 443)
    assert sc.conversation('10.1.1.5', '10.1.1.9', 1, None, None) == ('10.1.1.5', '10.1.1.9', 1, 0)


def test_garbage_is_refused_not_crashing():
    for bad in (b'', b'\x00\x00\x00\x04' + b'\x00' * 20, _datagram([b'\x00' * 10])[:30]):
        with pytest.raises(ValueError):
            sc.parse_datagram(bad)
    # a header too short for IP is skipped, the datagram still parses
    assert sc.parse_datagram(_datagram([b'\x00' * 10]))[1] == []


def test_recent_and_hourly_history_add_up(monkeypatch):
    now = datetime(2026, 10, 13, 10, 15)
    flows = [('10.1.1.5', '10.1.1.9', 6, 51000, 443, 1000, 1), ('10.1.1.9', '10.1.1.5', 6, 443, 51000, 500, 1)]
    sc.ingest('10.0.0.1', flows, now=now)
    monkeypatch.setattr(sc, 'datetime', type('D', (), {'now': staticmethod(lambda: now), 'strptime': datetime.strptime}))
    rows = sc.recent(60)
    assert rows == [{'client': '10.1.1.5', 'server': '10.1.1.9', 'proto': 6, 'port': 443, 'bytes': 1500, 'packets': 2}]
    monkeypatch.setattr(sc, 'settings', lambda: dict(sc.DEFAULTS))
    hist = sc.history(24)
    assert hist[0]['bytes'] == 1500 and hist[0]['port'] == 443


def test_buckets_are_bounded(monkeypatch):
    monkeypatch.setattr(sc, 'MAX_KEYS_PER_MINUTE', 3)
    flows = [(f'10.0.0.{i}', '10.9.9.9', 6, 50000, 22, 10, 1) for i in range(10)]
    sc.ingest('10.0.0.1', flows)
    assert len(next(iter(sc._minutes.values()))) == 3


def test_agents_outside_the_allow_list_are_refused():
    cfg = {'allowed_agents': ['192.168.10.0/24']}
    assert sc.agent_allowed('192.168.10.7', cfg)
    assert not sc.agent_allowed('10.0.0.1', cfg)


def test_flows_api_needs_admin_settings_and_validates(api, seed, monkeypatch):
    monkeypatch.setattr(sc, 'start_sflow_collector', lambda: False)
    monkeypatch.setattr(sc, 'stop_sflow_collector', lambda: None)
    seed.user('root', role='admin')
    h = {'Authorization': f"Bearer {create_api_token('root', 'front', role='admin')['token']}"}
    viewer = {'Authorization': f"Bearer {create_api_token('root', 'ro', role='viewer')['token']}"}
    c = api.anon()
    assert c.get('/api/flows/status', headers=viewer).status_code == 403
    assert c.get('/api/flows/status', headers=h).get_json()['settings']['enabled'] is False
    assert c.put('/api/flows/config', headers=h, json={'port': 80}).status_code == 400
    assert c.put('/api/flows/config', headers=h, json={'allowed_agents': ['not an ip']}).status_code == 400
    r = c.put('/api/flows/config', headers=h, json={'enabled': True, 'allowed_agents': ['10.0.0.0/24'], 'port': 6343})
    assert r.status_code == 200 and r.get_json()['settings']['allowed_agents'] == ['10.0.0.0/24']
    sc.ingest('10.0.0.1', [('10.1.1.5', '10.1.1.9', 6, 51000, 443, 1000, 1)])
    top = c.get('/api/flows/top?minutes=60', headers=h).get_json()
    assert top['rows'][0]['port'] == 443 and top['rows'][0]['proto_name'] == 'tcp'
    assert 'hsflowd_conf' in c.get('/api/flows/setup?collector=10.0.0.100', headers=h).get_json()
