"""The protocol benchmark's analyzer (tools/bench/analyze/benchstat.py) reads a pcap the way
the README says it does: a generated sample pcap and pcapng with known bytes per class come
back as the same Mbps, split by workload marker, with the RDP counters averaged in."""
import importlib.util
import os

_PATH = os.path.join(os.path.dirname(__file__), '..', 'tools', 'bench', 'analyze', 'benchstat.py')


def _load():
    spec = importlib.util.spec_from_file_location('benchstat', _PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_selftest_parses_the_sample_captures(capsys):
    assert _load().selftest() == 0, capsys.readouterr().out


def test_the_server_port_decides_the_class_and_direction():
    b = _load()
    down = b.decode(1, b._eth_frame('10.0.0.10', '10.0.0.50', 'udp', 3389, 51000, 100))
    up = b.decode(1, b._eth_frame('10.0.0.50', '10.0.0.10', 'tcp', 51001, 3128, 100))
    assert b.classify(down) == ('rdp-udp', 'down')
    assert b.classify(up) == ('spice', 'up')
