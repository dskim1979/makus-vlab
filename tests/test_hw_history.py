# Hardware (BMC) health history — pegaprox/core/hw_history.py
#
# The 5-min metrics collector calls record() with the compact per-node hardware
# summary; only state CHANGES become events (new / escalated / recovered). The
# Korean operations report reads report_hardware() for a period. Uses the per-test
# throwaway DB from tests/conftest.py.

import pytest

H = 3_600_000  # 1 hour in ms
D = 24 * H


@pytest.fixture
def hw(db):
    import pegaprox.core.hw_history as m
    m._ensured = False  # fresh tables in this test's DB
    return m


def _s(health='ok', bad=(), available=True, source='inband'):
    return {'available': available, 'health': health, 'bad': list(bad), 'source': source}


def _events(hw, cluster='c1', node='n1'):
    return [dict(r) for r in hw._db().query(
        'SELECT ts, kind, severity, item FROM hw_events WHERE cluster_id = ? AND node = ? ORDER BY id', (cluster, node))]


def test_only_changes_are_recorded(hw):
    hw.record('c1', 'n1', _s(), 0)
    hw.record('c1', 'n1', _s(), 5)
    assert _events(hw) == []                                   # healthy, unchanged → nothing
    hw.record('c1', 'n1', _s('warning', ['Fan1']), 10)
    hw.record('c1', 'n1', _s('warning', ['Fan1']), 15)          # same state → no duplicate
    hw.record('c1', 'n1', _s('critical', ['Fan1', 'PSU2']), 20)
    hw.record('c1', 'n1', _s('critical', ['PSU2']), 30)
    hw.record('c1', 'n1', _s('ok'), 40)
    ev = [(e['ts'], e['kind'], e['severity'], e['item']) for e in _events(hw)]
    assert ev == [
        (10, 'new', 'warning', 'Fan1'),
        (20, 'new', 'critical', 'PSU2'),
        (20, 'escalated', 'critical', 'Fan1'),
        (30, 'recovered', 'critical', 'Fan1'),
        (40, 'recovered', 'critical', 'PSU2'),
    ]


def test_unavailable_reads_do_not_flap(hw):
    hw.record('c1', 'n1', _s('warning', ['SEL: Memory']), 0)
    hw.record('c1', 'n1', _s(available=False), 10)             # SSH/BMC hiccup → no "recovered"
    hw.record('c1', 'n1', None, 20)
    hw.record('c1', 'n1', _s('warning', ['SEL: Memory']), 30)
    assert [e['kind'] for e in _events(hw)] == ['new']


def test_rollup_without_items(hw):
    hw.record('c1', 'n1', _s('warning', []), 0)
    assert _events(hw)[0]['item'] == hw._ROLLUP
    assert hw.item_text(hw._ROLLUP)['ko'] == 'BMC 종합 상태 이상'
    assert hw.item_text('SEL: PSU')['ko'] == 'BMC 이벤트 로그: PSU'
    assert hw.item_text('chassis intrusion')['en'] == 'Chassis intrusion'
    assert hw.item_text('CPU1 Temp')['ko'] == '센서 이상: CPU1 Temp'


def test_incidents_in_period_rules(hw):
    ev = [
        {'ts': 1 * D, 'kind': 'new', 'severity': 'warning', 'item': 'A'},        # before period, ongoing
        {'ts': 3 * D, 'kind': 'new', 'severity': 'warning', 'item': 'B'},        # in period, recovered in period
        {'ts': 4 * D, 'kind': 'recovered', 'severity': 'warning', 'item': 'B'},
        {'ts': 5 * D, 'kind': 'new', 'severity': 'warning', 'item': 'B'},        # recurs after recovery → a separate incident
        {'ts': 5.5 * D, 'kind': 'new', 'severity': 'warning', 'item': 'B'},      # repeated while still open → count 2
        {'ts': 6 * D, 'kind': 'escalated', 'severity': 'critical', 'item': 'A'},
        {'ts': 12 * D, 'kind': 'recovered', 'severity': 'critical', 'item': 'A'},  # recovered after the period
        {'ts': 0.5 * D, 'kind': 'new', 'severity': 'warning', 'item': 'Z'},      # before and closed before → absent
        {'ts': 0.8 * D, 'kind': 'recovered', 'severity': 'warning', 'item': 'Z'},
    ]
    lst = hw.incidents_in_period(ev, 2 * D, 10 * D)
    assert sorted(i['key'] for i in lst) == ['A', 'B', 'B']
    a = next(i for i in lst if i['key'] == 'A')
    assert a['carried'] and a['severity'] == 'critical' and a['recoveredAt'] == 12 * D and a['at'] == 1 * D
    b1, b2 = [i for i in lst if i['key'] == 'B']
    assert (b1['at'], b1['recoveredAt'], b1['count']) == (3 * D, 4 * D, 1)
    assert (b2['at'], b2['recoveredAt'], b2['count'], b2['carried']) == (5 * D, None, 2, False)
    assert b2['text']['ko'] == '센서 이상: B'


def test_report_hardware_shape_and_scope(hw):
    hw.record('c1', 'n1', _s('ok'), 1 * D)
    hw.record('c1', 'n1', _s('critical', ['PSU2']), 3 * D)
    hw.record('c1', 'n2', _s('ok'), 1 * D)
    hw.record('c2', 'x1', _s('critical', ['Fan']), 1 * D)          # other cluster — not visible
    # past period
    past = hw.report_hardware({'c1': {'n1', 'n2'}}, 2 * D, 5 * D, now_ms=20 * D)
    assert past['live'] is False and past['covered'] is True and past['coveredFrom'] == 1 * D
    names = [s['name'] for s in past['servers']]
    assert names == ['n1', 'n2']
    n1 = past['servers'][0]
    assert n1['alarms'] == [] and n1['incidents'][0]['key'] == 'PSU2' and n1['incidents'][0]['severity'] == 'critical'
    # period containing "now" → current alarms too
    cur = hw.report_hardware({'c1': {'n1'}}, 2 * D, 30 * D, now_ms=20 * D)
    assert cur['live'] is True and cur['servers'][0]['alarms'][0]['since'] == 3 * D
    # a period before monitoring started → not covered
    early = hw.report_hardware({'c1': {'n1'}}, 0, 0.5 * D, now_ms=20 * D)
    assert early['covered'] is False
    # nothing recorded for these nodes → no hardware section
    assert hw.report_hardware({'c9': {'z'}}, 0, D) is None
    assert hw.report_hardware({}, 0, D) is None
