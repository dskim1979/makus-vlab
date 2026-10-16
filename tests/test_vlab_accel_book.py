"""MOAVI Desk card / board bookings (pegaprox/vlab/accel_bookings.py, api/vlab_accel_book.py) and the
growth forecast (pegaprox/vlab/forecast.py, api/vlab_forecast.py)."""
from datetime import date, datetime, timedelta

import pytest

from pegaprox.api import vlab_accel_book as api_ab
from pegaprox.vlab import accel_bookings as ab
from pegaprox.vlab import forecast as fc
from pegaprox.vlab import store
from test_vlab_research import CID, env  # noqa: F401 - the shared fixture

MAPPING = {'id': 'a100', 'description': 'NVIDIA A100', 'devices': [{'id': '10de:20b5', 'node': 'pve1', 'path': '0000:41:00.0'},
                                                                  {'id': '10de:20b5', 'node': 'pve1', 'path': '0000:42:00.0'}]}


def T(h, m=0, days=1):
    d = (datetime.now() + timedelta(days=days)).replace(hour=h, minute=m, second=0, microsecond=0)
    return ab.fmt(d)


# --- pure ------------------------------------------------------------------------------------

def test_conflicts_count_cards_loans_and_the_desktop():
    at = datetime(2026, 10, 20, 8, 0)
    s, e = datetime(2026, 10, 20, 9, 0), datetime(2026, 10, 20, 12, 0)
    cand = {'kind': 'card', 'cluster_id': 'c', 'resource': 'a100', 'desktop_id': 'd1', 'start': s, 'end': e}
    o1 = {'id': 'b1', 'kind': 'card', 'cluster_id': 'c', 'resource': 'a100', 'desktop_id': 'd2',
          'start_at': '2026-10-20T10:00', 'end_at': '2026-10-20T11:00'}
    assert ab.conflicts(cand, [o1], 2, [], at) == []
    assert [c['why'] for c in ab.conflicts(cand, [o1], 2, [('vm9', None)], at)] == ['TAKEN']          # a loan holds the 2nd
    assert [c['why'] for c in ab.conflicts(cand, [], 1, [('vm9', datetime(2026, 10, 20, 8, 30))], at)] == []   # its loan ends first
    assert [c['why'] for c in ab.conflicts(cand, [], 1, [('vm9', datetime(2026, 10, 20, 9, 30))], at)] == ['ON_LOAN']
    mine = dict(o1, id='b2', resource='other', desktop_id='d1')
    assert [c['why'] for c in ab.conflicts(cand, [mine], 2, [], at)] == ['DESKTOP_BUSY']
    assert ab.check_times(s, e, ab.DEFAULTS, at) is None
    assert ab.check_times(e, s, ab.DEFAULTS, at) == 'BAD_TIME'
    assert ab.check_times(s, s + timedelta(hours=100), ab.DEFAULTS, at) == 'TOO_LONG'
    assert ab.check_times(s + timedelta(days=40), s + timedelta(days=40, hours=1), ab.DEFAULTS, at) == 'TOO_FAR'


# --- the routes and the loop -----------------------------------------------------------------

@pytest.fixture
def cards(env, monkeypatch):
    api, mgr, agent, admin, alice, bob, viewer = env
    from pegaprox.vlab import accel
    monkeypatch.setattr(accel, 'pci_mappings', lambda m: [dict(MAPPING)])
    pool = store.create_pool('AI 연구실', 'dedicated', CID)
    da = store.add_desktop(pool, 'pve1', 710, 'ws-alice')
    store.set_assignment(da['id'], 'alice')
    db_ = store.add_desktop(pool, 'pve1', 711, 'ws-bob')
    store.set_assignment(db_['id'], 'bob')
    return env, da, db_


def _book(c, desk, start, end, resource='a100', kind='card'):
    return c.post('/api/vlab/me/accel-bookings', json={'kind': kind, 'cluster_id': CID, 'resource': resource,
                                                       'desktop_id': desk['id'], 'start_at': start, 'end_at': end, 'purpose': '학습'})


def test_book_cards_up_to_what_there_is(cards):
    (api, mgr, agent, admin, alice, bob, viewer), da, db_ = cards
    opt = alice.get('/api/vlab/me/accel-bookings/options').get_json()
    assert opt['allowed'] and opt['cards'][0]['count'] == 2 and opt['cards'][0]['kind'] == 'gpu'
    assert [d['name'] for d in opt['desktops']] == ['ws-alice']
    assert _book(alice, db_, T(9), T(12)).status_code == 404                       # not her desktop
    r = _book(alice, da, T(9), T(12))
    assert r.status_code == 201 and r.get_json()['booking']['status'] == 'approved'
    assert _book(bob, db_, T(10), T(11)).status_code == 201                        # the second card
    store.add_desktop(store.get_pool(da['pool_id']), 'pve1', 712, 'ws-root')
    third = [d for d in store.list_desktops() if d['vmid'] == 712][0]
    store.set_assignment(third['id'], 'root')
    r = _book(admin, third, T(10, 30), T(11, 30))
    assert r.status_code == 409 and {c['why'] for c in r.get_json()['conflicts']} == {'TAKEN'}
    assert _book(admin, third, T(12), T(13)).status_code == 201                    # after them: free
    assert _book(alice, da, T(11), T(13)).status_code == 409                       # her desktop has one then
    cal = bob.get('/api/vlab/accel-bookings/calendar').get_json()['bookings']
    others = [b for b in cal if b.get('username') != 'bob']
    assert others and all('username' not in b and 'purpose' not in b for b in others)   # others' names are not shown


def test_approval_and_the_minute_loop_lends_and_gives_back(cards, monkeypatch):
    (api, mgr, agent, admin, alice, bob, viewer), da, db_ = cards
    assert admin.put('/api/vlab/admin/accel-booking-settings', json={'approval': True}).status_code == 200
    assert alice.put('/api/vlab/admin/accel-booking-settings', json={'approval': False}).status_code == 403
    now = datetime.now().replace(second=0, microsecond=0)
    r = _book(alice, da, ab.fmt(now + timedelta(minutes=3)), ab.fmt(now + timedelta(hours=2)))
    bid = r.get_json()['booking']['id']
    assert r.get_json()['booking']['status'] == 'pending'
    assert admin.get('/api/vlab/admin/accel-bookings').get_json()['pending'][0]['id'] == bid
    assert alice.post(f'/api/vlab/admin/accel-bookings/{bid}/approve').status_code == 403
    assert admin.post(f'/api/vlab/admin/accel-bookings/{bid}/approve').status_code == 200
    lent, returned = [], []
    monkeypatch.setattr(api_ab.core, 'lend_card', lambda desk, mapping, ends, name, by, ip=None: (
        lent.append((desk['name'], mapping, ends)) or ({'lease': {'id': 'lease-1'}, 'needs_restart': True, 'warnings': []}, None)))
    monkeypatch.setattr(store, 'get_lease', lambda lid: {'id': lid, 'state': 'active', 'cluster_id': CID, 'vmid': 710,
                                                         'resource_name': 'NVIDIA A100', 'username': 'alice'})
    monkeypatch.setattr(api_ab.core, 'return_lease', lambda lease, by='system': returned.append(lease['id']))
    assert api_ab.booking_tick(now) == (1, 0)
    assert lent and lent[0][:2] == ('ws-alice', 'a100') and ab.get(bid)['lease_id'] == 'lease-1'
    assert api_ab.booking_tick(now) == (0, 0)                                      # once
    assert alice.post(f'/api/vlab/me/accel-bookings/{bid}/cancel').status_code == 200
    assert returned == ['lease-1'] and ab.get(bid)['finished_at']                  # cancelled while it ran: back now


def test_routes_need_the_right_permission(cards):
    (api, mgr, agent, admin, alice, bob, viewer), da, db_ = cards
    assert viewer.get('/api/vlab/me/accel-bookings/options').status_code == 403
    assert alice.get('/api/vlab/admin/accel-bookings').status_code == 403
    assert admin.put('/api/vlab/admin/accel-booking-settings', json={'max_hours': 0}).status_code == 400
    assert admin.put('/api/vlab/admin/accel-booking-settings', json={'enabled': False}).status_code == 200
    assert _book(alice, da, T(9), T(10)).status_code == 403


# --- the forecast ----------------------------------------------------------------------------

def test_the_line_and_when_it_crosses():
    assert fc.fit([(0, 1.0)]) is None
    slope, b, r2 = fc.fit([(0, 10), (1, 12), (2, 14)])
    assert round(slope, 6) == 2 and round(b, 6) == 10 and r2 == 1.0
    today = date(2026, 10, 17)
    rows = [((today - timedelta(days=29 - i)).isoformat(), {'cpu_avg': 50 + i}) for i in range(30)]
    p = fc.project(rows, 'cpu_avg', 80, today)
    assert p['enough'] and p['current'] == 79 and p['eta_days'] == 1 and p['confidence'] == 'high'
    assert fc.level(p) == 'soon'
    flat = [((today - timedelta(days=i)).isoformat(), {'cpu_avg': 40}) for i in range(20)]
    assert fc.project(flat, 'cpu_avg', 80, today)['eta_days'] is None and fc.level(fc.project(flat, 'cpu_avg', 80, today)) == 'ok'
    assert fc.project(rows[:5], 'cpu_avg', 80, today)['enough'] is False


def test_forecast_route(env):
    api, mgr, agent, admin, alice, bob, viewer = env
    today = date.today()
    for i in range(40):
        fc.save_day((today - timedelta(days=39 - i)).isoformat(), CID, {'storage_pct': 40 + i, 'cpu_avg': 30})
    body = admin.get(f'/api/vlab/admin/clusters/{CID}/forecast?days=90').get_json()
    st = next(m for m in body['metrics'] if m['key'] == 'storage_pct')
    assert st['level'] == 'soon' and st['eta_days'] <= 7 and st['advice']          # 79 % rising 1 a day, 85 % is near
    assert body['metrics'][0]['level'] in ('now', 'soon')
    assert admin.get(f'/api/vlab/admin/clusters/{CID}/forecast?days=7').status_code == 400
    assert alice.get(f'/api/vlab/admin/clusters/{CID}/forecast').status_code == 403
