"""MOAVI Desk LAB reservations (포털 > 예약, LAB > 예약): a whole LAB, N seats or N desktops,
once or weekly; what a booking collides with (classes, other bookings, seats, the pool's
size), approval, notices, the minute loop that prepares and cleans up, the hand-out of
desktops to participants only, the kiosk, and the booked-vs-used report.
pegaprox/vlab/reservations.py, pegaprox/api/vlab_reserve.py."""
from datetime import datetime, timedelta, timezone

import pytest

from pegaprox.vlab import reservations as rsv
from pegaprox.vlab import store

CID = 'cluster_1'
RES = [{'vmid': 400 + i, 'node': 'pve1', 'name': f'class-{i:02d}', 'type': 'qemu', 'status': 'stopped'} for i in range(4)]
NOW = datetime(2026, 10, 19, 8, 0)          # a Monday


# --- the rules, without the API -------------------------------------------------------------

def test_a_request_is_checked_and_a_series_expands_by_week():
    ok, occ, e = rsv.validate({'kind': 'seats', 'quantity': 5, 'start_at': '2026-10-19T10:00', 'end_at': '2026-10-19T12:00',
                               'repeat': {'weekdays': [0, 2], 'weeks': 3}, 'purpose': 'FPGA 실습',
                               'participants': [{'subject_type': 'group', 'subject_id': 'EE-301'}]})
    assert e is None and ok['quantity'] == 5 and ok['participants'][0]['subject_id'] == 'EE-301'
    assert [rsv.fmt(a) for a, _ in occ] == ['2026-10-19T10:00', '2026-10-21T10:00', '2026-10-26T10:00',
                                           '2026-10-28T10:00', '2026-11-02T10:00', '2026-11-04T10:00']
    assert all((b - a) == timedelta(hours=2) for a, b in occ)
    bad = lambda **kw: rsv.validate({'kind': 'lab', 'start_at': '2026-10-19T10:00', 'end_at': '2026-10-19T12:00', **kw})[2]
    assert bad(kind='room') and bad(end_at='2026-10-19T09:00') and bad(end_at='2026-10-20T11:00')
    assert bad(start_at='tomorrow') and bad(repeat={'weeks': 99}) and bad(participants=[{'subject_type': 'x', 'subject_id': 'y'}])
    assert bad(kind='seats', quantity=0)
    assert bad(end_at='2026-10-20T00:00') is None            # up to midnight is the same day


def test_the_lab_rules_say_what_they_refuse():
    s = dict(rsv.DEFAULTS, open_from='09:00', open_to='18:00', weekdays=[0, 1, 2, 3, 4], max_minutes=120, max_days_ahead=14)
    at = NOW
    day = lambda d, h0, h1: (datetime(2026, 10, d, h0), datetime(2026, 10, d, h1))
    assert rsv.rule_errors(s, *day(19, 10, 12), at) == []
    assert rsv.rule_errors(s, *day(19, 8, 10), at) == ['HOURS']
    assert rsv.rule_errors(s, *day(19, 10, 13), at) == ['TOO_LONG']
    assert rsv.rule_errors(s, *day(24, 10, 11), at) == ['WEEKDAY']             # Saturday
    assert 'TOO_FAR' in rsv.rule_errors(s, datetime(2026, 11, 20, 10), datetime(2026, 11, 20, 11), at)
    assert rsv.rule_errors(s, datetime(2026, 10, 18, 10), datetime(2026, 10, 18, 11), at)[0] == 'PAST'
    assert rsv.rule_errors(s, *day(24, 10, 15), at, privileged=True) == []       # an approver books past the rules
    assert rsv.rule_errors(dict(s, enabled=False), *day(19, 10, 12), at, privileged=True) == ['CLOSED']
    clean, e = rsv.clean_settings({'open_from': '18:00', 'open_to': '09:00'})
    assert e
    clean, e = rsv.clean_settings({'approval': True, 'max_minutes': 90, 'roles': ['professor'], 'open_to': '24:00'})
    assert e is None and clean['approval'] and clean['max_minutes'] == 90 and clean['roles'] == ['professor']


def test_conflicts_name_the_class_the_booking_and_the_limits():
    sched = {'id': 'sch1', 'lab_id': 'labA', 'pool_id': 'p1', 'title': '회로이론', 'weekdays': '0', 'start_time': '13:00',
             'end_time': '15:00', 'enabled': 1}
    lab = {'id': 'labA', 'seats': 10}
    a, b = datetime(2026, 10, 19, 14), datetime(2026, 10, 19, 16)
    seats = {'kind': 'seats', 'lab_id': 'labA', 'pool_id': 'p2', 'quantity': 4}
    (c,) = rsv.conflicts(seats, a, b, [sched], [], lab, 10)
    assert (c['type'], c['id'], c['why']) == ('schedule', 'sch1', 'lab_schedule')
    # another LAB's class on the same pool counts too
    (c,) = rsv.conflicts({'kind': 'desktops', 'lab_id': None, 'pool_id': 'p1', 'quantity': 1}, a, b, [sched], [], None, 4)
    assert c['why'] == 'pool_schedule'
    other = lambda i, kind, q, s='2026-10-19T09:00', e='2026-10-19T11:00', pool='p2': {
        'id': i, 'kind': kind, 'lab_id': 'labA', 'pool_id': pool, 'quantity': q, 'start_at': s, 'end_at': e,
        'purpose': '', 'requester': 'x', 'status': 'approved'}
    a, b = datetime(2026, 10, 19, 10), datetime(2026, 10, 19, 12)
    assert rsv.conflicts(seats, a, b, [], [other('r1', 'seats', 6)], lab, 20) == []                 # 6 + 4 seats of 10
    (c,) = rsv.conflicts(seats, a, b, [], [other('r1', 'seats', 7)], lab, 20)
    assert (c['id'], c['why'], c['limit']) == ('r1', 'seats', 10)
    (c,) = rsv.conflicts(seats, a, b, [], [other('r1', 'lab', 0)], lab, 20)
    assert c['why'] == 'lab_booked'
    (c,) = rsv.conflicts({**seats, 'kind': 'lab'}, a, b, [], [other('r1', 'seats', 1)], lab, 20)
    assert c['why'] == 'lab_booked'
    # seats one after the other do not add up
    assert rsv.conflicts(seats, a, b, [], [other('r1', 'seats', 6), other('r2', 'seats', 6, '2026-10-19T11:00', '2026-10-19T12:00')],
                         lab, 20) == []
    # the pool's size: 3 desktops booked elsewhere of 4, one more fits, two do not
    pool_q = lambda q: {'kind': 'desktops', 'lab_id': None, 'pool_id': 'p3', 'quantity': q}
    taken = [dict(other('r9', 'desktops', 3, pool='p3'), lab_id=None)]
    assert rsv.conflicts(pool_q(1), a, b, [], taken, None, 4) == []
    assert rsv.conflicts(pool_q(2), a, b, [], taken, None, 4)[0]['why'] == 'pool_full'
    assert rsv.conflicts(pool_q(5), a, b, [], [], None, 4)[0]['why'] == 'pool_size'


def test_what_the_minute_loop_does_with_a_booking():
    r = {'status': 'approved', 'start_at': '2026-10-19T10:00', 'end_at': '2026-10-19T12:00', 'prepare_min': 15,
         'prepared_at': None, 'finished_at': None, 'after': 'reset'}
    assert rsv.due(r, datetime(2026, 10, 19, 9, 40)) is None
    assert rsv.due(r, datetime(2026, 10, 19, 9, 45)) == 'prepare'
    assert rsv.due({**r, 'prepared_at': 'x'}, datetime(2026, 10, 19, 11)) is None
    assert rsv.due({**r, 'prepared_at': 'x'}, datetime(2026, 10, 19, 12, 1)) == 'finish'
    assert rsv.due(r, datetime(2026, 10, 19, 12, 1)) == 'skip'                  # never prepared: only marked
    assert rsv.due({**r, 'status': 'pending'}, datetime(2026, 10, 19, 10)) is None
    assert rsv.due({**r, 'status': 'cancelled', 'prepared_at': 'x'}, datetime(2026, 10, 19, 10, 30)) == 'finish'
    assert rsv.due({**r, 'status': 'cancelled'}, datetime(2026, 10, 19, 10, 30)) is None
    assert rsv.is_participant({'requester': 'prof', 'participants': [{'subject_type': 'group', 'subject_id': 'EE-301'}]},
                              'stu', None, {'ee-301'})
    assert not rsv.is_participant({'requester': 'prof', 'participants': []}, 'stu', None, set())


# --- through the API ----------------------------------------------------------------------------

@pytest.fixture
def lab_env(api, seed, monkeypatch, db):
    import pegaprox.api.vlab as vlab_api
    mgr = api.make_fake_manager(CID, get_vm_resources=RES, vm_action={'success': True, 'data': 'UPID:pve1:1:start'})
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    prof = api.as_user(seed.user('prof', role='user'))
    stu = api.as_user(seed.user('stu', role='user'))
    other = api.as_user(seed.user('other', role='user'))
    keeper = api.as_user(seed.user('keeper', role='user', permissions=['vlab.lab.manage']))
    u = db.get_user('prof')
    u['email'] = 'prof@example.edu'
    db.save_user('prof', u)
    clock = {'now': NOW}
    monkeypatch.setattr(vlab_api, '_local_now', lambda: clock['now'])
    monkeypatch.setattr(vlab_api, '_acl_set', lambda *a: True)
    sent = {'mail': [], 'hooks': []}
    import pegaprox.utils.email as email
    import pegaprox.utils.webhooks as webhooks
    monkeypatch.setattr(email, 'send_email', lambda to, subj, body, html=None: sent['mail'].append((to, subj)) or (True, ''))
    monkeypatch.setattr(webhooks, 'send_to_channels', lambda alert, ids=None: sent['hooks'].append((alert['kind'], ids)))
    pool = admin.post('/api/vlab/admin/pools', json={'name': '실습 풀', 'type': 'classroom', 'cluster_id': CID}).get_json()['pool']
    for i in range(4):
        r = admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': 400 + i})
        assert r.status_code == 201, r.get_json()
    lab = admin.post('/api/vlab/admin/labs', json={'name': '실습실 301', 'seats': 3}).get_json()['lab']
    return {'admin': admin, 'prof': prof, 'stu': stu, 'other': other, 'keeper': keeper, 'pool': pool, 'lab': lab,
            'clock': clock, 'sent': sent, 'mgr': mgr, 'vlab': vlab_api}


def _body(e, **kw):
    return {'kind': 'seats', 'lab_id': e['lab']['id'], 'pool_id': e['pool']['id'], 'quantity': 2,
            'start_at': '2026-10-19T10:00', 'end_at': '2026-10-19T12:00', 'purpose': 'FPGA 실습', **kw}


def test_who_may_use_the_routes(lab_env, api):
    e = lab_env
    assert api.anon().get('/api/vlab/me/reservations').status_code == 401
    assert e['prof'].get('/api/vlab/admin/reservations').status_code == 403
    assert e['prof'].post('/api/vlab/admin/reservations', json=_body(e)).status_code == 403
    assert e['keeper'].get('/api/vlab/admin/reservations').status_code == 200          # LAB 담당자 (vlab.lab.manage)
    assert e['keeper'].get('/api/vlab/admin/reservation-settings').status_code == 200
    opts = e['prof'].get('/api/vlab/reservations/options').get_json()
    (lab,) = opts['labs']
    assert lab['name'] == '실습실 301' and lab['may_book'] and [p['desktops'] for p in lab['pools']] == [4]
    assert opts['approver'] is False and e['keeper'].get('/api/vlab/reservations/options').get_json()['approver'] is True


def test_a_booking_without_approval_is_taken_and_collisions_are_refused(lab_env):
    e = lab_env
    r = e['prof'].post('/api/vlab/me/reservations/check', json=_body(e))
    assert r.get_json()['ok'] is True and r.get_json()['approval'] is False
    r = e['prof'].post('/api/vlab/me/reservations', json=_body(e))
    assert r.status_code == 201, r.get_json()
    (mine,) = r.get_json()['reservations']
    assert mine['status'] == 'approved' and mine['lab'] == '실습실 301' and mine['quantity'] == 2
    # 2 of 3 seats are taken: two more do not fit, one does
    r = e['other'].post('/api/vlab/me/reservations', json=_body(e, start_at='2026-10-19T11:00', end_at='2026-10-19T13:00'))
    assert r.status_code == 409 and r.get_json()['code'] == 'CONFLICT'
    (occ,) = r.get_json()['occurrences']
    assert occ['conflicts'][0]['id'] == mine['id'] and occ['conflicts'][0]['why'] == 'seats'
    assert e['other'].post('/api/vlab/me/reservations', json=_body(e, quantity=1, start_at='2026-10-19T11:00',
                                                                    end_at='2026-10-19T13:00')).status_code == 201
    # a whole-LAB booking collides with both
    r = e['other'].post('/api/vlab/me/reservations', json=_body(e, kind='lab', start_at='2026-10-19T09:00'))
    assert r.status_code == 409 and {c['why'] for c in r.get_json()['occurrences'][0]['conflicts']} == {'lab_booked'}
    assert e['prof'].post('/api/vlab/me/reservations', json=_body(e, quantity=4)).get_json()['code'] == 'SEATS'
    # the weekly class of the room
    e['admin'].post('/api/vlab/admin/lab-schedules', json={'lab_id': e['lab']['id'], 'pool_id': e['pool']['id'], 'weekdays': [2],
                                                           'start_time': '13:00', 'end_time': '15:00', 'title': '회로이론'})
    r = e['prof'].post('/api/vlab/me/reservations/check', json=_body(e, start_at='2026-10-21T14:00', end_at='2026-10-21T16:00'))
    c = r.get_json()['occurrences'][0]['conflicts'][0]
    assert (c['type'], c['title'], c['why']) == ('schedule', '회로이론', 'lab_schedule')
    cal = e['stu'].get('/api/vlab/reservations/calendar?from=2026-10-19&to=2026-10-25').get_json()['blocks']
    assert [b['type'] for b in cal] == ['reservation', 'reservation', 'schedule']
    assert 'note' not in cal[0] and cal[0]['purpose'] == 'FPGA 실습'      # another's booking: no note or participants


def test_a_weekly_booking_names_the_weeks_that_collide(lab_env):
    e = lab_env
    e['admin'].post('/api/vlab/admin/reservations', json=_body(e, kind='lab', start_at='2026-10-26T10:00', end_at='2026-10-26T11:00',
                                                               purpose='세미나'))
    body = _body(e, repeat={'weekdays': [0], 'weeks': 3})
    r = e['prof'].post('/api/vlab/me/reservations', json=body)
    assert r.status_code == 409
    occ = r.get_json()['occurrences']
    assert [o['start'] for o in occ] == ['2026-10-19T10:00', '2026-10-26T10:00', '2026-11-02T10:00']
    assert [bool(o['conflicts']) for o in occ] == [False, True, False]
    r = e['prof'].post('/api/vlab/me/reservations', json={**body, 'skip_conflicts': True})
    assert r.status_code == 201
    made = r.get_json()['reservations']
    assert [x['start_at'][:10] for x in made] == ['2026-10-19', '2026-11-02'] and made[0]['series_id'] == made[1]['series_id']
    assert [o['start'] for o in r.get_json()['skipped']] == ['2026-10-26T10:00']
    # cancel the rest of the series
    r = e['prof'].post(f"/api/vlab/me/reservations/{made[0]['id']}/cancel", json={'scope': 'series'})
    assert [x['status'] for x in r.get_json()['reservations']] == ['cancelled', 'cancelled']
    assert e['other'].post(f"/api/vlab/me/reservations/{made[0]['id']}/cancel").status_code == 404


def test_approval_rejection_and_the_requesters_notices(lab_env):
    e = lab_env
    lab_id = e['lab']['id']
    r = e['keeper'].put(f'/api/vlab/admin/reservation-settings/{lab_id}', json={'approval': True, 'max_minutes': 180})
    assert r.status_code == 200 and r.get_json()['settings']['approval'] is True
    assert e['keeper'].put('/api/vlab/admin/reservation-settings/_global', json={'channels': ['c1']}).status_code == 200
    r = e['prof'].post('/api/vlab/me/reservations', json=_body(e, repeat={'weekdays': [0], 'weeks': 2}))
    assert r.status_code == 201 and r.get_json()['approval'] is True
    made = r.get_json()['reservations']
    assert {x['status'] for x in made} == {'pending'}
    assert e['sent']['hooks'] == [('lab_reservation_requested', ['c1'])] and e['sent']['mail'] == []
    (waiting,) = e['keeper'].get('/api/vlab/admin/reservations/pending').get_json()['pending']
    assert waiting['waiting'] == 2
    # pending ones hold their slot
    r = e['other'].post('/api/vlab/me/reservations/check', json=_body(e, quantity=2))
    assert r.get_json()['ok'] is False
    assert e['keeper'].post(f"/api/vlab/admin/reservations/{made[0]['id']}/reject", json={}).status_code == 400   # a reason
    r = e['keeper'].post(f"/api/vlab/admin/reservations/{made[0]['id']}/approve", json={'scope': 'series'})
    assert [x['status'] for x in r.get_json()['reservations']] == ['approved', 'approved']
    assert e['sent']['mail'][-1][0] == ['prof@example.edu'] and '예약 승인' in e['sent']['mail'][-1][1]
    assert e['keeper'].post(f"/api/vlab/admin/reservations/{made[0]['id']}/approve").status_code == 409
    # an approver cancels one: the requester hears of it with the reason
    r = e['keeper'].post(f"/api/vlab/admin/reservations/{made[1]['id']}/cancel", json={'reason': '시설 점검'})
    assert r.get_json()['reservations'][0]['reason'] == '시설 점검' and '예약 취소' in e['sent']['mail'][-1][1]
    # a change by the requester goes back to waiting
    r = e['prof'].put(f"/api/vlab/me/reservations/{made[0]['id']}", json={'start_at': '2026-10-19T13:00', 'end_at': '2026-10-19T14:00'})
    assert r.status_code == 200 and r.get_json()['reservation']['status'] == 'pending'
    r = e['prof'].post('/api/vlab/me/reservations', json=_body(e, start_at='2026-10-19T09:00', end_at='2026-10-19T13:00'))
    assert r.status_code == 409 and 'TOO_LONG' in r.get_json()['occurrences'][0]['rules']
    # a rejection with its reason
    r = e['keeper'].post(f"/api/vlab/admin/reservations/{made[0]['id']}/reject", json={'reason': '수업과 겹침'})
    assert r.get_json()['reservations'][0]['status'] == 'rejected' and '예약 거절' in e['sent']['mail'][-1][1]


def test_roles_and_closed_labs(lab_env):
    e = lab_env
    lab_id = e['lab']['id']
    e['admin'].put(f'/api/vlab/admin/reservation-settings/{lab_id}', json={'roles': ['admin']})
    r = e['prof'].post('/api/vlab/me/reservations', json=_body(e))
    assert r.status_code == 403 and r.get_json()['code'] == 'ROLE'
    assert e['prof'].get('/api/vlab/reservations/options').get_json()['labs'][0]['may_book'] is False
    e['admin'].put(f'/api/vlab/admin/reservation-settings/{lab_id}', json={'roles': [], 'enabled': False})
    assert e['prof'].get('/api/vlab/reservations/options').get_json()['labs'] == []
    assert e['admin'].put('/api/vlab/admin/reservation-settings/nope', json={}).status_code == 404
    assert e['admin'].put(f'/api/vlab/admin/reservation-settings/{lab_id}', json={'pool_ids': ['nope']}).status_code == 404


def test_the_minute_loop_prepares_hands_out_to_participants_and_cleans_up(lab_env, api):
    e = lab_env
    vlab = e['vlab']
    r = e['prof'].post('/api/vlab/me/reservations', json=_body(e, participants=[{'subject_type': 'user', 'subject_id': 'stu'}]))
    rid = r.get_json()['reservations'][0]['id']
    e['mgr'].vm_action.reset_mock()
    assert [x for x in vlab.lab_tick(datetime(2026, 10, 19, 9, 40))] == []
    ((got, phase, res),) = vlab.lab_tick(datetime(2026, 10, 19, 9, 50))
    assert (got, phase) == (rid, 'prepare') and len(res['done']) == 2                  # two seats: two desktops started
    assert e['mgr'].vm_action.call_count == 2
    assert vlab.lab_tick(datetime(2026, 10, 19, 9, 55)) == []
    e['clock']['now'] = datetime(2026, 10, 19, 10, 30)
    assert e['other'].post(f'/api/vlab/me/reservations/{rid}/desktop').status_code == 404      # not a participant
    d1 = e['stu'].post(f'/api/vlab/me/reservations/{rid}/desktop').get_json()['desktop']
    d2 = e['prof'].post(f'/api/vlab/me/reservations/{rid}/desktop').get_json()['desktop']
    assert d1['id'] != d2['id'] and store.get_desktop(d1['id'])['assigned_user'] == 'stu'
    assert e['stu'].post(f'/api/vlab/me/reservations/{rid}/desktop').get_json()['desktop']['id'] == d1['id']
    now = e['stu'].get('/api/vlab/me/reservations/now').get_json()['reservations']
    assert [x['id'] for x in now] == [rid] and now[0]['running']
    assert e['admin'].get('/api/vlab/admin/reservations/summary').get_json()['running'] == 1
    # the clean-up after it takes the desktops back
    ((_, phase, res),) = vlab.lab_tick(datetime(2026, 10, 19, 12, 1))
    assert phase == 'finish'
    assert store.get_desktop(d1['id'])['assigned_user'] is None and store.get_desktop(d2['id'])['assigned_user'] is None
    assert vlab.lab_tick(datetime(2026, 10, 19, 12, 2)) == []


def test_a_start_waits_for_the_previous_clean_up_of_its_pool(lab_env):
    e = lab_env
    vlab = e['vlab']
    first = e['admin'].post('/api/vlab/admin/reservations', json=_body(e, kind='desktops', lab_id=None, quantity=4,
                                                                         start_at='2026-10-19T09:00', end_at='2026-10-19T10:00'))
    second = e['admin'].post('/api/vlab/admin/reservations', json=_body(e, kind='desktops', lab_id=None, quantity=4,
                                                                          start_at='2026-10-19T10:00', end_at='2026-10-19T11:00'))
    a, b = first.get_json()['reservations'][0]['id'], second.get_json()['reservations'][0]['id']
    assert [x[:2] for x in vlab.lab_tick(datetime(2026, 10, 19, 8, 55))] == [(a, 'prepare')]
    # 09:50: the second's start is due, but the first still runs until 10:00
    assert vlab.lab_tick(datetime(2026, 10, 19, 9, 50)) == []
    # 10:00: the first is cleaned up first, then the second starts
    assert [x[:2] for x in vlab.lab_tick(datetime(2026, 10, 19, 10, 0))] == [(a, 'finish'), (b, 'prepare')]


def test_the_kiosk_shows_the_booking_and_serves_its_participants_only(lab_env, api):
    e = lab_env
    t = e['admin'].post('/api/vlab/admin/terminals', json={'mac': '52:54:00:00:01:01', 'name': '301-PC-01',
                                                           'lab_id': e['lab']['id']}).get_json()['terminal']
    hdr = {'X-Terminal-Key': e['admin'].post(f"/api/vlab/admin/terminals/{t['id']}/key").get_json()['key']}
    r = e['prof'].post('/api/vlab/me/reservations', json=_body(e, kind='lab', purpose='캡스톤 세미나',
                                                                participants=[{'subject_type': 'user', 'subject_id': 'stu'}]))
    rid = r.get_json()['reservations'][0]['id']
    info = api.anon().get('/api/vlab/kiosk', headers=hdr).get_json()
    assert info['current'] is None and info['next']['reservation_id'] == rid and info['next']['title'] == '캡스톤 세미나'
    e['clock']['now'] = datetime(2026, 10, 19, 10, 5)
    info = api.anon().get('/api/vlab/kiosk', headers=hdr).get_json()
    assert info['current']['reservation_id'] == rid and info['current']['kind'] == 'lab'
    r = e['other'].post('/api/vlab/kiosk/start', headers=hdr)
    assert r.status_code == 403 and r.get_json()['code'] == 'NOT_PARTICIPANT'
    r = e['stu'].post('/api/vlab/kiosk/start', headers=hdr)
    assert r.status_code == 200, r.get_json()
    assert store.get_desktop(r.get_json()['desktop']['id'])['assigned_user'] == 'stu'


def test_the_report_puts_booked_beside_used_and_counts_no_shows(lab_env):
    e = lab_env
    used = e['admin'].post('/api/vlab/admin/reservations', json=_body(e, requester='prof', start_at='2026-10-19T09:00',
                                                                        end_at='2026-10-19T11:00')).get_json()['reservations'][0]
    idle = e['admin'].post('/api/vlab/admin/reservations', json=_body(e, requester='prof', quantity=1, purpose='=HYPERLINK()',
                                                                        start_at='2026-10-19T13:00', end_at='2026-10-19T14:00')
                           ).get_json()['reservations'][0]
    assert e['sent']['mail'] and e['sent']['mail'][0][0] == ['prof@example.edu']     # booked for them: they hear of it
    e['vlab'].lab_tick(datetime(2026, 10, 19, 8, 55))
    desk = store.get_desktop(rsv.get(used['id'])['desktops'][0])
    tz = datetime.now().astimezone().tzinfo
    utc = lambda h, m=0: datetime(2026, 10, 19, h, m, tzinfo=tz).astimezone(timezone.utc).isoformat(timespec='seconds')
    store.db().execute("""INSERT INTO vlab_sessions (id, username, desktop_id, pool_id, protocol, started_at, ended_at, result)
                          VALUES ('s1', 'stu', ?, ?, 'vnc', ?, ?, 'ended')""", (desk['id'], desk['pool_id'], utc(9, 30), utc(10, 0)))
    e['clock']['now'] = datetime(2026, 10, 19, 18, 0)
    d = e['admin'].get('/api/vlab/admin/reports/reservations?days=7').get_json()
    rows = {x['id']: x for x in d['reservations']}
    assert rows[used['id']]['booked_hours'] == 2 and rows[used['id']]['used_hours'] == 0.5 and not rows[used['id']]['no_show']
    assert rows[idle['id']]['no_show'] and d['totals']['no_shows'] == 1 and d['totals']['no_show_rate'] == 0.5
    assert d['by_lab'][0]['lab'] == '실습실 301' and d['by_lab'][0]['reservations'] == 2
    csv = e['admin'].get('/api/vlab/admin/reports/reservations?days=7&format=csv')
    text = csv.get_data(as_text=True)
    assert csv.mimetype == 'text/csv' and "'=HYPERLINK()" in text and text.splitlines()[0].lstrip('﻿').startswith('lab,pool')
    assert e['prof'].get('/api/vlab/admin/reports/reservations').status_code == 403


def test_a_removed_lab_cancels_its_bookings_that_have_not_started(lab_env):
    e = lab_env
    rid = e['prof'].post('/api/vlab/me/reservations', json=_body(e)).get_json()['reservations'][0]['id']
    assert e['admin'].delete(f"/api/vlab/admin/labs/{e['lab']['id']}").status_code == 200
    assert rsv.get(rid)['status'] == 'cancelled'
