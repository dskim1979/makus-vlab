"""MOAVI Desk user notices beyond GPU (pegaprox/api/vlab_notices.py): LAB bookings about to start,
NAS folders at 90 % / 100 %, desktops replaced by a golden rollout, moved off a node in
maintenance or disconnected by an administrator, and accounts locked by wrong passwords."""
from datetime import datetime, timedelta

import pytest

from pegaprox.api import vlab_notices as vn
from pegaprox.vlab import notices
from pegaprox.vlab import reservations as rsv


@pytest.fixture
def mails(monkeypatch):
    import pegaprox.utils.email as email
    import pegaprox.utils.webhooks as webhooks
    sent = []
    monkeypatch.setattr(email, 'send_email', lambda to, title, text, html=None: sent.append((to, title, text)) or (True, ''))
    monkeypatch.setattr(webhooks, 'send_to_channels', lambda data, channels=None: None)
    return sent


def _people(seed, *names):
    from pegaprox.utils.auth import load_users, save_single_user
    for n in names:
        seed.user(n, role='user')
    users = load_users()
    for n in names:
        save_single_user(n, dict(users[n], email=f'{n}@lab.example'))


def _to(mails, name):
    return [t for to, t, _ in mails if to == [f'{name}@lab.example']]


def test_storage_levels():
    gb = 1024 * 1024
    assert notices.storage_level(89 * gb // 10, 10) is None
    assert notices.storage_level(9 * gb, 10) == 'warn'
    assert notices.storage_level(10 * gb, 10) == 'full'
    assert notices.storage_level(10 * gb, 0) is None             # no quota
    assert 'booking' in notices.KINDS and 'storage' in notices.KINDS


def _booking(start, status='approved', participants=(), requester='prof'):
    row = {'kind': 'lab', 'pool_id': 'p1', 'quantity': 0, 'purpose': '회로 실습', 'note': '', 'participants': list(participants),
           'requester': requester, 'status': status, 'prepare_min': 10, 'after': 'reset'}
    return rsv.add(row, (start, start + timedelta(hours=2)))


def test_booking_reminder_goes_once_to_everyone_in_it(api, seed, mails, monkeypatch):
    _people(seed, 'prof', 'ta', 'stu1', 'stu2')
    from pegaprox.vlab import catalog
    monkeypatch.setattr(catalog, 'user_departments', lambda: {'stu1': 'd-ee', 'stu2': 'd-cs'})
    at = datetime(2026, 10, 19, 8, 40)
    _booking(datetime(2026, 10, 19, 9, 0), participants=[{'subject_type': 'user', 'subject_id': 'ta'},
                                                        {'subject_type': 'department', 'subject_id': 'd-ee'}])
    _booking(datetime(2026, 10, 19, 9, 0), status='pending', requester='stu2')       # not approved: nothing
    _booking(datetime(2026, 10, 19, 11, 0))                                          # too far ahead
    assert vn.booking_reminders(at) == 1
    assert len(_to(mails, 'prof')) == 1 and len(_to(mails, 'ta')) == 1 and len(_to(mails, 'stu1')) == 1
    assert _to(mails, 'stu2') == []
    assert _to(mails, 'prof')[0].startswith('[MOAVI Desk] 곧 시작하는 예약')
    assert vn.booking_reminders(at + timedelta(minutes=5)) == 0                      # once
    notices.save_prefs('ta', {'booking': False})
    _booking(datetime(2026, 10, 19, 9, 15), participants=[{'subject_type': 'user', 'subject_id': 'ta'}])
    n = len(mails)
    assert vn.booking_reminders(at + timedelta(minutes=10)) == 1
    assert [to for to, _, _ in mails[n:]] == [['prof@lab.example']]                  # ta turned it off


def test_booking_reminder_off_and_the_setting(api, seed, mails):
    admin = api.as_user(seed.user('root', role='admin'))
    assert admin.put('/api/vlab/admin/reservation-settings/_global', json={'remind_min': -1}).status_code == 400
    assert admin.put('/api/vlab/admin/reservation-settings/_global', json={'remind_min': 0}).status_code == 200
    _people(seed, 'prof')
    _booking(datetime(2026, 10, 19, 9, 0))
    assert vn.booking_reminders(datetime(2026, 10, 19, 8, 55)) == 0 and mails == []


def test_storage_steps_once_a_month(api, seed, mails, monkeypatch):
    _people(seed, 'alice')
    from pegaprox.vlab import nas
    monkeypatch.setattr(nas, 'get', lambda pid: {'folders': {'home': {'quota_gb': 10}, 'scratch': {'quota_gb': 0}}})
    pool = {'id': 'p1', 'name': 'AI 연구실'}
    gb = 1024 * 1024
    vn.storage_usage(pool, 'alice', {'home': 5 * gb, 'scratch': 999 * gb})
    assert mails == []
    vn.storage_usage(pool, 'alice', {'home': 9 * gb})
    vn.storage_usage(pool, 'alice', {'home': 9 * gb})
    assert len(_to(mails, 'alice')) == 1 and '90%' in _to(mails, 'alice')[0]
    vn.storage_usage(pool, 'alice', {'home': 10 * gb})
    assert len(_to(mails, 'alice')) == 2 and '가득' in _to(mails, 'alice')[1]


def test_desktop_replaced_disconnected_and_locked(api, seed, mails):
    _people(seed, 'alice')
    vn.desktop_replaced('alice', 'lab-win11-01', 'win11-수업', 'gold-20261017')
    vn.session_ended({'username': 'alice'}, {'name': 'lab-win11-01'}, 'root', record_only=True)
    notices.save_prefs('alice', {'desktop': False})
    vn.desktop_replaced('alice', 'lab-win11-02', 'win11-수업', 'gold-20261017')       # turned off
    vn.account_locked('alice', 5, '10.0.0.9')                                         # always
    titles = _to(mails, 'alice')
    assert len(titles) == 3
    assert '교체' in titles[0] and '접속을 끊었습니다' in titles[1] and '잠시 잠겼습니다' in titles[2]


def test_maintenance_tells_the_users_of_running_desktops_on_the_node(api, seed, mails, monkeypatch):
    _people(seed, 'alice', 'bob')
    from pegaprox.vlab import store
    monkeypatch.setattr(store, 'list_desktops', lambda pool_id=None: [
        {'cluster_id': 'c1', 'vmid': 101, 'name': 'ws-01', 'assigned_user': 'alice'},
        {'cluster_id': 'c1', 'vmid': 102, 'name': 'ws-02', 'assigned_user': 'bob'},
        {'cluster_id': 'c1', 'vmid': 103, 'name': 'ws-03', 'assigned_user': 'bob'}])
    monkeypatch.setattr(vn.core, '_vm_states', lambda cid: {101: {'node': 'pve1', 'status': 'running'},
                                                            102: {'node': 'pve2', 'status': 'running'},
                                                            103: {'node': 'pve1', 'status': 'stopped'}})
    assert vn.desktops_moving('c1', 'pve1', 'root') == 1
    assert len(_to(mails, 'alice')) == 1 and _to(mails, 'bob') == []
