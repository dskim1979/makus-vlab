"""MOAVI Desk per-user notices (pegaprox/vlab/notices.py, pegaprox/api/vlab_notices.py): the mails
of GPU jobs starting, GPU quota steps, loan reminders and automatic returns, web IDEs closed, the
answers to requests, the security notices, and the choices a user makes in 내 계정 > 알림."""
from datetime import datetime, timedelta, timezone

import pytest

from pegaprox.vlab import catalog, notices, research, store
from test_vlab_research import CID, _gpu_farm, _ide_desk, _job, env  # noqa: F401 - the shared fixture


class _Sent(list):
    def __init__(self):
        super().__init__()
        self.hooks = []


@pytest.fixture
def mails(monkeypatch):
    """Every mail sent: [(to, title, text)]; the webhook posts in mails.hooks."""
    import pegaprox.utils.email as email
    import pegaprox.utils.webhooks as webhooks
    sent = _Sent()
    monkeypatch.setattr(email, 'send_email', lambda to, title, text, html=None: sent.append((to, title, text)) or (True, ''))
    monkeypatch.setattr(webhooks, 'send_to_channels', lambda data, channels=None: sent.hooks.append((data, channels)))
    return sent


def _emails(*names):
    from pegaprox.utils.auth import load_users, save_single_user
    users = load_users()
    for n in names:
        save_single_user(n, dict(users[n], email=f'{n}@lab.example'))


def _to(mails, name):
    return [t for to, t, _ in mails if to == [f'{name}@lab.example']]


def _iso(dt):
    return dt.isoformat(timespec='seconds')


# --- the pure rules ---------------------------------------------------------------------------

def test_quota_steps_and_the_loan_window():
    assert notices.quota_level(7.9, 10, 80) is None
    assert notices.quota_level(8, 10, 80) == 'warn'
    assert notices.quota_level(10, 10, 80) == 'full'
    assert notices.quota_level(9.9, 10, 0) is None                   # 0 = only at 100%
    assert notices.quota_level(50, 0, 80) is None                    # no monthly quota
    at = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
    assert notices.due_soon(_iso(at + timedelta(hours=23)), 24, at)
    assert not notices.due_soon(_iso(at + timedelta(hours=25)), 24, at)
    assert not notices.due_soon(_iso(at - timedelta(minutes=1)), 24, at)   # already past: the return tells it
    assert not notices.due_soon(_iso(at + timedelta(hours=1)), 0, at)


def test_once_and_the_choices_of_a_user(env):
    assert notices.once('k:1') and not notices.once('k:1') and notices.was_sent('k:1')
    assert all(notices.prefs('alice').values())
    assert notices.save_prefs('alice', {'ide': False})['ide'] is False
    p = notices.save_prefs('alice', {'loan': False})
    assert p['ide'] is False and p['loan'] is False and p['gpu_job'] is True   # kinds left out are kept
    with pytest.raises(ValueError):
        notices.validate_prefs({'nope': True})
    with pytest.raises(ValueError):
        notices.validate_prefs({'ide': 'yes'})


def test_my_notice_choices_route(env, mails):
    _, _, _, admin, alice, bob, viewer = env
    _emails('alice')
    got = alice.get('/api/vlab/me/notices').get_json()
    assert got['email'] == 'alice@lab.example'
    assert [k['id'] for k in got['kinds']][:4] == ['gpu_job', 'gpu_quota', 'loan', 'ide']
    assert all(k['on'] and k['label_ko'] and k['label_en'] for k in got['kinds'])
    r = alice.put('/api/vlab/me/notices', json={'desktop': False})
    assert r.status_code == 200 and {k['id']: k['on'] for k in r.get_json()['kinds']}['desktop'] is False
    assert alice.put('/api/vlab/me/notices', json={'desktop': 1}).status_code == 400
    assert viewer.get('/api/vlab/me/notices').status_code == 403
    # bob's choices are his own
    assert all(k['on'] for k in bob.get('/api/vlab/me/notices').get_json()['kinds'])
    # the desktop notice follows the choice: alice turned it off
    desk = store.add_desktop(store.create_pool('개인', 'dedicated', CID), 'pve1', 710, 'ws-alice')
    assert admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': 'alice'}).status_code == 200
    assert _to(mails, 'alice') == []
    alice.put('/api/vlab/me/notices', json={'desktop': True})
    assert admin.put(f"/api/vlab/admin/desktops/{desk['id']}/assign", json={'username': None}).status_code == 200
    assert _to(mails, 'alice') == ['[MOAVI Desk] 데스크톱 회수: ws-alice']


def test_the_notice_settings_are_checked(env):
    _, _, _, admin, alice, _, _ = env
    r = admin.put('/api/vlab/admin/gpu-settings', json={'quota_warn_pct': 70, 'loan_remind_hours': 48, 'notice_webhook': True})
    assert r.status_code == 200
    s = r.get_json()['settings']
    assert s['quota_warn_pct'] == 70 and s['loan_remind_hours'] == 48 and s['notice_webhook'] is True and s['ide_notice'] is True
    assert admin.put('/api/vlab/admin/gpu-settings', json={'quota_warn_pct': 100}).status_code == 400
    assert admin.put('/api/vlab/admin/gpu-settings', json={'ide_notice': 'no'}).status_code == 400
    assert alice.put('/api/vlab/admin/gpu-settings', json={'ide_notice': False}).status_code == 403


# --- GPU jobs -----------------------------------------------------------------------------------

def test_a_gpu_job_tells_its_start_when_asked(env, mails):
    _, _, _, admin, alice, bob, _ = env
    _gpu_farm(admin)
    _emails('alice', 'bob')
    admin.put('/api/vlab/admin/gpu-settings', json={'channels': ['ch1']})
    r = _job(alice, name='bert', notify={'mail': True, 'webhook': True, 'start': True})
    assert r.status_code == 201 and r.get_json()['job']['status'] == 'running'
    assert _to(mails, 'alice') == ['[MOAVI Desk] 작업 시작: bert']
    assert [h[0]['kind'] for h in mails.hooks] == ['gpu_job_started'] and mails.hooks[0][1] == ['ch1']
    # the end only (no start asked), and nothing when the owner turned GPU job mails off
    _job(bob, name='quiet', notify={'mail': True})
    assert _to(mails, 'bob') == []
    notices.save_prefs('bob', {'gpu_job': False})
    _job(bob, name='off', notify={'mail': True, 'start': True})
    assert _to(mails, 'bob') == []
    assert _job(alice, notify={'start': 'yes'}).status_code == 400


# --- GPU quotas ----------------------------------------------------------------------------------

def _gpu_hours(username, hours, dep=''):
    """A running 1-GPU job started `hours` ago: that many GPU-hours this month."""
    started = research.utcnow() - timedelta(hours=hours)
    if started < research.month_start():
        pytest.skip('too early in the month for this test')
    job = catalog.add_build_job('', username, 'x', 'x', '', gpus=1, department_id=dep)
    catalog.update_build_job(job['id'], status='running', started_at=_iso(started))
    return job


def test_quota_warnings_go_once_a_month_to_the_user_and_the_department_manager(env, mails):
    from pegaprox.api import vlab_notices
    _, _, _, admin, alice, bob, _ = env
    _emails('alice', 'bob', 'root')
    dep = admin.post('/api/vlab/admin/departments', json={'name': 'AI 연구실', 'manager': 'root'}).get_json()['department']
    assert dep['manager'] == 'root'
    assert admin.post('/api/vlab/admin/departments', json={'name': 'x', 'manager': 'ghost'}).status_code == 400
    catalog.set_department('alice', dep['id'])
    assert admin.put('/api/vlab/admin/gpu-quotas', json={'subject_type': 'default', 'max_gpus': 0, 'monthly_gpu_hours': 10}).status_code == 200
    assert admin.put('/api/vlab/admin/gpu-quotas', json={'subject_type': 'department', 'subject_id': dep['id'],
                                                          'max_gpus': 0, 'monthly_gpu_hours': 20}).status_code == 200
    job = _gpu_hours('alice', 8.5, dep['id'])
    _gpu_hours('bob', 2)
    assert vlab_notices.quota_tick(force=True) == 1
    assert _to(mails, 'alice') == [f"[MOAVI Desk] GPU 할당량 85% 사용: {research.month_start().astimezone():%Y-%m}"]
    assert vlab_notices.quota_tick(force=True) == 0                      # once
    # past 100% of her own and 80% of the department's: the manager hears of the department
    catalog.update_build_job(job['id'], started_at=_iso(research.utcnow() - timedelta(hours=17)))
    assert vlab_notices.quota_tick(force=True) == 3
    assert any(t.startswith('[MOAVI Desk] GPU 할당량 소진') for t in _to(mails, 'alice'))
    assert _to(mails, 'root') == ['[MOAVI Desk] 부서 GPU 할당량 85% 사용: AI 연구실']
    assert _to(mails, 'bob') == []
    # switched off by the administrators: nothing
    admin.put('/api/vlab/admin/gpu-settings', json={'quota_notice': False})
    catalog.update_build_job(job['id'], started_at=_iso(research.utcnow() - timedelta(hours=25)))
    n = len(mails)
    assert vlab_notices.quota_tick(force=True) == 0 and len(mails) == n


# --- loans ----------------------------------------------------------------------------------------

def test_loan_reminder_before_the_end_and_a_notice_when_it_went_back(env, mails, monkeypatch):
    from pegaprox.api import vlab_notices
    from pegaprox.core import ha
    from pegaprox.vlab import loans
    _, _, _, admin, alice, _, _ = env
    _emails('alice')
    now = datetime.now(timezone.utc)
    lease = store.add_lease('gpu', 'a100', 'A100 #1', 'alice', CID, 710, _iso(now + timedelta(hours=5)))
    assert vlab_notices.loan_reminders() == 1 and vlab_notices.loan_reminders() == 0
    assert _to(mails, 'alice') == ['[MOAVI Desk] 대여 종료 예정: GPU 카드 A100 #1']
    # extended: a new end, a new reminder (and a mail of the extension)
    later = _iso(now + timedelta(hours=10))
    assert admin.post(f"/api/vlab/admin/leases/{lease['id']}/extend", json={'ends_at': later}).status_code == 200
    assert _to(mails, 'alice')[-1] == '[MOAVI Desk] 대여 연장: GPU 카드 A100 #1'
    assert vlab_notices.loan_reminders() == 1
    # the end passes: returned by the minute loop, and told
    store.extend_lease(lease['id'], _iso(now - timedelta(minutes=1)))
    import pegaprox.api.vlab as core
    monkeypatch.setattr(ha, 'confirm_step', lambda *a, **k: True)
    monkeypatch.setattr(core, 'return_lease', lambda l, by='system': store.close_lease(l['id']))
    assert loans.return_due() == (1, 0)
    assert _to(mails, 'alice')[-1] == '[MOAVI Desk] 대여 기간이 끝나 자동 반납: GPU 카드 A100 #1'
    assert store.get_lease(lease['id'])['state'] == 'returned'


def test_a_card_return_that_fails_alerts_the_administrators_once(env, mails, monkeypatch):
    import pegaprox.api.vlab as core
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    from pegaprox.core import ha
    from pegaprox.vlab import loans
    s = load_server_settings() or {}
    save_server_settings(dict(s, alert_email_recipients=['ops@lab.example']))
    lease = store.add_lease('gpu', 'a100', 'A100 #1', 'alice', CID, 710, _iso(datetime.now(timezone.utc) - timedelta(minutes=1)))
    monkeypatch.setattr(ha, 'confirm_step', lambda *a, **k: True)
    monkeypatch.setattr(core, 'return_lease', lambda l, by='system': 'the node did not answer')
    assert loans.return_due() == (0, 1)
    assert loans.return_due() == (0, 1)
    assert [t for to, t, _ in mails if to == ['ops@lab.example']] == ['[MOAVI Desk] 대여 자동 반납 실패: GPU 카드 A100 #1']
    assert store.get_lease(lease['id'])['state'] == 'active'


def test_a_board_loan_reminds_in_local_time(env, mails):
    from pegaprox.api import vlab_notices
    _emails('bob')
    b = catalog.save_board(None, 'Alveo U250', CID, 'pve1', '10ee:500c', 'fpga', '')
    until = (datetime.now() + timedelta(hours=3)).strftime('%Y-%m-%dT%H:%M')
    catalog.set_board_attachment(b['id'], 'dsk_x', 710, 'root', 'bob', until)
    assert vlab_notices.loan_reminders() == 1
    assert _to(mails, 'bob') == ['[MOAVI Desk] 보드 대여 종료 예정: Alveo U250']


# --- web IDEs -------------------------------------------------------------------------------------

def test_an_ide_closed_for_being_idle_or_by_an_administrator_is_told(env, mails, monkeypatch):
    import pegaprox.api.vlab_next as nxt
    from pegaprox.api import vlab_notices
    _, _, agent, admin, alice, _, _ = env
    _emails('alice')
    _, desk = _ide_desk(admin, kinds=('jupyter',))
    monkeypatch.setattr(nxt, '_tcp_probe', lambda h, p, timeout=2.0: (True, 1, ''))
    s = alice.post('/api/vlab/me/ide', json={'desktop_id': desk['id'], 'kind': 'jupyter'}).get_json()['session']
    pid = agent.scripts()[-1][2]
    vlab_notices.ide_tick()
    assert research.get_ide(s['id'])['state'] == 'running' and _to(mails, 'alice') == []
    # Jupyter ended itself after the pool's idle minutes (240 by default)
    research.update_ide(s['id'], last_seen=_iso(research.utcnow() - timedelta(minutes=241)))
    agent.done[pid] = {'exited': 1, 'exitcode': 0}
    vlab_notices.ide_tick()
    row = research.get_ide(s['id'])
    assert row['state'] == 'stopped' and row['error'] == 'closed after 240 idle minutes'
    assert _to(mails, 'alice') == ['[MOAVI Desk] 웹 IDE 유휴 종료: JupyterLab (ws-alice)']
    # an administrator closes the next one
    s2 = alice.post('/api/vlab/me/ide', json={'desktop_id': desk['id'], 'kind': 'jupyter'}).get_json()['session']
    assert admin.delete(f"/api/vlab/admin/ide-sessions/{s2['id']}").status_code == 200
    assert _to(mails, 'alice')[-1] == '[MOAVI Desk] 관리자가 웹 IDE 종료: JupyterLab (ws-alice)'
    # the user's own stop and an IDE closed from inside (not idle long) are not told
    s3 = alice.post('/api/vlab/me/ide', json={'desktop_id': desk['id'], 'kind': 'jupyter'}).get_json()['session']
    alice.delete(f"/api/vlab/me/ide/{s3['id']}")
    assert len(_to(mails, 'alice')) == 2


# --- requests, accounts, the queue -----------------------------------------------------------------

def test_sign_up_answers_and_the_admins_hear_of_one_waiting(env, mails):
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    api, _, _, admin, _, _, _ = env
    save_server_settings(dict(load_server_settings() or {}, alert_email_recipients=['ops@lab.example']))
    assert admin.put('/api/vlab/admin/signup-settings', json={'enabled': True, 'verify_email': 'off'}).status_code == 200
    r = api.anon().post('/api/vlab/signup', json={'username': 'newbie', 'password': 'Very-Long-Passw0rd!', 'email': 'nb@lab.example'})
    assert r.status_code == 201, r.get_json()
    assert [t for to, t, _ in mails if to == ['ops@lab.example']] == ['[MOAVI Desk] 가입 심사 대기: newbie']
    sid = r.get_json()['request']['id']
    assert admin.post(f'/api/vlab/admin/signups/{sid}/approve', json={}).status_code == 200
    assert [t for to, t, _ in mails if to == ['nb@lab.example']] == ['[MOAVI Desk] 가입 승인 / Sign-up approved']


def test_security_notices_go_even_when_turned_off(env, mails):
    _, _, _, admin, _, _, _ = env
    _emails('alice')
    notices.save_prefs('alice', {k: False for k in notices.KINDS})
    r = admin.put('/api/vlab/admin/users/alice/password', json={'password': 'Another-Long-Passw0rd!'})
    assert r.status_code == 200, r.get_json()
    assert admin.put('/api/vlab/admin/users/alice', json={'enabled': False}).status_code == 200
    assert _to(mails, 'alice') == ['[MOAVI Desk] 비밀번호가 재설정되었습니다', '[MOAVI Desk] 계정이 사용 중지되었습니다']


def test_a_gpu_job_waiting_long_is_told_to_the_admins_once(env, mails):
    from pegaprox.api import vlab_notices
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    save_server_settings(dict(load_server_settings() or {}, alert_email_recipients=['ops@lab.example']))
    job = catalog.add_build_job('', 'alice', 'llm', 'python t.py', '', gpus=8)
    catalog.db().execute('UPDATE vlab_build_jobs SET created_at = ? WHERE id = ?',
                         (_iso(research.utcnow() - timedelta(hours=7)), job['id']))
    assert vlab_notices.queue_tick() == 1 and vlab_notices.queue_tick() == 0
    assert [t for to, t, _ in mails if to == ['ops@lab.example']] == ['[MOAVI Desk] GPU 작업이 6시간 넘게 대기 중 (1건)']


def test_the_minute_loop_runs_the_notices(env, mails, monkeypatch):
    from pegaprox.api import vlab_notices
    calls = []
    for name in ('loan_reminders', 'quota_tick', 'ide_tick', 'queue_tick'):
        monkeypatch.setattr(vlab_notices, name, lambda name=name: calls.append(name))
    vlab_notices.notice_tick()
    assert calls == ['loan_reminders', 'quota_tick', 'ide_tick', 'queue_tick']
    from pegaprox.vlab import features
    monkeypatch.setattr(features, 'enabled', lambda g: g == 'fpga')
    calls.clear()
    vlab_notices.notice_tick()
    assert calls == ['loan_reminders']
