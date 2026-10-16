"""MOAVI Desk notices for the administrators (pegaprox/vlab/ops_notices.py, api/vlab_ops_notices.py)."""
from datetime import datetime, timedelta, timezone

from pegaprox.api import vlab_ops_notices as api_ops
from pegaprox.vlab import ops_notices as ops

T0 = datetime(2026, 10, 17, 9, 0, tzinfo=timezone.utc)


def test_settings_route_checks_and_saves(api, seed):
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    assert alice.get('/api/vlab/admin/ops-notices').status_code == 403
    body = admin.get('/api/vlab/admin/ops-notices').get_json()
    assert body['settings']['pair'] is True and 'vzdump' in body['task_types']
    assert admin.put('/api/vlab/admin/ops-notices', json={'pair': 'yes'}).status_code == 400
    assert admin.put('/api/vlab/admin/ops-notices', json={'task_types': ['rm-rf']}).status_code == 400
    assert admin.put('/api/vlab/admin/ops-notices', json={'terminal_every_min': 1}).status_code == 400
    assert admin.put('/api/vlab/admin/ops-notices', json={'nope': 1}).status_code == 400
    r = admin.put('/api/vlab/admin/ops-notices', json={'task_failed': False, 'task_types': ['vzdump', 'qmclone', 'vzdump'],
                                                       'channels': ['ops']})
    s = r.get_json()['settings']
    assert r.status_code == 200 and s['task_failed'] is False and s['task_types'] == ['qmclone', 'vzdump']
    assert ops.get_settings()['channels'] == ['ops'] and ops.get_settings()['pair'] is True


def test_terminals_waiting_are_told_at_most_every_n_minutes_and_warned_once():
    what, st = ops.terminal_due({}, 3, 10, 30, T0)
    assert what == 'waiting'
    assert ops.terminal_due(st, 4, 10, 30, T0 + timedelta(minutes=10))[0] is None
    what, st = ops.terminal_due(st, 4, 10, 30, T0 + timedelta(minutes=31))
    assert what == 'waiting'
    what, st = ops.terminal_due(st, 12, 10, 30, T0 + timedelta(minutes=32))
    assert what == 'warn'                                   # reaching the warning goes out at once
    assert ops.terminal_due(st, 15, 10, 30, T0 + timedelta(minutes=40))[0] is None
    what, st = ops.terminal_due(st, 0, 10, 30, T0 + timedelta(minutes=50))
    assert what is None and 'terminal_warned' not in st


def test_pair_member_down_once_then_up_and_forgotten_when_gone():
    m = {'instance_id': 'b', 'url': 'https://desk-b', 'last_contact': (T0 - timedelta(minutes=2)).isoformat()}
    ev, st = ops.pair_events({}, [m], 10, T0)
    assert ev == [] and st['pair'] == {'b': 'up'}
    ev, st = ops.pair_events(st, [m], 10, T0 + timedelta(minutes=15))
    assert [e['event'] for e in ev] == ['down']
    assert ops.pair_events(st, [m], 10, T0 + timedelta(minutes=20))[0] == []
    m2 = dict(m, last_contact=(T0 + timedelta(minutes=21)).isoformat())
    ev, st = ops.pair_events(st, [m2], 10, T0 + timedelta(minutes=22))
    assert [e['event'] for e in ev] == ['up']
    assert ops.pair_events(st, [], 10, T0)[1]['pair'] == {}


def test_promotion_is_seen_by_a_rising_epoch_only_on_the_active():
    took, st = ops.promoted({}, 'active', 3)
    assert took is False and st['epoch'] == 3              # the first look only notes it
    assert ops.promoted(st, 'active', 3)[0] is False
    assert ops.promoted(st, 'active', 4)[0] is True
    assert ops.promoted(st, 'standby', 5)[0] is False


def _row(end, ok=False, typ='vzdump', running=False):
    return {'endtime': end, 'ok': ok, 'type': typ, 'running': running, 'upid': f'UPID:n:{end}'}


def test_failed_tasks_after_the_cursor_of_watched_types():
    rows = [_row(100), _row(200, ok=True)]
    out, cur = ops.failed_tasks(rows, None, {'vzdump'})
    assert out == [] and cur == 200                         # no flood of old failures
    rows += [_row(300), _row(310, typ='qmstart'), _row(320, ok=True), _row(None, running=True)]
    out, cur = ops.failed_tasks(rows, cur, {'vzdump'})
    assert [r['endtime'] for r in out] == [300] and cur == 320
    assert ops.failed_tasks(rows, cur, {'vzdump'})[0] == []


def test_tick_sends_task_failures_through_the_alert_path(api, seed, monkeypatch):
    sent = []
    monkeypatch.setattr(api_ops, '_send', lambda title, text, data, s=None: sent.append((title, data)))
    monkeypatch.setattr(api_ops, 'pair_check', lambda s, st, at=None: st)

    class Mgr:
        cluster_type, is_connected = 'proxmox', True
        tasks = []

        def get_tasks(self, limit=100):
            return self.tasks

    mgr = Mgr()
    from pegaprox.api import vlab_next as nxt
    monkeypatch.setattr(nxt, '_task_clusters', lambda only=None: iter([('c1', mgr)]))
    monkeypatch.setattr(nxt.core, '_cluster_name', lambda cid, m: 'LAB-PVE')
    t = {'upid': 'UPID:pve1:1:2:3:vzdump:101:root@pam:', 'node': 'pve1', 'type': 'vzdump', 'id': '101'}
    mgr.tasks = [dict(t, starttime=90, endtime=100, status='OK')]
    api_ops.ops_tick(force=True)
    assert sent == []
    mgr.tasks.append(dict(t, upid=t['upid'] + 'x', starttime=150, endtime=200, status='ERROR: backup write failed'))
    api_ops.ops_tick(force=True)
    assert len(sent) == 1 and sent[0][0].startswith('작업 실패: 백업') and sent[0][1]['vmid'] == 101
    api_ops.ops_tick(force=True)
    assert len(sent) == 1                                   # told once
    monkeypatch.setattr(api_ops, '_clusters_with_task_rule', lambda: {'c1'})
    mgr.tasks.append(dict(t, upid=t['upid'] + 'y', starttime=250, endtime=300, status='ERROR: again'))
    api_ops.ops_tick(force=True)
    assert len(sent) == 1                                   # the cluster's own rule tells instead


def test_license_denials_summarise_features_and_users(monkeypatch):
    sent = []
    monkeypatch.setattr(api_ops, '_send', lambda title, text, data, s=None: sent.append((title, text, data)))
    from pegaprox.vlab import license_usage as lu
    monkeypatch.setattr(lu, 'denials', lambda sid, since, limit=None: [
        {'feature': 'Vivado_System_Edition', 'user': 'bob'}, {'feature': 'Vivado_System_Edition', 'user': 'carol'}])
    api_ops.license_denied({'id': 'l1', 'name': 'FlexLM', 'host': 'lic'}, 2)
    assert sent and sent[0][0] == '라이선스 거부 2건: FlexLM' and 'bob, carol' in sent[0][1]
    api_ops.license_denied({'id': 'l1', 'name': 'FlexLM', 'host': 'lic'}, 0)
    assert len(sent) == 1
