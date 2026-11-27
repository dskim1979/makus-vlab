"""MOAVI Desk support bundle (pegaprox/api/vlab_support.py): a period, what goes in, what never does."""
import io
import json
import zipfile
from datetime import datetime, timedelta

import pytest

from pegaprox.vlab import catalog, store

CID = 'cluster_1'


@pytest.fixture
def env(api, seed):
    mgr = api.make_fake_manager(CID, get_vm_resources=[], get_tasks=[
        {'upid': 'UPID:old', 'type': 'qmclone', 'starttime': (datetime.now() - timedelta(days=3)).timestamp(), 'status': 'OK'},
        {'upid': 'UPID:new', 'type': 'qmigrate', 'starttime': (datetime.now() - timedelta(hours=1)).timestamp(), 'status': 'OK'}])
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    pool = store.create_pool('공용 LAB A', 'dedicated', CID)
    desk = store.add_desktop(pool, 'pve1', 300, 'lab-win11-01')
    store.assign(desk['id'], 'alice') if hasattr(store, 'assign') else None
    store.start_session('alice', desk, 'spice', '192.168.10.21')
    return admin, alice


def _zip(resp):
    zf = zipfile.ZipFile(io.BytesIO(resp.data))
    root = zf.namelist()[0].split('/')[0]
    return zf, root, lambda name: zf.read(f'{root}/{name}').decode('utf-8')


def _fmt(dt):
    return dt.strftime('%Y-%m-%dT%H:%M')


def test_only_admins_and_a_sane_period(env):
    admin, alice = env
    assert alice.get('/api/vlab/admin/support-bundle').status_code == 403
    now = datetime.now()
    assert admin.get('/api/vlab/admin/support-bundle?from=nope').status_code == 400
    assert admin.get(f'/api/vlab/admin/support-bundle?from={_fmt(now)}&to={_fmt(now - timedelta(hours=1))}').status_code == 400
    assert admin.get(f'/api/vlab/admin/support-bundle?from={_fmt(now - timedelta(days=40))}&to={_fmt(now)}').status_code == 400


def test_preview_counts_the_period(env):
    admin, _ = env
    r = admin.get('/api/vlab/admin/support-bundle/preview')          # default: the last 24 hours
    assert r.status_code == 200, r.get_json()
    c = r.get_json()['counts']
    assert c['sessions'] == 1 and c['tasks'] == 1
    old = datetime.now() - timedelta(days=10)
    c = admin.get(f'/api/vlab/admin/support-bundle/preview?from={_fmt(old)}&to={_fmt(old + timedelta(days=1))}').get_json()['counts']
    assert c['sessions'] == 0 and c['tasks'] == 0


def test_bundle_holds_the_period_and_no_secrets(env):
    admin, _ = env
    r = admin.get('/api/vlab/admin/support-bundle')
    assert r.status_code == 200 and r.mimetype == 'application/zip'
    assert 'moavi-desk-support_' in r.headers['Content-Disposition']
    zf, root, read = _zip(r)
    names = {n.split('/', 1)[1] for n in zf.namelist()}
    for need in ('manifest.json', 'system/versions.json', 'clusters/status.json', 'clusters/tasks.json',
                 'activity/sessions.json', 'audit/audit_log.json', 'config/pools.json'):
        assert need in names, need
    manifest = json.loads(read('manifest.json'))
    assert manifest['contents']['sessions'] == 1 and 'docker compose logs --since' in manifest['not_included']
    assert [t['upid'] for t in json.loads(read('clusters/tasks.json'))] == ['UPID:new']
    everything = ''.join(zf.read(n).decode('utf-8', 'replace') for n in zf.namelist())
    assert 'a' * 32 not in everything                                   # the Guacamole key
    assert '192.168.10.21' not in everything and '192.x.x.x' in read('activity/sessions.json')   # IPs masked by default


def test_options_leave_parts_out_and_mask_users(env):
    admin, _ = env
    r = admin.get('/api/vlab/admin/support-bundle?logs=0&audit=0&config=0&tasks=0&mask_ips=0&mask_users=1')
    zf, root, read = _zip(r)
    names = {n.split('/', 1)[1] for n in zf.namelist()}
    assert not any(n.startswith(('audit/', 'config/', 'logs/')) for n in names) and 'clusters/tasks.json' not in names
    sessions = read('activity/sessions.json')
    assert '192.168.10.21' in sessions and '"alice"' not in sessions and 'user-' in sessions
