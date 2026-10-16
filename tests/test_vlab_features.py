"""MOAVI Desk site profile and feature groups (pegaprox/vlab/features.py, api/vlab_features.py)."""
from pegaprox.vlab import features


def test_not_chosen_means_everything_on(api, seed, monkeypatch):
    monkeypatch.delenv('VLAB_PROFILE', raising=False)
    alice = api.as_user(seed.user('alice', role='user'))
    body = alice.get('/api/vlab/features').get_json()
    assert body['chosen'] is False and set(body['groups']) == set(features.GROUPS)
    assert features.enabled('lab') and features.enabled('core-thing')


def test_admin_picks_a_profile_and_bundles(api, seed, monkeypatch):
    monkeypatch.delenv('VLAB_PROFILE', raising=False)
    admin = api.as_user(seed.user('root', role='admin'))
    alice = api.as_user(seed.user('alice', role='user'))
    assert alice.put('/api/vlab/admin/features', json={'profile': 'general'}).status_code == 403
    assert admin.put('/api/vlab/admin/features', json={'profile': 'nope'}).status_code == 400
    assert admin.put('/api/vlab/admin/features', json={'profile': 'general', 'groups': ['magic']}).status_code == 400
    r = admin.put('/api/vlab/admin/features', json={'profile': 'university', 'bundles': ['gpuai']})
    assert r.status_code == 200
    assert r.get_json()['groups'] == ['gpuai', 'lab', 'org', 'signup']
    assert features.enabled('lab') and not features.enabled('fpga') and not features.enabled('ha')
    r = admin.put('/api/vlab/admin/features', json={'profile': 'small_lab', 'groups': []})
    assert r.get_json()['groups'] == [] and not features.enabled('org')
    assert alice.get('/api/vlab/features').get_json()['chosen'] is True


def test_the_environment_sets_a_fresh_install_once(api, seed, monkeypatch):
    monkeypatch.setenv('VLAB_PROFILE', 'research')
    monkeypatch.setenv('VLAB_FEATURES', 'fpga, gpu-ai')
    got = features.get()
    assert got['chosen'] and got['profile'] == 'research'
    assert set(got['groups']) == {'org', 'external', 'data', 'ha', 'fpga', 'gpuai'}
    admin = api.as_user(seed.user('root', role='admin'))
    admin.put('/api/vlab/admin/features', json={'profile': 'general'})
    monkeypatch.setenv('VLAB_PROFILE', 'university')       # never over an admin's choice
    assert features.get()['profile'] == 'general'
