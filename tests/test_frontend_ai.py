"""AI assistant settings of a trusted front end (/api/frontend/ai).

Admin API token only; keys are stored encrypted, kept when sent back masked, cleared
with an empty string, never shown in the general server settings; addresses must be
http(s); a stale full-settings save cannot wipe the record.
"""
from pegaprox.api.helpers import load_server_settings, save_server_settings
from pegaprox.utils.auth import create_api_token


def _bearer(tok):
    return {'Authorization': f"Bearer {tok['token']}"}


def test_keys_are_encrypted_kept_when_masked_and_cleared_when_empty(api, seed, db):
    seed.user('root', role='admin')
    h = _bearer(create_api_token('root', 'front', role='admin'))
    c = api.anon()
    r = c.put('/api/frontend/ai', headers=h, json={'enabled': True, 'provider': 'openai', 'openaiBaseUrl': 'https://llm.example/v1/',
                                                   'openaiModel': 'gpt-x', 'openaiKey': 'sk-REAL'})
    assert r.status_code == 200, r.data
    raw = db.get_server_setting('frontend_ai', {})
    assert raw['openaiKey'] and 'sk-REAL' not in str(raw)
    got = c.get('/api/frontend/ai', headers=h).get_json()
    assert got['openaiKey'] == 'sk-REAL' and got['openaiBaseUrl'] == 'https://llm.example/v1'
    c.put('/api/frontend/ai', headers=h, json={'openaiKey': '********', 'openaiModel': 'gpt-y'})
    got = c.get('/api/frontend/ai', headers=h).get_json()
    assert got['openaiKey'] == 'sk-REAL' and got['openaiModel'] == 'gpt-y'
    c.put('/api/frontend/ai', headers=h, json={'openaiKey': ''})
    assert c.get('/api/frontend/ai', headers=h).get_json()['openaiKey'] == ''


def test_bad_values_and_callers_are_refused(api, seed):
    seed.user('root', role='admin')
    h = _bearer(create_api_token('root', 'front', role='admin'))
    c = api.anon()
    assert c.put('/api/frontend/ai', headers=h, json={'provider': 'other'}).status_code == 400
    assert c.put('/api/frontend/ai', headers=h, json={'ollamaUrl': 'file:///etc/passwd'}).status_code == 400
    assert api.as_user({'username': 'root', 'role': 'admin'}).get('/api/frontend/ai').status_code == 403
    viewer = _bearer(create_api_token('root', 'ro', role='viewer'))
    assert c.get('/api/frontend/ai', headers=viewer).status_code == 403


def test_not_in_server_settings_and_survives_a_stale_save(api, seed):
    seed.user('root', role='admin')
    h = _bearer(create_api_token('root', 'front', role='admin'))
    c = api.anon()
    stale = load_server_settings()
    c.put('/api/frontend/ai', headers=h, json={'enabled': True, 'anthropicKey': 'ak-REAL', 'provider': 'anthropic'})
    save_server_settings(stale)
    assert c.get('/api/frontend/ai', headers=h).get_json()['anthropicKey'] == 'ak-REAL'
    s = c.get('/api/settings/server', headers=h)
    assert s.status_code == 200 and 'frontend_ai' not in s.get_json()
