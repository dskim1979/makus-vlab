"""Audit events of a trusted front end (/api/frontend/audit) and SIEM targets edited through it.

Lines land in this server's audit log marked with their source, so they reach the SIEM
targets and can never pass for an action of this server. Only an admin API token may
send them. A SIEM target saved with the masked secret it was shown keeps its secret.
"""
import json

import pegaprox.api.siem as siem
from pegaprox.utils.auth import create_api_token


def _bearer(tok):
    return {'Authorization': f"Bearer {tok['token']}"}


def _rows(db, action):
    return db.conn.execute('SELECT user, action, details, ip_address FROM audit_log WHERE action = ?', (action,)).fetchall()


def test_events_land_marked_with_their_source(api, seed, db):
    seed.user('root', role='admin')
    h = _bearer(create_api_token('root', 'front', role='admin'))
    r = api.anon().post('/api/frontend/audit', headers=h, json={'events': [
        {'action': 'vm.start', 'category': 'vms', 'userEmail': 'kim@example.com', 'resourceType': 'vm',
         'resourceName': 'web01', 'ipAddress': '10.0.0.7', 'details': {'node': 'pve1'}},
        {'action': 'Login\nfake line', 'userEmail': 'x', 'status': 'failure', 'errorMessage': 'bad password'},
        {'action': ''}, 'not a dict']})
    assert r.status_code == 200, r.data
    assert r.get_json() == {'accepted': 2}
    row = _rows(db, 'console.vm.start')[0]
    assert row['user'] == 'console:kim@example.com' and row['ip_address'] == '10.0.0.7'
    assert 'resource=vm web01' in row['details'] and '"node":"pve1"' in row['details']
    bad = _rows(db, 'console.login_fake_line')[0]
    assert '\n' not in bad['action'] and 'status=failure' in bad['details']


def test_a_session_and_a_viewer_token_are_refused(api, seed):
    seed.user('root', role='admin')
    assert api.as_user({'username': 'root', 'role': 'admin'}).post('/api/frontend/audit', json={'events': []}).status_code == 403
    viewer = _bearer(create_api_token('root', 'ro', role='viewer'))
    assert api.anon().post('/api/frontend/audit', headers=viewer, json={'events': []}).status_code == 403


def test_size_and_source_are_bounded(api, seed):
    seed.user('root', role='admin')
    h = _bearer(create_api_token('root', 'front', role='admin'))
    c = api.anon()
    assert c.post('/api/frontend/audit', headers=h, json={'events': [{'action': 'a'}] * 201}).status_code == 413
    assert c.post('/api/frontend/audit', headers=h, json={'source': 'Pega Prox', 'events': []}).status_code == 400


def test_an_admin_token_manages_siem_targets_and_a_masked_secret_is_kept(api, seed, db):
    seed.user('root', role='admin')
    h = _bearer(create_api_token('root', 'front', role='admin'))
    c = api.anon()
    r = c.post('/api/siem/targets', headers=h, json={'name': 'splunk', 'type': 'splunk_hec',
                                                    'endpoint': 'https://splunk.example:8088/services/collector',
                                                    'settings': {'token': 'REAL-SECRET', 'index': 'main'}})
    assert r.status_code == 200, r.data
    t = r.get_json()['target']
    assert t['settings']['token'] == '********'
    r = c.put(f"/api/siem/targets/{t['id']}", headers=h, json={'settings': {'token': '********', 'index': 'audit'}})
    assert r.status_code == 200, r.data
    stored = json.loads(db.conn.execute('SELECT settings FROM siem_targets WHERE id = ?', (t['id'],)).fetchone()['settings'])
    assert stored == {'token': 'REAL-SECRET', 'index': 'audit'}
    c.put(f"/api/siem/targets/{t['id']}", headers=h, json={'settings': {'token': 'NEW', 'index': 'audit'}})
    stored = json.loads(db.conn.execute('SELECT settings FROM siem_targets WHERE id = ?', (t['id'],)).fetchone()['settings'])
    assert stored['token'] == 'NEW'
