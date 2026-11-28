"""MOAVI Desk desktop sign-in (데스크톱 자동 로그인): the logon CA (pegaprox/vlab/logon_ca.py) and the
prepare -> sign -> arm flow over the guest agent (pegaprox/api/vlab_logon.py). The DC is the ldap3
mock of tests/test_vlab_directory.py, the guest agent a fake that answers like moavi-logon.exe."""
import base64
import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from pegaprox.api import vlab_logon
from pegaprox.vlab import directory, logon_ca, store
from test_vlab_directory import CID, _make, dc, env  # noqa: F401

UPN_OID = ObjectIdentifier('1.3.6.1.4.1.311.20.2.3')
SC_LOGON = ObjectIdentifier('1.3.6.1.4.1.311.20.2.2')


def _ca(cn='MOAVI Desk Logon CA', is_ca=True, bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    t = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(t - dt.timedelta(days=1))
            .not_valid_after(t + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    kpem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption()).decode()
    return cert, key, pem, kpem


def _csr(bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    req = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'MOAVI Logon')]))
           .sign(key, hashes.SHA256()))
    return key, req.public_bytes(serialization.Encoding.DER)


class _Resp:
    def __init__(self, data, status=200, text=''):
        self.status_code, self._data, self.text = status, data, text

    def json(self):
        return {'data': self._data}


class Guest:
    """A Windows guest agent with moavi-logon.exe: prepare answers a CSR of a key it keeps, arm
    checks the certificate is for that key."""

    def __init__(self, mgr):
        self.key, self.csr = _csr()
        self.nonce = 'ab' * 16
        self.installed = True
        self.os_id = 'mswindows'
        self.prev = ''
        self.ppl = 'off'
        self.ppl_off_set, self.locked, self.restarts = False, False, 0
        self.runs, self.armed, self._pids, self.files = [], None, {}, {}
        mgr._api_get.side_effect = self.get
        mgr._api_post.side_effect = self.post

    def post(self, url, data=None):
        self.runs.append((url, data))
        if url.endswith('/agent/file-write'):
            self.files[data['file']] = base64.b64decode(data['content'])
            return _Resp({})
        pid = len(self.runs)
        cmd = data['command']
        if cmd[0].endswith('moavi-logon.exe') and not self.installed:
            return _Resp(None, 500, 'CreateProcessW() failed: The system cannot find the file specified.')
        self._pids[pid] = (cmd, data.get('input-data'))
        return _Resp({'pid': pid})

    def get(self, url, params=None):
        if url.endswith('/agent/get-osinfo'):
            return _Resp({'result': {'id': self.os_id}})
        if url.endswith('/agent/exec-status'):
            cmd, stdin = self._pids[params['pid']]
            return _Resp(dict(exited=1, **self._answer(cmd, stdin)))
        return _Resp({}, 404)

    def _answer(self, cmd, stdin):
        if cmd[-1] == 'prepare':
            return {'exitcode': 0, 'out-data': self.prev + f"csr={base64.b64encode(self.csr).decode()}\nnonce={self.nonce}\nversion=1.0.0\n"}
        if cmd[-1] == 'arm':
            kv = dict(line.split('=', 1) for line in stdin.splitlines() if '=' in line)
            cert = x509.load_der_x509_certificate(base64.b64decode(kv['cert']))
            pub = serialization.PublicFormat.SubjectPublicKeyInfo
            if kv['nonce'] != self.nonce or cert.public_key().public_bytes(serialization.Encoding.DER, pub) != \
                    self.key.public_key().public_bytes(serialization.Encoding.DER, pub):
                return {'exitcode': 2, 'out-data': 'error=cert is not for this key\n'}
            self.armed = (kv, cert)
            return {'exitcode': 0, 'out-data': 'armed=ok\nthumb=00\n'}
        if cmd[-1] in ('clear', 'status'):
            return {'exitcode': 0, 'out-data': 'version=1.0.0\ncp=registered\nlsa_ppl=off\nstate=none\n'}
        if cmd[0] == 'shutdown.exe':
            self.restarts += 1
            if not self.locked:
                self.ppl = 'off' if self.ppl_off_set else self.ppl
            return {'exitcode': 0, 'out-data': ''}
        if cmd[0] == 'powershell.exe':
            script = cmd[-1]
            if 'RunAsPPL' in script:
                self.ppl_off_set = True
                return {'exitcode': 0, 'out-data': 'lsa_ppl_off=1\n'}
            if 'install.ps1' in script:
                return {'exitcode': 0, 'out-data': f'version={vlab_logon.MODULE_VERSION}\ncp=registered\nlsa_ppl={self.ppl}\nca=AB\ninstall=ok\n'}
            return {'exitcode': 0, 'out-data': 'dir=ok\n'}
        return {'exitcode': 1, 'out-data': ''}

    def execs(self):
        return [d for u, d in self.runs if u.endswith('/agent/exec')]


@pytest.fixture
def sso(env, monkeypatch):
    api, seed, admin, dc, _ = env
    mgr = api.make_fake_manager(CID, get_vm_resources=[
        {'vmid': 300, 'node': 'pve1', 'name': 'win-01', 'type': 'qemu', 'status': 'running'}])
    mgr.is_connected = True
    api.set_manager(CID, mgr)
    pool = admin.post('/api/vlab/admin/pools', json={'name': '사무', 'type': 'dedicated', 'cluster_id': CID}).get_json()['pool']
    desk = admin.post(f"/api/vlab/admin/pools/{pool['id']}/desktops", json={'vmid': 300}).get_json()['desktop']
    _make(admin)                                                    # alice, a directory account
    store.set_assignment(desk['id'], 'alice')
    directory.db().execute("INSERT OR REPLACE INTO vlab_directory_joins (desktop_id, state, code, computer, domain, os, at) "
                           "VALUES (?, 'joined', 'OK', 'MD-300', 'moavi.lan', 'windows', ?)", (desk['id'], store.now()))
    cert, key, pem, kpem = _ca()
    logon_ca.import_ca(pem, kpem)
    logon_ca.save_config(gateway_ips=['192.168.0.55'], crl_url='http://192.168.0.55:8089/moavi-logon.crl')
    g = Guest(mgr)
    monkeypatch.setattr(vlab_logon, 'ARM_WAIT', 2)
    monkeypatch.setattr(vlab_logon, 'PREPARE_WAIT', 2)
    return dict(api=api, seed=seed, admin=admin, mgr=mgr, pool=pool, desk=store.get_desktop(desk['id']),
                g=g, ca=cert, ca_key=key, ca_key_pem=kpem)


# --- the certificate ---------------------------------------------------------------------------

def test_the_certificate_is_a_short_lived_smart_card_logon_for_the_upn(sso):
    _key, csr = _csr()
    cert, serial, not_after = logon_ca.sign_request(csr, 'alice@moavi.lan', 'alice')
    now = dt.datetime.now(dt.timezone.utc)
    assert cert.issuer == sso['ca'].subject
    assert format(cert.serial_number, 'x') == serial
    assert dt.timedelta(minutes=4) < not_after - now <= dt.timedelta(minutes=5, seconds=2)   # TTL 5 min by default
    assert logon_ca._nb(cert) <= now - dt.timedelta(minutes=4)                                 # clocks a little off still work
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    upn = [n for n in san if isinstance(n, x509.OtherName) and n.type_id == UPN_OID]
    assert upn and upn[0].value == b'\x0c\x0falice@moavi.lan'
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert SC_LOGON in eku and ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature and ku.key_encipherment
    cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    assert cdp[0].full_name[0].value == 'http://192.168.0.55:8089/moavi-logon.crl'
    sso['ca'].public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                  __import__('cryptography.hazmat.primitives.asymmetric.padding', fromlist=['x']).PKCS1v15(),
                                  cert.signature_hash_algorithm)


def test_ttl_is_capped_and_bad_requests_are_refused(sso):
    _key, csr = _csr()
    cert, _s, not_after = logon_ca.sign_request(csr, 'alice@moavi.lan', 'alice', ttl_min=999)
    assert not_after - dt.datetime.now(dt.timezone.utc) <= dt.timedelta(minutes=logon_ca.MAX_TTL_MIN, seconds=2)
    with pytest.raises(logon_ca.LogonCAError) as e:
        logon_ca.sign_request(b'not a csr', 'alice@moavi.lan', 'alice')
    assert e.value.code == 'CSR_BAD'
    _k, small = _csr(bits=1024)
    with pytest.raises(logon_ca.LogonCAError):
        logon_ca.sign_request(small, 'alice@moavi.lan', 'alice')
    with pytest.raises(ValueError):
        logon_ca.save_config(ttl_min=60)
    with pytest.raises(ValueError):
        logon_ca.save_config(gateway_ips=['not-an-ip'])


# --- the CA key --------------------------------------------------------------------------------

def test_the_ca_key_is_sealed_and_never_answered(sso):
    seed, admin = sso['seed'], sso['admin']
    body = sso['ca_key_pem'].splitlines()[1]
    cur = seed.db.conn.cursor()
    for t in [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()]:
        for row in cur.execute(f'SELECT * FROM "{t}"').fetchall():
            assert body not in ' '.join(str(v) for v in tuple(row)), f'{t} holds the CA key in clear'
    r = admin.get('/api/vlab/admin/logon-sso')
    assert r.status_code == 200
    text = r.get_data(as_text=True)
    assert body not in text and 'PRIVATE KEY' not in text and 'key_encrypted' not in text
    assert r.get_json()['config']['ca']['subject'] == 'CN=MOAVI Desk Logon CA' and r.get_json()['config']['ready']


def test_import_checks_the_ca(sso):
    c1, k1, pem1, kpem1 = _ca()
    _c2, _k2, _pem2, kpem2 = _ca()
    with pytest.raises(logon_ca.LogonCAError) as e:
        logon_ca.import_ca(pem1, kpem2)
    assert e.value.code == 'CA_KEY_MISMATCH'
    _c3, _k3, pem3, kpem3 = _ca(is_ca=False)
    with pytest.raises(logon_ca.LogonCAError) as e:
        logon_ca.import_ca(pem3, kpem3)
    assert e.value.code == 'CA_NOT_CA'
    r = sso['admin'].post('/api/vlab/admin/logon-sso/ca', json={'cert_pem': pem1, 'key_pem': kpem1})
    assert r.status_code == 200 and r.get_json()['ca']['sha256'] == c1.fingerprint(hashes.SHA256()).hex()


def test_import_from_the_dc_files(sso, tmp_path, monkeypatch):
    logon_ca.db().execute('DELETE FROM vlab_logon_ca')
    c, k, pem, kpem = _ca()
    (tmp_path / 'ca.pem').write_text(pem)
    (tmp_path / 'ca.key').write_text(kpem)
    monkeypatch.setenv('VLAB_LOGON_CA_DIR', str(tmp_path))
    info, why = logon_ca.import_from_dir()
    assert why is None and info['source'].startswith('file:')
    assert (tmp_path / 'ca.key').read_text() == kpem                 # read only


# --- who gets one ------------------------------------------------------------------------------

def test_only_directory_accounts_on_joined_desktops(sso):
    desk = sso['desk']
    assert logon_ca.eligible('alice', desk['id']) == (True, '')
    assert logon_ca.eligible('root', desk['id'])[1] == 'NOT_DIRECTORY_ACCOUNT'      # a local portal account
    assert logon_ca.eligible('vlab-svc', desk['id'])[1] == 'NOT_DIRECTORY_ACCOUNT'  # the engine's own
    directory.db().execute("UPDATE vlab_directory_joins SET state = 'pending' WHERE desktop_id = ?", (desk['id'],))
    assert logon_ca.eligible('alice', desk['id'])[1] == 'NOT_JOINED'
    directory.db().execute("UPDATE vlab_directory_joins SET state = 'joined' WHERE desktop_id = ?", (desk['id'],))
    logon_ca.db().execute("UPDATE vlab_logon_config SET gateway_ips = ''")
    assert logon_ca.eligible('alice', desk['id'])[1] == 'NO_GATEWAY_IPS'


# --- prepare -> sign -> arm --------------------------------------------------------------------

def test_arm_signs_the_vms_own_key_and_audits(sso):
    g, desk = sso['g'], sso['desk']
    ok, code, info = vlab_logon.arm(desk, sso['mgr'], 'pve1', 'alice', portal_session='sess-123', client_ip='10.0.0.7')
    assert ok, (code, info)
    kv, cert = g.armed
    assert kv['gateways'] == '192.168.0.55' and kv['user'] == 'alice' and kv['domain'] == 'MOAVI'
    assert kv['upn'] == 'alice@moavi.lan'
    assert int(kv['not_after']) == int(logon_ca._na(cert).timestamp())
    assert 'PRIVATE' not in ''.join(str(d) for d in g.execs())        # no key goes to the VM or back
    rows = logon_ca.issued(desktop_id=desk['id'])
    assert len(rows) == 1 and rows[0]['state'] == 'armed' and rows[0]['username'] == 'alice'
    assert rows[0]['portal_session'] == logon_ca.session_ref('sess-123') and 'sess-123' not in rows[0]['portal_session']
    assert rows[0]['serial'] == info['serial'] == format(cert.serial_number, 'x')
    audit = sso['seed'].db.conn.execute("SELECT details FROM audit_log WHERE action = 'vlab.logon.issue'").fetchall()
    assert audit and info['serial'] in audit[-1][0] and 'alice@moavi.lan' in audit[-1][0]


def test_arm_without_the_module_says_so(sso):
    sso['g'].installed = False
    ok, code, _ = vlab_logon.arm(sso['desk'], sso['mgr'], 'pve1', 'alice')
    assert not ok and code == 'NOT_INSTALLED'
    assert logon_ca.issued() == []                                      # nothing signed


def test_a_certificate_for_another_key_is_refused_by_the_vm(sso):
    g = sso['g']
    _other, g.csr = _csr()                                               # the VM answers a request it has no key for
    ok, code, _ = vlab_logon.arm(sso['desk'], sso['mgr'], 'pve1', 'alice')
    assert not ok and code == 'ARM_FAILED'
    assert logon_ca.issued()[0]['state'] == 'arm_failed'


def test_portal_route_arms_only_with_the_pool_switch(sso):
    api, seed, admin = sso['api'], sso['seed'], sso['admin']
    alice = api.as_user(dict(seed.db.get_user('alice'), username='alice'))
    desk = sso['desk']
    r = alice.post(f"/api/vlab/me/desktops/{desk['id']}/logon-sso")
    assert r.status_code == 409 and r.get_json()['code'] == 'SSO_OFF'
    r = admin.put(f"/api/vlab/admin/pools/{desk['pool_id']}/policy", json={'desktop_sso': True})
    assert r.status_code == 200, r.get_json()
    r = alice.post(f"/api/vlab/me/desktops/{desk['id']}/logon-sso")
    assert r.status_code == 200, r.get_json()
    j = r.get_json()
    assert j['armed'] and j['upn'] == 'alice@moavi.lan' and 'cert' not in j
    assert admin.post(f"/api/vlab/me/desktops/{desk['id']}/logon-sso").status_code == 404   # not root's desktop


def test_install_pushes_checked_files_and_the_ca(sso):
    g, admin, desk = sso['g'], sso['admin'], sso['desk']
    r = admin.post(f"/api/vlab/admin/desktops/{desk['id']}/logon-sso/install")
    assert r.status_code == 200, r.get_json()
    names = {f.rsplit('\\', 1)[1].rsplit('.part', 1)[0] for f in g.files}
    assert names == {'moavi-logon.exe', 'moavi-logon-cp.dll', 'moavi-logon-csp.dll', 'install.ps1', 'moavi-logon-ca.cer'}
    ca = b''.join(v for k, v in sorted(g.files.items()) if 'moavi-logon-ca.cer' in k)
    assert x509.load_der_x509_certificate(ca).subject == sso['ca'].subject
    manifest = next(d['input-data'] for d in reversed(g.execs()) if d.get('input-data'))
    dirs = {f.rsplit('\\', 1)[0] for f in g.files}
    assert len(dirs) == 1 and next(iter(dirs)).startswith(vlab_logon.SETUP_DIR + '-')   # a folder of its own
    import hashlib
    exe = b''.join(v for k, v in sorted(g.files.items()) if 'moavi-logon.exe.part' in k)
    assert f"moavi-logon.exe|{-(-len(exe) // vlab_logon.PIECE)}|{hashlib.sha256(exe).hexdigest()}" in manifest
    assert 'PRIVATE' not in ''.join(str(d) for d in g.execs())


def test_policy_switch_is_a_bool(sso):
    from pegaprox.vlab import policy
    assert policy.DEFAULTS['desktop_sso'] is False
    assert policy.validate({'desktop_sso': 'yes'}, 'dedicated')[1]
    assert policy.validate({'desktop_sso': True}, 'dedicated')[0]['desktop_sso'] is True


def test_cli_imports_the_ca_from_stdin_and_switches_a_pool(sso, monkeypatch, capsys):
    import io
    logon_ca.db().execute('DELETE FROM vlab_logon_ca')
    c, _k, pem, kpem = _ca()
    monkeypatch.setattr('sys.stdin', io.StringIO(pem + kpem))
    assert logon_ca.main(['import-ca']) == 0
    out = capsys.readouterr().out
    assert c.fingerprint(hashes.SHA256()).hex() in out and kpem.splitlines()[1] not in out
    assert logon_ca.main(['set', '--gateways', '192.168.0.55', '--allow-admins', 'on']) == 0
    assert logon_ca.config()['allow_admins'] is True
    pool_id = sso['desk']['pool_id']
    assert logon_ca.main(['pool-sso', pool_id, 'on']) == 0
    from pegaprox.vlab import policy
    assert policy.effective(store.get_pool(pool_id)['settings'])['desktop_sso'] is True


def test_portal_admins_get_no_logon_certificate_unless_allowed(sso):
    from pegaprox.models.permissions import ROLE_ADMIN
    from pegaprox.utils.auth import load_users, save_users
    users = load_users()
    users['alice'] = dict(users['alice'], role=ROLE_ADMIN)
    save_users(users)
    assert logon_ca.eligible('alice', sso['desk']['id'])[1] == 'ADMIN_REFUSED'
    ok, code, _ = vlab_logon.arm(sso['desk'], sso['mgr'], 'pve1', 'alice')
    assert not ok and code == 'ADMIN_REFUSED' and logon_ca.issued() == []
    logon_ca.save_config(allow_admins=True)
    assert logon_ca.eligible('alice', sso['desk']['id']) == (True, '')


def test_a_failed_arm_never_blocks_the_connect(sso, monkeypatch):
    """The connect route goes on to the sign-in screen when arming fails, and says so in the audit."""
    pool = store.get_pool(sso['desk']['pool_id'])
    sso['admin'].put(f"/api/vlab/admin/pools/{pool['id']}/policy", json={'desktop_sso': True})
    pool = store.get_pool(pool['id'])
    sso['g'].installed = False
    with sso['api'].app.test_request_context('/'):
        assert vlab_logon.arm_for_connect(sso['desk'], sso['mgr'], 'pve1', 'alice', pool) is False
    rows = sso['seed'].db.conn.execute("SELECT details FROM audit_log WHERE action = 'vlab.logon.fail'").fetchall()
    assert rows and 'NOT_INSTALLED' in rows[-1][0]
    with sso['api'].app.test_request_context('/'):
        assert vlab_logon.arm_for_connect(sso['desk'], sso['mgr'], 'pve1', 'alice', None) is None   # switch off: nothing


def test_the_certificate_cannot_outlive_its_ttl_or_the_ca(sso):
    logon_ca.save_config(ttl_min=1)
    _k, csr = _csr()
    _c, _s, not_after = logon_ca.sign_request(csr, 'alice@moavi.lan', 'alice')
    assert not_after - dt.datetime.now(dt.timezone.utc) <= dt.timedelta(minutes=1, seconds=2)


# --- automatic install -------------------------------------------------------------------------

def _sso_on(sso):
    r = sso['admin'].put(f"/api/vlab/admin/pools/{sso['desk']['pool_id']}/policy", json={'desktop_sso': True})
    assert r.status_code == 200, r.get_json()


def _installs(g):
    return [d for d in g.execs() if d['command'][0] == 'powershell.exe' and 'install.ps1' in d['command'][-1]]


def test_the_module_version_is_the_built_one():
    import os
    exe = open(os.path.join(vlab_logon.AGENT_DIR, 'moavi-logon.exe'), 'rb').read()
    assert vlab_logon.MODULE_VERSION.encode('utf-16-le') in exe


def test_a_pool_with_desktop_sso_installs_its_windows_desktops_once(sso):
    g, desk = sso['g'], sso['desk']
    with sso['api'].app.app_context():
        assert vlab_logon.install_round() == {'installed': 0, 'failed': 0, 'waiting': 0, 'skipped': 0}   # switch off
    _sso_on(sso)
    with sso['api'].app.app_context():
        assert vlab_logon.install_round()['installed'] == 1
        r = logon_ca.install_of(desk['id'])
        assert r['state'] == 'installed' and r['version'] == vlab_logon.MODULE_VERSION
        assert vlab_logon.install_round()['installed'] == 0           # current: nothing again
    assert len(_installs(g)) == 1
    audit = sso['seed'].db.conn.execute("SELECT user, details FROM audit_log WHERE action = 'vlab.logon.install'").fetchall()
    assert audit[-1][0] == 'system' and 'win-01' in audit[-1][1]
    j = sso['admin'].get(f"/api/vlab/admin/pools/{desk['pool_id']}/logon-sso").get_json()
    assert j['desktop_sso'] and j['desktops'][0]['state'] == 'installed' and j['desktops'][0]['current']


def test_a_newer_engine_module_is_installed_again(sso, monkeypatch):
    _sso_on(sso)
    with sso['api'].app.app_context():
        vlab_logon.install_round()
        logon_ca.db().execute("UPDATE vlab_logon_installs SET version = '1.0.0'")
        assert vlab_logon.install_round()['installed'] == 1
    assert len(_installs(sso['g'])) == 2


def test_a_failed_install_waits_and_tries_again(sso, monkeypatch):
    _sso_on(sso)
    monkeypatch.setattr(vlab_logon, 'install', lambda desk, mgr, node: (False, 'error=Root store: denied'))
    with sso['api'].app.app_context():
        assert vlab_logon.install_round()['failed'] == 1
        r = logon_ca.install_of(sso['desk']['id'])
        assert r['state'] == 'failed' and r['attempts'] == 1 and r['next_at'] > __import__('time').time()
        assert vlab_logon.install_round()['failed'] == 0               # not due yet
        logon_ca.db().execute('UPDATE vlab_logon_installs SET next_at = 0')
        assert vlab_logon.install_round()['failed'] == 1
        assert logon_ca.install_of(sso['desk']['id'])['attempts'] == 2
    fails = sso['seed'].db.conn.execute("SELECT details FROM audit_log WHERE action = 'vlab.logon.install' AND details LIKE '%failed%'").fetchall()
    assert len(fails) == 1                                             # once per failure streak
    j = sso['admin'].get(f"/api/vlab/admin/pools/{sso['desk']['pool_id']}/logon-sso").get_json()
    assert j['desktops'][0]['state'] == 'failed' and 'Root store' in j['desktops'][0]['detail']


def test_reinstall_button_records_the_result(sso):
    r = sso['admin'].post(f"/api/vlab/admin/desktops/{sso['desk']['id']}/logon-sso/install")
    assert r.status_code == 200
    assert logon_ca.install_of(sso['desk']['id'])['state'] == 'installed'


def test_a_stopped_or_linux_desktop_is_not_installed(sso):
    _sso_on(sso)
    sso['g'].os_id = 'linux'
    with sso['api'].app.app_context():
        assert vlab_logon.install_round()['skipped'] == 1
        assert logon_ca.install_of(sso['desk']['id'])['state'] == 'skipped'
        assert vlab_logon.install_round() == {'installed': 0, 'failed': 0, 'waiting': 0, 'skipped': 0}
    assert _installs(sso['g']) == []


# --- the VM reports back; LSA protection; the devices route ---------------------------------------

def test_the_next_prepare_reports_what_became_of_the_last_certificate(sso):
    g, desk = sso['g'], sso['desk']
    ok, _c, first = vlab_logon.arm(desk, sso['mgr'], 'pve1', 'alice')
    assert ok
    thumb = g.armed[1].fingerprint(hashes.SHA1()).hex()
    g.prev = f'prev_thumb={thumb.upper()}\nprev_state=done\nprev_result=0x00000000/0x00000000\n'
    g.key, g.csr = _csr()
    assert vlab_logon.arm(desk, sso['mgr'], 'pve1', 'alice')[0]
    rows = {r['serial']: r for r in logon_ca.issued(desktop_id=desk['id'])}
    assert rows[first['serial']]['state'] == 'used' and '0x00000000' in rows[first['serial']]['detail']
    g.prev = f'prev_thumb={thumb}\nprev_state=failed\nprev_result=0xc000006d\n'
    g.key, g.csr = _csr()
    vlab_logon.arm(desk, sso['mgr'], 'pve1', 'alice')
    assert {r['serial']: r for r in logon_ca.issued(desktop_id=desk['id'])}[first['serial']]['state'] == 'used'   # final once reported


def _due_now(desk):
    r = logon_ca.install_of(desk['id'])
    logon_ca.record_install(desk['id'], desk['vmid'], r['version'], r['state'], r['code'], r['detail'], r['attempts'], 0)


def test_lsa_protection_is_turned_off_and_the_desktop_restarted(sso, monkeypatch):
    _sso_on(sso)
    g, desk = sso['g'], sso['desk']
    g.ppl = 'on'
    monkeypatch.setattr(store, 'open_sessions', lambda: [{'desktop_id': desk['id']}])     # alice is on it
    with sso['api'].app.app_context():
        vlab_logon.install_round()
    r = logon_ca.install_of(desk['id'])
    assert r['state'] == 'pending' and r['code'] == 'LSA_PPL_WAIT' and g.ppl_off_set and g.restarts == 0
    monkeypatch.setattr(store, 'open_sessions', lambda: [])
    _due_now(desk)
    with sso['api'].app.app_context():
        vlab_logon.install_round()
    r = logon_ca.install_of(desk['id'])
    assert r['state'] == 'pending' and r['code'] == 'LSA_PPL_RESTART' and g.restarts == 1
    _due_now(desk)
    with sso['api'].app.app_context():
        vlab_logon.install_round()
    assert logon_ca.install_of(desk['id'])['state'] == 'installed'                 # back up without LSA protection


def test_lsa_protection_under_a_uefi_lock_stays_unsupported(sso, monkeypatch):
    _sso_on(sso)
    g, desk = sso['g'], sso['desk']
    g.ppl, g.locked = 'on', True
    monkeypatch.setattr(store, 'open_sessions', lambda: [])
    with sso['api'].app.app_context():
        vlab_logon.install_round()
        _due_now(desk)
        vlab_logon.install_round()
    r = logon_ca.install_of(desk['id'])
    assert r['state'] == 'unsupported' and r['code'] == 'LSA_PPL_LOCKED' and g.restarts == 1
    ok, code, _ = vlab_logon.arm(desk, sso['mgr'], 'pve1', 'alice')
    assert not ok and logon_ca.issued() == []                                       # no certificate for it
    with sso['api'].app.app_context():
        assert vlab_logon.install_round()['installed'] == 0                         # not tried again for this version


def test_the_join_turns_lsa_protection_off_for_desktop_sign_in():
    assert 'RunAsPPL' in directory.windows_join_script('MD-300', True, lsa_off=True)
    assert 'RunAsPPL' not in directory.windows_join_script('MD-300', True)


def test_the_devices_route_rdp_asks_for_nothing_with_desktop_sign_in():
    from pegaprox.vlab import rdpgw
    cfg = {'host': 'gw.example:443'}
    plain = rdpgw.rdp_file_text(cfg, 'tok', '10.0.0.5', 3389, 'MOAVI\\alice')
    sso = rdpgw.rdp_file_text(cfg, 'tok', '10.0.0.5', 3389, 'MOAVI\\alice', sso=True)
    assert 'prompt for credentials:i:1' in plain and 'enablecredsspsupport' not in plain
    assert 'prompt for credentials:i:0' in sso and 'enablecredsspsupport:i:0' in sso and 'gatewayaccesstoken:s:tok' in sso


def test_nla_goes_off_once_for_the_devices_route(sso):
    g, desk = sso['g'], sso['desk']
    vlab_logon._nla_off.clear()
    orig = g._answer
    fw = {'out': 'rdp_fw=scoped rules=2 remote=192.168.0.55\n', 'rc': 0}

    def answer(cmd, stdin):
        if cmd[1:] == ['rdp-nla', 'off']:
            return {'exitcode': 0, 'out-data': 'rdp_nla=off changed=1\n'}
        if cmd[0] == 'powershell.exe' and '28752' in cmd[-1]:
            return {'exitcode': fw['rc'], 'out-data': fw['out']}
        return orig(cmd, stdin)
    g._answer = answer
    nla = lambda: sum(1 for d in g.execs() if d['command'][1:] == ['rdp-nla', 'off'])
    scopes = lambda: [d['command'][-1] for d in g.execs() if d['command'][0] == 'powershell.exe' and '28752' in d['command'][-1]]
    # the Windows firewall off: no scope, NLA stays on, the .rdp asks for the password as before
    fw.update(out='rdp_fw=error firewall_off=Domain\n', rc=3)
    assert vlab_logon.rdp_nla_off(desk, sso['mgr'], 'pve1') is False and nla() == 0
    fw.update(out='rdp_fw=scoped rules=2 remote=192.168.0.55\n', rc=0)
    assert vlab_logon.rdp_nla_off(desk, sso['mgr'], 'pve1') is True
    assert vlab_logon.rdp_nla_off(desk, sso['mgr'], 'pve1') is True
    assert nla() == 1 and len(scopes()) == 2 and "@('192.168.0.55')" in scopes()[-1]
    # the gateways change: scoped again before NLA
    logon_ca.save_config(gateway_ips=['192.168.0.55', '192.168.0.56'])
    assert vlab_logon.rdp_nla_off(desk, sso['mgr'], 'pve1') is True
    assert "@('192.168.0.55','192.168.0.56')" in scopes()[-1]
    acts = [r[0] for r in sso['seed'].db.conn.execute("SELECT details FROM audit_log WHERE action = 'vlab.logon.nla' ORDER BY id")]
    assert len(acts) == 3 and 'NLA stays on' in acts[0] and 'only from 192.168.0.55' in acts[1]


def test_one_install_at_a_time_per_desktop(sso):
    """The automatic round and a 다시 설치 click at once: the second one waits its turn, it does not
    empty the setup folder under the first one."""
    desk = sso['desk']
    vlab_logon._installing.add(desk['id'])
    try:
        ok, got = vlab_logon.install_and_record(desk, sso['mgr'], 'pve1')
        assert not ok and str(got).startswith('INSTALL_RUNNING') and sso['g'].execs() == []
    finally:
        vlab_logon._installing.discard(desk['id'])
    assert vlab_logon.install_and_record(desk, sso['mgr'], 'pve1')[0]


def test_a_certificate_armed_a_moment_ago_is_used_again(sso, monkeypatch):
    """The client arms the sign-in when the desktop is picked; the connect then only asks the VM
    whether it still holds it (one round trip) instead of prepare, sign and arm again."""
    _sso_on(sso)
    g, desk = sso['g'], sso['desk']
    from pegaprox.vlab import store
    pool = store.get_pool(desk['pool_id'])
    with sso['api'].app.test_request_context('/'):
        assert vlab_logon.arm(desk, sso['mgr'], 'pve1', 'alice')[0]
        orig = g._answer
        held = {'state': 'armed'}
        g._answer = lambda cmd, stdin: ({'exitcode': 0, 'out-data': f"version=1.3.4\ncp=registered\nlsa_ppl=off\nstate={held['state']}\n"}
                                        if cmd[-1] == 'status' else orig(cmd, stdin))
        prepares = lambda: sum(1 for d in g.execs() if d['command'][-1] == 'prepare')
        before = prepares()
        assert vlab_logon.arm_for_connect(desk, sso['mgr'], 'pve1', 'alice', pool) is True
        assert prepares() == before and len(logon_ca.issued(desktop_id=desk['id'])) == 1
        held['state'] = 'none'                         # used by a logon: armed afresh
        g.key, g.csr = _csr()
        assert vlab_logon.arm_for_connect(desk, sso['mgr'], 'pve1', 'alice', pool) is True
        assert prepares() == before + 1 and len(logon_ca.issued(desktop_id=desk['id'])) == 2


def test_the_connect_waits_for_an_arm_on_its_way_and_uses_it(sso):
    """The client arms ahead and connects 0.1 s later: the connect waits for that arm and uses it
    (no second prepare, no two arms overwriting each other in the VM)."""
    import threading
    _sso_on(sso)
    g, desk = sso['g'], sso['desk']
    from pegaprox.vlab import store
    pool = store.get_pool(desk['pool_id'])
    orig = g._answer
    held = {'state': 'none'}
    go = threading.Event()

    def answer(cmd, stdin):
        if cmd[-1] == 'status':
            return {'exitcode': 0, 'out-data': f"version=1.3.4\ncp=registered\nlsa_ppl=off\nstate={held['state']}\n"}
        if cmd[-1] == 'arm':
            go.wait(5)                                   # the ahead arm is slow in the VM
            held['state'] = 'armed'
        return orig(cmd, stdin)
    g._answer = answer
    with sso['api'].app.test_request_context('/'):
        ahead = threading.Thread(target=vlab_logon.arm, args=(desk, sso['mgr'], 'pve1', 'alice'))
        ahead.start()
        threading.Event().wait(0.3)
        threading.Timer(0.3, go.set).start()
        assert vlab_logon.arm_for_connect(desk, sso['mgr'], 'pve1', 'alice', pool) is True
        ahead.join(5)
    assert sum(1 for d in g.execs() if d['command'][-1] == 'prepare') == 1
    assert len(logon_ca.issued(desktop_id=desk['id'])) == 1


def test_expired_certificates_are_forgotten_after_a_month(sso):
    import datetime as dt
    desk = sso['desk']
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=40)).isoformat()
    logon_ca.db().execute("INSERT INTO vlab_logon_issued (serial, username, upn, desktop_id, vmid, issued_at, not_after, state) "
                          "VALUES ('old1', 'alice', 'alice@moavi.lan', ?, 300, ?, ?, 'used')", (desk['id'], old, old))
    with sso['api'].app.test_request_context('/'):
        assert vlab_logon.arm(desk, sso['mgr'], 'pve1', 'alice')[0]
    assert logon_ca.prune() == 1
    assert [r['serial'] for r in logon_ca.issued(desktop_id=desk['id'])] != ['old1'] and len(logon_ca.issued(desktop_id=desk['id'])) == 1
    assert vlab_logon.ARMS_AT_ONCE == 8
