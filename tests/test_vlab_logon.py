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
            return _Resp({'result': {'id': 'mswindows'}})
        if url.endswith('/agent/exec-status'):
            cmd, stdin = self._pids[params['pid']]
            return _Resp(dict(exited=1, **self._answer(cmd, stdin)))
        return _Resp({}, 404)

    def _answer(self, cmd, stdin):
        if cmd[-1] == 'prepare':
            return {'exitcode': 0, 'out-data': f"csr={base64.b64encode(self.csr).decode()}\nnonce={self.nonce}\nversion=1.0.0\n"}
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
        if cmd[0] == 'powershell.exe':
            script = cmd[-1]
            if 'install.ps1' in script:
                return {'exitcode': 0, 'out-data': 'version=1.0.0\ncp=registered\nca=AB\ninstall=ok\n'}
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
    assert names == {'moavi-logon.exe', 'moavi-logon-cp.dll', 'moavi-logon-ksp.dll', 'moavi-logon-csp.dll', 'install.ps1', 'moavi-logon-ca.cer'}
    ca = b''.join(v for k, v in sorted(g.files.items()) if 'moavi-logon-ca.cer' in k)
    assert x509.load_der_x509_certificate(ca).subject == sso['ca'].subject
    manifest = g.execs()[-1]['input-data']
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
