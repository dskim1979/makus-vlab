# -*- coding: utf-8 -*-
"""
MOAVI Desk desktop sign-in (데스크톱 자동 로그인): the logon CA and its short-lived certificates.

Citrix FAS / VMware True SSO in shape, with the CA in the engine. A portal user opens a Windows
desktop of a pool with desktop_sso on; the engine then, through the guest agent (as SYSTEM):

  1. `moavi-logon.exe prepare` in the VM makes a fresh RSA key there (Microsoft Software KSP, machine
     key, SYSTEM only, not exportable) and answers its PKCS#10 request and a nonce;
  2. the engine signs it here with the MOAVI Desk Logon CA for that user's directory account: UPN in
     the SAN, EKU smart card logon + client auth, valid a few minutes (TTL), CRL distribution point;
  3. `moavi-logon.exe arm` puts the certificate next to its key with the gateway addresses the RDP
     session must come from. The credential provider in the VM then signs that one RDP session in
     with it (KERB_CERTIFICATE_LOGON -> PKINIT at the bundled DC) and throws both away.

No password is stored or sent anywhere. The CA key is sealed (get_db()._encrypt) and never leaves
this module: no API answer carries it. Every certificate is written to vlab_logon_issued and the
audit log (who, which desktop, which portal session, serial, until when).

Only accounts of the bundled directory (under its Users OU, so never the engine's own service
accounts) on a desktop joined to it get one. Docs: docs/desktop-sso.md.
"""

import datetime as _dt
import hashlib
import logging
import os
import threading

from pegaprox.vlab.store import db as _store_db, now

CA_ID = 'ca'
CONFIG_ID = 'cfg'

EKU_SMARTCARD_LOGON = '1.3.6.1.4.1.311.20.2.2'
OID_MS_UPN = '1.3.6.1.4.1.311.20.2.3'

DEFAULT_TTL_MIN = 5          # the certificate's life after it is issued
MAX_TTL_MIN = 30
BACKDATE_MIN = 5             # notBefore in the past: VM / DC clocks a little off still work
DEFAULT_CRL_URL = 'http://192.168.0.55:8089/moavi-logon.crl'

_SCHEMA = (
    # the CA: its certificate and its key, sealed
    '''CREATE TABLE IF NOT EXISTS vlab_logon_ca (
        id TEXT PRIMARY KEY,
        cert_pem TEXT NOT NULL DEFAULT '',
        key_encrypted TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT '',
        imported_at TEXT
    )''',
    # settings (one row): the CRL URL in each certificate, the gateway addresses RDP sessions come
    # from (what the VM sees as the client), the certificate's life
    '''CREATE TABLE IF NOT EXISTS vlab_logon_config (
        id TEXT PRIMARY KEY,
        crl_url TEXT NOT NULL DEFAULT '',
        gateway_ips TEXT NOT NULL DEFAULT '',
        ttl_min INTEGER NOT NULL DEFAULT 5,
        allow_admins INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT
    )''',
    # every certificate the CA signed
    '''CREATE TABLE IF NOT EXISTS vlab_logon_issued (
        serial TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        upn TEXT NOT NULL,
        desktop_id TEXT NOT NULL DEFAULT '',
        vmid INTEGER NOT NULL DEFAULT 0,
        portal_session TEXT NOT NULL DEFAULT '',
        client_ip TEXT NOT NULL DEFAULT '',
        issued_at TEXT NOT NULL,
        not_after TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'issued',
        detail TEXT NOT NULL DEFAULT ''
    )''',

    # the Windows module on each desktop (pegaprox/api/vlab_logon.py install_round): which version,
    # installed / failed / skipped, the next try
    '''CREATE TABLE IF NOT EXISTS vlab_logon_installs (
        desktop_id TEXT PRIMARY KEY,
        vmid INTEGER NOT NULL DEFAULT 0,
        version TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT '',
        code TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '',
        attempts INTEGER NOT NULL DEFAULT 0,
        next_at REAL NOT NULL DEFAULT 0,
        at TEXT NOT NULL DEFAULT ''
    )''',
)

TABLES = ('vlab_logon_ca', 'vlab_logon_config', 'vlab_logon_issued', 'vlab_logon_installs')

_lock = threading.Lock()


class LogonCAError(Exception):
    def __init__(self, message, code='LOGON_CA'):
        super().__init__(message)
        self.code = code


def db():
    d = _store_db()
    if not getattr(d, '_vlab_logon_ca', False):
        with _lock:
            if not getattr(d, '_vlab_logon_ca', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                try:    # the certificate's SHA-1, how the VM names it when it reports the logon back
                    d.execute("ALTER TABLE vlab_logon_issued ADD COLUMN thumb TEXT NOT NULL DEFAULT ''")
                except Exception:
                    pass
                d._vlab_logon_ca = True
    return d


# --- settings ----------------------------------------------------------------------------------

def _env_gateways():
    raw = os.environ.get('VLAB_LOGON_GATEWAY_IPS') or ''
    return [x.strip() for x in raw.split(',') if x.strip()]


def config():
    """Settings with defaults; never the CA key."""
    r = db().query_one('SELECT * FROM vlab_logon_config WHERE id = ?', (CONFIG_ID,))
    r = dict(r) if r else {}
    gws = [x for x in (r.get('gateway_ips') or '').split(',') if x] or _env_gateways()
    ca = ca_info()
    return {
        'crl_url': r.get('crl_url') or os.environ.get('VLAB_LOGON_CRL_URL') or DEFAULT_CRL_URL,
        'gateway_ips': gws,
        'ttl_min': int(r.get('ttl_min') or DEFAULT_TTL_MIN),
        'allow_admins': bool(r.get('allow_admins')),
        'ca': ca,
        'ready': bool(ca) and bool(gws),
    }


def _valid_ip(v):
    import ipaddress
    try:
        return ipaddress.ip_address(v).version == 4
    except ValueError:
        return False


def save_config(crl_url=None, gateway_ips=None, ttl_min=None, allow_admins=None):
    """None keeps the stored value. Raises ValueError on a bad value."""
    cur = db().query_one('SELECT * FROM vlab_logon_config WHERE id = ?', (CONFIG_ID,))
    cur = dict(cur) if cur else {'crl_url': '', 'gateway_ips': '', 'ttl_min': DEFAULT_TTL_MIN, 'allow_admins': 0}
    if crl_url is not None:
        crl_url = str(crl_url).strip()
        if crl_url and not crl_url.startswith('http://'):
            raise ValueError('crl_url: an http:// URL (Windows reads the CRL without TLS)')
        cur['crl_url'] = crl_url
    if gateway_ips is not None:
        if isinstance(gateway_ips, str):
            gateway_ips = [x.strip() for x in gateway_ips.split(',') if x.strip()]
        if not isinstance(gateway_ips, list) or any(not isinstance(x, str) or not _valid_ip(x) for x in gateway_ips) \
                or len(gateway_ips) > 16:
            raise ValueError('gateway_ips: up to 16 IPv4 addresses')
        cur['gateway_ips'] = ','.join(gateway_ips)
    if ttl_min is not None:
        if not isinstance(ttl_min, int) or isinstance(ttl_min, bool) or not 1 <= ttl_min <= MAX_TTL_MIN:
            raise ValueError(f'ttl_min: 1 to {MAX_TTL_MIN} minutes')
        cur['ttl_min'] = ttl_min
    if allow_admins is not None:
        if not isinstance(allow_admins, bool):
            raise ValueError('allow_admins must be true or false')
        cur['allow_admins'] = int(allow_admins)
    db().execute('INSERT OR REPLACE INTO vlab_logon_config (id, crl_url, gateway_ips, ttl_min, allow_admins, updated_at) '
                 'VALUES (?, ?, ?, ?, ?, ?)',
                 (CONFIG_ID, cur['crl_url'], cur['gateway_ips'], int(cur['ttl_min']), int(cur['allow_admins']), now()))
    return config()


# --- the CA ------------------------------------------------------------------------------------

def _ca_row():
    r = db().query_one('SELECT * FROM vlab_logon_ca WHERE id = ?', (CA_ID,))
    return dict(r) if r else None


def ca_info():
    """The CA certificate's public facts (subject, validity, SHA-256), or None."""
    r = _ca_row()
    if not r or not r['cert_pem'] or not r['key_encrypted']:
        return None
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    try:
        c = x509.load_pem_x509_certificate(r['cert_pem'].encode())
    except Exception:
        return None
    return {'subject': c.subject.rfc4514_string(), 'not_before': _iso(_nb(c)), 'not_after': _iso(_na(c)),
            'sha256': c.fingerprint(hashes.SHA256()).hex(), 'sha1': c.fingerprint(hashes.SHA1()).hex(),
            'source': r['source'], 'imported_at': r['imported_at']}


def ca_cert_pem():
    r = _ca_row()
    return r['cert_pem'] if r and r['key_encrypted'] else ''


def _nb(c):
    return getattr(c, 'not_valid_before_utc', None) or c.not_valid_before.replace(tzinfo=_dt.timezone.utc)


def _na(c):
    return getattr(c, 'not_valid_after_utc', None) or c.not_valid_after.replace(tzinfo=_dt.timezone.utc)


def _iso(t):
    return t.astimezone(_dt.timezone.utc).isoformat()


def import_ca(cert_pem, key_pem, source='import'):
    """Take the CA in: its certificate must be a CA (basicConstraints CA:true, keyCertSign) and the key
    its own (RSA). The key is sealed at once. Returns ca_info(). Raises LogonCAError."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from pegaprox.core.db import get_db
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem)
    except Exception:
        raise LogonCAError('the CA certificate is not a PEM certificate', 'CA_BAD_CERT')
    try:
        key = serialization.load_pem_private_key(key_pem.encode() if isinstance(key_pem, str) else key_pem, password=None)
    except Exception:
        raise LogonCAError('the CA key is not an unencrypted PEM private key', 'CA_BAD_KEY')
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise LogonCAError('the CA key must be RSA, 2048 bits or more', 'CA_BAD_KEY')
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(serialization.Encoding.DER, pub) != \
            cert.public_key().public_bytes(serialization.Encoding.DER, pub):
        raise LogonCAError('the key is not the certificate\'s', 'CA_KEY_MISMATCH')
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not bc.ca:
            raise LogonCAError('the certificate is not a CA (basicConstraints CA:false)', 'CA_NOT_CA')
    except x509.ExtensionNotFound:
        raise LogonCAError('the certificate is not a CA (no basicConstraints)', 'CA_NOT_CA')
    if _na(cert) <= _dt.datetime.now(_dt.timezone.utc):
        raise LogonCAError('the CA certificate has expired', 'CA_EXPIRED')
    key_text = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()).decode()
    sealed = get_db()._encrypt(key_text)
    if not sealed or sealed == key_text:
        raise LogonCAError('the engine could not seal the CA key', 'CA_SEAL')
    db().execute('INSERT OR REPLACE INTO vlab_logon_ca (id, cert_pem, key_encrypted, source, imported_at) VALUES (?, ?, ?, ?, ?)',
                 (CA_ID, cert.public_bytes(serialization.Encoding.PEM).decode(), sealed, source[:60], now()))
    return ca_info()


def ca_dir():
    """Where the bundled DC's PKI files are shared with the engine (VLAB_LOGON_CA_DIR, else the
    directory's files folder /pki)."""
    d = os.environ.get('VLAB_LOGON_CA_DIR')
    if d:
        return d
    from pegaprox.vlab import directory
    return os.path.join(directory.config()['files'], 'pki')


def import_from_dir(path=None):
    """The DC's CA (ca.pem + ca.key) taken in once when the engine has none: (info, None) or
    (None, reason). The files are only read, never changed."""
    if ca_info():
        return ca_info(), None
    path = path or ca_dir()
    cp, kp = os.path.join(path, 'ca.pem'), os.path.join(path, 'ca.key')
    if not (os.path.isfile(cp) and os.path.isfile(kp)):
        return None, f'no ca.pem / ca.key in {path}'
    try:
        with open(cp, 'rb') as f:
            cert = f.read()
        with open(kp, 'rb') as f:
            key = f.read()
        return import_ca(cert, key, source=f'file:{path}'), None
    except LogonCAError as e:
        return None, str(e)
    except OSError as e:
        return None, str(e)[:200]


def _ca_key():
    from cryptography.hazmat.primitives import serialization
    from pegaprox.core.db import get_db
    r = _ca_row()
    if not r or not r['key_encrypted']:
        raise LogonCAError('no logon CA in the engine', 'CA_MISSING')
    try:
        text = get_db()._decrypt(r['key_encrypted'])
        key = serialization.load_pem_private_key(text.encode(), password=None)
    except Exception:
        raise LogonCAError('the sealed CA key cannot be opened', 'CA_SEAL')
    from cryptography import x509
    return x509.load_pem_x509_certificate(r['cert_pem'].encode()), key


# --- issuing -----------------------------------------------------------------------------------

def session_ref(session_id):
    """The portal session a certificate was issued for, as a short hash (never the session id)."""
    return hashlib.sha256(('moavi-logon:' + (session_id or '')).encode()).hexdigest()[:16] if session_id else ''


def _upn_der(upn):
    """UTF8String DER of the UPN (the otherName value)."""
    b = upn.encode('utf-8')
    if len(b) < 128:
        return b'\x0c' + bytes([len(b)]) + b
    n = len(b).to_bytes((len(b).bit_length() + 7) // 8, 'big')
    return b'\x0c' + bytes([0x80 | len(n)]) + n + b


def sign_request(csr, upn, common_name, ttl_min=None, crl_url=None):
    """Sign a PKCS#10 request (DER or PEM) for `upn`. The request's subject and extensions are
    ignored: the CA writes its own. Returns (certificate, serial hex, not_after). Raises LogonCAError."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
    try:
        req = x509.load_der_x509_csr(csr) if isinstance(csr, (bytes, bytearray)) and not csr.startswith(b'-----') \
            else x509.load_pem_x509_csr(csr.encode() if isinstance(csr, str) else csr)
    except Exception:
        raise LogonCAError('the desktop\'s request is not a PKCS#10 request', 'CSR_BAD')
    if not req.is_signature_valid:
        raise LogonCAError('the desktop\'s request is not signed by its own key', 'CSR_BAD')
    pub = req.public_key()
    if not isinstance(pub, rsa.RSAPublicKey) or pub.key_size < 2048:
        raise LogonCAError('the desktop\'s key must be RSA, 2048 bits or more', 'CSR_BAD')
    cfg = config()
    ttl = int(ttl_min or cfg['ttl_min'])
    ttl = max(1, min(ttl, MAX_TTL_MIN))
    crl = cfg['crl_url'] if crl_url is None else crl_url
    ca_cert, ca_key = _ca_key()
    t = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    not_after = min(t + _dt.timedelta(minutes=ttl), _na(ca_cert))
    serial = x509.random_serial_number()
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, (common_name or upn)[:64])]))
         .issuer_name(ca_cert.subject)
         .public_key(pub)
         .serial_number(serial)
         .not_valid_before(t - _dt.timedelta(minutes=BACKDATE_MIN))
         .not_valid_after(not_after)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, content_commitment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ObjectIdentifier(EKU_SMARTCARD_LOGON), ExtendedKeyUsageOID.CLIENT_AUTH]),
                        critical=False)
         .add_extension(x509.SubjectAlternativeName([x509.OtherName(ObjectIdentifier(OID_MS_UPN), _upn_der(upn))]),
                        critical=False)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False))
    if crl:
        b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(crl)], relative_name=None, reasons=None, crl_issuer=None)]),
            critical=False)
    cert = b.sign(ca_key, hashes.SHA256())
    return cert, format(serial, 'x'), not_after


def upn_for(username):
    from pegaprox.vlab import directory
    return f"{username}@{directory.config()['realm'].lower()}"


def eligible(username, desktop_id):
    """(True, '') or (False, code): may this portal user get a logon certificate for this desktop?"""
    from pegaprox.vlab import directory
    if not ca_info():
        return False, 'CA_MISSING'
    if not config()['gateway_ips']:
        return False, 'NO_GATEWAY_IPS'
    if not directory.active():
        return False, 'NO_DIRECTORY'
    row = directory._rows().get(username)
    if not directory.owns(row):
        return False, 'NOT_DIRECTORY_ACCOUNT'
    if not directory.NAME.match(username or ''):
        return False, 'NOT_DIRECTORY_ACCOUNT'
    from pegaprox.models.permissions import ROLE_ADMIN
    if row.get('role') == ROLE_ADMIN and not config()['allow_admins']:
        return False, 'ADMIN_REFUSED'
    if row.get('enabled') is False or row.get('disabled'):
        return False, 'ACCOUNT_DISABLED'
    j = directory.join_of(desktop_id)
    if not j or j.get('state') != 'joined':
        return False, 'NOT_JOINED'
    return True, ''


def issue(username, desktop, csr, portal_session='', client_ip=''):
    """A logon certificate for this user on this desktop, written down and audited. Returns
    {'cert_der', 'serial', 'not_after' (datetime), 'upn'}. Raises LogonCAError."""
    from cryptography.hazmat.primitives import serialization
    from pegaprox.utils.audit import log_audit
    ok, code = eligible(username, desktop['id'])
    if not ok:
        raise LogonCAError(f'no logon certificate for {username}: {code}', code)
    upn = upn_for(username)
    cert, serial, not_after = sign_request(csr, upn, username)
    sref = session_ref(portal_session)
    thumb = cert.fingerprint(__import__('cryptography.hazmat.primitives.hashes', fromlist=['SHA1']).SHA1()).hex()
    db().execute('INSERT INTO vlab_logon_issued (serial, username, upn, desktop_id, vmid, portal_session, client_ip, '
                 'issued_at, not_after, state, thumb) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                 (serial, username, upn, desktop['id'], int(desktop.get('vmid') or 0), sref, (client_ip or '')[:64],
                  now(), _iso(not_after), 'issued', thumb))
    log_audit(username, 'vlab.logon.issue',
              f"desktop sign-in certificate for '{desktop.get('name')}' (qemu/{desktop.get('vmid')}): {upn}, "
              f"serial {serial}, valid until {_iso(not_after)}, portal session {sref or '-'}", client_ip or '')
    return {'cert_der': cert.public_bytes(serialization.Encoding.DER), 'serial': serial,
            'not_after': not_after, 'upn': upn}


VM_STATES = {'done': 'used', 'used': 'used', 'failed': 'failed', 'expired': 'expired', 'armed': 'expired'}


def mark_reported(desktop_id, thumb, vm_state, result=''):
    """The VM's word on an earlier certificate of this desktop (moavi-logon.exe prepare reports the
    previous logon): used / failed (with Windows' status) / expired unused."""
    state = VM_STATES.get(vm_state)
    if not state or not thumb:
        return False
    r = db().execute('UPDATE vlab_logon_issued SET state = ?, detail = ? WHERE desktop_id = ? AND thumb = ? '
                     "AND state IN ('issued', 'armed')", (state, (f'logon {result}' if result else '')[:300],
                                                          desktop_id, thumb.lower()))
    return bool(getattr(r, 'rowcount', 1))


def mark(serial, state, detail=''):
    db().execute('UPDATE vlab_logon_issued SET state = ?, detail = ? WHERE serial = ?', (state, (detail or '')[:300], serial))


def issued(limit=100, username=None, desktop_id=None):
    q, args = 'SELECT * FROM vlab_logon_issued', []
    cond = []
    if username:
        cond.append('username = ?')
        args.append(username)
    if desktop_id:
        cond.append('desktop_id = ?')
        args.append(desktop_id)
    if cond:
        q += ' WHERE ' + ' AND '.join(cond)
    q += ' ORDER BY issued_at DESC LIMIT ?'
    args.append(int(limit))
    return [dict(r) for r in db().query(q, tuple(args)) or []]


def install_of(desktop_id):
    r = db().query_one('SELECT * FROM vlab_logon_installs WHERE desktop_id = ?', (desktop_id,))
    return dict(r) if r else None


def installs(desktop_ids=None):
    rows = {r['desktop_id']: dict(r) for r in db().query('SELECT * FROM vlab_logon_installs') or []}
    return rows if desktop_ids is None else {d: rows[d] for d in desktop_ids if d in rows}


def record_install(desktop_id, vmid, version, state, code='', detail='', attempts=0, next_at=0.0):
    db().execute('INSERT OR REPLACE INTO vlab_logon_installs (desktop_id, vmid, version, state, code, detail, attempts, '
                 'next_at, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                 (desktop_id, int(vmid or 0), version or '', state, code or '', (detail or '')[:300], int(attempts),
                  float(next_at), now()))


def forget_install(desktop_id):
    db().execute('DELETE FROM vlab_logon_installs WHERE desktop_id = ?', (desktop_id,))


def startup_import():
    """At engine start: take the DC's CA in if the engine has none yet (quiet when there is none)."""
    try:
        info, why = import_from_dir()
        if info and why is None:
            logging.info(f"[VLAB] desktop sign-in CA: {info['subject']} ({info['source']})")
    except Exception as e:
        logging.warning(f"[VLAB] desktop sign-in CA not imported: {str(e)[:200]}")


# --- command line (inside the engine container: python -m pegaprox.vlab.logon_ca ...) ---------

def _split_pem(text):
    import re
    cert = re.search(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', text, re.S)
    key = re.search(r'-----BEGIN (?:RSA |)PRIVATE KEY-----.+?-----END (?:RSA |)PRIVATE KEY-----', text, re.S)
    return (cert.group(0) + '\n' if cert else ''), (key.group(0) + '\n' if key else '')


def main(argv=None):
    """  import-ca                 stdin: the CA certificate and its key (PEM); the key is sealed, never printed
      set [--gateways a,b] [--ttl N] [--crl URL] [--allow-admins on|off]
      pool-sso <pool_id> on|off  the pool's desktop_sso switch (the rest of its policy kept)
      status"""
    import argparse
    import json
    import sys
    from pegaprox.utils.audit import log_audit
    p = argparse.ArgumentParser(prog='python -m pegaprox.vlab.logon_ca', description='MOAVI Desk desktop sign-in CA')
    sub = p.add_subparsers(dest='cmd', required=True)
    sub.add_parser('import-ca')
    s = sub.add_parser('set')
    s.add_argument('--gateways')
    s.add_argument('--ttl', type=int)
    s.add_argument('--crl')
    s.add_argument('--allow-admins', choices=('on', 'off'))
    ps = sub.add_parser('pool-sso')
    ps.add_argument('pool_id')
    ps.add_argument('state', choices=('on', 'off'))
    sub.add_parser('status')
    a = p.parse_args(argv)
    if a.cmd == 'import-ca':
        cert, key = _split_pem(sys.stdin.read())
        if not cert or not key:
            print('error: stdin needs the CA certificate and its private key (PEM)')
            return 2
        try:
            info = import_ca(cert, key, source='cli')
        except LogonCAError as e:
            print(f'error: {e} ({e.code})')
            return 1
        log_audit('cli', 'vlab.logon.ca', f"desktop sign-in CA {info['subject']} sha256 {info['sha256'][:16]} (cli)", '')
        print(json.dumps(info, indent=1))
        return 0
    if a.cmd == 'set':
        try:
            cfg = save_config(crl_url=a.crl, gateway_ips=a.gateways, ttl_min=a.ttl,
                              allow_admins=None if a.allow_admins is None else a.allow_admins == 'on')
        except ValueError as e:
            print(f'error: {e}')
            return 2
        log_audit('cli', 'vlab.logon.config', f"desktop sign-in: gateways {','.join(cfg['gateway_ips']) or '-'}, "
                  f"ttl {cfg['ttl_min']} min, admins {cfg['allow_admins']}", '')
        print(json.dumps(cfg, indent=1))
        return 0
    if a.cmd == 'pool-sso':
        from pegaprox.vlab import store
        pool = store.get_pool(a.pool_id)
        if not pool:
            print('error: no such pool')
            return 2
        settings = dict(pool.get('settings') or {})
        pol = dict(settings.get('policy') or {})
        pol['desktop_sso'] = a.state == 'on'
        settings['policy'] = pol
        store.set_pool_settings(pool['id'], settings)
        log_audit('cli', 'vlab.pool.policy', f"pool '{pool['name']}': desktop_sso={pol['desktop_sso']}", '')
        print(f"pool {pool['name']}: desktop_sso={pol['desktop_sso']}")
        return 0
    print(json.dumps({'config': config(), 'issued': issued(10)}, indent=1, default=str))
    return 0


if __name__ == '__main__':
    import sys as _sys
    _sys.exit(main())
