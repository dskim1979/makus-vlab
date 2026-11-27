# -*- coding: utf-8 -*-
"""
MOAVI Desk - a minimal OpenID Connect provider for one client: the bundled Warpgate.

Warpgate's web UI asks its users to sign in before it opens a desktop. With this, Warpgate sends the
browser here (an sso_providers entry, type custom) and MOAVI Desk answers from the portal session the
user already has - no Warpgate password exists or is typed. The portal's 보안 게이트웨이 link then
opens the desktop with at most one click on "MOAVI Desk" in Warpgate's login page, and none while
Warpgate's own session lasts.

What Warpgate 0.29.2 needs (warpgate-sso, openidconnect-rs): discovery at
<issuer>/.well-known/openid-configuration, an RS256 ID token with iss/aud/exp/iat/nonce/sub/email,
PKCE S256, client_secret_basic at the token endpoint; userinfo is read if it is there. A Warpgate user
is matched by its SSO credential (provider name + e-mail), which ensure_user adds - the e-mail is a
fixed per-user name (sso_email), not the user's real address.

- The client secret comes from the environment (VLAB_WARPGATE_OIDC_SECRET, the same value in
  warpgate.yaml); unset = the provider is off and every endpoint answers 404.
- The issuer is the URL Warpgate itself fetches (VLAB_WARPGATE_OIDC_ISSUER, default the engine on
  the compose network); the authorize endpoint is the console address the browser uses.
- The RSA signing key is made once and kept sealed (get_db()._encrypt) in vlab_wg_oidc, so an HA
  standby signs with the same key.
- Authorization codes and access tokens live in memory, single use, a minute / five minutes.
"""

import base64
import hashlib
import hmac
import os
import secrets
import threading
import time

from pegaprox.vlab.store import db as _store_db, now

PROVIDER_NAME = 'moavi-desk'          # sso_providers[].name in warpgate.yaml
CLIENT_ID = 'warpgate'
SSO_EMAIL_DOMAIN = 'moavi-desk.invalid'
RETURN_PATH = '/@warpgate/api/sso/return'
CODE_TTL = 60
TOKEN_TTL = 300
ID_TOKEN_TTL = 300

_SCHEMA = '''CREATE TABLE IF NOT EXISTS vlab_wg_oidc (
    id TEXT PRIMARY KEY,
    kid TEXT NOT NULL,
    private_key_encrypted TEXT NOT NULL,
    created_at TEXT
)'''

_lock = threading.Lock()
_codes = {}      # code -> {user, redirect_uri, nonce, challenge, exp}
_tokens = {}     # access token -> {user, exp}


def db():
    d = _store_db()
    if not getattr(d, '_vlab_wg_oidc', False):
        with _lock:
            if not getattr(d, '_vlab_wg_oidc', False):
                d.execute(_SCHEMA)
                d._vlab_wg_oidc = True
    return d


# --- settings ----------------------------------------------------------------------------

def client_secret():
    return os.environ.get('VLAB_WARPGATE_OIDC_SECRET', '').strip()


def is_enabled():
    return bool(client_secret())


def issuer():
    v = os.environ.get('VLAB_WARPGATE_OIDC_ISSUER', '').strip().rstrip('/')
    return v or 'http://vlab-engine:5000/api/vlab/oidc'


def public_base():
    """The console address the browser uses (the authorize endpoint must see the portal cookie)."""
    v = os.environ.get('VLAB_PUBLIC_URL', '').strip().rstrip('/')
    if v:
        return v
    host = os.environ.get('VLAB_HOSTNAME', '').strip() or 'vlab.local'
    port = os.environ.get('VLAB_HTTPS_PORT', '443').strip()
    return f'https://{host}' + ('' if port in ('', '443') else f':{port}')


def sso_email(username):
    """The e-mail Warpgate matches the user's SSO credential on: fixed per user, never a real address
    (of the normalised identity: MOAVI\\admin and admin are one)."""
    from pegaprox.vlab.warpgate import WarpgateError, portal_id
    try:
        username = portal_id(username)
    except WarpgateError:
        pass
    return f'{username}@{SSO_EMAIL_DOMAIN}'


def metadata():
    iss = issuer()
    return {
        'issuer': iss,
        'authorization_endpoint': public_base() + '/api/vlab/oidc/authorize',
        'token_endpoint': iss + '/token',
        'userinfo_endpoint': iss + '/userinfo',
        'jwks_uri': iss + '/jwks',
        'response_types_supported': ['code'],
        'grant_types_supported': ['authorization_code'],
        'subject_types_supported': ['public'],
        'id_token_signing_alg_values_supported': ['RS256'],
        'scopes_supported': ['openid', 'email', 'profile'],
        'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post'],
        'code_challenge_methods_supported': ['S256'],
        'claims_supported': ['sub', 'email', 'email_verified', 'preferred_username', 'name'],
    }


def redirect_allowed(redirect_uri, warpgate_base_url):
    """Only Warpgate's own SSO return URL, on the host Warpgate is configured with."""
    from urllib.parse import urlparse
    u, w = urlparse(redirect_uri or ''), urlparse(warpgate_base_url or '')
    return (u.scheme in ('http', 'https') and bool(u.hostname) and u.hostname == w.hostname
            and u.path == RETURN_PATH and not u.fragment)


# --- signing key -------------------------------------------------------------------------

def _key():
    """(kid, private key object); made once and sealed."""
    from cryptography.hazmat.primitives import serialization
    from pegaprox.core.db import get_db
    r = db().query_one('SELECT * FROM vlab_wg_oidc WHERE id = ?', ('key',))
    if r:
        pem = get_db()._decrypt(r['private_key_encrypted'])
        return r['kid'], serialization.load_pem_private_key(pem.encode(), password=None)
    from cryptography.hazmat.primitives.asymmetric import rsa
    with _lock:
        r = db().query_one('SELECT * FROM vlab_wg_oidc WHERE id = ?', ('key',))
        if r:
            pem = get_db()._decrypt(r['private_key_encrypted'])
            return r['kid'], serialization.load_pem_private_key(pem.encode(), password=None)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
        kid = secrets.token_hex(8)
        db().execute('INSERT INTO vlab_wg_oidc (id, kid, private_key_encrypted, created_at) VALUES (?, ?, ?, ?)',
                     ('key', kid, get_db()._encrypt(pem), now()))
        return kid, key


def _b64u_int(n):
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def jwks():
    kid, key = _key()
    pub = key.public_key().public_numbers()
    return {'keys': [{'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': kid,
                      'n': _b64u_int(pub.n), 'e': _b64u_int(pub.e)}]}


# --- the flow ----------------------------------------------------------------------------

def _sweep(store):
    t = time.time()
    for k in [k for k, v in store.items() if v['exp'] < t]:
        store.pop(k, None)


def issue_code(username, redirect_uri, nonce, code_challenge):
    code = secrets.token_urlsafe(32)
    with _lock:
        _sweep(_codes)
        _codes[code] = {'user': username, 'redirect_uri': redirect_uri, 'nonce': nonce,
                        'challenge': code_challenge, 'exp': time.time() + CODE_TTL}
    return code


def check_client(client_id, secret):
    want = client_secret()
    return bool(want) and client_id == CLIENT_ID and hmac.compare_digest(str(secret or ''), want)


def _pkce_ok(challenge, verifier):
    if not challenge:
        return True
    if not verifier:
        return False
    digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    return hmac.compare_digest(digest, challenge)


def redeem_code(code, redirect_uri, code_verifier):
    """The token response for a code (single use), or None when the code is unknown, spent, expired,
    for another redirect URI or fails PKCE."""
    import jwt
    with _lock:
        _sweep(_codes)
        c = _codes.pop(code or '', None)
    if not c or c['redirect_uri'] != redirect_uri or not _pkce_ok(c['challenge'], code_verifier):
        return None
    access = secrets.token_urlsafe(32)
    with _lock:
        _sweep(_tokens)
        _tokens[access] = {'user': c['user'], 'exp': time.time() + TOKEN_TTL}
    kid, key = _key()
    t = int(time.time())
    claims = {'iss': issuer(), 'aud': CLIENT_ID, 'sub': c['user'], 'iat': t, 'exp': t + ID_TOKEN_TTL,
              'email': sso_email(c['user']), 'email_verified': True, 'preferred_username': c['user'],
              'name': c['user']}
    if c['nonce']:
        claims['nonce'] = c['nonce']
    id_token = jwt.encode(claims, key, algorithm='RS256', headers={'kid': kid})
    return {'access_token': access, 'token_type': 'Bearer', 'expires_in': TOKEN_TTL, 'id_token': id_token,
            'scope': 'openid email profile'}


def userinfo(access_token):
    with _lock:
        _sweep(_tokens)
        t = _tokens.get(access_token or '')
    if not t:
        return None
    u = t['user']
    return {'sub': u, 'email': sso_email(u), 'email_verified': True, 'preferred_username': u, 'name': u}


def warpgate_yaml_snippet(secret_placeholder='${VLAB_WARPGATE_OIDC_SECRET}'):
    """The sso_providers entry for warpgate.yaml (the secret is a placeholder, never the value)."""
    return (f'sso_providers:\n'
            f'  - name: {PROVIDER_NAME}\n'
            f'    label: MOAVI Desk\n'
            f'    provider:\n'
            f'      type: custom\n'
            f'      client_id: {CLIENT_ID}\n'
            f'      client_secret: {secret_placeholder}\n'
            f'      issuer_url: {issuer()}\n'
            f'      scopes: [email, profile]\n')
