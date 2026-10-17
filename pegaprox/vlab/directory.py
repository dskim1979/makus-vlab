# -*- coding: utf-8 -*-
"""
MOAVI Desk - the bundled directory (내장 디렉터리): an optional Samba AD DC that comes with the
compose install (VLAB_DIRECTORY=1) for a site without Active Directory, so that the portal
account is the desktop account there too - the same way a site with its own AD has it.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

What lives where (the DC's start script, deploy/directory/entrypoint.sh in the console
repository, makes the layout; the engine only works inside OU=MOAVI):

  OU=Users,OU=MOAVI,<base>     one account per portal account (sAMAccountName = the username,
                               info = moavi-desk). Portal sign-in looks here and nowhere else.
  OU=Groups,OU=MOAVI,<base>    moavi-users (every portal account) and one group per department
                               (dep-<id>, the department's name as description; a sub-department's
                               group is a member of its parent's), so a pool grant to an "AD group"
                               and a GPO or a NAS ACL work on departments.
  OU=Desktops,OU=MOAVI,<base>  the desktops the engine joined (vlab-join may make computers here only)
  OU=Service,OU=MOAVI,<base>   vlab-svc (the engine's own account, full control of OU=MOAVI, its
                               password in the vlab-directory-out volume) and vlab-join

The portal decides, the directory follows:

  * an account the portal makes (one by one, by CSV import, by an approved sign-up) gets its
    directory account at once, with the password given at that moment; an account made while the
    DC was away, or made before the directory was turned on, moves over at its owner's next
    sign-in (the password they typed is written to the directory then). Administrators stay
    portal-local unless include_admins: the console must stay reachable when the DC is not.
  * disabled, enabled, renamed, moved to another department, deleted - pushed right away, and a
    reconcile every RECONCILE_EVERY seconds on the active instance puts back whatever drifted.
  * the portal's row of a directory account is auth_source 'ldap' with its ldap_dn under
    OU=Users,OU=MOAVI and no password hash; sign-in is the core's LDAP sign-in (pegaprox/utils/ldap.py), pointed at this DC
    by ldap_settings() while the site has no LDAP of its own configured.

Passwords: the engine never keeps, logs or stores a user's password. It passes through in the
request that carries it (sign-up, the reset link, 내 계정, an admin's reset, the first sign-in
of a moved account) straight to the DC's own password operation (unicodePwd over LDAPS) and is
gone with that request. A sign-up waiting for review therefore already has its (disabled)
directory account holding the password; the review only enables it. Nothing here stores a
desktop password for an automatic sign-in, and nothing should.

Desktops join the domain through the QEMU guest agent (pegaprox/api/vlab_directory.py):
Windows with Add-Computer, Linux with realm join (sssd). The join account's password is made by
the engine, set on the DC and kept sealed with the core DB key (vlab_directory_secrets), like the
NAS service account in pegaprox/vlab/nas.py; it reaches the guest on the agent's stdin only.
"""

import logging
import os
import re
import secrets
import ssl
import string
import threading
import time
from contextlib import contextmanager

from pegaprox.vlab.store import db as _store_db, now

SERVICE_USER = 'vlab-svc'
JOIN_USER = 'vlab-join'
ALL_GROUP = 'moavi-users'
MARK = 'moavi-desk'                 # info= on what the engine made: only those it deletes
SIGNUP_PREFIX = 'signup:'           # description= of an account waiting for its sign-up review
SIGNUP_SALT = 'directory'           # vlab_signups.password_salt of a request whose password is on the DC
RECONCILE_EVERY = 600
CONNECT_TIMEOUT = 8

# sAMAccountName of a user is at most 20 characters
NAME = re.compile(r'^[a-z0-9][a-z0-9._-]{0,19}$')
_COMPUTER = re.compile(r'^[A-Za-z0-9][A-Za-z0-9-]{0,14}$')

UAC_NORMAL = 0x0200
UAC_DISABLED = 0x0002
UAC_DONT_EXPIRE = 0x10000
GROUP_GLOBAL_SECURITY = -2147483646

# exit status of the guest join scripts
JOIN_CODES = {0: 'OK', 21: 'OTHER_DOMAIN', 22: 'NO_DNS', 23: 'JOIN_FAILED', 24: 'NO_TOOLS', 25: 'RENAME_FAILED'}

SETTINGS_KEY = 'vlab_directory'
SETTING_DEFAULTS = {
    'include_admins': False,            # administrators get a directory account too
    'desktop_dns': [],                  # DNS servers a join sets on the desktop; [] = the DC's address
    'set_dns': True,                    # a join points the desktop's DNS at the DC (else DHCP must)
    'computer_name': 'MD-{vmid}',       # a desktop's name in the domain (15 characters at most)
    'rdp_group': True,                  # moavi-users in the desktop's Remote Desktop Users (Windows)
    'migrate_on_login': True,           # a local account moves to the directory at its next sign-in
}

_SCHEMA = (
    # the sealed passwords of the engine's two accounts: id 'bind' (vlab-svc), 'join' (vlab-join)
    '''CREATE TABLE IF NOT EXISTS vlab_directory_secrets (
        id TEXT PRIMARY KEY,
        secret_encrypted TEXT NOT NULL DEFAULT '',
        updated_at TEXT NOT NULL
    )''',
    # the last push of each portal account: ok, the code and the server's own message
    '''CREATE TABLE IF NOT EXISTS vlab_directory_accounts (
        username TEXT PRIMARY KEY,
        ok INTEGER NOT NULL DEFAULT 0,
        code TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '',
        dn TEXT NOT NULL DEFAULT '',
        at TEXT NOT NULL
    )''',
    # the domain join of each desktop
    '''CREATE TABLE IF NOT EXISTS vlab_directory_joins (
        desktop_id TEXT PRIMARY KEY,
        state TEXT NOT NULL DEFAULT '',
        code TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '',
        computer TEXT NOT NULL DEFAULT '',
        domain TEXT NOT NULL DEFAULT '',
        os TEXT NOT NULL DEFAULT '',
        at TEXT NOT NULL
    )''',
)
TABLES = ('vlab_directory_secrets', 'vlab_directory_accounts', 'vlab_directory_joins')

_lock = threading.Lock()
_last_reconcile = [0.0]


class DirectoryError(Exception):
    """code: NOT_ON, NO_SERVICE_ACCOUNT, UNREACHABLE, PASSWORD_REFUSED, WRONG_PASSWORD, NOT_FOUND,
    EXISTS, DENIED, BAD_NAME, FAILED. detail: the DC's own message - never a password."""

    def __init__(self, code, detail=''):
        super().__init__(f'{code}: {detail}' if detail else code)
        self.code, self.detail = code, (detail or '')[:300]


def db():
    d = _store_db()
    if not getattr(d, '_vlab_directory', False):
        with _lock:
            if not getattr(d, '_vlab_directory', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_directory = True
    return d


# --- configuration -------------------------------------------------------------------------

def _env_on():
    return os.environ.get('VLAB_DIRECTORY', '').strip().lower() not in ('', '0', 'false', 'no', 'off')


def _settings():
    from pegaprox.api.helpers import load_server_settings
    return load_server_settings() or {}


def settings():
    saved = _settings().get(SETTINGS_KEY) or {}
    out = dict(SETTING_DEFAULTS)
    out.update({k: saved[k] for k in SETTING_DEFAULTS if k in saved})
    return out


def clean_settings(data):
    """The settings after a PUT: keys left out stay. ValueError on a bad one."""
    out = settings()
    extra = sorted(k for k in data if k not in SETTING_DEFAULTS)
    if extra:
        raise ValueError('Not accepted here: ' + ', '.join(extra))
    for k in ('include_admins', 'set_dns', 'rdp_group', 'migrate_on_login'):
        if k in data:
            if not isinstance(data[k], bool):
                raise ValueError(f'{k} must be true or false')
            out[k] = data[k]
    if 'desktop_dns' in data:
        v = data['desktop_dns'] or []
        if not isinstance(v, list) or len(v) > 4 or not all(isinstance(x, str) and _IPV4.match(x.strip()) for x in v):
            raise ValueError('desktop_dns: up to 4 IPv4 addresses')
        out['desktop_dns'] = [x.strip() for x in v]
    if 'computer_name' in data:
        v = str(data['computer_name'] or '').strip()
        probe = v.replace('{vmid}', '99999')
        if '{vmid}' not in v or not _COMPUTER.match(probe):
            raise ValueError('computer_name: letters, digits and "-" with {vmid}, 15 characters at most')
        out['computer_name'] = v
    return out


def save_settings(cfg):
    from pegaprox.api.helpers import save_server_settings
    s = _settings()
    s[SETTINGS_KEY] = {k: cfg[k] for k in SETTING_DEFAULTS}
    save_server_settings(s)
    return settings()


_IPV4 = re.compile(r'^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$')


def config():
    """The bundled DC as the environment describes it (the same values the DC was made with)."""
    realm = (os.environ.get('VLAB_DIRECTORY_REALM') or 'moavi.lan').strip().lower()
    host = (os.environ.get('VLAB_DIRECTORY_HOSTNAME') or 'dc1').strip().lower()
    base = ','.join(f'DC={p}' for p in realm.split('.') if p)
    ou = f'OU=MOAVI,{base}'
    files = os.environ.get('VLAB_DIRECTORY_FILES') or '/etc/vlab/directory'
    return {
        'enabled': _env_on(),
        'realm': realm,
        'domain': (os.environ.get('VLAB_DIRECTORY_DOMAIN') or 'MOAVI').strip().upper(),
        'host': host,
        'fqdn': f'{host}.{realm}',
        'ip': (os.environ.get('VLAB_DIRECTORY_IP') or '').strip(),
        'base_dn': base,
        'ou_dn': ou,
        'users_dn': f'OU=Users,{ou}',
        'groups_dn': f'OU=Groups,{ou}',
        'desktops_dn': f'OU=Desktops,{ou}',
        'service_dn': f'OU=Service,{ou}',
        'bind_dn': f'CN={SERVICE_USER},OU=Service,{ou}',
        'join_dn': f'CN={JOIN_USER},OU=Service,{ou}',
        'files': files,
        'ca_file': os.path.join(files, 'ca.pem'),
        'bind_file': os.path.join(files, 'engine-bind'),
    }


def own_ldap_configured():
    """The site set up its own AD / LDAP (Settings > 도메인): that one is used, not the bundled DC."""
    return bool(_settings().get('ldap_enabled', False))


def active():
    """The portal's accounts live in the bundled directory now."""
    return _env_on() and not own_ldap_configured()


def _standby():
    try:
        from pegaprox.core import ha
        return ha.is_standby()
    except Exception:
        return False


# --- the engine's two secrets ----------------------------------------------------------------

def _secret(sid):
    r = db().query_one('SELECT secret_encrypted FROM vlab_directory_secrets WHERE id = ?', (sid,))
    if not r or not r['secret_encrypted']:
        return ''
    from pegaprox.core.db import get_db
    try:
        return get_db()._decrypt(r['secret_encrypted'])
    except Exception:
        return ''


def _store_secret(sid, value):
    from pegaprox.core.db import get_db
    db().execute('INSERT OR REPLACE INTO vlab_directory_secrets (id, secret_encrypted, updated_at) VALUES (?, ?, ?)',
                 (sid, get_db()._encrypt(value) if value else '', now()))


def _read_file(path):
    try:
        with open(path, encoding='utf-8') as f:
            return f.read().strip()
    except OSError:
        return ''


def bind_password():
    """vlab-svc's password: the file the DC wrote wins (it is what the DC holds), else the sealed
    copy - a standby on the HA partner has no file of its primary, the copy comes with the sync."""
    pw = _read_file(config()['bind_file'])
    if pw:
        if pw != _secret('bind') and not _standby():
            _store_secret('bind', pw)
        return pw
    return _secret('bind')


def has_join_password():
    return bool(_secret('join'))


def sync_builtin():
    """At start: keep the service account's password and say what the directory is doing."""
    c = config()
    if not c['enabled']:
        return {'enabled': False}
    have = bool(bind_password())
    if own_ldap_configured():
        logging.info('[VLAB] bundled directory: the site has its own LDAP configured - the bundled DC is not used for sign-in')
    elif not have:
        logging.warning(f"[VLAB] bundled directory: no service account password yet ({c['bind_file']}) - "
                        'is the vlab-directory container up?')
    return {'enabled': True, 'service_account': have}


# --- the core LDAP sign-in pointed at the bundled DC --------------------------------------------

def ldap_settings():
    """What pegaprox/utils/ldap.get_ldap_settings answers while active(): the DC over LDAPS, the
    users OU only, no account made by a sign-in (the portal makes them), the CA the DC made."""
    from pegaprox.models.permissions import ROLE_USER
    c = config()
    ca = c['ca_file'] if os.path.isfile(c['ca_file']) else ''
    return {
        'enabled': True,
        'server': c['fqdn'],
        'port': 636,
        'use_ssl': True,
        'use_starttls': False,
        'bind_dn': c['bind_dn'],
        'bind_password': bind_password(),
        'base_dn': c['users_dn'],
        'user_filter': '(&(objectClass=user)(sAMAccountName={username}))',
        'username_attribute': 'sAMAccountName',
        'email_attribute': 'mail',
        'display_name_attribute': 'displayName',
        'group_base_dn': c['ou_dn'],
        'group_filter': '(&(objectClass=group)(member={user_dn}))',
        'admin_group': '', 'user_group': '', 'viewer_group': '',
        'default_role': ROLE_USER,
        'auto_create_users': False,
        'verify_tls': bool(ca),
        'ca_certs_file': ca,
        'group_mappings': [],
        'bundled': True,
    }


def owns(row):
    """Is this portal row an account of the bundled directory? An LDAP row whose DN is under the
    bundled DC's users OU (the core users table has no column of ours)."""
    if not isinstance(row, dict) or row.get('auth_source') != 'ldap':
        return False
    dn = str(row.get('ldap_dn') or '').lower()
    return bool(dn) and dn.endswith(',' + config()['users_dn'].lower())


def eligible(username, row):
    """May this local account move to the directory?"""
    from pegaprox.models.permissions import ROLE_ADMIN
    if not active() or not isinstance(row, dict) or (row.get('auth_source') or 'local') != 'local':
        return False
    if row.get('role') == ROLE_ADMIN and not settings()['include_admins']:
        return False
    return bool(NAME.match(username or ''))


# --- LDAP -----------------------------------------------------------------------------------

def _tls():
    from ldap3 import Tls
    ca = config()['ca_file']
    if os.path.isfile(ca):
        return Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca)
    logging.warning('[VLAB] bundled directory: no ca.pem yet - the DC certificate is not checked')
    return Tls(validate=ssl.CERT_NONE)


def _open():
    """A bound connection as vlab-svc. Tests replace this with an ldap3 MOCK_SYNC connection."""
    from ldap3 import Connection, Server
    c = config()
    pw = bind_password()
    if not pw:
        raise DirectoryError('NO_SERVICE_ACCOUNT', f"no password for {SERVICE_USER} ({c['bind_file']})")
    server = Server(c['fqdn'], port=636, use_ssl=True, tls=_tls(), connect_timeout=CONNECT_TIMEOUT)
    try:
        conn = Connection(server, user=c['bind_dn'], password=pw, receive_timeout=15, raise_exceptions=False)
        if not conn.bind():
            raise DirectoryError('DENIED', f"{SERVICE_USER}: {conn.result.get('description', '')} {conn.result.get('message', '')}".strip())
    except DirectoryError:
        raise
    except Exception as e:
        raise DirectoryError('UNREACHABLE', f"{c['fqdn']}:636 - {e.__class__.__name__}")
    return conn


def _user_bind(dn, password):
    """True when the DC accepts this password for dn (a bind of its own, closed at once)."""
    from ldap3 import Connection, Server
    c = config()
    server = Server(c['fqdn'], port=636, use_ssl=True, tls=_tls(), connect_timeout=CONNECT_TIMEOUT)
    try:
        conn = Connection(server, user=dn, password=password, receive_timeout=15, raise_exceptions=False)
        ok = bool(conn.bind())
        try:
            conn.unbind()
        except Exception:
            pass
        return ok
    except Exception as e:
        raise DirectoryError('UNREACHABLE', f"{c['fqdn']}:636 - {e.__class__.__name__}")


@contextmanager
def session():
    if not _env_on():
        raise DirectoryError('NOT_ON', 'the bundled directory is off (VLAB_DIRECTORY)')
    conn = _open()
    try:
        yield conn
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


_RESULT_CODES = {19: 'PASSWORD_REFUSED', 68: 'EXISTS', 32: 'NOT_FOUND', 50: 'DENIED', 53: 'REFUSED', 49: 'WRONG_PASSWORD'}


def _check(conn, ok, what):
    if ok:
        return
    r = conn.result or {}
    code = _RESULT_CODES.get(r.get('result'), 'FAILED')
    raise DirectoryError(code, f"{what}: {r.get('description', '')} {r.get('message', '')}".strip())


def _esc_rdn(v):
    from ldap3.utils.dn import escape_rdn
    return escape_rdn(v)


def _esc(v):
    from ldap3.utils.conv import escape_filter_chars
    return escape_filter_chars(v)


def _raw(entry, attr):
    vals = (entry.get('raw_attributes') or {}).get(attr) or []
    v = vals[0] if vals else None
    return v.decode('utf-8', 'replace') if isinstance(v, bytes) else (str(v) if v is not None else None)


def _raw_all(entry, attr):
    return [v.decode('utf-8', 'replace') if isinstance(v, bytes) else str(v)
            for v in (entry.get('raw_attributes') or {}).get(attr) or []]


def _search(conn, base, flt, attrs):
    from ldap3 import SUBTREE
    ok = conn.search(base, flt, search_scope=SUBTREE, attributes=attrs)
    if not ok and (conn.result or {}).get('result') not in (0, 32):
        _check(conn, False, f'search {base}')
    return [e for e in (conn.response or []) if e.get('type') == 'searchResEntry']


_USER_ATTRS = ['sAMAccountName', 'userAccountControl', 'displayName', 'mail', 'info', 'description',
               'pwdLastSet', 'memberOf']


def _user_view(e):
    uac = _raw(e, 'userAccountControl')
    pls = _raw(e, 'pwdLastSet')
    return {
        'dn': e['dn'],
        'username': (_raw(e, 'sAMAccountName') or '').lower(),
        'uac': int(uac) if uac and uac.lstrip('-').isdigit() else UAC_NORMAL | UAC_DISABLED,
        'display_name': _raw(e, 'displayName') or '',
        'mail': _raw(e, 'mail') or '',
        'info': _raw(e, 'info') or '',
        'description': _raw(e, 'description') or '',
        # AD has pwdLastSet 0 until a password is set; a directory without the attribute has one
        'has_password': pls is None or pls not in ('0',),
        'groups': [g.lower() for g in _raw_all(e, 'memberOf')],
    }


def find_user(conn, username):
    rows = _search(conn, config()['users_dn'], f'(&(objectClass=user)(sAMAccountName={_esc(username)}))', _USER_ATTRS)
    return _user_view(rows[0]) if rows else None


def list_users(conn):
    return {u['username']: u for u in (_user_view(e) for e in _search(conn, config()['users_dn'], '(objectClass=user)', _USER_ATTRS))}


def user_dn(username):
    return f"CN={_esc_rdn(username)},{config()['users_dn']}"


def _pwd(password):
    return ('"%s"' % password).encode('utf-16-le')


def _modify(conn, dn, changes, what):
    from ldap3 import MODIFY_REPLACE
    ok = conn.modify(dn, {k: [(MODIFY_REPLACE, v if isinstance(v, list) else [v])] for k, v in changes.items()})
    _check(conn, ok, what)


def _set_password_dn(conn, dn, password, what):
    from ldap3 import MODIFY_REPLACE
    ok = conn.modify(dn, {'unicodePwd': [(MODIFY_REPLACE, [_pwd(password)])]})
    _check(conn, ok, what)


def _create_user(conn, username, row, description=''):
    c = config()
    attrs = {
        'sAMAccountName': username,
        'userPrincipalName': f"{username}@{c['realm']}",
        'displayName': (row.get('display_name') or username)[:256],
        'info': MARK,
        'userAccountControl': str(UAC_NORMAL | UAC_DISABLED | UAC_DONT_EXPIRE),
    }
    if row.get('email'):
        attrs['mail'] = row['email'][:256]
    if description:
        attrs['description'] = description
    dn = user_dn(username)
    ok = conn.add(dn, ['top', 'person', 'organizationalPerson', 'user'], attrs)
    _check(conn, ok, f'make {username}')
    return find_user(conn, username) or {'dn': dn, 'username': username, 'uac': UAC_NORMAL | UAC_DISABLED,
                                          'display_name': attrs['displayName'], 'mail': attrs.get('mail', ''),
                                          'info': MARK, 'description': description, 'has_password': False, 'groups': []}


def _apply_state(conn, cur, row, has_password=None):
    """displayName, mail and enabled as the portal row says. Enabled needs a password set."""
    want = {}
    disp = (row.get('display_name') or cur['username'])[:256]
    if disp != cur['display_name']:
        want['displayName'] = disp
    mail = (row.get('email') or '')[:256]
    if mail != cur['mail']:
        want['mail'] = mail if mail else []
    has_pw = cur['has_password'] if has_password is None else has_password
    enabled = row.get('enabled', True) is not False and has_pw
    uac = (cur['uac'] & ~UAC_DISABLED) if enabled else (cur['uac'] | UAC_DISABLED)
    uac |= UAC_DONT_EXPIRE
    if uac != cur['uac']:
        want['userAccountControl'] = str(uac)
    if want:
        _modify(conn, cur['dn'], want, f"update {cur['username']}")
    return enabled


# --- groups ---------------------------------------------------------------------------------

def group_cn(dep_id):
    return 'dep-' + re.sub(r'[^A-Za-z0-9-]', '-', str(dep_id))[:56]


def group_dn(dep_id=None):
    c = config()
    return f"CN={ALL_GROUP if dep_id is None else group_cn(dep_id)},{c['groups_dn']}"


def _list_groups(conn):
    out = {}
    for e in _search(conn, config()['groups_dn'], '(objectClass=group)', ['cn', 'description', 'info', 'member']):
        out[e['dn'].lower()] = {'dn': e['dn'], 'description': _raw(e, 'description') or '', 'info': _raw(e, 'info') or '',
                                'members': {m.lower(): m for m in _raw_all(e, 'member')}}
    return out


def _ensure_group(conn, groups, dn, cn, description):
    g = groups.get(dn.lower())
    if g is None:
        ok = conn.add(dn, ['top', 'group'], {'sAMAccountName': cn, 'description': description[:1024], 'info': MARK,
                                              'groupType': str(GROUP_GLOBAL_SECURITY)})
        _check(conn, ok, f'make group {cn}')
        g = groups[dn.lower()] = {'dn': dn, 'description': description, 'info': MARK, 'members': {}}
    elif g['description'] != description:
        _modify(conn, dn, {'description': description[:1024]}, f'rename group {cn}')
        g['description'] = description
    return g


def _set_members(conn, g, want):
    """want: {lower dn: dn}. Adds and removes the difference."""
    from ldap3 import MODIFY_ADD, MODIFY_DELETE
    add = [d for k, d in want.items() if k not in g['members']]
    rem = [d for k, d in g['members'].items() if k not in want]
    changes = {}
    if add and rem:
        changes['member'] = [(MODIFY_ADD, add), (MODIFY_DELETE, rem)]
    elif add:
        changes['member'] = [(MODIFY_ADD, add)]
    elif rem:
        changes['member'] = [(MODIFY_DELETE, rem)]
    if changes:
        _check(conn, conn.modify(g['dn'], changes), f"members of {g['dn']}")
        g['members'] = dict(want)
    return len(add), len(rem)


def _member_add(conn, g, dn):
    from ldap3 import MODIFY_ADD
    if dn.lower() not in g['members']:
        _check(conn, conn.modify(g['dn'], {'member': [(MODIFY_ADD, [dn])]}), f"add to {g['dn']}")
        g['members'][dn.lower()] = dn


def _member_remove(conn, g, dn):
    from ldap3 import MODIFY_DELETE
    if dn.lower() in g['members']:
        _check(conn, conn.modify(g['dn'], {'member': [(MODIFY_DELETE, [g['members'][dn.lower()]])]}), f"remove from {g['dn']}")
        g['members'].pop(dn.lower(), None)


def sync_groups(conn, accounts=None, groups=None):
    """moavi-users and the department groups as the portal has them. accounts: {username: dn} of
    the directory accounts of portal rows (None: every one). Groups of departments that are gone
    are deleted (only ours)."""
    from pegaprox.vlab import catalog
    groups = _list_groups(conn) if groups is None else groups
    if accounts is None:
        accounts = {n: v['dn'] for n, v in list_users(conn).items() if owns(_rows().get(n))}
    deps = catalog.list_departments()
    by_id = {d['id']: d for d in deps}
    dep_of = {}
    for r in catalog.members(list(by_id)):
        dep_of[r['username']] = r['department_id']
    everyone = _ensure_group(conn, groups, group_dn(), ALL_GROUP, 'MOAVI Desk: every portal account')
    changed = sum(_set_members(conn, everyone, {dn.lower(): dn for dn in accounts.values()}))
    want_dns = {group_dn().lower()}
    for d in deps:
        _ensure_group(conn, groups, group_dn(d['id']), group_cn(d['id']), d['name'])
        want_dns.add(group_dn(d['id']).lower())
    for d in deps:
        g = groups[group_dn(d['id']).lower()]
        want = {dn.lower(): dn for n, dn in accounts.items() if dep_of.get(n) == d['id']}
        for child in deps:
            if child.get('parent_id') == d['id']:
                cdn = groups[group_dn(child['id']).lower()]['dn']
                want[cdn.lower()] = cdn
        changed += sum(_set_members(conn, g, want))
    removed = 0
    for key, g in list(groups.items()):
        if key not in want_dns and g['info'] == MARK:
            _check(conn, conn.delete(g['dn']), f"delete group {g['dn']}")
            groups.pop(key, None)
            removed += 1
    return {'groups': len(want_dns), 'membership_changes': changed, 'groups_removed': removed}


def _user_groups(conn, username, dn, groups=None):
    """One account's moavi-users and department membership (a push of one user)."""
    from pegaprox.vlab import catalog
    groups = _list_groups(conn) if groups is None else groups
    everyone = _ensure_group(conn, groups, group_dn(), ALL_GROUP, 'MOAVI Desk: every portal account')
    _member_add(conn, everyone, dn)
    dep = catalog.department_of(username)
    for d in catalog.list_departments():
        g = _ensure_group(conn, groups, group_dn(d['id']), group_cn(d['id']), d['name'])
        if d['id'] == dep:
            _member_add(conn, g, dn)
        else:
            _member_remove(conn, g, dn)


# --- portal rows ----------------------------------------------------------------------------

def _rows():
    from pegaprox.utils.auth import load_users
    return load_users() or {}


def _record(username, ok, code='', detail='', dn=''):
    db().execute('INSERT OR REPLACE INTO vlab_directory_accounts (username, ok, code, detail, dn, at) VALUES (?, ?, ?, ?, ?, ?)',
                 (username, int(bool(ok)), code, (detail or '')[:300], dn or '', now()))


def account_states():
    return {r['username']: dict(r, ok=bool(r['ok'])) for r in db().query('SELECT * FROM vlab_directory_accounts') or []}


def _forget(username):
    db().execute('DELETE FROM vlab_directory_accounts WHERE username = ?', (username,))


def _to_directory_row(row, dn):
    """The portal row of a directory account: no password of its own any more."""
    out = dict(row)
    out.update(auth_source='ldap', ldap_dn=dn, password_hash='', password_salt='')
    out.pop('password_changed_at', None)
    return out


# --- what the portal calls ------------------------------------------------------------------

def adopt(username, password, row=None):
    """Give a local account its directory account with this password (made now or set again) and
    turn the portal row into the directory's. The password goes to the DC and nowhere else.
    Returns the new row; DirectoryError when the DC refused or is away (the row is left as it was)."""
    from pegaprox.utils.auth import save_single_user
    row = row if row is not None else _rows().get(username)
    if row is None:
        raise DirectoryError('NOT_FOUND', f'no portal account {username}')
    if not NAME.match(username):
        raise DirectoryError('BAD_NAME', 'a directory account name has at most 20 characters: a-z 0-9 . _ -')
    _require_policy(password, username, row.get('display_name') or '')
    with session() as conn:
        cur = find_user(conn, username)
        if cur is None:
            cur = _create_user(conn, username, row)
        elif cur['info'] != MARK:
            raise DirectoryError('EXISTS', f'{username} is in the directory already and was not made by MOAVI Desk')
        _set_password_dn(conn, cur['dn'], password, f'password of {username}')
        if cur['description'].startswith(SIGNUP_PREFIX):
            _modify(conn, cur['dn'], {'description': []}, f'sign-up mark of {username}')
        _apply_state(conn, cur, row, has_password=True)
        _user_groups(conn, username, cur['dn'])
        new = _to_directory_row(row, cur['dn'])
    save_single_user(username, new)
    _record(username, True, 'OK', 'made in the directory', cur['dn'])
    logging.info(f'[VLAB] bundled directory: {username} now signs in with the directory account')
    return new


def push_user(username, row=None):
    """The directory account as the portal row says (enabled, name, mail, groups); one that is not
    there is made disabled - without a password it waits for the owner's reset link. Raises."""
    row = row if row is not None else _rows().get(username)
    if not owns(row):
        return None
    with session() as conn:
        cur = find_user(conn, username)
        made = False
        if cur is None:
            cur = _create_user(conn, username, row)
            made = True
        enabled = _apply_state(conn, cur, row)
        _user_groups(conn, username, cur['dn'])
    if not cur['has_password']:
        _record(username, False, 'NO_PASSWORD', 'the account has no password yet - a reset link sets one', cur['dn'])
    else:
        _record(username, True, 'OK', 'made again' if made else ('enabled' if enabled else 'disabled'), cur['dn'])
    return cur['dn']


def remove_user(username):
    """Delete the directory account of a deleted portal account (only one we made). Raises."""
    with session() as conn:
        cur = find_user(conn, username)
        if cur is not None and cur['info'] == MARK:
            _check(conn, conn.delete(cur['dn']), f'delete {username}')
    _forget(username)


def set_password(username, password, row=None):
    """An admin's reset or the reset link: the DC's own password set. The account is made when
    it is missing and enabled when the portal row is."""
    row = row if row is not None else _rows().get(username)
    if not owns(row):
        raise DirectoryError('NOT_FOUND', f'{username} is not a directory account')
    _require_policy(password, username, row.get('display_name') or '')
    with session() as conn:
        cur = find_user(conn, username) or _create_user(conn, username, row)
        _set_password_dn(conn, cur['dn'], password, f'password of {username}')
        _apply_state(conn, cur, row, has_password=True)
        _user_groups(conn, username, cur['dn'])
    _record(username, True, 'OK', 'password set', cur['dn'])


def change_password(username, old, new, row=None):
    """내 계정: the current password checked by the DC itself, then the new one set."""
    row = row if row is not None else _rows().get(username)
    if not owns(row):
        raise DirectoryError('NOT_FOUND', f'{username} is not a directory account')
    _require_policy(new, username, row.get('display_name') or '')
    with session() as conn:
        cur = find_user(conn, username)
        if cur is None:
            raise DirectoryError('NOT_FOUND', f'{username} is not in the directory')
        if not _user_bind(cur['dn'], old):
            raise DirectoryError('WRONG_PASSWORD', 'the current password is not right')
        _set_password_dn(conn, cur['dn'], new, f'password of {username}')
    _record(username, True, 'OK', 'password changed', cur['dn'])


def signup_account(username, display_name, email, password, signup_id):
    """A sign-up while the directory is on: its account is made now, disabled, holding the password
    the person chose - the portal keeps no hash of it. The review enables it (approve_signup) or
    deletes it (drop_signup). Raises; the caller then falls back to the portal's own hash."""
    if not NAME.match(username):
        raise DirectoryError('BAD_NAME', 'a directory account name has at most 20 characters')
    _require_policy(password, username, display_name)
    row = {'display_name': display_name, 'email': email, 'enabled': False}
    with session() as conn:
        cur = find_user(conn, username)
        if cur is not None:
            if cur['info'] != MARK or not cur['description'].startswith(SIGNUP_PREFIX):
                raise DirectoryError('EXISTS', f'{username} is taken in the directory')
            _modify(conn, cur['dn'], {'description': SIGNUP_PREFIX + signup_id}, f'sign-up of {username}')
        else:
            cur = _create_user(conn, username, row, description=SIGNUP_PREFIX + signup_id)
        _set_password_dn(conn, cur['dn'], password, f'password of {username}')
    return cur['dn']


def approve_signup(username, row):
    """The portal row of an approved sign-up whose password is in the directory: enabled there."""
    from pegaprox.utils.auth import save_single_user
    with session() as conn:
        cur = find_user(conn, username)
        if cur is None:
            raise DirectoryError('NOT_FOUND', f'the directory account of the sign-up {username} is gone')
        if cur['description'].startswith(SIGNUP_PREFIX):
            _modify(conn, cur['dn'], {'description': []}, f'sign-up mark of {username}')
        new = _to_directory_row(row, cur['dn'])
        _apply_state(conn, cur, new, has_password=True)
        _user_groups(conn, username, cur['dn'])
    save_single_user(username, new)
    _record(username, True, 'OK', 'sign-up approved', cur['dn'])
    return new


def drop_signup(username):
    """A rejected sign-up: its waiting directory account goes. Raises."""
    with session() as conn:
        cur = find_user(conn, username)
        if cur is not None and cur['info'] == MARK and cur['description'].startswith(SIGNUP_PREFIX):
            _check(conn, conn.delete(cur['dn']), f'delete the sign-up account {username}')


# --- the password policy: the portal's and the directory's together --------------------------

_policy_cache = {'at': 0.0, 'dc': None}
POLICY_TTL = 300


def _dc_policy():
    """The domain's own rule (minPwdLength, the complexity bit of pwdProperties), read from the
    domain object and kept POLICY_TTL seconds. None when the DC cannot be asked."""
    if time.time() - _policy_cache['at'] < POLICY_TTL:
        return _policy_cache['dc']
    try:
        with session() as conn:
            rows = _search(conn, config()['base_dn'], '(objectClass=domain)', ['minPwdLength', 'pwdProperties'])
    except DirectoryError:
        _policy_cache['at'] = time.time() - POLICY_TTL + 30     # asked again in 30 s, not on every call
        return _policy_cache['dc']
    out = {'min_length': 0, 'complexity': False}
    for e in rows:
        if e['dn'].lower() != config()['base_dn'].lower():
            continue
        m, p = _raw(e, 'minPwdLength'), _raw(e, 'pwdProperties')
        out = {'min_length': int(m) if m and m.isdigit() else 0, 'complexity': bool(p and p.isdigit() and int(p) & 1)}
    _policy_cache.update(at=time.time(), dc=out)
    return out


def password_policy():
    """What a password must be so that the portal and, while the bundled directory is in use, the
    DC both take it: {min_length, uppercase, lowercase, numbers, special, complexity, unified,
    domain}. complexity is AD's: three of upper / lower / digit / sign, and not the account name."""
    s = _settings()
    out = {'min_length': int(s.get('password_min_length', 8) or 8),
           'uppercase': bool(s.get('password_require_uppercase', True)),
           'lowercase': bool(s.get('password_require_lowercase', True)),
           'numbers': bool(s.get('password_require_numbers', True)),
           'special': bool(s.get('password_require_special', False)),
           'complexity': False, 'unified': False, 'domain': ''}
    if active():
        out.update(unified=True, domain=config()['domain'])
        dc = _dc_policy() or {'min_length': 0, 'complexity': False}
        out['min_length'] = max(out['min_length'], dc['min_length'])
        out['complexity'] = dc['complexity']
    return out


def policy_error(password, username='', display_name=''):
    """None when both the portal and the directory accept it, else what is missing (English,
    the same wording as the core's validate_password_policy)."""
    from pegaprox.utils.auth import validate_password_policy
    pol = password_policy()
    password = password or ''
    ok, why = validate_password_policy(password)
    errs = [why] if not ok and why else []
    portal_min = int(_settings().get('password_min_length', 8) or 8)
    if pol['min_length'] > portal_min and len(password) < pol['min_length']:
        errs.append(f"at least {pol['min_length']} characters (the directory's rule)")
    if pol['complexity']:
        kinds = sum((any(c.isupper() for c in password), any(c.islower() for c in password),
                     any(c.isdigit() for c in password), any(not c.isalnum() for c in password)))
        if kinds < 3:
            errs.append("three of: upper-case, lower-case, digits, signs (the directory's rule)")
        low = password.lower()
        name = (username or '').lower()
        parts = [name] + [p for p in re.split(r'[\s,._\-#\t]+', (display_name or '').lower()) if len(p) >= 3]
        if any(len(p) >= 3 and p in low for p in parts):
            errs.append("not the account name or parts of the full name (the directory's rule)")
    return '; '.join(errs) if errs else None


def _require_policy(password, username, display_name=''):
    why = policy_error(password, username, display_name)
    if why:
        raise DirectoryError('PASSWORD_POLICY', why)


# --- hooks: never raise into the portal's own work -----------------------------------------------

def _quiet(what, fn, *a, **kw):
    if not active() or _standby():
        return None
    try:
        return fn(*a, **kw)
    except DirectoryError as e:
        logging.warning(f'[VLAB] bundled directory: {what}: {e.code} {e.detail}')
        return e
    except Exception as e:
        logging.warning(f'[VLAB] bundled directory: {what}: {e.__class__.__name__}')
        return e


def after_change(username):
    """A portal account changed (enabled, name, mail, department): pushed now; a failure is
    recorded and the next reconcile tries again."""
    row = _rows().get(username)
    if not owns(row):
        return None
    out = _quiet(f'push {username}', push_user, username, row)
    if isinstance(out, DirectoryError):
        _record(username, False, out.code, out.detail)
    return out


def after_delete(username):
    out = _quiet(f'delete {username}', remove_user, username)
    if isinstance(out, DirectoryError):
        _record(username, False, out.code, 'deleted in the portal, still in the directory: ' + out.detail)
    return out


def after_signup_rejected(username):
    return _quiet(f'drop the sign-up account {username}', drop_signup, username)


def after_departments():
    def run():
        with session() as conn:
            return sync_groups(conn)
    return _quiet('department groups', run)


def after_create(username, password):
    """An account the portal just made with this password: moved to the directory when it may.
    False when it stays local (not eligible, or the DC is away - its next sign-in moves it)."""
    row = _rows().get(username)
    if not eligible(username, row) or _standby():
        return False
    try:
        adopt(username, password, row)
        return True
    except DirectoryError as e:
        logging.warning(f'[VLAB] bundled directory: {username} stays a portal account for now: {e.code} {e.detail}')
        _record(username, False, e.code, 'made in the portal only; moves at the next sign-in: ' + e.detail)
        return False


def migrate_on_login(username, row, password):
    """A local account signed in with a good password: move it to the directory now (the core
    login calls this once the password is checked). Returns the new row or None."""
    if not settings()['migrate_on_login'] or not eligible(username, row) or _standby():
        return None
    try:
        return adopt(username, password, row)
    except DirectoryError as e:
        logging.warning(f'[VLAB] bundled directory: {username} not moved at sign-in: {e.code} {e.detail}')
        _record(username, False, e.code, 'not moved at sign-in: ' + e.detail)
        return None


# --- reconcile -------------------------------------------------------------------------------

def reconcile():
    """Every portal account of the directory as the portal says, every account we made without a
    portal account (and not a sign-up still waiting) deleted, and the groups. Returns counts."""
    from pegaprox.vlab import catalog
    rows = _rows()
    mine = {n: r for n, r in rows.items() if owns(r)}
    pending = {s['username'] for s in catalog.list_signups('pending')}
    out = {'accounts': 0, 'made': 0, 'updated': 0, 'deleted': 0, 'no_password': 0, 'errors': 0}
    with session() as conn:
        have = list_users(conn)
        accounts = {}
        for name, row in mine.items():
            cur = have.get(name)
            try:
                if cur is None:
                    cur = _create_user(conn, name, row)
                    out['made'] += 1
                _apply_state(conn, cur, row)
                accounts[name] = cur['dn']
                out['accounts'] += 1
                if not cur['has_password']:
                    out['no_password'] += 1
                    _record(name, False, 'NO_PASSWORD', 'the account has no password yet - a reset link sets one', cur['dn'])
                else:
                    _record(name, True, 'OK', 'in step', cur['dn'])
            except DirectoryError as e:
                out['errors'] += 1
                _record(name, False, e.code, e.detail, (cur or {}).get('dn', ''))
        for name, cur in have.items():
            if name in mine or cur['info'] != MARK:
                continue
            if cur['description'].startswith(SIGNUP_PREFIX) and name in pending:
                continue
            try:
                _check(conn, conn.delete(cur['dn']), f'delete {name}')
                out['deleted'] += 1
                _forget(name)
            except DirectoryError as e:
                out['errors'] += 1
                logging.warning(f'[VLAB] bundled directory: {name} has no portal account and was not deleted: {e.detail}')
        out.update(sync_groups(conn, accounts))
    _last_reconcile[0] = time.time()
    return out


def directory_tick():
    """On the minute loop of the active instance (pegaprox/vlab/loans.py): a reconcile every
    RECONCILE_EVERY seconds."""
    if not active() or time.time() - _last_reconcile[0] < RECONCILE_EVERY:
        return None
    from pegaprox.core import ha
    _last_reconcile[0] = time.time()
    if not ha.confirm_step('bundled directory reconcile'):
        return None
    try:
        return reconcile()
    except DirectoryError as e:
        logging.warning(f'[VLAB] bundled directory reconcile: {e.code} {e.detail}')
        return {'error': e.code}


def check():
    """Can the engine reach the DC as vlab-svc, and is the layout there?"""
    c = config()
    out = {'enabled': c['enabled'], 'active': active(), 'own_ldap': own_ldap_configured(), 'reachable': False,
           'service_account': bool(bind_password()), 'tls_verified': os.path.isfile(c['ca_file']),
           'join_account': has_join_password(), 'ou': False, 'users': 0, 'code': '', 'detail': ''}
    if not c['enabled']:
        out['code'] = 'NOT_ON'
        return out
    try:
        with session() as conn:
            out['reachable'] = True
            out['ou'] = bool(_search(conn, c['ou_dn'], '(objectClass=organizationalUnit)', ['ou']))
            out['users'] = len(list_users(conn))
        out['code'] = 'OK' if out['ou'] else 'NO_OU'
    except DirectoryError as e:
        out['code'], out['detail'] = e.code, e.detail
    return out


# --- the join account ---------------------------------------------------------------------------

def _random_password(n=24):
    alphabet = string.ascii_letters + string.digits
    body = ''.join(secrets.choice(alphabet) for _ in range(n))
    return body + 'aA1!'


def rotate_join():
    """A new password for vlab-join: set on the DC, then sealed here. Raises."""
    pw = _random_password()
    with session() as conn:
        _set_password_dn(conn, config()['join_dn'], pw, JOIN_USER)
    _store_secret('join', pw)
    return True


def join_password():
    """vlab-join's password for a guest join; made the first time it is needed."""
    pw = _secret('join')
    if pw:
        return pw
    rotate_join()
    return _secret('join')


# --- desktop joins -----------------------------------------------------------------------------

def computer_name(vmid):
    return settings()['computer_name'].replace('{vmid}', str(int(vmid)))[:15]


def desktop_dns():
    s = settings()
    return list(s['desktop_dns']) or ([config()['ip']] if config()['ip'] else [])


def _ps_str(v):
    return "'" + str(v).replace("'", "''") + "'"


def windows_join_script(name, restart=False):
    """PowerShell for the guest agent (as SYSTEM). The join account's password comes on stdin."""
    c, s = config(), settings()
    dns = desktop_dns() if s['set_dns'] else []
    dns_ps = '@(' + ','.join(_ps_str(x) for x in dns) + ')'
    return '\n'.join([
        "$ErrorActionPreference = 'Stop'",
        f"$domain = {_ps_str(c['realm'])}; $netbios = {_ps_str(c['domain'])}; $ou = {_ps_str(c['desktops_dn'])}",
        f"$user = {_ps_str(c['domain'] + chr(92) + JOIN_USER)}; $name = {_ps_str(name)}; $dns = {dns_ps}",
        "$pw = [Console]::In.ReadToEnd().Trim()",
        "$cs = Get-CimInstance Win32_ComputerSystem",
        "if ($cs.PartOfDomain) {",
        "  \"domain=$($cs.Domain)\"; \"computer=$env:COMPUTERNAME\"",
        "  if ($cs.Domain -ieq $domain) { 'joined=1'; exit 0 } else { exit 21 }",
        "}",
        "if ($dns.Count -gt 0) {",
        "  Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {",
        "    Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses $dns }",
        "  Clear-DnsClientCache",
        "}",
        "try { Resolve-DnsName -Type SRV \"_ldap._tcp.dc._msdcs.$domain\" | Out-Null }",
        "catch { [Console]::Error.WriteLine(\"no DC found for $domain in DNS: $($_.Exception.Message)\"); exit 22 }",
        "$cred = New-Object System.Management.Automation.PSCredential($user, (ConvertTo-SecureString $pw -AsPlainText -Force))",
        "$p = @{ DomainName = $domain; OUPath = $ou; Credential = $cred; Force = $true }",
        "if ($env:COMPUTERNAME -ine $name) { $p['NewName'] = $name }",
        "try { Add-Computer @p -ErrorAction Stop }",
        "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 23 }",
        "\"domain=$domain\"; \"computer=$name\"; 'joined=1'; 'reboot=1'",
        ("try { Add-LocalGroupMember -SID 'S-1-5-32-555' -Member \"$netbios\\" + ALL_GROUP + "\" -ErrorAction Stop; 'rdp_group=1' }"
         " catch { 'rdp_group=0' }") if s['rdp_group'] else "'rdp_group=skipped'",
        "shutdown.exe /r /t 15 /c 'MOAVI Desk: domain join' | Out-Null; 'restarting=1'" if restart else "'restarting=0'",
        "exit 0",
    ])


def _sh(v):
    return "'" + str(v).replace("'", "'\"'\"'") + "'"


def linux_join_script(name):
    """sh for the guest agent (as root): realm join with sssd, short names, home folders made at
    the first sign-in, moavi-users allowed in. The join account's password comes on stdin."""
    c, s = config(), settings()
    dns = desktop_dns() if s['set_dns'] else []
    host = f"{name.lower()}.{c['realm']}"
    return '\n'.join([
        'set -u',
        f"REALM={_sh(c['realm'])}; OU={_sh(c['desktops_dn'])}; JOINER={_sh(JOIN_USER)}; HOST={_sh(host)}",
        f"DNS={_sh(' '.join(dns))}",
        'PW=$(cat)',
        'command -v realm >/dev/null 2>&1 || { echo "realmd, sssd and adcli are not installed" >&2; exit 24; }',
        'CUR=$(realm list --name-only 2>/dev/null | head -n1)',
        'if [ -n "$CUR" ]; then echo "domain=$CUR"; echo "computer=$(hostname -s)";',
        '  if [ "$(echo "$CUR" | tr A-Z a-z)" = "$REALM" ]; then echo joined=1; exit 0; else exit 21; fi; fi',
        'if [ -n "$DNS" ] && command -v nmcli >/dev/null 2>&1; then',
        '  C=$(nmcli -t -f NAME,DEVICE connection show --active | awk -F: \'$2!="lo"{print $1; exit}\')',
        '  [ -n "$C" ] && nmcli connection modify "$C" ipv4.dns "$DNS" ipv4.ignore-auto-dns yes && nmcli connection up "$C" >/dev/null 2>&1',
        'elif [ -n "$DNS" ] && command -v resolvectl >/dev/null 2>&1; then',
        '  I=$(ip route show default | awk \'{print $5; exit}\'); [ -n "$I" ] && resolvectl dns "$I" $DNS && resolvectl domain "$I" "$REALM"',
        'fi',
        'realm discover "$REALM" >/dev/null 2>&1 || { echo "no DC found for $REALM in DNS" >&2; exit 22; }',
        '[ "$(hostname -f 2>/dev/null)" = "$HOST" ] || hostnamectl set-hostname "$HOST" || exit 25',
        'printf %s "$PW" | realm join --user="$JOINER" --computer-ou="$OU" "$REALM" >/tmp/.moavi-join 2>&1 '
        '|| { cat /tmp/.moavi-join >&2; rm -f /tmp/.moavi-join; exit 23; }',
        'rm -f /tmp/.moavi-join',
        'F=/etc/sssd/sssd.conf',
        'if [ -f "$F" ]; then',
        '  sed -i "s/^use_fully_qualified_names.*/use_fully_qualified_names = False/; s|^fallback_homedir.*|fallback_homedir = /home/%u|" "$F"',
        '  grep -q "^use_fully_qualified_names" "$F" || sed -i "/^\\[domain\\//a use_fully_qualified_names = False" "$F"',
        '  systemctl restart sssd >/dev/null 2>&1 || true',
        'fi',
        'command -v pam-auth-update >/dev/null 2>&1 && pam-auth-update --enable mkhomedir >/dev/null 2>&1',
        'command -v authselect >/dev/null 2>&1 && authselect enable-feature with-mkhomedir >/dev/null 2>&1 '
        '&& systemctl enable --now oddjobd >/dev/null 2>&1',
        f'realm permit -g {ALL_GROUP} >/dev/null 2>&1 && echo rdp_group=1 || echo rdp_group=0',
        'echo "domain=$REALM"; echo "computer=$(hostname -s)"; echo joined=1',
        'exit 0',
    ])


def status_script(os_kind):
    """Only asks: is the guest in a domain, which one, under which name."""
    if os_kind == 'windows':
        return ('$cs = Get-CimInstance Win32_ComputerSystem; "computer=$env:COMPUTERNAME"; '
                'if ($cs.PartOfDomain) { "domain=$($cs.Domain)"; "joined=1" } else { "joined=0" }; exit 0')
    return ('D=$(realm list --name-only 2>/dev/null | head -n1); echo "computer=$(hostname -s)"; '
            'if [ -n "$D" ]; then echo "domain=$D"; echo joined=1; else echo joined=0; fi; exit 0')


def record_join(desktop_id, state, code, detail='', computer='', domain='', os_kind=''):
    db().execute('INSERT OR REPLACE INTO vlab_directory_joins (desktop_id, state, code, detail, computer, domain, os, at) '
                 'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                 (desktop_id, state, code, (detail or '')[:500], computer or '', domain or '', os_kind or '', now()))
    return join_of(desktop_id)


def join_of(desktop_id):
    r = db().query_one('SELECT * FROM vlab_directory_joins WHERE desktop_id = ?', (desktop_id,))
    return dict(r) if r else None


def joins():
    return {r['desktop_id']: dict(r) for r in db().query('SELECT * FROM vlab_directory_joins') or []}


def forget_desktop(desktop_id):
    db().execute('DELETE FROM vlab_directory_joins WHERE desktop_id = ?', (desktop_id,))


def desktop_login(desktop_id, username):
    """The name a user signs in to a desktop with: DOMAIN\\user once the desktop joined the bundled
    directory and the account is the directory's; else the name as it is."""
    try:
        if not active() or not owns(_rows().get(username)):
            return username
        j = join_of(desktop_id)
    except Exception:
        return username
    if j and j['state'] == 'joined':
        return f"{config()['domain']}\\{username}"
    return username


def summary():
    """For the console: the directory, its accounts and joins in a few numbers."""
    c = config()
    states = account_states()
    j = joins()
    return {
        'enabled': c['enabled'], 'active': active(), 'own_ldap': own_ldap_configured(),
        'realm': c['realm'], 'domain': c['domain'], 'dc': c['fqdn'], 'ip': c['ip'],
        'base_dn': c['base_dn'], 'users_dn': c['users_dn'], 'groups_dn': c['groups_dn'],
        'desktops_dn': c['desktops_dn'], 'all_group_dn': group_dn(),
        'service_account': bool(bind_password()) if c['enabled'] else False,
        'join_account': has_join_password(), 'tls_verified': os.path.isfile(c['ca_file']),
        'settings': settings(),
        'accounts': {'total': len(states), 'ok': sum(1 for s in states.values() if s['ok']),
                     'failed': sum(1 for s in states.values() if not s['ok'])},
        'joins': {'total': len(j), 'joined': sum(1 for x in j.values() if x['state'] == 'joined'),
                  'failed': sum(1 for x in j.values() if x['state'] == 'failed')},
        'last_reconcile': _last_reconcile[0] and time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(_last_reconcile[0])) or None,
    }
