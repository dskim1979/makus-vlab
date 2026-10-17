# -*- coding: utf-8 -*-
"""
MOAVI Desk - AD objects (AD 디렉터리): browse and change the objects of a directory from the
console - the bundled DC (pegaprox/vlab/directory.py) or the site's own AD configured under
도메인(AD/LDAP). Users, groups (security / distribution; global, universal, domain local) and
OUs: made, changed, enabled / disabled, deleted, members added and removed.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

Every change goes to the real directory with the bind account of that source (vlab-svc for the
bundled DC, the configured service account for the site's AD) - what that account may not do,
the directory refuses, and the answer says so (DENIED). test() reads which classes the account
may create at a place (AD's allowedChildClassesEffective). Nothing here keeps a copy of the
directory: each call reads it.

Rules:
  * a DN must be under the source's base DN (no walking out of it)
  * on the bundled DC the objects the engine keeps for the portal (info=moavi-desk: the portal's
    accounts, moavi-users, the department groups) are read-only here - they follow the portal
    (users and departments in the console); everything else in OU=MOAVI and the rest of the
    domain may be changed. A department is never moved by a change here.
  * a group never becomes a member of itself, directly or through other groups (cycle check)
  * an OU is deleted only when empty
  * a password given for a new user or a reset goes to the directory's own password set and is
    not kept or logged
"""

import re
import ssl

from pegaprox.vlab import directory

SOURCES = ('bundled', 'ldap')
MAX_ROWS = 500
MAX_NESTED = 2000

GT_GLOBAL, GT_DOMAIN_LOCAL, GT_UNIVERSAL, GT_SECURITY = 0x2, 0x4, 0x8, 0x80000000
SCOPES = {'global': GT_GLOBAL, 'domain_local': GT_DOMAIN_LOCAL, 'universal': GT_UNIVERSAL}
CONTAINER_FILTER = '(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain))'
KIND_FILTERS = {
    'users': '(&(objectClass=user)(!(objectClass=computer)))',
    'groups': '(objectClass=group)',
    'computers': '(objectClass=computer)',
    'ous': '(objectClass=organizationalUnit)',
    'all': '(|(objectClass=user)(objectClass=group)(objectClass=organizationalUnit)(objectClass=container))',
}
EDITABLE = {
    'user': ('displayName', 'givenName', 'sn', 'mail', 'description', 'telephoneNumber', 'title', 'department', 'company'),
    'group': ('description', 'mail', 'info'),
    'organizationalUnit': ('description',),
}
_ATTRS = ['objectClass', 'cn', 'ou', 'name', 'sAMAccountName', 'userPrincipalName', 'displayName', 'givenName', 'sn', 'mail',
          'description', 'telephoneNumber', 'title', 'department', 'company', 'info', 'userAccountControl', 'groupType',
          'memberOf', 'whenCreated', 'whenChanged']
_NAME = re.compile(r'^[^\x00-\x1f"/\\\[\]:;|=,+*?<>@]{1,64}$')
_SAM = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$')
_GROUP_SAM = re.compile(r'^[^\x00-\x1f"/\\\[\]:;|=,+*?<>@]{1,64}$')

Error = directory.DirectoryError


# --- sources --------------------------------------------------------------------------------

def _own_ldap():
    from pegaprox.utils.ldap import get_ldap_settings
    c = get_ldap_settings()
    return c if c.get('enabled') and not c.get('bundled') and c.get('server') and c.get('base_dn') else None


def sources():
    out = []
    c = directory.config()
    if c['enabled']:
        out.append({'id': 'bundled', 'name': f"내장 디렉터리 ({c['realm']})", 'base_dn': c['base_dn'], 'server': c['fqdn']})
    own = _own_ldap()
    if own:
        out.append({'id': 'ldap', 'name': f"기관 AD ({own['server']})", 'base_dn': own['base_dn'], 'server': own['server']})
    return out


def base_dn(source):
    if source == 'bundled':
        if not directory.config()['enabled']:
            raise Error('NOT_ON', 'the bundled directory is off')
        return directory.config()['base_dn']
    if source == 'ldap':
        own = _own_ldap()
        if not own:
            raise Error('NOT_ON', 'no AD / LDAP of the site is configured')
        return own['base_dn']
    raise Error('BAD_SOURCE', 'source: bundled or ldap')


def _ldap_open():
    """A bound connection with the site's configured service account. Tests replace this."""
    from ldap3 import Connection, Server, Tls
    c = _own_ldap()
    if not c:
        raise Error('NOT_ON', 'no AD / LDAP of the site is configured')
    tls = None
    if c['use_ssl'] or c['use_starttls']:
        tls = Tls(validate=ssl.CERT_REQUIRED if c.get('verify_tls') else ssl.CERT_NONE,
                  ca_certs_file=c.get('ca_certs_file') or None)
    try:
        server = Server(c['server'], port=int(c['port']), use_ssl=c['use_ssl'], tls=tls, connect_timeout=directory.CONNECT_TIMEOUT)
        conn = Connection(server, user=c['bind_dn'] or None, password=c['bind_password'] or None, receive_timeout=15,
                          raise_exceptions=False)
        conn.open()
        if c['use_starttls'] and not c['use_ssl']:
            conn.start_tls()
        if not conn.bind():
            raise Error('DENIED', f"bind: {conn.result.get('description', '')} {conn.result.get('message', '')}".strip())
    except Error:
        raise
    except Exception as e:
        raise Error('UNREACHABLE', f"{c['server']}:{c['port']} - {e.__class__.__name__}")
    return conn


class _Session:
    def __init__(self, source):
        self.source = source
        self.base = base_dn(source)
        self.conn = None

    def __enter__(self):
        self.conn = directory._open() if self.source == 'bundled' else _ldap_open()
        return self

    def __exit__(self, *exc):
        try:
            self.conn.unbind()
        except Exception:
            pass


def session(source):
    return _Session(source)


# --- helpers ----------------------------------------------------------------------------------

def _norm(dn):
    from ldap3.utils.dn import safe_dn
    try:
        return safe_dn(dn)
    except Exception:
        raise Error('BAD_DN', 'not a DN')


def _inside(s, dn):
    if not isinstance(dn, str) or not dn.strip() or len(dn) > 1024:
        raise Error('BAD_DN', 'a DN is needed')
    n = _norm(dn.strip())
    base = _norm(s.base)
    if n.lower() != base.lower() and not n.lower().endswith(',' + base.lower()):
        raise Error('OUTSIDE', f'{dn} is not under {s.base}')
    return n


def _rdn_value(dn):
    from ldap3.utils.dn import parse_dn
    try:
        return parse_dn(dn, escape=False)[0][1]
    except Exception:
        return dn


def _parent(dn):
    from ldap3.utils.dn import to_dn
    parts = to_dn(dn)
    return ','.join(parts[1:])


def _view(e):
    raw = e.get('raw_attributes') or {}
    one = lambda k: (raw.get(k) or [b''])[0].decode('utf-8', 'replace') if raw.get(k) else ''
    classes = [c.decode('utf-8', 'replace') if isinstance(c, bytes) else str(c) for c in raw.get('objectClass') or []]
    low = {c.lower() for c in classes}
    if 'computer' in low:
        kind = 'computer'
    elif 'user' in low:
        kind = 'user'
    elif 'group' in low:
        kind = 'group'
    elif 'organizationalunit' in low:
        kind = 'ou'
    else:
        kind = 'container'
    out = {'dn': e['dn'], 'kind': kind, 'name': one('name') or one('cn') or one('ou') or _rdn_value(e['dn']),
           'description': one('description'), 'managed': one('info') == directory.MARK}
    if kind in ('user', 'computer'):
        uac = one('userAccountControl')
        uac = int(uac) if uac.lstrip('-').isdigit() else 0
        out.update(sam=one('sAMAccountName'), upn=one('userPrincipalName'), display_name=one('displayName'),
                   given_name=one('givenName'), surname=one('sn'), mail=one('mail'), title=one('title'),
                   department=one('department'), company=one('company'), telephone=one('telephoneNumber'),
                   enabled=not (uac & directory.UAC_DISABLED))
    elif kind == 'group':
        gt = one('groupType')
        gt = int(gt) if gt.lstrip('-').isdigit() else 0
        gt &= 0xFFFFFFFF
        out.update(sam=one('sAMAccountName'), mail=one('mail'),
                   type='security' if gt & GT_SECURITY else 'distribution',
                   scope='universal' if gt & GT_UNIVERSAL else 'domain_local' if gt & GT_DOMAIN_LOCAL else 'global')
    if kind in ('user', 'group', 'computer'):
        out['member_of'] = [m.decode('utf-8', 'replace') if isinstance(m, bytes) else str(m) for m in raw.get('memberOf') or []]
    return out


def _search(s, base, flt, scope, attrs=None, limit=MAX_ROWS):
    from ldap3 import BASE, LEVEL, SUBTREE
    sc = {'base': BASE, 'one': LEVEL, 'sub': SUBTREE}[scope]
    ok = s.conn.search(base, flt, search_scope=sc, attributes=attrs or _ATTRS, size_limit=limit)
    r = s.conn.result or {}
    if not ok and r.get('result') not in (0, 4, 32):
        directory._check(s.conn, False, f'search {base}')
    return [e for e in (s.conn.response or []) if e.get('type') == 'searchResEntry']


def _get(s, dn, attrs=None):
    rows = _search(s, dn, '(objectClass=*)', 'base', attrs)
    if not rows:
        raise Error('NOT_FOUND', f'{dn} is not there')
    return rows[0]


def _guard(s, dn, what):
    """The bundled DC's portal-kept objects follow the portal: not changed here."""
    if s.source != 'bundled':
        return
    v = _view(_get(s, dn))
    if v['managed']:
        raise Error('MANAGED', f'{what}: {v["name"]} follows the portal (users and departments in the console)')


# --- reads -----------------------------------------------------------------------------------

def test(source):
    """Bind, read the base, and what the account may create there."""
    with session(source) as s:
        rows = _search(s, s.base, '(objectClass=*)', 'base', ['allowedChildClassesEffective'])
        can = None
        if rows:
            vals = (rows[0].get('raw_attributes') or {}).get('allowedChildClassesEffective')
            if vals:
                low = {v.decode('utf-8', 'replace').lower() if isinstance(v, bytes) else str(v).lower() for v in vals}
                can = {k: k.lower() in low for k in ('user', 'group', 'organizationalUnit')}
        return {'ok': True, 'source': source, 'base_dn': s.base, 'can_create': can}


def tree(source, dn=None):
    """The containers right under dn (the base when None)."""
    with session(source) as s:
        at = _inside(s, dn) if dn else s.base
        rows = _search(s, at, CONTAINER_FILTER, 'one', ['objectClass', 'ou', 'cn', 'name', 'description', 'info'])
        out = []
        for e in rows:
            if e['dn'].lower() == at.lower():
                continue
            v = _view(e)
            out.append({'dn': v['dn'], 'name': v['name'], 'kind': v['kind'], 'description': v['description'], 'managed': v['managed']})
        return {'dn': at, 'children': sorted(out, key=lambda x: (x['kind'] != 'ou', x['name'].lower()))}


def objects(source, dn=None, kind='all', q='', subtree=False):
    if kind not in KIND_FILTERS:
        raise Error('BAD_KIND', 'kind: ' + ', '.join(KIND_FILTERS))
    with session(source) as s:
        at = _inside(s, dn) if dn else s.base
        flt = KIND_FILTERS[kind]
        q = (q or '').strip()[:64]
        if q:
            e = directory._esc(q)
            flt = f'(&{flt}(|(cn=*{e}*)(sAMAccountName=*{e}*)(displayName=*{e}*)(mail=*{e}*)(description=*{e}*)))'
        rows = _search(s, at, flt, 'sub' if (subtree or q) else 'one')
        items = [_view(e) for e in rows if e['dn'].lower() != at.lower()]
        return {'dn': at, 'objects': sorted(items, key=lambda x: (x['kind'], x['name'].lower())), 'truncated': len(rows) >= MAX_ROWS}


def _members(s, dn):
    e = _get(s, dn, ['member'])
    return [m.decode('utf-8', 'replace') if isinstance(m, bytes) else str(m) for m in (e.get('raw_attributes') or {}).get('member') or []]


def nested_members(s, dn):
    """Every member reached through member groups (breadth first, each once): {dn_lower: dn}."""
    seen, todo = {}, [dn]
    while todo and len(seen) < MAX_NESTED:
        cur = todo.pop(0)
        try:
            ms = _members(s, cur)
        except Error:
            continue
        for m in ms:
            if m.lower() in seen:
                continue
            seen[m.lower()] = m
            todo.append(m)            # a non-group answers with no members
    return seen


def get_object(source, dn):
    with session(source) as s:
        dn = _inside(s, dn)
        v = _view(_get(s, dn))
        if v['kind'] == 'group':
            direct = _members(s, dn)
            nested = nested_members(s, dn)
            direct_low = {m.lower() for m in direct}
            v['members'] = direct
            v['nested_members'] = [m for k, m in nested.items() if k not in direct_low and k != dn.lower()]
        return v


# --- changes ---------------------------------------------------------------------------------

def _checked_name(name, what):
    name = (name or '').strip()
    if not _NAME.match(name):
        raise Error('BAD_NAME', f'{what}: 1-64 characters, none of " / \\ [ ] : ; | = , + * ? < > @')
    return name


def create_ou(source, parent_dn, name, description=''):
    from ldap3.utils.dn import escape_rdn
    with session(source) as s:
        parent = _inside(s, parent_dn)
        name = _checked_name(name, 'name')
        dn = f'OU={escape_rdn(name)},{parent}'
        attrs = {'ou': name}
        if description:
            attrs['description'] = description[:1024]
        directory._check(s.conn, s.conn.add(dn, ['top', 'organizationalUnit'], attrs), f'make OU {name}')
        return _view(_get(s, dn))


def create_group(source, parent_dn, name, scope='global', gtype='security', description='', sam=None):
    from ldap3.utils.dn import escape_rdn
    if scope not in SCOPES:
        raise Error('BAD_SCOPE', 'scope: global, universal or domain_local')
    if gtype not in ('security', 'distribution'):
        raise Error('BAD_TYPE', 'type: security or distribution')
    with session(source) as s:
        parent = _inside(s, parent_dn)
        name = _checked_name(name, 'name')
        sam = (sam or name).strip()
        if not _GROUP_SAM.match(sam):
            raise Error('BAD_NAME', 'sAMAccountName is not valid')
        gt = SCOPES[scope] | (GT_SECURITY if gtype == 'security' else 0)
        if gt & 0x80000000:
            gt -= 1 << 32                 # AD stores groupType as a signed 32-bit number
        dn = f'CN={escape_rdn(name)},{parent}'
        attrs = {'sAMAccountName': sam, 'groupType': str(gt)}
        if description:
            attrs['description'] = description[:1024]
        directory._check(s.conn, s.conn.add(dn, ['top', 'group'], attrs), f'make group {name}')
        return _view(_get(s, dn))


def create_user(source, parent_dn, sam, display_name='', given_name='', surname='', mail='', description='',
                password=None, enabled=True):
    """A user; with a password it is set by the directory and the account enabled when asked,
    without one it stays disabled (a password set later enables it). The password is not kept."""
    from ldap3.utils.dn import escape_rdn
    with session(source) as s:
        parent = _inside(s, parent_dn)
        users_ou = directory.config()['users_dn'].lower()
        if s.source == 'bundled' and (parent.lower() == users_ou or parent.lower().endswith(',' + users_ou)):
            raise Error('MANAGED', 'portal accounts are made under 사용자 in the console - they get their directory account there')
        sam = (sam or '').strip()
        if not _SAM.match(sam):
            raise Error('BAD_NAME', 'sAMAccountName: 1-20 letters, digits, ".", "_" or "-"')
        realm = '.'.join(p.split('=', 1)[1] for p in s.base.split(',') if p.strip().upper().startswith('DC='))
        cn = (display_name or sam).strip()[:64]
        _checked_name(cn, 'name')
        dn = f'CN={escape_rdn(cn)},{parent}'
        attrs = {'sAMAccountName': sam, 'userPrincipalName': f'{sam}@{realm}' if realm else sam,
                 'userAccountControl': str(directory.UAC_NORMAL | directory.UAC_DISABLED)}
        for k, v in (('displayName', display_name), ('givenName', given_name), ('sn', surname), ('mail', mail),
                     ('description', description)):
            if v:
                attrs[k] = str(v)[:256]
        directory._check(s.conn, s.conn.add(dn, ['top', 'person', 'organizationalPerson', 'user'], attrs), f'make user {sam}')
        if password:
            directory._set_password_dn(s.conn, dn, password, f'password of {sam}')
            if enabled:
                directory._modify(s.conn, dn, {'userAccountControl': str(directory.UAC_NORMAL)}, f'enable {sam}')
        return _view(_get(s, dn))


def update_object(source, dn, changes):
    with session(source) as s:
        dn = _inside(s, dn)
        _guard(s, dn, 'change')
        v = _view(_get(s, dn))
        cls = {'user': 'user', 'computer': 'user', 'group': 'group', 'ou': 'organizationalUnit'}.get(v['kind'])
        allowed = EDITABLE.get(cls, ())
        bad = sorted(k for k in changes if k not in allowed)
        if bad:
            raise Error('NOT_EDITABLE', 'not changed here: ' + ', '.join(bad))
        out = {}
        for k, val in changes.items():
            if val is not None and not isinstance(val, str):
                raise Error('BAD_VALUE', f'{k} must be text')
            out[k] = (val or '').strip()[:1024] or []
        if out:
            directory._modify(s.conn, dn, out, f'change {v["name"]}')
        return _view(_get(s, dn))


def set_enabled(source, dn, enabled):
    with session(source) as s:
        dn = _inside(s, dn)
        _guard(s, dn, 'enable / disable')
        e = _get(s, dn)
        v = _view(e)
        if v['kind'] not in ('user', 'computer'):
            raise Error('NOT_A_USER', 'only users and computers are enabled or disabled')
        raw = (e.get('raw_attributes') or {}).get('userAccountControl') or [b'512']
        uac = int(raw[0])
        uac = (uac & ~directory.UAC_DISABLED) if enabled else (uac | directory.UAC_DISABLED)
        directory._modify(s.conn, dn, {'userAccountControl': str(uac)}, ('enable ' if enabled else 'disable ') + v['name'])
        return _view(_get(s, dn))


def set_password(source, dn, password):
    with session(source) as s:
        dn = _inside(s, dn)
        _guard(s, dn, 'password')
        if _view(_get(s, dn))['kind'] != 'user':
            raise Error('NOT_A_USER', 'only a user has a password')
        directory._set_password_dn(s.conn, dn, password, 'password')
        return True


def delete_object(source, dn):
    with session(source) as s:
        dn = _inside(s, dn)
        if dn.lower() == s.base.lower():
            raise Error('REFUSED', 'the base of the directory is not deleted')
        _guard(s, dn, 'delete')
        v = _view(_get(s, dn))
        if v['kind'] in ('ou', 'container'):
            kids = [k for k in _search(s, dn, '(objectClass=*)', 'one', ['objectClass'], limit=3) if k['dn'].lower() != dn.lower()]
            if kids:
                raise Error('NOT_EMPTY', f'{v["name"]} is not empty - move or delete what is in it first')
        directory._check(s.conn, s.conn.delete(dn), f'delete {v["name"]}')
        return v


def change_member(source, group_dn, member_dn, add=True):
    """Add or remove a member. A group cannot contain itself, directly or through its members."""
    from ldap3 import MODIFY_ADD, MODIFY_DELETE
    with session(source) as s:
        group_dn = _inside(s, group_dn)
        member_dn = _inside(s, member_dn)
        _guard(s, group_dn, 'members')
        g = _view(_get(s, group_dn))
        if g['kind'] != 'group':
            raise Error('NOT_A_GROUP', f'{g["name"]} is not a group')
        m = _view(_get(s, member_dn))
        current = {x.lower(): x for x in _members(s, group_dn)}
        if add:
            if member_dn.lower() == group_dn.lower():
                raise Error('SELF', 'a group cannot be a member of itself')
            if m['kind'] == 'group' and group_dn.lower() in nested_members(s, member_dn):
                raise Error('CYCLE', f'{m["name"]} already contains {g["name"]} - adding it would make a loop')
            if member_dn.lower() in current:
                return get_view_members(s, group_dn)
            directory._check(s.conn, s.conn.modify(group_dn, {'member': [(MODIFY_ADD, [member_dn])]}), f'add to {g["name"]}')
        else:
            if member_dn.lower() not in current:
                return get_view_members(s, group_dn)
            directory._check(s.conn, s.conn.modify(group_dn, {'member': [(MODIFY_DELETE, [current[member_dn.lower()]])]}),
                             f'remove from {g["name"]}')
        return get_view_members(s, group_dn)


def get_view_members(s, group_dn):
    v = _view(_get(s, group_dn))
    v['members'] = _members(s, group_dn)
    return v
