# -*- coding: utf-8 -*-
"""
MOAVI Desk - Warpgate 접근 게이트웨이(bastion) 연동.

Warpgate(github.com/warp-tech/warpgate, Apache-2.0)를 데스크톱 접속의 단일 bastion으로 쓴다.
모든 RDP/SSH/VNC가 Warpgate를 거치므로 데스크톱 실제 주소가 숨고, 세션이 녹화되며, 접속할 때
사용자·데스크톱 비밀번호를 저장·전달하지 않는다(대상·사용자에 고정된 1회용·단시간 티켓).

설계: docs/warpgate-gateway.md.

- 설정 1행 테이블 vlab_warpgate: base_url + 관리자 API 토큰(get_db()._encrypt로 봉인, nas.py 패턴)
  + SSH/RDP/VNC 리스너 포트. 대상 매핑 vlab_warpgate_targets: MOAVI Desk 데스크톱/외부 데스크톱 ↔
  Warpgate target UUID.
- Admin API 인증 헤더: X-Warpgate-Token. 티켓 발급 POST /tickets, 대상 POST /targets.
- 비밀번호 저장 안 함: VNC는 None 인증, SSH는 Warpgate 공개키, RDP는 interactive_logon(자동 로그인
  안 함; NLA용 서비스 계정은 사용자 비번이 아님). 엔진 DB엔 사용자 비번을 넣지 않는다.

HTTP 호출은 _api() 한 곳으로 모아 테스트에서 가로채기 쉽게 했다(네트워크 없이 규칙을 검증).
"""

import json
import logging
import os
import re
import threading

from pegaprox.vlab.store import db as _store_db, now

CONFIG_ID = 'wg'            # single-row config
TARGET_KINDS = ('rdp', 'ssh', 'vnc')

# Warpgate 리스너 기본 포트(기본 설정 기준; config로 바꿀 수 있어 설정값을 우선한다)
DEFAULT_PORTS = {'ssh': 2222, 'rdp': 3389, 'vnc': 5900, 'http': 443}

# 티켓 유효 시간(초): 좌표를 받은 뒤 접속을 시작하기까지의 여유. 1회용이라 접속하면 소진된다.
TICKET_TTL_SECONDS = 180

_SCHEMA = (
    '''CREATE TABLE IF NOT EXISTS vlab_warpgate (
        id TEXT PRIMARY KEY,
        base_url TEXT NOT NULL DEFAULT '',
        admin_token_encrypted TEXT NOT NULL DEFAULT '',
        ssh_port INTEGER NOT NULL DEFAULT 2222,
        rdp_port INTEGER NOT NULL DEFAULT 3389,
        vnc_port INTEGER NOT NULL DEFAULT 5900,
        verify_tls INTEGER NOT NULL DEFAULT 0,
        rdp_nla_user TEXT NOT NULL DEFAULT '',
        rdp_nla_password_encrypted TEXT NOT NULL DEFAULT '',
        web_rdp_provider TEXT NOT NULL DEFAULT 'guac',
        rdp_via_warpgate INTEGER NOT NULL DEFAULT 0,
        allow_direct_fallback INTEGER NOT NULL DEFAULT 0,
        enabled INTEGER NOT NULL DEFAULT 0,
        last_check TEXT,
        last_ok INTEGER,
        last_detail TEXT NOT NULL DEFAULT '',
        updated_at TEXT
    )''',
    # MOAVI Desk 데스크톱/외부 데스크톱 1개를 Warpgate target 1개에 매핑(동기화 상태).
    '''CREATE TABLE IF NOT EXISTS vlab_warpgate_targets (
        ref TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        target_uuid TEXT NOT NULL DEFAULT '',
        target_name TEXT NOT NULL DEFAULT '',
        proto TEXT NOT NULL DEFAULT 'rdp',
        address TEXT NOT NULL DEFAULT '',
        port INTEGER NOT NULL DEFAULT 0,
        synced_at TEXT
    )''',
    # one-off upgrade steps that went through (migrate_legacy_users)
    '''CREATE TABLE IF NOT EXISTS vlab_warpgate_state (key TEXT PRIMARY KEY, value TEXT)''',
)

TABLES = ('vlab_warpgate', 'vlab_warpgate_targets', 'vlab_warpgate_state')

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_warpgate', False):
        with _lock:
            if not getattr(d, '_vlab_warpgate', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                _migrate_target_refs(d)
                d._vlab_warpgate = True
    return d


def _migrate_target_refs(d):
    """Older engines kept one mapping per desktop (ref = desktop id) whatever its protocol, so a
    desktop first opened over SSH could never get an RDP target. SSH/VNC mappings now live under
    target_ref(ref, proto); move old ones there (the Warpgate target itself is kept and renamed on its
    next sync). Idempotent."""
    d.execute("""UPDATE vlab_warpgate_targets SET ref = ref || '-' || proto
                 WHERE proto IN ('ssh', 'vnc') AND ref NOT LIKE '%-' || proto""")


def target_ref(ref, proto):
    """Mapping key of a desktop's Warpgate target for one protocol: Warpgate cannot change a target's
    kind, so each protocol gets its own target. RDP keeps the plain ref (existing targets stay valid)."""
    return ref if proto == 'rdp' else f'{ref}-{proto}'


# --- config ------------------------------------------------------------------------------

def _row():
    return db().query_one('SELECT * FROM vlab_warpgate WHERE id = ?', (CONFIG_ID,))


def is_enabled():
    r = _row()
    return bool(r and r['enabled'] and r['base_url'] and r['admin_token_encrypted'])


def config(secret=False):
    """공개용 설정(토큰 없음). secret=True면 관리자 토큰을 복호화해 담는다(내부 전용)."""
    r = _row()
    if not r:
        return {'base_url': '', 'ssh_port': DEFAULT_PORTS['ssh'], 'rdp_port': DEFAULT_PORTS['rdp'],
                'vnc_port': DEFAULT_PORTS['vnc'], 'verify_tls': False, 'enabled': False,
                'rdp_nla_user': '', 'has_nla_password': False, 'web_rdp_provider': 'guac',
                'rdp_via_warpgate': False, 'allow_direct_fallback': False,
                'has_token': False, 'last_check': None, 'last_ok': None, 'last_detail': ''}
    out = {'base_url': r['base_url'], 'ssh_port': r['ssh_port'], 'rdp_port': r['rdp_port'],
           'vnc_port': r['vnc_port'], 'verify_tls': bool(r['verify_tls']), 'enabled': bool(r['enabled']),
           'rdp_nla_user': r['rdp_nla_user'], 'has_nla_password': bool(r['rdp_nla_password_encrypted']),
           'web_rdp_provider': r['web_rdp_provider'] or 'guac',
           'rdp_via_warpgate': bool(r['rdp_via_warpgate']),
           'allow_direct_fallback': bool(r['allow_direct_fallback']),
           'has_token': bool(r['admin_token_encrypted']), 'last_check': r['last_check'],
           'last_ok': None if r['last_ok'] is None else bool(r['last_ok']), 'last_detail': r['last_detail']}
    if secret:
        out['admin_token'] = _unseal(r['admin_token_encrypted'])
        out['rdp_nla_password'] = _unseal(r['rdp_nla_password_encrypted'])
    return out


def _unseal(sealed):
    if not sealed:
        return ''
    from pegaprox.core.db import get_db
    try:
        return get_db()._decrypt(sealed)
    except Exception:
        return ''


def save_config(base_url, ssh_port, rdp_port, vnc_port, verify_tls, enabled,
                admin_token=None, rdp_nla_user=None, rdp_nla_password=None, web_rdp_provider=None,
                rdp_via_warpgate=None, allow_direct_fallback=None):
    """설정 저장. admin_token / rdp_nla_password: None이면 기존값 유지, ''이면 지움, 값이면 봉인해 저장.
    web_rdp_provider: 'guac'(기본, 항상 작동) 또는 'warpgate'(실클러스터 검증 후 전환).
    rdp_via_warpgate: 전용 앱·mstsc용 .rdp를 Warpgate로 향하게 할지(None이면 기존값 유지).
    allow_direct_fallback: Warpgate 장애 때 직접/Guacamole 경로로 열어 줄지(기본 꺼짐 = 접속 거부. 켜면 보안 약화)."""
    base_url = (base_url or '').strip().rstrip('/')
    r = _row()
    sealed = r['admin_token_encrypted'] if r else ''
    nla_sealed = r['rdp_nla_password_encrypted'] if r else ''
    nla_user = r['rdp_nla_user'] if r else ''
    provider = (r['web_rdp_provider'] if r else 'guac') or 'guac'
    via = bool(r['rdp_via_warpgate']) if r else False
    if rdp_via_warpgate is not None:
        via = bool(rdp_via_warpgate)
    fallback = bool(r['allow_direct_fallback']) if r else False
    if allow_direct_fallback is not None:
        fallback = bool(allow_direct_fallback)
    if admin_token is not None or rdp_nla_password is not None:
        from pegaprox.core.db import get_db
        gdb = get_db()
        if admin_token is not None:
            sealed = gdb._encrypt(admin_token) if admin_token else ''
        if rdp_nla_password is not None:
            nla_sealed = gdb._encrypt(rdp_nla_password) if rdp_nla_password else ''
    if rdp_nla_user is not None:
        nla_user = (rdp_nla_user or '').strip()
    if web_rdp_provider in ('guac', 'warpgate'):
        provider = web_rdp_provider
    db().execute(
        '''INSERT OR REPLACE INTO vlab_warpgate
           (id, base_url, admin_token_encrypted, ssh_port, rdp_port, vnc_port, verify_tls,
            rdp_nla_user, rdp_nla_password_encrypted, web_rdp_provider, rdp_via_warpgate, allow_direct_fallback, enabled,
            last_check, last_ok, last_detail, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (CONFIG_ID, base_url, sealed, int(ssh_port), int(rdp_port), int(vnc_port),
         1 if verify_tls else 0, nla_user, nla_sealed, provider, 1 if via else 0, 1 if fallback else 0, 1 if enabled else 0,
         r['last_check'] if r else None, r['last_ok'] if r else None,
         r['last_detail'] if r else '', now()))
    return config()


def mark_check(ok, detail):
    db().execute('UPDATE vlab_warpgate SET last_check = ?, last_ok = ?, last_detail = ? WHERE id = ?',
                 (now(), 1 if ok else 0, (detail or '')[:300], CONFIG_ID))
    return config()


# --- target mapping ----------------------------------------------------------------------

def get_mapping(ref):
    r = db().query_one('SELECT * FROM vlab_warpgate_targets WHERE ref = ?', (ref,))
    return dict(r) if r else None


def list_mappings():
    return [dict(r) for r in db().query('SELECT * FROM vlab_warpgate_targets ORDER BY ref')]


def save_mapping(ref, kind, target_uuid, target_name, proto, address, port):
    db().execute(
        '''INSERT OR REPLACE INTO vlab_warpgate_targets
           (ref, kind, target_uuid, target_name, proto, address, port, synced_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
        (ref, kind, target_uuid or '', target_name or '', proto, address or '', int(port or 0), now()))
    return get_mapping(ref)


def delete_mapping(ref):
    db().execute('DELETE FROM vlab_warpgate_targets WHERE ref = ?', (ref,))


# --- pure payload / coordinate helpers (네트워크 없이 테스트 가능) -----------------------------

def target_name_for(ref, label):
    """Warpgate 대상 이름: MOAVI Desk ref를 넣어 충돌 없이 되찾을 수 있게 한다."""
    safe = re.sub(r'[^A-Za-z0-9._-]+', '-', str(label or '')).strip('-').lower() or 'desktop'
    # cut the label, never the ref: two protocol targets of one desktop differ only at the end
    head = f'moavi-{safe}'[:max(6, 62 - len(str(ref)))].rstrip('-')
    return f'{head}-{ref}'


def ssh_target_options(host, port, username):
    """SSH 대상: Warpgate 자체 공개키로 대상에 접속(사용자 비번 저장 안 함).
    공개키는 Warpgate가 보관(ssh/own-keys)하고 대상 authorized_keys에 심는다."""
    return {'kind': 'Ssh', 'host': host, 'port': int(port), 'username': username,
            'allow_insecure_algos': False, 'auth': {'kind': 'PublicKey'}}


def rdp_target_options(host, port, username, nla_password, domain='', interactive_logon=True):
    """RDP 대상: interactive_logon=True → 자동 로그인하지 않고 대상의 Windows 로그온 화면을 띄운다.
    nla_password는 네트워크 수준 인증(CredSSP)용 **서비스 계정** 비밀번호이지 사용자 비번이 아니며,
    아무도 로그인시키지 않는다. 사용자는 자기 디렉터리 계정으로 로그온 화면에서 직접 로그인한다."""
    opts = {'kind': 'Rdp', 'host': host, 'port': int(port), 'username': username,
            'auth': {'kind': 'Password', 'password': nla_password or ''},
            'verify_tls': False, 'compression': 'remotefx',
            'interactive_logon': bool(interactive_logon), 'tls_security': 'Tls12'}
    if domain:
        opts['domain'] = domain
    return opts


def vnc_target_options(host, port, vnc_password=None):
    """VNC 대상: 비밀번호가 없으면 None 인증(저장 자격 없음). 있으면 대상 자체의 VNC 비번."""
    if vnc_password:
        return {'kind': 'Vnc', 'host': host, 'port': int(port), 'auth': {'kind': 'Password', 'password': vnc_password}}
    return {'kind': 'Vnc', 'host': host, 'port': int(port), 'auth': {'kind': 'None'}}


def ticket_login(secret):
    """RDP/SSH/VNC에서 티켓을 제시하는 사용자 이름(비밀번호는 쓰이지 않는다)."""
    return f'ticket-{secret}'


def web_ui_url(cfg, proto=None, target_uuid=None):
    """Warpgate 웹 UI(로그인 뒤 대상 목록에서 브라우저 RDP/SSH를 연다).

    실제 Warpgate(v0.29.2)로 확인: `?warpgate-ticket=` 은 HTTP 대상에만 웹 세션을 열고, RDP/SSH
    대상의 티켓으로는 세션을 열지 않으며 티켓도 쓰지 않는다(Warpgate 자체 테스트
    test_non_http_ticket_opens_no_session). 그래서 브라우저 경로는 티켓 없이 Warpgate 웹 UI로
    보내고 사용자는 SSO/LDAP으로 로그인한다(비밀번호를 우리가 저장하지 않음). 티켓은 native 전용.
    With a target, the link opens that desktop directly (Warpgate 0.29.2 web UI routes:
    #/web-desktop/start/<uuid> for RDP/VNC, #/web-ssh/start/<uuid> for SSH) once signed in."""
    base = cfg['base_url'].rstrip('/') + '/@warpgate#/'
    if target_uuid and proto in TARGET_KINDS:
        return base + ('web-ssh' if proto == 'ssh' else 'web-desktop') + f'/start/{target_uuid}'
    return base


def connection_coordinates(cfg, proto, target_name, secret, target_uuid=None):
    """티켓 secret으로 접속할 native 좌표 + 브라우저용 Warpgate 웹 UI 주소(티켓 없음).
    엔진은 secret을 저장하지 않고 이 응답에만 싣는다."""
    host = _host_of(cfg['base_url'])
    login = ticket_login(secret)
    browser = web_ui_url(cfg, proto, target_uuid)
    if proto == 'ssh':
        return {'proto': 'ssh', 'host': host, 'port': int(cfg['ssh_port']),
                'username': login, 'ssh': f"ssh {login}@{host} -p {int(cfg['ssh_port'])}", 'browser_url': browser}
    if proto == 'vnc':
        return {'proto': 'vnc', 'host': host, 'port': int(cfg['vnc_port']), 'username': login, 'browser_url': browser}
    return {'proto': 'rdp', 'host': host, 'port': int(cfg['rdp_port']), 'username': login,
            'full_address': f"{host}:{int(cfg['rdp_port'])}", 'browser_url': browser}


def rdp_file_text(cfg, secret, redirect_lines=(), network_lines=()):
    """An .rdp aimed at Warpgate's RDP listener for one single-use ticket (mstsc / the MOAVI Desk
    client open it unchanged). The ticket is the user name; there is no password to store or send.

    - enablecredsspsupport:i:0: Warpgate's RDP listener is TLS without NLA (it reads the ticket from
      the user name after the handshake), so mstsc must not ask for CredSSP credentials first.
    - prompt for credentials:i:0: nothing to type for Warpgate itself; with interactive logon the
      desktop's own Windows logon screen then asks the user for their own (AD) account.
    - autoreconnection off: the ticket is spent on the first connect, a silent reconnect would fail -
      the user reconnects from the client/portal, which issues a new ticket."""
    host = _host_of(cfg['base_url'])
    lines = [f"full address:s:{host}:{int(cfg['rdp_port'])}", f'username:s:{ticket_login(secret)}',
             'prompt for credentials:i:0', 'enablecredsspsupport:i:0', 'authentication level:i:2',
             'screen mode id:i:2', 'use multimon:i:1', *redirect_lines, 'audiomode:i:0']
    lines += [x for x in network_lines if not x.startswith('autoreconnection enabled:')]
    lines.append('autoreconnection enabled:i:0')
    return '\r\n'.join(lines) + '\r\n'


def _host_of(base_url):
    m = re.match(r'^[a-z]+://([^/:]+)', base_url or '')
    return m.group(1) if m else (base_url or '')


# --- admin API client (requests; _api() 한 곳으로 모아 테스트에서 가로챈다) --------------------

class WarpgateError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def _api(method, path, token, base_url, verify_tls, body=None, timeout=15):
    """Warpgate 관리자 API 호출. 반환: (status_code, parsed_json_or_text)."""
    import requests
    url = base_url.rstrip('/') + '/@warpgate/admin/api' + path
    headers = {'X-Warpgate-Token': token, 'Accept': 'application/json'}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    resp = requests.request(method, url, headers=headers,
                            data=json.dumps(body) if body is not None else None,
                            timeout=timeout, verify=bool(verify_tls), allow_redirects=False)
    try:
        parsed = resp.json()
    except Exception:
        parsed = resp.text
    return resp.status_code, parsed


def _call(cfg, method, path, body=None):
    if not cfg.get('base_url') or not cfg.get('admin_token'):
        raise WarpgateError('보안 게이트웨이가 설정되지 않았습니다')
    code, data = _api(method, path, cfg['admin_token'], cfg['base_url'], cfg.get('verify_tls'), body)
    if code >= 400:
        raise WarpgateError(f'Warpgate API {method} {path} -> {code}: {str(data)[:200]}', code)
    return data


def test_connection(cfg):
    """설정 점검: 대상 목록을 읽어 토큰/주소가 맞는지 본다. (ok, detail)."""
    try:
        data = _call(cfg, 'GET', '/targets')
        n = len(data) if isinstance(data, list) else 0
        return True, f'대상 {n}개'
    except WarpgateError as e:
        return False, str(e)
    except Exception as e:  # 네트워크/TLS 등
        return False, str(e)[:200]


def ensure_role(cfg, name='moavi-desk'):
    """MOAVI Desk 전용 역할을 보장하고 UUID를 돌려준다(대상·사용자 연결용)."""
    for r in _call(cfg, 'GET', '/roles') or []:
        if isinstance(r, dict) and r.get('name') == name:
            return r['id']
    created = _call(cfg, 'POST', '/roles', {'name': name})
    return created['id']


# Warpgate users the engine makes carry this prefix and this description: a portal account named like
# one of Warpgate's own (its superadmin 'admin') must never become that account.
USER_PREFIX = 'moavi-'
MANAGED_DESC = 'MOAVI Desk managed user'


def wg_user_name(username):
    """The Warpgate user name of a portal user (reserved prefix, never one of Warpgate's own accounts)."""
    return f'{USER_PREFIX}{username}'


def ensure_user(cfg, username, role_id=None):
    """포털 사용자 username의 Warpgate 사용자(moavi-<username>)를 보장한다(비밀번호 자격 없이; 인증은
    SSO/티켓/공개키). role_id가 있으면 그 역할을 붙인다. UUID 반환.
    엔진이 만든 사용자(MANAGED_DESC)가 아니거나 Warpgate 관리자 역할이 있는 사용자에게는 자격·역할을
    붙이지 않고 거부한다."""
    name = wg_user_name(username)
    uid = None
    for u in _call(cfg, 'GET', '/users') or []:
        if isinstance(u, dict) and u.get('username') == name:
            if not str(u.get('description') or '').startswith(MANAGED_DESC):
                raise WarpgateError(f'Warpgate user {name} is not managed by MOAVI Desk', 409)
            uid = u['id']
            break
    if uid is None:
        created = _call(cfg, 'POST', '/users', {'username': name, 'description': f'{MANAGED_DESC} ({username})'})
        uid = created['id']
    if _call(cfg, 'GET', f'/users/{uid}/admin-roles'):
        raise WarpgateError(f'Warpgate user {name} has an admin role; MOAVI Desk leaves it alone', 409)
    _ensure_sso_credential(cfg, uid, username)
    if role_id:
        try:
            # the API wants a JSON body here (AddUserRoleRequest, optional expires_at) - without one
            # it refuses the request (found against a live Warpgate)
            _call(cfg, 'POST', f'/users/{uid}/roles/{role_id}', {})
        except WarpgateError as e:
            if e.status != 409:   # 409 = already has the role; anything else is a real failure
                raise
    return uid


def _ensure_sso_credential(cfg, uid, username):
    """With MOAVI Desk as Warpgate's sign-in (pegaprox/vlab/wg_oidc.py), Warpgate finds the user by
    this SSO credential: provider moavi-desk + the user's fixed SSO e-mail. No password anywhere."""
    from pegaprox.vlab import wg_oidc
    if not wg_oidc.is_enabled():
        return
    email = wg_oidc.sso_email(username)
    have = _call(cfg, 'GET', f'/users/{uid}/credentials/sso') or []
    if any(isinstance(c, dict) and c.get('provider') == wg_oidc.PROVIDER_NAME and c.get('email') == email
           for c in have):
        return
    _call(cfg, 'POST', f'/users/{uid}/credentials/sso', {'provider': wg_oidc.PROVIDER_NAME, 'email': email})


def sync_target(cfg, ref, label, proto, options, role_id=None):
    """데스크톱 1개·프로토콜 1개에 대응하는 Warpgate 대상을 보장(없으면 생성)하고 매핑을 저장한다.
    options는 *_target_options()가 만든 dict. role_id가 있으면 대상에 역할을 연결.
    SSH 대상이면 대상의 호스트 키를 Warpgate known hosts에 올린다(실패해도 동기화는 계속)."""
    ref = target_ref(ref, proto)
    name = target_name_for(ref, label)
    mp = get_mapping(ref)
    body = {'name': name, 'options': options, 'ticket_requests_disabled': False,
            'ticket_require_approval': False, 'require_approval': False}
    uuid_val = ''
    if mp and mp['target_uuid']:
        try:
            _call(cfg, 'PUT', f"/targets/{mp['target_uuid']}", body)
            uuid_val = mp['target_uuid']
        except WarpgateError:
            uuid_val = ''
    if not uuid_val:
        try:
            uuid_val = _call(cfg, 'POST', '/targets', body)['id']
        except WarpgateError as e:
            # the name is ours (moavi-<label>-<ref>) but our mapping is gone - a restored or
            # standby DB, a reinstall: adopt Warpgate's target and bring it up to date
            if e.status != 409:
                raise
            found = [t for t in (_call(cfg, 'GET', '/targets') or []) if isinstance(t, dict) and t.get('name') == name]
            if not found:
                raise
            owner = _mapping_of_target(found[0]['id'])
            if owner and owner['ref'] != ref:
                # the desktop's target for another protocol still has this name (an older engine used one
                # name per desktop): give it its own name, then create ours
                _rename_target(cfg, owner, target_name_for(owner['ref'], label))
                uuid_val = _call(cfg, 'POST', '/targets', body)['id']
            else:
                uuid_val = found[0]['id']
                _call(cfg, 'PUT', f'/targets/{uuid_val}', body)
        if role_id:
            try:
                _call(cfg, 'POST', f'/targets/{uuid_val}/roles/{role_id}')
            except WarpgateError as e:
                if e.status != 409:   # 409 = the role is already on the target
                    raise
    save_mapping(ref, 'desktop', uuid_val, name, proto, options.get('host', ''), options.get('port', 0))
    if proto == 'ssh':
        try:
            trust_ssh_host(cfg, options.get('host', ''), options.get('port', 22))
        except Exception as e:
            logging.warning(f"[VLAB] Warpgate: SSH host key of {name} not added to known hosts: {str(e)[:200]}")
    return uuid_val, name


def _mapping_of_target(target_uuid):
    r = db().query_one('SELECT * FROM vlab_warpgate_targets WHERE target_uuid = ?', (target_uuid,))
    return dict(r) if r else None


def _rename_target(cfg, mapping, new_name):
    """Rename a mapped Warpgate target, keeping its options as Warpgate has them."""
    t = _call(cfg, 'GET', f"/targets/{mapping['target_uuid']}") or {}
    body = {'name': new_name, 'options': t.get('options')}
    if t.get('description'):
        body['description'] = t['description']
    _call(cfg, 'PUT', f"/targets/{mapping['target_uuid']}", body)
    db().execute('UPDATE vlab_warpgate_targets SET target_name = ? WHERE ref = ?', (new_name, mapping['ref']))


# --- SSH host keys (Warpgate trusts a target's key only once it is in its known hosts) -------

def scan_host_keys(host, port=22, timeout=5):
    """ssh-keyscan: the target's SSH host keys as [(key_type, key_base64)], one per key type it offers."""
    import socket
    import paramiko
    out = []
    for alg in ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'rsa-sha2-512'):
        sock = t = None
        try:
            sock = socket.create_connection((host, int(port)), timeout=timeout)
            t = paramiko.Transport(sock)
            t.get_security_options().key_types = (alg,)
            t.start_client(timeout=timeout)
            k = t.get_remote_server_key()
            pair = (k.get_name(), k.get_base64())
            if pair not in out:
                out.append(pair)
        except Exception:
            pass   # the host does not offer this key type
        finally:
            if t:
                t.close()
            elif sock:
                sock.close()
    return out


def trust_ssh_host(cfg, host, port=22):
    """Put the target's current SSH host keys into Warpgate's known hosts (POST /ssh/known-hosts), so
    exec/scp/VS Code work on the first connect instead of waiting for someone to accept the key
    interactively. A stale key of the same type for this host:port (an address reused by a rebuilt
    desktop) is replaced. Returns how many keys were added."""
    keys = scan_host_keys(host, port)
    if not keys:
        raise WarpgateError(f'no SSH host key from {host}:{port}')
    known = [k for k in (_call(cfg, 'GET', '/ssh/known-hosts') or [])
             if isinstance(k, dict) and k.get('host') == host and int(k.get('port') or 0) == int(port)]
    added = 0
    for key_type, b64 in keys:
        same = [k for k in known if k.get('key_type') == key_type]
        if any(k.get('key_base64') == b64 for k in same):
            continue
        for k in same:
            _call(cfg, 'DELETE', f"/ssh/known-hosts/{k['id']}")
            logging.info(f'[VLAB] Warpgate: replaced the old {key_type} host key of {host}:{port}')
        _call(cfg, 'POST', '/ssh/known-hosts',
              {'host': host, 'port': int(port), 'key_type': key_type, 'key_base64': b64})
        added += 1
    return added


def remove_target(cfg, ref, proto=None):
    """데스크톱이 없어질 때 그 Warpgate 대상과 매핑을 지운다. 이미 없으면(404) 매핑만 지운다.
    proto=None: every protocol's target of the desktop; returns the removed UUIDs (list).
    proto given: that one target; returns its UUID or None."""
    if proto is None:
        removed, err = [], None
        for p in TARGET_KINDS:
            try:
                removed.append(remove_target(cfg, ref, p))
            except WarpgateError as e:   # try the others, then report
                err = e
        if err:
            raise err
        return [u for u in removed if u]
    ref = target_ref(ref, proto)
    mp = get_mapping(ref)
    if not mp:
        return None
    if mp['target_uuid']:
        code, data = _api('DELETE', f"/targets/{mp['target_uuid']}", cfg['admin_token'], cfg['base_url'],
                          cfg.get('verify_tls'))
        if code >= 400 and code != 404:
            raise WarpgateError(f"Warpgate API DELETE /targets/{mp['target_uuid']} -> {code}: {str(data)[:200]}")
    delete_mapping(ref)
    return mp['target_uuid'] or None


def forget_desktop(desktop_id, background=True):
    """A desktop was deleted or taken from its user: remove its Warpgate targets (every protocol) so
    they do not pile up and nobody keeps a way in. Best effort, off the request thread; failures are
    logged and the mappings stay for the next try."""
    if not any(get_mapping(target_ref(desktop_id, p)) for p in TARGET_KINDS) or not is_enabled():
        return
    cfg = config(secret=True)

    def run():
        try:
            remove_target(cfg, desktop_id)
        except Exception as e:
            logging.warning(f'[VLAB] Warpgate: targets of {desktop_id} not removed: {str(e)[:200]}')

    if background:
        threading.Thread(target=run, name='vlab-wg-forget', daemon=True).start()
    else:
        run()


def issue_ticket(cfg, username, target_name, ttl_seconds=TICKET_TTL_SECONDS):
    """그 사용자 + 그 대상에만 쓸 수 있는 1회용·단시간 티켓을 발급한다.
    반환: (ticket_dict, secret). secret은 저장하지 말고 응답에만 싣는다."""
    from datetime import datetime, timedelta, timezone
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
    body = {'username': wg_user_name(username), 'target_name': target_name, 'number_of_uses': 1,
            'expiry': expiry, 'description': f'MOAVI Desk connect: {username} -> {target_name}'}
    data = _call(cfg, 'POST', '/tickets', body)
    return data.get('ticket'), data.get('secret')


# --- researcher native SSH (own tools through Warpgate) ----------------------------------

_PUBKEY_RE = re.compile(r'^(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-\S+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-\S+)\s+[A-Za-z0-9+/=]+(\s+\S.*)?$')


def looks_like_private_key(text):
    """A pasted private key (PEM / OpenSSH / PuTTY .ppk) - refused with its own message."""
    t = (text or '').upper()
    return 'PRIVATE KEY' in t or 'PUTTY-USER-KEY-FILE' in t


def is_public_key(text):
    """OpenSSH 공개키 한 줄인지 확인. 개인키처럼 보이면(-----BEGIN ... PRIVATE KEY-----) 거부."""
    t = (text or '').strip()
    if not t or 'PRIVATE KEY' in t.upper():
        return False
    return bool(_PUBKEY_RE.match(t))


def list_user_keys(cfg, username):
    """사용자의 Warpgate 공개키 자격 목록(개인키는 다루지 않음)."""
    uid = ensure_user(cfg, username)
    rows = _call(cfg, 'GET', f'/users/{uid}/credentials/public-keys') or []
    return [{'id': r.get('id'), 'label': r.get('label', ''), 'openssh_public_key': r.get('openssh_public_key', ''),
             'date_added': r.get('date_added'), 'last_used': r.get('last_used')} for r in rows if isinstance(r, dict)]


def add_user_key(cfg, username, label, openssh_public_key, role_id=None):
    """사용자 공개키를 Warpgate에 등록한다(엔진 DB에는 저장하지 않는다)."""
    uid = ensure_user(cfg, username, role_id)
    created = _call(cfg, 'POST', f'/users/{uid}/credentials/public-keys',
                    {'label': (label or 'MOAVI Desk')[:80], 'openssh_public_key': openssh_public_key.strip()})
    return created


def delete_user_key(cfg, username, key_id):
    uid = ensure_user(cfg, username)
    _call(cfg, 'DELETE', f'/users/{uid}/credentials/public-keys/{key_id}')


def ssh_username(username, target_name):
    """Warpgate SSH는 점프 호스트가 아니라, 사용자 이름에 대상을 넣어 대상을 고른다(README: specifically
    formatted credentials). 그래서 ProxyJump가 아니라 `User moavi-<user>:<target>` 형식을 쓴다."""
    return f'{wg_user_name(username)}:{target_name}'


def ssh_config_entry(cfg, host_alias, username, target_name):
    """native SSH 도구(PuTTY/scp/WinSCP/VS Code Remote-SSH)용 ~/.ssh/config 한 항목."""
    wg_host = _host_of(cfg['base_url'])
    return {
        'host': host_alias,
        'hostname': wg_host,
        'port': int(cfg['ssh_port']),
        'user': ssh_username(username, target_name),
        'target_name': target_name,
        'ssh_command': f'ssh {host_alias}',
        'config_snippet': (f'Host {host_alias}\n'
                           f'    HostName {wg_host}\n'
                           f'    Port {int(cfg["ssh_port"])}\n'
                           f'    User {ssh_username(username, target_name)}\n'),
    }


def recording_url(cfg, session_id=None):
    """관리자 세션/녹화 페이지. session_id가 있으면 그 세션으로."""
    base = (cfg.get('base_url') or '').rstrip('/')
    if session_id:
        return f'{base}/@warpgate/admin/sessions/{session_id}'
    return f'{base}/@warpgate/admin/sessions'


# --- first start: connect the bundled Warpgate by itself ---------------------------------

AUTO_TOKEN_LABEL = 'moavi-desk-engine'
AUTO_TOKEN_DAYS = 365
_auto_lock = threading.Lock()


def migrate_legacy_users(cfg):
    """Engines before the moavi- prefix synced a portal user onto the Warpgate user of the same name -
    for the portal's 'admin' that was Warpgate's own superadmin. On every Warpgate user without the
    prefix, take back only what the engine put there: the moavi-desk SSO credential with that user's
    MOAVI Desk e-mail, and the moavi-desk access role. Runs until it went through once (state row).
    Returns (credentials removed, roles removed)."""
    from pegaprox.vlab import wg_oidc
    if _state('legacy_users_cleaned'):
        return 0, 0
    role_ids = {r['id'] for r in (_call(cfg, 'GET', '/roles') or [])
                if isinstance(r, dict) and r.get('name') == 'moavi-desk'}
    creds = roles = 0
    for u in _call(cfg, 'GET', '/users') or []:
        if not isinstance(u, dict) or str(u.get('username', '')).startswith(USER_PREFIX):
            continue
        uid, name = u['id'], u['username']
        ours = wg_oidc.sso_email(name)
        for c in _call(cfg, 'GET', f'/users/{uid}/credentials/sso') or []:
            if isinstance(c, dict) and c.get('provider') == wg_oidc.PROVIDER_NAME and c.get('email') == ours:
                _call(cfg, 'DELETE', f"/users/{uid}/credentials/sso/{c['id']}")
                creds += 1
                logging.warning(f'[VLAB] Warpgate: removed the MOAVI Desk sign-in the engine had put on user {name}')
        for r in _call(cfg, 'GET', f'/users/{uid}/roles') or []:
            if isinstance(r, dict) and r.get('id') in role_ids:
                _call(cfg, 'DELETE', f"/users/{uid}/roles/{r['id']}")
                roles += 1
                logging.warning(f'[VLAB] Warpgate: removed the moavi-desk role the engine had given user {name}')
    _set_state('legacy_users_cleaned', now())
    return creds, roles


def _state(key):
    r = db().query_one('SELECT value FROM vlab_warpgate_state WHERE key = ?', (key,))
    return r['value'] if r else None


def _set_state(key, value):
    db().execute('INSERT OR REPLACE INTO vlab_warpgate_state (key, value) VALUES (?, ?)', (key, value))


def _env_on(name):
    return os.environ.get(name, '').strip().lower() not in ('', '0', 'false', 'no', 'off')


def _env_port(name, default):
    v = os.environ.get(name, '').strip()
    return int(v) if v.isdigit() and 1 <= int(v) <= 65535 else default


def _is_unconfigured():
    r = _row()
    return not r or not (r['base_url'] or r['admin_token_encrypted'])


def _mint_api_token(base_url, username, password, verify_tls=False, timeout=15):
    """Log in to Warpgate as its admin and create an admin API token (~1 year), as the CI workflow
    does. Returns the token secret; the password is only sent to Warpgate, never kept."""
    import requests
    from datetime import datetime, timedelta, timezone
    api = base_url.rstrip('/') + '/@warpgate/api'
    s = requests.Session()
    s.verify = bool(verify_tls)
    r = s.post(api + '/auth/login', json={'username': username, 'password': password},
               timeout=timeout, allow_redirects=False)
    if r.status_code >= 300:
        raise WarpgateError(f'Warpgate login -> {r.status_code}', r.status_code)
    expiry = (datetime.now(timezone.utc) + timedelta(days=AUTO_TOKEN_DAYS)).strftime('%Y-%m-%dT%H:%M:%SZ')
    r = s.post(api + '/profile/api-tokens', json={'label': AUTO_TOKEN_LABEL, 'expiry': expiry},
               timeout=timeout, allow_redirects=False)
    if r.status_code >= 300:
        raise WarpgateError(f'Warpgate API token -> {r.status_code}', r.status_code)
    secret = (r.json() or {}).get('secret')
    if not secret:
        raise WarpgateError('Warpgate returned no API token')
    return secret


def auto_connect():
    """VLAB_WARPGATE=1 with VLAB_WARPGATE_URL and VLAB_WARPGATE_ADMIN_PASSWORD set, and nothing configured
    yet: log in to Warpgate, mint an admin API token, seal it and save the connection (web RDP stays on
    Guacamole). Never touches an existing configuration. Returns True when it saved one, False when it
    had nothing to do; raises when Warpgate could not be reached (the caller retries)."""
    if not _env_on('VLAB_WARPGATE'):
        return False
    base_url = os.environ.get('VLAB_WARPGATE_URL', '').strip().rstrip('/')
    password = os.environ.get('VLAB_WARPGATE_ADMIN_PASSWORD', '')
    if not base_url.startswith(('http://', 'https://')) or not password or not _is_unconfigured():
        return False
    verify = _env_on('VLAB_WARPGATE_VERIFY_TLS')
    token = _mint_api_token(base_url, os.environ.get('VLAB_WARPGATE_ADMIN_USER', '').strip() or 'admin',
                            password, verify)
    with _auto_lock:
        if not _is_unconfigured():   # someone saved a configuration meanwhile - theirs wins
            return False
        save_config(base_url, _env_port('VLAB_WARPGATE_SSH_PORT', DEFAULT_PORTS['ssh']),
                    _env_port('VLAB_WARPGATE_RDP_PORT', DEFAULT_PORTS['rdp']),
                    _env_port('VLAB_WARPGATE_VNC_PORT', DEFAULT_PORTS['vnc']),
                    verify, True, admin_token=token, web_rdp_provider='guac')
    ok, detail = test_connection(config(secret=True))
    mark_check(ok, detail)
    logging.info(f'[VLAB] Warpgate connected at first start: {base_url} ({"ok" if ok else "check failed"})')
    return True


def start_auto_connect(attempts=30, wait=10):
    """auto_connect() off the start-up path, retried while Warpgate is still starting."""
    if not _env_on('VLAB_WARPGATE'):
        return None

    def run():
        import time
        for _ in range(attempts):
            try:
                auto_connect()
                if is_enabled():
                    migrate_legacy_users(config(secret=True))
                return
            except Exception as e:
                # the message carries no token or password (status codes only)
                logging.info(f'[VLAB] Warpgate not connected yet: {str(e)[:120]}')
            time.sleep(wait)
        logging.warning('[VLAB] Warpgate auto-connect gave up; set it in the console (플랫폼 설정 > 보안 게이트웨이)')

    t = threading.Thread(target=run, name='vlab-wg-autoconnect', daemon=True)
    t.start()
    return t
