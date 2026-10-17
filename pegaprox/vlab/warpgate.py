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
)

TABLES = ('vlab_warpgate', 'vlab_warpgate_targets')

_lock = threading.Lock()


def db():
    d = _store_db()
    if not getattr(d, '_vlab_warpgate', False):
        with _lock:
            if not getattr(d, '_vlab_warpgate', False):
                for stmt in _SCHEMA:
                    d.execute(stmt)
                d._vlab_warpgate = True
    return d


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
                'has_token': False, 'last_check': None, 'last_ok': None, 'last_detail': ''}
    out = {'base_url': r['base_url'], 'ssh_port': r['ssh_port'], 'rdp_port': r['rdp_port'],
           'vnc_port': r['vnc_port'], 'verify_tls': bool(r['verify_tls']), 'enabled': bool(r['enabled']),
           'rdp_nla_user': r['rdp_nla_user'], 'has_nla_password': bool(r['rdp_nla_password_encrypted']),
           'web_rdp_provider': r['web_rdp_provider'] or 'guac',
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
                admin_token=None, rdp_nla_user=None, rdp_nla_password=None, web_rdp_provider=None):
    """설정 저장. admin_token / rdp_nla_password: None이면 기존값 유지, ''이면 지움, 값이면 봉인해 저장.
    web_rdp_provider: 'guac'(기본, 항상 작동) 또는 'warpgate'(실클러스터 검증 후 전환)."""
    base_url = (base_url or '').strip().rstrip('/')
    r = _row()
    sealed = r['admin_token_encrypted'] if r else ''
    nla_sealed = r['rdp_nla_password_encrypted'] if r else ''
    nla_user = r['rdp_nla_user'] if r else ''
    provider = (r['web_rdp_provider'] if r else 'guac') or 'guac'
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
            rdp_nla_user, rdp_nla_password_encrypted, web_rdp_provider, enabled,
            last_check, last_ok, last_detail, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (CONFIG_ID, base_url, sealed, int(ssh_port), int(rdp_port), int(vnc_port),
         1 if verify_tls else 0, nla_user, nla_sealed, provider, 1 if enabled else 0,
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
    return f'moavi-{safe}-{ref}'[:63]


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


def web_ui_url(cfg):
    """Warpgate 웹 UI(로그인 뒤 대상 목록에서 브라우저 RDP/SSH를 연다).

    실제 Warpgate(v0.29.2)로 확인: `?warpgate-ticket=` 은 HTTP 대상에만 웹 세션을 열고, RDP/SSH
    대상의 티켓으로는 세션을 열지 않으며 티켓도 쓰지 않는다(Warpgate 자체 테스트
    test_non_http_ticket_opens_no_session). 그래서 브라우저 경로는 티켓 없이 Warpgate 웹 UI로
    보내고 사용자는 SSO/LDAP으로 로그인한다(비밀번호를 우리가 저장하지 않음). 티켓은 native 전용."""
    return cfg['base_url'].rstrip('/') + '/@warpgate#/'


def connection_coordinates(cfg, proto, target_name, secret):
    """티켓 secret으로 접속할 native 좌표 + 브라우저용 Warpgate 웹 UI 주소(티켓 없음).
    엔진은 secret을 저장하지 않고 이 응답에만 싣는다."""
    host = _host_of(cfg['base_url'])
    login = ticket_login(secret)
    browser = web_ui_url(cfg)
    if proto == 'ssh':
        return {'proto': 'ssh', 'host': host, 'port': int(cfg['ssh_port']),
                'username': login, 'ssh': f"ssh {login}@{host} -p {int(cfg['ssh_port'])}", 'browser_url': browser}
    if proto == 'vnc':
        return {'proto': 'vnc', 'host': host, 'port': int(cfg['vnc_port']), 'username': login, 'browser_url': browser}
    return {'proto': 'rdp', 'host': host, 'port': int(cfg['rdp_port']), 'username': login,
            'full_address': f"{host}:{int(cfg['rdp_port'])}", 'browser_url': browser}


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
        raise WarpgateError('Warpgate가 설정되지 않았습니다')
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


def ensure_user(cfg, username, role_id=None):
    """포털 사용자명과 같은 Warpgate 사용자를 보장한다(비밀번호 자격 없이; 인증은 SSO/LDAP/티켓).
    role_id가 있으면 그 역할을 붙인다. UUID 반환."""
    uid = None
    for u in _call(cfg, 'GET', '/users') or []:
        if isinstance(u, dict) and u.get('username') == username:
            uid = u['id']
            break
    if uid is None:
        created = _call(cfg, 'POST', '/users', {'username': username})
        uid = created['id']
    if role_id:
        try:
            # the API wants a JSON body here (AddUserRoleRequest, optional expires_at) - without one
            # it refuses the request (found against a live Warpgate)
            _call(cfg, 'POST', f'/users/{uid}/roles/{role_id}', {})
        except WarpgateError as e:
            if e.status != 409:   # 409 = already has the role; anything else is a real failure
                raise
    return uid


def sync_target(cfg, ref, label, proto, options, role_id=None):
    """데스크톱 1개에 대응하는 Warpgate 대상을 보장(없으면 생성)하고 매핑을 저장한다.
    options는 *_target_options()가 만든 dict. role_id가 있으면 대상에 역할을 연결."""
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
            uuid_val = found[0]['id']
            _call(cfg, 'PUT', f'/targets/{uuid_val}', body)
        if role_id:
            try:
                _call(cfg, 'POST', f'/targets/{uuid_val}/roles/{role_id}')
            except WarpgateError as e:
                if e.status != 409:   # 409 = the role is already on the target
                    raise
    save_mapping(ref, 'desktop', uuid_val, name, proto, options.get('host', ''), options.get('port', 0))
    return uuid_val, name


def remove_target(cfg, ref):
    """데스크톱이 없어질 때 그 Warpgate 대상과 매핑을 지운다. 이미 없으면(404) 매핑만 지운다.
    반환: 지운 대상 UUID 또는 None."""
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


def issue_ticket(cfg, username, target_name, ttl_seconds=TICKET_TTL_SECONDS):
    """그 사용자 + 그 대상에만 쓸 수 있는 1회용·단시간 티켓을 발급한다.
    반환: (ticket_dict, secret). secret은 저장하지 말고 응답에만 싣는다."""
    from datetime import datetime, timedelta, timezone
    expiry = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
    body = {'username': username, 'target_name': target_name, 'number_of_uses': 1,
            'expiry': expiry, 'description': f'MOAVI Desk connect: {username} -> {target_name}'}
    data = _call(cfg, 'POST', '/tickets', body)
    return data.get('ticket'), data.get('secret')


# --- researcher native SSH (own tools through Warpgate) ----------------------------------

_PUBKEY_RE = re.compile(r'^(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-\S+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-\S+)\s+[A-Za-z0-9+/=]+(\s+\S.*)?$')


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
    formatted credentials). 그래서 ProxyJump가 아니라 `User <wguser>:<target>` 형식을 쓴다."""
    return f'{username}:{target_name}'


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
