"""MOAVI Desk: LAB 단말 등록 - enrolment codes, the MOAVI Desk Agent's enrolment and heartbeat,
the one-file installer, approval (pegaprox/vlab/enroll.py).

  GET    /api/vlab/admin/enroll-codes              codes (never the code itself: its last 4 characters)  vlab.pool.view
  POST   /api/vlab/admin/enroll-codes              {name, lab_id?, auto_approve?, max_uses?, days?} -> the code, shown once  vlab.pool.manage
  PUT    /api/vlab/admin/enroll-codes/<code_id>    {name?, enabled?, lab_id?, auto_approve?}  vlab.pool.manage
  DELETE /api/vlab/admin/enroll-codes/<code_id>    remove it (PCs it brought in stay)       vlab.pool.manage
  POST   /api/vlab/admin/installer                 {code, kiosk?} install.cmd for a room's PCs with that code  vlab.pool.manage
  POST   /api/vlab/admin/terminals/approve         {ids, lab_id?} approve several, put them in a LAB  vlab.pool.manage
  POST   /api/vlab/admin/terminals/reject          {ids} refuse them; their agent token stops  vlab.pool.manage
  POST   /api/vlab/admin/terminals/<id>/resend-key the agent gets a new kiosk key with its next heartbeat  vlab.pool.manage
  GET    /api/vlab/admin/terminal-install          portal install link, auto-approval, limits, the MSI  admin.settings
  PUT    /api/vlab/admin/terminal-install          change them                               admin.settings
  POST   /api/vlab/admin/terminal-install/msi/upload  multipart file: the client MSI the installers fetch  admin.settings
  DELETE /api/vlab/admin/terminal-install/msi      remove it                                 admin.settings
  GET    /api/vlab/lab-install                     may the caller install a room's PC from the portal, and the LABs  signed in
  POST   /api/vlab/lab-install                     {lab_id?, uses?} install.cmd with a token for the caller  signed in (role)
  GET    /api/vlab/client/installer                install.cmd for a personal PC (the server filled in, no enrolment)  signed in
  GET    /api/vlab/client/msi                      the client MSI (public: the installers fetch it, sha256 checked)
  POST   /api/vlab/terminals/enroll                {mac, name?, code, info?} the agent's first start -> {token, state}  public (code)
  POST   /api/vlab/terminals/heartbeat             {info} with X-Agent-Token -> state, LAB, the kiosk key once  public (token)

The public enrol and heartbeat routes take no session: the code, then the agent token, is the
credential. Wrong ones are counted per address and stop for a while after a few; every token
issued, enrolment, refusal, approval, rejection and key hand-over is in the audit log. Both are
POSTs, so a standby forwards them to the active like any write.
"""
import hashlib
import logging
import os
import re
from datetime import datetime

from flask import Blueprint, Response, jsonify, request, send_file

from pegaprox.api import vlab as core
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.utils.ratelimit import SlidingWindow
from pegaprox.vlab import enroll, labs, store

bp = Blueprint('vlab_enroll', __name__)

AGENT_HEADER = 'X-Agent-Token'
# a wrong code: a few per address, then a pause (a mistyped code is fixed in one go)
_code_failures = SlidingWindow(limit=10, window=300, max_keys=4096, name='vlab-enroll-code')
# every enrolment from one address: a room behind one NAT enrols at once, a script does more
_enrolments = SlidingWindow(limit=300, window=300, max_keys=4096, name='vlab-enroll')
# a wrong agent token
_token_failures = SlidingWindow(limit=20, window=300, max_keys=4096, name='vlab-enroll-token')
# heartbeats of one agent: one every HEARTBEAT_SECONDS, room for restarts
_heartbeats = SlidingWindow(limit=30, window=300, max_keys=8192, name='vlab-agent-heartbeat')
# install files from the portal, per user
_installers = SlidingWindow(limit=20, window=3600, max_keys=4096, name='vlab-lab-install')

_REASONS = {
    'BAD_CODE': 'This enrolment code is not valid',
    'CODE_DISABLED': 'This enrolment code was switched off',
    'CODE_EXPIRED': 'This enrolment code has expired',
    'CODE_USED_UP': 'This enrolment code has been used by as many PCs as it allows',
    'BAD_TOKEN': 'This agent token is not known',
    'TOKEN_EXPIRED': 'This PC waited too long for approval - enrol again',
    'REJECTED': 'An administrator refused this PC',
}


def _refuse(code, status):
    return jsonify({'error': _REASONS.get(code, code), 'code': code}), status


def _too_many():
    return jsonify({'error': 'Too many tries - wait a few minutes', 'code': 'TOO_MANY', 'retry_after': 300}), 429


def _lab_brief(lab_id):
    lab = store.get_lab(lab_id) if lab_id else None
    return {'id': lab['id'], 'name': lab['name']} if lab else None


# --- settings: the portal's install link, auto-approval, limits, the MSI --------------------

_SETTINGS_KEY = 'vlab_terminal_install'
_DEFAULTS = {
    'lab_install_enabled': False,     # the portal's "실습실 PC로 설치" link
    'lab_install_roles': ['admin'],   # roles that see it
    'auto_approve_roles': [],         # files these roles made are approved at once
    'token_hours': 24,                # how long a portal token lasts
    'max_uses': 40,                   # most PCs one portal file may enrol
    'user_active_tokens': 5,          # tokens one user may hold at once
    'pending_warn': 100,              # the console warns past this many waiting PCs
    'kiosk': True,                    # room PCs install in kiosk mode
    'server_url': '',                 # what the PCs reach ('' = this request's address)
    'server_cert_sha256': '',         # pin a private certificate (SHA-256 of the DER, hex)
}
_LIMITS = {'token_hours': (1, 24 * 30), 'max_uses': (1, 1000), 'user_active_tokens': (1, 100), 'pending_warn': (1, 100000)}
_SHA_RE = re.compile(r'^[0-9A-Fa-f]{64}$')


def settings():
    from pegaprox.api.helpers import load_server_settings
    saved = (load_server_settings() or {}).get(_SETTINGS_KEY) or {}
    if not isinstance(saved, dict):
        saved = {}
    out = {k: saved.get(k, v) for k, v in _DEFAULTS.items()}
    out['msi'] = saved.get('msi') if isinstance(saved.get('msi'), dict) else None
    return out


def _save(s):
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    all_settings = load_server_settings() or {}
    all_settings[_SETTINGS_KEY] = s
    return save_server_settings(all_settings)


def _msi_path():
    from pegaprox.constants import CONFIG_DIR
    return os.path.join(CONFIG_DIR, 'vlab_client', 'moavi-desk.msi')


def _msi_ready(s):
    return bool(s.get('msi') and os.path.isfile(_msi_path()))


@bp.route('/api/vlab/admin/terminal-install', methods=['GET'])
@require_auth(perms=['admin.settings'])
def install_settings_get():
    s = settings()
    s['msi_ready'] = _msi_ready(s)
    s['pending'] = enroll.pending_count()
    return jsonify({'settings': s})


@bp.route('/api/vlab/admin/terminal-install', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def install_settings_put():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return core._bad('JSON body required')
    unknown = sorted(set(data) - set(_DEFAULTS))
    if unknown:
        return core._bad(f"unknown fields: {', '.join(unknown)}")
    s = settings()
    for k, v in data.items():
        d = _DEFAULTS[k]
        if isinstance(d, bool):
            if not isinstance(v, bool):
                return core._bad(f'{k} must be true or false')
        elif isinstance(d, int):
            lo, hi = _LIMITS[k]
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                return core._bad(f'{k} must be {lo}-{hi}')
        elif isinstance(d, list):
            if not isinstance(v, list) or len(v) > 50 or not all(isinstance(x, str) and 0 < len(x) <= 64 for x in v):
                return core._bad(f'{k} must be a list of role ids')
        else:
            if not isinstance(v, str):
                return core._bad(f'{k} must be a string')
            v = v.strip()
        s[k] = v
    if s['server_url'] and not re.match(r'^https?://[^\s/]+/?$', s['server_url']):
        return core._bad('server_url: https://host[:port]')
    s['server_cert_sha256'] = s['server_cert_sha256'].replace(':', '').upper()
    if s['server_cert_sha256'] and not _SHA_RE.match(s['server_cert_sha256']):
        return core._bad('server_cert_sha256: 64 hex digits')
    if not _save(s):
        return core._bad('Could not save the settings', 500)
    log_audit(core._user(), 'vlab.terminal_install.settings',
              f"portal link {'on' if s['lab_install_enabled'] else 'off'} for {s['lab_install_roles']}, "
              f"auto-approve {s['auto_approve_roles'] or 'none'}, {s['token_hours']} h, up to {s['max_uses']} PCs",
              get_client_ip())
    s['msi_ready'] = _msi_ready(s)
    return jsonify({'settings': s})


@bp.route('/api/vlab/admin/terminal-install/msi/upload', methods=['POST'])
@require_auth(perms=['admin.settings'])
def install_msi_upload():
    """multipart file: MOAVI-Desk-<version>-x64.msi. Kept in the config folder of this instance
    (an HA peer needs its own upload) and served at /api/vlab/client/msi with its SHA-256."""
    f = request.files.get('file')
    if not f or not (f.filename or '').lower().endswith('.msi'):
        return core._bad('file: the MOAVI Desk client .msi')
    path = _msi_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.part'
    h, size = hashlib.sha256(), 0
    with open(tmp, 'wb') as out:
        head = b''
        while True:
            chunk = f.stream.read(1 << 20)
            if not chunk:
                break
            if not head:
                head = chunk[:8]
            h.update(chunk)
            size += len(chunk)
            out.write(chunk)
    if head != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':   # an MSI is an OLE compound file
        os.remove(tmp)
        return core._bad('This is not an MSI file')
    os.replace(tmp, path)
    m = re.search(r'(\d+\.\d+\.\d+)', f.filename or '')
    s = settings()
    s['msi'] = {'name': os.path.basename(f.filename), 'version': m.group(1) if m else '', 'sha256': h.hexdigest().upper(),
                'size': size, 'uploaded_at': store.now(), 'uploaded_by': core._user()}
    _save(s)
    log_audit(core._user(), 'vlab.terminal_install.msi', f"client MSI {s['msi']['name']} ({size} bytes, sha256 {s['msi']['sha256'][:16]}…)",
              get_client_ip())
    return jsonify({'msi': s['msi']})


@bp.route('/api/vlab/admin/terminal-install/msi', methods=['DELETE'])
@require_auth(perms=['admin.settings'])
def install_msi_delete():
    s = settings()
    try:
        os.remove(_msi_path())
    except FileNotFoundError:
        pass
    s['msi'] = None
    _save(s)
    log_audit(core._user(), 'vlab.terminal_install.msi', 'client MSI removed', get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/client/msi', methods=['GET'])
def client_msi():
    """The client MSI the install files fetch (they check its SHA-256). Public, like a release download."""
    s = settings()
    if not _msi_ready(s):
        return core._bad('No client MSI on this server', 404)
    return send_file(_msi_path(), mimetype='application/x-msi', as_attachment=True,
                     download_name=s['msi']['name'] or 'MOAVI-Desk-x64.msi')


# --- the one-file installer (install.cmd) --------------------------------------------------

def _server(s):
    """(url, host, port, https) of this engine as the PCs reach it."""
    url = s['server_url']
    if not url:
        proto = (request.headers.get('X-Forwarded-Proto') or request.scheme or 'https').split(',')[0].strip()
        host = (request.headers.get('X-Forwarded-Host') or request.host or '').split(',')[0].strip()
        url = f'{proto}://{host}'
    from urllib.parse import urlsplit
    u = urlsplit(url.rstrip('/'))
    https = u.scheme == 'https'
    return url.rstrip('/'), u.hostname or '', u.port or (443 if https else 80), https


_SAFE = re.compile(r'^[A-Za-z0-9.\-:\[\]]+$')


def installer_cmd(s, code=None, kiosk=False, note=''):
    """A Windows batch file that asks for elevation once, fetches the MSI from this server over
    HTTPS, checks its SHA-256 and installs it silently with the server (and enrolment) filled in."""
    url, host, port, https = _server(s)
    if not _SAFE.match(host or '-'):
        raise ValueError('server address')
    msi = s['msi']
    pin = s['server_cert_sha256']
    props = [f'SERVER={host}', f'PORT={port}', f'HTTPS={1 if https else 0}']
    if kiosk:
        props.append('KIOSK=1')
    if code:
        props.append(f'ENROLL_TOKEN={code}')
    if pin:
        props.append(f'SERVER_CERT_SHA256={pin}')
    # the certificate check of the download: the usual chain, or the pinned fingerprint
    check = ("[Net.ServicePointManager]::ServerCertificateValidationCallback={param($s,$c,$ch,$e) "
             f"$e -eq 'None' -or ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($c.GetRawCertData())).Replace('-','') -eq '{pin}')}};"
             if pin else '')
    ps = ("$ErrorActionPreference='Stop';[Net.ServicePointManager]::SecurityProtocol='Tls12';" + check +
          f"(New-Object Net.WebClient).DownloadFile('{url}/api/vlab/client/msi',$env:MOAVI_MSI);"
          f"if((Get-FileHash $env:MOAVI_MSI -Algorithm SHA256).Hash -ne '{msi['sha256']}'){{Remove-Item $env:MOAVI_MSI;exit 2}}")
    lines = [
        '@echo off',
        'chcp 65001 >nul',
        f'rem MOAVI Desk {"실습실 PC 설치 (단말 등록)" if code else "클라이언트 설치"} - {note}',
        f'rem {datetime.now().strftime("%Y-%m-%d %H:%M")} {url}',
        'net session >nul 2>&1',
        'if errorlevel 1 (',
        '  powershell -NoProfile -Command "Start-Process -FilePath \'%~f0\' -Verb RunAs"',
        '  exit /b',
        ')',
        'set "MOAVI_MSI=%TEMP%\\moavi-desk-%RANDOM%.msi"',
        'echo MOAVI Desk 설치 파일을 받는 중...',
        f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{ps}"',
        'if errorlevel 1 (',
        '  echo 설치 파일을 받지 못했거나 파일이 맞지 않습니다. 서버 주소와 네트워크를 확인하세요.',
        '  pause',
        '  exit /b 1',
        ')',
        'echo 설치하는 중...',
        f'msiexec /i "%MOAVI_MSI%" /qn /norestart /l*v "%TEMP%\\moavi-desk-install.log" {" ".join(props)}',
        'set "RC=%ERRORLEVEL%"',
        'del "%MOAVI_MSI%" >nul 2>&1',
        'if not "%RC%"=="0" if not "%RC%"=="3010" (',
        '  echo 설치하지 못했습니다 ^(코드 %RC%^). 기록: %TEMP%\\moavi-desk-install.log',
        '  pause',
        '  exit /b %RC%',
        ')',
        ('echo 설치했습니다. 이 PC는 관리 콘솔 [LAB ^> 단말 관리]에서 관리자 승인을 기다립니다.' if code
         else 'echo 설치했습니다. 바탕 화면의 MOAVI Desk로 로그인하세요.'),
        'pause',
    ]
    return '\r\n'.join(lines) + '\r\n'


def _cmd_response(text, name):
    return Response(text.encode('utf-8'), mimetype='application/octet-stream',
                    headers={'Content-Disposition': f'attachment; filename="{name}"', 'Cache-Control': 'no-store'})


def _role():
    return str(request.session.get('role') or '')


@bp.route('/api/vlab/lab-install', methods=['GET'])
@require_auth()
def lab_install_info():
    """For the portal: may the caller install a room's PC from here, and into which LABs."""
    s = settings()
    allowed = s['lab_install_enabled'] and _role() in s['lab_install_roles']
    return jsonify({
        'enabled': s['lab_install_enabled'], 'allowed': allowed, 'msi_ready': _msi_ready(s),
        'labs': [{'id': l['id'], 'name': l['name'], 'location': l['location']} for l in store.list_labs()] if allowed else [],
        'max_uses': s['max_uses'], 'hours': s['token_hours'], 'auto_approve': _role() in s['auto_approve_roles'],
        'personal_installer': _msi_ready(s)})


@bp.route('/api/vlab/lab-install', methods=['POST'])
@require_auth()
def lab_install_file():
    """{lab_id?, uses?}: install.cmd with an enrolment token for the caller (token_hours, `uses`
    PCs, the LAB picked). The PCs wait for an admin unless the caller's role is auto-approved."""
    s = settings()
    user, role = core._user(), _role()
    if not s['lab_install_enabled'] or role not in s['lab_install_roles']:
        return core._bad('Installing room PCs from the portal is not open to you', 403)
    if not _msi_ready(s):
        return core._bad('The administrator has not put the client MSI on this server yet', 409)
    if not _installers.allow(user):
        return _too_many()
    data = request.get_json(silent=True) or {}
    lab_id = data.get('lab_id') or None
    if lab_id and not store.get_lab(lab_id):
        return core._bad('LAB not found', 404)
    try:
        uses = int(data.get('uses') or 1)
    except (TypeError, ValueError):
        return core._bad('uses must be a number')
    if not 1 <= uses <= s['max_uses']:
        return core._bad(f"uses must be 1-{s['max_uses']}")
    if len(enroll.active_user_codes(user)) >= s['user_active_tokens']:
        return core._bad(f"You hold {s['user_active_tokens']} unused install files already - use them or wait until they run out", 409)
    auto = role in s['auto_approve_roles']
    row, code = enroll.make_code(f'{user} 포털 설치', lab_id, auto, uses, 0, user, kind='user', hours=s['token_hours'])
    lab = _lab_brief(lab_id)
    try:
        text = installer_cmd(s, code, kiosk=s['kiosk'], note=f"{user}, {lab['name'] if lab else 'LAB 미지정'}, {uses}대")
    except ValueError:
        enroll.delete_code(row['id'])
        return core._bad('Set the server address under 플랫폼 설정 > 클라이언트', 409)
    log_audit(user, 'vlab.enroll_token.issue',
              f"install file for {uses} PC(s), LAB {lab['name'] if lab else '-'}, {s['token_hours']} h, "
              f"{'approved at once' if auto else 'admin approves'} (…{row['hint']})", get_client_ip())
    return _cmd_response(text, 'moavi-desk-lab-install.cmd')


@bp.route('/api/vlab/client/installer', methods=['GET'])
@require_auth()
def personal_installer():
    """install.cmd for a personal PC: the server filled in, no enrolment, no kiosk."""
    s = settings()
    if not _msi_ready(s):
        return core._bad('No client MSI on this server', 404)
    try:
        text = installer_cmd(s, None, kiosk=False, note=core._user())
    except ValueError:
        return core._bad('Set the server address under 플랫폼 설정 > 클라이언트', 409)
    return _cmd_response(text, 'moavi-desk-install.cmd')


@bp.route('/api/vlab/admin/installer', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def admin_installer():
    """{code, kiosk?}: install.cmd for a room's PCs with an enrolment code the admin holds."""
    s = settings()
    if not _msi_ready(s):
        return core._bad('Put the client MSI on the server first (플랫폼 설정 > 클라이언트)', 409)
    data = request.get_json(silent=True) or {}
    c, why = enroll.code_for(data.get('code'))
    if not c:
        return _refuse(why, 400)
    try:
        text = installer_cmd(s, data['code'].strip().upper(), kiosk=bool(data.get('kiosk', s['kiosk'])), note=c['name'])
    except ValueError:
        return core._bad('Set the server address under 플랫폼 설정 > 클라이언트', 409)
    log_audit(core._user(), 'vlab.installer.download', f"install file with code '{c['name']}' (…{c['hint']})", get_client_ip())
    return _cmd_response(text, 'moavi-desk-lab-install.cmd')


# --- the agent ------------------------------------------------------------------------------

@bp.route('/api/vlab/terminals/enroll', methods=['POST'])
def enroll_terminal():
    """The MOAVI Desk Agent's first start with the code its installer was given:
    {mac, name?, code, info?}. A new PC becomes a terminal (pending, or approved in the code's
    LAB when the code says so); a known one waits for an admin again if it held a key, unless
    the code approves at once. A refused PC stays refused. Answers {token, state, lab,
    heartbeat_seconds}; the token is the agent's for its heartbeats."""
    ip = get_client_ip() or ''
    if _code_failures.full(ip) or not _enrolments.allow(ip):
        return _too_many()
    data = request.get_json(silent=True) or {}
    mac = labs.norm_mac(data.get('mac'))
    if not mac:
        return core._bad('A MAC address is required')
    name = str(data.get('name') or '').strip()[:80]
    code, why = enroll.code_for(data.get('code'))
    if not code:
        _code_failures.allow(ip)
        log_audit(f'terminal:{mac}', 'vlab.terminal.enroll_refused', f"terminal {mac} '{name}': {why}", ip)
        return _refuse(why, 403)

    lab_id = code['lab_id'] if code['lab_id'] and store.get_lab(code['lab_id']) else None
    t = store.terminal_by_mac(mac)
    if t and t['state'] == 'rejected':
        log_audit(f'terminal:{mac}', 'vlab.terminal.enroll_refused', f"terminal {mac} '{name}': rejected before", ip)
        return _refuse('REJECTED', 403)
    if t:
        fields = {'ip': ip, 'last_seen': store.now()}
        if not t['name'] and name:
            fields['name'] = name
        if lab_id and not t.get('lab_id'):
            fields['lab_id'] = lab_id
        if code['auto_approve']:
            fields['state'] = 'approved'
        elif t['has_key']:
            # it held a key: a PC that comes back with a code gets a new one only once an admin
            # looks at it again (someone else could have sent this MAC address)
            fields['state'] = 'pending'
        t = store.update_terminal(t['id'], **fields)
        what = f"known terminal {mac} '{t['name']}' enrolled again ({t['state']})"
    else:
        t = store.add_terminal(mac, name, lab_id, ip, 'approved' if code['auto_approve'] else 'pending', code['created_by'])
        what = f"terminal {mac} '{t['name']}' enrolled ({t['state']})"
    enroll.count_use(code['id'])
    token = enroll.start(t['id'], code['id'], data.get('info'))
    log_audit(f'terminal:{mac}', 'vlab.terminal.enroll',
              f"{what} with {'the install file of ' + code['created_by'] if code['kind'] == 'user' else 'code'} "
              f"'{code['name']}' (…{code['hint']})" + (f", LAB {t['lab_id']}" if t.get('lab_id') else ''), ip)
    pending = enroll.pending_count()
    if pending >= settings()['pending_warn']:
        logging.warning('[vlab] %d terminals wait for approval (warning at %d)', pending, settings()['pending_warn'])
    return jsonify({'token': token, 'state': t['state'], 'lab': _lab_brief(t.get('lab_id')),
                    'terminal': {'id': t['id'], 'name': t['name']}, 'heartbeat_seconds': enroll.HEARTBEAT_SECONDS}), 201


@bp.route('/api/vlab/terminals/heartbeat', methods=['POST'])
def agent_heartbeat():
    """The agent's heartbeat (header X-Agent-Token, body {info}): records what it said and
    answers the terminal's state and LAB; once the terminal is approved and its key has not gone
    out, the kiosk key, made now and handed out this once."""
    ip = get_client_ip() or ''
    if _token_failures.full(ip):
        return _too_many()
    token = request.headers.get(AGENT_HEADER, '').strip()
    e, why = enroll.by_token(token)
    if not e:
        _token_failures.allow(ip)
        return _refuse(why, 404)
    if not _heartbeats.allow(e['terminal_id']):
        return _too_many()
    t = store.get_terminal(e['terminal_id'])
    if not t:
        enroll.forget(e['terminal_id'])
        return _refuse('BAD_TOKEN', 404)
    if t['state'] == 'rejected':
        enroll.end_token(t['id'], 'rejected')
        return _refuse('REJECTED', 410)
    if enroll.waited_too_long(e) and t['state'] != 'approved':
        enroll.end_token(t['id'], 'expired')
        return _refuse('TOKEN_EXPIRED', 410)
    data = request.get_json(silent=True) or {}
    enroll.heartbeat(t['id'], data.get('info'), ip)
    store.update_terminal(t['id'], ip=ip or t.get('ip') or '', last_seen=store.now())
    out = {'state': t['state'], 'lab': _lab_brief(t.get('lab_id')), 'terminal': {'id': t['id'], 'name': t['name']},
           'heartbeat_seconds': enroll.HEARTBEAT_SECONDS}
    if t['state'] == 'approved' and e['state'] == 'waiting':
        import secrets
        key = 'mdt_' + secrets.token_urlsafe(24)
        store.set_terminal_key(t['id'], core._key_hash(key))
        enroll.set_key_state(t['id'], 'delivered')
        log_audit(f"terminal:{t['mac']}", 'vlab.terminal.key_delivered',
                  f"terminal {t['mac']} '{t['name']}': kiosk key handed to its agent", ip)
        out['key'] = key
    return jsonify(out)


# --- the admin -----------------------------------------------------------------------------

@bp.route('/api/vlab/admin/enroll-codes', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_enroll_codes():
    labs_by_id = {l['id']: l['name'] for l in store.list_labs()}
    codes = enroll.list_codes(request.args.get('kind') or None)
    for c in codes:
        c['lab_name'] = labs_by_id.get(c['lab_id']) if c['lab_id'] else None
    return jsonify({'codes': codes})


def _int(value, lo, hi, what):
    try:
        n = int(value or 0)
    except (TypeError, ValueError):
        raise ValueError(f'{what} must be a number')
    if n < lo or n > hi:
        raise ValueError(f'{what} must be {lo}-{hi}')
    return n


@bp.route('/api/vlab/admin/enroll-codes', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_enroll_code():
    """A new code. max_uses 0 = any number of PCs, days 0 = no end. The code is in the answer
    this once; afterwards only its last four characters are shown."""
    data = request.get_json(silent=True) or {}
    name = str(data.get('name') or '').strip()
    if not name or len(name) > 80:
        return core._bad('A name of 1-80 characters is required')
    try:
        max_uses = _int(data.get('max_uses'), 0, enroll.MAX_USES, 'max_uses')
        days = _int(data.get('days'), 0, enroll.MAX_DAYS, 'days')
    except ValueError as e:
        return core._bad(str(e))
    lab_id = data.get('lab_id') or None
    if lab_id and not store.get_lab(lab_id):
        return core._bad('LAB not found', 404)
    row, code = enroll.make_code(name, lab_id, bool(data.get('auto_approve')), max_uses, days, core._user())
    log_audit(core._user(), 'vlab.enroll_code.create',
              f"enrolment code '{name}' (…{row['hint']}): LAB {lab_id or '-'}, "
              f"{'approved at once' if row['auto_approve'] else 'admin approves'}, "
              f"{max_uses or 'any number of'} PCs, {f'{days} days' if days else 'no end'}", get_client_ip())
    return jsonify({'code': code, 'enroll_code': row}), 201


@bp.route('/api/vlab/admin/enroll-codes/<code_id>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def update_enroll_code(code_id):
    c = enroll.get_code(code_id)
    if not c:
        return core._bad('Enrolment code not found', 404)
    data = request.get_json(silent=True) or {}
    fields = {}
    if 'name' in data:
        name = str(data.get('name') or '').strip()
        if not name or len(name) > 80:
            return core._bad('A name of 1-80 characters is required')
        fields['name'] = name
    if 'enabled' in data:
        fields['enabled'] = 1 if data.get('enabled') else 0
    if 'auto_approve' in data:
        fields['auto_approve'] = 1 if data.get('auto_approve') else 0
    if 'lab_id' in data:
        lab_id = data.get('lab_id') or None
        if lab_id and not store.get_lab(lab_id):
            return core._bad('LAB not found', 404)
        fields['lab_id'] = lab_id
    c = enroll.update_code(code_id, **fields)
    log_audit(core._user(), 'vlab.enroll_code.update', f"enrolment code '{c['name']}' (…{c['hint']}) {fields}", get_client_ip())
    return jsonify({'enroll_code': c})


@bp.route('/api/vlab/admin/enroll-codes/<code_id>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_enroll_code(code_id):
    c = enroll.get_code(code_id)
    if not c:
        return core._bad('Enrolment code not found', 404)
    enroll.delete_code(code_id)
    log_audit(core._user(), 'vlab.enroll_code.delete', f"enrolment code '{c['name']}' (…{c['hint']})", get_client_ip())
    return jsonify({'success': True})


def _ids():
    data = request.get_json(silent=True) or {}
    ids = data.get('ids')
    if not isinstance(ids, list) or not ids or len(ids) > 1000 or not all(isinstance(i, str) for i in ids):
        return None, data, core._bad('ids: a list of 1-1000 terminal ids is required')
    return list(dict.fromkeys(ids)), data, None


@bp.route('/api/vlab/admin/terminals/approve', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def approve_terminals():
    """{ids: [...], lab_id?}: approve these terminals (and put them in the LAB, when one is
    given). Their agents pick their keys up with the next heartbeat."""
    ids, data, err = _ids()
    if err:
        return err
    lab_id = data.get('lab_id') or None
    if lab_id and not store.get_lab(lab_id):
        return core._bad('LAB not found', 404)
    done, missing = [], []
    for tid in ids:
        t = store.get_terminal(tid)
        if not t:
            missing.append(tid)
            continue
        fields = {'state': 'approved'}
        if lab_id:
            fields['lab_id'] = lab_id
        done.append(store.update_terminal(tid, **fields))
    if done:
        log_audit(core._user(), 'vlab.terminal.approve',
                  f"{len(done)} terminals approved{f' into LAB {lab_id}' if lab_id else ''}: "
                  + ', '.join(t['name'] or t['mac'] for t in done[:50]) + (' …' if len(done) > 50 else ''),
                  get_client_ip())
    return jsonify({'terminals': enroll.annotate(done), 'missing': missing})


@bp.route('/api/vlab/admin/terminals/reject', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def reject_terminals():
    """{ids: [...]}: refuse these PCs. Their agent tokens and kiosk keys stop; the same MAC
    cannot enrol again until an admin deletes the terminal."""
    ids, _, err = _ids()
    if err:
        return err
    done, missing = [], []
    for tid in ids:
        t = store.get_terminal(tid)
        if not t:
            missing.append(tid)
            continue
        store.set_terminal_key(tid, '')                  # its kiosk key stops (this also approves...)
        store.update_terminal(tid, state='rejected')     # ...so the refusal comes after
        enroll.end_token(tid, 'rejected')
        done.append(store.get_terminal(tid))
    if done:
        log_audit(core._user(), 'vlab.terminal.reject',
                  f"{len(done)} terminals rejected: " + ', '.join(f"{t['name'] or '-'} {t['mac']}" for t in done[:50]),
                  get_client_ip())
    return jsonify({'terminals': enroll.annotate(done), 'missing': missing})


@bp.route('/api/vlab/admin/terminals/<terminal_id>/resend-key', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def resend_terminal_key(terminal_id):
    """The terminal's agent gets a new kiosk key with its next heartbeat (the old one keeps
    working until then)."""
    t = store.get_terminal(terminal_id)
    if not t:
        return core._bad('Terminal not found', 404)
    rows = enroll.annotate([dict(t)])[0]['enrollment']
    if not rows or rows['state'] in ('expired', 'rejected'):
        return core._bad('This terminal has no agent to send a key to', 409)
    enroll.set_key_state(terminal_id, 'waiting')
    log_audit(core._user(), 'vlab.terminal.key', f"terminal {t['mac']} '{t['name']}': new kiosk key goes with the next heartbeat",
              get_client_ip())
    return jsonify({'terminal': enroll.annotate([store.get_terminal(terminal_id)])[0]})
