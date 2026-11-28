# -*- coding: utf-8 -*-
"""
MOAVI Desk desktop sign-in (데스크톱 자동 로그인) API: the portal user lands on their Windows desktop
over RDP with no second sign-in and no stored password (pegaprox/vlab/logon_ca.py, docs/desktop-sso.md).

  GET  /api/vlab/admin/logon-sso                       settings, CA facts (no key), recent certificates  vlab.pool.view
  PUT  /api/vlab/admin/logon-sso                       crl_url, gateway_ips, ttl_min, allow_admins       vlab.pool.manage
  POST /api/vlab/admin/logon-sso/ca                    {cert_pem, key_pem} or {from_dir: true}           vlab.pool.manage
  POST /api/vlab/admin/desktops/<id>/logon-sso/install the Windows module + CA trust, over the guest agent vlab.pool.manage
  GET  /api/vlab/admin/desktops/<id>/logon-sso/status  what the module in the VM says                     vlab.pool.view
  POST /api/vlab/me/desktops/<id>/logon-sso            arm the next RDP sign-in of the signed-in user     vlab.desk

The connect routes call arm_for_connect() themselves for pools with desktop_sso on, so the portal's
.rdp needs nothing more. Arming never blocks a connect: when it fails the desktop's own sign-in
screen comes up as before.
"""

import base64
import hashlib
import logging
import os
import threading
import time

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import logon_ca
from pegaprox.vlab import policy as pool_policy
from pegaprox.vlab import store

bp = Blueprint('vlab_logon', __name__)

_bad = core._bad
_user = core._user

EXE = r'C:\Program Files\MOAVI\Logon\moavi-logon.exe'
AGENT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'vlab', 'logon_agent')
AGENT_FILES = ('moavi-logon.exe', 'moavi-logon-cp.dll', 'moavi-logon-csp.dll', 'install.ps1')
SETUP_DIR = r'C:\Windows\Temp\moavi-logon-setup'
PIECE = 46080                  # bytes per guest agent file-write (Proxmox takes 61440 base64 characters)
PREPARE_WAIT = 20
ARM_WAIT = 20

SSO_OFF_TEXT = '이 풀은 데스크톱 자동 로그인이 꺼져 있습니다.'


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _kv(text):
    out = {}
    for line in (text or '').splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            out[k.strip()] = v.strip()
    return out


def _portal_session():
    return request.headers.get('X-Session-ID') or request.cookies.get('session_id') or ''


# --- arming one RDP sign-in ------------------------------------------------------------------

_arm_locks = {}                    # desktop id -> lock: one arm at a time per desktop
_arm_locks_guard = threading.Lock()
# arms at once over the whole engine: each is a few guest agent calls through the node's API. Sized
# for up to 200 desktops on a handful of nodes - a morning rush queues here a few seconds instead of
# piling onto Proxmox
ARMS_AT_ONCE = 8
_arms = threading.BoundedSemaphore(ARMS_AT_ONCE)


def _arm_lock(desktop_id):
    with _arm_locks_guard:
        return _arm_locks.setdefault(desktop_id, threading.Lock())


def arm(desk, mgr, node, username, portal_session='', client_ip=''):
    """prepare -> sign -> arm for this user's next RDP session on this Windows desktop.
    (True, '', info) or (False, code, detail). Never raises. One at a time per desktop: two at once
    (the client arming ahead and the connect right behind it) overwrote each other in the VM."""
    with _arm_lock(desk['id']):
        return _arm(desk, mgr, node, username, portal_session, client_ip)


def _arm(desk, mgr, node, username, portal_session='', client_ip=''):
    with _arms:
        return _arm_now(desk, mgr, node, username, portal_session, client_ip)


def _arm_now(desk, mgr, node, username, portal_session='', client_ip=''):
    from pegaprox.api.vlab_next import _agent_run, agent_exec_disabled
    ok, code = logon_ca.eligible(username, desk['id'])
    if not ok:
        return False, code, ''
    inst = logon_ca.install_of(desk['id']) or {}
    if inst.get('state') == 'unsupported':
        return False, inst.get('code') or 'UNSUPPORTED', inst.get('detail') or ''
    vmid = int(desk['vmid'])
    try:
        rc, out, err, e = _agent_run(mgr, node, vmid, [EXE, 'prepare'], wait=PREPARE_WAIT)
    except Exception as ex:
        rc, out, err, e = None, '', '', str(ex)[:200]
    got = _kv(out)
    if got.get('prev_thumb'):
        logon_ca.mark_reported(desk['id'], got['prev_thumb'], got.get('prev_state', ''), got.get('prev_result', ''))
    if rc != 0 or not got.get('csr') or not got.get('nonce'):
        if agent_exec_disabled(e):
            return False, 'AGENT_EXEC_DISABLED', e
        if 'cannot find' in (e or '').lower() or 'no such file' in (e or '').lower() or 'not found' in (e or '').lower():
            r = logon_ca.install_of(desk['id'])
            if r and r['state'] == 'installed':      # the module went missing: the next round puts it back
                logon_ca.record_install(desk['id'], desk['vmid'], r['version'], 'pending', 'NOT_INSTALLED', 'module missing')
            return False, 'NOT_INSTALLED', e
        return False, 'PREPARE_FAILED', e or f"exit {rc}: {(got.get('error') or err or '').strip()[:200]}"
    try:
        csr = base64.b64decode(got['csr'], validate=True)
        cert = logon_ca.issue(username, desk, csr, portal_session=portal_session, client_ip=client_ip)
    except logon_ca.LogonCAError as ex:
        _agent_run(mgr, node, vmid, [EXE, 'clear'], wait=8)
        return False, ex.code, str(ex)
    except Exception as ex:
        _agent_run(mgr, node, vmid, [EXE, 'clear'], wait=8)
        return False, 'CSR_BAD', str(ex)[:200]
    from pegaprox.vlab import directory
    cfg = logon_ca.config()
    lines = {
        'nonce': got['nonce'],
        'cert': base64.b64encode(cert['cert_der']).decode('ascii'),
        'not_after': str(int(cert['not_after'].timestamp())),
        'gateways': ','.join(cfg['gateway_ips']),
        'user': username,
        'domain': directory.config()['domain'],
        'upn': cert['upn'],
    }
    stdin = ''.join(f'{k}={v}\n' for k, v in lines.items())
    try:
        rc, out, err, e = _agent_run(mgr, node, vmid, [EXE, 'arm'], stdin=stdin, wait=ARM_WAIT)
    except Exception as ex:
        rc, out, err, e = None, '', '', str(ex)[:200]
    if rc != 0 or 'armed=ok' not in (out or ''):
        detail = e or f"exit {rc}: {(_kv(out).get('error') or err or '').strip()[:200]}"
        logon_ca.mark(cert['serial'], 'arm_failed', detail)
        return False, 'ARM_FAILED', detail
    logon_ca.mark(cert['serial'], 'armed')
    return True, '', {'serial': cert['serial'], 'not_after': logon_ca._iso(cert['not_after']), 'upn': cert['upn']}


from pegaprox.vlab.rdp_done import Done as _Done
_nla_off = _Done('nla_off')     # desktop id -> (vmid, gateway ips): RDP scoped to the gateways and NLA off (kept over a restart)

# The desktop's own "Remote Desktop" inbound rules (the group, by its resource name, so any Windows
# language) take RDP only from the gateways. Fails - and NLA stays on - when the Windows firewall is
# off in a profile (a scope would filter nothing) or no rule is found.
_RDP_SCOPE_PS = r"""$ErrorActionPreference = 'Stop'
$ips = @(%s)
$off = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
if ($off.Count) { "rdp_fw=error firewall_off=" + ($off -join ','); exit 3 }
$rules = @(Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Direction Inbound -ErrorAction SilentlyContinue)
if (-not $rules.Count) { 'rdp_fw=error no_rules'; exit 4 }
$rules | Set-NetFirewallRule -RemoteAddress $ips
$now = @($rules | Get-NetFirewallAddressFilter | ForEach-Object { $_.RemoteAddress } | Sort-Object -Unique)
"rdp_fw=scoped rules=$($rules.Count) remote=" + ($now -join ',')
"""


def rdp_scope(desk, mgr, node, ips):
    """The desktop's RDP firewall rules take only the gateways' addresses. True when scoped."""
    from pegaprox.api.vlab_next import _agent_run
    script = _RDP_SCOPE_PS % ','.join("'%s'" % ip for ip in ips)        # ips: validated addresses
    try:
        rc, out, _err, e = _agent_run(mgr, node, int(desk['vmid']), ['powershell.exe', '-NoProfile', '-NonInteractive',
                                      '-ExecutionPolicy', 'Bypass', '-Command', script], wait=30)
    except Exception as ex:
        rc, out, e = None, '', str(ex)[:200]
    if rc == 0 and 'rdp_fw=scoped' in (out or ''):
        return True
    why = (e or (out or '').strip())[:120]
    logging.info(f"[VLAB] desktop sign-in: RDP on {desk.get('name')} not scoped to the gateways: {why}")
    log_audit('system', 'vlab.logon.nla', f"'{desk['name']}' (qemu/{desk['vmid']}): RDP not limited to the gateways "
              f"({why}); NLA stays on", '')
    return False


def rdp_nla_off(desk, mgr, node):
    """The devices route (RD Gateway): mstsc talks to the desktop itself and with NLA it asks for a
    password before the desktop is reached. A desktop_sso desktop on that route takes RDP without NLA -
    only after its RDP firewall rules take nothing but the gateways (the logon screen then signs the
    user in). True when off; False leaves NLA on and the .rdp asks for the password as before."""
    from pegaprox.api.vlab_next import _agent_run
    ips = tuple(logon_ca.config()['gateway_ips'])
    if not ips:
        return False
    if _nla_off.get(desk['id']) == (desk['vmid'], ips):
        return True
    if not rdp_scope(desk, mgr, node, ips):
        return False
    try:
        rc, out, _err, e = _agent_run(mgr, node, int(desk['vmid']), [EXE, 'rdp-nla', 'off'], wait=15)
    except Exception as ex:
        rc, out, e = None, '', str(ex)[:200]
    if rc == 0 and 'rdp_nla=off' in (out or ''):
        _nla_off[desk['id']] = (desk['vmid'], ips)
        log_audit('system', 'vlab.logon.nla', f"'{desk['name']}' (qemu/{desk['vmid']}): RDP without NLA for desktop "
                  f"sign-in on the devices route, RDP only from {', '.join(ips)}", '')
        return True
    logging.info(f"[VLAB] desktop sign-in: NLA on {desk.get('name')} not turned off: {e or out}")
    return False


def sso_on(pool):
    return bool(pool_policy.effective((pool or {}).get('settings')).get('desktop_sso'))


REUSE_MARGIN = 90           # seconds an armed certificate must still have to be used again


def _still_armed(desk, mgr, node, username):
    """True when this desktop's newest certificate is this user's, armed, good for REUSE_MARGIN more
    and the VM still holds it (moavi-logon status: state=armed - the newest arm is the one it holds,
    a logon or an expiry clears it). One guest round trip instead of prepare, sign and arm."""
    import datetime as _dt
    from pegaprox.api.vlab_next import _agent_run
    rows = logon_ca.issued(1, desktop_id=desk['id'])
    if not rows:
        return False
    r = rows[0]
    if r['username'] != username or r['state'] != 'armed' or int(r['vmid'] or 0) != int(desk['vmid']):
        return False
    try:
        left = (_dt.datetime.fromisoformat(r['not_after']) - _dt.datetime.now(_dt.timezone.utc)).total_seconds()
    except (TypeError, ValueError):
        return False
    if left < REUSE_MARGIN:
        return False
    try:
        rc, out, _err, _e = _agent_run(mgr, node, int(desk['vmid']), [EXE, 'status'], wait=8)
    except Exception:
        return False
    return rc == 0 and _kv(out).get('state') == 'armed'


def arm_for_connect(desk, mgr, node, username, pool):
    """The connect routes (RDP file, browser RDP) on a Windows desktop: arm its next sign-in when the
    pool has desktop_sso on. Failures are logged, never shown - the sign-in screen is the fallback."""
    if not sso_on(pool):
        return None
    # an arm already on its way for this desktop (the client's, ahead) finishes first, then is used
    with _arm_lock(desk['id']):
        if _still_armed(desk, mgr, node, username):
            return True             # armed a moment ago (the client asks when the desktop is picked)
        try:
            ok, code, info = _arm(desk, mgr, node, username, _portal_session(), get_client_ip())
        except Exception as e:      # never in the way of the connect
            ok, code, info = False, 'ERROR', str(e)[:200]
    if not ok:
        logging.info(f"[VLAB] desktop sign-in on {desk.get('name')} for {username} not armed: {code} {str(info)[:200]}")
        if code not in ('NOT_DIRECTORY_ACCOUNT', 'NOT_JOINED', 'ADMIN_REFUSED', 'NO_DIRECTORY'):
            log_audit('system', 'vlab.logon.fail', f"desktop sign-in on '{desk.get('name')}' for {username}: {code} "
                      f"{str(info)[:150]}", '')
    return ok


# --- admin -----------------------------------------------------------------------------------

@bp.route('/api/vlab/admin/logon-sso', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_logon_sso():
    return jsonify({'config': logon_ca.config(), 'issued': logon_ca.issued(50)})


@bp.route('/api/vlab/admin/logon-sso', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def put_logon_sso():
    d = _body()
    try:
        cfg = logon_ca.save_config(crl_url=d.get('crl_url'), gateway_ips=d.get('gateway_ips'),
                                   ttl_min=d.get('ttl_min'), allow_admins=d.get('allow_admins'))
    except ValueError as e:
        return _bad(str(e))
    log_audit(_user(), 'vlab.logon.config', f"desktop sign-in: gateways {','.join(cfg['gateway_ips']) or '-'}, "
              f"ttl {cfg['ttl_min']} min, admins {cfg['allow_admins']}", get_client_ip())
    return jsonify({'config': cfg})


@bp.route('/api/vlab/admin/logon-sso/ca', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def import_logon_ca():
    d = _body()
    if d.get('from_dir') is True:
        if logon_ca.ca_info():
            return jsonify({'error': '이미 로그온 CA가 있습니다', 'code': 'CA_EXISTS'}), 409
        info, why = logon_ca.import_from_dir()
        if not info:
            return jsonify({'error': why, 'code': 'CA_NOT_FOUND'}), 404
    else:
        cert, key = d.get('cert_pem'), d.get('key_pem')
        if not isinstance(cert, str) or not isinstance(key, str):
            return _bad('cert_pem and key_pem (PEM text) required')
        try:
            info = logon_ca.import_ca(cert, key)
        except logon_ca.LogonCAError as e:
            return jsonify({'error': str(e), 'code': e.code}), 400
    log_audit(_user(), 'vlab.logon.ca', f"desktop sign-in CA {info['subject']} sha256 {info['sha256'][:16]} ({info['source']})",
              get_client_ip())
    return jsonify({'ca': info})


def _running_windows(desktop_id):
    """(desk, mgr, node, None) or (None, None, None, error response)."""
    from pegaprox.api.vlab_next import _guest_os
    desk = store.get_desktop(desktop_id)
    if not desk:
        return None, None, None, _bad('Desktop not found', 404)
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return None, None, None, _bad('Cluster not connected', 503)
    live = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
    if live.get('status') != 'running':
        return None, None, None, (jsonify({'error': 'The desktop is not running', 'code': 'VM_STOPPED'}), 409)
    node = live.get('node') or desk['node']
    if _guest_os(mgr, node, int(desk['vmid'])) != 'windows':
        return None, None, None, (jsonify({'error': '데스크톱 자동 로그인은 Windows 데스크톱만 됩니다.', 'code': 'NOT_WINDOWS'}), 409)
    return desk, mgr, node, None


def _write_file(mgr, node, vmid, path, data):
    """One file into the VM through the guest agent, in PIECE-sized parts (path.partNNN)."""
    from pegaprox.api.vlab_next import _agent
    n = 0
    for i in range(0, max(len(data), 1), PIECE):
        resp = mgr._api_post(_agent(mgr, node, vmid, 'file-write'),
                             data={'file': f'{path}.part{n:03d}', 'content': base64.b64encode(data[i:i + PIECE]).decode('ascii'),
                                   'encode': 0})
        if getattr(resp, 'status_code', 0) != 200:
            why = (getattr(resp, 'text', '') or '').strip()[:200] or (f"HTTP {resp.status_code}" if resp is not None else 'no answer from the node')
            raise RuntimeError(f"file-write {os.path.basename(path)} part {n}: {why}")
        n += 1
    return n


def install_payload():
    """The files the installer pushes: {name: bytes}, plus the CA certificate (DER)."""
    files = {}
    for name in AGENT_FILES:
        with open(os.path.join(AGENT_DIR, name), 'rb') as f:
            files[name] = f.read()
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    pem = logon_ca.ca_cert_pem()
    if not pem:
        raise logon_ca.LogonCAError('no logon CA in the engine', 'CA_MISSING')
    files['moavi-logon-ca.cer'] = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
    return files


def install(desk, mgr, node):
    """Push the module and run its installer as SYSTEM. (ok, output kv or error text)."""
    from pegaprox.api.vlab_next import _agent_run, agent_exec_disabled
    vmid = int(desk['vmid'])
    files = install_payload()
    # a folder of its own each time: a part the guest agent still holds open from an earlier try that
    # timed out (a busy guest right after an update restart) can be neither removed nor written again,
    # and failed every install after it. Earlier folders go when they can.
    setup = f"{SETUP_DIR}-{os.urandom(4).hex()}"
    mk = ("Get-ChildItem 'C:\\Windows\\Temp' -Directory -Filter 'moavi-logon-setup*' -ErrorAction SilentlyContinue | "
          "ForEach-Object { Remove-Item -Recurse -Force $_.FullName -ErrorAction SilentlyContinue }; "
          "$d='" + setup + "'; "
          "New-Item -ItemType Directory -Force $d | Out-Null; "
          "icacls $d /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null; 'dir=ok'")
    rc, out, err, e = _agent_run(mgr, node, vmid, ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy',
                                                   'Bypass', '-Command', mk], wait=20)
    if rc != 0 or 'dir=ok' not in (out or ''):
        if agent_exec_disabled(e):
            return False, 'AGENT_EXEC_DISABLED'
        return False, e or (err or out or f'exit {rc}')[:300]
    manifest = []
    for name, data in files.items():
        parts = _write_file(mgr, node, vmid, setup + '\\' + name, data)
        manifest.append(f"{name}|{parts}|{hashlib.sha256(data).hexdigest()}")
    run = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
           "$d='" + setup + "'; "
           "Get-ChildItem $d -Filter '*.part*' | Group-Object { $_.Name -replace '\\.part\\d{3}$','' } | ForEach-Object { "
           "$o=[IO.File]::Create((Join-Path $d $_.Name)); "
           "foreach ($p in ($_.Group | Sort-Object Name)) { $b=[IO.File]::ReadAllBytes($p.FullName); $o.Write($b,0,$b.Length); "
           "Remove-Item -Force $p.FullName }; $o.Close() }; "
           "& (Join-Path $d 'install.ps1') -Setup $d"]
    rc, out, err, e = _agent_run(mgr, node, vmid, run, stdin='\n'.join(manifest) + '\n', wait=90)
    got = _kv(out)
    try:      # the setup folder is not needed once the installer ran (best effort; the next install clears it too)
        _agent_run(mgr, node, vmid, ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                                     f"Remove-Item -Recurse -Force '{setup}' -ErrorAction SilentlyContinue"], wait=10)
    except Exception:
        pass
    if rc == 0 and got.get('install') == 'ok':
        return True, got
    return False, e or got.get('error') or (err or out or f'exit {rc}').strip()[-400:]


@bp.route('/api/vlab/admin/desktops/<desktop_id>/logon-sso/install', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def install_desktop_logon(desktop_id):
    desk, mgr, node, err = _running_windows(desktop_id)
    if err:
        return err
    if not logon_ca.ca_info():
        return jsonify({'error': 'no logon CA in the engine', 'code': 'CA_MISSING'}), 409
    ok, got = install_and_record(desk, mgr, node, who=_user(), ip=get_client_ip())   # the console's "다시 설치" too
    if not ok and str(got).startswith('INSTALL_RUNNING'):
        return jsonify({'error': '이 데스크톱에 설치가 이미 진행 중입니다. 잠시 뒤에 상태를 보세요.', 'code': 'INSTALL_RUNNING'}), 409
    if not ok:
        return jsonify({'error': str(got)[:400], 'code': 'INSTALL_FAILED'}), 502
    return jsonify({'installed': True, 'module': got})


@bp.route('/api/vlab/admin/desktops/<desktop_id>/logon-sso/status', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def desktop_logon_status(desktop_id):
    from pegaprox.api.vlab_next import _agent_run
    desk, mgr, node, err = _running_windows(desktop_id)
    if err:
        return err
    rc, out, err_, e = _agent_run(mgr, node, int(desk['vmid']), [EXE, 'status'], wait=15)
    if rc != 0:
        return jsonify({'installed': False, 'detail': (e or err_ or out or '')[:300]})
    return jsonify({'installed': True, 'module': _kv(out), 'issued': logon_ca.issued(10, desktop_id=desk['id'])})


# --- portal ----------------------------------------------------------------------------------

@bp.route('/api/vlab/me/desktops/<desktop_id>/logon-sso', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def my_desktop_logon(desktop_id):
    """Arm the signed-in user's next RDP sign-in on their own Windows desktop: a certificate valid a
    few minutes, for this portal session and this desktop, made for a key the VM made. The answer
    says until when; the certificate itself stays in the VM."""
    from pegaprox.api.vlab_next import shared_member
    username = _user()
    desk = store.get_desktop(desktop_id)
    if not desk or (desk['assigned_user'] != username and not shared_member(desk, username)):
        return _bad('Desktop not found', 404)
    if not sso_on(store.get_pool(desk['pool_id'])):
        return jsonify({'error': SSO_OFF_TEXT, 'code': 'SSO_OFF'}), 409
    desk, mgr, node, err = _running_windows(desktop_id)
    if err:
        return err
    ok, code, info = arm(desk, mgr, node, username, _portal_session(), get_client_ip())
    if not ok:
        logging.warning(f"[VLAB] desktop sign-in on {desk.get('name')} for {username} not armed ahead: {code} {str(info)[:200]}")
        return jsonify({'error': '자동 로그인을 준비하지 못했습니다. 로그온 화면에서 로그인하세요.', 'code': code}), 409
    return jsonify({'armed': True, **info})


# --- automatic install -------------------------------------------------------------------------
# A Windows desktop of a pool with desktop_sso on gets the module (and the CA trust) by itself: a new
# or newly added desktop once its guest agent answers, every Windows desktop of a pool when the switch
# goes on, and again when the engine carries a newer module. The CSP is installed under its version's
# file name, so an update never needs a restart and none is made. Failures are retried with a growing
# pause; a desktop without the module just shows its normal sign-in screen.

MODULE_VERSION = '1.3.4'      # windows/moavi-logon/common.h MOAVI_LOGON_VERSION (tests/test_vlab_logon.py checks)
AUTO_EVERY = 60
AUTO_PER_ROUND = 3
RETRY_MAX = 3600
_auto_thread = None


def _windows_running(desk):
    """(mgr, node, None) for a running Windows desktop, else (None, None, code)."""
    from pegaprox.api.vlab_next import _guest_os
    if desk.get('vm_type') != 'qemu':
        return None, None, 'NOT_QEMU'
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return None, None, 'NO_CLUSTER'
    live = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
    if live.get('status') != 'running':
        return None, None, 'NOT_RUNNING'
    node = live.get('node') or desk['node']
    osk = _guest_os(mgr, node, int(desk['vmid']))
    if osk is None:
        return None, None, 'NO_AGENT'
    if osk != 'windows':
        return None, None, 'NOT_WINDOWS'
    return mgr, node, None


_installing = set()            # desktop ids an install runs on now
_installing_lock = threading.Lock()


def install_and_record(desk, mgr, node, who='system', ip=''):
    """Install now and write the outcome (state, version, next try). (ok, info). One install per
    desktop at a time: each one empties the VM's setup folder, so a second one (the automatic
    round and a 다시 설치 click) would break the first one's file writes."""
    with _installing_lock:
        if desk['id'] in _installing:
            return False, 'INSTALL_RUNNING: an install runs on this desktop now'
        _installing.add(desk['id'])
    try:
        return _install_and_record(desk, mgr, node, who, ip)
    finally:
        with _installing_lock:
            _installing.discard(desk['id'])


def _install_and_record(desk, mgr, node, who, ip):
    prev = logon_ca.install_of(desk['id']) or {}
    try:
        ok, got = install(desk, mgr, node)
    except logon_ca.LogonCAError as e:
        ok, got = False, f'{e.code}: {e}'
    except Exception as e:
        ok, got = False, str(e)[:300]
    if ok and got.get('lsa_ppl') == 'on':
        return _lsa_off_and_restart(desk, mgr, node, prev, got, who, ip)
    if ok:
        logon_ca.record_install(desk['id'], desk['vmid'], got.get('version') or MODULE_VERSION, 'installed', 'OK',
                                f"cp={got.get('cp', '')} csp={got.get('csp', '')}")
        log_audit(who, 'vlab.logon.install', f"desktop sign-in module {got.get('version', '')} on '{desk['name']}' "
                  f"(qemu/{desk['vmid']})", ip)
        return True, got
    attempts = int(prev.get('attempts') or 0) + 1 if prev.get('state') == 'failed' else 1
    code = 'AGENT_EXEC_DISABLED' if 'AGENT_EXEC_DISABLED' in str(got) else 'INSTALL_FAILED'
    logon_ca.record_install(desk['id'], desk['vmid'], MODULE_VERSION, 'failed', code, str(got)[:300], attempts,
                            time.time() + min(60 * 2 ** attempts, RETRY_MAX))
    if prev.get('state') != 'failed' or who != 'system':      # once per failure streak, not every retry
        log_audit(who, 'vlab.logon.install', f"desktop sign-in module on '{desk['name']}' (qemu/{desk['vmid']}) "
                  f"failed: {str(got)[:200]}", ip)
    return False, got


LSA_RESTART_WAIT = 180      # seconds a desktop gets to restart before the module is installed again
LSA_BUSY_WAIT = 300         # someone is on it: looked at again in 5 minutes


def _lsa_off_and_restart(desk, mgr, node, prev, got, who, ip):
    """LSA protection (RunAsPPL) is on: LSASS loads no unsigned CSP, so the module is installed but
    quiet. Turn it off and restart the desktop - only when nobody is signed in on it; else again in
    5 minutes. Still on after that restart: set with a UEFI lock, which only the desktop's own
    administrator can clear (unsupported, LSA_PPL_LOCKED; its normal sign-in screen stays)."""
    from pegaprox.api.vlab_next import _agent_run
    from pegaprox.vlab.directory import LSA_OFF_PS
    version = got.get('version') or MODULE_VERSION
    if prev.get('code') == 'LSA_PPL_RESTART':
        logon_ca.record_install(desk['id'], desk['vmid'], version, 'unsupported', 'LSA_PPL_LOCKED',
                                'LSA protection is still on after it was turned off and the desktop restarted '
                                '(UEFI lock): turn it off on the desktop itself')
        log_audit(who, 'vlab.logon.install', f"desktop sign-in on '{desk['name']}' (qemu/{desk['vmid']}): LSA protection "
                  "stays on after a restart (UEFI lock)", ip)
        return True, got
    try:
        rc, out, err, e = _agent_run(mgr, node, int(desk['vmid']), ['powershell.exe', '-NoProfile', '-NonInteractive',
                                     '-ExecutionPolicy', 'Bypass', '-Command', LSA_OFF_PS], wait=20)
    except Exception as ex:
        rc, out, err, e = None, '', '', str(ex)[:200]
    if rc != 0 or 'lsa_ppl_off=1' not in (out or ''):
        logon_ca.record_install(desk['id'], desk['vmid'], version, 'failed', 'LSA_PPL',
                                f"LSA protection could not be turned off: {(e or err or out or '')[:200]}", 1,
                                time.time() + LSA_BUSY_WAIT)
        return False, got
    if any(s.get('desktop_id') == desk['id'] for s in store.open_sessions()):
        logon_ca.record_install(desk['id'], desk['vmid'], version, 'pending', 'LSA_PPL_WAIT',
                                'LSA protection turned off; the desktop restarts once nobody is signed in', 0,
                                time.time() + LSA_BUSY_WAIT)
        return True, got
    try:
        rc, out, err, e = _agent_run(mgr, node, int(desk['vmid']), ['shutdown.exe', '/r', '/t', '15', '/c',
                                     'MOAVI Desk: desktop sign-in (LSA protection off)'], wait=10)
    except Exception as ex:
        rc, e = None, str(ex)[:200]
    logon_ca.record_install(desk['id'], desk['vmid'], version, 'pending', 'LSA_PPL_RESTART',
                            'LSA protection turned off; restarting the desktop' + ('' if rc == 0 else f' (restart: {e or rc})'),
                            0, time.time() + LSA_RESTART_WAIT)
    log_audit(who, 'vlab.logon.install', f"desktop sign-in on '{desk['name']}' (qemu/{desk['vmid']}): LSA protection off, "
              "restarting", ip)
    return True, got


def _install_due(desk):
    r = logon_ca.install_of(desk['id'])
    if not r or int(r['vmid']) != int(desk['vmid']):
        return True                                    # new, or a recreated VM
    if r['state'] == 'unsupported' and r['code'] == 'LSA_PPL':
        return True                                    # from before LSA protection was turned off by the engine
    if r['state'] in ('installed', 'unsupported'):
        return r['version'] != MODULE_VERSION          # the engine carries a newer module
    if r['state'] == 'skipped':
        return False                                   # not Windows (a rebuilt VM has a new vmid)
    return float(r['next_at'] or 0) <= time.time()


def install_round(limit=AUTO_PER_ROUND):
    """One pass (the thread below, and tests): {installed, failed, waiting, skipped}."""
    done = {'installed': 0, 'failed': 0, 'waiting': 0, 'skipped': 0}
    if not logon_ca.ca_info():
        return done
    left = limit
    for pool in store.list_pools():
        if not sso_on(pool):
            continue
        for desk in store.list_desktops(pool['id']):
            if left <= 0:
                return done
            if not _install_due(desk):
                continue
            mgr, node, why = _windows_running(desk)
            if why in ('NOT_WINDOWS', 'NOT_QEMU'):
                logon_ca.record_install(desk['id'], desk['vmid'], MODULE_VERSION, 'skipped', why, 'not a Windows desktop')
                done['skipped'] += 1
                continue
            if why:
                prev = logon_ca.install_of(desk['id']) or {}
                if prev.get('state') != 'installed':
                    # a stopped desktop is looked at again in 5 minutes; the engine still connecting to its
                    # cluster or a guest agent still starting, at the next round
                    pause = 300 if why == 'NOT_RUNNING' else AUTO_EVERY
                    logon_ca.record_install(desk['id'], desk['vmid'], prev.get('version') or MODULE_VERSION, 'pending',
                                            why, 'waiting for the desktop', int(prev.get('attempts') or 0), time.time() + pause)
                done['waiting'] += 1
                continue
            from pegaprox.core import ha
            if not ha.confirm_step(f"desktop sign-in install on qemu/{desk['vmid']}"):
                return done
            left -= 1
            ok, _ = install_and_record(desk, mgr, node)
            done['installed' if ok else 'failed'] += 1
    return done


PRUNE_EVERY = 3600


def _install_loop():
    pruned = 0.0
    while True:
        try:
            from pegaprox.core import ha
            if ha.is_active():
                install_round()
                if time.time() - pruned > PRUNE_EVERY:
                    pruned = time.time()
                    logon_ca.prune()
        except Exception as e:
            logging.error(f'[VLAB] desktop sign-in automatic install: {e}')
        time.sleep(AUTO_EVERY)


def start_install_thread():
    global _auto_thread
    if _auto_thread is None or not _auto_thread.is_alive():
        _auto_thread = threading.Thread(target=_install_loop, daemon=True, name='vlab-logon-install')
        _auto_thread.start()


@bp.route('/api/vlab/admin/pools/<pool_id>/logon-sso', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def pool_logon_installs(pool_id):
    """The pool's switch and, per desktop, the module: installed (version) / pending / failed / skipped."""
    pool = store.get_pool(pool_id)
    if not pool:
        return _bad('Pool not found', 404)
    desks = store.list_desktops(pool_id)
    rows = logon_ca.installs([d['id'] for d in desks])
    out = []
    for d in desks:
        r = rows.get(d['id']) or {}
        out.append({'desktop_id': d['id'], 'name': d['name'], 'state': r.get('state') or 'none',
                    'version': r.get('version') or '', 'code': r.get('code') or '', 'detail': r.get('detail') or '',
                    'at': r.get('at') or '', 'current': r.get('state') == 'installed' and r.get('version') == MODULE_VERSION})
    return jsonify({'desktop_sso': sso_on(pool), 'module_version': MODULE_VERSION, 'ready': logon_ca.config()['ready'],
                    'desktops': out})
