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
AGENT_FILES = ('moavi-logon.exe', 'moavi-logon-cp.dll', 'moavi-logon-ksp.dll', 'moavi-logon-csp.dll', 'install.ps1')
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

def arm(desk, mgr, node, username, portal_session='', client_ip=''):
    """prepare -> sign -> arm for this user's next RDP session on this Windows desktop.
    (True, '', info) or (False, code, detail). Never raises."""
    from pegaprox.api.vlab_next import _agent_run, agent_exec_disabled
    ok, code = logon_ca.eligible(username, desk['id'])
    if not ok:
        return False, code, ''
    vmid = int(desk['vmid'])
    try:
        rc, out, err, e = _agent_run(mgr, node, vmid, [EXE, 'prepare'], wait=PREPARE_WAIT)
    except Exception as ex:
        rc, out, err, e = None, '', '', str(ex)[:200]
    got = _kv(out)
    if rc != 0 or not got.get('csr') or not got.get('nonce'):
        if agent_exec_disabled(e):
            return False, 'AGENT_EXEC_DISABLED', e
        if 'cannot find' in (e or '').lower() or 'no such file' in (e or '').lower() or 'not found' in (e or '').lower():
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


def sso_on(pool):
    return bool(pool_policy.effective((pool or {}).get('settings')).get('desktop_sso'))


def arm_for_connect(desk, mgr, node, username, pool):
    """The connect routes (RDP file, browser RDP) on a Windows desktop: arm its next sign-in when the
    pool has desktop_sso on. Failures are logged, never shown - the sign-in screen is the fallback."""
    if not sso_on(pool):
        return None
    try:
        ok, code, info = arm(desk, mgr, node, username, _portal_session(), get_client_ip())
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
            raise RuntimeError(f"file-write {os.path.basename(path)}: {(getattr(resp, 'text', '') or '')[:200]}")
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
    mk = ("$d='" + SETUP_DIR + "'; if (Test-Path $d) { Remove-Item -Recurse -Force $d }; "
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
        parts = _write_file(mgr, node, vmid, SETUP_DIR + '\\' + name, data)
        manifest.append(f"{name}|{parts}|{hashlib.sha256(data).hexdigest()}")
    run = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command',
           "$d='" + SETUP_DIR + "'; "
           "Get-ChildItem $d -Filter '*.part*' | Group-Object { $_.Name -replace '\\.part\\d{3}$','' } | ForEach-Object { "
           "$o=[IO.File]::Create((Join-Path $d $_.Name)); "
           "foreach ($p in ($_.Group | Sort-Object Name)) { $b=[IO.File]::ReadAllBytes($p.FullName); $o.Write($b,0,$b.Length); "
           "Remove-Item -Force $p.FullName }; $o.Close() }; "
           "& (Join-Path $d 'install.ps1') -Setup $d"]
    rc, out, err, e = _agent_run(mgr, node, vmid, run, stdin='\n'.join(manifest) + '\n', wait=90)
    got = _kv(out)
    if rc == 0 and got.get('install') == 'ok':
        return True, got
    return False, e or got.get('error') or (err or out or f'exit {rc}').strip()[-400:]


@bp.route('/api/vlab/admin/desktops/<desktop_id>/logon-sso/install', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def install_desktop_logon(desktop_id):
    desk, mgr, node, err = _running_windows(desktop_id)
    if err:
        return err
    try:
        ok, got = install(desk, mgr, node)
    except logon_ca.LogonCAError as e:
        return jsonify({'error': str(e), 'code': e.code}), 409
    except Exception as e:
        ok, got = False, str(e)[:300]
    log_audit(_user(), 'vlab.logon.install', f"desktop sign-in module on '{desk['name']}' (qemu/{desk['vmid']}): "
              f"{'ok ' + str(got.get('version', '')) if ok else 'failed: ' + str(got)[:200]}", get_client_ip())
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
        return jsonify({'error': '자동 로그인을 준비하지 못했습니다. 로그온 화면에서 로그인하세요.', 'code': code}), 409
    return jsonify({'armed': True, **info})
