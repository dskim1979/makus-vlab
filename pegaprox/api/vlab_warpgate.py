# -*- coding: utf-8 -*-
"""
MOAVI Desk - Warpgate 접근 게이트웨이(bastion) API (pegaprox/vlab/warpgate.py).

모든 데스크톱 RDP/SSH/VNC를 Warpgate 하나로 중계한다. 포털 사용자가 연결하면 그 사용자+그 대상에만
쓸 수 있는 1회용·단시간 티켓을 발급하고 접속 좌표를 돌려준다. 사용자·데스크톱 비밀번호는 저장/전달하지
않는다. 설계·대체 관계는 docs/warpgate-gateway.md.

  GET  /api/vlab/admin/warpgate              설정(토큰 없음) + 매핑 수                        vlab.pool.view
  PUT  /api/vlab/admin/warpgate              설정 저장(base_url·토큰·포트·NLA 서비스 계정)    vlab.pool.manage
  POST /api/vlab/admin/warpgate/test         연결 점검(대상 목록 읽기)                         vlab.pool.manage
  GET  /api/vlab/admin/warpgate/sessions     관리자 세션/녹화 페이지 링크                      vlab.pool.view
  POST /api/vlab/me/desktops/<id>/warpgate   {protocol: rdp|ssh|vnc} 티켓 발급 + 접속 좌표     vlab.desk
  /api/vlab/oidc/...                         Warpgate 로그인을 MOAVI Desk 세션으로(OIDC 공급자, wg_oidc.py)
  POST /api/vlab/admin/desktops/<id>/warpgate-nla/rotate  그 Windows 데스크톱 NLA 서비스 계정 비번 교체  vlab.pool.manage
"""

import logging
import re

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import policy as pool_policy
from pegaprox.vlab import store
from pegaprox.vlab import warpgate as wg
from pegaprox.vlab import wg_oidc

bp = Blueprint('vlab_warpgate', __name__)

_bad = core._bad
_user = core._user


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _port(data, key, default):
    try:
        v = int(data.get(key, default))
    except (TypeError, ValueError):
        raise ValueError(f'{key}: 포트는 1~65535 사이의 숫자')
    if not (1 <= v <= 65535):
        raise ValueError(f'{key}: 포트는 1~65535 사이의 숫자')
    return v


# --- admin -------------------------------------------------------------------------------

@bp.route('/api/vlab/admin/warpgate', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_warpgate():
    return jsonify({'config': wg.config(), 'targets': len(wg.list_mappings())})


@bp.route('/api/vlab/admin/warpgate', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def put_warpgate():
    data = _body()
    try:
        base_url = str(data.get('base_url') or '').strip()
        if base_url and not base_url.startswith(('http://', 'https://')):
            return _bad('base_url: http(s)://로 시작해야 합니다')
        ssh_port = _port(data, 'ssh_port', wg.DEFAULT_PORTS['ssh'])
        rdp_port = _port(data, 'rdp_port', wg.DEFAULT_PORTS['rdp'])
        vnc_port = _port(data, 'vnc_port', wg.DEFAULT_PORTS['vnc'])
    except ValueError as e:
        return _bad(str(e))
    verify_tls = data.get('verify_tls', False) is True
    enabled = data.get('enabled', False) is True
    # token / nla_password: 키가 아예 없으면 기존값 유지(None), 있으면 그 값(''도 반영)
    token = data['admin_token'] if 'admin_token' in data else None
    nla_pw = data['rdp_nla_password'] if 'rdp_nla_password' in data else None
    nla_user = data['rdp_nla_user'] if 'rdp_nla_user' in data else None
    via = data.get('rdp_via_warpgate')
    if via is not None and not isinstance(via, bool):
        return _bad('rdp_via_warpgate must be true or false')
    fallback = data.get('allow_direct_fallback')
    if fallback is not None and not isinstance(fallback, bool):
        return _bad('allow_direct_fallback must be true or false')
    cfg = wg.save_config(base_url, ssh_port, rdp_port, vnc_port, verify_tls, enabled,
                         admin_token=token, rdp_nla_user=nla_user, rdp_nla_password=nla_pw,
                         rdp_via_warpgate=via, allow_direct_fallback=fallback)
    log_audit(_user(), 'vlab.warpgate.config', f"Warpgate {base_url or '-'} enabled={enabled}", get_client_ip())
    return jsonify({'config': cfg})


@bp.route('/api/vlab/admin/warpgate/test', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def test_warpgate():
    cfg = wg.config(secret=True)
    if not cfg['base_url'] or not cfg.get('admin_token'):
        return _bad('먼저 base_url과 관리자 API 토큰을 저장하세요', 409)
    ok, detail = wg.test_connection(cfg)
    wg.mark_check(ok, detail)
    return jsonify({'ok': ok, 'detail': detail, 'config': wg.config()})


@bp.route('/api/vlab/admin/warpgate/sessions', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def warpgate_sessions():
    cfg = wg.config()
    if not cfg['base_url']:
        return _bad('보안 게이트웨이가 설정되지 않았습니다', 409)
    return jsonify({'url': wg.recording_url(cfg, request.args.get('session_id'))})


# --- portal ------------------------------------------------------------------------------

@bp.route('/api/vlab/me/warpgate', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_warpgate_status():
    """포털이 보안 게이트웨이 연결 항목을 보일지 판단하는 가벼운 상태(토큰·주소 노출 없음)."""
    return jsonify({'enabled': wg.is_enabled(), 'protocols': list(wg.TARGET_KINDS)})


# --- researcher native SSH: the user's own keys and ssh config ---------------------------

def _my_ssh_desktops(username):
    """researcher_ssh 정책이 켜진 풀의, 이 사용자에게 배정된 데스크톱."""
    from pegaprox.api.vlab_next import shared_member
    out = []
    for d in store.list_desktops():
        if d['assigned_user'] != username and not shared_member(d, username):
            continue
        pol = pool_policy.effective((store.get_pool(d['pool_id']) or {}).get('settings'))
        if pol.get('researcher_ssh'):
            out.append(d)
    return out


@bp.route('/api/vlab/me/ssh-keys', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_ssh_keys():
    """내 계정: 내가 Warpgate에 등록한 SSH 공개키 목록. 개인키는 다루지 않는다."""
    if not wg.is_enabled():
        return jsonify({'enabled': False, 'keys': []})
    cfg = wg.config(secret=True)
    try:
        return jsonify({'enabled': True, 'keys': wg.list_user_keys(cfg, _user())})
    except wg.WarpgateError as e:
        return jsonify({'error': str(e), 'code': 'WG_API'}), 502
    except Exception as e:
        return jsonify({'error': str(e)[:200], 'code': 'WG_UNREACHABLE'}), 502


@bp.route('/api/vlab/me/ssh-keys', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def add_my_ssh_key():
    """내 공개키를 Warpgate에 등록(엔진은 저장하지 않음). 개인키·잘못된 형식은 거부한다."""
    if not wg.is_enabled():
        return jsonify({'error': '보안 게이트웨이가 꺼져 있습니다', 'code': 'WG_OFF'}), 409
    data = _body()
    key = str(data.get('openssh_public_key') or '').strip()
    label = str(data.get('label') or '').strip() or 'MOAVI Desk'
    # codes for the screens to word (PRIVATE_KEY / BAD_PUBLIC_KEY); the key itself is never echoed
    if wg.looks_like_private_key(key):
        return jsonify({'error': '공개키만 올리세요.', 'code': 'PRIVATE_KEY'}), 400
    if not wg.is_public_key(key):
        return jsonify({'error': '공개키 형식이 아닙니다.', 'code': 'BAD_PUBLIC_KEY'}), 400
    cfg = wg.config(secret=True)
    try:
        wg.add_user_key(cfg, _user(), label, key)
    except wg.WarpgateError as e:
        return jsonify({'error': str(e), 'code': 'WG_API'}), 502
    except Exception as e:
        return jsonify({'error': str(e)[:200], 'code': 'WG_UNREACHABLE'}), 502
    log_audit(_user(), 'vlab.warpgate.ssh_key_add', f"SSH public key '{label}'", get_client_ip())
    return jsonify({'keys': wg.list_user_keys(cfg, _user())}), 201


@bp.route('/api/vlab/me/ssh-keys/<key_id>', methods=['DELETE'])
@require_auth(perms=['vlab.desk'])
def delete_my_ssh_key(key_id):
    if not wg.is_enabled():
        return jsonify({'error': '보안 게이트웨이가 꺼져 있습니다', 'code': 'WG_OFF'}), 409
    cfg = wg.config(secret=True)
    try:
        wg.delete_user_key(cfg, _user(), key_id)
    except wg.WarpgateError as e:
        return jsonify({'error': str(e), 'code': 'WG_API'}), 502
    except Exception as e:
        return jsonify({'error': str(e)[:200], 'code': 'WG_UNREACHABLE'}), 502
    log_audit(_user(), 'vlab.warpgate.ssh_key_del', f"SSH public key {key_id}", get_client_ip())
    return jsonify({'keys': wg.list_user_keys(cfg, _user())})


@bp.route('/api/vlab/me/ssh-config', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_ssh_config():
    """researcher_ssh 풀의 내 데스크톱을 자기 SSH 도구로 쓰기 위한 정보: Warpgate 호스트·포트·로그인과
    데스크톱별 ~/.ssh/config 항목(`User <wguser>:<target>`; Warpgate는 점프 호스트가 아니라 이 형식으로
    대상을 고른다). MOAVI Desk 클라이언트가 이 블록을 사용자의 config에 자동으로 넣는다."""
    if not wg.is_enabled():
        return jsonify({'enabled': False, 'entries': []})
    cfg = wg.config()
    username = _user()
    host_alias_prefix = 'moavi-'
    entries = []
    for d in _my_ssh_desktops(username):
        # the desktop's SSH target (its own, next to the RDP one); a synced one keeps its Warpgate name
        mp = wg.get_mapping(wg.target_ref(d['id'], 'ssh'))
        target = (mp or {}).get('target_name') or wg.target_name_for(wg.target_ref(d['id'], 'ssh'), d['name'])
        alias = host_alias_prefix + re.sub(r'[^A-Za-z0-9._-]+', '-', d['name']).strip('-').lower()
        e = wg.ssh_config_entry(cfg, alias, username, target)
        e['desktop_id'] = d['id']
        e['desktop_name'] = d['name']
        entries.append(e)
    managed = ''.join(e['config_snippet'] + '\n' for e in entries)
    return jsonify({'enabled': True, 'warpgate_host': wg._host_of(cfg['base_url']), 'ssh_port': cfg['ssh_port'],
                    'login': wg.wg_user_name(username), 'entries': entries, 'managed_block': managed.strip()})


# --- portal connect ----------------------------------------------------------------------

def _desktop_target_options(cfg, proto, ip, desk=None, pol=None):
    """프로토콜별 Warpgate 대상 옵션. RDP는 interactive_logon=True(자동 로그인 안 함); NLA 서비스
    계정은 콘솔 설정의 것이 있으면 그것, 없으면 그 Windows 데스크톱의 moavi-nla(엔진이 만든 무작위
    비번, prepare_windows_nla) - 사용자 비번이 아니다. VNC는 None 인증."""
    if proto == 'ssh':
        # the pool's file transfer switch also turns the gateway's web-SSH file panel on or off
        return wg.ssh_target_options(ip, 22, 'moavi', None if pol is None else pol.get('ssh_files', 'off') != 'off')
    if proto == 'vnc':
        return wg.vnc_target_options(ip, int(cfg['vnc_port']))
    user, pw = cfg.get('rdp_nla_user') or '', cfg.get('rdp_nla_password') or ''
    if not (user and pw) and desk:
        own = wg.nla_applied_credentials(desk['id'], desk['vmid'])
        if own:
            user, pw = own
    return wg.rdp_target_options(ip, 3389, user or wg.NLA_USER, pw, interactive_logon=True)


def warpgate_serves_rdp(protocol):
    """Will this connect go through Warpgate: the .rdp with "RDP through 보안 게이트웨이" on?"""
    return protocol == 'rdp' and wg.is_enabled() and bool(wg.config()['rdp_via_warpgate'])


def prepare_windows_nla(desk, mgr, node, wait=25):
    """Before Warpgate opens RDP to a Windows desktop: its own NLA account moavi-nla, made / refreshed
    through the guest agent (password on stdin). Skipped when the console sets a global NLA account or
    Warpgate is off. True when the desktop's own account is ready. Never raises."""
    if not wg.is_enabled():
        return False
    cfg = wg.config(secret=True)
    if cfg.get('rdp_nla_user') and cfg.get('rdp_nla_password'):
        return False
    if not wg.nla_needs_apply(desk['id'], desk['vmid']):
        return True
    from pegaprox.api.vlab_next import _agent_run
    pw = wg.nla_password(desk['id'], desk['vmid'])
    try:
        code, out, err, e = _agent_run(mgr, node, desk['vmid'], ['powershell.exe', '-NoProfile', '-NonInteractive',
                                       '-ExecutionPolicy', 'Bypass', '-Command', wg.nla_account_script()],
                                       stdin=pw + '\n', wait=wait)
    except Exception as ex:
        code, out, err, e = None, '', '', str(ex)[:200]
    if code == 0 and 'nla=ok' in (out or ''):
        wg.nla_mark_applied(desk['id'])
        log_audit('system', 'vlab.warpgate.nla', f"{desk['name']}: RDP NLA service account {wg.NLA_USER} set", '')
        return True
    # Windows' own words (the script asks for UTF-8 output); the password never echoed back
    detail = e or ' '.join(x for x in ((out or '').strip()[:80], (err or '').replace(pw, '***').strip()[:300]) if x)
    logging.warning(f"[VLAB] Warpgate NLA account on {desk.get('name')} not set (exit {code}): {detail}")
    return False


@bp.route('/api/vlab/admin/desktops/<desktop_id>/warpgate-nla/rotate', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def rotate_desktop_nla(desktop_id):
    """A new NLA service account password for this Windows desktop, now: set in the VM through the
    guest agent and put on its Warpgate RDP target. A stopped desktop gets it on its next connect
    (the old one keeps working in the VM until then). The password is never in the answer."""
    from pegaprox.api.vlab_next import _guest_ipv4, _guest_os
    desk = store.get_desktop(desktop_id)
    if not desk:
        return _bad('Desktop not found', 404)
    if not wg.is_enabled():
        return jsonify({'error': '보안 게이트웨이가 꺼져 있습니다', 'code': 'WG_OFF'}), 409
    wg.nla_forget(desk['id'])
    applied = synced = False
    mgr = cluster_managers.get(desk['cluster_id'])
    live = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {} if mgr else {}
    node = live.get('node') or desk['node']
    if mgr and getattr(mgr, 'is_connected', False) and live.get('status') == 'running' \
            and _guest_os(mgr, node, int(desk['vmid'])) == 'windows':
        applied = prepare_windows_nla(desk, mgr, node)
        ip = _guest_ipv4(mgr, node, int(desk['vmid'])) if applied else None
        if ip and wg.get_mapping(desk['id']):
            try:
                cfg = wg.config(secret=True)
                wg.sync_target(cfg, desk['id'], desk['name'], 'rdp', _desktop_target_options(cfg, 'rdp', ip, desk))
                synced = True
            except Exception as e:
                logging.warning(f"[VLAB] Warpgate target of {desk['name']} not updated after NLA rotation: {str(e)[:200]}")
    log_audit(_user(), 'vlab.warpgate.nla_rotate',
              f"'{desk['name']}': NLA service account password rotated (in VM: {applied}, Warpgate: {synced})",
              get_client_ip())
    return jsonify({'rotated': True, 'applied': applied, 'target_updated': synced})


WG_DOWN_TEXT = '보안 게이트웨이에 연결할 수 없습니다. 잠시 뒤 다시 시도하세요.'


def _wg_down(cfg, what, desk, e):
    """Warpgate failed on a path the admin switched to Warpgate. Fail closed (code WG_DOWN): a silent
    fall back would go around the bastion - and fails anyway where direct access is blocked. Only
    with the admin's explicit allow_direct_fallback (security weakened) does the caller go on with the
    direct path. Returns (None, error response), or (None, None) to go on."""
    if cfg.get('allow_direct_fallback'):
        logging.warning(f"[VLAB] Warpgate {what} for {desk.get('name')} failed, direct path allowed by setting: {str(e)[:200]}")
        log_audit('system', 'vlab.warpgate.fallback', f"{what} to '{desk.get('name')}' without Warpgate (allow_direct_fallback)", '')
        return None, None
    logging.warning(f"[VLAB] Warpgate {what} for {desk.get('name')} failed, refused (fail closed): {str(e)[:200]}")
    return None, (jsonify({'error': WG_DOWN_TEXT, 'code': 'WG_DOWN'}), 503)


def _external_rdp_options(cfg, ext):
    """An external desktop (a physical PC) has no guest agent: its NLA account is the console's
    global one, if set (otherwise the PC must allow RDP without NLA)."""
    return wg.rdp_target_options(ext['address'], int(ext.get('port') or 3389),
                                 cfg.get('rdp_nla_user') or wg.NLA_USER, cfg.get('rdp_nla_password') or '',
                                 interactive_logon=True)


def external_rdp_via_warpgate(ext, username):
    """The .rdp for an external desktop when "RDP through 보안 게이트웨이" is on: aimed at Warpgate with a
    single-use ticket, like a pool desktop. (None, None): switch off - the caller writes the direct
    file. Warpgate fails: WG_DOWN unless the admin allowed the direct fallback."""
    if not wg.is_enabled():
        return None, None
    cfg = wg.config(secret=True)
    if not cfg.get('rdp_via_warpgate'):
        return None, None
    from pegaprox.api.vlab_next import rdp_redirects
    try:
        role_id = wg.ensure_role(cfg)
        wg.ensure_user(cfg, username, role_id)
        _uuid, target_name = wg.sync_target(cfg, ext['id'], ext['name'], 'rdp', _external_rdp_options(cfg, ext), role_id)
        _ticket, secret = wg.issue_ticket(cfg, username, target_name)
        if not secret:
            raise wg.WarpgateError('Warpgate did not return a ticket secret')
    except Exception as e:
        return _wg_down(cfg, 'RDP file', ext, e)
    log_audit(username, 'vlab.external.connect', f"RDP file for '{ext['name']}' via 보안 게이트웨이", get_client_ip())
    return {'type': 'rdp', 'via': 'warpgate', 'rdp': wg.rdp_file_text(cfg, secret, rdp_redirects(None), ())}, None


def external_web_via_warpgate(ext, username):
    """Browser RDP to an external desktop: 보안 게이트웨이's web UI opened on its target. (url, None), or
    (None, error) - WG_OFF when Warpgate is off, WG_DOWN when it fails (there is no other browser path)."""
    if not wg.is_enabled():
        return None, (jsonify({'error': '보안 게이트웨이가 꺼져 있습니다', 'code': 'WG_OFF'}), 409)
    cfg = wg.config(secret=True)
    try:
        role_id = wg.ensure_role(cfg)
        wg.ensure_user(cfg, username, role_id)
        target_uuid, _name = wg.sync_target(cfg, ext['id'], ext['name'], 'rdp', _external_rdp_options(cfg, ext), role_id)
    except Exception as e:
        logging.warning(f"[VLAB] Warpgate browser RDP for {ext.get('name')} failed: {str(e)[:200]}")
        return None, (jsonify({'error': WG_DOWN_TEXT, 'code': 'WG_DOWN'}), 503)
    log_audit(username, 'vlab.external.connect', f"browser RDP to '{ext['name']}' via 보안 게이트웨이", get_client_ip())
    return wg.web_ui_url(cfg, 'rdp', target_uuid), None


def rdp_answer_via_warpgate(desk, username, ip, pol):
    """The connect route's .rdp for the client / mstsc when "RDP through Warpgate" is on: aimed at
    Warpgate's RDP listener with a single-use ticket for this user and this desktop, the pool's
    redirect lines kept. (answer, None) when on; (None, None) when the switch is off - the caller writes
    the direct / RD Gateway .rdp as before. Warpgate fails: (None, WG_DOWN error) - fail closed -
    unless the admin allowed the direct fallback, then (None, None)."""
    if not wg.is_enabled():
        return None, None
    cfg = wg.config(secret=True)
    if not cfg.get('rdp_via_warpgate'):
        return None, None
    from pegaprox.api.vlab_next import RDP_NETWORK, rdp_redirects
    try:
        role_id = wg.ensure_role(cfg)
        wg.ensure_user(cfg, username, role_id)
        _uuid, target_name = wg.sync_target(cfg, desk['id'], desk['name'], 'rdp',
                                            _desktop_target_options(cfg, 'rdp', ip, desk), role_id)
        _ticket, secret = wg.issue_ticket(cfg, username, target_name)
        if not secret:
            raise wg.WarpgateError('Warpgate did not return a ticket secret')
    except Exception as e:
        return _wg_down(cfg, 'RDP file', desk, e)
    log_audit(username, 'vlab.warpgate.connect', f"RDP file to '{desk['name']}' via Warpgate", get_client_ip())
    return {'type': 'rdp', 'via': 'warpgate', 'filename': f"{desk['name']}.rdp",
            'rdp': wg.rdp_file_text(cfg, secret, rdp_redirects(pol), RDP_NETWORK)}, None


@bp.route('/api/vlab/me/desktops/<desktop_id>/warpgate', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def my_desktop_warpgate(desktop_id):
    """그 사용자+그 대상에만 쓸 수 있는 1회용·단시간 Warpgate 티켓을 발급하고 접속 좌표를 돌려준다.
    사용자 비밀번호는 묻지도 저장하지도 않는다."""
    from pegaprox.api.vlab_next import _guest_ipv4, rdp_listening, rdp_prepare, _guest_os, shared_member

    if not wg.is_enabled():
        return jsonify({'error': '보안 게이트웨이가 꺼져 있습니다', 'code': 'WG_OFF'}), 409
    proto = (_body().get('protocol') or 'rdp').lower()
    if proto not in wg.TARGET_KINDS:
        return _bad('protocol must be one of ' + ', '.join(wg.TARGET_KINDS))

    desk = store.get_desktop(desktop_id)
    username = _user()
    if not desk or (desk['assigned_user'] != username and not shared_member(desk, username)):
        return _bad('Desktop not found', 404)
    pool = store.get_pool(desk['pool_id']) or {}
    pol = pool_policy.effective(pool.get('settings'))
    # RDP/VNC는 pool 프로토콜 정책을 따른다. SSH는 browser_ssh 정책과 같은 취지로 허용.
    if proto in ('rdp', 'vnc') and proto not in pol['protocols']:
        return _bad(f"protocol must be one of {', '.join(pol['protocols'])}")
    if proto == 'ssh' and not pol.get('browser_ssh'):
        return jsonify({'error': 'SSH is off for this pool', 'code': 'SSH_OFF'}), 403

    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    live = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
    if live.get('status') != 'running':
        return jsonify({'error': 'The desktop is not running', 'code': 'VM_STOPPED'}), 409
    node = live.get('node') or desk['node']
    ip = _guest_ipv4(mgr, node, int(desk['vmid']))
    if not ip:
        return jsonify({'error': 'The desktop has no address yet - is its guest agent running?', 'code': 'NO_IP'}), 409

    if proto == 'rdp':
        os_kind = _guest_os(mgr, node, int(desk['vmid']))
        if os_kind == 'windows':
            if pol['rdp_tune']:
                rdp_prepare(desk, mgr, node)
            prepare_windows_nla(desk, mgr, node)
        elif os_kind == 'linux' and not rdp_listening(ip, 3389):
            return jsonify({'error': 'This Linux desktop has no RDP server (xrdp)', 'code': 'NO_RDP'}), 409
    elif proto == 'ssh' and not rdp_listening(ip, 22):
        return jsonify({'error': 'This desktop has no SSH server on port 22', 'code': 'NO_SSH'}), 409
    elif proto == 'vnc' and not rdp_listening(ip, int(wg.config()['vnc_port'])):
        return jsonify({'error': 'This desktop has no VNC server', 'code': 'NO_VNC'}), 409

    cfg = wg.config(secret=True)
    try:
        role_id = wg.ensure_role(cfg)
        wg.ensure_user(cfg, username, role_id)
        options = _desktop_target_options(cfg, proto, ip, desk, pol)
        target_uuid, target_name = wg.sync_target(cfg, desk['id'], desk['name'], proto, options, role_id)
        _ticket, secret = wg.issue_ticket(cfg, username, target_name)
    except wg.WarpgateError as e:
        return jsonify({'error': str(e), 'code': 'WG_API'}), 502
    except Exception as e:  # network/TLS: the detail (internal URL) goes to the log only
        logging.warning(f"[VLAB] Warpgate {proto} connect for {desk.get('name')} failed: {str(e)[:200]}")
        return jsonify({'error': WG_DOWN_TEXT, 'code': 'WG_DOWN'}), 503
    if not secret:
        return jsonify({'error': '보안 게이트웨이 응답 오류', 'code': 'WG_API'}), 502

    log_audit(username, 'vlab.warpgate.connect', f"{proto.upper()} to '{desk['name']}' via Warpgate", get_client_ip())
    return jsonify({'type': 'warpgate', 'connection': wg.connection_coordinates(cfg, proto, target_name, secret, target_uuid)})


# --- Warpgate signs its users in with MOAVI Desk (OpenID Connect, pegaprox/vlab/wg_oidc.py) --------

def _oidc_off():
    return jsonify({'error': 'not found'}), 404


def _oauth_error(code, status=400):
    resp = jsonify({'error': code})
    resp.status_code = status
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@bp.route('/api/vlab/oidc/.well-known/openid-configuration', methods=['GET'])
def oidc_discovery():
    """OIDC discovery for Warpgate (no sign-in; nothing secret)."""
    if not wg_oidc.is_enabled():
        return _oidc_off()
    return jsonify(wg_oidc.metadata())


@bp.route('/api/vlab/oidc/jwks', methods=['GET'])
def oidc_jwks():
    """The public key Warpgate checks the ID token with."""
    if not wg_oidc.is_enabled():
        return _oidc_off()
    return jsonify(wg_oidc.jwks())


@bp.route('/api/vlab/oidc/authorize', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def oidc_authorize():
    """Warpgate sends the browser here; the user's portal session answers (no password). Only
    Warpgate's own SSO return URL is accepted, with PKCE S256."""
    from urllib.parse import urlencode
    if not wg_oidc.is_enabled() or not wg.is_enabled():
        return _oidc_off()
    if (getattr(request, 'session', None) or {}).get('api_token'):
        return _bad('Sign in to the portal first', 403)     # an API token is not a browser sign-in
    a = request.args
    redirect_uri = a.get('redirect_uri', '')
    if a.get('client_id') != wg_oidc.CLIENT_ID or not wg_oidc.redirect_allowed(redirect_uri, wg.config()['base_url']):
        return _bad('invalid client or redirect_uri')      # never redirect to an unknown place
    state = a.get('state', '')

    def back(**q):
        return '', 302, {'Location': redirect_uri + ('&' if '?' in redirect_uri else '?') + urlencode(q),
                         'Cache-Control': 'no-store'}
    if a.get('response_type') != 'code' or 'openid' not in a.get('scope', '').split():
        return back(error='unsupported_response_type', state=state)
    challenge = a.get('code_challenge', '')
    if not challenge or a.get('code_challenge_method') != 'S256':
        return back(error='invalid_request', error_description='PKCE S256 required', state=state)
    username = _user()
    # make sure Warpgate knows this user and its MOAVI Desk SSO credential before it comes back
    try:
        cfg = wg.config(secret=True)
        wg.ensure_user(cfg, username, wg.ensure_role(cfg))
    except Exception as e:
        logging.warning(f"[VLAB] Warpgate user {username} not prepared for sign-in: {str(e)[:200]}")
    code = wg_oidc.issue_code(username, redirect_uri, a.get('nonce', ''), challenge)
    log_audit(username, 'vlab.warpgate.sso', 'signed in to 보안 게이트웨이 with the portal session', get_client_ip())
    return back(code=code, state=state)


@bp.route('/api/vlab/oidc/token', methods=['POST'])
def oidc_token():
    """Code -> ID token, for Warpgate (client_secret_basic or _post)."""
    if not wg_oidc.is_enabled():
        return _oidc_off()
    auth = request.authorization
    form = request.form
    if auth and auth.type == 'basic':
        from urllib.parse import unquote
        cid, secret = unquote(auth.username or ''), unquote(auth.password or '')
    else:
        cid, secret = form.get('client_id', ''), form.get('client_secret', '')
    if not wg_oidc.check_client(cid, secret):
        return _oauth_error('invalid_client', 401)
    if form.get('grant_type') != 'authorization_code':
        return _oauth_error('unsupported_grant_type')
    out = wg_oidc.redeem_code(form.get('code'), form.get('redirect_uri', ''), form.get('code_verifier', ''))
    if not out:
        return _oauth_error('invalid_grant')
    resp = jsonify(out)
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@bp.route('/api/vlab/oidc/userinfo', methods=['GET', 'POST'])
def oidc_userinfo():
    if not wg_oidc.is_enabled():
        return _oidc_off()
    h = request.headers.get('Authorization', '')
    info = wg_oidc.userinfo(h[7:] if h.startswith('Bearer ') else '')
    if not info:
        return _oauth_error('invalid_token', 401)
    return jsonify(info)
