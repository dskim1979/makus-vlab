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
    provider = data.get('web_rdp_provider')
    if provider is not None and provider not in ('guac', 'warpgate'):
        return _bad('web_rdp_provider must be guac or warpgate')
    cfg = wg.save_config(base_url, ssh_port, rdp_port, vnc_port, verify_tls, enabled,
                         admin_token=token, rdp_nla_user=nla_user, rdp_nla_password=nla_pw,
                         web_rdp_provider=provider)
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
        return _bad('Warpgate가 설정되지 않았습니다', 409)
    return jsonify({'url': wg.recording_url(cfg, request.args.get('session_id'))})


# --- portal ------------------------------------------------------------------------------

@bp.route('/api/vlab/me/warpgate', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_warpgate_status():
    """포털이 Warpgate 연결 버튼을 보일지 판단하는 가벼운 상태(토큰·주소 노출 없음).
    web_rdp_provider: 브라우저 RDP를 누가 서비스하는지(guac 기본 / warpgate 검증 후)."""
    cfg = wg.config()
    return jsonify({'enabled': wg.is_enabled(), 'protocols': list(wg.TARGET_KINDS),
                    'web_rdp_provider': cfg['web_rdp_provider']})


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
        return jsonify({'error': 'Warpgate 게이트웨이가 켜져 있지 않습니다', 'code': 'WG_OFF'}), 409
    data = _body()
    key = str(data.get('openssh_public_key') or '').strip()
    label = str(data.get('label') or '').strip() or 'MOAVI Desk'
    if not wg.is_public_key(key):
        return _bad('openssh_public_key: OpenSSH 공개키 한 줄이어야 합니다(개인키는 받지 않습니다)')
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
        return jsonify({'error': 'Warpgate 게이트웨이가 켜져 있지 않습니다', 'code': 'WG_OFF'}), 409
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
        target = wg.target_name_for(d['id'], d['name'])
        alias = host_alias_prefix + re.sub(r'[^A-Za-z0-9._-]+', '-', d['name']).strip('-').lower()
        e = wg.ssh_config_entry(cfg, alias, username, target)
        e['desktop_id'] = d['id']
        e['desktop_name'] = d['name']
        entries.append(e)
    managed = ''.join(e['config_snippet'] + '\n' for e in entries)
    return jsonify({'enabled': True, 'warpgate_host': wg._host_of(cfg['base_url']), 'ssh_port': cfg['ssh_port'],
                    'login': username, 'entries': entries, 'managed_block': managed.strip()})


# --- portal connect ----------------------------------------------------------------------

def _desktop_target_options(cfg, proto, ip):
    """프로토콜별 Warpgate 대상 옵션. RDP는 interactive_logon=True(자동 로그인 안 함); NLA 서비스
    계정 비번은 설정의 것(사용자 비번 아님). VNC는 None 인증."""
    if proto == 'ssh':
        return wg.ssh_target_options(ip, 22, 'moavi')
    if proto == 'vnc':
        return wg.vnc_target_options(ip, int(cfg['vnc_port']))
    return wg.rdp_target_options(ip, 3389, cfg.get('rdp_nla_user') or 'moavi-nla',
                                 cfg.get('rdp_nla_password') or '', interactive_logon=True)


def browser_rdp_via_warpgate(desk, username, ip):
    """The portal's "브라우저 RDP로 열기" for a pool desktop: Warpgate's web UI when Warpgate is on AND
    web_rdp_provider is 'warpgate'; otherwise None and the caller keeps Guacamole. Any Warpgate failure
    also gives None, so browser RDP falls back to Guacamole rather than going dark.

    Warpgate opens no web session from a ticket for an RDP/SSH target (checked against a live
    Warpgate), so no ticket here: the user, role and target are synced so the desktop is in the
    user's Warpgate list, and the user signs in to Warpgate (SSO/LDAP) and opens it there."""
    if not wg.is_enabled():
        return None
    cfg = wg.config(secret=True)
    if cfg.get('web_rdp_provider') != 'warpgate':
        return None
    try:
        role_id = wg.ensure_role(cfg)
        wg.ensure_user(cfg, username, role_id)
        wg.sync_target(cfg, desk['id'], desk['name'], 'rdp', _desktop_target_options(cfg, 'rdp', ip), role_id)
    except Exception as e:
        logging.warning(f"[VLAB] Warpgate browser RDP for {desk.get('name')} failed, using Guacamole: {str(e)[:200]}")
        return None
    log_audit(username, 'vlab.warpgate.connect', f"browser RDP to '{desk['name']}' via Warpgate (web UI)", get_client_ip())
    return wg.web_ui_url(cfg)


@bp.route('/api/vlab/me/desktops/<desktop_id>/warpgate', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def my_desktop_warpgate(desktop_id):
    """그 사용자+그 대상에만 쓸 수 있는 1회용·단시간 Warpgate 티켓을 발급하고 접속 좌표를 돌려준다.
    사용자 비밀번호는 묻지도 저장하지도 않는다."""
    from pegaprox.api.vlab_next import _guest_ipv4, rdp_listening, rdp_prepare, _guest_os, shared_member

    if not wg.is_enabled():
        return jsonify({'error': 'Warpgate 게이트웨이가 켜져 있지 않습니다', 'code': 'WG_OFF'}), 409
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
        if _guest_os(mgr, node, int(desk['vmid'])) == 'windows' and pol['rdp_tune']:
            rdp_prepare(desk, mgr, node)
        elif _guest_os(mgr, node, int(desk['vmid'])) == 'linux' and not rdp_listening(ip, 3389):
            return jsonify({'error': 'This Linux desktop has no RDP server (xrdp)', 'code': 'NO_RDP'}), 409
    elif proto == 'ssh' and not rdp_listening(ip, 22):
        return jsonify({'error': 'This desktop has no SSH server on port 22', 'code': 'NO_SSH'}), 409
    elif proto == 'vnc' and not rdp_listening(ip, int(wg.config()['vnc_port'])):
        return jsonify({'error': 'This desktop has no VNC server', 'code': 'NO_VNC'}), 409

    cfg = wg.config(secret=True)
    try:
        role_id = wg.ensure_role(cfg)
        wg.ensure_user(cfg, username, role_id)
        options = _desktop_target_options(cfg, proto, ip)
        _uuid, target_name = wg.sync_target(cfg, desk['id'], desk['name'], proto, options, role_id)
        _ticket, secret = wg.issue_ticket(cfg, username, target_name)
    except wg.WarpgateError as e:
        return jsonify({'error': str(e), 'code': 'WG_API'}), 502
    except Exception as e:  # 네트워크/TLS
        return jsonify({'error': str(e)[:200], 'code': 'WG_UNREACHABLE'}), 502
    if not secret:
        return jsonify({'error': 'Warpgate did not return a ticket secret', 'code': 'WG_API'}), 502

    log_audit(username, 'vlab.warpgate.connect', f"{proto.upper()} to '{desk['name']}' via Warpgate", get_client_ip())
    return jsonify({'type': 'warpgate', 'connection': wg.connection_coordinates(cfg, proto, target_name, secret)})
