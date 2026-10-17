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
    cfg = wg.save_config(base_url, ssh_port, rdp_port, vnc_port, verify_tls, enabled,
                         admin_token=token, rdp_nla_user=nla_user, rdp_nla_password=nla_pw)
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
