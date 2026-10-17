# -*- coding: utf-8 -*-
"""
MOAVI Desk - the bundled directory (내장 디렉터리, pegaprox/vlab/directory.py): its state, a
reconcile on demand, the join account, and the domain join of desktops through the QEMU guest
agent.

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

  GET    /api/vlab/admin/bundled-directory                         the DC, the engine's accounts, counts   admin.users
  PUT    /api/vlab/admin/bundled-directory                         {include_admins?, desktop_dns?, set_dns?,
                                                           computer_name?, rdp_group?, migrate_on_login?}  admin.settings
  POST   /api/vlab/admin/bundled-directory/check                   reach the DC as vlab-svc now            admin.users
  POST   /api/vlab/admin/bundled-directory/sync                    reconcile now: accounts and groups      admin.users
  POST   /api/vlab/admin/bundled-directory/join-account/rotate     a new password for vlab-join            admin.settings
  GET    /api/vlab/admin/bundled-directory/accounts                each portal account: local | directory, the last push  admin.users
  GET    /api/vlab/admin/bundled-directory/groups                  the department groups (DN for an "AD group" grant)  vlab.pool.view
  GET    /api/vlab/admin/bundled-directory/joins                   ?pool_id= the join state of each desktop  vlab.pool.view
  POST   /api/vlab/admin/desktops/<id>/domain-join      {restart?} join the domain now          vlab.pool.manage
  POST   /api/vlab/admin/desktops/<id>/domain-join/check   ask the guest whether it is joined       vlab.pool.view
  POST   /api/vlab/admin/pools/<id>/domain-join         {restart?, limit?} every running desktop not joined yet  vlab.pool.manage

A join runs inside the request (the guest agent, up to JOIN_WAIT seconds per desktop): no thread
of its own. Windows: Add-Computer into OU=Desktops with vlab-join (its password on the agent's
stdin), the name computer_name, DNS pointed at the DC first when set_dns; it needs a restart,
which `restart` does 15 seconds later. The template must have been generalized with sysprep -
clones of one installed Windows share its SID and name. Linux: realm join (realmd, sssd, adcli,
oddjob-mkhomedir / pam mkhomedir in the template), short names, moavi-users allowed in.
"""

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import catalog, directory, nas, store

bp = Blueprint('vlab_directory', __name__)

_bad = core._bad
_user = core._user

JOIN_WAIT = 150
POOL_JOIN_LIMIT = 10


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _off():
    if not directory.config()['enabled']:
        return jsonify({'error': 'The bundled directory is off (VLAB_DIRECTORY=1 in the install .env)', 'code': 'NOT_ON'}), 409
    return None


@bp.route('/api/vlab/admin/bundled-directory', methods=['GET'])
@require_auth(perms=['admin.users'])
def get_directory():
    return jsonify({'directory': directory.summary()})


@bp.route('/api/vlab/admin/bundled-directory', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def put_directory():
    try:
        cfg = directory.clean_settings(_body())
    except ValueError as e:
        return _bad(str(e))
    out = directory.save_settings(cfg)
    log_audit(_user(), 'vlab.directory.settings', ', '.join(f'{k}={v}' for k, v in out.items()), get_client_ip())
    return jsonify({'settings': out})


@bp.route('/api/vlab/admin/bundled-directory/check', methods=['POST'])
@require_auth(perms=['admin.users'])
def check_directory():
    return jsonify({'check': directory.check()})


@bp.route('/api/vlab/admin/bundled-directory/sync', methods=['POST'])
@require_auth(perms=['admin.users'])
def sync_directory():
    off = _off()
    if off:
        return off
    if not directory.active():
        return jsonify({'error': 'The site has its own LDAP configured - the bundled directory is not used', 'code': 'OWN_LDAP'}), 409
    try:
        out = directory.reconcile()
    except directory.DirectoryError as e:
        return jsonify({'error': 'The directory cannot be reached', 'code': e.code, 'detail': e.detail}), 503
    log_audit(_user(), 'vlab.directory.sync', ', '.join(f'{k} {v}' for k, v in out.items()), get_client_ip())
    return jsonify({'sync': out})


@bp.route('/api/vlab/admin/bundled-directory/join-account/rotate', methods=['POST'])
@require_auth(perms=['admin.settings'])
def rotate_join_account():
    off = _off()
    if off:
        return off
    try:
        directory.rotate_join()
    except directory.DirectoryError as e:
        return jsonify({'error': 'The directory cannot be reached', 'code': e.code, 'detail': e.detail}), 503
    log_audit(_user(), 'vlab.directory.join_account', f'new password for {directory.JOIN_USER} (sealed, not shown)', get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/bundled-directory/accounts', methods=['GET'])
@require_auth(perms=['admin.users'])
def directory_accounts():
    from pegaprox.utils.auth import load_users
    visible = core._visible_users()
    states = directory.account_states()
    out = []
    for name, row in sorted((load_users() or {}).items()):
        if name not in visible:
            continue
        st = states.get(name) or {}
        if directory.owns(row):
            where = 'directory'
        elif (row.get('auth_source') or 'local') == 'local':
            where = 'waiting' if directory.eligible(name, row) else 'local'
        else:
            where = row.get('auth_source')
        out.append({'username': name, 'where': where, 'ok': st.get('ok'), 'code': st.get('code') or '',
                    'detail': st.get('detail') or '', 'dn': st.get('dn') or row.get('ldap_dn') or '', 'at': st.get('at')})
    return jsonify({'accounts': out})


@bp.route('/api/vlab/admin/bundled-directory/groups', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def directory_groups():
    deps = catalog.list_departments()
    return jsonify({'all': {'name': directory.ALL_GROUP, 'dn': directory.group_dn()},
                    'groups': [{'department_id': d['id'], 'name': d['name'], 'parent_id': d['parent_id'],
                                'cn': directory.group_cn(d['id']), 'dn': directory.group_dn(d['id'])} for d in deps]})


@bp.route('/api/vlab/admin/bundled-directory/joins', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def directory_joins():
    pool_id = request.args.get('pool_id') or None
    j = directory.joins()
    out = []
    for d in store.list_desktops(pool_id):
        r = j.get(d['id']) or {}
        out.append({'desktop_id': d['id'], 'pool_id': d['pool_id'], 'vmid': d['vmid'], 'name': d.get('name') or '',
                    'state': r.get('state') or 'unknown', 'code': r.get('code') or '', 'detail': r.get('detail') or '',
                    'computer': r.get('computer') or '', 'domain': r.get('domain') or '', 'os': r.get('os') or '',
                    'at': r.get('at')})
    return jsonify({'joins': out})


# --- the join through the guest agent ------------------------------------------------------------

def _where(desk):
    """(manager, node, None) or (None, None, (code, detail))."""
    if desk.get('vm_type') != 'qemu':
        return None, None, ('UNSUPPORTED', 'a container is not joined to a domain')
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return None, None, ('NO_CLUSTER', 'the cluster is not connected')
    live = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
    if live.get('status') != 'running':
        return None, None, ('NOT_RUNNING', 'the desktop is not running')
    return mgr, live.get('node') or desk['node'], None


def join_desktop(desk, restart=False, check_only=False):
    """Join (or only ask) one desktop. Returns the stored join row."""
    from pegaprox.api import vlab_next as nx
    mgr, node, why = _where(desk)
    if why:
        prev = directory.join_of(desk['id']) or {}
        state = prev.get('state') if why[0] == 'NOT_RUNNING' and prev.get('state') else 'failed'
        return directory.record_join(desk['id'], state, why[0], why[1], prev.get('computer', ''), prev.get('domain', ''), prev.get('os', ''))
    os_kind = nx._guest_os(mgr, node, desk['vmid'])
    if not os_kind:
        return directory.record_join(desk['id'], 'failed', 'NO_AGENT',
                                     'the QEMU guest agent does not answer (qemu-guest-agent installed, agent: 1 on the VM?)')
    secret = None
    name = directory.computer_name(desk['vmid'])
    if check_only:
        script = directory.status_script(os_kind)
    else:
        try:
            secret = directory.join_password()
        except directory.DirectoryError as e:
            return directory.record_join(desk['id'], 'failed', e.code, e.detail, os_kind=os_kind)
        script = directory.windows_join_script(name, restart) if os_kind == 'windows' else directory.linux_join_script(name)
    if os_kind == 'windows':
        command = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script]
    else:
        command = ['/bin/sh', '-c', script]
    code, out, err, e = nx._agent_run(mgr, node, desk['vmid'], command, stdin=secret, wait=JOIN_WAIT)
    secret = None
    if code is None:
        if e:
            return directory.record_join(desk['id'], 'failed', 'AGENT_ERROR', e, os_kind=os_kind)
        return directory.record_join(desk['id'], 'pending', 'PENDING', 'still running on the guest', os_kind=os_kind)
    got = nas.parse_output(out)
    computer, domain = got.get('computer', ''), got.get('domain', '')
    if code != 0:
        label = directory.JOIN_CODES.get(code, 'FAILED')
        detail = (err or '').strip()[-400:] or f'exit {code}'
        if label == 'OTHER_DOMAIN':
            detail = f'the guest is in another domain: {domain}'
        return directory.record_join(desk['id'], 'other' if label == 'OTHER_DOMAIN' else 'failed', label, detail,
                                     computer, domain, os_kind)
    if got.get('joined') != '1':
        return directory.record_join(desk['id'], 'not_joined', 'NOT_JOINED', 'the guest is in no domain', computer, '', os_kind)
    if domain and domain.lower() != directory.config()['realm']:
        return directory.record_join(desk['id'], 'other', 'OTHER_DOMAIN', f'the guest is in another domain: {domain}',
                                     computer, domain, os_kind)
    if got.get('reboot') == '1':
        code_txt = 'RESTARTING' if got.get('restarting') == '1' else 'RESTART_NEEDED'
        note = 'joined; Windows applies it after a restart' + ('' if got.get('rdp_group') != '0' else
                                                                '; moavi-users not added to Remote Desktop Users yet')
        return directory.record_join(desk['id'], 'joined', code_txt, note, computer, domain or directory.config()['realm'], os_kind)
    return directory.record_join(desk['id'], 'joined', 'OK', '' if got.get('rdp_group') != '0' else 'moavi-users not permitted',
                                 computer, domain or directory.config()['realm'], os_kind)


@bp.route('/api/vlab/admin/desktops/<desktop_id>/domain-join', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def join_one(desktop_id):
    off = _off()
    if off:
        return off
    desk = store.get_desktop(desktop_id)
    if not desk:
        return _bad('Desktop not found', 404)
    restart = _body().get('restart') is True
    row = join_desktop(desk, restart=restart)
    log_audit(_user(), 'vlab.directory.join', f"{desk['vm_type']}/{desk['vmid']}: {row['state']} {row['code']}"
              + (' (restart)' if restart else ''), get_client_ip())
    return jsonify({'join': row})


@bp.route('/api/vlab/admin/desktops/<desktop_id>/domain-join/check', methods=['POST'])
@require_auth(perms=['vlab.pool.view'])
def check_one(desktop_id):
    off = _off()
    if off:
        return off
    desk = store.get_desktop(desktop_id)
    if not desk:
        return _bad('Desktop not found', 404)
    return jsonify({'join': join_desktop(desk, check_only=True)})


@bp.route('/api/vlab/admin/pools/<pool_id>/domain-join', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def join_pool(pool_id):
    """The pool's running desktops that are not joined yet, up to `limit` (default 10, at most
    20) in this request; `remaining` says how many are left for the next call."""
    off = _off()
    if off:
        return off
    if not store.get_pool(pool_id):
        return _bad('Pool not found', 404)
    data = _body()
    restart = data.get('restart') is True
    try:
        limit = max(1, min(20, int(data.get('limit') or POOL_JOIN_LIMIT)))
    except (TypeError, ValueError):
        return _bad('limit must be a number')
    j = directory.joins()
    todo = [d for d in store.list_desktops(pool_id) if (j.get(d['id']) or {}).get('state') != 'joined']
    done = []
    for d in todo[:limit]:
        done.append(join_desktop(d, restart=restart))
    joined = sum(1 for r in done if r['state'] == 'joined')
    log_audit(_user(), 'vlab.directory.join', f"pool {pool_id}: {joined} of {len(done)} joined"
              + (' (restart)' if restart else ''), get_client_ip())
    return jsonify({'joins': done, 'joined': joined, 'remaining': max(0, len(todo) - len(done))})
