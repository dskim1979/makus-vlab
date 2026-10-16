# -*- coding: utf-8 -*-
"""
MOAVI Desk - the next-phase screens of the console (docs/vlab-design.md 4-2, 7-3, 10-2..10-4).

Copyright (C) 2025-2026 PegaProx Team / MAKUS SYSTEMS - AGPL-3.0 (see LICENSE, NOTICE).

  GET    /api/vlab/admin/departments                     the department tree, member counts   vlab.pool.view
  POST   /api/vlab/admin/departments                     {name, parent_id?, sort?}            admin.users
  PUT    /api/vlab/admin/departments/<id>                rename / move                        admin.users
  DELETE /api/vlab/admin/departments/<id>                one without sub-departments          admin.users
  GET    /api/vlab/admin/departments/<id>/members        ?children=1 includes sub-departments  vlab.pool.view
  PUT    /api/vlab/admin/users/<username>/department     {department_id|null}                 admin.users

  GET    /api/vlab/signup/config                         is sign-up open, the departments     public
  POST   /api/vlab/signup                                {username, password, display_name?, email?, department_id?, note?}  public
  GET    /api/vlab/admin/signups                         ?status=pending|approved|rejected     admin.users
  POST   /api/vlab/admin/signups/<id>/approve            makes the account (role user, portal only)  admin.users
  POST   /api/vlab/admin/signups/<id>/reject             {reason?}                            admin.users
  GET/PUT /api/vlab/admin/signup-settings                {enabled}                            admin.settings

  GET/POST /api/vlab/admin/usb-devices, PUT/DELETE .../<id>   the USB device library       vlab.pool.view / manage
  GET/POST /api/vlab/admin/gateways, PUT/DELETE .../<id>, POST .../<id>/check   gateways    vlab.pool.view / manage
  GET/POST /api/vlab/admin/external-desktops, PUT/DELETE .../<id>   physical PCs over RDP   vlab.pool.view / manage
  GET    /api/vlab/me/external                           the caller's external desktops       vlab.desk
  GET    /api/vlab/me/external/<id>/rdp                  an .rdp file for it                  vlab.desk

  GET    /api/vlab/admin/golden-images                   with their versions (snapshots)      vlab.pool.view
  POST   /api/vlab/admin/golden-images                   {cluster_id, vmid, name?, notes?}    vlab.pool.manage
  DELETE /api/vlab/admin/golden-images/<id>              stop treating the VM as one (VM kept) vlab.pool.manage
  POST   /api/vlab/admin/golden-images/<id>/versions     {description?} a new version = snapshot gold-<time>  vlab.pool.manage
  PUT    /api/vlab/admin/golden-images/<id>/current      {version}                            vlab.pool.manage
  POST   /api/vlab/admin/golden-images/<id>/deploy       {pool_id, count, name_prefix, start_vmid?} full clones of the current version  vlab.pool.manage

  GET/POST /api/vlab/admin/boards, PUT/DELETE .../<id>   the board lab (JTAG cables)          vlab.pool.view / vlab.accel.manage
  POST   /api/vlab/admin/boards/<id>/attach              {desktop_id} USB passthrough, slot usb4  vlab.accel.manage
  POST   /api/vlab/admin/boards/<id>/detach                                                    vlab.accel.manage

  GET    /api/vlab/admin/buildfarm                       build farm pools: size, in use, load  vlab.pool.view

  GET/POST /api/vlab/admin/license-servers, PUT/DELETE .../<id>, POST .../<id>/check   licence servers  vlab.pool.view / vlab.accel.manage
"""

import re
import socket
import time
from datetime import datetime

from flask import Blueprint, jsonify, request

from pegaprox.api import vlab as core
from pegaprox.globals import cluster_managers
from pegaprox.utils.audit import get_client_ip, log_audit
from pegaprox.utils.auth import require_auth
from pegaprox.vlab import catalog, store

bp = Blueprint('vlab_next', __name__)

_bad = core._bad
_user = core._user


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _text(data, key, limit, required=False):
    v = str(data.get(key) or '').strip()
    if required and not v:
        raise ValueError(f'{key} is required')
    if len(v) > limit:
        raise ValueError(f'{key}: at most {limit} characters')
    return v


def _int(data, key, lo, hi, default=None):
    v = data.get(key, default)
    if v in (None, ''):
        if default is None:
            raise ValueError(f'{key} is required')
        v = default
    try:
        v = int(v)
    except (TypeError, ValueError):
        raise ValueError(f'{key} must be a number')
    if not lo <= v <= hi:
        raise ValueError(f'{key} must be {lo} to {hi}')
    return v


_HOST = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$|^\[?[0-9A-Fa-f:]+\]?$')


def _host(data, key):
    v = _text(data, key, 253, required=True)
    if not _HOST.match(v):
        raise ValueError(f'{key} must be a host name or an IP address')
    return v.strip('[]')


def _tcp_probe(host, port, timeout=2.0):
    """Is something listening on host:port? Returns (ok, milliseconds, error)."""
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, int((time.monotonic() - t0) * 1000), ''
    except OSError as e:
        return False, int((time.monotonic() - t0) * 1000), (e.strerror or e.__class__.__name__)[:120]


# --- departments -------------------------------------------------------------------------

@bp.route('/api/vlab/admin/departments', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_departments():
    return jsonify({'departments': catalog.list_departments()})


def _department_body(dep_id=None):
    data = _body()
    name = _text(data, 'name', 80, required=True)
    parent = str(data.get('parent_id') or '').strip() or None
    if parent:
        if not catalog.get_department(parent):
            raise ValueError('parent_id: no such department')
        if dep_id and parent in catalog.descendants(dep_id):
            raise ValueError('A department cannot move under itself')
    return name, parent, _int(data, 'sort', 0, 10000, 0)


@bp.route('/api/vlab/admin/departments', methods=['POST'])
@require_auth(perms=['admin.users'])
def create_department():
    try:
        name, parent, sort = _department_body()
    except ValueError as e:
        return _bad(str(e))
    dep = catalog.save_department(None, name, parent, sort)
    log_audit(_user(), 'vlab.department.create', f"department '{name}'", get_client_ip())
    return jsonify({'department': dep}), 201


@bp.route('/api/vlab/admin/departments/<dep_id>', methods=['PUT'])
@require_auth(perms=['admin.users'])
def update_department(dep_id):
    if not catalog.get_department(dep_id):
        return _bad('Department not found', 404)
    try:
        name, parent, sort = _department_body(dep_id)
    except ValueError as e:
        return _bad(str(e))
    dep = catalog.save_department(dep_id, name, parent, sort)
    log_audit(_user(), 'vlab.department.update', f"department '{name}'", get_client_ip())
    return jsonify({'department': dep})


@bp.route('/api/vlab/admin/departments/<dep_id>', methods=['DELETE'])
@require_auth(perms=['admin.users'])
def delete_department(dep_id):
    dep = catalog.get_department(dep_id)
    if not dep:
        return _bad('Department not found', 404)
    if len(catalog.descendants(dep_id)) > 1:
        return _bad('Move or delete its sub-departments first', 409)
    catalog.delete_department(dep_id)
    log_audit(_user(), 'vlab.department.delete', f"department '{dep['name']}' (its members now belong to none)", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/departments/<dep_id>/members', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def department_members(dep_id):
    if not catalog.get_department(dep_id):
        return _bad('Department not found', 404)
    ids = catalog.descendants(dep_id) if request.args.get('children') in ('1', 'true') else {dep_id}
    return jsonify({'members': catalog.members(ids)})


@bp.route('/api/vlab/admin/users/<username>/department', methods=['PUT'])
@require_auth(perms=['admin.users'])
def set_user_department(username):
    from pegaprox.utils.auth import load_users
    if username not in load_users():
        return _bad('User not found', 404)
    dep = str(_body().get('department_id') or '').strip() or None
    if dep and not catalog.get_department(dep):
        return _bad('department_id: no such department')
    catalog.set_department(username, dep)
    log_audit(_user(), 'vlab.department.member', f"{username} -> {dep or '(none)'}", get_client_ip())
    return jsonify({'username': username, 'department_id': dep})


# --- sign-up requests --------------------------------------------------------------------

_SIGNUP_KEY = 'vlab_signup'
_USERNAME = re.compile(r'^[a-z0-9][a-z0-9._-]{2,31}$')
MAX_PENDING = 200
MAX_PENDING_PER_IP = 5


def _signup_settings():
    from pegaprox.api.helpers import load_server_settings
    saved = (load_server_settings() or {}).get(_SIGNUP_KEY) or {}
    return {'enabled': bool(saved.get('enabled', False))}


@bp.route('/api/vlab/signup/config', methods=['GET'])
def signup_config():
    """For the sign-in screen: whether to offer 가입 신청, and the departments to pick."""
    s = _signup_settings()
    deps = [{'id': d['id'], 'name': d['name'], 'parent_id': d['parent_id']} for d in catalog.list_departments()] if s['enabled'] else []
    return jsonify({'enabled': s['enabled'], 'departments': deps})


@bp.route('/api/vlab/signup', methods=['POST'])
def signup():
    """Ask for an account. An admin approves it under 사용자 > 가입 심사; approving gives no
    desktop by itself (pool rights are separate)."""
    from pegaprox.utils.auth import hash_password, load_users, validate_password_policy
    if not _signup_settings()['enabled']:
        return _bad('Sign-up is closed on this server', 403)
    data = _body()
    username = str(data.get('username') or '').strip().lower()
    if not _USERNAME.match(username):
        return _bad('username: 3-32 lower-case letters, digits, ".", "_" or "-", starting with a letter or digit')
    password = str(data.get('password') or '')
    ok, why = validate_password_policy(password)
    if not ok:
        return _bad(why)
    try:
        display = _text(data, 'display_name', 80) or username
        email = _text(data, 'email', 120)
        note = _text(data, 'note', 300)
    except ValueError as e:
        return _bad(str(e))
    if email and not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return _bad('email is not valid')
    dep = str(data.get('department_id') or '').strip() or None
    if dep and not catalog.get_department(dep):
        return _bad('department_id: no such department')
    if username in load_users() or catalog.pending_signup_for(username):
        return _bad('This username is taken or already waiting for review', 409)
    ip = get_client_ip() or ''
    if catalog.count_pending() >= MAX_PENDING:
        return _bad('Too many requests are waiting - try again later', 429)
    if ip and sum(1 for s in catalog.list_signups('pending') if s['client_ip'] == ip) >= MAX_PENDING_PER_IP:
        return _bad('Too many requests from this address are waiting', 429)
    salt, pw_hash = hash_password(password)
    req = catalog.add_signup(username, display, email, dep, note, salt, pw_hash, ip)
    log_audit(username, 'vlab.signup.request', f"sign-up request {req['id']}", ip)
    return jsonify({'request': {'id': req['id'], 'status': req['status']}}), 201


@bp.route('/api/vlab/admin/signups', methods=['GET'])
@require_auth(perms=['admin.users'])
def list_signups():
    status = request.args.get('status') or None
    if status and status not in ('pending', 'approved', 'rejected'):
        return _bad('status must be pending, approved or rejected')
    return jsonify({'signups': catalog.list_signups(status), 'pending': catalog.count_pending()})


@bp.route('/api/vlab/admin/signups/<sid>/approve', methods=['POST'])
@require_auth(perms=['admin.users'])
def approve_signup(sid):
    from pegaprox.core.db import DEFAULT_TENANT_ID
    from pegaprox.models.permissions import ROLE_USER
    from pegaprox.utils.auth import load_users, save_users
    req = catalog.get_signup(sid, with_secret=True)
    if not req:
        return _bad('Request not found', 404)
    if req['status'] != 'pending':
        return _bad(f"This request is already {req['status']}", 409)
    users = load_users()
    if req['username'] in users:
        catalog.review_signup(sid, 'rejected', _user(), 'username taken meanwhile')
        return _bad('The username was taken meanwhile - the request is rejected', 409)
    stamp = datetime.now().isoformat()
    users[req['username']] = {
        'password_salt': req['password_salt'], 'password_hash': req['password_hash'], 'password_changed_at': stamp,
        'role': ROLE_USER, 'display_name': req['display_name'] or req['username'], 'email': req['email'], 'enabled': True,
        'created_at': stamp, 'last_login': None, 'tenant_id': DEFAULT_TENANT_ID, 'permissions': [], 'denied_permissions': [],
        'portal_only': True,
    }
    save_users(users)
    if req['department_id'] and catalog.get_department(req['department_id']):
        catalog.set_department(req['username'], req['department_id'])
    out = catalog.review_signup(sid, 'approved', _user())
    log_audit(_user(), 'user.created', f"Approved sign-up of {req['username']} (role: user, portal only)", get_client_ip())
    return jsonify({'signup': out})


@bp.route('/api/vlab/admin/signups/<sid>/reject', methods=['POST'])
@require_auth(perms=['admin.users'])
def reject_signup(sid):
    req = catalog.get_signup(sid)
    if not req:
        return _bad('Request not found', 404)
    if req['status'] != 'pending':
        return _bad(f"This request is already {req['status']}", 409)
    try:
        reason = _text(_body(), 'reason', 200)
    except ValueError as e:
        return _bad(str(e))
    out = catalog.review_signup(sid, 'rejected', _user(), reason)
    log_audit(_user(), 'vlab.signup.reject', f"sign-up of {req['username']} rejected" + (f': {reason}' if reason else ''), get_client_ip())
    return jsonify({'signup': out})


@bp.route('/api/vlab/admin/signup-settings', methods=['GET'])
@require_auth(perms=['admin.settings'])
def get_signup_settings():
    return jsonify({'signup': _signup_settings()})


@bp.route('/api/vlab/admin/signup-settings', methods=['PUT'])
@require_auth(perms=['admin.settings'])
def put_signup_settings():
    from pegaprox.api.helpers import load_server_settings, save_server_settings
    data = _body()
    if not isinstance(data.get('enabled'), bool):
        return _bad('enabled must be true or false')
    settings = load_server_settings() or {}
    settings[_SIGNUP_KEY] = {'enabled': data['enabled']}
    if not save_server_settings(settings):
        return _bad('Could not save the settings', 500)
    log_audit(_user(), 'vlab.signup.settings', f"sign-up {'open' if data['enabled'] else 'closed'}", get_client_ip())
    return jsonify({'signup': _signup_settings()})


# --- USB device library ------------------------------------------------------------------

def _usb_body():
    data = _body()
    name = _text(data, 'name', 80, required=True)
    vid = str(data.get('vid') or '').strip().lower()
    pid = str(data.get('pid') or '').strip().lower()
    if not catalog.HEX4.match(vid):
        raise ValueError('vid must be 4 hex digits')
    if pid and not catalog.HEX4.match(pid):
        raise ValueError('pid must be 4 hex digits, or empty for every device of the vendor')
    cat = str(data.get('category') or 'other')
    if cat not in catalog.USB_CATEGORIES:
        raise ValueError('category must be one of ' + ', '.join(catalog.USB_CATEGORIES))
    return name, vid, pid, cat, _text(data, 'notes', 300)


def _usb_refs():
    """How many pools name each library entry in their USB policy (settings.usb.devices)."""
    refs = {}
    for p in store.list_pools():
        for uid in ((p.get('settings') or {}).get('usb') or {}).get('devices') or []:
            refs[uid] = refs.get(uid, 0) + 1
    return refs


@bp.route('/api/vlab/admin/usb-devices', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_usb_devices():
    refs = _usb_refs()
    return jsonify({'devices': [dict(d, pools=refs.get(d['id'], 0)) for d in catalog.list_usb_devices()],
                    'categories': list(catalog.USB_CATEGORIES)})


@bp.route('/api/vlab/admin/usb-devices', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_usb_device():
    try:
        name, vid, pid, cat, notes = _usb_body()
    except ValueError as e:
        return _bad(str(e))
    if catalog.usb_device_by_ids(vid, pid):
        return _bad(f'{vid}:{pid or "*"} is already in the library', 409)
    dev = catalog.save_usb_device(None, name, vid, pid, cat, notes)
    log_audit(_user(), 'vlab.usb.create', f"USB {vid}:{pid or '*'} '{name}'", get_client_ip())
    return jsonify({'device': dev}), 201


@bp.route('/api/vlab/admin/usb-devices/<uid>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def update_usb_device(uid):
    if not catalog.get_usb_device(uid):
        return _bad('Device not found', 404)
    try:
        name, vid, pid, cat, notes = _usb_body()
    except ValueError as e:
        return _bad(str(e))
    other = catalog.usb_device_by_ids(vid, pid)
    if other and other['id'] != uid:
        return _bad(f'{vid}:{pid or "*"} is already in the library', 409)
    dev = catalog.save_usb_device(uid, name, vid, pid, cat, notes)
    log_audit(_user(), 'vlab.usb.update', f"USB {vid}:{pid or '*'} '{name}'", get_client_ip())
    return jsonify({'device': dev})


@bp.route('/api/vlab/admin/usb-devices/<uid>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_usb_device(uid):
    dev = catalog.get_usb_device(uid)
    if not dev:
        return _bad('Device not found', 404)
    if _usb_refs().get(uid):
        return _bad('Pools still use this device in their USB policy', 409)
    catalog.delete_usb_device(uid)
    log_audit(_user(), 'vlab.usb.delete', f"USB {dev['vid']}:{dev['pid'] or '*'} '{dev['name']}'", get_client_ip())
    return jsonify({'success': True})


# --- gateways ----------------------------------------------------------------------------

def _gateway_body():
    data = _body()
    kind = str(data.get('kind') or '')
    if kind not in catalog.GATEWAY_KINDS:
        raise ValueError('kind must be ' + ', '.join(catalog.GATEWAY_KINDS))
    return (_text(data, 'name', 80, required=True), kind, _host(data, 'address'),
            _int(data, 'port', 1, 65535, catalog.GATEWAY_KINDS[kind]), _text(data, 'notes', 300), data.get('enabled', True) is not False)


@bp.route('/api/vlab/admin/gateways', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_gateways():
    used = {}
    for e in catalog.list_external():
        if e['gateway_id']:
            used[e['gateway_id']] = used.get(e['gateway_id'], 0) + 1
    return jsonify({'gateways': [dict(g, external=used.get(g['id'], 0)) for g in catalog.list_gateways()],
                    'kinds': catalog.GATEWAY_KINDS})


@bp.route('/api/vlab/admin/gateways', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_gateway():
    try:
        args = _gateway_body()
    except ValueError as e:
        return _bad(str(e))
    gw = catalog.save_gateway(None, *args)
    log_audit(_user(), 'vlab.gateway.create', f"gateway '{gw['name']}' {gw['kind']} {gw['address']}:{gw['port']}", get_client_ip())
    return jsonify({'gateway': gw}), 201


@bp.route('/api/vlab/admin/gateways/<gid>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def update_gateway(gid):
    if not catalog.get_gateway(gid):
        return _bad('Gateway not found', 404)
    try:
        args = _gateway_body()
    except ValueError as e:
        return _bad(str(e))
    gw = catalog.save_gateway(gid, *args)
    log_audit(_user(), 'vlab.gateway.update', f"gateway '{gw['name']}'", get_client_ip())
    return jsonify({'gateway': gw})


@bp.route('/api/vlab/admin/gateways/<gid>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_gateway(gid):
    gw = catalog.get_gateway(gid)
    if not gw:
        return _bad('Gateway not found', 404)
    catalog.delete_gateway(gid)
    log_audit(_user(), 'vlab.gateway.delete', f"gateway '{gw['name']}' (external desktops on it go direct)", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/gateways/<gid>/check', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def check_gateway(gid):
    gw = catalog.get_gateway(gid)
    if not gw:
        return _bad('Gateway not found', 404)
    ok, ms, err = _tcp_probe(gw['address'], gw['port'])
    gw = catalog.mark_gateway(gid, ok, f'{ms} ms' if ok else err)
    return jsonify({'gateway': gw, 'ok': ok, 'ms': ms, 'error': err})


# --- external desktops -------------------------------------------------------------------

def _external_body():
    from pegaprox.utils.auth import load_users
    data = _body()
    user = str(data.get('assigned_user') or '').strip() or None
    if user and user not in load_users():
        raise ValueError('assigned_user: no such user')
    gw = str(data.get('gateway_id') or '').strip() or None
    if gw and not catalog.get_gateway(gw):
        raise ValueError('gateway_id: no such gateway')
    return (_text(data, 'name', 80, required=True), _host(data, 'address'), _int(data, 'port', 1, 65535, 3389),
            user, gw, _text(data, 'notes', 300))


@bp.route('/api/vlab/admin/external-desktops', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_external():
    return jsonify({'desktops': catalog.list_external()})


@bp.route('/api/vlab/admin/external-desktops', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_external():
    try:
        args = _external_body()
    except ValueError as e:
        return _bad(str(e))
    ext = catalog.save_external(None, *args)
    log_audit(_user(), 'vlab.external.create', f"external desktop '{ext['name']}' {ext['address']}:{ext['port']} -> {ext['assigned_user'] or '-'}", get_client_ip())
    return jsonify({'desktop': ext}), 201


@bp.route('/api/vlab/admin/external-desktops/<eid>', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def update_external(eid):
    if not catalog.get_external(eid):
        return _bad('External desktop not found', 404)
    try:
        args = _external_body()
    except ValueError as e:
        return _bad(str(e))
    ext = catalog.save_external(eid, *args)
    log_audit(_user(), 'vlab.external.update', f"external desktop '{ext['name']}' -> {ext['assigned_user'] or '-'}", get_client_ip())
    return jsonify({'desktop': ext})


@bp.route('/api/vlab/admin/external-desktops/<eid>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_external(eid):
    ext = catalog.get_external(eid)
    if not ext:
        return _bad('External desktop not found', 404)
    catalog.delete_external(eid)
    log_audit(_user(), 'vlab.external.delete', f"external desktop '{ext['name']}'", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/me/external', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_external():
    return jsonify({'desktops': [{k: e[k] for k in ('id', 'name', 'address', 'port', 'notes')} for e in catalog.list_external(_user())]})


def rdp_file(ext, username):
    lines = [f"full address:s:{ext['address']}:{ext['port']}", f'username:s:{username}', 'prompt for credentials:i:1',
             'screen mode id:i:2', 'use multimon:i:1', 'redirectclipboard:i:1', 'audiomode:i:0', 'authentication level:i:2']
    gw = catalog.get_gateway(ext['gateway_id']) if ext.get('gateway_id') else None
    if gw and gw['enabled'] and gw['kind'] in ('rdpgw', 'msrdgw'):
        lines += [f"gatewayhostname:s:{gw['address']}:{gw['port']}", 'gatewayusagemethod:i:1', 'gatewaycredentialssource:i:4',
                  'gatewayprofileusagemethod:i:1']
    return '\r\n'.join(lines) + '\r\n'


@bp.route('/api/vlab/me/external/<eid>/rdp', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_external_rdp(eid):
    ext = catalog.get_external(eid)
    if not ext or ext['assigned_user'] != _user():
        return _bad('External desktop not found', 404)
    log_audit(_user(), 'vlab.external.connect', f"RDP file for '{ext['name']}'", get_client_ip())
    safe = re.sub(r'[^A-Za-z0-9._-]+', '-', ext['name']).strip('-') or 'desktop'
    return jsonify({'filename': f'{safe}.rdp', 'rdp': rdp_file(ext, _user())})


# --- golden images -----------------------------------------------------------------------

GOLD_PREFIX = 'gold-'


def _versions(img):
    mgr = cluster_managers.get(img['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return None
    try:
        snaps = mgr.get_snapshots(img['node'], int(img['vmid']), img['vm_type']) or []
    except Exception:
        return None
    out = [{'name': s.get('name'), 'description': s.get('description') or '', 'time': s.get('snaptime')}
           for s in snaps if isinstance(s, dict) and str(s.get('name') or '').startswith(GOLD_PREFIX)]
    return sorted(out, key=lambda v: v['time'] or 0, reverse=True)


def _golden_or_error(gid):
    img = catalog.get_golden(gid)
    if not img or not core._can_reach(img['cluster_id']):
        return None, _bad('Golden image not found', 404)
    return img, None


@bp.route('/api/vlab/admin/golden-images', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_golden():
    used = {}
    for p in store.list_pools():
        gid = (p.get('settings') or {}).get('golden_id')
        if gid:
            used.setdefault(gid, []).append(p['name'])
    out = []
    for img in catalog.list_golden():
        if not core._can_reach(img['cluster_id']):
            continue
        live = core._vm_states(img['cluster_id']).get(int(img['vmid'])) or {}
        out.append(dict(img, versions=_versions(img), status=live.get('status') or 'unknown', pools=used.get(img['id'], [])))
    return jsonify({'images': out})


@bp.route('/api/vlab/admin/golden-images', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def create_golden():
    data = _body()
    cluster_id = str(data.get('cluster_id') or '')
    if not core._can_reach(cluster_id):
        return _bad('Cluster not found', 404)
    try:
        vmid = _int(data, 'vmid', 100, 999999999)
        name = _text(data, 'name', 80)
        notes = _text(data, 'notes', 300)
    except ValueError as e:
        return _bad(str(e))
    vm = core._vm_states(cluster_id).get(vmid)
    if not vm:
        return _bad(f'Guest {vmid} not found on this cluster', 404)
    if vm.get('template'):
        return _bad('This guest is a template: use it from 템플릿 관리. A golden image is a normal VM you keep editing', 409)
    if (vm.get('type') or 'qemu') != 'qemu':
        return _bad('Golden images are virtual machines (QEMU) only')
    if catalog.golden_for_vm(cluster_id, vmid):
        return _bad('This VM is already a golden image', 409)
    if store.desktop_for_vm(cluster_id, vmid):
        return _bad('This VM is a desktop of a pool - take it out of the pool first', 409)
    img = catalog.add_golden(cluster_id, vm.get('node') or '', vmid, 'qemu', name or vm.get('name') or f'vm-{vmid}', notes, _user())
    log_audit(_user(), 'vlab.golden.create', f"golden image '{img['name']}' (qemu/{vmid})", get_client_ip())
    return jsonify({'image': img}), 201


@bp.route('/api/vlab/admin/golden-images/<gid>', methods=['DELETE'])
@require_auth(perms=['vlab.pool.manage'])
def delete_golden(gid):
    img, err = _golden_or_error(gid)
    if err:
        return err
    catalog.delete_golden(gid)
    log_audit(_user(), 'vlab.golden.delete', f"golden image '{img['name']}' (the VM and its snapshots are kept)", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/golden-images/<gid>/versions', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def make_golden_version(gid):
    img, err = _golden_or_error(gid)
    if err:
        return err
    try:
        desc = _text(_body(), 'description', 200)
    except ValueError as e:
        return _bad(str(e))
    mgr = cluster_managers.get(img['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    live = core._vm_states(img['cluster_id']).get(int(img['vmid'])) or {}
    node = live.get('node') or img['node']
    snap = GOLD_PREFIX + datetime.now().strftime('%Y%m%d-%H%M%S')
    r = mgr.create_snapshot(node, int(img['vmid']), img['vm_type'], snap, desc or 'MOAVI Desk golden image version')
    if not isinstance(r, dict) or not r.get('success'):
        return _bad(f"Snapshot failed: {str((r or {}).get('error') if isinstance(r, dict) else r)[:200]}", 502)
    img = catalog.set_golden(gid, current_version=snap, node=node)
    log_audit(_user(), 'vlab.golden.version', f"golden image '{img['name']}': new version {snap}", get_client_ip())
    return jsonify({'image': img, 'version': snap}), 201


@bp.route('/api/vlab/admin/golden-images/<gid>/current', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def set_golden_current(gid):
    img, err = _golden_or_error(gid)
    if err:
        return err
    version = str(_body().get('version') or '')
    versions = _versions(img)
    if versions is None:
        return _bad('Cluster not connected', 503)
    if version not in {v['name'] for v in versions}:
        return _bad('No such version of this image', 404)
    img = catalog.set_golden(gid, current_version=version)
    log_audit(_user(), 'vlab.golden.current', f"golden image '{img['name']}': deploys {version}", get_client_ip())
    return jsonify({'image': img})


@bp.route('/api/vlab/admin/golden-images/<gid>/deploy', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def deploy_golden(gid):
    """Full clones of the image's current version into a pool (a golden image is a normal VM,
    so its clones cannot be linked). New desktops start 'provisioning', as template clones do."""
    from pegaprox.api.helpers import acting_user
    from pegaprox.utils.rbac import TenantRangeUnknown, tenant_vmid_range
    img, err = _golden_or_error(gid)
    if err:
        return err
    if not img['current_version']:
        return _bad('Make a version of the image first', 409)
    data = _body()
    pool, err = core._pool_or_error(str(data.get('pool_id') or ''))
    if err:
        return err
    if pool['cluster_id'] != img['cluster_id']:
        return _bad('The pool is on another cluster than the image', 409)
    try:
        count = _int(data, 'count', 1, core.MAX_CLONES, 1)
        start_vmid = _int(data, 'start_vmid', 0, 999999999, 0)
    except ValueError as e:
        return _bad(str(e))
    prefix = str(data.get('name_prefix') or '').strip()
    if not core._NAME_OK.match(prefix):
        return _bad('name_prefix: letters, digits and "-", starting with a letter or digit (DNS name rules)')
    mgr = cluster_managers.get(pool['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    live = core._vm_states(pool['cluster_id'])
    node = (live.get(int(img['vmid'])) or {}).get('node') or img['node']
    try:
        tenant_range = tenant_vmid_range((acting_user() or {}).get('tenant_id') or 'default')
    except TenantRangeUnknown:
        return _bad('Tenant settings unavailable - nothing created', 503)
    if not start_vmid and not tenant_range[0]:
        nxt = mgr.get_next_vmid()
        if isinstance(nxt, dict) and nxt.get('success'):
            start_vmid = int(nxt.get('vmid') or 0)
    vmids = core._free_vmids(pool['cluster_id'], count, start_vmid, tenant_range, live)
    if len(vmids) < count:
        return _bad(f'Only {len(vmids)} free VMIDs in range for {count} desktops', 409)
    taken = {d['name'] for d in store.list_desktops(pool['id'])}
    names, n = [], 1
    while len(names) < count:
        cand = f'{prefix}-{n:02d}'
        if cand not in taken:
            names.append(cand)
        n += 1
    created, failure = [], None
    for vmid, name in zip(vmids, names):
        r = mgr.clone_vm(node, int(img['vmid']), 'qemu', vmid, name=name, full=True, snapname=img['current_version'],
                         description=f"MOAVI Desk pool '{pool['name']}' from golden image '{img['name']}' {img['current_version']}")
        if not isinstance(r, dict) or not r.get('success'):
            failure = {'vmid': vmid, 'name': name, 'error': str((r or {}).get('error') if isinstance(r, dict) else r)[:300]}
            break
        desk = store.add_desktop(pool, node, vmid, name, 'qemu', state='provisioning')
        created.append({'id': desk['id'], 'vmid': vmid, 'name': name, 'task': r.get('data')})
    if created and (pool.get('settings') or {}).get('golden_id') != gid:
        store.set_pool_settings(pool['id'], dict(pool.get('settings') or {}, golden_id=gid))
    log_audit(_user(), 'vlab.golden.deploy', f"{len(created)}/{count} from golden image '{img['name']}' {img['current_version']} into pool '{pool['name']}'"
              + (f" - stopped at {failure['vmid']}: {failure['error'][:120]}" if failure else ''), get_client_ip())
    return jsonify({'created': created, 'failed': failure}), (201 if not failure else (207 if created else 502))


# --- board lab ---------------------------------------------------------------------------

BOARD_SLOT = 'usb4'     # the slot MOAVI Desk owns on a desktop VM (usb0-3 stay the admin's)
_USB_ID = re.compile(r'^([0-9a-f]{4}:[0-9a-f]{4}|\d+-\d+(\.\d+)*)$')


def _board_body():
    data = _body()
    cluster_id = str(data.get('cluster_id') or '')
    if not core._can_reach(cluster_id):
        raise LookupError('Cluster not found')
    usb = str(data.get('usb') or '').strip().lower()
    if not _USB_ID.match(usb):
        raise ValueError('usb: vendor:product (03fd:0008) or a port path (1-2.3)')
    node = _text(data, 'node', 64, required=True)
    return _text(data, 'name', 80, required=True), cluster_id, node, usb, _text(data, 'kind', 80), _text(data, 'notes', 300)


@bp.route('/api/vlab/admin/boards', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_boards():
    out = []
    for b in catalog.list_boards():
        if not core._can_reach(b['cluster_id']):
            continue
        desk = store.get_desktop(b['attached_desktop']) if b['attached_desktop'] else None
        out.append(dict(b, desktop=({'id': desk['id'], 'name': desk['name'], 'assigned_user': desk['assigned_user']} if desk else None)))
    return jsonify({'boards': out, 'slot': BOARD_SLOT})


@bp.route('/api/vlab/admin/boards', methods=['POST'])
@require_auth(perms=['vlab.accel.manage'])
def create_board():
    try:
        args = _board_body()
    except LookupError as e:
        return _bad(str(e), 404)
    except ValueError as e:
        return _bad(str(e))
    b = catalog.save_board(None, *args)
    log_audit(_user(), 'vlab.board.create', f"board '{b['name']}' {b['node']} usb {b['usb']}", get_client_ip())
    return jsonify({'board': b}), 201


@bp.route('/api/vlab/admin/boards/<bid>', methods=['PUT'])
@require_auth(perms=['vlab.accel.manage'])
def update_board(bid):
    old = catalog.get_board(bid)
    if not old or not core._can_reach(old['cluster_id']):
        return _bad('Board not found', 404)
    if old['attached_desktop']:
        return _bad('Detach the board before changing it', 409)
    try:
        args = _board_body()
    except LookupError as e:
        return _bad(str(e), 404)
    except ValueError as e:
        return _bad(str(e))
    b = catalog.save_board(bid, *args)
    log_audit(_user(), 'vlab.board.update', f"board '{b['name']}'", get_client_ip())
    return jsonify({'board': b})


@bp.route('/api/vlab/admin/boards/<bid>', methods=['DELETE'])
@require_auth(perms=['vlab.accel.manage'])
def delete_board(bid):
    b = catalog.get_board(bid)
    if not b or not core._can_reach(b['cluster_id']):
        return _bad('Board not found', 404)
    if b['attached_desktop']:
        return _bad('Detach the board first', 409)
    catalog.delete_board(bid)
    log_audit(_user(), 'vlab.board.delete', f"board '{b['name']}'", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/boards/<bid>/attach', methods=['POST'])
@require_auth(perms=['vlab.accel.manage'])
def attach_board(bid):
    """Pass the board's USB device through to a desktop VM (slot usb4). The desktop must run
    on the node the board is plugged into."""
    b = catalog.get_board(bid)
    if not b or not core._can_reach(b['cluster_id']):
        return _bad('Board not found', 404)
    if b['attached_desktop']:
        return _bad('The board is attached already - detach it first', 409)
    desk = store.get_desktop(str(_body().get('desktop_id') or ''))
    if not desk or desk['cluster_id'] != b['cluster_id']:
        return _bad('Desktop not found on the board\'s cluster', 404)
    if desk['vm_type'] != 'qemu':
        return _bad('USB passthrough needs a virtual machine (QEMU)')
    live = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
    node = live.get('node') or desk['node']
    if node != b['node']:
        return _bad(f"The desktop runs on {node}, the board is on {b['node']} - move the desktop first", 409)
    if any(o['attached_vmid'] == int(desk['vmid']) and o['cluster_id'] == desk['cluster_id'] for o in catalog.list_boards()):
        return _bad('Another board is attached to this desktop', 409)
    mgr = cluster_managers.get(desk['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    r = mgr.update_vm_config(node, int(desk['vmid']), 'qemu', {BOARD_SLOT: f"host={b['usb']}"})
    if not isinstance(r, dict) or not r.get('success'):
        return _bad(f"Could not attach: {str((r or {}).get('error') if isinstance(r, dict) else r)[:200]}", 502)
    b = catalog.set_board_attachment(bid, desk['id'], desk['vmid'], _user())
    log_audit(_user(), 'vlab.board.attach', f"board '{b['name']}' usb {b['usb']} -> {desk['name']} (qemu/{desk['vmid']})", get_client_ip())
    return jsonify({'board': b})


@bp.route('/api/vlab/admin/boards/<bid>/detach', methods=['POST'])
@require_auth(perms=['vlab.accel.manage'])
def detach_board(bid):
    b = catalog.get_board(bid)
    if not b or not core._can_reach(b['cluster_id']):
        return _bad('Board not found', 404)
    if not b['attached_desktop']:
        return _bad('The board is not attached', 409)
    desk = store.get_desktop(b['attached_desktop'])
    if desk:
        mgr = cluster_managers.get(desk['cluster_id'])
        if not mgr or not getattr(mgr, 'is_connected', False):
            return _bad('Cluster not connected', 503)
        live = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
        r = mgr.update_vm_config(live.get('node') or desk['node'], int(desk['vmid']), 'qemu', {'delete': BOARD_SLOT})
        if not isinstance(r, dict) or not r.get('success'):
            return _bad(f"Could not detach: {str((r or {}).get('error') if isinstance(r, dict) else r)[:200]}", 502)
    b = catalog.set_board_attachment(bid, None, None, '')
    log_audit(_user(), 'vlab.board.detach', f"board '{b['name']}' from {desk['name'] if desk else 'a removed desktop'}", get_client_ip())
    return jsonify({'board': b})


# --- build farm --------------------------------------------------------------------------

@bp.route('/api/vlab/admin/buildfarm', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def buildfarm():
    """The build farm pools at a glance: desktops, how many are on and in use, their load."""
    busy = store.open_session_desktops()
    pools = []
    for p in store.list_pools():
        if p['type'] != 'buildfarm' or not core._can_reach(p['cluster_id']):
            continue
        live = core._vm_states(p['cluster_id'])
        desks = store.list_desktops(p['id'])
        rows, cpu, cpus, mem, maxmem = [], 0.0, 0, 0, 0
        for d in desks:
            v = live.get(int(d['vmid'])) or {}
            on = v.get('status') == 'running'
            used = bool(d['assigned_user']) or d['id'] in busy
            c = float(v.get('cpu') or 0) if on else 0.0
            rows.append({'id': d['id'], 'name': d['name'], 'status': v.get('status') or 'unknown', 'assigned_user': d['assigned_user'],
                         'in_session': d['id'] in busy, 'cpu': round(c * 100, 1), 'maxcpu': v.get('maxcpu'),
                         'mem': v.get('mem') if on else 0, 'maxmem': v.get('maxmem')})
            if on:
                cpu += c * float(v.get('maxcpu') or 1)
                cpus += int(v.get('maxcpu') or 1)
                mem += int(v.get('mem') or 0)
                maxmem += int(v.get('maxmem') or 0)
        running = sum(1 for r in rows if r['status'] == 'running')
        in_use = sum(1 for r in rows if r['assigned_user'] or r['in_session'])
        pools.append({'id': p['id'], 'name': p['name'], 'cluster_id': p['cluster_id'], 'total': len(rows), 'running': running,
                      'in_use': in_use, 'free': len(rows) - in_use, 'cpu_pct': round(100 * cpu / cpus, 1) if cpus else 0.0,
                      'mem_used': mem, 'mem_total': maxmem, 'desktops': rows})
    return jsonify({'pools': pools})


# --- licence servers ---------------------------------------------------------------------

def _license_body():
    data = _body()
    ports = data.get('ports')
    if isinstance(ports, str):
        ports = [p for p in re.split(r'[\s,]+', ports) if p]
    if not isinstance(ports, list) or not 1 <= len(ports) <= 10:
        raise ValueError('ports: 1 to 10 port numbers')
    try:
        ports = sorted({int(p) for p in ports})
    except (TypeError, ValueError):
        raise ValueError('ports must be numbers')
    if any(not 1 <= p <= 65535 for p in ports):
        raise ValueError('ports must be 1 to 65535')
    cluster_id = str(data.get('cluster_id') or '')
    vmid = data.get('vmid')
    if cluster_id or vmid not in (None, ''):
        if not core._can_reach(cluster_id):
            raise ValueError('cluster_id: cluster not found')
        vmid = _int(data, 'vmid', 100, 999999999)
    else:
        cluster_id, vmid = '', None
    mac = str(data.get('fixed_mac') or '').strip().lower()
    if mac and not re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac):
        raise ValueError('fixed_mac must look like 52:54:00:12:34:56')
    return (_text(data, 'name', 80, required=True), _host(data, 'host'), ports, cluster_id, vmid, mac, _text(data, 'notes', 300))


def _license_view(s):
    out = dict(s)
    if s['cluster_id'] and s['vmid']:
        v = core._vm_states(s['cluster_id']).get(int(s['vmid'])) or {}
        out['vm_status'] = v.get('status') or 'unknown'
        out['vm_ha'] = bool(v.get('hastate'))
    return out


@bp.route('/api/vlab/admin/license-servers', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_license_servers():
    return jsonify({'servers': [_license_view(s) for s in catalog.list_license_servers()
                                if not s['cluster_id'] or core._can_reach(s['cluster_id'])],
                    'default_ports': [2100, 27000]})


@bp.route('/api/vlab/admin/license-servers', methods=['POST'])
@require_auth(perms=['vlab.accel.manage'])
def create_license_server():
    try:
        args = _license_body()
    except ValueError as e:
        return _bad(str(e))
    s = catalog.save_license_server(None, *args)
    log_audit(_user(), 'vlab.license.create', f"licence server '{s['name']}' {s['host']} ports {s['ports']}", get_client_ip())
    return jsonify({'server': s}), 201


@bp.route('/api/vlab/admin/license-servers/<lid>', methods=['PUT'])
@require_auth(perms=['vlab.accel.manage'])
def update_license_server(lid):
    if not catalog.get_license_server(lid):
        return _bad('Licence server not found', 404)
    try:
        args = _license_body()
    except ValueError as e:
        return _bad(str(e))
    s = catalog.save_license_server(lid, *args)
    log_audit(_user(), 'vlab.license.update', f"licence server '{s['name']}'", get_client_ip())
    return jsonify({'server': s})


@bp.route('/api/vlab/admin/license-servers/<lid>', methods=['DELETE'])
@require_auth(perms=['vlab.accel.manage'])
def delete_license_server(lid):
    s = catalog.get_license_server(lid)
    if not s:
        return _bad('Licence server not found', 404)
    catalog.delete_license_server(lid)
    log_audit(_user(), 'vlab.license.delete', f"licence server '{s['name']}'", get_client_ip())
    return jsonify({'success': True})


@bp.route('/api/vlab/admin/license-servers/<lid>/check', methods=['POST'])
@require_auth(perms=['vlab.pool.view'])
def check_license_server(lid):
    """Does every licence port answer? (MOAVI Desk never reads or holds licence files.)"""
    s = catalog.get_license_server(lid)
    if not s or (s['cluster_id'] and not core._can_reach(s['cluster_id'])):
        return _bad('Licence server not found', 404)
    detail = []
    for port in s['ports']:
        ok, ms, err = _tcp_probe(s['host'], port)
        detail.append({'port': port, 'ok': ok, 'ms': ms, 'error': err})
    ok = bool(detail) and all(d['ok'] for d in detail)
    s = catalog.mark_license_server(lid, ok, detail)
    return jsonify({'server': _license_view(s), 'ok': ok})
