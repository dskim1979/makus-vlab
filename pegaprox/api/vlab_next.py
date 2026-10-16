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

  GET/PUT /api/vlab/admin/pools/<id>/grants          who may claim / use a pool (user, department, group)  vlab.pool.view / manage
  GET    /api/vlab/me/pools, POST .../<id>/claim, POST .../<id>/route   claim a desktop, route into a shared pool  vlab.desk
  GET    /api/vlab/me/external/<id>/guac              browser RDP link (Guacamole) for an external desktop  vlab.desk
  POST   /api/vlab/admin/golden-images/<id>/rollout   desktops of an older version replaced by the current one  vlab.pool.manage
  GET/POST /api/vlab/me/build-jobs, POST .../<id>/cancel     the caller's build jobs                vlab.desk
  GET/POST /api/vlab/admin/build-jobs, POST .../<id>/cancel  every build job                        vlab.pool.view / manage
  GET    /api/vlab/admin/reports/cards                ?days=&format=csv card loans per card       vlab.report.view
"""

import base64
import hashlib
import hmac
import json as _json
import logging
import re
import shlex
import socket
import time
from datetime import datetime
from urllib.parse import quote as _quote

from flask import Blueprint, has_request_context, jsonify, request

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
    key = data.get('secret_key')
    if key not in (None, ''):
        key = str(key).strip().lower()
        if kind != 'guacamole' or not re.match(r'^[0-9a-f]{32}$', key):
            raise ValueError('secret_key: 32 hex digits (the 128-bit key of guacamole-auth-json), Guacamole only')
    else:
        key = None
    return (_text(data, 'name', 80, required=True), kind, _host(data, 'address'),
            _int(data, 'port', 1, 65535, catalog.GATEWAY_KINDS[kind]), _text(data, 'notes', 300), data.get('enabled', True) is not False, key)


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
    if gid == catalog.BUILTIN_GUAC_ID:      # the bundled one: the engine reaches it inside compose
        ok, ms, err = _tcp_probe('guacamole', 8080)
    else:
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
        have = catalog.desktop_versions(img['id'])
        outdated = {}
        for p in store.list_pools():
            if (p.get('settings') or {}).get('golden_id') == img['id']:
                outdated[p['id']] = {'pool': p['name'], 'total': 0, 'outdated': 0}
                for d in store.list_desktops(p['id']):
                    outdated[p['id']]['total'] += 1
                    outdated[p['id']]['outdated'] += 1 if have.get(d['id']) != img['current_version'] else 0
        out.append(dict(img, versions=_versions(img), status=live.get('status') or 'unknown', pools=used.get(img['id'], []),
                        rollout=[dict(v, pool_id=k) for k, v in outdated.items()]))
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
        catalog.set_desktop_version(desk['id'], gid, img['current_version'])
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
    data = _body()
    desk = store.get_desktop(str(data.get('desktop_id') or ''))
    if not desk or desk['cluster_id'] != b['cluster_id']:
        return _bad('Desktop not found on the board\'s cluster', 404)
    lease_user = str(data.get('lease_user') or '').strip() or (desk['assigned_user'] or '')
    lease_until = str(data.get('lease_until') or '').strip() or None
    if lease_until:
        try:
            if datetime.fromisoformat(lease_until[:16]) <= datetime.now():
                return _bad('lease_until must be in the future')
            lease_until = lease_until[:16]
        except ValueError:
            return _bad('lease_until must look like 2026-10-20T18:00')
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
    b = catalog.set_board_attachment(bid, desk['id'], desk['vmid'], _user(), lease_user, lease_until)
    log_audit(_user(), 'vlab.board.attach', f"board '{b['name']}' usb {b['usb']} -> {desk['name']} (qemu/{desk['vmid']})"
              + (f", lent to {lease_user} until {lease_until}" if lease_until else ''), get_client_ip())
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
    return (_text(data, 'name', 80, required=True), _host(data, 'host'), ports, cluster_id, vmid, mac, _text(data, 'notes', 300),
            data.get('watch', True) is not False)


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


# =========================================================================================
# Access and automation (docs/vlab-design.md 6-3, 7-1, 7-3, 9, 10-2, 10-4, 12 step 4)
#
#   GET/PUT /api/vlab/admin/pools/<id>/grants          {grants:[{subject_type, subject_id, include_children}], max_sessions?}
#   GET    /api/vlab/me/pools                           pools granted to the caller (claim / shared)    vlab.desk
#   POST   /api/vlab/me/pools/<id>/claim                a free desktop of the pool, assigned to the caller
#   POST   /api/vlab/me/pools/<id>/route                shared pool: the desktop to connect to now
#   GET    /api/vlab/me/external/<id>/guac              browser RDP (Guacamole) link for an external desktop
#   POST   /api/vlab/admin/golden-images/<id>/rollout   {pool_id, delete_old?} desktops of an older version -> current
#   GET    /api/vlab/admin/build-jobs, POST .../<id>/cancel; GET/POST /api/vlab/me/build-jobs
#   GET    /api/vlab/admin/reports/cards                ?days=30&format=csv card loans per card
# The minute loop (pegaprox/vlab/loans.py) also runs board_tick (due board loans) and
# license_tick (licence servers every 5 minutes, alerts on a change).
# =========================================================================================

MAX_SESSIONS_DEFAULT = 10


# --- pool grants -------------------------------------------------------------------------

def _user_groups(username):
    from pegaprox.core.db import get_db
    try:
        return {str(g).lower() for g in (get_db().get_user_directory_groups(username) or [])}
    except Exception:
        return set()


def granted(pool_id, username, grants=None, dep=None, groups=None):
    """Does a pool grant reach the user: by name, by department (and its sub-departments), or by directory group?"""
    grants = catalog.pool_grants(pool_id) if grants is None else grants
    if not grants:
        return False
    dep = catalog.department_of(username) if dep is None else dep
    for g in grants:
        if g['subject_type'] == 'user' and g['subject_id'] == username:
            return True
        if g['subject_type'] == 'department' and dep:
            if (dep == g['subject_id']) or (g['include_children'] and dep in catalog.descendants(g['subject_id'])):
                return True
        if g['subject_type'] == 'group':
            groups = _user_groups(username) if groups is None else groups
            if g['subject_id'].lower() in groups:
                return True
    return False


def shared_member(desk, username):
    """The core connect route asks this for a desktop not assigned to the caller: a shared pool's
    desktop is open to everyone the pool is granted to."""
    pool = store.get_pool(desk['pool_id']) or {}
    return pool.get('type') == 'shared' and granted(pool['id'], username)


def _max_sessions(pool):
    try:
        return max(1, min(500, int(((pool.get('settings') or {}).get('shared') or {}).get('max_sessions') or MAX_SESSIONS_DEFAULT)))
    except (TypeError, ValueError):
        return MAX_SESSIONS_DEFAULT


@bp.route('/api/vlab/admin/pools/<pool_id>/grants', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def get_pool_grants(pool_id):
    pool, err = core._pool_or_error(pool_id)
    if err:
        return err
    return jsonify({'grants': catalog.pool_grants(pool_id), 'max_sessions': _max_sessions(pool), 'types': list(catalog.GRANT_TYPES)})


@bp.route('/api/vlab/admin/pools/<pool_id>/grants', methods=['PUT'])
@require_auth(perms=['vlab.pool.manage'])
def put_pool_grants(pool_id):
    from pegaprox.utils.auth import load_users
    pool, err = core._pool_or_error(pool_id)
    if err:
        return err
    data = _body()
    rows = data.get('grants')
    if not isinstance(rows, list) or len(rows) > 500:
        return _bad('grants: a list of at most 500')
    users = load_users()
    clean = []
    for g in rows:
        if not isinstance(g, dict):
            return _bad('grants: objects with subject_type and subject_id')
        t, sid = str(g.get('subject_type') or ''), str(g.get('subject_id') or '').strip()
        if t not in catalog.GRANT_TYPES or not sid or len(sid) > 300:
            return _bad('subject_type must be user, department or group, with a subject_id')
        if t == 'user' and sid not in users:
            return _bad(f'No such user: {sid}')
        if t == 'department' and not catalog.get_department(sid):
            return _bad(f'No such department: {sid}')
        clean.append({'subject_type': t, 'subject_id': sid, 'include_children': g.get('include_children', True) is not False})
    if 'max_sessions' in data:
        try:
            ms = int(data['max_sessions'])
        except (TypeError, ValueError):
            return _bad('max_sessions must be a number')
        if not 1 <= ms <= 500:
            return _bad('max_sessions must be 1 to 500')
        settings = dict(pool.get('settings') or {})
        settings['shared'] = dict(settings.get('shared') or {}, max_sessions=ms)
        store.set_pool_settings(pool_id, settings)
    out = catalog.set_pool_grants(pool_id, clean)
    log_audit(_user(), 'vlab.pool.grants', f"pool '{pool['name']}': {len(out)} grants "
              + ', '.join(f"{g['subject_type']}:{g['subject_id']}" for g in out[:10]), get_client_ip())
    return jsonify({'grants': out, 'max_sessions': _max_sessions(store.get_pool(pool_id))})


CLAIM_TYPES = ('dedicated', 'reset', 'buildfarm')


@bp.route('/api/vlab/me/pools', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_pools():
    """Pools granted to the caller: claim a desktop of a dedicated / reset / build farm pool, or
    connect to a shared pool (the engine picks its least busy desktop)."""
    username = _user()
    dep, groups = catalog.department_of(username), _user_groups(username)
    busy = store.open_session_desktops()
    by_pool = {}
    for g in catalog.pool_grants():
        by_pool.setdefault(g['pool_id'], []).append(g)
    out = []
    for pool in store.list_pools():
        if not pool.get('enabled', True) or not core._can_reach(pool['cluster_id']):
            continue
        if not granted(pool['id'], username, by_pool.get(pool['id'], []), dep, groups):
            continue
        desks = store.list_desktops(pool['id'])
        mine = [d for d in desks if d['assigned_user'] == username]
        free = [d for d in desks if not d['assigned_user'] and d['id'] not in busy and d.get('state') not in ('provisioning', 'resetting', 'error')]
        kind = 'shared' if pool['type'] == 'shared' else ('claim' if pool['type'] in CLAIM_TYPES else 'other')
        out.append({'id': pool['id'], 'name': pool['name'], 'type': pool['type'], 'description': pool.get('description', ''),
                    'action': kind, 'desktops': len(desks), 'free': len(free), 'mine': [d['id'] for d in mine]})
    return jsonify({'pools': out})


@bp.route('/api/vlab/me/pools/<pool_id>/claim', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def claim_desktop(pool_id):
    username = _user()
    pool = store.get_pool(pool_id)
    if not pool or not core._can_reach(pool['cluster_id']) or not granted(pool_id, username):
        return _bad('Pool not found', 404)
    if pool['type'] not in CLAIM_TYPES:
        return _bad('Desktops of this pool are not handed out on request', 409)
    desks = store.list_desktops(pool_id)
    mine = next((d for d in desks if d['assigned_user'] == username), None)
    if mine:
        return jsonify({'desktop': {'id': mine['id'], 'name': mine['name']}, 'new': False})
    busy = store.open_session_desktops()
    free = [d for d in desks if not d['assigned_user'] and d['id'] not in busy and d.get('state') not in ('provisioning', 'resetting', 'error')]
    if not free:
        return jsonify({'error': 'Every desktop of this pool is taken', 'code': 'FULL'}), 409
    d = free[0]
    if not core._acl_set(d['cluster_id'], d['vmid'], username, True):
        return _bad('VM access list unavailable - try again', 503)
    store.set_assignment(d['id'], username)
    log_audit(username, 'vlab.desktop.claim', f"{d['vm_type']}/{d['vmid']} '{d['name']}' from pool '{pool['name']}'", get_client_ip())
    return jsonify({'desktop': {'id': d['id'], 'name': d['name']}, 'new': True})


@bp.route('/api/vlab/me/pools/<pool_id>/route', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def route_shared(pool_id):
    """Shared pool: the running desktop with the fewest open sessions for its weight, under the
    pool's limit per desktop. The caller then connects to it like to their own desktop."""
    username = _user()
    pool = store.get_pool(pool_id)
    if not pool or not core._can_reach(pool['cluster_id']) or not granted(pool_id, username):
        return _bad('Pool not found', 404)
    if pool['type'] != 'shared':
        return _bad('Only shared pools are routed', 409)
    live = core._vm_states(pool['cluster_id'])
    weights = ((pool.get('settings') or {}).get('shared') or {}).get('weights') or {}
    counts = {}
    for s in store.open_sessions():
        counts[s['desktop_id']] = counts.get(s['desktop_id'], 0) + 1
    limit = _max_sessions(pool)
    best = None
    for d in store.list_desktops(pool_id):
        if (live.get(int(d['vmid'])) or {}).get('status') != 'running' or d.get('state') in ('provisioning', 'resetting', 'error'):
            continue
        n = counts.get(d['id'], 0)
        if n >= limit:
            continue
        try:
            w = max(1, int(weights.get(d['id'], 1)))
        except (TypeError, ValueError):
            w = 1
        key = (n / w, n, d['name'])
        if best is None or key < best[0]:
            best = (key, d)
    if not best:
        return jsonify({'error': 'Every desktop of this pool is full or off', 'code': 'FULL'}), 409
    d = best[1]
    if not core._acl_set(d['cluster_id'], d['vmid'], username, True):
        return _bad('VM access list unavailable - try again', 503)
    return jsonify({'desktop': {'id': d['id'], 'name': d['name']}, 'sessions': counts.get(d['id'], 0), 'limit': limit})


# --- RDP files and Guacamole -------------------------------------------------------------

def _guest_ipv4(mgr, node, vmid):
    try:
        ips = mgr._fetch_qemu_ips(node, int(vmid)) or []
    except Exception:
        ips = []
    for ip in ips:
        ip = str(ip)
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip) and not ip.startswith(('127.', '169.254.')):
            return ip
    return None


def _guac_gateway(pool=None):
    gid = ((pool or {}).get('settings') or {}).get('guac_gateway_id')
    for g in catalog.list_gateways(secret=True):
        if g['kind'] == 'guacamole' and g['enabled'] and g['secret_key'] and (not gid or g['id'] == gid):
            return g
    return None


def guac_link(gw, username, name, host, port, minutes=5):
    """A guacamole-auth-json login link: the JSON (one RDP connection) signed with HMAC-SHA256 and
    encrypted with AES-128-CBC (zero IV) under the gateway's 128-bit key, base64 in ?data=."""
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = bytes.fromhex(gw['secret_key'])
    payload = _json.dumps({'username': username, 'expires': int((time.time() + minutes * 60) * 1000),
                           'connections': {name: {'protocol': 'rdp', 'parameters': {
                               'hostname': host, 'port': str(port), 'username': username,
                               'ignore-cert': 'true', 'security': 'any', 'resize-method': 'display-update'}}}},
                          separators=(',', ':')).encode()
    signed = hmac.new(key, payload, hashlib.sha256).digest() + payload
    padder = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(b'\0' * 16)).encryptor()
    data = enc.update(padder.update(signed) + padder.finalize()) + enc.finalize()
    q = _quote(base64.b64encode(data).decode())
    if gw['id'] == catalog.BUILTIN_GUAC_ID and has_request_context():
        # the bundled one sits behind the console's own address: use the name the user came in by
        return f"https://{request.host}/guacamole/?data={q}"
    scheme = 'http' if gw['port'] in (80, 8080) else 'https'
    return f"{scheme}://{gw['address']}:{gw['port']}/guacamole/?data={q}"


def desktop_rdp_answer(desk, mgr, node, vmid, username, protocol, pool):
    """The connect route's answer for rdp (an .rdp file) and guac (a browser RDP link).
    Returns (answer, None) or (None, error response)."""
    if desk['vm_type'] != 'qemu':
        return None, _bad('RDP needs a virtual machine (QEMU) with its guest agent')
    ip = _guest_ipv4(mgr, node, vmid)
    if not ip:
        return None, (jsonify({'error': 'The desktop has no address yet - is its guest agent running?', 'code': 'NO_IP'}), 409)
    port = 3389
    if protocol == 'rdp':
        ext = {'address': ip, 'port': port, 'gateway_id': ((pool or {}).get('settings') or {}).get('rdp_gateway_id')}
        return {'type': 'rdp', 'rdp': rdp_file(ext, username), 'filename': f"{desk['name']}.rdp"}, None
    gw = _guac_gateway(pool)
    if not gw:
        return None, (jsonify({'error': 'No browser RDP gateway (Guacamole with a key) is set up', 'code': 'NO_GATEWAY'}), 409)
    return {'type': 'guac', 'url': guac_link(gw, username, desk['name'], ip, port)}, None


@bp.route('/api/vlab/me/external/<eid>/guac', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_external_guac(eid):
    ext = catalog.get_external(eid)
    if not ext or ext['assigned_user'] != _user():
        return _bad('External desktop not found', 404)
    gw = None
    if ext.get('gateway_id'):
        g = catalog.get_gateway(ext['gateway_id'], secret=True)
        if g and g['kind'] == 'guacamole' and g['enabled'] and g['secret_key']:
            gw = g
    gw = gw or _guac_gateway()
    if not gw:
        return jsonify({'error': 'No browser RDP gateway (Guacamole with a key) is set up', 'code': 'NO_GATEWAY'}), 409
    log_audit(_user(), 'vlab.external.connect', f"browser RDP to '{ext['name']}'", get_client_ip())
    return jsonify({'url': guac_link(gw, _user(), ext['name'], ext['address'], ext['port'])})


# --- golden image rollout ----------------------------------------------------------------

MAX_ROLLOUT = 20


@bp.route('/api/vlab/admin/golden-images/<gid>/rollout', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def rollout_golden(gid):
    """Bring a pool's desktops to the image's current version (design 6-3, method A): a new full
    clone per desktop, the user moved over (VM access too), the old desktop out of the pool.
    Desktops in a session now are left for the next run. With delete_old, a stopped old VM is deleted."""
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
    delete_old = data.get('delete_old') is True
    mgr = cluster_managers.get(pool['cluster_id'])
    if not mgr or not getattr(mgr, 'is_connected', False):
        return _bad('Cluster not connected', 503)
    from pegaprox.api.helpers import acting_user
    from pegaprox.utils.rbac import TenantRangeUnknown, tenant_vmid_range
    versions = catalog.desktop_versions(gid)
    busy = store.open_session_desktops()
    todo, skipped = [], []
    for d in store.list_desktops(pool['id']):
        if versions.get(d['id']) == img['current_version']:
            continue
        if d['id'] in busy or d.get('state') in ('provisioning', 'resetting'):
            skipped.append(d['name'])
            continue
        todo.append(d)
    todo = todo[:MAX_ROLLOUT]
    if not todo:
        return jsonify({'replaced': [], 'skipped': skipped, 'failed': None})
    live = core._vm_states(pool['cluster_id'])
    node = (live.get(int(img['vmid'])) or {}).get('node') or img['node']
    try:
        tenant_range = tenant_vmid_range((acting_user() or {}).get('tenant_id') or 'default')
    except TenantRangeUnknown:
        return _bad('Tenant settings unavailable - nothing changed', 503)
    start = 0
    if not tenant_range[0]:
        nxt = mgr.get_next_vmid()
        if isinstance(nxt, dict) and nxt.get('success'):
            start = int(nxt.get('vmid') or 0)
    vmids = core._free_vmids(pool['cluster_id'], len(todo), start, tenant_range, live)
    replaced, failure = [], None
    for old, vmid in zip(todo, vmids):
        r = mgr.clone_vm(node, int(img['vmid']), 'qemu', vmid, name=old['name'], full=True, snapname=img['current_version'],
                         description=f"MOAVI Desk pool '{pool['name']}' from golden image '{img['name']}' {img['current_version']}")
        if not isinstance(r, dict) or not r.get('success'):
            failure = {'name': old['name'], 'error': str((r or {}).get('error') if isinstance(r, dict) else r)[:300]}
            break
        new = store.add_desktop(pool, node, vmid, old['name'], 'qemu', state='provisioning')
        catalog.set_desktop_version(new['id'], gid, img['current_version'])
        user = old['assigned_user']
        if user:
            core._acl_set(pool['cluster_id'], vmid, user, True)
            store.set_assignment(new['id'], user)
            core._acl_set(old['cluster_id'], old['vmid'], user, False)
        store.remove_desktop(old['id'])
        catalog.forget_desktop_version(old['id'])
        deleted = False
        if delete_old and (live.get(int(old['vmid'])) or {}).get('status') == 'stopped':
            dr = mgr.delete_vm(live.get(int(old['vmid']), {}).get('node') or old['node'], int(old['vmid']), old['vm_type'], purge=True)
            deleted = isinstance(dr, dict) and bool(dr.get('success'))
        replaced.append({'name': old['name'], 'old_vmid': old['vmid'], 'new_vmid': vmid, 'user': user, 'old_deleted': deleted})
    log_audit(_user(), 'vlab.golden.rollout', f"pool '{pool['name']}' -> {img['current_version']}: {len(replaced)} replaced, "
              f"{len(skipped)} in use" + (f", stopped at {failure['name']}" if failure else ''), get_client_ip())
    return jsonify({'replaced': replaced, 'skipped': skipped, 'failed': failure}), (200 if not failure else (207 if replaced else 502))


# --- board loans -------------------------------------------------------------------------

def _detach_board(b):
    """Take the board off its desktop. Returns an error text or None."""
    desk = store.get_desktop(b['attached_desktop']) if b['attached_desktop'] else None
    if desk:
        mgr = cluster_managers.get(desk['cluster_id'])
        if not mgr or not getattr(mgr, 'is_connected', False):
            return 'cluster not connected'
        live = core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}
        r = mgr.update_vm_config(live.get('node') or desk['node'], int(desk['vmid']), 'qemu', {'delete': BOARD_SLOT})
        if not isinstance(r, dict) or not r.get('success'):
            return str((r or {}).get('error') if isinstance(r, dict) else r)[:200] or 'update failed'
    catalog.set_board_attachment(b['id'], None, None, '')
    return None


def board_tick(now_iso=None):
    """Detach the boards whose loan has ended (the minute loop). Returns (done, failed)."""
    from pegaprox.core import ha
    done = failed = 0
    for b in catalog.due_boards(now_iso or store.now()):
        if not ha.confirm_step(f"vLAB board loan end {b['id']}"):
            break
        err = _detach_board(b)
        if err:
            failed += 1
            logging.warning(f"[VLAB] board {b['name']} not detached at loan end: {err}")
        else:
            done += 1
            log_audit('system', 'vlab.board.return', f"board '{b['name']}': loan to {b['lease_user'] or '-'} ended", '')
    return done, failed


# --- licence server watch ----------------------------------------------------------------

LICENSE_EVERY = 300
_license_last = [0.0]


def _alert(title, text, data):
    """Licence alerts go to every webhook channel and the alert mail recipients."""
    try:
        from pegaprox.utils.webhooks import send_to_channels
        send_to_channels(dict(data, title=title, message=text, source='moavi-desk', severity=data.get('severity', 'critical')))
    except Exception as e:
        logging.warning(f'[VLAB] licence alert webhooks: {e}')
    try:
        from pegaprox.api.helpers import load_server_settings
        from pegaprox.utils.email import send_email
        rcpt = (load_server_settings() or {}).get('alert_email_recipients') or []
        if rcpt:
            send_email(rcpt, f'[MOAVI Desk] {title}', text, None)
    except Exception as e:
        logging.warning(f'[VLAB] licence alert mail: {e}')


def license_tick(force=False):
    """Check every watched licence server's ports (every 5 minutes); alert when one stops
    answering and again when it is back. Returns the number checked."""
    if not force and time.time() - _license_last[0] < LICENSE_EVERY:
        return 0
    _license_last[0] = time.time()
    n = 0
    for s in catalog.list_license_servers():
        if not s.get('watch', 1):
            continue
        detail = []
        for port in s['ports']:
            ok, ms, err = _tcp_probe(s['host'], port)
            detail.append({'port': port, 'ok': ok, 'ms': ms, 'error': err})
        ok = bool(detail) and all(d['ok'] for d in detail)
        was = s.get('last_ok')
        catalog.mark_license_server(s['id'], ok, detail)
        n += 1
        down = ', '.join(str(d['port']) for d in detail if not d['ok'])
        if not ok and not s.get('alerted_at'):
            _alert(f"라이선스 서버 응답 없음: {s['name']}", f"{s['name']} ({s['host']}) 포트 {down} 가 응답하지 않습니다.",
                   {'kind': 'license_down', 'server': s['name'], 'host': s['host'], 'ports': down})
            catalog.mark_license_alerted(s['id'], store.now())
            log_audit('system', 'vlab.license.down', f"licence server '{s['name']}' ports {down} not answering", '')
        elif ok and s.get('alerted_at'):
            _alert(f"라이선스 서버 복구: {s['name']}", f"{s['name']} ({s['host']}) 의 모든 포트가 다시 응답합니다.",
                   {'kind': 'license_up', 'server': s['name'], 'host': s['host'], 'severity': 'info'})
            catalog.mark_license_alerted(s['id'], None)
            log_audit('system', 'vlab.license.up', f"licence server '{s['name']}' answers again", '')
        elif ok and was is None:
            pass
    return n


# --- build job queue ---------------------------------------------------------------------

MAX_OUTPUT = 20000


def _agent(mgr, node, vmid, path):
    return f"https://{mgr.host}:{mgr.api_port}/api2/json/nodes/{node}/qemu/{int(vmid)}/agent/{path}"


def _start_job(job, desk, mgr, node):
    cmd = job['command'] if not job['workdir'] else f"cd {shlex.quote(job['workdir'])} && {job['command']}"
    resp = mgr._api_post(_agent(mgr, node, desk['vmid'], 'exec'), data={'command': ['/bin/bash', '-lc', cmd]})
    if getattr(resp, 'status_code', 0) != 200:
        return None, (getattr(resp, 'text', '') or 'guest agent refused')[:300]
    try:
        pid = (resp.json().get('data') or {}).get('pid')
    except Exception:
        pid = None
    return pid, (None if pid else 'guest agent returned no pid')


def refresh_jobs(pool_id=None):
    """Bring the queue up to date: read the running jobs' state from the guest agent, then start
    queued jobs on free build VMs (running, unassigned, not in a session, no job). Runs when the
    job lists are read and when a job is sent."""
    for job in catalog.jobs_in('running', pool_id):
        desk = store.get_desktop(job['desktop_id']) if job['desktop_id'] else None
        mgr = cluster_managers.get(desk['cluster_id']) if desk else None
        if not desk or not mgr or not getattr(mgr, 'is_connected', False):
            continue
        node = (core._vm_states(desk['cluster_id']).get(int(desk['vmid'])) or {}).get('node') or desk['node']
        try:
            resp = mgr._api_get(_agent(mgr, node, desk['vmid'], 'exec-status'), params={'pid': job['pid']})
            st = (resp.json().get('data') or {}) if getattr(resp, 'status_code', 0) == 200 else {}
        except Exception:
            st = {}
        if st.get('exited'):
            code = st.get('exitcode')
            out = (st.get('out-data') or '')[-MAX_OUTPUT:]
            err = (st.get('err-data') or '')[-4000:]
            catalog.update_build_job(job['id'], status='done' if code in (0, None) else 'failed', exit_code=code,
                                     output=out, error=err, finished_at=store.now())
    for job in catalog.jobs_in('queued', pool_id):
        pool = store.get_pool(job['pool_id'])
        if not pool:
            catalog.update_build_job(job['id'], status='cancelled', error='pool removed', finished_at=store.now())
            continue
        mgr = cluster_managers.get(pool['cluster_id'])
        if not mgr or not getattr(mgr, 'is_connected', False):
            continue
        live = core._vm_states(pool['cluster_id'])
        busy = store.open_session_desktops() | {j['desktop_id'] for j in catalog.jobs_in('running', pool['id'])}
        free = [d for d in store.list_desktops(pool['id'])
                if not d['assigned_user'] and d['id'] not in busy and d['vm_type'] == 'qemu'
                and (live.get(int(d['vmid'])) or {}).get('status') == 'running']
        if not free:
            continue
        d = free[0]
        node = (live.get(int(d['vmid'])) or {}).get('node') or d['node']
        pid, err = _start_job(job, d, mgr, node)
        if err:
            catalog.update_build_job(job['id'], status='failed', desktop_id=d['id'], error=err, finished_at=store.now())
        else:
            catalog.update_build_job(job['id'], status='running', desktop_id=d['id'], pid=pid, started_at=store.now())
            log_audit(job['username'], 'vlab.build.start', f"build '{job['name']}' on {d['name']} (qemu/{d['vmid']})", '')


def _job_view(j):
    desk = store.get_desktop(j['desktop_id']) if j.get('desktop_id') else None
    pool = store.get_pool(j['pool_id'])
    return dict(j, desktop=desk['name'] if desk else None, pool=pool['name'] if pool else None)


def _job_body():
    data = _body()
    pool = store.get_pool(str(data.get('pool_id') or ''))
    if not pool or pool['type'] != 'buildfarm' or not core._can_reach(pool['cluster_id']):
        raise LookupError('Build farm pool not found')
    name = _text(data, 'name', 80, required=True)
    command = _text(data, 'command', 2000, required=True)
    workdir = _text(data, 'workdir', 300)
    return pool, name, command, workdir


@bp.route('/api/vlab/me/build-jobs', methods=['GET'])
@require_auth(perms=['vlab.desk'])
def my_build_jobs():
    refresh_jobs()
    pools = [{'id': p['id'], 'name': p['name']} for p in store.list_pools()
             if p['type'] == 'buildfarm' and core._can_reach(p['cluster_id']) and granted(p['id'], _user())]
    return jsonify({'jobs': [_job_view(j) for j in catalog.list_build_jobs(username=_user(), limit=100)], 'pools': pools})


@bp.route('/api/vlab/me/build-jobs', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def submit_build_job():
    try:
        pool, name, command, workdir = _job_body()
    except LookupError as e:
        return _bad(str(e), 404)
    except ValueError as e:
        return _bad(str(e))
    if not granted(pool['id'], _user()):
        return _bad('Build farm pool not found', 404)
    if len(catalog.jobs_in('queued')) >= 500:
        return _bad('The build queue is full', 429)
    job = catalog.add_build_job(pool['id'], _user(), name, command, workdir)
    log_audit(_user(), 'vlab.build.submit', f"build '{name}' to pool '{pool['name']}'", get_client_ip())
    refresh_jobs(pool['id'])
    return jsonify({'job': _job_view(catalog.get_build_job(job['id']))}), 201


def _cancel(job):
    if job['status'] != 'queued':
        return _bad('Only a queued job can be cancelled (a running build ends on its build VM)', 409)
    return jsonify({'job': _job_view(catalog.update_build_job(job['id'], status='cancelled', finished_at=store.now()))})


@bp.route('/api/vlab/me/build-jobs/<jid>/cancel', methods=['POST'])
@require_auth(perms=['vlab.desk'])
def cancel_my_build_job(jid):
    job = catalog.get_build_job(jid)
    if not job or job['username'] != _user():
        return _bad('Job not found', 404)
    return _cancel(job)


@bp.route('/api/vlab/admin/build-jobs', methods=['GET'])
@require_auth(perms=['vlab.pool.view'])
def list_build_jobs():
    pool_id = request.args.get('pool_id') or None
    refresh_jobs(pool_id)
    jobs = catalog.list_build_jobs(pool_id=pool_id, limit=300)
    return jsonify({'jobs': [_job_view(j) for j in jobs],
                    'counts': {s: sum(1 for j in jobs if j['status'] == s) for s in catalog.JOB_STATES}})


@bp.route('/api/vlab/admin/build-jobs', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def admin_submit_build_job():
    """Send a job on someone's behalf (or the admin's own)."""
    from pegaprox.utils.auth import load_users
    try:
        pool, name, command, workdir = _job_body()
    except LookupError as e:
        return _bad(str(e), 404)
    except ValueError as e:
        return _bad(str(e))
    owner = str(_body().get('username') or '').strip() or _user()
    if owner not in load_users():
        return _bad('No such user')
    job = catalog.add_build_job(pool['id'], owner, name, command, workdir)
    log_audit(_user(), 'vlab.build.submit', f"build '{name}' for {owner} to pool '{pool['name']}'", get_client_ip())
    refresh_jobs(pool['id'])
    return jsonify({'job': _job_view(catalog.get_build_job(job['id']))}), 201


@bp.route('/api/vlab/admin/build-jobs/<jid>/cancel', methods=['POST'])
@require_auth(perms=['vlab.pool.manage'])
def cancel_build_job(jid):
    job = catalog.get_build_job(jid)
    if not job:
        return _bad('Job not found', 404)
    return _cancel(job)


# --- card usage report -------------------------------------------------------------------

@bp.route('/api/vlab/admin/reports/cards', methods=['GET'])
@require_auth(perms=['vlab.report.view'])
def card_report():
    """Loans per card over the last N days: how many, hours in the window, users, lent now."""
    from datetime import timedelta
    try:
        days = max(1, min(366, int(request.args.get('days') or 30)))
    except ValueError:
        return _bad('days must be a number')
    now = datetime.now()
    since = now - timedelta(days=days)
    parse = lambda s: datetime.fromisoformat(s[:19]) if s else None   # noqa: E731
    cards = {}
    for l in store.list_leases(active_only=False, limit=20000):
        start = parse(l['starts_at'])
        end = parse(l['returned_at']) or (now if l['state'] == 'active' else parse(l['ends_at']) or now)
        if not start or end < since:
            continue
        hours = max(0.0, (min(end, now) - max(start, since)).total_seconds() / 3600)
        key = l['resource_name'] or l['resource_id']
        c = cards.setdefault(key, {'card': key, 'resource_id': l['resource_id'], 'loans': 0, 'hours': 0.0, 'users': set(), 'active': 0})
        c['loans'] += 1
        c['hours'] += hours
        c['users'].add(l['username'])
        c['active'] += 1 if l['state'] == 'active' else 0
    rows = sorted(({**c, 'hours': round(c['hours'], 1), 'users': sorted(c['users']),
                    'use_pct': round(100 * c['hours'] / (days * 24), 1)} for c in cards.values()),
                  key=lambda r: -r['hours'])
    if request.args.get('format') == 'csv':
        from flask import Response
        lines = ['card,loans,hours,use_pct,users,lent_now']
        for r in rows:
            lines.append(','.join([_csv(r['card']), str(r['loans']), str(r['hours']), str(r['use_pct']), _csv(' '.join(r['users'])), str(r['active'])]))
        return Response('﻿' + '\n'.join(lines) + '\n', mimetype='text/csv; charset=utf-8',
                        headers={'Content-Disposition': f'attachment; filename="card-usage-{days}d.csv"'})
    return jsonify({'days': days, 'cards': rows, 'total_hours': round(sum(r['hours'] for r in rows), 1)})


def _csv(v):
    v = str(v)
    return '"' + v.replace('"', '""') + '"' if any(ch in v for ch in ',"\n') else v
